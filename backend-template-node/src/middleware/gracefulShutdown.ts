// graceful shutdown is disabled for local dev
// to be tested on local, use:
//  - DEPLOY_ENV=simprod
//  - PROD_PORT=80
//  - npm run start
//  - send http://test/slow request from POSTMAN and stop the server with CTRL-C
//  - the request should finish with 200 and only then the server shall shutdown 

import type { MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { setAuditError } from '../helpers/errHandler';

export interface GracefulShutdownOptions {
    status?: 503;
    message?: string;
    excludePaths?: string[];
}

export interface GracefulShutdownController {
    isDraining(): boolean;
    activeRequests(): number;
    startDraining(): void;
    waitForDrain(timeoutMs?: number): Promise<boolean>;
}

export function createGracefulShutdown(options: GracefulShutdownOptions = {}): {
    middleware: MiddlewareHandler;
    controller: GracefulShutdownController;
} {
    const {
        status = 503,
        message = 'Service is shutting down.',
        excludePaths = [],
    } = options;

    const excludedPaths = new Set(excludePaths);

    let draining = false;
    let activeRequests = 0;
    let drainResolver: ((drained: boolean) => void) | undefined;

    const middleware: MiddlewareHandler = async (c, next) => {
        if (excludedPaths.has(c.req.path)) {
            await next();
            return;
        }

        if (draining) {
            setAuditError(c, {
                name: 'Warning',
                message: message,
                code: 'GRACEFUL_SHUTDOWN',
                status: 503,
            });

            throw new HTTPException(status, { message });
        }

        activeRequests++;

        try {
            await next();
        } finally {
            activeRequests--;

            if (activeRequests === 0 && drainResolver) {
                const resolve = drainResolver;
                drainResolver = undefined;
                resolve(true);
            }
        }
    };

    const controller: GracefulShutdownController = {
        isDraining: () => draining,
        activeRequests: () => activeRequests,
        startDraining: () => { draining = true; },

        waitForDrain: (timeoutMs = parseInt(process.env.GRSD_WAIT_FOR_DRAIN_MS ?? '3000', 10)): Promise<boolean> => {
            if (activeRequests === 0) return Promise.resolve(true);

            return new Promise<boolean>((resolve) => {
                let settled = false;

                const finish = (drained: boolean): void => {
                    if (settled) return;

                    settled = true;
                    clearTimeout(timeout);
                    drainResolver = undefined;
                    resolve(drained);
                };

                const timeout = setTimeout(() => {finish(false);}, timeoutMs);

                drainResolver = () => finish(true);
            });
        },
    };

    return { middleware, controller };
}