// ------------------------------------------------------------
// Concurrency Limiter
// Limits simultaneous requests per client.
// ------------------------------------------------------------

import type { Context, MiddlewareHandler } from 'hono';
import { setAuditError } from '../helpers/errHandler';

export interface ConcurrencyLimitEvent {
    type: 'concurrency_limit';
    key: string;
    current: number;
    limit: number;
    path: string;
    method: string;
}

export interface ConcurrencyLimiterOptions {
    /**
     * Maximum number of simultaneous requests per key.
     */
    maxConcurrent?: number;

    /**
     * Resolves the identity used for concurrency tracking.
     *
     * By default:
     *   authenticated client -> client.id (API Key used)
     *   unauthenticated      -> getClientIP(c) (public routes)
     */
    key: (c: Context) => string;

    /**
     * HTTP status returned when the limit is exceeded.
     */
    status?: 429 | 503;

    /**
     * Called whenever a request is rejected.
     */
    onReject?: (event: ConcurrencyLimitEvent) => void;
}

interface Counter {
    active: number;
}

export function concurrencyLimiter(
    options: ConcurrencyLimiterOptions,
): MiddlewareHandler {
    const {
        maxConcurrent = parseInt(process.env.CO_MAX_ALLOWED ?? '10', 10),
        key,
        status = 429,
        onReject,
    } = options;

    if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1) {
        throw new Error(
            'concurrencyLimiter: maxConcurrent must be an integer >= 1',
        );
    }

    const counters = new Map<string, Counter>();

    return async (c, next) => {
        const clientKey = key(c);

        if (!clientKey) {
            setAuditError(c, {
                name: 'Error',
                message: `unable_to_identify_client`,
                code: 'CONCURRENCY_LIMIT',
                status: 400,
            });

            return c.json(
                {
                    error: 'unable_to_identify_client',
                    message: 'Unknown request identity',
                },
                400,
            );
        }

        let counter = counters.get(clientKey);

        if (!counter) {
            counter = {
                active: 0,
            };

            counters.set(clientKey, counter);
        }

        if (counter.active >= maxConcurrent) {
            const event: ConcurrencyLimitEvent = {
                type: 'concurrency_limit',
                key: clientKey,
                current: counter.active,
                limit: maxConcurrent,
                path: c.req.path,
                method: c.req.method,
            };

            onReject?.(event);

            setAuditError(c, {
                name: 'Error',
                message: `too many concurrent requests (accepted: ${maxConcurrent}, reached: ${counter.active})`,
                code: 'CONCURRENCY_LIMIT',
                status: status,
            });
            

            return c.json(
                {
                    error: 'Server busy, try again later.',
                },
                status,
            );
        }

        counter.active++;

        try {
            await next();
        } finally {
            counter.active--;

            if (counter.active === 0) {
                counters.delete(clientKey);
            }
        }
    };
}