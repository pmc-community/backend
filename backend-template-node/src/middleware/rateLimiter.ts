// ------------------------------------------------------------
// Rate limiting - defined in .env
// to be used in route definition as rateLimniter(<max_no_of_requests/minute/IP>)
//
// - can be applied as general like app.use('*', rateLimiter(100))
// - can be overwritten in a specific route lile app.get('routeX', ..., rateLimiter(5), ...)
// ------------------------------------------------------------

import type { MiddlewareHandler } from 'hono';
import { getClientIP } from '../helpers/utilities';
import { setAuditError } from '../helpers/errHandler'; 

interface RateLimitEntry {
    count: number;
    reset: number;
}

const rateLimits = new Map<string, RateLimitEntry>();

export const rateLimiter = ( maxRqPerMin: number): MiddlewareHandler => {
    
    if (!Number.isSafeInteger(maxRqPerMin) || maxRqPerMin <= 0) {
        throw new Error('rateLimiter maxRqPerMin must be a positive safe integer',);
    }

    return async (c, next) => {
        const ip = getClientIP(c) ?? 'unknown';

        const now = Date.now();
        const windowMs = parseInt(process.env.minuteInMs ?? '60000');

        const entry = rateLimits.get(ip);

        if (!entry || now > entry.reset) {
            rateLimits.set(ip, {
                count: 1,
                reset: now + windowMs,
            });
        } else {
            entry.count++;

            if (entry.count > maxRqPerMin) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Too many requests (accepted:${maxRqPerMin} reached:${entry.count})`,
                    code: 'RATE_LIMIT_EXEEDED',
                    status: 429,
                });

                return c.json(
                    {
                        error: 'Too many requests',
                    },
                    429,
                );
            }
        }

        await next();
    };
};