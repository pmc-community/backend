import type { MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { setAuditError } from '../helpers/errHandler';

// ------------------------------------------------------------
// Per-key rate limiter
// ------------------------------------------------------------

interface RateLimitEntry {
    count: number;
    windowStart: number;
}

// ------------------------------------------------------------
// Middleware
// ------------------------------------------------------------

export function perKeyRateLimiter(
    maxRequestsPerMinute: number,
): MiddlewareHandler {
    const windowMs = parseInt(process.env.minuteInMs ?? '60000', 10);

    // --------------------------------------------------------
    // Validate configuration
    // --------------------------------------------------------

    if (
        !Number.isSafeInteger(maxRequestsPerMinute) ||
        maxRequestsPerMinute <= 0
    ) {
        throw new Error(
            'maxRequestsPerMinute must be a positive safe integer',
        );
    }

    // --------------------------------------------------------
    // One counter per client
    // --------------------------------------------------------

    const clients = new Map<string, RateLimitEntry>();

    return async (c, next) => {
        const client = c.get('client');

        if (!client?.id) {
            setAuditError(c, {
                name: 'Error',
                message: `Authentication required`,
                code: 'AUTH_NEEDED',
                status: 401,
            });

            throw new HTTPException(401, {
                message: 'Authentication required',
            });
        }

        const key = client.id;
        const now = Date.now();

        let entry = clients.get(key);

        // ----------------------------------------------------
        // Start a new one-minute window
        // ----------------------------------------------------

        if (
            entry === undefined ||
            now - entry.windowStart >= windowMs
        ) {
            entry = {
                count: 0,
                windowStart: now,
            };

            clients.set(key, entry);
        }

        // ----------------------------------------------------
        // Rate limit exceeded
        // ----------------------------------------------------

        if (entry.count >= maxRequestsPerMinute) {
            const retryAfterMs =
                windowMs - (now - entry.windowStart);

            c.header(
                'Retry-After',
                String(Math.ceil(retryAfterMs / 1000)),
            );

            setAuditError(c, {
                name: 'Error',
                message: `Authentication rate limit exceeded (accepted: ${maxRequestsPerMinute}, reached; ${entry.count})`,
                code: 'AUTH_LIMITS',
                status: 429,
            });

            throw new HTTPException(429, {
                message: 'Too many requests. Try again later.',
            });
        }

        // ----------------------------------------------------
        // Consume request
        // ----------------------------------------------------

        entry.count++;

        await next();
    };
}