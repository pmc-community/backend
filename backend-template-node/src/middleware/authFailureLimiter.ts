// ------------------------------------------------------------
// Failed authentication rate limiting
// ------------------------------------------------------------

import type { MiddlewareHandler } from 'hono';
import { authFailures } from '../types/types';
import { getClientIP } from '../helpers/utilities';
import { setAuditError } from '../helpers/errHandler';


export const authFailureLimiter: MiddlewareHandler = async (c,next) => {
    const ip =  getClientIP(c)  ?? 'unknown';
    const now = Date.now();
    const max = parseInt(process.env.maxRqAuthFailures ?? '10', 10);
    const entry = authFailures.get(ip);

    if (
        entry &&
        now < entry.reset &&
        entry.count >= max
    ) { 
        setAuditError(c, {
            name: 'Error',
            message: `Too many failed auth attempts (${entry.count})`,
            code: 'AUTH_FAIL_LIMITS',
            status: 429,
        });

        return c.json(
            {
                error: 'Authorization problem, try again later',
            },
            429
        );
    }

    await next();
};
