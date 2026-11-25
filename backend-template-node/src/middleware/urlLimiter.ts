import type { MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { setAuditError } from '../helpers/errHandler';

// ------------------------------------------------------------
// Path / URL length limiter
// ------------------------------------------------------------

export interface PathUrlLengthLimiterOptions {
    /**
     * Maximum allowed URL length in characters.
     * Includes pathname + query string.
     */
    maxLength?: number;

    /**
     * Whether to measure the complete URL or only the pathname.
     *
     * true  = pathname + query string
     * false = pathname only
     */
    includeQuery?: boolean;
}

const DEFAULT_MAX_LENGTH = parseInt(process.env.MAX_URL_LENGTH ?? '1024',10,);

export const urlLengthLimiter = (
    options: PathUrlLengthLimiterOptions = {},
): MiddlewareHandler => {

    const maxLength = options.maxLength ?? DEFAULT_MAX_LENGTH;
    const includeQuery = options.includeQuery ?? true;

    if (!Number.isInteger(maxLength) || maxLength <= 0) {
        throw new Error('maxLength must be a positive integer');
    }

    return async (c, next) => {

        const url = new URL(c.req.url);

        const value = includeQuery
            ? `${url.pathname}${url.search}`
            : url.pathname;

        if (value.length > maxLength) {
            setAuditError(c, {
                name: 'Error',
                message: `URI Too Long (accepted: ${maxLength}, got: ${value.length})`,
                code: 'URL_SIZE',
                status: 414,
            });

            throw new HTTPException(414, {
                message: 'Bad request URL',
            });
        }

        await next();
    };
};