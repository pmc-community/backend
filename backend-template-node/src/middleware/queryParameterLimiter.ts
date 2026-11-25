import type { MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { setAuditError } from '../helpers/errHandler';

// ------------------------------------------------------------
// Query parameter limiter
// ------------------------------------------------------------

export interface QueryParameterLimiterOptions {
    maxParameters?: number;
    maxKeyLength?: number;
    maxValueLength?: number;
    maxQueryStringLength?: number;
}

const DEFAULT_MAX_PARAMETERS = parseInt(
    process.env.DEFAULT_MAX_QUERY_PARAMETERS ?? '20',
    10,
);

const DEFAULT_MAX_KEY_LENGTH = parseInt(
    process.env.DEFAULT_MAX_QUERY_KEY_LENGTH ?? '100',
    10,
);

const DEFAULT_MAX_VALUE_LENGTH = parseInt(
    process.env.DEFAULT_MAX_QUERY_VALUE_LENGTH ?? '2000',
    10,
);

const DEFAULT_MAX_QUERY_STRING_LENGTH = parseInt(
    process.env.DEFAULT_MAX_QUERY_STRING_LENGTH ?? '4000',
    10,
);

export const queryParameterLimiter = (
    options: QueryParameterLimiterOptions = {},
): MiddlewareHandler => {
    const maxParameters =
        options.maxParameters ?? DEFAULT_MAX_PARAMETERS;

    const maxKeyLength =
        options.maxKeyLength ?? DEFAULT_MAX_KEY_LENGTH;

    const maxValueLength =
        options.maxValueLength ?? DEFAULT_MAX_VALUE_LENGTH;

    const maxQueryStringLength =
        options.maxQueryStringLength ?? DEFAULT_MAX_QUERY_STRING_LENGTH;

    return async (c, next) => {
        const url = new URL(c.req.url);
        const queryString = url.search;

        // --------------------------------------------------------
        // Total query-string size
        // --------------------------------------------------------

        if (queryString.length > maxQueryStringLength) {
            setAuditError(c, {
                name: 'Error',
                message: `Query string too long (accepted:${maxQueryStringLength} provided:${queryString.length})`,
                code: 'QP_QSTRING_TOO_LONG',
                status: 414,
            });

            throw new HTTPException(414, {
                message: 'invalid request format',
            });
        }

        // --------------------------------------------------------
        // Parameter count
        // --------------------------------------------------------

        const parameters = Array.from(url.searchParams.entries());

        if (parameters.length > maxParameters) {
            setAuditError(c, {
                name: 'Error',
                message: `Too many query parameters (accepted:${maxParameters} provided:${parameters.length})`,
                code: 'QP_TOO_MANY',
                status: 400,
            });
            throw new HTTPException(400, {
                message: 'Invalid request format',
            });
        }

        // --------------------------------------------------------
        // Individual parameter validation
        // --------------------------------------------------------

        for (const [key, value] of parameters) {
            if (key.length > maxKeyLength) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Query parameter name too long (${key.length})`,
                    code: 'QP_NAME_TOO_LONG',
                    status: 400,
                });
                throw new HTTPException(400, {
                    message: 'Invalid request format',
                });
            }

            if (value.length > maxValueLength) {
                setAuditError(c, {
                    name: 'Error',
                    message: `Query parameter value too long (${value.length})`,
                    code: 'QP_VALUE_TOO_LONG',
                    status: 400,
                });

                throw new HTTPException(400, {
                    message: 'Invalid request format',
                });
            }
        }

        await next();
    };
};