// ------------------------------------------------------------
// Response size limiter
// ------------------------------------------------------------

import { HTTPException } from 'hono/http-exception';
import type { MiddlewareHandler } from 'hono';
import { setAuditError } from '../helpers/errHandler';

export type ResponseSizeVariables = Record<string, never>;

/**
 * Creates middleware that prevents responses larger than the
 * specified number of bytes from being returned.
 *
 * @param maxBytes Maximum allowed response size in bytes.
 *
 * The response is fully buffered before it is returned so that
 * the size can be checked.
 */
export const responseSizeLimiter = (maxBytes: number,): MiddlewareHandler => {

    if (!Number.isFinite(maxBytes) || maxBytes <= 0) {
        throw new Error('maxBytes must be a positive number');
    }

    return async (c, next) => {

        // Let the downstream middleware / route generate
        // the response first.
        await next();

        const response = c.res;

        // No response body.
        if (response.body === null) {
            return;
        }

        // Read the response body.
        const buffer = await response.arrayBuffer();

        // Check actual byte size.
        if (buffer.byteLength > maxBytes) {
            setAuditError(c, {
                name: 'Error',
                message: `Response exceeds maximum size (accepted: ${maxBytes}, reached ${buffer.byteLength} bytes)`,
                code: 'RESPONSE_SIZE',
                status: 413,
            });

            throw new HTTPException(
                413, 
                {
                    message: `Response exceeds maximum size, Refine your request`,
                }
            );
        }

        // Re-create the response because arrayBuffer() consumes
        // the original response body.
        c.res = new Response(buffer, {
            status: response.status,
            headers: response.headers,
        });
    };
};