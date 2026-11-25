// ------------------------------------------------------------
// Request size limit middleware
// ------------------------------------------------------------
//
// Measures the actual number of bytes received from the
// request body.
//
// The original request body is preserved for downstream
// middleware such as zValidator() / c.req.json().
//
// IMPORTANT:
// This middleware must run BEFORE anything that consumes
// the request body.
// ------------------------------------------------------------

import type { MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { setAuditError } from '../helpers/errHandler';

/**
 * Restrict the maximum request body size.
 *
 * The request body is read from a cloned Request so the
 * original request remains available to downstream handlers.
 *
 * @param maxBytes Maximum allowed request body size in bytes.
 *
 * @throws HTTPException 413 when the body exceeds maxBytes.
 */
export const sizeLimiter = (maxBytes: number): MiddlewareHandler => {

    // --------------------------------------------------------
    // Validate configuration when the middleware is created.
    // --------------------------------------------------------

    if (
        !Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
        throw new Error('sizeLimit maxBytes must be a positive safe integer');
    }

    return async (c, next) => {

        // ----------------------------------------------------
        // No body means nothing to limit.
        // ----------------------------------------------------

        const body = c.req.raw.body;

        if (!body) {
            await next();
            return;
        }

        // ----------------------------------------------------
        // Clone the request.
        //
        // The original request remains untouched and can still
        // be consumed by downstream middleware.
        // ----------------------------------------------------

        let clonedRequest: Request;

        try {
            clonedRequest = c.req.raw.clone();
        } catch {
            setAuditError(c, {
                name: 'Error',
                message: `invalid request`,
                code: 'RQ_SIZE',
                status: 400,
            });

            throw new HTTPException(
                400, 
                {
                    message: 'invalid request',
                }
            );
        }

        const clonedBody = clonedRequest.body;

        if (!clonedBody) {
            await next();
            return;
        }

        // ----------------------------------------------------
        // Count the actual bytes received.
        // ----------------------------------------------------

        const reader = clonedBody.getReader();
        let bytesRead = 0;

        try {
            while (true) {
                const { done, value } = await reader.read();

                if (done) break;
                if (!value) continue;
                
                bytesRead += value.byteLength;

                // ------------------------------------------------
                // Reject as soon as the actual body exceeds the
                // configured limit.
                // ------------------------------------------------

                if (bytesRead > maxBytes) {
                    await reader.cancel();

                    setAuditError(c, {
                        name: 'Error',
                        message: `request too large (accepted: ${maxBytes}, reached: ${bytesRead})`,
                        code: 'RQ_SIZE',
                        status: 413,
                    });


                    throw new HTTPException(
                        413, 
                        {
                            message: 'Bad request size',
                        }
                    );
                }
            }
        } catch (error) {
            // Preserve our HTTPException.
            if (error instanceof HTTPException) {
                throw error;
            }

            // Body could not be read correctly.
            setAuditError(c, {
                name: 'Error',
                message: `invalid request body`,
                code: 'RQ_SIZE',
                status: 400,
            });

            throw new HTTPException(
                400, 
                {
                    message: 'Bad request body',
                }
            
            );
        }

        // ----------------------------------------------------
        // Actual body size is within the configured limit.
        //
        // The ORIGINAL request body has not been consumed,
        // so downstream middleware can still call:
        //
        //   c.req.json()
        //   c.req.text()
        //   zValidator('json', ...)
        //
        // etc.
        // ----------------------------------------------------

        await next();
    };
};
