import type { MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { setAuditError } from '../helpers/errHandler';

export const noBodyLimiter: MiddlewareHandler = async (c, next) => {
    const request = c.req.raw;

    // Fast path: Content-Length header, if present, tells us immediately
    const contentLength = request.headers.get('content-length');
    if (contentLength && Number(contentLength) > 0) {
                    
        setAuditError(c, {
            name: 'Error',
            message: `Request body length identified in content-length header. Body is not allowed.`,
            code: 'BODY_NOT_ALLOWED_HD',
            status: 400,
        });

        throw new HTTPException(400, { message: 'Bad request' });
    }

    // No body stream at all -> nothing to check, continue
    if (request.body === null) {
        return next();
    }

    // Fallback: actually drain the stream (covers chunked
    // transfer-encoding, where Content-Length may be absent)
    let byteLength = 0;
    try {
        const buf = await request.clone().arrayBuffer();
        byteLength = buf.byteLength;
    } catch {
        setAuditError(c, {
            name: 'Error',
            message: `Invalid request. Body is not allowed.`,
            code: 'BODY_NOT_ALLOWED',
            status: 400,
        });

        throw new HTTPException(400, { message: 'Invalid request' });
    }

    if (byteLength > 0) {
        setAuditError(c, {
            name: 'Error',
            message: `Request body not allowed`,
            code: 'BODY_NOT_ALLOWED',
            status: 400,
        });

        throw new HTTPException(400, { message: 'Invalid request' });
    }

    return next();
};