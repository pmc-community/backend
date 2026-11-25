import type { MiddlewareHandler } from 'hono';
import { setAuditError } from '../helpers/errHandler';

export const jsonOnlyLimiter: MiddlewareHandler = async (c, next) => {
    const request = c.req.raw;

    if (!request.body) {
        setAuditError(c, {
            name: 'Error',
            message: `JSON body required`,
            code: 'BODY_JSON_ONLY',
            status: 400,
        });

        return c.json(
            {
                error: 'Bad request body',
            },
            400,
        );
    }

    try {
        const clonedRequest = request.clone();
        const body = await clonedRequest.text();

        JSON.parse(body);
    } catch {

        setAuditError(c, {
            name: 'Error',
            message: `Invalid JSON payload`,
            code: 'BODY_JSON_ONLY_STRUCT',
            status: 400,
        });

        return c.json(
            {
                error: 'Bad request body',
            },
            400,
        );
    }

    await next();
};