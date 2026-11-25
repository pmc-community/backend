// ------------------------------------------------------------
// Structured error handling
// ------------------------------------------------------------

import { HTTPException } from 'hono/http-exception';
import type { Context } from 'hono';
import { AuditError } from '../types/types';

export const errHandler = (err: any, c: Context) => {
    //console.error(err);

    if (err instanceof HTTPException) {
        return c.json(
            {
                error: err.message,
            },
            err.status
        );
    }
    console.log(err)
    return c.json(
        {
            error: 'Internal server error',
        },
        500
    );
    
}

export function setAuditError(
    c: Context,
    error: AuditError,
): void {
    c.set('auditError', error);
}

export const zValidatorError = (result: any, c: any) => {
    if (!result.success) {
        console.warn('[Validation]', result.error);

        setAuditError(c, {
            name: 'ZodError',
            message: 'Request body validation failed. Bad JSON.',
            code: 'VALIDATION_FAILED',
            status: 400,
            details: result.error.issues.map(
                (issue: (typeof result.error.issues)[number]) => ({
                    code: issue.code,
                    path: issue.path,
                    message: issue.message,
                }),
)        });

        return c.json(
            {
                error: 'Invalid request',
            },
            400,
        );
    }

    return undefined;
}

export const ipRestrictionError = (remote: any, c: any) => {
    console.warn(`Access denied for IP ${remote.addr}`)
    setAuditError(c, {
        name: 'IPRestrictionError',
        message: `Access denied for IP ${remote.addr}`,
        code: 'IP_NOT_ALLOWED',
        status: 403,
    });

    throw new HTTPException(403, {
        message: 'Not allowed',
    });
}