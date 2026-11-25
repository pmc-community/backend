// ------------------------------------------------------------
// Scope authorization middleware
// ------------------------------------------------------------

import type { MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import type { Variables } from '../types/types';
import { setAuditError } from '../helpers/errHandler';

export const requireScope = (...scopes: string[]): MiddlewareHandler<{ Variables: Variables }> => {
    return async (c, next) => {
        const client = c.get('client');

        if (!scopes.every(scope => client.scopes.includes(scope))) {
            setAuditError(c, {
                name: 'Error',
                message: `Insufficient_scope (required: ${scopes.join(', ')} / provided: ${client.scopes.join(', ')})`,
                code: 'SCOPE_NOT_ENOUFH',
                status: 403,
            });

            throw new HTTPException(403, {
                message: 'Insufficient scope',
            });
        }

        await next();
    };
};
