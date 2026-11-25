// ------------------------------------------------------------
// API key authentication middleware
// ------------------------------------------------------------

import type { MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { hashKey } from '../keystore/appKeys';
import type { Variables } from '../types/types';
import { authFailures } from '../types/types';
import { getClientIP } from '../helpers/utilities';
import { setAuditError } from '../helpers/errHandler';

import { keystoreProvider } from '../keystore/provider';
const { getAPIKey } = await keystoreProvider();

// only API key routes needs auth failure limits protection
// these are defined later
function recordAuthFailure(ip: string): void {
    const now = Date.now();
    const windowMs = parseInt(process.env.rqFailuresInterval ?? '15', 10) * parseInt(process.env.minuteInMs ?? '60000', 10);
    const entry = authFailures.get(ip);

    if (!entry || now > entry.reset) {
        authFailures.set(ip, {
            count: 1,
            reset: now + windowMs,
        });
    } else {
        entry.count++;
    }
}

export const apiKeyAuth: MiddlewareHandler<{Variables: Variables;}> = async (c, next) => {

    // we use X-api-Key to authorize api requests because 
    // Authorization header may be used to send access tokens or authorization codes 
    // retrieved through the browser part of a login flow

    const authHeader = c.req.header('X-Api-Key'); 
    const key = authHeader?.startsWith('Bearer ')
        ? authHeader.slice(7)
        : undefined;

    const ip = getClientIP(c) ?? 'unknown';

    if (!key) {
        recordAuthFailure(ip);
        
        setAuditError(c, {
            name: 'Error',
            message: `Missing API key`,
            code: 'AUTH_API_KEY',
            status: 401,
        });

        throw new HTTPException(
            401, 
            {
                message: 'Request not authorized',
            }
        );
    }

    // ----------------------------------------------------------
    // Hash the supplied raw API key.
    //
    // getAPIKey() is the storage abstraction.
    //
    // Local:
    //     JSON -> cached Map -> lookup
    //
    // Production:
    //     database -> indexed key_hash lookup
    // ----------------------------------------------------------

    if (!getAPIKey) {
        throw new HTTPException(500, {
            message: 'Something wrong happen when reading API Key with getAPIKey',
        });
    }

    const keyHash = await hashKey(key);
    const client = await getAPIKey(keyHash);

    if (!client) {
        recordAuthFailure(ip);
        
        setAuditError(c, {
            name: 'Error',
            message: `Invalid API key`,
            code: 'AUTH_API_KEY',
            status: 401,
        });

        throw new HTTPException(401, {
            message: 'Not authorized',
        });
    }

    c.set('client', {
        id: client.clientId,
        scopes: client.scopes,
    });

    await next();
};