import type { MiddlewareHandler } from 'hono';
import type { RouteDefinition } from '../types/route';

import { userSchema } from '../config/bodySchemas';

//------ MIDDLEWARES --------
import { zValidator } from '@hono/zod-validator';
import { requireScope } from '../middleware/scopes';
import { sizeLimiter } from '../middleware/sizeLimiter';
import { ipRestriction } from 'hono/ip-restriction';
import { jsonOnlyLimiter } from '../middleware/jsonOnlyLimiter';
import { timeoutLimiter } from '../middleware/timeoutLimiter';
import { perKeyRateLimiter } from '../middleware/perKeyLimiter';
import { signedRequestProtection } from '../middleware/signedRequestProtection';
//------ END MIDDLEWARES -----

import { getClientIP } from '../helpers/utilities';

import {
  zValidatorError,
  ipRestrictionError,
} from '../helpers/errHandler';

const route: RouteDefinition = {
  routeType: 'protected',

  method: 'post',

  middlewares: [
    ipRestriction(
      getClientIP,
      {
        denyList: [],
        allowList: ['192.168.1.0/24'],
        //allowList: ['192.168.1.111'],
      },
      async (remote, c) => ipRestrictionError(remote, c),
    ),

    // testing signed request feature
    // is hardcoded for testClient, having a hardcoded client secret
    // here it must be a function getting the secret from the secrets storage
    // same clientId and secret are configured in POSTMAN pre-request scripts
    // see scripts/postman-pre-request.js
    signedRequestProtection({
        getSigningSecret: async (
            c,
            clientId,
        ) => {
            console.log(
                'Signing secret requested for client:',
                clientId,
            );

            if (
                clientId === 'testClient'
            ) {
                return 'test-secret-123';
            }

            return undefined;
        },
    }),
    

    perKeyRateLimiter(10),

    requireScope('write:users'),

    sizeLimiter(
      parseInt(process.env.maxBytesBase ?? '1024', 10) ** 2,
    ),

    jsonOnlyLimiter,

    zValidator(
      'json',
      userSchema,
      (result, c) => zValidatorError(result, c),
    ),

    timeoutLimiter(1),
  ] as MiddlewareHandler[],

  processor: async (route, c) => {
    const body = c.req.valid('json');
    return c.json(
        {
            received: body,
        },
        201
    );
  },
};

export default route;