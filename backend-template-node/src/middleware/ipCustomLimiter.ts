import * as data from '../data.provider/data';
import type { MiddlewareHandler } from 'hono';
import { getClientIP } from '../helpers/utilities';
import { ipRestrictionError  } from '../helpers/errHandler';
import { ipMatchesRule } from '../helpers/utilities';

export const ipCustomLimiter: MiddlewareHandler = async (c, next) => {
    const remote = getClientIP(c);

    const denied = data.GLOBAL_IP_DENY.some((rule) =>
        ipMatchesRule(remote, rule),
    );

    if (denied) {
        return ipRestrictionError({ addr: remote }, c);
    }

    await next();
};