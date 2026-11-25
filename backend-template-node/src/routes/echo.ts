import type { RouteDefinition } from '../types/route';

import { userSchema } from '../config/bodySchemas';

//------ MIDDLEWARES --------
import { requireScope } from '../middleware/scopes';
import { noBodyLimiter } from '../middleware/noBodyLimiter';
import { queryParameterLimiter } from '../middleware/queryParameterLimiter';
//------ END MIDDLEWARES -----



const route: RouteDefinition = {
  routeType: 'protected',
  method: 'get',
  middlewares:[
    noBodyLimiter,
    queryParameterLimiter({maxParameters: 0}),
    requireScope('read:echo'),
    //requireScope('read:echo', 'additional:scope'), // --> multiple scopes required
  ],
  processor: (route, c) => {
    const client = c.get('client');

    return c.json({
      status: 'ok',
      client: client.id,
    });
  },
};

export default route;