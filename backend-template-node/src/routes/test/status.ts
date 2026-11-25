import type { RouteDefinition } from '../../types/route';

import { userSchema } from '../../config/bodySchemas';

//------ MIDDLEWARES --------
import { noBodyLimiter } from '../../middleware/noBodyLimiter';
import { queryParameterLimiter } from '../../middleware/queryParameterLimiter';
//------ END MIDDLEWARES -----

const route: RouteDefinition = {
  routeType: 'public',
  method: 'get',
  middlewares: [
    noBodyLimiter, 
    queryParameterLimiter({maxParameters: 0})
  ],
  processor: (route, c) => {
    return c.json({
      test_status: 'ok',
    });
  },
};

export default route;