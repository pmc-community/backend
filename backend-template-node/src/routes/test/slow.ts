import type { RouteDefinition } from '../../types/route';


//------ MIDDLEWARES --------
import { noBodyLimiter } from '../../middleware/noBodyLimiter';
//------ END MIDDLEWARES -----

const route: RouteDefinition = {
    routeType: 'public',
    method: 'get',
    middlewares: [noBodyLimiter],
    processor: async (route, c) => {
        console.log('SLOW REQUEST START');

        await new Promise((resolve) => setTimeout(resolve, 10_000)); // simulating slow route with a 10sec delay

        console.log('SLOW REQUEST FINISHED');

        return c.json({
            status: 'simulated slow request completed',
        });
    },
};

export default route;