import type { RouteDefinition } from '../../../types/route'; // adjust relative depth to match actual path

const route: RouteDefinition = {
  method: 'post',
  routeType: 'protected', // or 'protected', per your routeType addition
  processor: (route, c) => {
    const param = c.req.param('p1'); // matches the bracket name exactly

    return c.json({
      status: 'ok',
      param,
    });
  },
};

export default route;