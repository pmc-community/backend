import type { RouteDefinition } from '../../../../types/route';

const route: RouteDefinition = {
  method: 'post',
  routeType: 'public',
  processor: (route, c) => {
    const pa = c.req.param('pa');
    const pb = c.req.param('pb');

    return c.json({
      status: 'ok',
      pa,
      pb,
    });
  },
};

export default route;