import type { Context, MiddlewareHandler } from 'hono';
import type { HttpMethod } from '../config/methods';

export type RouteProcessor = (
  route: string,
  c: Context<any, any, any>
) => Response | Promise<Response>;

export type RouteType = 'public' | 'protected';

export interface RouteDefinition {
  method: HttpMethod;
  routeType: RouteType;
  middlewares?: MiddlewareHandler[];
  processor: RouteProcessor;
}

export interface RouteManifestEntry {
  route: string;
  load: () => Promise<RouteDefinition>;
}