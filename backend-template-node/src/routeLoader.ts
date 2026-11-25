import type { Hono, Env, Schema, MiddlewareHandler } from 'hono';
import type { RouteManifestEntry, RouteType } from './types/route';
import { VALID_METHODS } from './config/methods';

export async function routeLoader<E extends Env = Env, S extends Schema = {}>(
  app: Hono<E, S, any>,
  manifest: RouteManifestEntry[],
  routeType: RouteType,
  sharedMiddlewares: MiddlewareHandler[] = []
): Promise<void> {
  const registered = new Set<string>();

  for (const { route, load } of manifest) {
    let definition;
    try {
      definition = await load();
    } catch (err) {
      console.error(`[routeLoader] Failed to load route ${route}:`, err);
      continue;
    }

    if (!definition || typeof definition.processor !== 'function') {
      console.warn(`[routeLoader] Skipping invalid route definition for ${route}`);
      continue;
    }

    if (definition.routeType !== routeType) continue;

    if (!VALID_METHODS.has(definition.method)) {
      console.warn(`[routeLoader] Skipping ${route}: method '${definition.method}' not in ALLOWED_METHODS`);
      continue;
    }

    const key = `${definition.method} ${route}`;
    if (registered.has(key)) {
      console.warn(`[routeLoader] Duplicate route skipped: ${key}`);
      continue;
    }
    registered.add(key);

    const { method, middlewares = [], processor } = definition;
    const handler = (c: Parameters<typeof processor>[1]) => processor(route, c);

    // sharedMiddlewares (e.g. apiKeyAuth) run first, then the route's own middlewares
    (app as any)[method](route, ...sharedMiddlewares, ...middlewares, handler);

    console.log(`[routeLoader] [${routeType}] ${method.toUpperCase().padEnd(6)} ${route}`);
  }
}