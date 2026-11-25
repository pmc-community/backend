// ------------------------------------------------------------
// CORS
// ------------------------------------------------------------

import { cors } from 'hono/cors';
import * as data from '../data.provider/data'

export const corsSettings = cors({
    origin: (origin) => {
      if (!origin) {
        return undefined;
      }

    return data.BLOCKED_ORIGINS.includes(origin)
      ? null
      : origin;
    },

    allowMethods: data.ALLOW_METHODS,
    allowHeaders: data.ALLOW_HEADERS,
    credentials: true,
})