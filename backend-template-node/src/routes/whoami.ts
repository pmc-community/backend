// ------------------------------------------------------------
// whoami.ts — GET /whoami
// includes a portable client-info resolver (also exported for reuse)
// ------------------------------------------------------------

import type { Context } from 'hono';
import type { RouteDefinition } from '../types/route';
import { getClientIP } from '../helpers/utilities';

//------ MIDDLEWARES --------
import { noBodyLimiter } from '../middleware/noBodyLimiter';
import { queryParameterLimiter } from '../middleware/queryParameterLimiter';
//------ END MIDDLEWARES -----


export interface ClientInfo {
    ip: string;
    userAgent: string;
    acceptLanguage: string | null;
    referer: string | null;
    origin: string | null;
    geo: {
        country: string | null;
        region: string | null;
        city: string | null;
        timezone: string | null;
        source: 'cloudflare' | 'vercel' | 'lookup' | 'unavailable';
    };
}

// ---- Geo resolution: platform headers first, network lookup as last resort ----
async function resolveGeo(c: Context, ip: string): Promise<ClientInfo['geo']> {
    // Cloudflare enriches every request at the edge — zero extra latency.
    const cf = (c.req.raw as any).cf as Record<string, any> | undefined;
    if (cf) {
        return {
            country: cf.country ?? null,
            region: cf.region ?? null,
            city: cf.city ?? null,
            timezone: cf.timezone ?? null,
            source: 'cloudflare',
        };
    }

    // Vercel injects geo headers at the edge too.
    const vCountry = c.req.header('x-vercel-ip-country');
    if (vCountry) {
        return {
            country: vCountry,
            region: c.req.header('x-vercel-ip-country-region') ?? null,
            city: c.req.header('x-vercel-ip-city') ?? null,
            timezone: c.req.header('x-vercel-ip-timezone') ?? null,
            source: 'vercel',
        };
    }

    // Nothing platform-provided (plain Node/Bun/Deno behind nginx, etc).
    // Fall back to an HTTP geo-IP API — works identically on every runtime.
    if (ip === 'unknown' || ip.startsWith('127.') || ip === '::1') {
        return { country: null, region: null, city: null, timezone: null, source: 'unavailable' };
    }

    try {
        const res = await fetch(`https://ipapi.co/${ip}/json/`);
        if (!res.ok) throw new Error('geo lookup failed');
        const data = await res.json();
        return {
            country: data.country_name ?? null,
            region: data.region ?? null,
            city: data.city ?? null,
            timezone: data.timezone ?? null,
            source: 'lookup',
        };
    } catch {
        return { country: null, region: null, city: null, timezone: null, source: 'unavailable' };
    }
}

export async function getClientInfo(c: Context): Promise<ClientInfo> {
    const ip = getClientIP(c);
    const geo = ip !== 'unknown' ? await resolveGeo(c, ip) : null;

    return {
        ip,
        userAgent: c.req.header('user-agent') ?? 'unknown',
        acceptLanguage: c.req.header('accept-language') ?? null,
        referer: c.req.header('referer') ?? null,
        origin: c.req.header('origin') ?? null,
        geo: geo ?? { country: null, region: null, city: null, timezone: null, source: 'unavailable' },
    };
}

const route: RouteDefinition = {
    routeType: 'protected',
    method: 'get',
    middlewares:[
        queryParameterLimiter({maxParameters: 0}),
        noBodyLimiter,
    ],
    processor: async (route, c) => {
        const client = c.get('client');
        const info = await getClientInfo(c);

        return c.json({
            clientId: client.id,
            scopes: client.scopes,
            ...info,
        });
    },
};

export default route;