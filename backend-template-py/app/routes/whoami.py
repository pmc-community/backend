# ------------------------------------------------------------
# whoami.py — GET /whoami
# includes a client-info resolver (also exported for reuse)
# ------------------------------------------------------------

from __future__ import annotations

from typing import Any

import httpx

from app.core.context import Context
from app.helpers.utilities import get_client_ip
from app.route_types import RouteDefinition

# ------ MIDDLEWARES --------
from app.middleware.no_body_limiter import no_body_limiter
from app.middleware.query_parameter_limiter import query_parameter_limiter
# ------ END MIDDLEWARES -----


def _unavailable() -> dict[str, Any]:
    return {"country": None, "region": None, "city": None, "timezone": None, "source": "unavailable"}


# ---- Geo resolution: platform headers first, network lookup as last resort ----
async def resolve_geo(c: Context, ip: str) -> dict[str, Any]:
    # Cloudflare enriches every request at the edge - zero extra latency.
    # (ASGI servers running on Workers expose it as scope["cf"].)
    cf = c.scope.get("cf")

    if cf:
        return {
            "country": cf.get("country"),
            "region": cf.get("region"),
            "city": cf.get("city"),
            "timezone": cf.get("timezone"),
            "source": "cloudflare",
        }

    # Vercel injects geo headers at the edge too.
    v_country = c.req.header("x-vercel-ip-country")

    if v_country:
        return {
            "country": v_country,
            "region": c.req.header("x-vercel-ip-country-region"),
            "city": c.req.header("x-vercel-ip-city"),
            "timezone": c.req.header("x-vercel-ip-timezone"),
            "source": "vercel",
        }

    # Nothing platform-provided (plain server behind nginx, etc).
    # Fall back to an HTTP geo-IP API.
    if ip == "unknown" or ip.startswith("127.") or ip == "::1":
        return _unavailable()

    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(f"https://ipapi.co/{ip}/json/")

        if res.status_code >= 400:
            raise RuntimeError("geo lookup failed")

        data = res.json()

        return {
            "country": data.get("country_name"),
            "region": data.get("region"),
            "city": data.get("city"),
            "timezone": data.get("timezone"),
            "source": "lookup",
        }
    except Exception:  # noqa: BLE001
        return _unavailable()


async def get_client_info(c: Context) -> dict[str, Any]:
    ip = get_client_ip(c)
    geo = await resolve_geo(c, ip) if ip != "unknown" else None

    return {
        "ip": ip,
        "userAgent": c.req.header("user-agent") or "unknown",
        "acceptLanguage": c.req.header("accept-language"),
        "referer": c.req.header("referer"),
        "origin": c.req.header("origin"),
        "geo": geo or _unavailable(),
    }


async def processor(route, c):
    client = c.get("client")
    info = await get_client_info(c)

    return c.json({"clientId": client["id"], "scopes": client["scopes"], **info})


route = RouteDefinition(
    route_type="protected",
    method="get",
    middlewares=[
        query_parameter_limiter(max_parameters=0),
        no_body_limiter,
    ],
    processor=processor,
)
