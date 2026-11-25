"""Security response headers (hono/secure-headers, default options)."""

from __future__ import annotations

from app.core.compose import Middleware
from app.core.context import Context

# Hono's defaults: everything on except Cross-Origin-Embedder-Policy;
# no CSP / Permissions-Policy; X-Powered-By removed.
_HEADERS: list[tuple[str, str]] = [
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Origin-Agent-Cluster", "?1"),
    ("Referrer-Policy", "no-referrer"),
    ("Strict-Transport-Security", "max-age=15552000; includeSubDomains"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-DNS-Prefetch-Control", "off"),
    ("X-Download-Options", "noopen"),
    ("X-Frame-Options", "SAMEORIGIN"),
    ("X-Permitted-Cross-Domain-Policies", "none"),
    ("X-XSS-Protection", "0"),
]


def secure_headers() -> Middleware:
    async def middleware(c: Context, next):
        response = await next()

        for name, value in _HEADERS:
            response.headers[name] = value

        if "x-powered-by" in response.headers:
            del response.headers["x-powered-by"]

        return response

    return middleware
