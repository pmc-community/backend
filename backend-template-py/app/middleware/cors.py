"""
------------------------------------------------------------
CORS (hono/cors configured as in the original cors.ts)
------------------------------------------------------------
"""

from __future__ import annotations

from typing import Callable, Optional, Sequence

from starlette.responses import Response

from app.core.compose import Middleware
from app.core.context import Context
from app.data_provider import data


def cors(
    *,
    origin: Callable[[str], Optional[str]],
    allow_methods: Sequence[str],
    allow_headers: Sequence[str],
    credentials: bool = False,
    expose_headers: Sequence[str] = (),
    max_age: Optional[int] = None,
) -> Middleware:
    # Same as hono: the method/header lists are joined once, when the
    # middleware is created; only the origin callback is evaluated per request.
    expose_headers_str = ",".join(expose_headers) if expose_headers else None
    allow_headers_str = ",".join(allow_headers) if allow_headers else None
    allow_methods_str = ",".join(allow_methods)

    async def middleware(c: Context, next):
        request_origin = c.req.header("origin") or ""
        allow_origin = origin(request_origin)

        headers: list[tuple[str, str]] = []

        if allow_origin:
            headers.append(("Access-Control-Allow-Origin", allow_origin))

        if credentials:
            headers.append(("Access-Control-Allow-Credentials", "true"))

        if expose_headers_str:
            headers.append(("Access-Control-Expose-Headers", expose_headers_str))

        # ---------------------------------------------------------------
        # Preflight
        # ---------------------------------------------------------------
        if c.req.method == "OPTIONS":
            response = c.apply_prepared_headers(Response(status_code=204))

            for name, value in headers:
                response.headers[name] = value

            response.headers.append("Vary", "Origin")  # origin is not "*"

            if max_age is not None:
                response.headers["Access-Control-Max-Age"] = str(max_age)

            if allow_methods_str:
                response.headers["Access-Control-Allow-Methods"] = allow_methods_str

            headers_str = allow_headers_str

            if not headers_str:
                requested = c.req.header("Access-Control-Request-Headers")

                if requested:
                    headers_str = ",".join(h.strip() for h in requested.split(","))

            if headers_str:
                response.headers["Access-Control-Allow-Headers"] = headers_str
                response.headers.append("Vary", "Access-Control-Request-Headers")

            for name in ("content-length", "content-type"):
                if name in response.headers:
                    del response.headers[name]

            return response

        # ---------------------------------------------------------------
        # Normal request
        # ---------------------------------------------------------------
        response = await next()

        for name, value in headers:
            response.headers[name] = value

        response.headers.append("Vary", "Origin")

        return response

    return middleware


def _origin(origin: str) -> Optional[str]:
    if not origin:
        return None

    return None if origin in data.BLOCKED_ORIGINS else origin


cors_settings: Middleware = cors(
    origin=_origin,
    allow_methods=data.ALLOW_METHODS,
    allow_headers=data.ALLOW_HEADERS,
    credentials=True,
)
