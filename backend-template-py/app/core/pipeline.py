"""
Global middleware pipeline (the equivalent of ``app.use('*', ...)``).

It is a pure ASGI middleware that wraps the whole FastAPI application - 404s
included, like Hono's ``app.use('*')`` - and runs the Hono-style chain around
the router.  The router response is captured (buffered) so that the outer
middleware (audit logger, circuit breaker, CORS, secure headers, response size
limiter, ...) can inspect and post-process it.
"""

from __future__ import annotations

from starlette.responses import Response
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.compose import ErrorHandler, Middleware, run_chain
from app.core.context import Context, make_response

CONTEXT_SCOPE_KEY = "app_ctx"


async def _capture(app: ASGIApp, scope: Scope, receive: Receive) -> Response:
    """Run an ASGI app and capture its output as a Response object."""
    status = 500
    raw_headers: list[tuple[bytes, bytes]] = []
    chunks: list[bytes] = []

    async def capture_send(message) -> None:
        nonlocal status, raw_headers

        if message["type"] == "http.response.start":
            status = message["status"]
            raw_headers = list(message.get("headers", []))

        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    await app(scope, receive, capture_send)

    return make_response(b"".join(chunks), status, raw_headers)


class PipelineMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        middlewares: list[Middleware],
        on_error: ErrorHandler,
    ) -> None:
        self.app = app
        self.middlewares = middlewares
        self.on_error = on_error

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        c = Context(scope, receive)
        scope[CONTEXT_SCOPE_KEY] = c

        async def router(ctx: Context) -> Response:
            response = await _capture(self.app, scope, receive)

            # Headers prepared with c.header() (X-Request-Id, ...) must also be
            # present on responses that were not built through the context.
            return ctx.apply_prepared_headers(response, only_missing=True)

        response = await run_chain(c, self.middlewares, router, self.on_error)

        await response(scope, receive, send)
