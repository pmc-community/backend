"""
Middleware composition with Hono semantics.

A middleware is ``async def mw(c, next) -> Response``.  Calling ``await next()``
runs everything downstream and returns its response; a middleware may return
its own response to short-circuit the chain, or post-process the response it
got from ``next()``.

Error handling mirrors Hono's ``compose``: an exception raised at some depth of
the chain is converted to a response by the error handler *at that depth*
(``app.onError``).  Middleware that sit further out therefore never see the
exception - they see the error response, exactly like in the original code.
"""

from __future__ import annotations

import inspect
from typing import Any, Awaitable, Callable

from starlette.responses import Response

from app.core.context import Context

Next = Callable[[], Awaitable[Response]]
Middleware = Callable[[Context, Next], Awaitable[Response]]
Handler = Callable[[Context], Any]
ErrorHandler = Callable[[Exception, Context], Any]


async def _resolve(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


async def run_chain(
    c: Context,
    middlewares: list[Middleware],
    handler: Handler,
    on_error: ErrorHandler,
) -> Response:
    async def dispatch(index: int) -> Response:
        try:
            if index >= len(middlewares):
                result = await _resolve(handler(c))
            else:

                async def call_next() -> Response:
                    return await dispatch(index + 1)

                result = await middlewares[index](c, call_next)

            if not isinstance(result, Response):
                raise TypeError(
                    "Middleware/handler did not return a Response "
                    f"(got {type(result).__name__})"
                )

            return result

        except Exception as error:  # noqa: BLE001 - mirrors Hono's onError
            return await _resolve(on_error(error, c))

    return await dispatch(0)
