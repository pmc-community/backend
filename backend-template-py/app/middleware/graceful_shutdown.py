"""
Graceful shutdown is disabled for local dev.  To test it locally use:
  - DEPLOY_ENV=simprod
  - PROD_PORT=80
  - python main.py
  - send GET /test/slow from Postman and stop the server with CTRL-C
  - the request should finish with 200 and only then the server shuts down
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from app.core.compose import Middleware
from app.core.context import Context
from app.core.http_exception import HTTPException
from app.helpers.err_handler import set_audit_error
from app.helpers.js import env_int


@dataclass
class GracefulShutdownController:
    is_draining: Callable[[], bool]
    active_requests: Callable[[], int]
    start_draining: Callable[[], None]
    wait_for_drain: Callable[..., "asyncio.Future[bool]"]


def create_graceful_shutdown(
    status: int = 503,
    message: str = "Service is shutting down.",
    exclude_paths: Sequence[str] = (),
) -> tuple[Middleware, GracefulShutdownController]:
    excluded_paths = set(exclude_paths)

    state = {"draining": False, "active": 0}
    drain_resolver: list[Optional[Callable[[bool], None]]] = [None]

    async def middleware(c: Context, next):
        if c.req.path in excluded_paths:
            return await next()

        if state["draining"]:
            set_audit_error(
                c,
                {"name": "Warning", "message": message, "code": "GRACEFUL_SHUTDOWN", "status": 503},
            )

            raise HTTPException(status, message=message)

        state["active"] += 1

        try:
            return await next()
        finally:
            state["active"] -= 1

            if state["active"] == 0 and drain_resolver[0]:
                resolve = drain_resolver[0]
                drain_resolver[0] = None
                resolve(True)

    def start_draining() -> None:
        state["draining"] = True

    def wait_for_drain(timeout_ms: Optional[int] = None) -> "asyncio.Future[bool]":
        if timeout_ms is None:
            timeout_ms = env_int("GRSD_WAIT_FOR_DRAIN_MS", "3000")  # type: ignore[assignment]

        loop = asyncio.get_running_loop()
        future: "asyncio.Future[bool]" = loop.create_future()

        if state["active"] == 0:
            future.set_result(True)
            return future

        handle: list[Optional[asyncio.TimerHandle]] = [None]

        def finish(drained: bool) -> None:
            if future.done():
                return

            if handle[0]:
                handle[0].cancel()

            drain_resolver[0] = None
            future.set_result(drained)

        handle[0] = loop.call_later(timeout_ms / 1000, lambda: finish(False))  # type: ignore[operator]
        drain_resolver[0] = finish

        return future

    controller = GracefulShutdownController(
        is_draining=lambda: state["draining"],
        active_requests=lambda: state["active"],
        start_draining=start_draining,
        wait_for_drain=wait_for_drain,
    )

    return middleware, controller
