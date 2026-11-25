"""Console request logger (hono/logger)."""

from __future__ import annotations

import os
import re
import sys
from typing import Callable

from app.core.compose import Middleware
from app.core.context import Context
from app.helpers.js import now_ms


def _humanize(times: list[str]) -> str:
    ordered = [re.sub(r"(\d)(?=(\d\d\d)+(?!\d))", r"\1,", v) for v in times]
    return ".".join(ordered)


def _time(start: float) -> str:
    delta = now_ms() - start
    return _humanize([f"{int(delta)}ms" if delta < 1000 else f"{round(delta / 1000)}s"])


def _color_enabled() -> bool:
    return "NO_COLOR" not in os.environ


def _color_status(status: int) -> str:
    if _color_enabled():
        group = status // 100
        code = {5: 31, 4: 33, 3: 36, 2: 32}.get(group)

        if code:
            return f"\x1b[{code}m{status}\x1b[0m"

    return str(status)


def logger(fn: Callable[[str], None] = print) -> Middleware:
    async def middleware(c: Context, next):
        method = c.req.method
        url = c.req.url
        path = url[url.index("/", 8):]

        fn(f"<-- {method} {path}")

        start = now_ms()
        response = await next()

        fn(f"--> {method} {path} {_color_status(response.status_code)} {_time(start)}")

        return response

    return middleware
