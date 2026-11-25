"""Request ID middleware (hono/request-id)."""

from __future__ import annotations

import re
import uuid
from typing import Callable, Optional

from app.core.compose import Middleware
from app.core.context import Context

_INVALID = re.compile(r"[^\w\-=]", re.ASCII)


def request_id(
    limit_length: int = 255,
    header_name: Optional[str] = "X-Request-Id",
    generator: Optional[Callable[[Context], str]] = None,
) -> Middleware:
    generate = generator or (lambda c: str(uuid.uuid4()))

    async def middleware(c: Context, next):
        req_id = c.req.header(header_name) if header_name else None

        if not req_id or len(req_id) > limit_length or _INVALID.search(req_id):
            req_id = generate(c)

        c.set("requestId", req_id)

        if header_name:
            c.header(header_name, req_id)

        return await next()

    return middleware
