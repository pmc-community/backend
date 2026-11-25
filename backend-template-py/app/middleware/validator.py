"""
Body validation middleware (the equivalent of ``zValidator('json', schema, hook)``
from @hono/zod-validator, built on hono's ``validator('json', ...)``).
"""

from __future__ import annotations

import re
from typing import Any, Callable, Optional, Type

from pydantic import BaseModel
from starlette.responses import Response

from app.config.body_schemas import safe_parse
from app.core.compose import Middleware
from app.core.context import Context
from app.core.http_exception import HTTPException

_JSON_REGEX = re.compile(
    r"^application\/([a-z-\.]+\+)?json(;\s*[a-zA-Z0-9\-]+\=([^;]+))*\Z", re.IGNORECASE
)


def z_validator(
    target: str,
    schema: Type[BaseModel],
    hook: Optional[Callable[[dict, Context], Optional[Response]]] = None,
) -> Middleware:
    if target != "json":
        raise ValueError("Only the 'json' target is implemented")

    async def middleware(c: Context, next):
        value: Any = {}
        content_type = c.req.header("Content-Type")

        # Not a JSON content type -> validate an empty object (it will normally fail).
        if content_type and _JSON_REGEX.match(content_type):
            try:
                value = await c.req.json()
            except ValueError:
                raise HTTPException(400, message="Malformed JSON in request body")

        result = safe_parse(schema, value)

        if hook:
            hook_result = hook({"data": value, "target": target, **result}, c)

            if isinstance(hook_result, Response):
                return hook_result

        if not result["success"]:
            return c.json(result, 400)

        c.set(f"valid:{target}", result["data"])

        return await next()

    return middleware
