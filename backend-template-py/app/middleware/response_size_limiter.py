"""
------------------------------------------------------------
Response size limiter
------------------------------------------------------------
"""

from __future__ import annotations

import math

from app.core.compose import Middleware
from app.core.context import Context
from app.core.http_exception import HTTPException
from app.helpers.err_handler import set_audit_error


def response_size_limiter(max_bytes: int) -> Middleware:
    """
    Prevents responses larger than ``max_bytes`` from being returned.

    The response is always fully buffered by the pipeline, so the actual body
    size can be checked.
    """
    if not isinstance(max_bytes, (int, float)) or not math.isfinite(max_bytes) or max_bytes <= 0:
        raise ValueError("maxBytes must be a positive number")

    async def middleware(c: Context, next):
        # Let the downstream middleware / route generate the response first.
        response = await next()

        # No response body.
        if not response.body:
            return response

        size = len(response.body)

        # Check actual byte size.
        if size > max_bytes:
            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": f"Response exceeds maximum size (accepted: {max_bytes}, reached {size} bytes)",
                    "code": "RESPONSE_SIZE",
                    "status": 413,
                },
            )

            raise HTTPException(413, message="Response exceeds maximum size, Refine your request")

        return response

    return middleware
