from __future__ import annotations

from typing import Optional

from app.core.compose import Middleware
from app.core.context import Context
from app.core.http_exception import HTTPException
from app.helpers.err_handler import set_audit_error
from app.helpers.js import env_int, is_integer

# ------------------------------------------------------------
# Request header limiter
#
# Protects against:
# - Excessively large individual headers
# - Excessively large total headers
# - Excessive number of headers
#
# Limits are configurable per middleware instance.
#
# Defaults:
#   max_header_bytes       = 16 KB total
#   max_header_value_bytes = 8 KB per header
#   max_header_count       = 50 headers
# ------------------------------------------------------------

DEFAULT_MAX_HEADER_BYTES = env_int("DEFAULT_MAX_HEADER_BYTES", "16") * 1024
DEFAULT_MAX_HEADER_VALUE_BYTES = env_int("DEFAULT_MAX_HEADER_VALUE_BYTES", "8") * 1024
DEFAULT_MAX_HEADER_COUNT = env_int("DEFAULT_MAX_HEADER_COUNT", "50")


def header_size_limiter(
    max_header_bytes: Optional[int] = None,
    max_header_value_bytes: Optional[int] = None,
    max_header_count: Optional[int] = None,
) -> Middleware:
    max_total = max_header_bytes if max_header_bytes is not None else DEFAULT_MAX_HEADER_BYTES
    max_value = max_header_value_bytes if max_header_value_bytes is not None else DEFAULT_MAX_HEADER_VALUE_BYTES
    max_count = max_header_count if max_header_count is not None else DEFAULT_MAX_HEADER_COUNT

    if not is_integer(max_total) or max_total <= 0:
        raise ValueError("maxHeaderBytes must be a positive integer")

    if not is_integer(max_value) or max_value <= 0:
        raise ValueError("maxHeaderValueBytes must be a positive integer")

    if not is_integer(max_count) or max_count <= 0:
        raise ValueError("maxHeaderCount must be a positive integer")

    async def middleware(c: Context, next):
        header_count = 0
        total_bytes = 0

        for name, value in c.req.header_items():
            header_count += 1

            # Count the header name and value using UTF-8 byte length.
            name_bytes = len(name.encode("utf-8"))
            value_bytes = len(value.encode("utf-8"))

            # Header count
            if header_count > max_count:
                set_audit_error(
                    c,
                    {
                        "name": "Error",
                        "message": f"Too many request headers (accepted: {max_count}, received: {header_count})",
                        "code": "HD_TOO_MANY",
                        "status": 400,
                    },
                )

                raise HTTPException(400, message="Bad headers")

            # Individual header value
            if value_bytes > max_value:
                set_audit_error(
                    c,
                    {
                        "name": "Error",
                        "message": f"Request header value is too large (accepted: {max_value}, received: {value_bytes})",
                        "code": "HD_TOO_LARGE",
                        "status": 400,
                    },
                )

                raise HTTPException(400, message="Bad headers")

            # Include a conservative representation of:  name: value\r\n
            total_bytes += name_bytes + value_bytes + 4

            # Total headers
            if total_bytes > max_total:
                set_audit_error(
                    c,
                    {
                        "name": "Error",
                        "message": f"Request headers are too large (accepted: {max_total}, received: {total_bytes})",
                        "code": "HD_TOTAL_TOO_LARGE",
                        "status": 400,
                    },
                )

                raise HTTPException(400, message="Bad headers")

        return await next()

    return middleware
