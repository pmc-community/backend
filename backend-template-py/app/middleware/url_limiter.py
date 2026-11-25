from __future__ import annotations

from typing import Optional

from app.core.compose import Middleware
from app.core.context import Context
from app.core.http_exception import HTTPException
from app.helpers.err_handler import set_audit_error
from app.helpers.js import env_int, is_integer

# ------------------------------------------------------------
# Path / URL length limiter
# ------------------------------------------------------------

DEFAULT_MAX_LENGTH = env_int("MAX_URL_LENGTH", "1024")


def url_length_limiter(
    max_length: Optional[int] = None,
    include_query: bool = True,
) -> Middleware:
    """
    :param max_length: maximum allowed URL length in characters.
    :param include_query: True = pathname + query string, False = pathname only.
    """
    maximum = max_length if max_length is not None else DEFAULT_MAX_LENGTH

    if not is_integer(maximum) or maximum <= 0:
        raise ValueError("maxLength must be a positive integer")

    async def middleware(c: Context, next):
        value = f"{c.req.pathname}{c.req.search}" if include_query else c.req.pathname

        if len(value) > maximum:
            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": f"URI Too Long (accepted: {maximum}, got: {len(value)})",
                    "code": "URL_SIZE",
                    "status": 414,
                },
            )

            raise HTTPException(414, message="Bad request URL")

        return await next()

    return middleware
