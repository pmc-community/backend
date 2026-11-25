# ------------------------------------------------------------
# Content-Type validation middleware
#
# General-purpose Content-Type protection.
#
# Policy:
#
#   - No body + no Content-Type          -> allowed
#   - No body + valid/allowed Content-Type -> allowed
#   - No body + invalid/unsupported Content-Type -> 415
#   - Body + no Content-Type             -> 415
#   - Body + invalid Content-Type        -> 415
#   - Body + unsupported Content-Type    -> 415
#
# NOTE: "body" means "the request declares a body" (Content-Length > 0 or
# Transfer-Encoding).  The original implementation tested
# `request.body !== null`, which @hono/node-server makes true for EVERY method
# except GET/HEAD - so CORS preflights (OPTIONS) and body-less POST/DELETE
# requests were rejected with 415 even though the policy above allows them.
# This port implements the policy as documented.
#
# Endpoint-specific body rules remain separate:
#   - no_body_limiter()   -> endpoint must not contain a body
#   - json_only_limiter() -> endpoint requires JSON
#
# Allowed Content-Types are loaded from data.ALLOWED_CONTENT_TYPE and remain
# hot-reloadable because the source list itself is not replaced.
#
# Content-Type parameters are ignored for matching:
#
#   application/json
#   application/json; charset=utf-8     -> application/json
#
# Wildcards such as image/* are NOT supported.
# ------------------------------------------------------------

from __future__ import annotations

import re
from typing import Optional

from app.core.compose import Middleware
from app.core.context import Context
from app.data_provider import data
from app.helpers.err_handler import set_audit_error

# Keep a reference to the mutable hot-reloadable list.
allowed_content_type_source = data.ALLOWED_CONTENT_TYPE

# RFC-style token / token validation.
#
# Accepted:  application/json, text/plain, multipart/form-data, application/problem+json
# Rejected:  sdfsdf, application/, /json, "application json"
_MEDIA_TYPE_PATTERN = re.compile(
    r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+/[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z"
)


def parse_media_type(value: Optional[str]) -> Optional[str]:
    """Parse and normalize a Content-Type header ('application/json; charset=utf-8' -> 'application/json')."""
    if value is None:
        return None

    trimmed = value.strip()

    if not trimmed:
        return None

    # Only the media type itself is relevant; parameters are ignored.
    media_type = trimmed.split(";")[0].strip()

    if not media_type:
        return None

    if not _MEDIA_TYPE_PATTERN.match(media_type):
        return None

    return media_type.lower()


def normalize_media_type(value: str) -> str:
    """
    Normalize a configured Content-Type.  Configuration errors are treated as
    configuration errors rather than silently ignored.
    """
    media_type = parse_media_type(value)

    if not media_type:
        raise RuntimeError(f"[content type] Invalid configured media type: {value}")

    return media_type


def content_type_limiter() -> Middleware:
    async def middleware(c: Context, next):
        content_type = c.req.header("Content-Type")
        has_body = c.req.has_declared_body

        # No body + no Content-Type (e.g. GET /users, HEAD /users)
        if not content_type and not has_body:
            return await next()

        # Body present but Content-Type missing.
        if not content_type and has_body:
            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": "Content-Type is required",
                    "code": "CONTENT_TYPE_ERR",
                    "status": 415,
                },
            )

            return c.json({"error": "Invalid request"}, 415)

        # Content-Type was supplied.  Validate it even when there is no body, so
        # "GET /users  Content-Type: sdfsdf" cannot bypass validation.
        media_type = parse_media_type(content_type)

        if not media_type:
            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": "Invalid Content-Type'",
                    "code": "CONTENT_TYPE_ERR",
                    "status": 415,
                },
            )

            return c.json({"error": "Invalid request"}, 415)

        # Build the allowed set from the current hot-reloaded source list.
        # Do NOT create this set at import time because ALLOWED_CONTENT_TYPE is
        # hot-reloaded.
        allowed_content_types = {normalize_media_type(v) for v in allowed_content_type_source}

        if media_type not in allowed_content_types:
            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": f"Unsupported Content-Type: {media_type}",
                    "code": "CONTENT_TYPE_ERR",
                    "status": 415,
                },
            )

            return c.json({"error": "Invalid request"}, 415)

        return await next()

    return middleware
