from __future__ import annotations

from typing import Optional

from app.core.compose import Middleware
from app.core.context import Context
from app.core.http_exception import HTTPException
from app.data_provider import data
from app.data_provider.list_provider import ListProvider
from app.helpers.err_handler import set_audit_error

# ------------------------------------------------------------
# Duplicate Header Protection
#
#   protected_headers    - headers for which duplicate occurrences are rejected
#                          (case-insensitive).  A ListProvider, so large or
#                          external lists never need to be pulled fully into
#                          memory - membership is checked via has().
#   allowed_headers      - headers that may legitimately occur multiple times
#   reject_all_duplicates- reject every duplicate header (default: False)
#   status / message     - response status (default 400) / message
#
# Source of truth lives in data/duplicateHeaderProtection/*.txt (edit those
# files to add/remove entries - no redeploy needed, the provider picks up
# changes on its own reload-check interval).
# ------------------------------------------------------------

DEFAULT_PROTECTED_HEADERS = data.DEFAULT_PROTECTED_HEADERS
DEFAULT_ALLOWED_HEADERS = data.DEFAULT_ALLOWED_HEADERS


# ------------------------------------------------------------
# Find duplicate headers
#
# Uses the headers exactly as received (not the combined view), because
# c.req.header() already merges duplicates.
# ------------------------------------------------------------


def _get_duplicate_headers(raw_headers: list[tuple[str, str]]) -> dict[str, int]:
    counts: dict[str, int] = {}

    for name, _ in raw_headers:
        if not name:
            continue

        normalized = name.strip().lower()
        counts[normalized] = counts.get(normalized, 0) + 1

    return {name: count for name, count in counts.items() if count > 1}


def duplicate_header_protection(
    protected_headers: Optional[ListProvider] = DEFAULT_PROTECTED_HEADERS,
    allowed_headers: Optional[ListProvider] = DEFAULT_ALLOWED_HEADERS,
    reject_all_duplicates: bool = False,
    status: int = 400,
    message: str = "Invalid request headers.",
) -> Middleware:
    async def middleware(c: Context, next):
        duplicates = _get_duplicate_headers(c.req.raw_headers)

        if not duplicates:
            return await next()

        rejected: list[str] = []

        for header in duplicates:
            # Explicitly allowed duplicate.
            if allowed_headers is not None and await allowed_headers.has(header):
                continue

            # Security-sensitive header.
            if protected_headers is not None and await protected_headers.has(header):
                rejected.append(header)
                continue

            # Optional strict mode.
            if reject_all_duplicates:
                rejected.append(header)
                continue

            # Otherwise ignore the duplicate.

        if not rejected:
            return await next()

        set_audit_error(
            c,
            {"name": "Error", "message": message, "code": "HD_DUPL", "status": 400},
        )

        raise HTTPException(status, message=message)

    return middleware
