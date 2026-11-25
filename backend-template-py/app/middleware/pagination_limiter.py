from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from app.core.compose import Middleware
from app.core.context import Context
from app.core.http_exception import HTTPException
from app.helpers.err_handler import set_audit_error
from app.helpers.js import env_int, is_safe_integer

# ------------------------------------------------------------
# Pagination information stored in the request context
# (c.get('pagination'))
# ------------------------------------------------------------


@dataclass
class Pagination:
    limit: int
    page: Optional[int]
    offset: int


# ------------------------------------------------------------
# Defaults
# ------------------------------------------------------------

DEFAULT_MAX_LIMIT = env_int("PAGINATION_MAX_REC_PER_PAGE", "100")
DEFAULT_LIMIT = env_int("PAGINATION_DEFAULT_REC_PER_PAGE", "50")
DEFAULT_MAX_PAGE = env_int("PAGINATION_MAX_PAGES", "10000")
DEFAULT_MAX_OFFSET = env_int("PAGINATION_MAX_RECORDS", "1000000")

_DIGITS = re.compile(r"[0-9]+\Z", re.ASCII)


# ------------------------------------------------------------
# Positive / non-negative integer parsers
# ------------------------------------------------------------


def _parse_positive_integer(value: str, parameter: str) -> int:
    if not _DIGITS.match(value):
        raise HTTPException(400, message=f'"{parameter}" must be a positive integer')

    number = int(value)

    if not is_safe_integer(number) or number <= 0:
        raise HTTPException(400, message=f'"{parameter}" must be a positive integer')

    return number


def _parse_non_negative_integer(value: str, parameter: str) -> int:
    if not _DIGITS.match(value):
        raise HTTPException(400, message=f'"{parameter}" must be a non-negative integer')

    number = int(value)

    if not is_safe_integer(number) or number < 0:
        raise HTTPException(400, message=f'"{parameter}" must be a non-negative integer')

    return number


# ------------------------------------------------------------
# Pagination limiter
# ------------------------------------------------------------


def pagination_limiter(
    max_limit: Optional[int] = None,
    default_limit: Optional[int] = None,
    max_page: Optional[int] = None,
    max_offset: Optional[int] = None,
    page_parameter: str = "page",
    limit_parameter: str = "limit",
    offset_parameter: str = "offset",
    allow_page: bool = True,
    allow_offset: bool = True,
) -> Middleware:
    max_lim = max_limit if max_limit is not None else DEFAULT_MAX_LIMIT
    def_lim = default_limit if default_limit is not None else DEFAULT_LIMIT
    max_pg = max_page if max_page is not None else DEFAULT_MAX_PAGE
    max_off = max_offset if max_offset is not None else DEFAULT_MAX_OFFSET

    # Validate configuration
    if not is_safe_integer(max_lim) or max_lim <= 0:
        raise ValueError("maxLimit must be a positive safe integer")

    if not is_safe_integer(def_lim) or def_lim <= 0 or def_lim > max_lim:
        raise ValueError("defaultLimit must be a positive safe integer <= maxLimit")

    if not is_safe_integer(max_pg) or max_pg <= 0:
        raise ValueError("maxPage must be a positive safe integer")

    if not is_safe_integer(max_off) or max_off < 0:
        raise ValueError("maxOffset must be a non-negative safe integer")

    if not allow_page and not allow_offset:
        raise ValueError("At least one pagination mode must be enabled")

    def fail(c: Context, message: str, code: str, public_message: Optional[str] = None):
        set_audit_error(c, {"name": "Error", "message": message, "code": code, "status": 400})
        raise HTTPException(400, message=public_message or message)

    async def middleware(c: Context, next):
        params = c.req.search_params()

        def get_all(name: str) -> list[str]:
            return [v for k, v in params if k == name]

        def get(name: str) -> Optional[str]:
            values = get_all(name)
            return values[0] if values else None

        # ----- Reject duplicate pagination parameters -----
        if len(get_all(limit_parameter)) > 1:
            fail(c, f'Duplicate "{limit_parameter}" parameter', "PAG_DUPL_LIMIT")

        if allow_page and len(get_all(page_parameter)) > 1:
            fail(c, f'Duplicate "{page_parameter}" parameter', "PAG_DUPL_PAGE")

        if allow_offset and len(get_all(offset_parameter)) > 1:
            fail(c, f'Duplicate "{offset_parameter}" parameter', "PAG_DUPL_OFFSET")

        # ----- Parse limit -----
        limit_value = get(limit_parameter)

        limit = (
            def_lim
            if limit_value is None
            else _parse_positive_integer(limit_value, limit_parameter)
        )

        if limit > max_lim:
            fail(
                c,
                f'{limit_parameter}" exceeds the maximum allowed value (accepted: {max_lim}, reached {limit})',
                "PAG_LIMIT_MAX",
                f'"{limit_parameter}" exceeds the maximum allowed value',
            )

        # ----- Parse page -----
        page_value = get(page_parameter)
        page: Optional[int] = None

        if page_value is not None:
            if not allow_page:
                fail(
                    c,
                    f'"{page_parameter}" pagination is not supported',
                    "PAG_PAGE_NOT_SUPPORTED",
                )

            page = _parse_positive_integer(page_value, page_parameter)

            if page > max_pg:
                fail(
                    c,
                    f'"{page_parameter}" exceeds the maximum allowed value (accepted: {max_pg}, reached: {page})',
                    "PAG_PAGE_MAX",
                    f'"{page_parameter}" exceeds the maximum allowed value',
                )

        # ----- Parse offset -----
        offset_value = get(offset_parameter)
        offset = 0

        if offset_value is not None:
            if not allow_offset:
                fail(
                    c,
                    f'"{offset_parameter}" pagination is not supported',
                    "PAG_OFFSET_NOT_SUPPORTED",
                )

            offset = _parse_non_negative_integer(offset_value, offset_parameter)

        # ----- page and offset cannot be combined -----
        if page is not None and offset_value is not None:
            fail(
                c,
                f'"{page_parameter}" and "{offset_parameter}" cannot be used together',
                "PAG_PAGE_AND_OFFSET",
            )

        # ----- Convert page -> offset (page=1 -> 0, page=2 -> limit, ...) -----
        if page is not None:
            calculated_offset = (page - 1) * limit

            # Protect against unsafe integer calculations
            if not is_safe_integer(calculated_offset):
                fail(
                    c,
                    f'"{page_parameter}" results in an invalid offset',
                    "PAG_PAGE_INVALID_OFFSET",
                )

            # Prevent page pagination from bypassing the maximum offset restriction.
            if calculated_offset > max_off:
                fail(
                    c,
                    f'"{page_parameter}" results in an offset exceeding the maximum allowed value (max offset: {max_off}, calculated: {calculated_offset})',
                    "PAG_PAGE_EXCEED_OFFSET",
                    f'"{page_parameter}" results in an offset exceeding the maximum allowed value',
                )

            offset = calculated_offset

        # ----- Validate explicit offset -----
        if offset > max_off:
            fail(
                c,
                f'"{offset_parameter}" exceeds the maximum allowed value (max offset: {max_off}, required: {offset})',
                "PAG_PAGE_EXCEED_OFFSET",
                f'"{offset_parameter}" exceeds the maximum allowed value',
            )

        # ----- Store normalized pagination in the context -----
        c.set("pagination", Pagination(limit=limit, page=page, offset=offset))

        return await next()

    return middleware
