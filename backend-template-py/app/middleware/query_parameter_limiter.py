from __future__ import annotations

from typing import Optional

from app.core.compose import Middleware
from app.core.context import Context
from app.core.http_exception import HTTPException
from app.helpers.err_handler import set_audit_error
from app.helpers.js import env_int

# ------------------------------------------------------------
# Query parameter limiter
# ------------------------------------------------------------

DEFAULT_MAX_PARAMETERS = env_int("DEFAULT_MAX_QUERY_PARAMETERS", "20")
DEFAULT_MAX_KEY_LENGTH = env_int("DEFAULT_MAX_QUERY_KEY_LENGTH", "100")
DEFAULT_MAX_VALUE_LENGTH = env_int("DEFAULT_MAX_QUERY_VALUE_LENGTH", "2000")
DEFAULT_MAX_QUERY_STRING_LENGTH = env_int("DEFAULT_MAX_QUERY_STRING_LENGTH", "4000")


def query_parameter_limiter(
    max_parameters: Optional[int] = None,
    max_key_length: Optional[int] = None,
    max_value_length: Optional[int] = None,
    max_query_string_length: Optional[int] = None,
) -> Middleware:
    max_params = max_parameters if max_parameters is not None else DEFAULT_MAX_PARAMETERS
    max_key = max_key_length if max_key_length is not None else DEFAULT_MAX_KEY_LENGTH
    max_value = max_value_length if max_value_length is not None else DEFAULT_MAX_VALUE_LENGTH
    max_query = (
        max_query_string_length
        if max_query_string_length is not None
        else DEFAULT_MAX_QUERY_STRING_LENGTH
    )

    async def middleware(c: Context, next):
        query_string = c.req.search

        # Total query-string size
        if len(query_string) > max_query:
            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": f"Query string too long (accepted:{max_query} provided:{len(query_string)})",
                    "code": "QP_QSTRING_TOO_LONG",
                    "status": 414,
                },
            )

            raise HTTPException(414, message="invalid request format")

        # Parameter count
        parameters = c.req.search_params()

        if len(parameters) > max_params:
            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": f"Too many query parameters (accepted:{max_params} provided:{len(parameters)})",
                    "code": "QP_TOO_MANY",
                    "status": 400,
                },
            )

            raise HTTPException(400, message="Invalid request format")

        # Individual parameter validation
        for key, value in parameters:
            if len(key) > max_key:
                set_audit_error(
                    c,
                    {
                        "name": "Error",
                        "message": f"Query parameter name too long ({len(key)})",
                        "code": "QP_NAME_TOO_LONG",
                        "status": 400,
                    },
                )

                raise HTTPException(400, message="Invalid request format")

            if len(value) > max_value:
                set_audit_error(
                    c,
                    {
                        "name": "Error",
                        "message": f"Query parameter value too long ({len(value)})",
                        "code": "QP_VALUE_TOO_LONG",
                        "status": 400,
                    },
                )

                raise HTTPException(400, message="Invalid request format")

        return await next()

    return middleware
