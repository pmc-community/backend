"""Equivalent of hono/http-exception."""

from __future__ import annotations

from typing import Any


class HTTPException(Exception):
    """
    Raised anywhere inside the middleware chain to short-circuit the request.

    The global error handler (see ``app.helpers.err_handler``) converts it to
    ``{"error": <message>}`` with ``status`` as the HTTP status code.
    """

    def __init__(
        self,
        status: int = 500,
        message: str = "",
        cause: Any = None,
        res: Any = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.cause = cause
        self.res = res

    @property
    def name(self) -> str:
        return "HTTPException"
