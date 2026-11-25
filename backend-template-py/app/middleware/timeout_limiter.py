# ------------------------------------------------------------
# Request timeout middleware
# ------------------------------------------------------------

from __future__ import annotations

import asyncio
import math
from typing import Mapping, Optional

from app.core.compose import Middleware
from app.core.context import Context
from app.core.http_exception import HTTPException
from app.helpers.err_handler import set_audit_error


def timeout_limiter(
    default_timeout_seconds: float,
    overrides: Optional[Mapping[str, float]] = None,
) -> Middleware:
    """
    Creates a request timeout middleware.

    The default timeout applies to every request unless the request path has an
    explicit timeout override.

        timeout_limiter(30, {"/r1": 1, "/api/import": 300})

        /r1          -> 1 second
        /api/import  -> 300 seconds
        everything else -> 30 seconds

    When the timeout is reached:
      - the ``requestSignal`` event (``c.get('requestSignal')``) is set, so
        downstream asynchronous operations can stop,
      - HTTPException(408) is raised and the global error handler formats the
        response.
    """
    overrides = dict(overrides or {})

    if not isinstance(default_timeout_seconds, (int, float)) or not math.isfinite(default_timeout_seconds) or default_timeout_seconds <= 0:
        raise ValueError("defaultTimeoutSeconds must be a positive number")

    for path, seconds in overrides.items():
        if not math.isfinite(seconds) or seconds <= 0:
            raise ValueError(f'Timeout for "{path}" must be a positive number')

    async def middleware(c: Context, next):
        timeout_seconds = overrides.get(c.req.path, default_timeout_seconds)

        # AbortSignal equivalent for downstream asynchronous operations.
        signal = asyncio.Event()
        c.set("requestSignal", signal)

        # Start the downstream request pipeline.
        task = asyncio.ensure_future(next())

        try:
            done, _ = await asyncio.wait({task}, timeout=timeout_seconds)
        except asyncio.CancelledError:
            task.cancel()
            raise

        if task in done:
            # next() completed normally (or failed, in which case it re-raises)
            return task.result()

        # Timeout: notify downstream operations that the request was cancelled.
        signal.set()

        def _log_late_failure(finished: "asyncio.Future") -> None:
            # The timeout has already produced the HTTP response.  Do not let a
            # late failure become an unhandled task exception.
            if finished.cancelled():
                return

            error = finished.exception()

            if error is not None:
                print("Request failed after timeout:", error)

        task.add_done_callback(_log_late_failure)

        set_audit_error(
            c,
            {
                "name": "Error",
                "message": f"Request timed out (accepted: {timeout_seconds} , reached {timeout_seconds} seconds)",
                "code": "TO_TIMEOUT",
                "status": 408,
            },
        )

        raise HTTPException(408, message="Timeout. Try again later")

    return middleware
