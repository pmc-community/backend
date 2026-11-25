"""
------------------------------------------------------------
Concurrency Limiter
Limits simultaneous requests per client.
------------------------------------------------------------
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from app.core.compose import Middleware
from app.core.context import Context
from app.helpers.err_handler import set_audit_error
from app.helpers.js import env_int, is_integer


def concurrency_limiter(
    key: Callable[[Context], str],
    max_concurrent: Optional[int] = None,
    status: int = 429,
    on_reject: Optional[Callable[[dict], Any]] = None,
) -> Middleware:
    """
    :param key: resolves the identity used for concurrency tracking
                (authenticated client -> client.id, otherwise client IP).
    :param max_concurrent: maximum number of simultaneous requests per key.
    :param status: HTTP status returned when the limit is exceeded (429 or 503).
    :param on_reject: called whenever a request is rejected.
    """
    maximum = max_concurrent if max_concurrent is not None else env_int("CO_MAX_ALLOWED", "10")

    if not is_integer(maximum) or maximum < 1:
        raise ValueError("concurrencyLimiter: maxConcurrent must be an integer >= 1")

    counters: dict[str, int] = {}

    async def middleware(c: Context, next):
        client_key = key(c)

        if not client_key:
            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": "unable_to_identify_client",
                    "code": "CONCURRENCY_LIMIT",
                    "status": 400,
                },
            )

            return c.json(
                {"error": "unable_to_identify_client", "message": "Unknown request identity"},
                400,
            )

        active = counters.get(client_key, 0)

        if active >= maximum:
            event = {
                "type": "concurrency_limit",
                "key": client_key,
                "current": active,
                "limit": maximum,
                "path": c.req.path,
                "method": c.req.method,
            }

            if on_reject:
                on_reject(event)

            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": f"too many concurrent requests (accepted: {maximum}, reached: {active})",
                    "code": "CONCURRENCY_LIMIT",
                    "status": status,
                },
            )

            return c.json({"error": "Server busy, try again later."}, status)

        counters[client_key] = active + 1

        try:
            return await next()
        finally:
            counters[client_key] -= 1

            if counters[client_key] == 0:
                del counters[client_key]

    return middleware
