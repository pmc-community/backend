"""
------------------------------------------------------------
Rate limiting - defined in .env
to be used as rate_limiter(<max_no_of_requests/minute/IP>)

- can be applied as general:  rate_limiter(100) in the global chain
- can be overwritten in a specific route: add rate_limiter(5) to its middlewares
------------------------------------------------------------
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.compose import Middleware
from app.core.context import Context
from app.helpers.err_handler import set_audit_error
from app.helpers.js import env_int, is_safe_integer, now_ms
from app.helpers.utilities import get_client_ip


@dataclass
class _Entry:
    count: int
    reset: float


_rate_limits: dict[str, _Entry] = {}


def rate_limiter(max_rq_per_min: int) -> Middleware:
    if not is_safe_integer(max_rq_per_min) or max_rq_per_min <= 0:
        raise ValueError("rateLimiter maxRqPerMin must be a positive safe integer")

    async def middleware(c: Context, next):
        ip = get_client_ip(c) or "unknown"

        now = now_ms()
        window_ms = env_int("minuteInMs", "60000")

        entry = _rate_limits.get(ip)

        if entry is None or now > entry.reset:
            _rate_limits[ip] = _Entry(count=1, reset=now + window_ms)
        else:
            entry.count += 1

            if entry.count > max_rq_per_min:
                set_audit_error(
                    c,
                    {
                        "name": "Error",
                        "message": f"Too many requests (accepted:{max_rq_per_min} reached:{entry.count})",
                        "code": "RATE_LIMIT_EXEEDED",
                        "status": 429,
                    },
                )

                return c.json({"error": "Too many requests"}, 429)

        return await next()

    return middleware
