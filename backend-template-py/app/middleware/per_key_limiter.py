"""
------------------------------------------------------------
Per-key rate limiter
------------------------------------------------------------
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from app.core.compose import Middleware
from app.core.context import Context
from app.core.http_exception import HTTPException
from app.helpers.err_handler import set_audit_error
from app.helpers.js import env_int, is_safe_integer, now_ms


@dataclass
class _Entry:
    count: int
    window_start: float


def per_key_rate_limiter(max_requests_per_minute: int) -> Middleware:
    window_ms = env_int("minuteInMs", "60000")

    # Validate configuration
    if not is_safe_integer(max_requests_per_minute) or max_requests_per_minute <= 0:
        raise ValueError("maxRequestsPerMinute must be a positive safe integer")

    # One counter per client
    clients: dict[str, _Entry] = {}

    async def middleware(c: Context, next):
        client = c.get("client")

        if not client or not client.get("id"):
            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": "Authentication required",
                    "code": "AUTH_NEEDED",
                    "status": 401,
                },
            )

            raise HTTPException(401, message="Authentication required")

        key = client["id"]
        now = now_ms()

        entry = clients.get(key)

        # Start a new one-minute window
        if entry is None or now - entry.window_start >= window_ms:
            entry = _Entry(count=0, window_start=now)
            clients[key] = entry

        # Rate limit exceeded
        if entry.count >= max_requests_per_minute:
            retry_after_ms = window_ms - (now - entry.window_start)

            c.header("Retry-After", str(math.ceil(retry_after_ms / 1000)))

            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": f"Authentication rate limit exceeded (accepted: {max_requests_per_minute}, reached; {entry.count})",
                    "code": "AUTH_LIMITS",
                    "status": 429,
                },
            )

            raise HTTPException(429, message="Too many requests. Try again later.")

        # Consume request
        entry.count += 1

        return await next()

    return middleware
