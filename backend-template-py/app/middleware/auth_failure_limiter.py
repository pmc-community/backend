"""
------------------------------------------------------------
Failed authentication rate limiting
------------------------------------------------------------
"""

from app.core.context import Context
from app.helpers.err_handler import set_audit_error
from app.helpers.js import env_int, now_ms
from app.helpers.utilities import get_client_ip
from app.shared_types import auth_failures


async def auth_failure_limiter(c: Context, next):
    ip = get_client_ip(c) or "unknown"
    now = now_ms()
    maximum = env_int("maxRqAuthFailures", "10")
    entry = auth_failures.get(ip)

    if entry and now < entry.reset and entry.count >= maximum:
        set_audit_error(
            c,
            {
                "name": "Error",
                "message": f"Too many failed auth attempts ({entry.count})",
                "code": "AUTH_FAIL_LIMITS",
                "status": 429,
            },
        )

        return c.json({"error": "Authorization problem, try again later"}, 429)

    return await next()
