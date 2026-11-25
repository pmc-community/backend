"""
------------------------------------------------------------
API key authentication middleware
------------------------------------------------------------
"""

from __future__ import annotations

from app.core.compose import Middleware
from app.core.context import Context
from app.core.http_exception import HTTPException
from app.helpers.err_handler import set_audit_error
from app.helpers.js import env_int, now_ms
from app.helpers.utilities import get_client_ip
from app.keystore.app_keys import hash_key
from app.keystore.provider import keystore_provider
from app.shared_types import AuthFailureEntry, auth_failures

_keystore = keystore_provider()
get_api_key = getattr(_keystore, "get_api_key", None)


# only API key routes needs auth failure limits protection
# these are defined later
def record_auth_failure(ip: str) -> None:
    now = now_ms()
    window_ms = env_int("rqFailuresInterval", "15") * env_int("minuteInMs", "60000")
    entry = auth_failures.get(ip)

    if entry is None or now > entry.reset:
        auth_failures[ip] = AuthFailureEntry(count=1, reset=now + window_ms)
    else:
        entry.count += 1


async def api_key_auth(c: Context, next):
    # we use X-Api-Key to authorize api requests because the Authorization
    # header may be used to send access tokens or authorization codes
    # retrieved through the browser part of a login flow

    auth_header = c.req.header("X-Api-Key")
    key = auth_header[7:] if auth_header and auth_header.startswith("Bearer ") else None

    ip = get_client_ip(c) or "unknown"

    if not key:
        record_auth_failure(ip)

        set_audit_error(
            c,
            {"name": "Error", "message": "Missing API key", "code": "AUTH_API_KEY", "status": 401},
        )

        raise HTTPException(401, message="Request not authorized")

    # ----------------------------------------------------------
    # Hash the supplied raw API key.
    #
    # get_api_key() is the storage abstraction.
    #   Local:      JSON -> cached dict -> lookup
    #   Production: database -> indexed key_hash lookup
    # ----------------------------------------------------------

    if not get_api_key:
        raise HTTPException(
            500, message="Something wrong happen when reading API Key with getAPIKey"
        )

    key_hash = await hash_key(key)
    client = await get_api_key(key_hash)

    if not client:
        record_auth_failure(ip)

        set_audit_error(
            c,
            {"name": "Error", "message": "Invalid API key", "code": "AUTH_API_KEY", "status": 401},
        )

        raise HTTPException(401, message="Not authorized")

    c.set("client", {"id": client.clientId, "scopes": client.scopes})

    return await next()
