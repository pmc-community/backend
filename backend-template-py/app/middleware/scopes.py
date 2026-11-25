"""
------------------------------------------------------------
Scope authorization middleware
------------------------------------------------------------
"""

from app.core.compose import Middleware
from app.core.context import Context
from app.core.http_exception import HTTPException
from app.helpers.err_handler import set_audit_error


def require_scope(*scopes: str) -> Middleware:
    async def middleware(c: Context, next):
        client = c.get("client")

        if not all(scope in client["scopes"] for scope in scopes):
            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": f"Insufficient_scope (required: {', '.join(scopes)} / provided: {', '.join(client['scopes'])})",
                    "code": "SCOPE_NOT_ENOUFH",
                    "status": 403,
                },
            )

            raise HTTPException(403, message="Insufficient scope")

        return await next()

    return middleware
