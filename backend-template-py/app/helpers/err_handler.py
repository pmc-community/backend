"""
------------------------------------------------------------
Structured error handling
------------------------------------------------------------
"""

from __future__ import annotations

import traceback
from typing import Any

from starlette.responses import Response

from app.core.context import Context
from app.core.http_exception import HTTPException
from app.shared_types import AuditError


def err_handler(err: Exception, c: Context) -> Response:
    """``app.onError``: HTTPException -> {"error": message}, anything else -> 500."""
    if isinstance(err, HTTPException):
        return c.json({"error": err.message}, err.status)

    traceback.print_exception(type(err), err, err.__traceback__)

    return c.json({"error": "Internal server error"}, 500)


def set_audit_error(c: Context, error: AuditError) -> None:
    c.set("auditError", error)


def z_validator_error(result: dict, c: Context) -> Response | None:
    """
    Validation hook (the equivalent of the zValidator hook).

    ``result`` is ``{"success": bool, "issues": [{code, path, message}, ...]}``.
    """
    if not result["success"]:
        print("[Validation]", result["issues"])

        set_audit_error(
            c,
            {
                "name": "ZodError",
                "message": "Request body validation failed. Bad JSON.",
                "code": "VALIDATION_FAILED",
                "status": 400,
                "details": [
                    {
                        "code": issue["code"],
                        "path": issue["path"],
                        "message": issue["message"],
                    }
                    for issue in result["issues"]
                ],
            },
        )

        return c.json({"error": "Invalid request"}, 400)

    return None


def ip_restriction_error(remote: Any, c: Context) -> Response:
    print(f"Access denied for IP {remote['addr']}")

    set_audit_error(
        c,
        {
            "name": "IPRestrictionError",
            "message": f"Access denied for IP {remote['addr']}",
            "code": "IP_NOT_ALLOWED",
            "status": 403,
        },
    )

    raise HTTPException(403, message="Not allowed")
