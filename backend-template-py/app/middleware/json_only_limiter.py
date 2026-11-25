from app.core.context import Context
from app.helpers.err_handler import set_audit_error


async def json_only_limiter(c: Context, next):
    if not c.req.has_body_stream:
        set_audit_error(
            c,
            {"name": "Error", "message": "JSON body required", "code": "BODY_JSON_ONLY", "status": 400},
        )

        return c.json({"error": "Bad request body"}, 400)

    try:
        await c.req.json()
    except Exception:  # noqa: BLE001 - invalid JSON or unreadable body
        set_audit_error(
            c,
            {
                "name": "Error",
                "message": "Invalid JSON payload",
                "code": "BODY_JSON_ONLY_STRUCT",
                "status": 400,
            },
        )

        return c.json({"error": "Bad request body"}, 400)

    return await next()
