from app.core.context import Context
from app.core.http_exception import HTTPException
from app.helpers.err_handler import set_audit_error


def _number(value: str):
    try:
        return float(value)
    except ValueError:
        return float("nan")


async def no_body_limiter(c: Context, next):
    # Fast path: Content-Length header, if present, tells us immediately
    content_length = c.req.header("content-length")

    if content_length and _number(content_length) > 0:
        set_audit_error(
            c,
            {
                "name": "Error",
                "message": "Request body length identified in content-length header. Body is not allowed.",
                "code": "BODY_NOT_ALLOWED_HD",
                "status": 400,
            },
        )

        raise HTTPException(400, message="Bad request")

    # No body stream at all -> nothing to check, continue
    if not c.req.has_body_stream:
        return await next()

    # Fallback: actually drain the stream (covers chunked transfer-encoding,
    # where Content-Length may be absent)
    try:
        byte_length = len(await c.req.body())
    except Exception:  # noqa: BLE001
        set_audit_error(
            c,
            {
                "name": "Error",
                "message": "Invalid request. Body is not allowed.",
                "code": "BODY_NOT_ALLOWED",
                "status": 400,
            },
        )

        raise HTTPException(400, message="Invalid request")

    if byte_length > 0:
        set_audit_error(
            c,
            {
                "name": "Error",
                "message": "Request body not allowed",
                "code": "BODY_NOT_ALLOWED",
                "status": 400,
            },
        )

        raise HTTPException(400, message="Invalid request")

    return await next()
