# ------------------------------------------------------------
# Request size limit middleware
#
# Measures the actual number of bytes received from the request body.
#
# The body is cached while it is read, so downstream middleware and the route
# handler (validators, c.req.json(), ...) can still read it.
#
# IMPORTANT: this middleware must run BEFORE anything that consumes the
# request body.
# ------------------------------------------------------------

from app.core.compose import Middleware
from app.core.context import BodyTooLarge, Context
from app.core.http_exception import HTTPException
from app.helpers.err_handler import set_audit_error
from app.helpers.js import is_safe_integer


def size_limiter(max_bytes: int) -> Middleware:
    """Restrict the maximum request body size (HTTP 413 when exceeded)."""
    if not is_safe_integer(max_bytes) or max_bytes <= 0:
        raise ValueError("sizeLimit maxBytes must be a positive safe integer")

    async def middleware(c: Context, next):
        # No body means nothing to limit.
        if not c.req.has_body_stream:
            return await next()

        # Count the actual bytes received, rejecting as soon as the actual body
        # exceeds the configured limit.
        try:
            await c.req.read_limited(max_bytes)

        except BodyTooLarge as error:
            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": f"request too large (accepted: {max_bytes}, reached: {error.bytes_read})",
                    "code": "RQ_SIZE",
                    "status": 413,
                },
            )

            raise HTTPException(413, message="Bad request size")

        except Exception:  # noqa: BLE001 - body could not be read correctly
            set_audit_error(
                c,
                {
                    "name": "Error",
                    "message": "invalid request body",
                    "code": "RQ_SIZE",
                    "status": 400,
                },
            )

            raise HTTPException(400, message="Bad request body")

        return await next()

    return middleware
