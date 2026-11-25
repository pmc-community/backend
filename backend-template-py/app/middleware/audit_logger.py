from __future__ import annotations

import re
import time
import traceback
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from app.core.compose import Middleware
from app.core.context import Context
from app.core.http_exception import HTTPException
from app.data_provider import data
from app.helpers.js import env_int
from app.helpers.server_log import log_event
from app.helpers.utilities import ServerIdentity, get_client_ip
from app.shared_types import (
    AuditError,
    AuditLogEvent,
    HeaderAnomaly,
    HeaderAnomalyOptions,
)

# ------------------------------------------------------------
# Defaults
# ------------------------------------------------------------

DEFAULT_SLOW_REQUEST_MS = env_int("DEFAULT_SLOW_RESPONSE", "1000")

import os

DEFAULT_INCLUDE_STACK = os.environ.get("NODE_ENV") != "production"

# ------------------------------------------------------------
# Header anomaly defaults
#
# This is NOT a strict allow-list.  Many perfectly legitimate clients/proxies
# use headers that are not listed here.  "Unexpected" therefore means "header
# is outside the normal API header vocabulary" and is treated as LOW severity.
# ------------------------------------------------------------

DEFAULT_LOG_HEADERS = data.DEFAULT_LOG_HEADERS
DEFAULT_EXPECTED_HEADERS = data.DEFAULT_EXPECTED_HEADERS
DEFAULT_SUSPICIOUS_HEADERS = data.DEFAULT_SUSPICIOUS_HEADERS
FORWARDING_HEADERS = data.FORWARDING_HEADERS


# ------------------------------------------------------------
# Sanitizers
# ------------------------------------------------------------


def sanitize_error_message(message: str) -> str:
    message = re.sub(r"[\r\n\t]+", " ", message)
    message = re.sub(r"\s+", " ", message)
    return message.strip()[:2000]


def sanitize_error_name(name: str) -> str:
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_$.-]{0,100}", name):
        return name

    return "Error"


def sanitize_error_code(code: str) -> str:
    if re.fullmatch(r"[A-Z][A-Z0-9_.-]{0,100}", code):
        return code

    return "UNKNOWN_ERROR"


def sanitize_stack(stack: str) -> str:
    return "\n".join(stack.replace("\r", "").split("\n")[:20])[:5000]


def sanitize_header_value(value: str) -> str:
    return re.sub(r"[\r\n\t]+", " ", value)[:2000]


# ------------------------------------------------------------
# HTTP status descriptions
# ------------------------------------------------------------

_STATUS_DESCRIPTIONS = {
    400: "Bad Request",
    401: "Authentication required",
    403: "Forbidden",
    404: "Resource not found",
    405: "Method not allowed",
    408: "Request timeout",
    409: "Conflict",
    413: "Request entity too large",
    415: "Unsupported media type",
    422: "Unprocessable entity",
    429: "Too many requests",
    500: "Internal server error",
    501: "Not implemented",
    502: "Bad gateway",
    503: "Service unavailable",
    504: "Gateway timeout",
}


def get_http_status_description(status: int) -> str:
    return _STATUS_DESCRIPTIONS.get(status, f"HTTP {status}")


def _stack_of(error: BaseException) -> str:
    return "".join(traceback.format_exception(type(error), error, error.__traceback__))


# ------------------------------------------------------------
# Set structured audit error
# ------------------------------------------------------------


def set_audit_error(
    c: Context,
    message: str,
    name: Optional[str] = None,
    code: Optional[str] = None,
    status: Optional[int] = None,
    stack: Optional[str] = None,
) -> None:
    error: AuditError = {
        "name": sanitize_error_name(name or "Error"),
        "message": sanitize_error_message(message),
    }

    if code:
        error["code"] = sanitize_error_code(code)

    error["status"] = status if status is not None else 500

    if stack:
        error["stack"] = sanitize_stack(stack)

    c.set("auditError", error)


def set_audit_error_from_exception(
    c: Context,
    error: Any,
    code: Optional[str] = None,
    status: Optional[int] = None,
    name: Optional[str] = None,
) -> None:
    """Convenience helper for exception instances."""
    if isinstance(error, HTTPException):
        set_audit_error(
            c,
            message=error.message or get_http_status_description(error.status),
            name=name or "HTTPException",
            code=code,
            status=status if status is not None else error.status,
            stack=_stack_of(error),
        )
        return

    if isinstance(error, Exception):
        set_audit_error(
            c,
            message=str(error) or "An error occurred",
            name=name or type(error).__name__,
            code=code,
            status=status if status is not None else 500,
            stack=_stack_of(error),
        )
        return

    set_audit_error(
        c,
        message="An unknown error was thrown",
        name=name or "UnknownError",
        code=code,
        status=status if status is not None else 500,
    )


# ============================================================
# Header anomaly detection
# ============================================================


def _is_forwarding_header(name: str) -> bool:
    return name in FORWARDING_HEADERS


def _is_method_override_header(name: str) -> bool:
    return name in ("x-http-method-override", "x-http-method", "x-method-override")


def _has_suspicious_duplicate_values(value: str) -> bool:
    values = [item.strip() for item in value.split(",") if item.strip()]

    if len(values) < 2:
        return False

    normalized = [item.lower() for item in values]

    return len(set(normalized)) != len(normalized)


def _detect_forwarding_header_conflicts(c: Context, anomalies: list[HeaderAnomaly]) -> None:
    present = [header for header in FORWARDING_HEADERS if c.req.header(header) is not None]

    # Multiple independent client-IP sources.  Not automatically malicious, but
    # useful anomaly information because different proxies may legitimately add
    # different headers.
    if len(present) >= 2:
        anomalies.append(
            {
                "type": "conflicting_headers",
                "relatedHeaders": present,
                "message": "Multiple client-IP/forwarding headers are present.",
                "severity": "medium",
            }
        )

    # X-Forwarded-For with multiple hops.  Multiple hops are normal behind
    # proxies, so this is deliberately NOT marked as suspicious by itself.
    xff = c.req.header("x-forwarded-for")

    if xff:
        ips = [value.strip() for value in xff.split(",") if value.strip()]

        if len(ips) > 10:
            anomalies.append(
                {
                    "type": "conflicting_headers",
                    "header": "x-forwarded-for",
                    "message": "X-Forwarded-For contains an unusually large number of proxy hops.",
                    "severity": "medium",
                }
            )


def _detect_framing_conflict(c: Context, anomalies: list[HeaderAnomaly]) -> None:
    content_length = c.req.header("content-length")
    transfer_encoding = c.req.header("transfer-encoding")

    if content_length is not None and transfer_encoding is not None:
        anomalies.append(
            {
                "type": "conflicting_headers",
                "relatedHeaders": ["content-length", "transfer-encoding"],
                "message": "Content-Length and Transfer-Encoding are both present.",
                "severity": "high",
            }
        )


def _deduplicate_header_anomalies(anomalies: list[HeaderAnomaly]) -> list[HeaderAnomaly]:
    seen: set[str] = set()
    result: list[HeaderAnomaly] = []

    for anomaly in anomalies:
        key = "|".join(
            [
                anomaly["type"],
                anomaly.get("header", ""),
                ",".join(anomaly.get("relatedHeaders", [])),
                anomaly["message"],
            ]
        )

        if key in seen:
            continue

        seen.add(key)
        result.append(anomaly)

    return result


_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")


def detect_header_anomalies_for_request(c: Context, options: HeaderAnomalyOptions) -> list[HeaderAnomaly]:
    anomalies: list[HeaderAnomaly] = []
    total_header_bytes = 0

    # Inspect every visible header
    for name, value in c.req.header_items():
        total_header_bytes += len(name) + len(value)

        # Unexpected header
        if name not in options.expected_headers:
            anomalies.append(
                {
                    "type": "unexpected_header",
                    "header": name,
                    "message": "Header is outside the configured normal header set.",
                    "severity": "low",
                }
            )

        # Suspicious header
        if name in options.suspicious_headers:
            anomalies.append(
                {
                    "type": "suspicious_header",
                    "header": name,
                    "message": "Header belongs to the configured suspicious-header set.",
                    "severity": "medium",
                }
            )

        # Oversized value
        if len(value) > options.max_header_value_length:
            anomalies.append(
                {
                    "type": "oversized_header",
                    "header": name,
                    "message": "Header value exceeds the configured audit threshold.",
                    "valueLength": len(value),
                    "severity": "high",
                }
            )

        # Invalid control characters
        if _CONTROL_CHARS.search(value):
            anomalies.append(
                {
                    "type": "invalid_header_value",
                    "header": name,
                    "message": "Header contains control characters.",
                    "severity": "high",
                }
            )

        # Suspicious comma-separated duplicate values (forwarding headers)
        if _is_forwarding_header(name) and _has_suspicious_duplicate_values(value):
            anomalies.append(
                {
                    "type": "duplicate_header_value",
                    "header": name,
                    "message": "Forwarding header contains suspicious duplicate values.",
                    "severity": "medium",
                }
            )

        # Method override
        if _is_method_override_header(name):
            anomalies.append(
                {
                    "type": "method_override",
                    "header": name,
                    "message": "HTTP method override header is present.",
                    "severity": "medium",
                }
            )

    # Total header volume
    if total_header_bytes > options.max_total_header_bytes:
        anomalies.append(
            {
                "type": "header_volume",
                "message": "Total request header volume exceeds the configured audit threshold.",
                "valueLength": total_header_bytes,
                "severity": "high",
            }
        )

    # Forwarding-header conflicts
    _detect_forwarding_header_conflicts(c, anomalies)

    # Content-Length / Transfer-Encoding
    _detect_framing_conflict(c, anomalies)

    # Remove duplicate anomaly records
    return _deduplicate_header_anomalies(anomalies)


# ============================================================
# Get actual audit error
# ============================================================


def get_audit_error(
    c: Context,
    caught_error: Optional[BaseException],
    status: int,
    include_stack: bool,
) -> Optional[AuditError]:
    # 1. Middleware supplied the actual error
    middleware_error = c.get("auditError")

    if middleware_error:
        result: AuditError = {
            "name": sanitize_error_name(middleware_error.get("name", "Error")),
            "message": sanitize_error_message(middleware_error.get("message", "")),
        }

        if middleware_error.get("code"):
            result["code"] = sanitize_error_code(middleware_error["code"])

        result["status"] = middleware_error.get("status", 500)

        if include_stack and middleware_error.get("stack"):
            result["stack"] = sanitize_stack(middleware_error["stack"])

        return result

    # 2. HTTPException
    if isinstance(caught_error, HTTPException):
        cause = caught_error.cause

        if isinstance(cause, dict) and any(k in cause for k in ("name", "message", "code", "stack")):
            name = cause["name"] if isinstance(cause.get("name"), str) else "HTTPException"
            message = (
                cause["message"]
                if isinstance(cause.get("message"), str)
                else (caught_error.message or get_http_status_description(caught_error.status))
            )
            code = cause["code"] if isinstance(cause.get("code"), str) else None
            stack = cause["stack"] if isinstance(cause.get("stack"), str) else _stack_of(caught_error)

            result = {
                "name": sanitize_error_name(name),
                "message": sanitize_error_message(message),
            }

            if code:
                result["code"] = sanitize_error_code(code)

            result["status"] = caught_error.status

            if include_stack and stack:
                result["stack"] = sanitize_stack(stack)

            return result

        result = {
            "name": sanitize_error_name(caught_error.name or "HTTPException"),
            "message": sanitize_error_message(
                caught_error.message or get_http_status_description(caught_error.status)
            ),
            "status": caught_error.status,
        }

        if include_stack:
            result["stack"] = sanitize_stack(_stack_of(caught_error))

        return result

    # 3. Normal Error
    if isinstance(caught_error, Exception):
        result = {
            "name": sanitize_error_name(type(caught_error).__name__),
            "message": sanitize_error_message(str(caught_error)),
            "status": status if status >= 400 else 500,
        }

        if include_stack:
            result["stack"] = sanitize_stack(_stack_of(caught_error))

        return result

    # 4. Unknown value
    if caught_error is not None:
        return {
            "name": "UnknownError",
            "message": "An unknown error was thrown",
            "status": status if status >= 400 else 500,
        }

    # 5. HTTP error response without exception
    if status >= 400:
        return {
            "name": "HTTPError",
            "message": get_http_status_description(status),
            "status": status,
        }

    return None


# ============================================================
# Request ID / client
# ============================================================


def _get_request_id(c: Context) -> str:
    return c.get("requestId") or c.req.header("x-request-id") or "unknown"


def _get_client_id(c: Context) -> Optional[str]:
    client = c.get("client")

    if isinstance(client, dict) and isinstance(client.get("id"), str):
        return client["id"]

    return None


# ------------------------------------------------------------
# Audit logger middleware
# ------------------------------------------------------------


def audit_logger(
    server_identity: Optional[ServerIdentity] = None,
    log_success: bool = True,
    log_failures: bool = True,
    slow_request_ms: Optional[int] = None,
    log_headers: Optional[list[str]] = None,
    include_stack: Optional[bool] = None,
    detect_header_anomalies: bool = True,
    max_header_value_length: int = 8192,
    max_total_header_bytes: int = 32768,
    expected_headers: Optional[list[str]] = None,
    suspicious_headers: Optional[list[str]] = None,
) -> Middleware:
    slow_ms = slow_request_ms if slow_request_ms is not None else DEFAULT_SLOW_REQUEST_MS
    stack_enabled = include_stack if include_stack is not None else DEFAULT_INCLUDE_STACK

    # Same as the original: the header sets are built when the middleware is
    # created (from the list loaded at that time).
    log_header_set = {h.lower() for h in (log_headers if log_headers is not None else DEFAULT_LOG_HEADERS)}
    expected_set = {h.lower() for h in (expected_headers if expected_headers is not None else DEFAULT_EXPECTED_HEADERS)}
    suspicious_set = {h.lower() for h in (suspicious_headers if suspicious_headers is not None else DEFAULT_SUSPICIOUS_HEADERS)}

    # Validate configuration
    if not isinstance(slow_ms, int) or slow_ms < 0:
        raise ValueError("slowRequestMs must be a non-negative integer")

    if not isinstance(max_header_value_length, int) or max_header_value_length <= 0:
        raise ValueError("maxHeaderValueLength must be a positive integer")

    if not isinstance(max_total_header_bytes, int) or max_total_header_bytes <= 0:
        raise ValueError("maxTotalHeaderBytes must be a positive integer")

    async def middleware(c: Context, next):
        start = time.perf_counter()
        response = None
        caught_error: Optional[BaseException] = None

        try:
            response = await next()
            return response
        except Exception as error:  # noqa: BLE001
            caught_error = error
            raise
        finally:
            # Logging itself must never break request handling.
            try:
                duration_ms = round((time.perf_counter() - start) * 1000)

                # Determine status
                status = response.status_code if response is not None else 200

                if isinstance(caught_error, HTTPException):
                    status = caught_error.status
                elif caught_error is not None and status < 400:
                    status = 500

                # Determine outcome
                outcome = "failure" if status >= 400 or caught_error is not None else "success"
                slow = slow_ms > 0 and duration_ms >= slow_ms

                # Logging filters
                skip = (
                    (outcome == "success" and not log_success and not slow)
                    or (outcome == "failure" and not log_failures)
                )

                if not skip:
                    # Selected headers
                    headers: dict[str, str] = {}

                    for header_name in log_header_set:
                        value = c.req.header(header_name)

                        if value is not None:
                            headers[header_name] = sanitize_header_value(value)

                    header_anomalies = (
                        detect_header_anomalies_for_request(
                            c,
                            HeaderAnomalyOptions(
                                expected_headers=expected_set,
                                suspicious_headers=suspicious_set,
                                max_header_value_length=max_header_value_length,
                                max_total_header_bytes=max_total_header_bytes,
                            ),
                        )
                        if detect_header_anomalies
                        else []
                    )

                    identity = server_identity or ServerIdentity(
                        name="unknown", hostname=None, ips=[], has_network_identity=False
                    )

                    event: AuditLogEvent = {
                        "server": identity.name,
                        "serverIPs": identity.ips,
                        "type": "audit",
                        "timestamp": datetime.now(timezone.utc)
                        .isoformat(timespec="milliseconds")
                        .replace("+00:00", "Z"),
                        "requestId": _get_request_id(c),
                        "method": c.req.method,
                        "path": c.req.path,
                        "status": status,
                        "durationMs": duration_ms,
                        "clientId": _get_client_id(c),
                        "ip": get_client_ip(c) or None,
                        "userAgent": c.req.header("user-agent"),
                        "headers": headers,
                        "headerAnomalies": header_anomalies,
                        "outcome": outcome,
                        "slow": slow,
                        "error": get_audit_error(c, caught_error, status, stack_enabled),
                    }

                    log_event(event)
            except Exception:  # noqa: BLE001
                # Ignore logger failures.
                pass

    return middleware
