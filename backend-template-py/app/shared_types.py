"""Shared types and process-wide state (port of src/types/types.ts)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, TypedDict

# ----------------------------------------------------------------------
# Variables stored on the request context (c.get / c.set)
#
#   client       -> {"id": str, "scopes": list[str]}   (set by api key auth)
#   auditError   -> AuditError                          (set via set_audit_error)
#   requestId    -> str                                 (request_id middleware)
#   pagination   -> Pagination                          (pagination limiter)
#   requestSignal-> asyncio.Event, set when the request timed out
# ----------------------------------------------------------------------


class AuditError(TypedDict, total=False):
    name: str
    message: str
    status: int
    code: str
    details: Any
    stack: str


@dataclass
class AuthFailureEntry:
    count: int
    reset: float  # epoch milliseconds


# IP -> failed authentication counter (see apikey / authFailureLimiter)
auth_failures: dict[str, AuthFailureEntry] = {}


# ----------------------------------------------------------------------
# Header anomalies
# ----------------------------------------------------------------------

HeaderAnomalyType = Literal[
    "unexpected_header",
    "suspicious_header",
    "oversized_header",
    "invalid_header_value",
    "conflicting_headers",
    "duplicate_header_value",
    "header_volume",
    "method_override",
]


@dataclass
class HeaderAnomalyOptions:
    expected_headers: set[str]
    suspicious_headers: set[str]
    max_header_value_length: int
    max_total_header_bytes: int


class HeaderAnomaly(TypedDict, total=False):
    type: HeaderAnomalyType
    header: str
    relatedHeaders: list[str]
    message: str
    valueLength: int
    severity: Literal["low", "medium", "high"]


# ----------------------------------------------------------------------
# Audit log event
# ----------------------------------------------------------------------


class AuditLogEvent(TypedDict):
    server: str | None
    serverIPs: list[str]
    type: Literal["audit"]
    timestamp: str
    requestId: str
    method: str
    path: str
    status: int
    durationMs: int
    clientId: str | None
    ip: str | None
    userAgent: str | None
    headers: dict[str, str]
    headerAnomalies: list[HeaderAnomaly]
    outcome: Literal["success", "failure"]
    slow: bool
    error: AuditError | None
