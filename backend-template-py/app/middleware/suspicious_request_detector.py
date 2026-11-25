from __future__ import annotations

import inspect
import re
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Pattern

from app.core import uri
from app.core.compose import Middleware
from app.core.context import Context
from app.core.http_exception import HTTPException
from app.data_provider import data
from app.helpers.js import env_int
from app.helpers.utilities import get_client_ip

# Pattern lists (hot-reloaded in place by the data layer)
SCANNER_USER_AGENT_PATTERNS = data.SCANNER_USER_AGENT_PATTERNS
MALFORMED_USER_AGENT_PATTERNS = data.MALFORMED_USER_AGENT_PATTERNS
SQL_INJECTION_PATTERNS = data.SQL_INJECTION_PATTERNS
XSS_PATTERNS = data.XSS_PATTERNS
COMMAND_INJECTION_PATTERNS = data.COMMAND_INJECTION_PATTERNS
PATH_TRAVERSAL_PATTERNS = data.PATH_TRAVERSAL_PATTERNS
PROTOTYPE_POLLUTION_PATTERNS = data.PROTOTYPE_POLLUTION_PATTERNS
SUSPICIOUS_PATH_PATTERNS = data.SUSPICIOUS_PATH_PATTERNS


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------


def matches_any(value: str, patterns: list[Pattern[str]]) -> bool:
    return any(pattern.search(value) for pattern in patterns)


def safe_decode(value: str) -> str:
    result = value

    for _ in range(3):
        try:
            decoded = uri.decode_uri_component(result)
        except ValueError:
            break

        if decoded == result:
            break

        result = decoded

    return result


class _Score:
    value = 0

    def __init__(self) -> None:
        self.value = 0


def add_reason(reasons: list[str], score: _Score, reason: str, points: int) -> None:
    if reason not in reasons:
        reasons.append(reason)
        score.value += points


# ------------------------------------------------------------
# User-Agent validation
# ------------------------------------------------------------


def validate_user_agent(user_agent: str) -> list[str]:
    reasons: list[str] = []

    # 1. Must contain at least one ASCII letter
    #    (rejects 9999, 9999.9999, 123-456, !!!, @@@, ...)
    if not re.search(r"[A-Za-z]", user_agent):
        reasons.append("user-agent-without-letters")

    # 2. Only printable ASCII (0x20 space ... 0x7E ~) is allowed.
    #    Rejects control characters, newlines, tabs, null bytes, Unicode.
    if re.search(r"[^\x20-\x7E]", user_agent):
        reasons.append("user-agent-invalid-characters")

    # 3. Empty/whitespace-only
    if not user_agent.strip():
        reasons.append("empty-user-agent")

    # 4. Known placeholder / malformed values
    if matches_any(user_agent, MALFORMED_USER_AGENT_PATTERNS):
        reasons.append("malformed-user-agent")

    return reasons


# ------------------------------------------------------------
# Middleware
# ------------------------------------------------------------


def suspicious_request_detector(
    threshold: Optional[int] = None,
    block: Optional[bool] = None,
    status: int = 403,
    message: str = "Suspicious request detected.",
    max_query_parameters: Optional[int] = None,
    max_url_length: Optional[int] = None,
    on_detect: Optional[Callable[[dict, Context], Any]] = None,
    detect_scanner_user_agents: bool = True,
    detect_malformed_user_agents: bool = True,
    detect_sql_injection: bool = True,
    detect_xss: bool = True,
    detect_command_injection: bool = True,
    detect_path_traversal: bool = True,
    detect_prototype_pollution: bool = True,
) -> Middleware:
    import os

    thr = threshold if threshold is not None else env_int("SRD_THRESHOLD", "5")
    do_block = block if block is not None else os.environ.get("SRD_BLOCK_SUSPICIOUS_REQUESTS") == "true"
    max_params = max_query_parameters if max_query_parameters is not None else env_int("DEFAULT_MAX_QUERY_PARAMETERS", "20")
    max_url = max_url_length if max_url_length is not None else env_int("MAX_URL_LENGTH", "1024")

    async def middleware(c: Context, next):
        reasons: list[str] = []
        score = _Score()

        method = c.req.method
        path = c.req.path
        url = c.req.url

        raw_user_agent = c.req.header("user-agent")
        user_agent = raw_user_agent.strip() if raw_user_agent is not None else None

        content_type = c.req.header("content-type")

        # Client IP
        ip = get_client_ip(c)

        # Query parameters
        query_parameter_count = len(c.req.search_params())

        if query_parameter_count > max_params:
            add_reason(reasons, score, "too-many-query-parameters", 3)

        # URL length
        if len(url) > max_url:
            add_reason(reasons, score, "url-too-long", 3)

        # Scanner User-Agent
        if (
            detect_scanner_user_agents
            and user_agent
            and matches_any(user_agent, SCANNER_USER_AGENT_PATTERNS)
        ):
            add_reason(reasons, score, "scanner-user-agent", 5)

        # User-Agent validation
        if detect_malformed_user_agents:
            if not user_agent:
                add_reason(reasons, score, "missing-user-agent", 5)
            else:
                for reason in validate_user_agent(user_agent):
                    add_reason(reasons, score, reason, 5)

        # Decode URL
        decoded_path = safe_decode(path)
        decoded_url = safe_decode(url)

        # Suspicious path
        if matches_any(decoded_path, SUSPICIOUS_PATH_PATTERNS):
            add_reason(reasons, score, "suspicious-path", 4)

        # SQL Injection
        if detect_sql_injection and matches_any(decoded_url, SQL_INJECTION_PATTERNS):
            add_reason(reasons, score, "sql-injection", 8)

        # XSS
        if detect_xss and matches_any(decoded_url, XSS_PATTERNS):
            add_reason(reasons, score, "xss", 8)

        # Command Injection
        if detect_command_injection and matches_any(decoded_url, COMMAND_INJECTION_PATTERNS):
            add_reason(reasons, score, "command-injection", 8)

        # Path Traversal
        if detect_path_traversal and matches_any(decoded_url, PATH_TRAVERSAL_PATTERNS):
            add_reason(reasons, score, "path-traversal", 8)

        # Prototype Pollution
        if detect_prototype_pollution and matches_any(decoded_url, PROTOTYPE_POLLUTION_PATTERNS):
            add_reason(reasons, score, "prototype-pollution", 8)

        # Control characters in URL
        if re.search(r"[\x00-\x1F\x7F]", url):
            add_reason(reasons, score, "control-character", 5)

        # Malformed percent encoding
        if re.search(r"%(?![0-9a-f]{2})", url, re.IGNORECASE):
            add_reason(reasons, score, "malformed-percent-encoding", 4)

        # Header count
        header_count = len(c.req.header_items())

        # Suspicious request detected
        if score.value >= thr:
            event = {
                "type": "suspicious-request",
                "score": score.value,
                "reasons": reasons,
                "method": method,
                "path": path,
                "url": url,
                "ip": ip,
                "userAgent": user_agent,
                "contentType": content_type,
                "queryParameterCount": query_parameter_count,
                "headerCount": header_count,
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "requestId": c.get("requestId"),
            }

            if on_detect:
                result = on_detect(event, c)

                if inspect.isawaitable(result):
                    await result

            if do_block:
                raise HTTPException(status, message=message)

        return await next()

    return middleware
