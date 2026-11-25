"""
Central place where every configurable list used by the middleware is loaded.

The exported lists are mutable and are updated IN PLACE on hot reload, so any
module that keeps a reference to them (``SINGLE_IP_HEADERS = data.SINGLE_IP_HEADERS``)
always sees the current values.  The two trusted-proxy values are plain
comma-separated strings that are re-assigned on reload - read them as
``data.TRUSTED_PROXY_IPS`` at call time.

Everything is loaded once at import time (so the rest of the application can
rely on it) and refreshed by ``start_data_hot_reload()`` which is started from
the FastAPI lifespan.
"""

from __future__ import annotations

import os
import re
from typing import Callable, Optional, Pattern

from app.data_provider.provider_data import (
    data_source as _data_source_name,
    get_list_values,
    get_mem_regex_values,
    get_mem_values,
    register_reloadable_list,
    start_data_hot_reload,
    stop_data_hot_reload,
)

if not os.environ.get("DATA_SOURCE"):
    raise RuntimeError("[data loader] DATA_SOURCE is not configured")

data_source = _data_source_name

# For each data source, the location of every list
sources: dict[str, dict[str, str]] = {
    # server.py
    "GLOBAL_IP_DENY": {"fs": "./data/general/global-ip-deny.txt"},
    # app/config/methods.py
    "ALLOWED_METHODS": {"fs": "./data/cors/allow-methods.txt"},
    # app/helpers/utilities.py
    "TRUSTED_PROXY_IPS": {"fs": "./data/general/trusted-proxy-ip.txt"},
    "TRUSTED_PROXY_CIDRS": {"fs": "./data/general/trusted-proxy-cidrs.txt"},
    "SINGLE_IP_HEADERS": {"fs": "./data/general/single-ip-headers.txt"},
    # app/middleware/audit_logger.py
    "DEFAULT_LOG_HEADERS": {"fs": "./data/auditLogger/log-headers.txt"},
    "DEFAULT_EXPECTED_HEADERS": {"fs": "./data/auditLogger/expected-headers.txt"},
    "DEFAULT_SUSPICIOUS_HEADERS": {"fs": "./data/auditLogger/suspicious-headers.txt"},
    "FORWARDING_HEADERS": {"fs": "./data/auditLogger/forwarding-headers.txt"},
    # app/middleware/cors.py
    "BLOCKED_ORIGINS": {"fs": "./data/cors/blocked-origins.txt"},
    "ALLOW_METHODS": {"fs": "./data/cors/allow-methods.txt"},
    "ALLOW_HEADERS": {"fs": "./data/cors/allow-headers.txt"},
    # app/middleware/duplicate_header_protection.py
    "DEFAULT_PROTECTED_HEADERS": {"fs": "./data/duplicateHeaderProtection/protected-headers.txt"},
    "DEFAULT_ALLOWED_HEADERS": {"fs": "./data/duplicateHeaderProtection/allowed-headers.txt"},
    # app/middleware/suspicious_request_detector.py
    "SCANNER_USER_AGENT_PATTERNS": {"fs": "./data/suspiciousRequest/scanner-user-agent-patterns.txt"},
    "MALFORMED_USER_AGENT_PATTERNS": {"fs": "./data/suspiciousRequest/malformed-user-agent-patterns.txt"},
    "SQL_INJECTION_PATTERNS": {"fs": "./data/suspiciousRequest/sql-injection-patterns.txt"},
    "XSS_PATTERNS": {"fs": "./data/suspiciousRequest/xss-patterns.txt"},
    "COMMAND_INJECTION_PATTERNS": {"fs": "./data/suspiciousRequest/command-patterns.txt"},
    "PATH_TRAVERSAL_PATTERNS": {"fs": "./data/suspiciousRequest/path-traversal-patterns.txt"},
    "PROTOTYPE_POLLUTION_PATTERNS": {"fs": "./data/suspiciousRequest/prototype-pollution-patterns.txt"},
    "SUSPICIOUS_PATH_PATTERNS": {"fs": "./data/suspiciousRequest/suspicious-path-patterns.txt"},
    # app/middleware/host_validation.py
    "ALLOWED_HOSTS": {"fs": "./data/hostValidation/host-allow-list.txt"},
    # app/middleware/content_type_limiter.py
    "ALLOWED_CONTENT_TYPE": {"fs": "./data/contentType/allowed-content-type.txt"},
}


def _source(key: str) -> Optional[str]:
    return sources[key].get(data_source)


# ---------------------------------------------------------------------------
# Mutable exported values
# ---------------------------------------------------------------------------

GLOBAL_IP_DENY: list[str] = []
ALLOWED_METHODS: list[str] = []
TRUSTED_PROXY_IPS: str = ""
TRUSTED_PROXY_CIDRS: str = ""
SINGLE_IP_HEADERS: list[str] = []
DEFAULT_LOG_HEADERS: list[str] = []
DEFAULT_EXPECTED_HEADERS: list[str] = []
DEFAULT_SUSPICIOUS_HEADERS: list[str] = []
FORWARDING_HEADERS: list[str] = []
BLOCKED_ORIGINS: list[str] = []
ALLOW_METHODS: list[str] = []
ALLOW_HEADERS: list[str] = []
SCANNER_USER_AGENT_PATTERNS: list[Pattern[str]] = []
MALFORMED_USER_AGENT_PATTERNS: list[Pattern[str]] = []
SQL_INJECTION_PATTERNS: list[Pattern[str]] = []
XSS_PATTERNS: list[Pattern[str]] = []
COMMAND_INJECTION_PATTERNS: list[Pattern[str]] = []
PATH_TRAVERSAL_PATTERNS: list[Pattern[str]] = []
PROTOTYPE_POLLUTION_PATTERNS: list[Pattern[str]] = []
SUSPICIOUS_PATH_PATTERNS: list[Pattern[str]] = []
ALLOWED_HOSTS: list[str] = []
ALLOWED_CONTENT_TYPE: list[str] = []

# Sorted/persistent lists (never fully loaded in memory)
DEFAULT_PROTECTED_HEADERS = get_list_values(
    "duplicateHeaderProtection-protected-headers",
    _source("DEFAULT_PROTECTED_HEADERS"),
)

DEFAULT_ALLOWED_HEADERS = get_list_values(
    "duplicateHeaderProtection-allowed-headers",
    _source("DEFAULT_ALLOWED_HEADERS"),
)


def _replace_array(target: list, source: list) -> None:
    target[:] = source


def _set_trusted_proxy_ips(values: list[str]) -> None:
    global TRUSTED_PROXY_IPS
    TRUSTED_PROXY_IPS = ",".join(values)


def _set_trusted_proxy_cidrs(values: list[str]) -> None:
    global TRUSTED_PROXY_CIDRS
    TRUSTED_PROXY_CIDRS = ",".join(values)


# (kind, list name, sources key, applier) - the order is the original load order
# kind: "list" = plain string list, "regex" = JS-notation regex list
_SPECS: list[tuple[str, str, str, Callable]] = [
    ("list", "general-global-ip-deny", "GLOBAL_IP_DENY", lambda v: _replace_array(GLOBAL_IP_DENY, v)),
    ("list", "general-allowed-methods", "ALLOWED_METHODS", lambda v: _replace_array(ALLOWED_METHODS, v)),
    ("list", "general-trusted-proxy-ip", "TRUSTED_PROXY_IPS", _set_trusted_proxy_ips),
    ("list", "general-trusted-proxy-cidrs", "TRUSTED_PROXY_CIDRS", _set_trusted_proxy_cidrs),
    ("list", "general-single-ip-headers", "SINGLE_IP_HEADERS", lambda v: _replace_array(SINGLE_IP_HEADERS, v)),
    ("list", "auditLogger-log-headers", "DEFAULT_LOG_HEADERS", lambda v: _replace_array(DEFAULT_LOG_HEADERS, v)),
    ("list", "auditLogger-expected-headers", "DEFAULT_EXPECTED_HEADERS", lambda v: _replace_array(DEFAULT_EXPECTED_HEADERS, v)),
    ("list", "auditLogger-suspicious-headers", "DEFAULT_SUSPICIOUS_HEADERS", lambda v: _replace_array(DEFAULT_SUSPICIOUS_HEADERS, v)),
    ("list", "auditLogger-forwarding-headers", "FORWARDING_HEADERS", lambda v: _replace_array(FORWARDING_HEADERS, v)),
    ("list", "cors-blocked-origins", "BLOCKED_ORIGINS", lambda v: _replace_array(BLOCKED_ORIGINS, v)),
    ("list", "cors-allow-methods", "ALLOW_METHODS", lambda v: _replace_array(ALLOW_METHODS, v)),
    ("list", "cors-allow-headers", "ALLOW_HEADERS", lambda v: _replace_array(ALLOW_HEADERS, v)),
    ("regex", "suspiciousRequest-scanner-user-agent", "SCANNER_USER_AGENT_PATTERNS", lambda v: _replace_array(SCANNER_USER_AGENT_PATTERNS, v)),
    ("regex", "suspiciousRequest-malformed-user-agent", "MALFORMED_USER_AGENT_PATTERNS", lambda v: _replace_array(MALFORMED_USER_AGENT_PATTERNS, v)),
    ("regex", "suspiciousRequest-sql-injection", "SQL_INJECTION_PATTERNS", lambda v: _replace_array(SQL_INJECTION_PATTERNS, v)),
    ("regex", "suspiciousRequest-xss", "XSS_PATTERNS", lambda v: _replace_array(XSS_PATTERNS, v)),
    ("regex", "suspiciousRequest-command", "COMMAND_INJECTION_PATTERNS", lambda v: _replace_array(COMMAND_INJECTION_PATTERNS, v)),
    ("regex", "suspiciousRequest-path-traversal", "PATH_TRAVERSAL_PATTERNS", lambda v: _replace_array(PATH_TRAVERSAL_PATTERNS, v)),
    ("regex", "suspiciousRequest-prototype-pollution", "PROTOTYPE_POLLUTION_PATTERNS", lambda v: _replace_array(PROTOTYPE_POLLUTION_PATTERNS, v)),
    ("regex", "suspiciousRequest-suspicious-path", "SUSPICIOUS_PATH_PATTERNS", lambda v: _replace_array(SUSPICIOUS_PATH_PATTERNS, v)),
    ("list", "hostValidation-blocked-hosts", "ALLOWED_HOSTS", lambda v: _replace_array(ALLOWED_HOSTS, v)),
    ("list", "contentType-allowed-content-type", "ALLOWED_CONTENT_TYPE", lambda v: _replace_array(ALLOWED_CONTENT_TYPE, v)),
]


def _load_one(kind: str, list_name: str, source_key: str, apply: Callable) -> None:
    source = _source(source_key)

    if kind == "regex":
        apply(get_mem_regex_values(list_name, source))
        return

    result = get_mem_values(list_name, source)
    apply(result.values if result else [])


def load_all_data() -> None:
    """Initial loading (runs once, at import time)."""
    for kind, list_name, source_key, apply in _SPECS:
        _load_one(kind, list_name, source_key, apply)


def _register_all() -> None:
    """Register every reloadable data source for hot reload."""
    for kind, list_name, source_key, apply in _SPECS:
        register_reloadable_list(
            list_name,
            _source(source_key),
            lambda k=kind, n=list_name, s=source_key, a=apply: _load_one(k, n, s, a),
        )


_register_all()
load_all_data()

__all__ = [
    "start_data_hot_reload",
    "stop_data_hot_reload",
]
