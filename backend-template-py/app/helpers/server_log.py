"""
------------------------------------------------------------
Logger
------------------------------------------------------------
"""

from __future__ import annotations

import json
from typing import Any

from app.hooks.hooks import proxied_globals


def _log_event(event: dict) -> str:
    print("[logEvent]", json.dumps(event, default=str, indent=2, ensure_ascii=False))
    return event["requestId"]  # --> return relevant info if there is a hook after the execution


proxied_globals.logEvent = _log_event
log_event = proxied_globals.logEvent


def log_suspicious_request(event: Any) -> None:
    print(event)


def log_concurrent_requests(event: Any) -> None:
    print(event)
