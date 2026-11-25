"""Small helpers reproducing JavaScript number/env semantics used by the original code."""

from __future__ import annotations

import os
import re
import time

MAX_SAFE_INTEGER = 2**53 - 1

_INT_PREFIX = re.compile(r"^\s*[+-]?\d+", re.ASCII)


def now_ms() -> float:
    """Date.now()"""
    return time.time() * 1000


def parse_int(value: str | None) -> int | float:
    """parseInt(value, 10): leading integer or NaN."""
    match = _INT_PREFIX.match(value or "")
    return int(match.group(0)) if match else float("nan")


def env_int(name: str, default: str) -> int | float:
    """``parseInt(process.env.NAME ?? 'default', 10)``"""
    value = os.environ.get(name)
    return parse_int(default if value is None else value)


def is_integer(value: object) -> bool:
    """Number.isInteger (NaN/inf/float are not)."""
    return isinstance(value, int) and not isinstance(value, bool)


def is_safe_integer(value: object) -> bool:
    return is_integer(value) and abs(value) <= MAX_SAFE_INTEGER  # type: ignore[operator]
