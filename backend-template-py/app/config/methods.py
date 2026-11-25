from __future__ import annotations

from typing import Sequence

from app.data_provider import data

DEFAULT_METHODS = ("get", "post", "put", "patch", "delete", "options")

SUPPORTED_METHODS = set(DEFAULT_METHODS)


def parse_allowed_methods(raw: Sequence[str]) -> set[str]:
    if len(raw) == 0:
        print("[methods] ALLOWED_METHODS not set, defaulting to all supported methods")
        return set(SUPPORTED_METHODS)

    parsed = [m for m in (method.strip().lower() for method in raw) if m]

    invalid = [m for m in parsed if m not in SUPPORTED_METHODS]

    if invalid:
        raise RuntimeError(
            f"[methods] ALLOWED_METHODS contains unsupported method(s): {', '.join(invalid)}. "
            f"Supported: {', '.join(sorted(SUPPORTED_METHODS))}"
        )

    if len(parsed) == 0:
        raise RuntimeError("[methods] ALLOWED_METHODS resolved to an empty list")

    return set(parsed)


VALID_METHODS: set[str] = parse_allowed_methods(data.ALLOWED_METHODS)


def is_valid_method(method: str) -> bool:
    return method.lower() in VALID_METHODS
