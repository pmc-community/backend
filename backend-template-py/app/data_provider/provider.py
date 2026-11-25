"""
Backend loader.

A backend is a pair of modules: a memory-list provider (small/medium lists
loaded from the storage into memory) and a sorted-list provider (big lists
searched in place).  To add a new backend (S3, Durable Objects, KV, ...) add an
entry to BACKENDS - see app/data_provider/readme.md.
"""

from __future__ import annotations

import importlib
from types import ModuleType
from typing import Callable

BACKENDS: dict[str, Callable[[], tuple[ModuleType, ModuleType]]] = {
    "fs": lambda: (
        importlib.import_module("app.data_provider.fs.mem_list_provider"),
        importlib.import_module("app.data_provider.fs.sorted_list_provider"),
    ),
    # "s3": lambda: (
    #     importlib.import_module("app.data_provider.s3.mem_list_provider"),
    #     importlib.import_module("app.data_provider.s3.sorted_list_provider"),
    # ),
}


def is_backend_name(name: str) -> bool:
    return name in BACKENDS


def load_data_providers(name: str) -> tuple[ModuleType, ModuleType]:
    if not is_backend_name(name):
        raise RuntimeError(
            f'Unknown provider: "{name}". Expected one of: {", ".join(BACKENDS)}'
        )

    try:
        return BACKENDS[name]()
    except Exception as error:
        raise RuntimeError(
            f'Failed to load "{name}" provider modules: {error}'
        ) from error
