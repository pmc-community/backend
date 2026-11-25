"""
Data layer: reads lists from the configured data source (DATA_SOURCE=fs),
parses regex lists, tracks changes and hot-reloads everything periodically.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Optional, Pattern

from app.data_provider.provider import load_data_providers

_configured_data_source = os.environ.get("DATA_SOURCE")

if not _configured_data_source:
    raise RuntimeError("[provider] DATA_SOURCE is not configured")

data_source: str = _configured_data_source

mem_module, sorted_module = load_data_providers(data_source)

# list name -> last seen values (used to log what changed on hot reload)
_list_snapshots: dict[str, list[str]] = {}


def resolve_fs_source(source: str) -> str:
    """
    Resolve a filesystem source.

    The source definitions remain portable:

        ./data/general/example.txt

    For DATA_SOURCE=fs this resolves relative to the process working directory,
    so the application must be started from the project root.  Other providers
    never call this function.
    """
    if source.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", source):
        return source

    #return f"{os.getcwd()}/{re.sub(r'^\.?[\\/]', '', source, count=1)}"
    relative = re.sub(r"^\.?[\\/]", "", source, count=1)
    return f"{os.getcwd()}/{relative}"


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def values_equal(a: list, b: list) -> bool:
    return len(a) == len(b) and all(x == y for x, y in zip(a, b))


def log_data_change(list_name: str, old_values: list[str], new_values: list[str]) -> None:
    print(f"[DATA CHANGE] {list_name} ({data_source})")
    print(f"[DATA CHANGE] {list_name}: {len(old_values)} -> {len(new_values)} entries")

    old_set = set(old_values)
    new_set = set(new_values)

    added = [v for v in new_values if v not in old_set]
    removed = [v for v in old_values if v not in new_set]

    if added:
        print(f"[DATA CHANGE] {list_name} added:", added)

    if removed:
        print(f"[DATA CHANGE] {list_name} removed:", removed)

    if not added and not removed and not values_equal(old_values, new_values):
        print(f"[DATA CHANGE] {list_name}: values changed")


# ---------------------------------------------------------------------------
# Memory lists
# ---------------------------------------------------------------------------


@dataclass
class MemListResult:
    object: Any
    values: list[str]


def get_mem_values(list_name: str, source: Optional[str]) -> Optional[MemListResult]:
    if not source:
        print(f"[DATA] {list_name}: no source configured for DATA_SOURCE={data_source}")
        return None

    if data_source == "fs":
        obj = mem_module.create_memory_list(
            list_name,
            mem_module.MemoryFileListProviderOptions(file_path=resolve_fs_source(source)),
        )

        # IMPORTANT: the filesystem provider must read the file on every
        # values() call.  This is what makes hot reload work.
        values = [str(v) for v in obj.values_sync() if v]

        previous_values = _list_snapshots.get(list_name)

        if previous_values is not None and not values_equal(previous_values, values):
            log_data_change(list_name, previous_values, values)

        _list_snapshots[list_name] = list(values)

        return MemListResult(object=obj, values=values)

    print(f"[DATA] Unsupported DATA_SOURCE: {data_source}")
    return None


# ---------------------------------------------------------------------------
# Regex lists
# ---------------------------------------------------------------------------

_JS_REGEX = re.compile(r"^/(.+)/([dgimsuvy]*)$")
_JS_NAMED_GROUP = re.compile(r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>")
_JS_NAMED_BACKREF = re.compile(r"\\k<([A-Za-z_][A-Za-z0-9_]*)>")


def compile_js_regex(source: str, flags: str) -> Pattern[str]:
    """
    Compile a JavaScript regular expression (``/source/flags``) with Python's
    ``re``.  The data files keep the JS notation so that the pattern lists
    stay portable.

    Differences handled here:
      * flags: i -> IGNORECASE, m -> MULTILINE, s -> DOTALL; g/y/d/v are
        irrelevant for ``test()``-style matching.
      * without the ``u`` flag JS ``\\w \\d \\b`` and case folding are ASCII-only,
        so ``re.ASCII`` is applied unless ``u`` is present.
      * named groups ``(?<n>...)`` / ``\\k<n>`` -> ``(?P<n>...)`` / ``(?P=n)``.
    """
    py_flags = 0

    if "i" in flags:
        py_flags |= re.IGNORECASE

    if "m" in flags:
        py_flags |= re.MULTILINE

    if "s" in flags:
        py_flags |= re.DOTALL

    if "u" not in flags:
        py_flags |= re.ASCII

    converted = _JS_NAMED_GROUP.sub(r"(?P<\1>", source)
    converted = _JS_NAMED_BACKREF.sub(r"(?P=\1)", converted)

    return re.compile(converted, py_flags)


def get_mem_regex_values(list_name: str, source: Optional[str]) -> list[Pattern[str]]:
    if not source:
        print(f"[Regex list] {list_name}: no source configured for DATA_SOURCE={data_source}")
        return []

    if data_source == "fs":
        return _get_regex_list_in_mem(list_name, source)

    print(f"[Regex list] Unsupported DATA_SOURCE: {data_source}")
    return []


def _get_regex_list_in_mem(list_name: str, source: str) -> list[Pattern[str]]:
    obj = mem_module.create_memory_list(
        list_name,
        mem_module.MemoryFileListProviderOptions(file_path=resolve_fs_source(source)),
    )

    raw_patterns = obj.values_sync()
    patterns = [p for p in (str(pattern).strip() for pattern in raw_patterns) if p]

    previous_values = _list_snapshots.get(list_name)

    if previous_values is None:
        _list_snapshots[list_name] = list(patterns)

    elif not values_equal(previous_values, patterns):
        log_data_change(list_name, previous_values, patterns)
        _list_snapshots[list_name] = list(patterns)

    compiled: list[Pattern[str]] = []

    for pattern in patterns:
        match = _JS_REGEX.match(pattern)

        if not match:
            print(f"[Regex list] {list_name}: invalid pattern ignored: {pattern}")
            continue

        try:
            compiled.append(compile_js_regex(match.group(1), match.group(2)))
        except (re.error, ValueError, OverflowError) as error:
            print(f"[Regex list] {list_name}: invalid RegExp ignored: {pattern}", error)

    return compiled


# ---------------------------------------------------------------------------
# Sorted lists
# ---------------------------------------------------------------------------


def get_list_values(list_name: str, source: Optional[str]):
    if not source:
        print(f"[LIST] {list_name}: no source configured for DATA_SOURCE={data_source}")
        return None

    if data_source == "fs":
        return sorted_module.create_sorted_list(
            list_name,
            sorted_module.FsSortedListProviderOptions(file_path=resolve_fs_source(source)),
        )

    print(f"[LIST] Unsupported DATA_SOURCE: {data_source}")
    return None


# ---------------------------------------------------------------------------
# Hot reload
# ---------------------------------------------------------------------------


@dataclass
class ReloadableList:
    list_name: str
    source: str
    reload: Callable[[], None]


_reloadable_lists: list[ReloadableList] = []
_reload_task: Optional["asyncio.Task[None]"] = None
_reload_in_progress = False


def reload_all_lists() -> None:
    global _reload_in_progress

    if _reload_in_progress:
        return

    _reload_in_progress = True

    try:
        for item in _reloadable_lists:
            try:
                item.reload()
            except Exception as error:  # noqa: BLE001
                print(f"[DATA RELOAD] Failed to reload {item.list_name}:", error)
    finally:
        _reload_in_progress = False


def register_reloadable_list(
    list_name: str,
    source: Optional[str],
    reload: Callable[[], None],
) -> None:
    for existing in _reloadable_lists:
        if existing.list_name == list_name:
            existing.source = source  # type: ignore[assignment]
            existing.reload = reload
            return

    _reloadable_lists.append(ReloadableList(list_name, source, reload))  # type: ignore[arg-type]


def _reload_interval_ms() -> float:
    try:
        configured = float(os.environ.get("DATA_RELOAD_INTERVAL", 1000))
    except ValueError:
        return 1000

    return configured if configured == configured and configured > 0 else 1000


async def _hot_reload_loop(seconds: float) -> None:
    while True:
        await asyncio.sleep(seconds)
        reload_all_lists()


def start_data_hot_reload() -> None:
    """Must be called from inside a running event loop (see main.py lifespan)."""
    global _reload_task

    if data_source != "fs":
        print(f"[DATA RELOAD] Hot reload is not implemented for DATA_SOURCE={data_source}")
        return

    if _reload_task is not None:
        return

    interval_ms = _reload_interval_ms()

    print(f"[DATA RELOAD] Enabled for DATA_SOURCE={data_source}; interval={interval_ms:g}ms")

    _reload_task = asyncio.get_running_loop().create_task(
        _hot_reload_loop(interval_ms / 1000)
    )


def stop_data_hot_reload() -> None:
    global _reload_task

    if _reload_task is None:
        return

    _reload_task.cancel()
    _reload_task = None

    print("[DATA RELOAD] Stopped")
