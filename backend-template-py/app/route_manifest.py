"""
Route discovery (port of scripts/generate-routes.ts).

Routes are file-based, like in the original project:

    app/routes/echo.py                     ->  /echo
    app/routes/test/slow.py                ->  /test/slow
    app/routes/test/proute/[p1].py         ->  /test/proute/{p1}
    app/routes/test/proute/[pa]/[pb].py    ->  /test/proute/{pa}/{pb}
    app/routes/blog/[...slug].py           ->  /blog/{slug:path}      (catch-all)
    app/routes/users/index.py | route.py   ->  /users                 (index files)

Instead of generating a ``routes.generated`` module at install time, the
manifest is built when the application starts.  ``.routeignore`` keeps working:
exact names (files or folders) and ``*`` globs are skipped.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Union

from app.route_types import RouteManifestEntry

ROUTES_DIR = Path(__file__).resolve().parent / "routes"
IGNORE_FILE = Path.cwd() / ".routeignore"

# Filenames that mean "this file IS the route for its containing folder" -
# don't add a segment for them.
INDEX_FILENAMES = {"route.py", "index.py"}

# Fallback exceptions used only if .routeignore doesn't exist.
DEFAULT_EXCEPTIONS = [
    "schema.py",
    "types.py",
    "utils.py",
    "helpers.py",
    "__init__.py",
    "__tests__",
    "__pycache__",
    "test_*.py",
    "*_test.py",
]


def glob_to_regexp(pattern: str) -> "re.Pattern[str]":
    escaped = re.sub(r"[.+^${}()|\[\]\\]", lambda m: "\\" + m.group(0), pattern)
    return re.compile("^" + escaped.replace("*", ".*") + "$")


def load_exceptions() -> list[Union[str, "re.Pattern[str]"]]:
    if not IGNORE_FILE.exists():
        print("[generate-routes] No .routeignore found, using default exceptions")
        lines = DEFAULT_EXCEPTIONS
    else:
        lines = [
            line
            for line in (l.strip() for l in IGNORE_FILE.read_text(encoding="utf-8").split("\n"))
            if line and not line.startswith("#")
        ]

    return [glob_to_regexp(line) if "*" in line else line for line in lines]


def _is_excluded(name: str, exceptions) -> bool:
    return any(
        name == pattern if isinstance(pattern, str) else pattern.match(name)
        for pattern in exceptions
    )


def _walk(directory: Path, exceptions) -> list[Path]:
    files: list[Path] = []

    for entry in sorted(os.listdir(directory)):
        if _is_excluded(entry, exceptions):
            continue

        full = directory / entry

        if full.is_dir():
            files.extend(_walk(full, exceptions))
        elif entry.endswith(".py"):
            files.append(full)

    return files


def to_path_segment(segment: str) -> str:
    """
    '[user]'    -> '{user}'
    '[...slug]' -> '{slug:path}'
    'users'     -> 'users'
    """
    catch_all = re.fullmatch(r"\[\.\.\.(.+)\]", segment)

    if catch_all:
        return f"{{{catch_all.group(1)}:path}}"

    dynamic = re.fullmatch(r"\[(.+)\]", segment)

    if dynamic:
        return f"{{{dynamic.group(1)}}}"

    return segment


def to_route_path(file_path: Path, routes_dir: Path = ROUTES_DIR) -> str:
    parts = file_path.relative_to(routes_dir).parts

    filename = parts[-1]
    dir_segments = list(parts[:-1])

    segments = (
        dir_segments
        if filename in INDEX_FILENAMES
        else [*dir_segments, re.sub(r"\.py$", "", filename)]
    )

    path_segments = [to_path_segment(s) for s in segments]

    return "/" + "/".join(path_segments) if path_segments else "/"


def specificity_score(route: str) -> int:
    return len([s for s in route.split("/") if s.startswith("{")])


def build_route_manifest(routes_dir: Path = ROUTES_DIR) -> list[RouteManifestEntry]:
    """Static routes first, then routes with an increasing number of path parameters."""
    exceptions = load_exceptions()

    entries = [
        RouteManifestEntry(route=to_route_path(file, routes_dir), file=str(file))
        for file in _walk(routes_dir, exceptions)
    ]

    # JS localeCompare is case-insensitive at the first level
    entries.sort(key=lambda e: (specificity_score(e.route), e.route.lower(), e.route))

    return entries
