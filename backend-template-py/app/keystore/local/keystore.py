"""
------------------------------------------------------------
API key information

The keystore maps:

    hash(rawKey) -> { clientId, scopes }
------------------------------------------------------------
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass


@dataclass
class APIKeyInfo:
    clientId: str
    scopes: list[str]


# ------------------------------------------------------------
# LOCAL JSON CACHE
#
# Used only by the local-development implementation of get_api_key().
# In production, this can be removed when get_api_key() is changed to use
# a database.
# ------------------------------------------------------------

_api_keys: dict[str, APIKeyInfo] | None = None


def _get_keystore_path() -> str:
    keystore_path = os.environ.get("KEYSTORE_PATH")

    if not keystore_path:
        raise RuntimeError("KEYSTORE_PATH not set in .env")

    return keystore_path


def _read_keystore(keystore_path: str) -> dict[str, APIKeyInfo]:
    """Read and parse keystore.json (LOCAL DEVELOPMENT ONLY)."""
    if not os.path.exists(keystore_path):
        raise RuntimeError(
            f"Missing {keystore_path} — generate keys with scripts/generate_key.py first"
        )

    with open(keystore_path, "r", encoding="utf-8") as handle:
        keystore_raw = handle.read()

    try:
        parsed = json.loads(keystore_raw)
    except ValueError as error:
        raise RuntimeError(f"Invalid JSON in {keystore_path}: {error}") from error

    if not isinstance(parsed, dict):
        raise RuntimeError(f"Invalid keystore format in {keystore_path}")

    keystore: dict[str, APIKeyInfo] = {}

    # Validate each entry.
    for key_hash, entry in parsed.items():
        if not isinstance(entry, dict):
            raise RuntimeError(f'Invalid keystore entry for key hash "{key_hash}"')

        if not isinstance(entry.get("clientId"), str):
            raise RuntimeError(f'Invalid clientId for key hash "{key_hash}"')

        scopes = entry.get("scopes")

        if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
            raise RuntimeError(f'Invalid scopes for key hash "{key_hash}"')

        keystore[key_hash] = APIKeyInfo(clientId=entry["clientId"], scopes=scopes)

    return keystore


# ============================================================
# API KEY LOOKUP
# ============================================================
#
# THIS IS THE STORAGE ABSTRACTION.
#
# The rest of the application should only call:
#
#     await get_api_key(key_hash)
#
# It does not know whether keys are stored in JSON, SQLite, PostgreSQL, Redis
# or another external key store.
#
# For LOCAL DEVELOPMENT, this implementation uses JSON.
# For PRODUCTION, replace the implementation of this function with a database
# lookup.  It is async to keep the production pattern, even though local dev
# does not need it.
# ============================================================


async def get_api_key(key_hash: str) -> APIKeyInfo | None:
    # Load the JSON file once and cache it in memory.
    # First lookup: read/parse JSON; subsequent lookups: O(1) dict lookup.
    global _api_keys

    if _api_keys is None:
        _api_keys = _read_keystore(_get_keystore_path())

    return _api_keys.get(key_hash)


# ----------------------------------------------------------
# PRODUCTION DATABASE VERSION
# ----------------------------------------------------------
#
# async def get_api_key(key_hash: str) -> APIKeyInfo | None:
#     row = await db.fetch_one(
#         "SELECT client_id, scopes FROM api_keys WHERE key_hash = $1 LIMIT 1",
#         key_hash,
#     )
#
#     if row is None:
#         return None
#
#     return APIKeyInfo(clientId=row["client_id"], scopes=row["scopes"])
# ----------------------------------------------------------
