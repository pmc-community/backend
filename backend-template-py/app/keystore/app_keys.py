"""
------------------------------------------------------------
Cryptographic helpers
------------------------------------------------------------
"""

import hashlib


def sha256(value: str) -> str:
    """SHA-256 hash, returned as a 64-character lowercase hexadecimal string."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


async def hash_key(key: str) -> str:
    """Hash an API key before using it as a keystore lookup key."""
    return sha256(key)
