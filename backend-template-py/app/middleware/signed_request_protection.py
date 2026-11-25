# ------------------------------------------------------------
# HMAC Signature + In-Memory Replay Protection Middleware
#
# Protects authenticated requests against:
#
#   - Missing signatures
#   - Invalid signatures
#   - Request tampering
#   - Expired signed requests
#   - Future-dated signed requests
#   - Replay of previously accepted nonces
#
# Requirements:
#
#   - api_key_auth (or another authentication middleware) MUST run BEFORE this
#     middleware.
#   - The authenticated client ID must be available as c.get('client')['id'].
#   - A signing secret must be available for the authenticated client through
#     get_signing_secret().
#   - The client MUST sign:
#
#       method, path, timestamp, nonce, SHA-256(body)
#
# Canonical request (joined with "\n"):
#
#   METHOD
#   PATH
#   TIMESTAMP
#   NONCE
#   BODY_SHA256
#
# Headers:
#
#   X-Signature-Timestamp: Unix timestamp in seconds
#   X-Signature-Nonce:     unique request nonce
#   X-Signature:           HMAC-SHA256 signature in hex
#
# Storage: process-local in-memory dict (no database / Redis / filesystem).
#
# Suitable for:     one server process.
# NOT suitable for: multiple worker processes, multiple containers/replicas,
#                   distributed/serverless deployments.
# ------------------------------------------------------------

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
import os
import re
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional, Union

from app.core.compose import Middleware
from app.core.context import Context
from app.helpers.err_handler import set_audit_error
from app.helpers.js import env_int, is_integer, is_safe_integer, now_ms

SigningSecretGetter = Callable[[Context, str], Union[Optional[str], Awaitable[Optional[str]]]]


class MemoryReplayStore:
    """
    Remembers nonces until they expire.

    ``remember()`` returns False when the key was not used before, True when it
    was already used, and raises when the store cannot safely accept another
    entry.  It is fully synchronous, so no other request can interleave between
    the lookup and the insertion.

    Expired entries are purged periodically (``cleanup_interval_ms``), whenever
    ``remember()`` runs, and when the capacity is reached.
    """

    def __init__(self, cleanup_interval_ms: int = 60_000, max_entries: int = 1_000_000) -> None:
        self.cleanup_interval_ms = cleanup_interval_ms
        self.max_entries = max_entries

        if not is_integer(self.cleanup_interval_ms) or self.cleanup_interval_ms <= 0:
            raise ValueError("MemoryReplayStore: cleanupIntervalMs must be a positive integer")

        if not is_integer(self.max_entries) or self.max_entries <= 0:
            raise ValueError("MemoryReplayStore: maxEntries must be a positive integer")

        self._entries: dict[str, float] = {}  # key -> expires_at (ms)
        self._last_cleanup = now_ms()

    def remember(self, key: str, ttl_seconds: float) -> bool:
        now = now_ms()

        if now - self._last_cleanup >= self.cleanup_interval_ms:
            self.cleanup()

        existing = self._entries.get(key)

        if existing is not None:
            if existing > now:
                return True

            # Existing entry expired.
            del self._entries[key]

        # Hard memory bound.
        if len(self._entries) >= self.max_entries:
            self.cleanup()

            if len(self._entries) >= self.max_entries:
                raise RuntimeError("REPLAY_STORE_CAPACITY_EXCEEDED")

        self._entries[key] = now + ttl_seconds * 1000

        return False

    def cleanup(self) -> None:
        now = now_ms()
        self._last_cleanup = now

        for key in [k for k, expires_at in self._entries.items() if expires_at <= now]:
            del self._entries[key]

    def size(self) -> int:
        return len(self._entries)

    def destroy(self) -> None:
        self._entries.clear()


def _get_header(c: Context, name: str) -> Optional[str]:
    value = c.req.header(name)

    if not value:
        return None

    trimmed = value.strip()

    return trimmed if len(trimmed) > 0 else None


def _parse_timestamp(value: str) -> Optional[int]:
    if not re.fullmatch(r"[0-9]+", value):
        return None

    timestamp = int(value)

    if not is_safe_integer(timestamp):
        return None

    return timestamp


def _hex_to_bytes(value: str) -> Optional[bytes]:
    if len(value) == 0 or len(value) % 2 != 0 or not re.fullmatch(r"[0-9a-fA-F]+", value):
        return None

    return bytes.fromhex(value)


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _verify_hmac_sha256(secret: str, canonical_request: str, signature_hex: str) -> bool:
    signature_bytes = _hex_to_bytes(signature_hex)

    if signature_bytes is None:
        return False

    try:
        expected = hmac.new(
            secret.encode("utf-8"), canonical_request.encode("utf-8"), hashlib.sha256
        ).digest()

        return hmac.compare_digest(expected, signature_bytes)
    except Exception:  # noqa: BLE001
        return False


def signed_request_protection(
    get_signing_secret: SigningSecretGetter,
    max_age_seconds: Optional[int] = None,
    max_future_seconds: Optional[int] = None,
    max_nonce_length: Optional[int] = None,
    timestamp_header: Optional[str] = None,
    nonce_header: Optional[str] = None,
    signature_header: Optional[str] = None,
    cleanup_interval_ms: Optional[int] = None,
    max_entries: Optional[int] = None,
    get_client_id: Optional[Callable[[Context], Optional[str]]] = None,
) -> Middleware:
    # ----- Configuration -----

    # How old a signed request is allowed to be (seconds).
    max_age = max_age_seconds if max_age_seconds is not None else env_int("SIGNRQ_MAX_AGE_SECONDS", "300")

    # How far ahead of the server's clock the client's timestamp may be
    # (accommodates small clock differences between client and server).
    max_future = max_future_seconds if max_future_seconds is not None else env_int("SIGNRQ_MAX_FUTURE_SECONDS", "30")

    # Maximum size of the replay nonce.
    max_nonce = max_nonce_length if max_nonce_length is not None else env_int("SIGNRQ_MAX_NONCE_LENGTH", "256")

    ts_header = timestamp_header or os.environ.get("SIGNRQ_TIMESTAMP_HEADER") or "X-Signature-Timestamp"
    nonce_hdr = nonce_header or os.environ.get("SIGNRQ_NONCE_HEADER") or "X-Signature-Nonce"
    sig_header = signature_header or os.environ.get("SIGNRQ_SIGNATURE_HEADER") or "X-Signature"

    # How often expired replay entries are removed (default 60s).
    cleanup_ms = cleanup_interval_ms if cleanup_interval_ms is not None else env_int("SIGNRQ_CLEANUP_INTERVAL_MS", "60000")

    # Hard maximum number of replay entries held in memory.
    max_ent = max_entries if max_entries is not None else env_int("SIGNRQ_MAX_ENTRIES", "1000000")

    # ----- Client ID resolver -----
    def default_get_client_id(c: Context) -> Optional[str]:
        client = c.get("client")
        client_id = client.get("id") if isinstance(client, dict) else None
        return client_id if isinstance(client_id, str) else None

    resolve_client_id = get_client_id or default_get_client_id

    # ----- Validate configuration -----
    if not is_integer(max_age) or max_age <= 0:
        raise ValueError("replayProtection: maxAgeSeconds must be a positive integer")

    if not is_integer(max_future) or max_future < 0:
        raise ValueError("replayProtection: maxFutureSeconds must be a non-negative integer")

    if not is_integer(max_nonce) or max_nonce <= 0:
        raise ValueError("replayProtection: maxNonceLength must be a positive integer")

    if not callable(get_signing_secret):
        raise ValueError("replayProtection: getSigningSecret is required")

    # Create ONE store for this middleware instance (not inside the handler).
    store = MemoryReplayStore(cleanup_interval_ms=cleanup_ms, max_entries=max_ent)

    def unauthorized(c: Context, message: str, status: int = 401, response_status: int = 401):
        set_audit_error(
            c, {"name": "Error", "message": message, "code": "SIGN_RQ_ERR", "status": status}
        )

        return c.json({"error": "Unauthorized" if response_status == 401 else "Server error"}, response_status)

    async def middleware(c: Context, next):
        # ===== 1. AUTHENTICATED CLIENT =====
        client_id = resolve_client_id(c)

        if not client_id:
            return unauthorized(c, "Authentication required")

        # ===== 2. SIGNATURE TIMESTAMP =====
        timestamp_value = _get_header(c, ts_header)

        if not timestamp_value:
            return unauthorized(c, "Timestamp error. Timestamp missing in header")

        timestamp = _parse_timestamp(timestamp_value)

        if timestamp is None:
            return unauthorized(
                c,
                f"Timestamp error. Timestamp is undefined, probably could not be parsed from header ({timestamp})",
            )

        # ===== 3. NONCE =====
        nonce = _get_header(c, nonce_hdr)

        if not nonce:
            return unauthorized(c, "Nonce error, nonce missing")

        if len(nonce) > max_nonce:
            return unauthorized(
                c, f"Nonce error. Invalid nonce length (got {len(nonce)}, allowed {max_nonce}"
            )

        # ===== 4. SIGNATURE =====
        signature = _get_header(c, sig_header)

        if not signature:
            return unauthorized(c, "Signature error. Signature missing")

        # ===== 5. TIMESTAMP VALIDATION =====
        now = int(now_ms() // 1000)
        age = now - timestamp

        # Too old.
        if age > max_age:
            return unauthorized(c, f"Too old (age {age}, accepted {max_age})")

        # Too far into the future.
        if timestamp - now > max_future:
            return unauthorized(
                c,
                f"Too far in the future (client timestamp too far from server timestamp) (age {timestamp - now}, accepted {max_future})",
            )

        # ===== 6. GET SERVER-SIDE SIGNING SECRET =====
        signing_secret = get_signing_secret(c, client_id)

        if inspect.isawaitable(signing_secret):
            signing_secret = await signing_secret

        if not isinstance(signing_secret, str) or len(signing_secret) == 0:
            kind = "string" if isinstance(signing_secret, str) else (
                "undefined" if signing_secret is None else type(signing_secret).__name__
            )
            length = len(signing_secret) if isinstance(signing_secret, str) else None

            return unauthorized(
                c,
                f"Sign secret error. Invalid signing secret (invalid type ({kind}) or length {length})}}",
            )

        # ===== 7. READ REQUEST BODY (cached, so the handler can still read it) =====
        try:
            body = await c.req.text()
        except Exception:  # noqa: BLE001
            return unauthorized(c, "Request error. Cannot clone request body.")

        # ===== 8. HASH BODY =====
        body_hash = _sha256_hex(body)

        # ===== 9. BUILD CANONICAL REQUEST =====
        #
        # IMPORTANT: this MUST exactly match the Postman/client implementation.
        method = c.req.method.upper()
        path = c.req.pathname
        canonical_request = "\n".join([method, path, timestamp_value, nonce, body_hash])

        # ===== 10. VERIFY HMAC-SHA256 =====
        if not _verify_hmac_sha256(signing_secret, canonical_request, signature):
            return unauthorized(c, "Invalid signature")

        # ===== 11. CREATE REPLAY KEY (the signature is now verified) =====
        replay_key = f"{client_id}:{timestamp}:{nonce}"

        # ===== 12. CHECK + REMEMBER NONCE =====
        try:
            already_used = store.remember(replay_key, max_age + max_future)
        except RuntimeError as error:
            if str(error) == "REPLAY_STORE_CAPACITY_EXCEEDED":
                # Fail closed: do not accept signed requests when replay
                # tracking can no longer be guaranteed.
                return unauthorized(
                    c,
                    "Request error. replay_protection_unavailable: REPLAY_STORE_CAPACITY_EXCEEDED",
                    status=401,
                    response_status=503,
                )

            raise

        if already_used:
            return unauthorized(c, "Request error. Nonce already used")

        # ===== 13. CONTINUE TO ROUTE =====
        return await next()

    return middleware
