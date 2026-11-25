"""
JavaScript-compatible URI helpers.

Hono derives ``c.req.path`` with ``decodeURI`` (falling back to a partial
decode when the path is malformed) and parses query strings with
``URLSearchParams``.  These helpers reproduce those semantics so the length
checks, pattern matching and audit logging see the same strings they did in
the original Hono implementation.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qsl

# decodeURI() never decodes escape sequences of these reserved characters.
URI_RESERVED = ";/?:@&=+$,#"

_HEX = "0123456789abcdefABCDEF"
_PCT_RUN = re.compile(r"(?:%[0-9A-Fa-f]{2})+")


def _js_decode(value: str, reserved: str) -> str:
    """Strict percent-decoding with JS decodeURI / decodeURIComponent semantics.

    Raises ValueError where JavaScript would raise URIError.
    """
    out: list[str] = []
    i = 0
    n = len(value)

    while i < n:
        ch = value[i]

        if ch != "%":
            out.append(ch)
            i += 1
            continue

        hex_pair = value[i + 1:i + 3]

        if len(hex_pair) != 2 or any(h not in _HEX for h in hex_pair):
            raise ValueError("URI malformed")

        first = int(hex_pair, 16)

        # Single byte (ASCII)
        if first < 0x80:
            char = chr(first)
            out.append(value[i:i + 3] if char in reserved else char)
            i += 3
            continue

        # Multi-byte UTF-8 sequence
        if first & 0xE0 == 0xC0:
            need = 2
        elif first & 0xF0 == 0xE0:
            need = 3
        elif first & 0xF8 == 0xF0:
            need = 4
        else:
            raise ValueError("URI malformed")

        buf = bytearray([first])
        j = i + 3

        for _ in range(need - 1):
            pair = value[j + 1:j + 3]

            if (
                j >= n
                or value[j] != "%"
                or len(pair) != 2
                or any(h not in _HEX for h in pair)
            ):
                raise ValueError("URI malformed")

            next_byte = int(pair, 16)

            if next_byte & 0xC0 != 0x80:
                raise ValueError("URI malformed")

            buf.append(next_byte)
            j += 3

        # Strict decoding rejects overlong forms, surrogates and > U+10FFFF.
        out.append(bytes(buf).decode("utf-8"))
        i = j

    return "".join(out)


def decode_uri(value: str) -> str:
    return _js_decode(value, URI_RESERVED)


def decode_uri_component(value: str) -> str:
    return _js_decode(value, "")


def try_decode(value: str, decoder) -> str:
    """Hono's tryDecode: full decode, else decode each %XX run independently."""
    try:
        return decoder(value)
    except ValueError:

        def _sub(match: re.Match) -> str:
            try:
                return decoder(match.group(0))
            except ValueError:
                return match.group(0)

        return _PCT_RUN.sub(_sub, value)


def try_decode_uri(value: str) -> str:
    return try_decode(value, decode_uri)


def try_decode_uri_component(value: str) -> str:
    return try_decode(value, decode_uri_component) if "%" in value else value


def get_path(url: str) -> str:
    """Port of hono/utils/url getPath(): path (no query) taken from an absolute URL."""
    start = url.index("/", url.index(":") + 4)
    i = start

    while i < len(url):
        code = url[i]

        if code == "%":
            query_index = url.find("?", i)
            hash_index = url.find("#", i)

            if query_index == -1:
                end = None if hash_index == -1 else hash_index
            else:
                end = query_index if hash_index == -1 else min(query_index, hash_index)

            path = url[start:end]

            return try_decode_uri(
                path.replace("%25", "%2525") if "%25" in path else path
            )

        if code in ("?", "#"):
            break

        i += 1

    return url[start:i]


def search_params(query_string: str) -> list[tuple[str, str]]:
    """URLSearchParams entries for a raw query string (without the leading '?')."""
    if not query_string:
        return []

    return parse_qsl(
        query_string,
        keep_blank_values=True,
        encoding="utf-8",
        errors="replace",
    )
