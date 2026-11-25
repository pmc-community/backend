"""
Hono-style request context.

Everything in the original code base is written against Hono's ``Context``
(``c``): ``c.req.header()``, ``c.get()/c.set()``, ``c.json()``, ``c.header()``
and so on.  This module provides the same surface on top of a raw ASGI scope so
that every middleware keeps its original shape and behaviour.

The context is created once per request by ``PipelineMiddleware`` and shared
between the global middleware chain, the per-route chain and the route handler,
exactly like Hono shares ``c`` between ``app.use('*')`` and route handlers.
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator
from urllib.parse import quote

from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

from app.core import uri

# node-server only attaches a body stream to methods other than GET and HEAD.
# Hono's `c.req.raw.body !== null` therefore means "method is not GET/HEAD".
NO_BODY_METHODS = frozenset({"GET", "HEAD"})


class ClientDisconnect(Exception):
    """The client went away while the request body was being read."""


class BodyTooLarge(Exception):
    """Raised by Req.read_limited() as soon as the limit is exceeded."""

    def __init__(self, bytes_read: int) -> None:
        super().__init__(f"request body exceeds limit ({bytes_read} bytes read)")
        self.bytes_read = bytes_read


def _reject_constant(name: str) -> Any:
    # JSON.parse rejects NaN / Infinity / -Infinity, Python's json accepts them.
    raise ValueError(f"Unexpected token {name} in JSON")


class Req:
    """Equivalent of ``c.req`` (HonoRequest) / ``c.req.raw`` (Fetch Request)."""

    def __init__(self, scope: dict, receive, variables: dict | None = None) -> None:
        self.scope = scope
        self._receive = receive
        self._variables = variables if variables is not None else {}
        self._body: bytes | None = None
        self._headers: dict[str, str] | None = None
        self._url: str | None = None

    # ------------------------------------------------------------------
    # Basics
    # ------------------------------------------------------------------

    @property
    def method(self) -> str:
        return self.scope["method"]

    @property
    def has_body_stream(self) -> bool:
        """``c.req.raw.body !== null`` under @hono/node-server."""
        return self.method.upper() not in NO_BODY_METHODS

    @property
    def has_declared_body(self) -> bool:
        """The request announces a body (Content-Length > 0 or Transfer-Encoding)."""
        if self.header("transfer-encoding") is not None:
            return True

        length = self.header("content-length")

        try:
            return length is not None and float(length) > 0
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Headers (Fetch Headers semantics: case-insensitive, duplicates joined)
    # ------------------------------------------------------------------

    @property
    def raw_headers(self) -> list[tuple[str, str]]:
        """Headers exactly as received (duplicates kept, lower-case names)."""
        return [
            (name.decode("latin-1").lower(), value.decode("latin-1"))
            for name, value in self.scope.get("headers", [])
        ]

    def _combined_headers(self) -> dict[str, str]:
        if self._headers is None:
            groups: dict[str, list[str]] = {}

            for name, value in self.raw_headers:
                groups.setdefault(name, []).append(value.strip())

            self._headers = {
                name: ("; " if name == "cookie" else ", ").join(values)
                for name, values in groups.items()
            }

        return self._headers

    def header(self, name: str) -> str | None:
        return self._combined_headers().get(name.lower())

    def header_items(self) -> list[tuple[str, str]]:
        """Iteration order of a Fetch Headers object: sorted, lower-case, combined."""
        return sorted(self._combined_headers().items())

    # ------------------------------------------------------------------
    # URL / path / query
    # ------------------------------------------------------------------

    @property
    def raw_query_string(self) -> str:
        return self.scope.get("query_string", b"").decode("latin-1")

    @property
    def url(self) -> str:
        """Absolute request URL, built the way @hono/node-server builds it."""
        if self._url is None:
            scheme = "https" if self.scope.get("scheme") in ("https", "wss") else "http"

            host = None
            for name, value in self.raw_headers:
                if name == "host":
                    host = value.strip()
                    break

            if not host:
                server = self.scope.get("server")
                host = f"{server[0]}:{server[1]}" if server else "localhost"

            raw_path = self.scope.get("raw_path")
            path = (
                raw_path.decode("latin-1")
                if raw_path
                else quote(self.scope.get("path", "/"), safe="/%")
            )

            query = self.raw_query_string
            self._url = f"{scheme}://{host}{path}" + (f"?{query}" if query else "")

        return self._url

    @property
    def path(self) -> str:
        """``c.req.path`` (Hono getPath)."""
        return uri.get_path(self.url)

    @property
    def pathname(self) -> str:
        """``new URL(c.req.url).pathname`` (raw, still percent-encoded)."""
        url = self.url
        start = url.index("/", url.index(":") + 4)
        end = len(url)

        for marker in ("?", "#"):
            index = url.find(marker, start)

            if index != -1:
                end = min(end, index)

        return url[start:end]

    @property
    def search(self) -> str:
        """``new URL(c.req.url).search`` ('' or '?a=b')."""
        query = self.raw_query_string
        return f"?{query}" if query else ""

    def search_params(self) -> list[tuple[str, str]]:
        """``Array.from(new URL(c.req.url).searchParams.entries())``."""
        return uri.search_params(self.raw_query_string)

    def valid(self, target: str) -> Any:
        """``c.req.valid('json')``: data stored by a validator middleware."""
        return self._variables.get(f"valid:{target}")

    def param(self, name: str) -> str | None:
        """``c.req.param(name)`` for routes registered with path parameters."""
        return self.scope.get("path_params", {}).get(name)

    # ------------------------------------------------------------------
    # Body
    # ------------------------------------------------------------------

    async def stream(self) -> AsyncIterator[bytes]:
        if self._body is not None:
            if self._body:
                yield self._body
            return

        while True:
            message = await self._receive()
            kind = message["type"]

            if kind == "http.request":
                chunk = message.get("body", b"")

                if chunk:
                    yield chunk

                if not message.get("more_body", False):
                    return

            elif kind == "http.disconnect":
                raise ClientDisconnect()

    async def body(self) -> bytes:
        """Whole body, cached so that every later reader sees the same bytes."""
        if self._body is None:
            chunks: list[bytes] = []

            async for chunk in self.stream():
                chunks.append(chunk)

            self._body = b"".join(chunks)

        return self._body

    async def read_limited(self, max_bytes: int) -> bytes:
        """
        Read the body, giving up as soon as it is larger than ``max_bytes``.

        On success the body is cached, so downstream code (``c.req.json()`` and
        friends) can still read it - the equivalent of the ``request.clone()``
        used by the original sizeLimiter.
        """
        if self._body is not None:
            if len(self._body) > max_bytes:
                raise BodyTooLarge(len(self._body))
            return self._body

        total = 0
        chunks: list[bytes] = []

        async for chunk in self.stream():
            total += len(chunk)

            if total > max_bytes:
                raise BodyTooLarge(total)

            chunks.append(chunk)

        self._body = b"".join(chunks)
        return self._body

    async def text(self) -> str:
        """``await request.text()``: UTF-8 decode, BOM stripped, invalid bytes -> U+FFFD."""
        text = (await self.body()).decode("utf-8", errors="replace")
        return text[1:] if text.startswith("\ufeff") else text

    async def json(self) -> Any:
        """``await c.req.json()`` (raises ValueError on malformed JSON)."""
        return json.loads(await self.text(), parse_constant=_reject_constant)


class Context:
    """Equivalent of Hono's ``Context`` (``c``)."""

    def __init__(self, scope: dict, receive) -> None:
        self.scope = scope
        self._vars: dict[str, Any] = {}
        self.req = Req(scope, receive, self._vars)
        self._prepared: list[tuple[str, str]] = []

    # ------------------------------------------------------------------
    # Connection info (the equivalent of c.env.incoming.socket)
    # ------------------------------------------------------------------

    @property
    def remote_address(self) -> str | None:
        client = self.scope.get("client")
        return client[0] if client else None

    # ------------------------------------------------------------------
    # Variables
    # ------------------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        return self._vars.get(key, default)

    def set(self, key: str, value: Any) -> None:
        self._vars[key] = value

    def valid(self, target: str) -> Any:
        """``c.req.valid('json')``: data stored by a validator middleware."""
        return self._vars.get(f"valid:{target}")

    # ------------------------------------------------------------------
    # Headers applied to the next response built through c.json()/c.text()...
    # ------------------------------------------------------------------

    def header(self, name: str, value: str | None, append: bool = False) -> None:
        lower = name.lower()

        if value is None:
            self._prepared = [(k, v) for k, v in self._prepared if k != lower]
            return

        if not append:
            self._prepared = [(k, v) for k, v in self._prepared if k != lower]

        self._prepared.append((lower, value))

    def apply_prepared_headers(self, response: Response, only_missing: bool = False) -> Response:
        existing = {k.decode("latin-1").lower() for k, _ in response.raw_headers}

        for name, value in self._prepared:
            if only_missing and name in existing:
                continue

            response.raw_headers.append(
                (name.encode("latin-1"), value.encode("latin-1"))
            )

        return response

    # ------------------------------------------------------------------
    # Response helpers
    # ------------------------------------------------------------------

    def json(self, data: Any, status: int = 200) -> Response:
        return self.apply_prepared_headers(JSONResponse(data, status_code=status))

    def text(self, text: str, status: int = 200) -> Response:
        return self.apply_prepared_headers(PlainTextResponse(text, status_code=status))

    def html(self, html: str, status: int = 200) -> Response:
        return self.apply_prepared_headers(HTMLResponse(html, status_code=status))


# ----------------------------------------------------------------------
# Response utilities used by middleware that post-process responses
# ----------------------------------------------------------------------


def make_response(
    body: bytes,
    status: int,
    raw_headers: list[tuple[bytes, bytes]],
) -> Response:
    """Rebuild a response from captured parts, keeping the header list verbatim."""
    response = Response(content=body, status_code=status)
    response.raw_headers = list(raw_headers)
    return response
