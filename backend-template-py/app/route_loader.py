"""
Route loader (port of src/routeLoader.ts).

Loads every route module found by the manifest, filters by route type
(public / protected), validates the HTTP method against ALLOWED_METHODS and
registers the route on the FastAPI app.

For each route, the middleware chain is:

    shared middlewares (e.g. api key auth)  ->  route middlewares  ->  processor

and it runs inside the request context created by the global pipeline, so the
whole thing behaves like the Hono route chain.
"""

from __future__ import annotations

import importlib.util
import inspect
import sys
from typing import Any

from fastapi import FastAPI, Request
from starlette.responses import Response

from app.config.methods import VALID_METHODS
from app.core.compose import Middleware, run_chain
from app.core.context import Context
from app.core.pipeline import CONTEXT_SCOPE_KEY
from app.helpers.err_handler import err_handler
from app.route_manifest import build_route_manifest
from app.route_types import RouteDefinition, RouteManifestEntry, RouteType


def _load_definition(entry: RouteManifestEntry) -> Any:
    """Import a route file by path (names like ``[p1].py`` are not importable)."""
    module_name = f"_route_{abs(hash(entry.file))}"
    spec = importlib.util.spec_from_file_location(module_name, entry.file)

    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {entry.file}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    return getattr(module, "route", None)


def _make_endpoint(route: str, definition: RouteDefinition, shared: list[Middleware]):
    chain = [*shared, *definition.middlewares]

    async def handler(c: Context) -> Response:
        result = definition.processor(route, c)
        return await result if inspect.isawaitable(result) else result

    async def endpoint(request: Request) -> Response:
        c: Context = request.scope[CONTEXT_SCOPE_KEY]
        return await run_chain(c, chain, handler, err_handler)

    return endpoint


def route_loader(
    app: FastAPI,
    manifest: list[RouteManifestEntry] | None,
    route_type: RouteType,
    shared_middlewares: list[Middleware] | None = None,
) -> None:
    shared = shared_middlewares or []
    manifest = manifest if manifest is not None else build_route_manifest()
    registered: set[str] = set()

    for entry in manifest:
        route = entry.route

        try:
            definition = _load_definition(entry)
        except Exception as error:  # noqa: BLE001
            print(f"[routeLoader] Failed to load route {route}:", error)
            continue

        if definition is None or not callable(getattr(definition, "processor", None)):
            print(f"[routeLoader] Skipping invalid route definition for {route}")
            continue

        if definition.route_type != route_type:
            continue

        if definition.method not in VALID_METHODS:
            print(
                f"[routeLoader] Skipping {route}: method '{definition.method}' not in ALLOWED_METHODS"
            )
            continue

        key = f"{definition.method} {route}"

        if key in registered:
            print(f"[routeLoader] Duplicate route skipped: {key}")
            continue

        registered.add(key)

        # Hono answers HEAD requests with the GET handler; Starlette does the
        # same only when told so.
        methods = [definition.method.upper()]

        if definition.method == "get":
            methods.append("HEAD")

        app.add_api_route(
            route,
            _make_endpoint(route, definition, shared),
            methods=methods,
            tags=[route_type],
            openapi_extra=(
                {"requestBody": definition.openapi_request_body}
                if definition.openapi_request_body
                else None
            ),
        )

        print(f"[routeLoader] [{route_type}] {definition.method.upper().ljust(6)} {route}")
