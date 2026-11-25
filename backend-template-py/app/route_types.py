"""Route definition types (port of src/types/route.ts)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Literal

from starlette.responses import Response

from app.core.compose import Middleware
from app.core.context import Context

HttpMethod = Literal["get", "post", "put", "patch", "delete", "options"]
RouteType = Literal["public", "protected"]

# processor(route, c) -> Response (sync or async)
RouteProcessor = Callable[[str, Context], "Response | Awaitable[Response]"]


@dataclass
class RouteDefinition:
    method: HttpMethod
    route_type: RouteType
    processor: RouteProcessor
    middlewares: list[Middleware] = field(default_factory=list)

    # Optional OpenAPI request-body schema, only used when ENABLE_DOCS=true.
    openapi_request_body: dict[str, Any] | None = None


@dataclass
class RouteManifestEntry:
    route: str          # FastAPI/Starlette path, e.g. /test/proute/{p1}
    file: str           # absolute path of the route module
