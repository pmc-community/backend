"""
FastAPI backend template - application entry point (port of server.ts).

    python main.py                       # starts the server (see DEPLOY_ENV)
    uvicorn main:app                     # or let any ASGI server import `app`

DEPLOY_ENV:
    local               HTTPS with ./key.pem + ./cert.pem, auto-reload, no graceful shutdown
    simprod / others    plain HTTP (TLS is terminated upstream), graceful shutdown enabled
    cloudflare_workers  the server is not started, only the ASGI ``app`` is exported
"""

from __future__ import annotations

import asyncio
import os
import signal
import ssl
from contextlib import asynccontextmanager
from typing import Optional

import uvicorn
from fastapi import FastAPI
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request
from starlette.responses import PlainTextResponse

import app  # noqa: F401  - loads .env before anything reads the environment

# ------ DATA / CONFIG --------
from app.data_provider import data
from app.helpers.err_handler import err_handler
from app.helpers.js import env_int
from app.helpers.server_log import log_concurrent_requests, log_suspicious_request
from app.helpers.utilities import get_client_ip, get_server_identity_sync

# ------ MIDDLEWARES --------
from app.core.pipeline import PipelineMiddleware
from app.middleware.apikey import api_key_auth
from app.middleware.audit_logger import audit_logger
from app.middleware.auth_failure_limiter import auth_failure_limiter
from app.middleware.concurrency_limiter import concurrency_limiter
from app.middleware.content_type_limiter import content_type_limiter
from app.middleware.cors import cors_settings
from app.middleware.duplicate_header_protection import duplicate_header_protection
from app.middleware.graceful_shutdown import create_graceful_shutdown
from app.middleware.header_size_limiter import header_size_limiter
from app.middleware.host_validation import host_validation
from app.middleware.ip_custom_limiter import ip_custom_limiter
from app.middleware.logger import logger
from app.middleware.overload_circuit_breaker import overload_circuit_breaker
from app.middleware.pagination_limiter import pagination_limiter
from app.middleware.query_parameter_limiter import query_parameter_limiter
from app.middleware.rate_limiter import rate_limiter
from app.middleware.request_id import request_id
from app.middleware.response_size_limiter import response_size_limiter
from app.middleware.secure_headers import secure_headers
from app.middleware.suspicious_request_detector import suspicious_request_detector
from app.middleware.timeout_limiter import timeout_limiter
from app.middleware.url_limiter import url_length_limiter
# ------ END MIDDLEWARES -----

from app.hooks.hooks_def import register_hooks
from app.route_loader import route_loader
from app.route_manifest import build_route_manifest

DEPLOY_ENV = os.environ.get("DEPLOY_ENV")
IS_LOCAL = DEPLOY_ENV == "local"

# ------------------------------------------------------------
# Graceful shutdown (not used for local dev / Cloudflare Workers)
# ------------------------------------------------------------

if DEPLOY_ENV not in ("local", "cloudflare_workers"):
    graceful_shutdown, shutdown_controller = create_graceful_shutdown(
        status=503,
        message="Service is shutting down.",
        # after the shutdown signal, until the drain completes, all requests
        # except the ones here get 503
        exclude_paths=["/status"],
    )
else:
    graceful_shutdown, shutdown_controller = None, None

_event_loop: Optional[asyncio.AbstractEventLoop] = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global _event_loop

    _event_loop = asyncio.get_running_loop()

    data.start_data_hot_reload()

    try:
        yield
    finally:
        data.stop_data_hot_reload()

        if shutdown_controller is not None:
            # uvicorn re-raises the termination signal once it has finished, so
            # this is the last point where the process can still log.
            print("Server closed.")


def _concurrency_key(c) -> str:
    client = c.get("client")

    # Authenticated API client
    if client and client.get("id"):
        return f"client:{client['id']}"

    # Unauthenticated request
    return f"ip:{get_client_ip(c)}"


def create_app() -> FastAPI:
    server_identity = get_server_identity_sync(name=os.environ.get("SERVER_NAME") or "api")

    docs_enabled = os.environ.get("ENABLE_DOCS") == "true"

    fastapi_app = FastAPI(
        title=server_identity.name,
        lifespan=lifespan,
        # The original API exposes no documentation endpoints.  Enable them
        # explicitly with ENABLE_DOCS=true.
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )

    # ------------------------------------------------------------
    # Global middleware (order matters - first = outermost)
    # ------------------------------------------------------------

    global_middlewares = [
        *([graceful_shutdown] if graceful_shutdown else []),
        request_id(),
        logger(),
        audit_logger(server_identity=server_identity),
        overload_circuit_breaker(),
        # custom IP restriction (hot-reloads the list of denied IPs)
        ip_custom_limiter,
        host_validation(),
        content_type_limiter(),
        concurrency_limiter(
            max_concurrent=env_int("CO_MAX_ALLOWED", "10"),
            key=_concurrency_key,
            on_reject=log_concurrent_requests,
        ),
        suspicious_request_detector(
            threshold=env_int("SRD_THRESHOLD", "5"),
            block=os.environ.get("SRD_BLOCK_SUSPICIOUS_REQUESTS") == "true",
            on_detect=lambda event, c: log_suspicious_request(event),
        ),
        duplicate_header_protection(),
        secure_headers(),
        cors_settings,
        url_length_limiter(),
        header_size_limiter(),
        # csrf(),  # --> to be applied only for routes that serve browser/cookie-authenticated clients
        pagination_limiter(),
        query_parameter_limiter(),
        rate_limiter(env_int("maxRqPerMin", "100")),
        timeout_limiter(env_int("defaultTimeout", "30")),
        response_size_limiter(10 * env_int("maxResponseBytesBase", "1024") ** 2),
    ]

    fastapi_app.add_middleware(
        PipelineMiddleware,
        middlewares=global_middlewares,
        on_error=err_handler,
    )

    # Hono answers unknown routes (and wrong methods) with a plain 404.
    @fastapi_app.exception_handler(StarletteHTTPException)
    async def _http_exception_handler(request: Request, exc: StarletteHTTPException):
        if exc.status_code in (404, 405):
            return PlainTextResponse("404 Not Found", status_code=404)

        return PlainTextResponse(str(exc.detail), status_code=exc.status_code)

    # ************************************************************
    # START ROUTES DEFINITION
    manifest = build_route_manifest()

    # Public routes - no api key required
    route_loader(fastapi_app, manifest, "public")

    # Protected routes - api key and limits protection
    route_loader(
        fastapi_app,
        manifest,
        "protected",
        # additional middlewares that make the routes protected
        [auth_failure_limiter, api_key_auth],
    )
    # END ROUTES DEFINITION
    # ************************************************************

    register_hooks()  # --> register hooks for after function(s) execution

    return fastapi_app


app = create_app()


# ------------------------------------------------------------
# Server
# ------------------------------------------------------------


class GracefulServer(uvicorn.Server):
    """
    Graceful shutdown with request draining (the SIGINT / SIGTERM handlers of
    the original server.ts):

      1. new requests get 503 (except /status) from the moment the signal arrives
      2. wait (up to 30 s) until the in-flight requests have finished
      3. only then ask uvicorn to stop
    """

    _shutting_down = False

    def handle_exit(self, sig: int, frame) -> None:  # type: ignore[override]
        if self._shutting_down:
            print("Shutdown already in progress.")
            return

        self._shutting_down = True

        if _event_loop is None or shutdown_controller is None:
            super().handle_exit(sig, frame)
            return

        _event_loop.call_soon_threadsafe(
            lambda: _event_loop.create_task(self._drain_then_exit(sig, frame))  # type: ignore[union-attr]
        )

    async def _drain_then_exit(self, sig: int, frame) -> None:
        assert shutdown_controller is not None

        name = signal.Signals(sig).name

        print(f"Received {name}; starting graceful shutdown.")
        print(f"Active requests before drain: {shutdown_controller.active_requests()}")

        shutdown_controller.start_draining()

        drained = await shutdown_controller.wait_for_drain(30_000)

        print(f"Drain completed: {drained}; active requests: {shutdown_controller.active_requests()}")

        if not drained:
            print(
                f"Graceful shutdown timeout reached with {shutdown_controller.active_requests()} active request(s)."
            )

        print("Closing server...")

        super().handle_exit(sig, frame)


def run() -> None:
    if DEPLOY_ENV == "cloudflare_workers":
        # Only the ASGI app is exported; the platform serves it.
        return

    port = int(
        (os.environ.get("DEV_PORT") or "3000")
        if IS_LOCAL
        else (os.environ.get("PROD_PORT") or "443")
    )

    common = dict(
        host="0.0.0.0",
        port=port,
        # IMPORTANT: the application evaluates X-Forwarded-* itself, based on the
        # trusted-proxy lists.  uvicorn must not rewrite the peer address.
        proxy_headers=False,
        server_header=False,
        # the audit logger and the request logger already log every request
        access_log=False,
    )

    if IS_LOCAL:
        # portable configuration for local development (HTTPS, auto-reload)
        print(f"Listening on https://0.0.0.0:{port}")

        uvicorn.run(
            "main:app",
            ssl_keyfile="./key.pem",
            ssl_certfile="./cert.pem",
            ssl_version=ssl.PROTOCOL_TLS_SERVER,
            reload=os.environ.get("RELOAD", "true") != "false",
            **common,  # type: ignore[arg-type]
        )
        return

    print(f"Listening on http://0.0.0.0:{port}")

    config = uvicorn.Config(app, timeout_graceful_shutdown=35, **common)  # type: ignore[arg-type]
    server = GracefulServer(config)
    server.run()


if __name__ == "__main__":
    run()
