# FastAPI backend template

Python / FastAPI implementation of the Hono + TypeScript `backend-template`. Every middleware,
data list, hook, route and script keeps its original logic, order and error codes.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env                 # then edit
python -m scripts.build_lists        # normalizes ./data/**/*.txt (was: npm run build:lists)
python -m scripts.generate_key       # create an API key, store its hash in keystore.json
python main.py                       # DEPLOY_ENV=local -> https://localhost:3000 (needs key.pem + cert.pem)
pytest                               # integration + unit tests (starts real uvicorn servers)
```

Run it from the project root (the `./data/...` paths are relative to the working directory).
`uvicorn main:app` also works, but then pass `--no-proxy-headers` (see note 3).

## Layout

| Original (TypeScript)                    | FastAPI port                                                        |
|------------------------------------------|---------------------------------------------------------------------|
| `server.ts`                              | `main.py`                                                           |
| `src/routes/**/*.ts` (+ generate-routes) | `app/routes/**/*.py`, `app/route_manifest.py`, `app/route_loader.py` |
| `src/middleware/*.ts`                    | `app/middleware/*.py` (+ Hono built-ins: `cors`, `secure_headers`, `request_id`, `logger`, `ip_restriction`, `validator`) |
| Hono `Context` / `compose` / `onError`   | `app/core/context.py`, `compose.py`, `pipeline.py`, `http_exception.py` |
| `src/data.provider/**`                   | `app/data_provider/**`                                              |
| `src/helpers`, `hooks`, `keystore`, `config` | same names under `app/`                                         |
| zod schemas                              | Pydantic models (`app/config/body_schemas.py`)                      |
| `scripts/*.ts`                           | `scripts/build_lists.py`, `scripts/generate_key.py`, `postman-pre-request.js` (unchanged) |

### How the Hono model maps onto FastAPI

* **Global middleware** (`app.use('*')`) is one ASGI middleware (`PipelineMiddleware`) that runs the
  Hono-style onion chain around the whole FastAPI app (404s included). The order is in `main.py`.
* **Route middleware** (`middlewares=[...]` in a route file) runs per route, after the shared
  middleware of its type (`[auth_failure_limiter, api_key_auth]` for protected routes).
* A middleware is `async def mw(c, next) -> Response`. Raising `HTTPException(status, message)` is
  converted to `{"error": message}` at the point where it is raised (like Hono's `onError`), so outer
  middleware (audit logger, circuit breaker, ...) see the error *response*, never the exception.
* File routes: `[id].py` -> `{id}`, `[...slug].py` -> `{slug:path}`, `index.py`/`route.py` -> folder
  route; `.routeignore` is honored; static routes register before dynamic ones.
* Docs endpoints are off (the original exposes none); `ENABLE_DOCS=true` enables `/docs`, `/redoc`,
  `/openapi.json`.

## Notes: behavior that differs from, or was fixed in, the port

1. **`contentTypeLimiter` body detection.** The original tested `request.body !== null`, which
   `@hono/node-server` makes true for every method except GET/HEAD, so CORS preflights and body-less
   POST/DELETE were answered 415 despite the documented policy ("no body + no Content-Type -> allowed").
   The port implements the documented policy (`Content-Length > 0` or `Transfer-Encoding`).
   `jsonOnlyLimiter`, `sizeLimiter` and `noBodyLimiter` keep the original GET/HEAD-based check.
2. **`hostValidation` trusted proxies.** The original iterated over the *characters* of the
   `TRUSTED_PROXY_IPS` string (and snapshotted it at startup). The port parses the comma-separated
   values and reads them on every request, so hot reload works.
3. **uvicorn `proxy_headers=False`** is set in `main.py`. Otherwise uvicorn rewrites the peer address
   from `X-Forwarded-For`, and the trusted-proxy logic would act on a client-controlled value.
4. **Graceful shutdown** hooks uvicorn's signal handler (`GracefulServer`): new requests get 503
   (except `/status`), in-flight requests are drained (30 s), then uvicorn stops.
5. Data lists are **lower-cased** on load and by `build_lists` (regex lists too) - write patterns
   accordingly (`\d`, not `\D`). JS regex literals in `data/` are translated to Python `re`.
6. CORS allowed methods/headers are read once at startup (as in Hono); the blocked-origin list hot-reloads.
7. `NODE_ENV`, `minuteInMs`, ... keep their original names so an existing `.env` keeps working.
8. Original quirk kept: the global concurrency limiter runs before API-key auth, so it always keys on IP.
9. `/test/page` is a plain HTML response (no JSX renderer); `whoami` uses `httpx` for the geo lookup.
10. Single process only: rate limiters, replay store, circuit breaker and auth-failure counters are
    in memory (as before). Do not run multiple workers without moving them to a shared store.
