"""
Production Dockerfile generator.

    python -m scripts.generate_dockerfile                 # run from the project root
    python -m scripts.generate_dockerfile --help

Reads the API server configuration AS IT IS AT THIS MOMENT (``.env``, the
requirements, the data lists, the keystore, the route files) and writes:

    Dockerfile                  a two-stage, Ubuntu-based production image
    Dockerfile.dockerignore     allow-list build context (only what the server needs)

The server is assumed to be production-ready when the generator runs, so no
preparation step is baked into the image and no setting is changed: the image
reflects the configuration as it is (DEPLOY_ENV=local included: HTTPS with
key.pem/cert.pem).  The generator only checks that the files and settings it
reads can actually start inside a container, and fails before you waste a build.

Requires Docker with BuildKit (default since Docker 23): the Dockerfile uses
``COPY <<heredoc``, ``COPY --chmod`` and a ``Dockerfile.dockerignore``.

Nothing here is imported by the server; it only uses python-dotenv, which is
already a dependency.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parent.parent

APP_DIR = "/app"
VENV_DIR = "/opt/venv"
APP_USER = "app"
APP_UID = 10001

# Settings the generator needs to know about.  A value exported in the shell
# wins over the one in the env file (same precedence the server itself uses).
CRITICAL_KEYS = ("DEPLOY_ENV", "DATA_SOURCE", "KEYSTORE_PATH", "PROD_PORT", "DEV_PORT", "SERVER_NAME")

# Packages that are only needed to develop / test the server.
DEV_PACKAGES = {
    "pytest", "pytest-asyncio", "pytest-cov", "pytest-mock", "pytest-xdist",
    "coverage", "mock", "hypothesis", "black", "ruff", "flake8", "mypy",
    "isort", "pylint", "pre-commit", "tox", "nox",
}

# Same drain window as main.py (30 s) + uvicorn's timeout_graceful_shutdown (35 s).
RECOMMENDED_STOP_TIMEOUT = 40


class GeneratorError(Exception):
    """The configuration cannot produce a working production image."""


@dataclass
class Plan:
    config: dict[str, str]
    deploy_env: str
    data_source: str
    port: int
    port_var: str                       # DEV_PORT (local) or PROD_PORT
    is_local: bool
    tls_files: list[str]                # key.pem / cert.pem, local only
    server_name: str
    base_image: str
    env_rel: str                        # env file, relative to the project root (it is copied to /app/.env)
    uses_local_keystore: bool
    keystore_rel: str | None            # path of the keystore inside the project
    keystore_container_path: str | None
    bake_keystore: bool
    requirements: list[str]
    dropped_requirements: list[str]
    healthcheck_host_file: str
    routes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------


def load_config(env_file: Path) -> dict[str, str]:
    """env file values, with the shell's values winning for the keys we care about."""
    config: dict[str, str] = {}

    config.update({k: v for k, v in dotenv_values(env_file).items() if v is not None})

    for key in CRITICAL_KEYS:
        if os.environ.get(key):
            config[key] = os.environ[key]

    return config


def parse_requirements(path: Path) -> tuple[list[str], list[str]]:
    """Runtime requirements and the dev/test ones that were dropped."""
    if not path.is_file():
        raise GeneratorError(f"{path.name} not found - the image needs it to install the dependencies.")

    keep: list[str] = []
    dropped: list[str] = []

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split(" #", 1)[0].strip()

        if not line or line.startswith("#"):
            continue

        name = re.split(r"[\s\[<>=!~;@]", line, maxsplit=1)[0].lower().replace("_", "-")

        (dropped if name in DEV_PACKAGES else keep).append(line)

    if not keep:
        raise GeneratorError("requirements.txt has no runtime dependencies.")

    return keep, dropped


# --------------------------------------------------------------------------
# probing the real code (in a subprocess, so the generator never imports the app)
# --------------------------------------------------------------------------

_PROBE = r"""
import json, os, sys
sys.path.insert(0, os.getcwd())
out = {}

try:
    from app.keystore.provider import keystore_provider
    out["keystore_module"] = keystore_provider().__name__
except Exception as e:
    out["keystore_error"] = str(e)

try:
    from app.data_provider.provider import is_backend_name
    out["data_source_ok"] = bool(is_backend_name(os.environ.get("DATA_SOURCE", "")))
except Exception as e:
    out["data_source_probe_error"] = str(e)

try:
    from app.route_manifest import build_route_manifest
    out["routes"] = [e.route for e in build_route_manifest()]
except Exception as e:
    out["routes_error"] = str(e)

print("@@PROBE@@" + json.dumps(out))
"""


def probe(config: dict[str, str]) -> dict:
    env = {**os.environ, **{k: config[k] for k in ("DEPLOY_ENV", "DATA_SOURCE") if k in config}}
    env["PYTHONPATH"] = str(ROOT)

    result = subprocess.run(
        [sys.executable, "-c", _PROBE],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=60,
    )

    for line in reversed(result.stdout.splitlines()):
        if line.startswith("@@PROBE@@"):
            return json.loads(line[len("@@PROBE@@"):])

    return {"probe_failed": (result.stderr or result.stdout).strip().splitlines()[-1:] or ["no output"]}


def listed_fs_data_files() -> list[str]:
    """Every ``./data/...`` list the server loads (read from app/data_provider/data.py)."""
    source = (ROOT / "app" / "data_provider" / "data.py").read_text(encoding="utf-8")
    return sorted(set(re.findall(r'"fs"\s*:\s*"\./(data/[^"]+)"', source)))


def unnormalized_lists() -> list[str]:
    """Lists that scripts/build_lists.py would still change (warning only)."""
    bad: list[str] = []

    for path in sorted((ROOT / "data").rglob("*.txt")):
        text = path.read_text(encoding="utf-8")
        values = {v for v in (line.strip().lower() for line in text.splitlines()) if v}

        if text != "\n".join(sorted(values)) + "\n":
            bad.append(path.relative_to(ROOT).as_posix())

    return bad


# --------------------------------------------------------------------------
# planning + validation
# --------------------------------------------------------------------------


def inside_project(path: Path) -> str | None:
    """Posix path relative to the project root, or None when outside of it."""
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return None


def build_plan(args: argparse.Namespace) -> Plan:
    warnings: list[str] = []

    if not args.base_image.lower().startswith("ubuntu"):
        raise GeneratorError(f"The image must be Ubuntu based; --base-image is '{args.base_image}'.")

    env_file = (ROOT / args.env_file) if not Path(args.env_file).is_absolute() else Path(args.env_file)

    if not env_file.is_file():
        raise GeneratorError(f"Env file '{args.env_file}' not found - it is the server configuration.")

    env_rel = inside_project(env_file)

    if env_rel is None:
        raise GeneratorError("The env file must be inside the project directory (Docker build context).")

    config = load_config(env_file)

    deploy_env = config.get("DEPLOY_ENV", "")

    if not deploy_env:
        raise GeneratorError("DEPLOY_ENV is not set - the server refuses to start without it.")

    if deploy_env == "cloudflare_workers":
        raise GeneratorError("DEPLOY_ENV=cloudflare_workers does not start a server - nothing to run in a container.")

    data_source = config.get("DATA_SOURCE", "")

    if not data_source:
        raise GeneratorError("DATA_SOURCE is not set - the data loader refuses to start without it.")

    is_local = deploy_env == "local"
    port_var, port_default = ("DEV_PORT", "3000") if is_local else ("PROD_PORT", "443")  # same defaults as main.py
    raw_port = config.get(port_var) or port_default

    try:
        port = int(raw_port)
        assert 0 < port < 65536
    except (ValueError, AssertionError):
        raise GeneratorError(f"{port_var}='{raw_port}' is not a valid TCP port.") from None

    # local mode serves HTTPS from ./key.pem and ./cert.pem (main.py)
    tls_files = ["key.pem", "cert.pem"] if is_local else []
    missing_tls = [f for f in tls_files if not (ROOT / f).is_file()]

    if missing_tls:
        raise GeneratorError(f"DEPLOY_ENV=local needs {', '.join(missing_tls)} in the project root (HTTPS) - not found.")

    # ---- ask the real code what it will do with this configuration ----
    probe_config = {**config, "DEPLOY_ENV": deploy_env}
    info = probe(probe_config)

    if "probe_failed" in info:
        warnings.append(
            "Could not run the checks against the app code (are the dependencies installed here?): "
            + " ".join(info["probe_failed"])
        )

    if "keystore_error" in info:
        raise GeneratorError(f"The server would crash on its first authenticated request: {info['keystore_error']}")

    if info.get("data_source_ok") is False:
        raise GeneratorError(f"DATA_SOURCE='{data_source}' is not a data backend known to the server.")

    uses_local_keystore = info.get("keystore_module", "").endswith("keystore.local.keystore")

    # ---- data lists ----
    if data_source == "fs":
        missing = [p for p in listed_fs_data_files() if not (ROOT / p).is_file()]

        if missing:
            raise GeneratorError("Data list(s) the server loads at startup are missing:\n  " + "\n  ".join(missing))

        stale = unnormalized_lists()

        if stale:
            warnings.append(
                f"{len(stale)} data list(s) are not normalized (run `python -m scripts.build_lists`): "
                + ", ".join(stale[:5]) + (" ..." if len(stale) > 5 else "")
            )
    else:
        warnings.append(f"DATA_SOURCE='{data_source}': only the local ./data folder is baked into the image.")

    # ---- keystore ----
    keystore_rel = keystore_container_path = None

    if uses_local_keystore:
        raw_keystore = config.get("KEYSTORE_PATH", "")

        if not raw_keystore:
            raise GeneratorError("KEYSTORE_PATH is not set - the local keystore needs it.")

        keystore = Path(raw_keystore) if Path(raw_keystore).is_absolute() else ROOT / raw_keystore

        if args.external_keystore:
            keystore_container_path = (
                raw_keystore if raw_keystore.startswith("/")
                else str(PurePosixPath(APP_DIR) / PurePosixPath(raw_keystore.replace("\\", "/")))
            )
            keystore_container_path = os.path.normpath(keystore_container_path)
        else:
            if not keystore.is_file():
                raise GeneratorError(f"Keystore '{raw_keystore}' not found - the API would reject every key.")

            keystore_rel = inside_project(keystore)

            if keystore_rel is None:
                raise GeneratorError(
                    f"Keystore '{raw_keystore}' is outside the project, so it cannot be part of the build context.\n"
                    "  Move it into the project or use --external-keystore and mount it at run time."
                )

            keystore_container_path = f"{APP_DIR}/{keystore_rel}"

    # ---- requirements ----
    requirements, dropped = parse_requirements(ROOT / "requirements.txt")

    if any(not re.search(r"==", r) for r in requirements):
        warnings.append("requirements.txt is not fully pinned (==): rebuilds may pull newer dependency versions.")

    # ---- routes ----
    routes = info.get("routes", [])
    test_routes = [r for r in routes if r == "/test" or r.startswith("/test/")]

    if test_routes:
        warnings.append(
            "These test routes are served by the image: " + ", ".join(test_routes)
            + " (add `test` to .routeignore to leave them out)."
        )

    if "/status" not in routes and routes:
        warnings.append("No /status route found - the HEALTHCHECK in the image will report unhealthy.")

    if not (ROOT / ".routeignore").is_file():
        raise GeneratorError(".routeignore not found - the server reads it at startup and it must be in the image.")

    if not (ROOT / "main.py").is_file() or not (ROOT / "app").is_dir():
        raise GeneratorError("main.py / app/ not found - run the generator from the project.")

    return Plan(
        config=config,
        deploy_env=deploy_env,
        data_source=data_source,
        port=port,
        port_var=port_var,
        is_local=is_local,
        tls_files=tls_files,
        server_name=config.get("SERVER_NAME") or "api",
        base_image=args.base_image,
        env_rel=env_rel,
        uses_local_keystore=uses_local_keystore,
        keystore_rel=keystore_rel,
        keystore_container_path=keystore_container_path,
        bake_keystore=uses_local_keystore and not args.external_keystore,
        requirements=requirements,
        dropped_requirements=dropped,
        healthcheck_host_file=f"{APP_DIR}/data/hostValidation/host-allow-list.txt",
        routes=routes,
        warnings=warnings,
    )


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

HEALTHCHECK_PY = '''\
"""Container health check: GET /status on the local port.

The server validates the Host header against data/hostValidation/host-allow-list.txt,
so the first allowed host is sent (read at check time, so list edits are honoured).
"""
import os
import ssl
import sys
import urllib.request

port = os.environ.get("{port_var}") or "{port}"
host = "localhost"
scheme = "{scheme}"
# the local certificate is self-signed / issued for another name: only reachability matters here
context = ssl._create_unverified_context() if scheme == "https" else None

try:
    with open("{host_file}", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#"):
                host = line
                break
except OSError:
    pass

request = urllib.request.Request(
    f"{scheme}://127.0.0.1:{{port}}/status",
    headers={{"Host": host, "User-Agent": "Mozilla/5.0 (compatible; docker-healthcheck/1.0)"}},
)

try:
    with urllib.request.urlopen(request, timeout=4, context=context) as response:
        sys.exit(0 if response.status == 200 else 1)
except Exception:
    sys.exit(1)
'''


SMOKE_TEST_PY = '''\
import contextlib
import io
import sys

captured = io.StringIO()

with contextlib.redirect_stdout(captured):
    import main  # noqa: F401  - loads .env, every data list and every route

output = captured.getvalue()
print(output, end="")

problems = [
    line for line in output.splitlines()
    if "Failed to load route" in line or "Skipping invalid route definition" in line
]

if problems:
    sys.exit("Route loading problems:\\n" + "\\n".join(problems))
'''


def image_slug(name: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", name.lower()).strip("-.") or "api"


def render_dockerfile(plan: Plan) -> str:
    slug = image_slug(plan.server_name)
    privileged = plan.port < 1024
    lines: list[str] = []
    add = lines.append

    # ---------------------------------------------------------------- header
    add("# syntax=docker/dockerfile:1")
    add("#")
    add("# GENERATED by scripts/generate_dockerfile.py - regenerate instead of editing.")
    add(f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    add("#")
    add("# Server configuration this image was generated from:")
    add(f"#   SERVER_NAME={plan.server_name}  DEPLOY_ENV={plan.deploy_env}  DATA_SOURCE={plan.data_source}")
    if plan.is_local:
        add(f"#   listens on HTTPS, port {plan.port} ({', '.join(plan.tls_files)} are in the image); "
            "auto-reload follows RELOAD in the config")
    else:
        add(f"#   listens on plain HTTP, port {plan.port} (TLS must be terminated upstream)")
    if plan.uses_local_keystore:
        add(f"#   keystore: {plan.keystore_container_path} "
            + ("(baked into the image)" if plan.bake_keystore else "(NOT in the image - mount it read-only)"))
    add("#")
    add("# Build:  docker build -f Dockerfile -t " + slug + " .")
    add("# Run:    docker run -d --name " + slug + f" -p {plan.port}:{plan.port} \\")
    add(f"#           " + ("" if plan.is_local else f"--stop-timeout {RECOMMENDED_STOP_TIMEOUT} ") + "--read-only --tmpfs /tmp --cap-drop ALL"
        + (" --cap-add NET_BIND_SERVICE" if privileged else "") + " \\")
    add("#           --restart unless-stopped " + slug)
    add("#")
    if not plan.is_local:
        add("# --stop-timeout: the server drains in-flight requests for up to 30 s on SIGTERM;")
        add("#   Docker's default of 10 s would SIGKILL it first.")
    add("# One container = one process: rate limiters, replay store and circuit breaker are")
    add("#   in memory, so scale by running more containers behind a proxy only if that is acceptable.")
    add("# Variables passed with `docker run -e` override the baked .env (the server never")
    add("#   overrides variables that are already set).")
    add("")
    add(f"ARG BASE_IMAGE={plan.base_image}")
    add("")

    # --------------------------------------------------------------- builder
    add("# ---------------------------------------------------------------------------")
    add("# Stage 1 - dependencies in a virtualenv")
    add("# ---------------------------------------------------------------------------")
    add("FROM ${BASE_IMAGE} AS builder")
    add("ENV DEBIAN_FRONTEND=noninteractive")
    add("RUN apt-get update \\")
    add(" && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \\")
    add(" && rm -rf /var/lib/apt/lists/*")
    add(f"RUN python3 -m venv {VENV_DIR}")
    add("")
    add("# Runtime requirements, captured from requirements.txt when this file was generated")
    if plan.dropped_requirements:
        add("# (left out as dev/test only: " + ", ".join(plan.dropped_requirements) + ")")
    add('COPY <<"EOF_REQUIREMENTS" /tmp/requirements.txt')
    lines.extend(plan.requirements)
    add("EOF_REQUIREMENTS")
    add(f"RUN {VENV_DIR}/bin/pip install --no-cache-dir -r /tmp/requirements.txt")
    add("")

    # --------------------------------------------------------------- runtime
    add("# ---------------------------------------------------------------------------")
    add("# Stage 2 - runtime image (same Ubuntu base, no pip / build leftovers)")
    add("# ---------------------------------------------------------------------------")
    add("FROM ${BASE_IMAGE} AS runtime")
    add("ENV DEBIAN_FRONTEND=noninteractive")
    add("RUN apt-get update \\")
    pkgs = "python3 ca-certificates" + (" libcap2-bin" if privileged else "")
    add(f" && apt-get install -y --no-install-recommends {pkgs} \\")
    add(" && rm -rf /var/lib/apt/lists/* \\")
    add(f" && groupadd --system --gid {APP_UID} {APP_USER} \\")
    add(f" && useradd --system --uid {APP_UID} --gid {APP_USER} --no-create-home "
        f"--home-dir /nonexistent --shell /usr/sbin/nologin {APP_USER}")
    add("")
    add(f"COPY --from=builder {VENV_DIR} {VENV_DIR}")
    if privileged:
        add(f"# Port {plan.port} is privileged: let the interpreter bind it without running as root.")
        add("# The container must keep NET_BIND_SERVICE (Docker's default).  To avoid this, set")
        add("# PROD_PORT >= 1024, map the host port to it, and regenerate.")
        add(f'RUN setcap cap_net_bind_service=+ep "$(readlink -f {VENV_DIR}/bin/python)"')
    add("")
    add(f"WORKDIR {APP_DIR}")
    add("")
    add("# --- application code and data (the server reads ./data and ./.routeignore relative to its cwd)")
    add(f"COPY main.py ./main.py")
    add(f"COPY app ./app")
    if plan.data_source == "fs":
        add(f"COPY data ./data")
    if (ROOT / ".routeignore").is_file():
        add(f"COPY .routeignore ./.routeignore")
    add("RUN chmod -R u=rwX,go=rX main.py app" + (" data" if plan.data_source == "fs" else "")
        + (" .routeignore" if (ROOT / ".routeignore").is_file() else ""))
    add("")
    add("# --- configuration and secrets: readable by root and the app group only")
    add(f"COPY --chown=root:{APP_USER} --chmod=0640 {plan.env_rel} ./.env")
    for tls in plan.tls_files:
        add(f"COPY --chown=root:{APP_USER} --chmod=0640 {tls} ./{tls}")
    if plan.bake_keystore and plan.keystore_rel:
        add(f"COPY --chown=root:{APP_USER} --chmod=0640 {plan.keystore_rel} ./{plan.keystore_rel}")
    add("")
    add("# --- container health check (stdlib only, no curl needed)")
    add('COPY --chmod=0644 <<"EOF_HEALTHCHECK" /usr/local/lib/healthcheck.py')
    lines.extend(HEALTHCHECK_PY.format(port=plan.port, port_var=plan.port_var, scheme="https" if plan.is_local else "http", host_file=plan.healthcheck_host_file).rstrip("\n").splitlines())
    add("EOF_HEALTHCHECK")
    add("")

    # ------------------------------------------------------------------- env
    add("# Settings read from the server configuration at generation time.  They win over the baked")
    add("# .env (the server never overrides variables that are already set), so the container")
    add("# behaves as configured even when .env is edited later or an -e flag is given.")
    env_lines = [
        f"PATH={VENV_DIR}/bin:$PATH",
        "PYTHONUNBUFFERED=1",
        "PYTHONDONTWRITEBYTECODE=1",
        f"DEPLOY_ENV={plan.deploy_env}",
        f"DATA_SOURCE={plan.data_source}",
        f"{plan.port_var}={plan.port}",
    ]
    if plan.uses_local_keystore and plan.keystore_container_path:
        env_lines.append(f"KEYSTORE_PATH={plan.keystore_container_path}")
    add("ENV " + " \\\n    ".join(env_lines))
    add("")
    add("# Build-time smoke test: the app must import, load every data list and register its routes.")
    add("# The route loader only prints when a route fails to load, so the build fails on those messages.")
    add('RUN python - <<"EOF_SMOKE"')
    lines.extend(SMOKE_TEST_PY.rstrip("\n").splitlines())
    add("EOF_SMOKE")
    add("")
    add(f"USER {APP_USER}")
    add(f"EXPOSE {plan.port}")
    add("STOPSIGNAL SIGTERM")
    add("HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \\")
    add('    CMD ["python", "/usr/local/lib/healthcheck.py"]')
    add("")
    add("# exec form: python is PID 1 and receives SIGTERM directly (graceful drain)")
    add('CMD ["python", "main.py"]')
    add("")

    return "\n".join(lines)


def render_dockerignore(plan: Plan) -> str:
    """Allow-list: everything is ignored except what the Dockerfile copies."""
    rules = ["# GENERATED by scripts/generate_dockerfile.py", "*", "!main.py", "!app"]

    if plan.data_source == "fs":
        rules.append("!data")
    if (ROOT / ".routeignore").is_file():
        rules.append("!.routeignore")

    rules.append(f"!{plan.env_rel}")

    rules += [f"!{tls}" for tls in plan.tls_files]

    if plan.bake_keystore and plan.keystore_rel:
        rules.append(f"!{plan.keystore_rel}")

    # must come after the allow rules (last matching rule wins): stale caches never go in
    rules += ["**/__pycache__", "**/*.pyc", "**/*.pyo"]

    return "\n".join(rules) + "\n"


def image_files(plan: Plan) -> list[str]:
    """Every file the Dockerfile copies into /app (same rules as Dockerfile.dockerignore)."""
    files = ["main.py", ".routeignore", plan.env_rel]

    for folder in ("app", "data") if plan.data_source == "fs" else ("app",):
        files += [
            f.relative_to(ROOT).as_posix()
            for f in sorted((ROOT / folder).rglob("*"))
            if f.is_file() and "__pycache__" not in f.parts and f.suffix not in (".pyc", ".pyo")
        ]

    files += plan.tls_files

    if plan.bake_keystore and plan.keystore_rel:
        files.append(plan.keystore_rel)

    return files


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.generate_dockerfile",
        description="Generate a production Dockerfile from the current server configuration.",
    )
    parser.add_argument("--output", default="Dockerfile", help="Dockerfile to write (default: Dockerfile)")
    parser.add_argument("--env-file", default=".env", help="server configuration file (default: .env)")
    parser.add_argument("--base-image", default="ubuntu:24.04", help="Ubuntu base image (default: ubuntu:24.04)")
    parser.add_argument(
        "--external-keystore",
        action="store_true",
        help="do not bake the local keystore file into the image; mount it at KEYSTORE_PATH at run time",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        plan = build_plan(args)
    except GeneratorError as error:
        print(f"\n✗ Cannot generate a production Dockerfile:\n  {error}\n", file=sys.stderr)
        return 1

    output = (ROOT / args.output) if not Path(args.output).is_absolute() else Path(args.output)
    ignore_file = output.with_name(output.name + ".dockerignore")

    output.write_text(render_dockerfile(plan), encoding="utf-8")
    ignore_file.write_text(render_dockerignore(plan), encoding="utf-8")

    print("\nProduction Dockerfile generated")
    print(f"  Dockerfile         {output}")
    print(f"  build context      {ignore_file.name} (allow-list)")
    print(f"  base image         {plan.base_image}")
    print(f"  DEPLOY_ENV         {plan.deploy_env}   DATA_SOURCE {plan.data_source}   {plan.port_var} {plan.port}"
          + ("   (HTTPS)" if plan.is_local else ""))
    print(f"  routes             {len(plan.routes)} file route(s)")
    print(f"  dependencies       {', '.join(plan.requirements)}")

    if plan.dropped_requirements:
        print(f"  left out (dev)     {', '.join(plan.dropped_requirements)}")

    files = image_files(plan)
    print(f"  files in the image {len(files)}: main.py, app/ ({sum(f.startswith('app/') for f in files)}), "
          f"data/ ({sum(f.startswith('data/') for f in files)}), .routeignore, "
          f"{plan.env_rel}" + "".join(f", {t}" for t in plan.tls_files)
          + (f", {plan.keystore_rel}" if plan.bake_keystore else ""))

    for warning in plan.warnings:
        print(f"  ! {warning}")

    slug = image_slug(plan.server_name)
    print(f"\nNext:  docker build -f {output.name} -t {slug} .\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())