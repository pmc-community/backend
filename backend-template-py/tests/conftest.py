"""
Integration tests run against a REAL uvicorn process (so TCP peer detection,
header handling and graceful shutdown behave exactly as in production).

The server runs in a temporary working directory with its own copy of ./data,
where 127.0.0.1 is configured as a trusted proxy - that lets the tests present
any client IP through X-Forwarded-For.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
HOST_HEADER = "192.168.1.134"
UA = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120"
RAW_KEY = "sk_test_abc123"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def key_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


class Server:
    def __init__(self, workdir: Path, extra_env: dict[str, str] | None = None):
        self.workdir = workdir
        self.port = free_port()
        self.extra_env = extra_env or {}
        self.proc: subprocess.Popen | None = None
        self.log_path = workdir / f"server-{self.port}.log"

    def start(self) -> "Server":
        env = {
            **os.environ,
            "PYTHONPATH": str(ROOT),
            "PYTHONUNBUFFERED": "1",
            "DATA_SOURCE": "fs",
            "DEPLOY_ENV": "simprod",
            "KEYSTORE_PATH": str(self.workdir / "keystore.json"),
            "PROD_PORT": str(self.port),
            "SERVER_NAME": "test-api",
            "NO_COLOR": "1",
            "DATA_RELOAD_INTERVAL": "200",
            **self.extra_env,
        }
        self.log = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            [sys.executable, str(ROOT / "main.py")],
            cwd=self.workdir, env=env, stdout=self.log, stderr=subprocess.STDOUT,
        )

        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                httpx.get(f"{self.url}/test/status", headers=self.headers(), timeout=1)
                return self          # any HTTP answer means the server is up
            except Exception:
                time.sleep(0.2)
        raise RuntimeError("server did not start:\n" + self.logs())

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def headers(self, **extra) -> dict[str, str]:
        return {"Host": HOST_HEADER, "User-Agent": UA, **extra}

    def logs(self) -> str:
        self.log.flush()
        return self.log_path.read_text()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def make_workdir(base: Path) -> Path:
    shutil.copytree(ROOT / "data", base / "data")
    shutil.copy(ROOT / ".routeignore", base / ".routeignore")
    # make the loopback peer a trusted proxy so tests can impersonate client IPs
    (base / "data/general/trusted-proxy-ip.txt").write_text("127.0.0.1\n")
    (base / "keystore.json").write_text(json.dumps({
        key_hash(RAW_KEY): {"clientId": "testClient", "scopes": ["read:echo", "write:users"]},
        key_hash("sk_noscope"): {"clientId": "noScope", "scopes": []},
    }))
    return base


@pytest.fixture(scope="session")
def workdir(tmp_path_factory) -> Path:
    return make_workdir(tmp_path_factory.mktemp("srv"))


@pytest.fixture(scope="session")
def server(workdir):
    s = Server(workdir).start()
    yield s
    s.stop()


@pytest.fixture()
def client(server):
    with httpx.Client(base_url=server.url, headers=server.headers(), timeout=15) as c:
        yield c


def auth(raw: str = RAW_KEY, **extra) -> dict[str, str]:
    return {"X-Api-Key": f"Bearer {raw}", **extra}
