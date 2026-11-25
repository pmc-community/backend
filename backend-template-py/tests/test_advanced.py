import asyncio
import os
import signal
import threading
import time
from pathlib import Path

import httpx
import pytest

from tests.conftest import ROOT, Server, auth, make_workdir


@pytest.fixture()
def fresh_dir(tmp_path):
    return make_workdir(tmp_path)


def run_server(wd, **env) -> Server:
    return Server(wd, env).start()


# ------------------------------------------------------------ timeouts / overload


def test_global_timeout_returns_408(fresh_dir):
    s = run_server(fresh_dir, defaultTimeout="1")
    try:
        t0 = time.time()
        r = httpx.get(f"{s.url}/test/slow", headers=s.headers(), timeout=15)
        assert r.status_code == 408 and r.json() == {"error": "Timeout. Try again later"}
        assert 0.9 < time.time() - t0 < 3
        assert '"code": "TO_TIMEOUT"' in s.logs()
    finally:
        s.stop()


def test_overload_returns_503_and_per_ip_limit(fresh_dir):
    s = run_server(fresh_dir, CO_MAX_ALLOWED="2")
    try:
        results: list[int] = []

        def call():
            results.append(httpx.get(f"{s.url}/test/slow", headers=s.headers(), timeout=20).status_code)

        threads = [threading.Thread(target=call) for _ in range(4)]
        [t.start() for t in threads]
        time.sleep(0.6)
        # a third concurrent request is rejected by the (outer) circuit breaker with 503
        r = httpx.get(f"{s.url}/status", headers=s.headers(), timeout=5)
        assert r.status_code == 503 and r.json() == {"error": "Server error"} and r.headers["retry-after"] == "1"
        [t.join() for t in threads]
        assert results.count(200) == 2 and results.count(503) == 2
    finally:
        s.stop()


# ------------------------------------------------------------ graceful shutdown


def test_graceful_shutdown_drains_requests(fresh_dir):
    s = run_server(fresh_dir)
    out: dict = {}

    def slow():
        out["slow"] = httpx.get(f"{s.url}/test/slow", headers=s.headers(), timeout=30).status_code

    t = threading.Thread(target=slow)
    t.start()
    time.sleep(1.0)
    assert s.proc is not None
    s.proc.send_signal(signal.SIGTERM)
    time.sleep(0.5)

    # draining: new requests get 503, /status stays available
    r = httpx.get(f"{s.url}/test/status", headers=s.headers(), timeout=5)
    assert r.status_code == 503 and r.json() == {"error": "Service is shutting down."}
    assert httpx.get(f"{s.url}/status", headers=s.headers(), timeout=5).status_code == 200

    t.join(timeout=30)
    assert out["slow"] == 200                       # the in-flight request finished
    assert s.proc.wait(timeout=15) is not None      # and only then the process exited
    logs = s.logs()
    assert "Received SIGTERM; starting graceful shutdown." in logs
    assert "Drain completed: True" in logs and "Server closed." in logs


# ------------------------------------------------------------ data layer / hot reload


def test_hot_reload_global_ip_deny(fresh_dir):
    s = run_server(fresh_dir)
    try:
        h = s.headers(**{"X-Forwarded-For": "9.9.9.9"})
        assert httpx.get(f"{s.url}/status", headers=h, timeout=5).status_code == 200

        (fresh_dir / "data/general/global-ip-deny.txt").write_text("9.9.9.0/24\n")

        deadline = time.time() + 10
        code = 200
        while time.time() < deadline and code == 200:
            time.sleep(0.5)
            code = httpx.get(f"{s.url}/status", headers=h, timeout=5).status_code
        assert code == 403
        assert httpx.get(f"{s.url}/status", headers=h, timeout=5).json() == {"error": "Not allowed"}
        assert "[DATA CHANGE] general-global-ip-deny" in s.logs()

        # another client is unaffected
        assert httpx.get(f"{s.url}/status", headers=s.headers(**{"X-Forwarded-For": "8.8.8.8"}), timeout=5).status_code == 200
    finally:
        s.stop()


def test_trusted_proxy_forwarded_host(fresh_dir):
    s = run_server(fresh_dir)       # 127.0.0.1 is trusted in make_workdir
    try:
        h = {"Host": "evil.example", "User-Agent": "Mozilla/5.0 Chrome", "X-Forwarded-Host": "192.168.1.134"}
        assert httpx.get(f"{s.url}/status", headers=h, timeout=5).status_code == 200
        h["X-Forwarded-Host"] = "not valid!"
        assert httpx.get(f"{s.url}/status", headers=h, timeout=5).status_code == 400
    finally:
        s.stop()

    (fresh_dir / "data/general/trusted-proxy-ip.txt").write_text("\n")      # nobody trusted
    s = run_server(fresh_dir)
    try:
        h = {"Host": "evil.example", "User-Agent": "Mozilla/5.0 Chrome", "X-Forwarded-Host": "192.168.1.134"}
        assert httpx.get(f"{s.url}/status", headers=h, timeout=5).status_code == 403
    finally:
        s.stop()


def test_suspicious_block_mode(fresh_dir):
    s = run_server(fresh_dir, SRD_BLOCK_SUSPICIOUS_REQUESTS="true")
    try:
        r = httpx.get(f"{s.url}/status", headers=s.headers(**{"User-Agent": "sqlmap/1.0"}), timeout=5)
        assert r.status_code == 403 and r.json() == {"error": "Suspicious request detected."}
        r = httpx.get(f"{s.url}/test/status?q=1%20union%20select%20password%20from%20users", headers=s.headers(), timeout=5)
        assert r.status_code in (403, 400)
        assert httpx.get(f"{s.url}/status", headers=s.headers(), timeout=5).status_code == 200
    finally:
        s.stop()


def test_response_size_limit(fresh_dir):
    s = run_server(fresh_dir, maxResponseBytesBase="1")      # 10 * 1^2 = 10 bytes
    try:
        r = httpx.get(f"{s.url}/status", headers=s.headers(), timeout=5)
        assert r.status_code == 413
        assert r.json() == {"error": "Response exceeds maximum size, Refine your request"}
    finally:
        s.stop()


# ------------------------------------------------------------ unit tests


def _ctx(headers=None, client=("127.0.0.1", 1234), path="/x", method="GET", query=b""):
    from app.core.context import Context

    scope = {
        "type": "http", "method": method, "scheme": "http", "path": path, "raw_path": path.encode(),
        "query_string": query, "client": client, "server": ("h", 80),
        "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()],
    }
    return Context(scope, None)


@pytest.fixture(scope="module", autouse=True)
def _env():
    os.environ.setdefault("DATA_SOURCE", "fs")
    os.environ.setdefault("DEPLOY_ENV", "local")
    os.chdir(ROOT)


def test_ip_parsing_and_cidr():
    from app.helpers import utilities as u

    assert u.ipv4_to_int("192.168.1.1") == 0xC0A80101 and u.ipv4_to_int("256.1.1.1") is None
    assert u.ipv6_to_bigint("::1") == 1 and u.ipv6_to_bigint("1::2::3") is None and u.ipv6_to_bigint("1:2:3") is None
    assert u.ip_matches_rule("192.168.1.77", "192.168.1.0/24") and not u.ip_matches_rule("192.168.2.1", "192.168.1.0/24")
    assert u.ip_matches_rule("2001:db8::5", "2001:db8::/32") and not u.ip_matches_rule("2001:dc8::5", "2001:db8::/32")
    assert u.ip_matches_rule("10.0.0.1", "0.0.0.0/0") and not u.ip_matches_rule("garbage", "0.0.0.0/0")
    m = u.build_trusted_proxy_matcher("1.1.1.1, bad", "10.0.0.0/8,fd00::/8")
    assert m("1.1.1.1") and m("10.9.9.9") and m("fd00::1") and not m("8.8.8.8")


def test_get_client_ip_trust_rules(monkeypatch):
    from app.data_provider import data
    from app.helpers.utilities import get_client_ip

    # untrusted peer: forwarding headers ignored
    assert get_client_ip(_ctx({"x-forwarded-for": "1.2.3.4"}, client=("5.6.7.8", 1))) == "5.6.7.8"

    monkeypatch.setattr(data, "TRUSTED_PROXY_IPS", "5.6.7.8")
    monkeypatch.setattr(data, "TRUSTED_PROXY_CIDRS", "10.0.0.0/8")
    # trusted peer: right-most untrusted entry of the chain is the client
    c = _ctx({"x-forwarded-for": "9.9.9.9, 1.2.3.4, 10.1.1.1"}, client=("5.6.7.8", 1))
    assert get_client_ip(c) == "1.2.3.4"
    assert get_client_ip(_ctx({"x-forwarded-for": "10.1.1.1"}, client=("5.6.7.8", 1))) == "10.1.1.1"
    assert get_client_ip(_ctx({"x-real-ip": "7.7.7.7"}, client=("5.6.7.8", 1))) == "7.7.7.7"
    assert get_client_ip(_ctx({}, client=("5.6.7.8", 1))) == "5.6.7.8"
    assert get_client_ip(_ctx({}, client=None)) == "unknown"


def test_uri_helpers():
    from app.core import uri

    assert uri.get_path("http://h/a%20b/c?x=%41") == "/a b/c"
    assert uri.get_path("http://h/a%2Fb") == "/a%2Fb"           # reserved characters stay encoded
    assert uri.get_path("http://h/%E4%BD%A0") == "/你"
    assert uri.get_path("http://h/%zz/ok") == "/%zz/ok"          # malformed -> left as is
    assert uri.get_path("http://h/a%25b") == "/a%25b"
    assert uri.try_decode_uri_component("%E4%BD") == "%E4%BD"
    assert uri.search_params("a=1&&b=%20x+y&c") == [("a", "1"), ("b", " x y"), ("c", "")]


def test_regex_translation_of_js_patterns():
    from app.data_provider.provider_data import compile_js_regex

    r = compile_js_regex(r"(?:^|[.[\]])__proto__(?:[.\[]|$)", "i")
    assert r.search("a.__PROTO__.b") and not r.search("a__proto__b")
    assert compile_js_regex(r"^(.)\1{7,}$", "").search("aaaaaaaa")
    assert compile_js_regex(r"\bselect\b", "i").search("SELECT x")
    assert compile_js_regex(r"(?<q>a)\k<q>", "").search("aa")


def test_route_manifest():
    from app.route_manifest import build_route_manifest

    routes = [e.route for e in build_route_manifest()]
    assert routes == [
        "/echo", "/status", "/test/page", "/test/slow", "/test/status", "/users", "/whoami",
        "/test/proute/{p1}", "/test/proute/{pa}/{pb}",
    ]


def test_route_name_conversion(tmp_path):
    from app.route_manifest import to_route_path

    base = tmp_path
    assert to_route_path(base / "a/[id]/index.py", base) == "/a/{id}"
    assert to_route_path(base / "docs/[...slug].py", base) == "/docs/{slug:path}"
    assert to_route_path(base / "route.py", base) == "/"


def test_compose_converts_errors_at_the_throwing_frame():
    from app.core.compose import run_chain
    from app.core.http_exception import HTTPException
    from app.helpers.err_handler import err_handler

    seen = {}

    async def outer(c, nxt):
        res = await nxt()          # never raises: the inner error is already a response
        seen["status"] = res.status_code
        return res

    async def inner(c, nxt):
        raise HTTPException(418, message="teapot")

    res = asyncio.run(run_chain(_ctx(), [outer, inner], lambda c: c.json({}), err_handler))
    assert seen["status"] == 418 and res.body == b'{"error":"teapot"}'

    async def boom(c, nxt):
        raise RuntimeError("x")

    res = asyncio.run(run_chain(_ctx(), [boom], lambda c: c.json({}), err_handler))
    assert res.status_code == 500 and res.body == b'{"error":"Internal server error"}'


def test_circuit_breaker_state_machine():
    from app.middleware.overload_circuit_breaker import overload_circuit_breaker
    from app.core.compose import run_chain
    from app.helpers.err_handler import err_handler

    changes = []
    mw = overload_circuit_breaker(
        max_concurrent_requests=5, failure_threshold=2, failure_window_ms=10_000,
        open_duration_ms=300, half_open_max_requests=1,
        on_state_change=lambda a, b: changes.append((a, b)),
    )
    state = {"status": 500}

    async def call():
        return await run_chain(_ctx(), [mw], lambda c: c.json({}, state["status"]), err_handler)

    async def scenario():
        assert (await call()).status_code == 500
        assert (await call()).status_code == 500            # 2nd failure opens the circuit
        r = await call()
        assert r.status_code == 503 and dict(r.headers).get("retry-after")
        await asyncio.sleep(0.4)
        state["status"] = 200
        assert (await call()).status_code == 200            # half-open probe succeeds -> closed
        assert (await call()).status_code == 200

    asyncio.run(scenario())
    assert changes == [("CLOSED", "OPEN"), ("OPEN", "HALF_OPEN"), ("HALF_OPEN", "CLOSED")]


def test_sorted_and_memory_list_providers(tmp_path):
    from app.data_provider.fs.mem_list_provider import MemoryFileListProviderOptions, create_memory_list
    from app.data_provider.fs.sorted_list_provider import FsSortedListProviderOptions, create_sorted_list

    f = tmp_path / "l.txt"
    f.write_text("\n".join(sorted(["alpha", "bravo", "charlie", "delta", "echo"])) + "\n")
    sl = create_sorted_list("t-sorted", FsSortedListProviderOptions(str(f)))
    for v in ("alpha", "Echo", "charlie"):
        assert asyncio.run(sl.has(v))
    for v in ("zulu", "", "alph"):
        assert not asyncio.run(sl.has(v))

    m = tmp_path / "m.txt"
    m.write_text("# comment\nFoo\n\nbar\nfoo\n")
    ml = create_memory_list("t-mem", MemoryFileListProviderOptions(str(m)))
    assert asyncio.run(ml.values()) == ["foo", "bar"] and asyncio.run(ml.has("FOO"))


def test_hooks_run_after_function_and_survive_callback_errors():
    from app.hooks.hooks import proxied_globals, register_function_callback

    calls = []
    proxied_globals.f = lambda x: x * 2
    register_function_callback("f", lambda n, r, a: calls.append((n, r, a)))
    register_function_callback("f", lambda n, r, a: 1 / 0)
    assert proxied_globals.f(21) == 42 and calls == [("f", 42, (21,))]
