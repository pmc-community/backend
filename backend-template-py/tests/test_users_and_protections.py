import hashlib
import hmac
import json
import time
import uuid

import httpx
import pytest

from tests.conftest import RAW_KEY, Server, auth

JSON = {"Content-Type": "application/json"}
INSIDE = {"X-Forwarded-For": "192.168.1.50"}     # allowed by /users (192.168.1.0/24)


def sign(method, path, body: bytes, *, secret="test-secret-123", ts=None, nonce=None):
    ts = str(ts if ts is not None else int(time.time()))
    nonce = nonce or str(uuid.uuid4())
    canonical = "\n".join([method, path, ts, nonce, hashlib.sha256(body).hexdigest()])
    sig = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return {"X-Signature-Timestamp": ts, "X-Signature-Nonce": nonce, "X-Signature": sig}


def post_user(client, payload, *, headers=None, signed=True, raw=None):
    body = raw if raw is not None else json.dumps(payload).encode()
    h = {**auth(), **JSON, **INSIDE, **(headers or {})}
    if signed:
        h.update(sign("POST", "/users", body))
    return client.post("/users", content=body, headers=h)


# ------------------------------------------------------------------ /users


@pytest.fixture()
def own_server(workdir):
    """Fresh server per test: the per-key limiter (10/min) is process state."""
    s = Server(workdir).start()
    yield s
    s.stop()


@pytest.fixture()
def client(own_server):
    with httpx.Client(base_url=own_server.url, headers=own_server.headers(), timeout=15) as c:
        yield c


def test_users_happy_path(client):
    r = post_user(client, {"name": "Ann", "email": "ann@example.com"})
    assert r.status_code == 201
    assert r.json() == {"received": {"name": "Ann", "email": "ann@example.com"}}


def test_users_ip_restriction(client):
    # peer is 127.0.0.1 (trusted proxy) and the forwarded client is outside the allow list
    r = post_user(client, {"name": "A", "email": "a@b.co"}, headers={"X-Forwarded-For": "10.0.0.9"})
    assert r.status_code == 403 and r.json() == {"error": "Not allowed"}


def test_users_requires_scope(client):
    body = json.dumps({"name": "A", "email": "a@b.co"}).encode()
    h = {**auth("sk_noscope"), **JSON, **INSIDE, **sign("POST", "/users", body)}
    # noScope client has no signing secret -> signature check fails first (401)
    assert client.post("/users", content=body, headers=h).status_code == 401


def test_users_signature_failures(client):
    payload = {"name": "A", "email": "a@b.co"}
    body = json.dumps(payload).encode()

    # missing headers
    r = client.post("/users", content=body, headers={**auth(), **JSON, **INSIDE})
    assert r.status_code == 401 and r.json() == {"error": "Unauthorized"}

    # wrong secret
    h = {**auth(), **JSON, **INSIDE, **sign("POST", "/users", body, secret="nope")}
    assert client.post("/users", content=body, headers=h).status_code == 401

    # tampered body
    h = {**auth(), **JSON, **INSIDE, **sign("POST", "/users", body)}
    assert client.post("/users", content=body + b" ", headers=h).status_code == 401

    # expired / future timestamps
    for ts in (int(time.time()) - 1000, int(time.time()) + 1000):
        h = {**auth(), **JSON, **INSIDE, **sign("POST", "/users", body, ts=ts)}
        assert client.post("/users", content=body, headers=h).status_code == 401

    # non-hex signature
    h = {**auth(), **JSON, **INSIDE, **sign("POST", "/users", body), "X-Signature": "zz"}
    assert client.post("/users", content=body, headers=h).status_code == 401


def test_users_replay_is_rejected(client):
    body = json.dumps({"name": "A", "email": "a@b.co"}).encode()
    h = {**auth(), **JSON, **INSIDE, **sign("POST", "/users", body)}
    assert client.post("/users", content=body, headers=h).status_code == 201
    assert client.post("/users", content=body, headers=h).status_code == 401   # same nonce


def test_users_validation(client):
    for payload in (
        {"name": "", "email": "a@b.co"},               # too small
        {"name": "A", "email": "not-an-email"},        # invalid email
        {"name": "A"},                                 # missing
        {"name": "A", "email": "a@b.co", "extra": 1},  # strict(): unknown key
        {"name": 5, "email": "a@b.co"},                # wrong type
        ["x"],
    ):
        r = post_user(client, payload)
        assert r.status_code == 400 and r.json() == {"error": "Invalid request"}, payload


def test_users_json_only(client):
    r = post_user(client, None, raw=b"{not json")
    assert r.status_code == 400 and r.json() == {"error": "Bad request body"}
    r = post_user(client, None, raw=b"NaN")
    assert r.status_code == 400


def test_users_non_json_content_type_fails_validation(client):
    body = json.dumps({"name": "A", "email": "a@b.co"}).encode()
    h = {**auth(), "Content-Type": "text/plain", **INSIDE, **sign("POST", "/users", body)}
    r = client.post("/users", content=body, headers=h)
    # jsonOnlyLimiter accepts it (valid JSON) but zValidator validates `{}` for non-JSON content types
    assert r.status_code == 400 and r.json() == {"error": "Invalid request"}


def test_users_body_size_limit(client):
    big = json.dumps({"name": "x" * (1024 * 1024 + 10), "email": "a@b.co"}).encode()
    r = post_user(client, None, raw=big)
    assert r.status_code == 413 and r.json() == {"error": "Bad request size"}


def test_users_per_key_rate_limit_last(client):
    # per-key limiter allows 10/min for the client; earlier tests used some of them
    codes = [post_user(client, {"name": "A", "email": "a@b.co"}).status_code for _ in range(12)]
    assert 429 in codes
    r = post_user(client, {"name": "A", "email": "a@b.co"})
    assert r.status_code == 429 and "retry-after" in r.headers
    assert r.json() == {"error": "Too many requests. Try again later."}


# ------------------------------------------------------------ protections


def test_duplicate_protected_header_is_rejected(client, own_server):
    server = own_server
    import socket

    req = (
        f"GET /status HTTP/1.1\r\nHost: 192.168.1.134\r\nUser-Agent: Mozilla/5.0 Chrome\r\n"
        f"X-Real-IP: 1.1.1.1\r\nX-Real-IP: 2.2.2.2\r\nConnection: close\r\n\r\n"
    )
    with socket.create_connection(("127.0.0.1", server.port)) as s:
        s.sendall(req.encode())
        data = b""
        while chunk := s.recv(4096):
            data += chunk
    assert data.startswith(b"HTTP/1.1 400") and b'{"error":"Invalid request headers."}' in data

    # duplicates of an explicitly allowed header are fine
    req = req.replace("X-Real-IP: 1.1.1.1\r\nX-Real-IP: 2.2.2.2", "Accept: a\r\nAccept: b")
    with socket.create_connection(("127.0.0.1", server.port)) as s:
        s.sendall(req.encode())
        assert s.recv(4096).startswith(b"HTTP/1.1 200")


def test_header_limits(client):
    r = client.get("/status", headers={"X-Big": "a" * 9000})
    assert r.status_code == 400 and r.json() == {"error": "Bad headers"}
    r = client.get("/status", headers={f"X-H{i}": "1" for i in range(60)})
    assert r.status_code == 400


def test_url_and_query_limits(client):
    assert client.get("/test/status?" + "a=" + "b" * 1100).status_code in (400, 414)
    assert client.get("/test/proute/" + "x" * 1100, headers=auth()).status_code == 414


def test_suspicious_requests_are_logged_not_blocked_by_default(client, own_server):
    server = own_server
    r = client.get("/status", headers={"User-Agent": "sqlmap/1.0"})
    assert r.status_code == 200
    time.sleep(0.2)
    assert "suspicious-request" in server.logs() and "scanner-user-agent" in server.logs()
    r = client.get("/test/status", headers={"User-Agent": "9999"})
    assert r.status_code == 200


def test_audit_log_content(client, own_server):
    server = own_server
    client.get("/echo")  # 401
    time.sleep(0.2)
    logs = server.logs()

    decoder = json.JSONDecoder()
    events = [decoder.raw_decode(part)[0] for part in logs.split("[logEvent] ")[1:]]
    event = [e for e in events if e["path"] == "/echo"][-1]
    
    assert event["server"] == "test-api" and event["status"] == 401 and event["outcome"] == "failure"
    assert event["error"]["code"] == "AUTH_API_KEY" and event["ip"] == "127.0.0.1"
    assert "[HOOHK] Function 'logEvent' returned: requestId=" in logs


def test_x_forwarded_for_is_trusted_only_from_trusted_proxy(client):
    r = client.get("/whoami", headers=auth() | {"X-Forwarded-For": "8.8.8.8"})
    assert r.json()["ip"] == "8.8.8.8"          # peer 127.0.0.1 is a trusted proxy in these tests


def test_auth_failures_are_throttled(workdir):
    # separate server: the failure counter is per IP and would pollute the other tests
    s = Server(workdir, {"maxRqAuthFailures": "3"}).start()
    try:
        codes = [httpx.get(f"{s.url}/echo", headers=s.headers(), timeout=5).status_code for _ in range(6)]
        assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429, 429]
        r = httpx.get(f"{s.url}/echo", headers=s.headers() | auth(), timeout=5)
        assert r.status_code == 429 and r.json() == {"error": "Authorization problem, try again later"}
    finally:
        s.stop()


def test_global_rate_limit(workdir):
    s = Server(workdir, {"maxRqPerMin": "5"}).start()
    try:
        codes = [httpx.get(f"{s.url}/status", headers=s.headers(), timeout=5).status_code for _ in range(8)]
        assert 429 in codes and codes[0] == 200
    finally:
        s.stop()
