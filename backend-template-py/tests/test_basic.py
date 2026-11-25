import re

from tests.conftest import RAW_KEY, UA, auth

JSON = {"Content-Type": "application/json"}


def test_public_status_and_security_headers(client):
    r = client.get("/status")
    assert r.status_code == 200 and r.json() == {"status": "ok"}
    h = r.headers
    assert re.fullmatch(r"[0-9a-f-]{36}", h["x-request-id"])
    assert h["x-frame-options"] == "SAMEORIGIN"
    assert h["strict-transport-security"] == "max-age=15552000; includeSubDomains"
    assert h["x-content-type-options"] == "nosniff"
    assert "x-powered-by" not in h
    assert h["access-control-allow-credentials"] == "true"
    assert h["vary"] == "Origin"


def test_request_id_is_echoed_when_valid(client):
    assert client.get("/status", headers={"X-Request-Id": "abc-123=ok"}).headers["x-request-id"] == "abc-123=ok"
    assert client.get("/status", headers={"X-Request-Id": "bad id!"}).headers["x-request-id"] != "bad id!"


def test_unknown_route_and_wrong_method_are_plain_404(client):
    for r in (client.get("/nope"), client.post("/status", headers=JSON, content=b"{}")):
        assert r.status_code == 404 and r.text == "404 Not Found"
        assert r.headers["content-type"].startswith("text/plain")


def test_head_uses_get_handler(client):
    r = client.head("/status")
    assert r.status_code == 200 and r.content == b""


def test_host_validation(client):
    r = client.get("/status", headers={"Host": "evil.example"})
    assert r.status_code == 403 and r.json() == {"error": "Invalid request"}
    assert client.get("/status", headers={"Host": "bad host!"}).status_code == 400
    # port is ignored
    assert client.get("/status", headers={"Host": "192.168.1.134:9999"}).status_code == 200


def test_content_type_policy(client):
    assert client.get("/status", headers={"Content-Type": "sdfsdf"}).status_code == 415
    assert client.get("/status", headers={"Content-Type": "application/x-nope"}).status_code == 415
    # allowed type, parameters ignored
    assert client.get("/status", headers={"Content-Type": "application/json; charset=utf-8"}).status_code == 200
    # a request that carries a body but no Content-Type -> 415
    r = client.post("/test/proute/a/b", content=b"{}")
    assert r.status_code == 415 and r.json() == {"error": "Invalid request"}
    # no body and no Content-Type is allowed
    assert client.post("/test/proute/a/b").status_code == 200
    r = client.post("/test/proute/a/b", headers=JSON, content=b"{}")
    assert r.status_code == 200 and r.json() == {"status": "ok", "pa": "a", "pb": "b"}


def test_no_body_and_query_limits(client):
    assert client.get("/status?x=1").status_code == 400          # maxParameters: 0
    assert client.request("GET", "/status", content=b"hello", headers={"Content-Type": "text/plain"}).status_code == 400


def test_html_page(client):
    r = client.get("/test/page")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert r.text.lstrip().startswith("<!DOCTYPE html>") and 'id="testBtn"' in r.text and "jquery-3.7.1" in r.text


def test_cors_preflight_and_blocked_origin(client):
    r = client.options("/echo", headers={"Origin": "https://ok.example", "Access-Control-Request-Method": "GET"})
    assert r.status_code == 204
    assert r.headers["access-control-allow-origin"] == "https://ok.example"
    assert r.headers["access-control-allow-methods"] == "delete,get,options,patch,post,put"
    assert r.headers["access-control-allow-headers"] == "authorization,content-type"
    assert "Origin" in r.headers["vary"] and "content-length" not in r.headers

    blocked = client.get("/status", headers={"Origin": "https://evil.example.com"})
    assert "access-control-allow-origin" not in blocked.headers
    ok = client.get("/status", headers={"Origin": "https://ok.example"})
    assert ok.headers["access-control-allow-origin"] == "https://ok.example"


def test_authentication(client):
    r = client.get("/echo")
    assert r.status_code == 401 and r.json() == {"error": "Request not authorized"}
    assert client.get("/echo", headers={"X-Api-Key": RAW_KEY}).status_code == 401   # no "Bearer "
    r = client.get("/echo", headers=auth("sk_wrong"))
    assert r.status_code == 401 and r.json() == {"error": "Not authorized"}
    r = client.get("/echo", headers=auth())
    assert r.status_code == 200 and r.json() == {"status": "ok", "client": "testClient"}


def test_scope_enforcement(client):
    r = client.get("/echo", headers=auth("sk_noscope"))
    assert r.status_code == 403 and r.json() == {"error": "Insufficient scope"}


def test_protected_param_route(client):
    r = client.post("/test/proute/hello", headers=auth(**JSON), content=b"{}")
    assert r.status_code == 200 and r.json() == {"status": "ok", "param": "hello"}


def test_whoami(client):
    r = client.get("/whoami", headers=auth())
    j = r.json()
    assert r.status_code == 200 and j["clientId"] == "testClient"
    assert j["scopes"] == ["read:echo", "write:users"]
    assert j["ip"] == "127.0.0.1" and j["userAgent"] == UA
    assert j["geo"]["source"] == "unavailable"
    assert client.get("/whoami?a=1", headers=auth()).status_code == 400


def test_pagination_limits(client):
    assert client.get("/echo?limit=1000", headers=auth()).status_code == 400
    assert client.get("/echo?limit=0", headers=auth()).status_code == 400
    assert client.get("/echo?page=1&offset=1", headers=auth()).status_code == 400
    assert client.get("/echo?limit=1&limit=2", headers=auth()).status_code == 400
