import json

import pytest

import server


def test_index_has_security_headers_and_no_wildcard_cors(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "Content-Security-Policy" in response.headers
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers.get("Access-Control-Allow-Origin") != "*"


def test_live_scan_rejects_get(client):
    response = client.get("/api/live-scan")
    assert response.status_code == 405
    assert response.headers["Allow"] == "POST"


def test_live_scan_requires_authorization_confirmation(client):
    response = client.post("/api/live-scan", json={"url": "https://example.com"})
    assert response.status_code == 400
    assert "authorization" in response.get_json()["error"].lower()


def test_live_scan_blocks_loopback(client):
    response = client.post(
        "/api/live-scan",
        json={"url": "http://127.0.0.1/", "authorized": True},
    )
    assert response.status_code == 400
    assert "private" in response.get_json()["error"].lower()


def test_live_scan_blocks_metadata_ip(client):
    response = client.post(
        "/api/live-scan",
        json={"url": "http://169.254.169.254/latest/meta-data/", "authorized": True},
    )
    assert response.status_code == 400
    assert "blocked" in response.get_json()["error"].lower()


def test_live_scan_blocks_file_scheme(client):
    response = client.post(
        "/api/live-scan",
        json={"url": "file:///etc/passwd", "authorized": True},
    )
    assert response.status_code == 400
    assert "http" in response.get_json()["error"].lower()


def test_live_scan_blocks_disallowed_port(client):
    response = client.post(
        "/api/live-scan",
        json={"url": "http://example.com:2082/", "authorized": True},
    )
    assert response.status_code == 400
    assert "port" in response.get_json()["error"].lower()


def test_live_scan_blocks_embedded_credentials(client):
    response = client.post(
        "/api/live-scan",
        json={"url": "http://user:pass@example.com/", "authorized": True},
    )
    assert response.status_code == 400
    assert "credentials" in response.get_json()["error"].lower()


def test_validate_domain_normalizes_urls_and_rejects_junk():
    assert server.validate_domain("https://Example.NL/path") == "example.nl"
    with pytest.raises(ValueError):
        server.validate_domain("bad domain")
    with pytest.raises(ValueError):
        server.validate_domain("example..nl")


def test_regex_length_is_capped():
    with pytest.raises(ValueError):
        server.validate_regex_pattern("a" * (server.MAX_REGEX_LENGTH + 1))


def test_clamp_and_bool_helpers():
    assert server.clamp_int("9999", 1, 200) == 200
    assert server.clamp_int("-5", 1, 200) == 1
    assert server.clamp_int("not-a-number", 1, 200) == 100
    assert server.parse_bool("false") is False
    assert server.parse_bool("true") is True
    assert server.parse_bool(True) is True


def test_filter_headers_removes_sensitive_values():
    filtered = server.filter_headers(
        {
            "Set-Cookie": "session=secret",
            "Authorization": "Bearer secret",
            "Server": "demo",
            "Content-Type": "text/html",
        }
    )
    assert filtered == {"server": "demo", "content-type": "text/html"}


def test_extract_data_redacts_aws_key():
    html = "<html><body><script>const key = 'AKIAABCDEFGHIJKLMNOP';</script></body></html>"
    matches = server.extract_data(html, [], "20200101000000", "https://web.archive.org/example")
    serialized = json.dumps(matches)
    assert "AKIAABCDEFGHIJKLMNOP" not in serialized
    assert "[REDACTED]" in serialized


def test_safe_request_blocks_private_redirect(monkeypatch, fake_public_dns):
    class FakeRedirect:
        status_code = 302
        headers = {"Location": "http://127.0.0.1/"}
        is_redirect = True

        def close(self):
            pass

        def iter_content(self, chunk_size=8192):
            return iter(())

    monkeypatch.setattr(server.requests, "request", lambda *args, **kwargs: FakeRedirect())
    with pytest.raises(server.OutboundRequestError):
        server.safe_request("GET", "http://example.com/")


def test_safe_request_enforces_response_size_limit(monkeypatch, fake_public_dns):
    class BigResponse:
        status_code = 200
        headers = {}
        is_redirect = False

        def close(self):
            pass

        def iter_content(self, chunk_size=8192):
            yield b"x" * 100

    monkeypatch.setattr(server.requests, "request", lambda *args, **kwargs: BigResponse())
    with pytest.raises(server.ResponseTooLarge):
        server.safe_request("GET", "http://example.com/", max_bytes=50)


def test_api_token_is_required_when_configured(client, monkeypatch):
    monkeypatch.setattr(server, "API_TOKEN", "s3cret")
    response = client.post(
        "/api/live-scan",
        json={"url": "file:///etc/passwd", "authorized": True},
    )
    assert response.status_code == 401

    response = client.post(
        "/api/live-scan",
        json={"url": "file:///etc/passwd", "authorized": True},
        headers={"Authorization": "Bearer s3cret"},
    )
    assert response.status_code == 400


def test_remote_unauthenticated_access_is_rejected(client):
    response = client.post(
        "/api/live-scan",
        json={"url": "https://example.com", "authorized": True},
        environ_base={"REMOTE_ADDR": "203.0.113.9"},
    )
    assert response.status_code == 401
    assert "token" in response.get_json()["error"].lower()


def test_forwarded_header_does_not_bypass_local_auth(client):
    response = client.post(
        "/api/live-scan",
        json={"url": "https://example.com", "authorized": True},
        headers={"X-Forwarded-For": "203.0.113.9"},
    )
    assert response.status_code == 401


def test_rate_limit_returns_429(client, monkeypatch):
    monkeypatch.setattr(server, "RATE_LIMIT_MAX", 1)
    server._rate_events.clear()
    first = client.post(
        "/api/live-scan",
        json={"url": "file:///etc/passwd", "authorized": True},
    )
    second = client.post(
        "/api/live-scan",
        json={"url": "file:///etc/passwd", "authorized": True},
    )
    assert first.status_code == 400
    assert second.status_code == 429
    assert second.headers["Retry-After"]


def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.get_json()["name"] == "Webway09"


def test_fetch_snapshots_passes_query_parameters(monkeypatch):
    captured = {}
    payload = json.dumps(
        [
            ["timestamp", "original"],
            ["20200101000000", "http://example.nl/"],
        ]
    ).encode("utf-8")

    def fake_request(method, url, **kwargs):
        captured["method"] = method
        captured["url"] = url
        captured["kwargs"] = kwargs
        return server.SafeResponse(200, {}, payload, url)

    monkeypatch.setattr(server, "safe_request", fake_request)
    rows = server.fetch_snapshots("example.nl", "2020", 25)

    assert rows == [
        {"timestamp": "20200101000000", "original": "http://example.nl/"}
    ]
    assert captured["url"] == server.CDX_API
    assert captured["kwargs"]["params"]["url"] == "example.nl"
    assert captured["kwargs"]["params"]["limit"] == "25"
    assert captured["kwargs"]["params"]["from"] == "20200101"
    assert captured["kwargs"]["params"]["to"] == "20201231"


def test_fetch_snapshots_rejects_invalid_year():
    with pytest.raises(ValueError):
        server.fetch_snapshots("example.nl", "20xx", 10)


def test_analyze_asset_redacts_secret(monkeypatch):
    fake = server.SafeResponse(
        status_code=200,
        headers={"Content-Type": "application/javascript"},
        content=b"const key = 'AKIAABCDEFGHIJKLMNOP';",
        url="https://example.com/app.js",
    )
    monkeypatch.setattr(server, "safe_request", lambda *args, **kwargs: fake)
    result = server.analyze_asset("https://example.com/app.js", "ctf", False)
    assert result is not None
    serialized = json.dumps(result)
    assert "AKIAABCDEFGHIJKLMNOP" not in serialized


def test_scan_live_site_filters_set_cookie(monkeypatch):
    def fake_request(method, url, **kwargs):
        if method == "OPTIONS":
            return server.SafeResponse(200, {"Allow": "GET, OPTIONS"}, b"", url)
        if url.endswith("/robots.txt"):
            return server.SafeResponse(404, {}, b"", url)
        return server.SafeResponse(
            200,
            {
                "Set-Cookie": "session=secret",
                "Server": "demo",
                "Content-Type": "text/html",
            },
            b"<html><body>ok</body></html>",
            url,
        )

    monkeypatch.setattr(server, "safe_request", fake_request)
    result = server.scan_live_site("https://example.com/", "", "ctf", False)
    serialized = json.dumps(result)
    assert "set-cookie" not in result["headers"]
    assert "session=secret" not in serialized
    assert result["headers"]["server"] == "demo"


def test_scan_live_site_rejects_cookie_newlines():
    with pytest.raises(server.OutboundRequestError):
        server.scan_live_site("https://example.com/", "a=b\nInjected: x", "ctf", False)


def test_validate_outbound_url_allows_public_dns(fake_public_dns):
    host, port = server.validate_outbound_url("https://example.com/path")
    assert host == "example.com"
    assert port == 443


def test_validate_outbound_url_blocks_private_ip_literal():
    with pytest.raises(server.OutboundRequestError):
        server.validate_outbound_url("http://10.0.0.1/")
    with pytest.raises(server.OutboundRequestError):
        server.validate_outbound_url("http://[::1]/")
