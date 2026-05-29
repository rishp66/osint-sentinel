"""Integration tests for FastAPI endpoints — run_scan is mocked."""

from unittest.mock import patch
from fastapi.testclient import TestClient
from starlette.requests import Request

from config.settings import get_settings
from main import app, _client_ip, _rate_hits

client = TestClient(app)

MOCK_RESULT = {
    "target": "example.com",
    "risk_score": 25,
    "risk_level": "MEDIUM",
    "threat_brief": "No significant threat indicators found.",
    "sources": [
        {"source": "whois", "_query_time_ms": 100.0},
        {"source": "virustotal", "_query_time_ms": 200.0},
        {"source": "abuseipdb", "_query_time_ms": 150.0},
        {"source": "shodan", "_query_time_ms": 300.0},
        {"source": "alienvault_otx", "_query_time_ms": 400.0},
        {"source": "ipinfo", "_query_time_ms": 120.0},
        {"source": "dns_resolution", "_query_time_ms": 10.0},
    ],
    "scan_duration_ms": 1234.5,
    "agent_report": "### Endpoint Summary\nTest endpoint.",
}


def _request_with_headers(headers: dict[str, str], client_host: str = "203.0.113.10"):
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/scan",
            "headers": [
                (name.lower().encode("latin-1"), value.encode("latin-1"))
                for name, value in headers.items()
            ],
            "client": (client_host, 12345),
            "server": ("testserver", 80),
            "scheme": "http",
            "query_string": b"",
        }
    )


# ─── /health ─────────────────────────────────────────────────────────────────


class TestHealthEndpoint:
    def test_returns_200(self):
        response = client.get("/health")
        assert response.status_code == 200

    def test_returns_ok_status(self):
        response = client.get("/health")
        assert response.json() == {"status": "ok"}

    def test_no_auth_required(self):
        response = client.get("/health")
        assert response.status_code != 401


class TestClientIp:
    def test_uses_rightmost_forwarded_for_hop_when_trusted(self, monkeypatch):
        monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
        get_settings.cache_clear()
        try:
            request = _request_with_headers(
                {"X-Forwarded-For": "10.0.0.99, 198.51.100.23"}
            )

            assert _client_ip(request) == "198.51.100.23"
        finally:
            monkeypatch.delenv("TRUST_PROXY_HEADERS", raising=False)
            get_settings.cache_clear()

    def test_ignores_spoofed_forwarded_for_when_not_trusted(self):
        request = _request_with_headers(
            {"X-Forwarded-For": "10.0.0.99, 198.51.100.23"},
            client_host="203.0.113.44",
        )

        assert _client_ip(request) == "203.0.113.44"


# ─── /scan ───────────────────────────────────────────────────────────────────


class TestScanEndpoint:
    def test_success_returns_200(self):
        with patch("main.run_scan", return_value=MOCK_RESULT):
            response = client.post("/scan", json={"target": "example.com"})
        assert response.status_code == 200

    def test_success_response_fields(self):
        with patch("main.run_scan", return_value=MOCK_RESULT):
            response = client.post("/scan", json={"target": "example.com"})
        data = response.json()
        assert data["target"] == "example.com"
        assert data["risk_score"] == 25
        assert data["risk_level"] == "MEDIUM"
        assert data["threat_brief"] == "No significant threat indicators found."
        assert isinstance(data["sources"], list)
        assert data["scan_duration_ms"] == 1234.5

    def test_empty_target_returns_422(self):
        response = client.post("/scan", json={"target": ""})
        assert response.status_code == 422

    def test_whitespace_only_target_returns_422(self):
        response = client.post("/scan", json={"target": "   "})
        assert response.status_code == 422

    def test_missing_target_field_returns_422(self):
        response = client.post("/scan", json={})
        assert response.status_code == 422

    def test_target_stripped_before_passing_to_run_scan(self):
        result_with_stripped = dict(MOCK_RESULT, target="example.com")
        with patch("main.run_scan", return_value=result_with_stripped) as mock_run:
            client.post("/scan", json={"target": "  example.com  "})
        mock_run.assert_called_once_with("example.com")

    def test_run_scan_called_once(self):
        with patch("main.run_scan", return_value=MOCK_RESULT) as mock_run:
            client.post("/scan", json={"target": "example.com"})
        assert mock_run.call_count == 1

    def test_scan_with_ip_target(self):
        ip_result = dict(MOCK_RESULT, target="8.8.8.8")
        with patch("main.run_scan", return_value=ip_result):
            response = client.post("/scan", json={"target": "8.8.8.8"})
        assert response.status_code == 200
        assert response.json()["target"] == "8.8.8.8"

    def test_ipv4_mapped_loopback_target_returns_422(self):
        response = client.post("/scan", json={"target": "::ffff:127.0.0.1"})

        assert response.status_code == 422

    def test_ipv4_mapped_metadata_url_returns_422(self):
        response = client.post(
            "/scan", json={"target": "http://[::ffff:169.254.169.254]/"}
        )

        assert response.status_code == 422

    def test_response_sources_is_list(self):
        with patch("main.run_scan", return_value=MOCK_RESULT):
            response = client.post("/scan", json={"target": "example.com"})
        assert isinstance(response.json()["sources"], list)
        assert len(response.json()["sources"]) == 7

    def test_get_method_not_allowed(self):
        response = client.get("/scan")
        assert response.status_code == 405

    def test_rate_limit_uses_trusted_proxy_hop(self, monkeypatch):
        monkeypatch.setenv("TRUST_PROXY_HEADERS", "true")
        get_settings.cache_clear()
        _rate_hits.clear()
        try:
            with patch("main.run_scan", return_value=MOCK_RESULT):
                responses = [
                    client.post(
                        "/scan",
                        json={"target": "example.com"},
                        headers={
                            "X-Forwarded-For": f"10.0.0.{i}, 198.51.100.23"
                        },
                    )
                    for i in range(11)
                ]

            assert [response.status_code for response in responses[:10]] == [200] * 10
            assert responses[10].status_code == 429
        finally:
            monkeypatch.delenv("TRUST_PROXY_HEADERS", raising=False)
            get_settings.cache_clear()
            _rate_hits.clear()

    def test_api_key_missing_returns_401_when_configured(self, monkeypatch):
        monkeypatch.setenv("API_KEY", "integration-test-secret")
        get_settings.cache_clear()
        try:
            with patch("main.run_scan", return_value=MOCK_RESULT):
                response = client.post("/scan", json={"target": "example.com"})
            assert response.status_code == 401
        finally:
            monkeypatch.delenv("API_KEY", raising=False)
            get_settings.cache_clear()

    def test_api_key_header_allows_scan(self, monkeypatch):
        monkeypatch.setenv("API_KEY", "integration-test-secret")
        get_settings.cache_clear()
        try:
            with patch("main.run_scan", return_value=MOCK_RESULT):
                response = client.post(
                    "/scan",
                    json={"target": "example.com"},
                    headers={"X-API-Key": "integration-test-secret"},
                )
            assert response.status_code == 200
        finally:
            monkeypatch.delenv("API_KEY", raising=False)
            get_settings.cache_clear()

    def test_api_key_bearer_allows_scan(self, monkeypatch):
        monkeypatch.setenv("API_KEY", "integration-test-secret")
        get_settings.cache_clear()
        try:
            with patch("main.run_scan", return_value=MOCK_RESULT):
                response = client.post(
                    "/scan",
                    json={"target": "example.com"},
                    headers={"Authorization": "Bearer integration-test-secret"},
                )
            assert response.status_code == 200
        finally:
            monkeypatch.delenv("API_KEY", raising=False)
            get_settings.cache_clear()
