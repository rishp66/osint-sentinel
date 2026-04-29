"""Unit tests for tools/llm_client.py — all HTTP calls mocked."""

import json
import pytest
from unittest.mock import patch, MagicMock

from tools.llm_client import synthesize, _score_to_level


# ─── helpers ─────────────────────────────────────────────────────────────────

class _FakeSecretStr:
    """Mimics pydantic.SecretStr for test settings."""
    def __init__(self, value: str):
        self._value = value
    def get_secret_value(self) -> str:
        return self._value
    def __bool__(self) -> bool:
        return bool(self._value)


def _settings(key="test-key/username", provider="lightning"):
    m = MagicMock()
    m.llm_provider = provider
    m.lightning_api_key = _FakeSecretStr(key)
    m.groq_api_key = _FakeSecretStr("")
    m.groq_model = "llama-3.3-70b-versatile"
    m.anthropic_api_key = _FakeSecretStr("")
    m.ollama_base_url = "http://localhost:11434"
    m.ollama_model = "llama3.1:8b"
    return m


def _llm_response(content: str):
    """Build a mock requests.Response whose content is an OpenAI-format JSON payload."""
    m = MagicMock()
    m.raise_for_status = MagicMock()
    m.content = json.dumps({
        "choices": [{"message": {"content": content}}]
    }).encode()
    return m


# ─── _score_to_level ─────────────────────────────────────────────────────────

class TestScoreToLevel:
    def test_critical_at_75(self):
        assert _score_to_level(75) == "CRITICAL"

    def test_critical_at_100(self):
        assert _score_to_level(100) == "CRITICAL"

    def test_high_at_50(self):
        assert _score_to_level(50) == "HIGH"

    def test_high_at_74(self):
        assert _score_to_level(74) == "HIGH"

    def test_medium_at_25(self):
        assert _score_to_level(25) == "MEDIUM"

    def test_medium_at_49(self):
        assert _score_to_level(49) == "MEDIUM"

    def test_low_at_0(self):
        assert _score_to_level(0) == "LOW"

    def test_low_at_24(self):
        assert _score_to_level(24) == "LOW"


# ─── synthesize (lightning provider — default) ───────────────────────────────

class TestSynthesize:
    def test_missing_key_returns_unknown(self):
        with patch("tools.llm_client.get_settings", return_value=_settings("")):
            r = synthesize("example.com", [])
        assert r["risk_level"] == "UNKNOWN"
        assert r["risk_score"] == 0
        assert "unavailable" in r["threat_brief"]

    def test_success_clean_json(self):
        payload = '{"threat_brief": "All clear.", "risk_score": 10, "risk_level": "LOW"}'
        with patch("tools.llm_client.get_settings", return_value=_settings("key/user")):
            with patch("tools.llm_client.requests.post", return_value=_llm_response(payload)):
                r = synthesize("example.com", [])
        assert r["risk_score"] == 10
        assert r["risk_level"] == "LOW"
        assert r["threat_brief"] == "All clear."

    def test_code_fence_json_stripped(self):
        body = '{"threat_brief": "Fenced output.", "risk_score": 60, "risk_level": "HIGH"}'
        fenced = f"```json\n{body}\n```"
        with patch("tools.llm_client.get_settings", return_value=_settings("key/user")):
            with patch("tools.llm_client.requests.post", return_value=_llm_response(fenced)):
                r = synthesize("example.com", [])
        assert r["risk_score"] == 60
        assert r["risk_level"] == "HIGH"
        assert r["threat_brief"] == "Fenced output."

    def test_code_fence_without_json_label(self):
        body = '{"threat_brief": "Plain fence.", "risk_score": 30, "risk_level": "MEDIUM"}'
        fenced = f"```\n{body}\n```"
        with patch("tools.llm_client.get_settings", return_value=_settings("key/user")):
            with patch("tools.llm_client.requests.post", return_value=_llm_response(fenced)):
                r = synthesize("example.com", [])
        assert r["risk_score"] == 30
        assert r["threat_brief"] == "Plain fence."

    def test_http_exception_returns_unknown(self):
        with patch("tools.llm_client.get_settings", return_value=_settings("key/user")):
            with patch("tools.llm_client.requests.post", side_effect=Exception("Connection refused")):
                r = synthesize("example.com", [])
        assert r["risk_level"] == "UNKNOWN"
        assert r["risk_score"] == 0
        assert "unavailable" in r["threat_brief"]

    def test_bad_json_falls_back_to_raw_text(self):
        raw = "This is a plain-text threat brief, not JSON."
        with patch("tools.llm_client.get_settings", return_value=_settings("key/user")):
            with patch("tools.llm_client.requests.post", return_value=_llm_response(raw)):
                r = synthesize("example.com", [])
        assert r["threat_brief"] == raw
        assert r["risk_score"] == 0
        assert r["risk_level"] == "UNKNOWN"

    def test_risk_score_clamped_to_int(self):
        payload = '{"threat_brief": "High risk.", "risk_score": 80, "risk_level": "CRITICAL"}'
        with patch("tools.llm_client.get_settings", return_value=_settings("key/user")):
            with patch("tools.llm_client.requests.post", return_value=_llm_response(payload)):
                r = synthesize("evil.com", [{"source": "virustotal", "malicious": 10}])
        assert isinstance(r["risk_score"], int)
        assert r["risk_score"] == 80

    def test_authorization_header_uses_bearer_format(self):
        payload = '{"threat_brief": "OK.", "risk_score": 5, "risk_level": "LOW"}'
        with patch("tools.llm_client.get_settings", return_value=_settings("mykey/myuser")):
            with patch("tools.llm_client.requests.post", return_value=_llm_response(payload)) as mp:
                synthesize("example.com", [])
        headers = mp.call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer mykey/myuser"

    def test_sources_included_in_request_body(self):
        payload = '{"threat_brief": "OK.", "risk_score": 5, "risk_level": "LOW"}'
        sources = [{"source": "virustotal", "malicious": 3}]
        with patch("tools.llm_client.get_settings", return_value=_settings("k/u")):
            with patch("tools.llm_client.requests.post", return_value=_llm_response(payload)) as mp:
                synthesize("example.com", sources)
        body = json.loads(mp.call_args[1]["data"])
        user_text = body["messages"][1]["content"][0]["text"]
        assert "virustotal" in user_text
        assert "example.com" in user_text


# ─── provider routing ────────────────────────────────────────────────────────

class TestProviderRouting:
    def test_ollama_provider_uses_local_url(self):
        payload = '{"threat_brief": "OK.", "risk_score": 5, "risk_level": "LOW"}'
        s = _settings(provider="ollama")
        with patch("tools.llm_client.get_settings", return_value=s):
            with patch("tools.llm_client.requests.post", return_value=_llm_response(payload)) as mp:
                r = synthesize("example.com", [])
        assert r["risk_score"] == 5
        url = mp.call_args[0][0]
        assert "localhost:11434" in url
        assert "/v1/chat/completions" in url
        # Ollama should NOT have Authorization header
        headers = mp.call_args[1]["headers"]
        assert "Authorization" not in headers

    def test_groq_provider_uses_groq_url(self):
        payload = '{"threat_brief": "OK.", "risk_score": 15, "risk_level": "LOW"}'
        s = _settings(provider="groq")
        s.groq_api_key = _FakeSecretStr("gsk_test123")
        with patch("tools.llm_client.get_settings", return_value=s):
            with patch("tools.llm_client.requests.post", return_value=_llm_response(payload)) as mp:
                r = synthesize("example.com", [])
        assert r["risk_score"] == 15
        url = mp.call_args[0][0]
        assert "api.groq.com" in url
        headers = mp.call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer gsk_test123"

    def test_anthropic_provider_calls_sdk(self):
        s = _settings(provider="anthropic")
        s.anthropic_api_key = _FakeSecretStr("sk-ant-test")
        with patch("tools.llm_client.get_settings", return_value=s):
            with patch("tools.llm_client._call_anthropic", return_value='{"threat_brief": "Via Anthropic.", "risk_score": 40, "risk_level": "MEDIUM"}'):
                r = synthesize("example.com", [])
        assert r["risk_score"] == 40
        assert r["threat_brief"] == "Via Anthropic."

    def test_missing_groq_key_returns_error(self):
        s = _settings(provider="groq")
        s.groq_api_key = _FakeSecretStr("")
        with patch("tools.llm_client.get_settings", return_value=s):
            r = synthesize("example.com", [])
        assert r["risk_level"] == "UNKNOWN"
        assert "unavailable" in r["threat_brief"]

    def test_missing_anthropic_key_returns_error(self):
        s = _settings(provider="anthropic")
        s.anthropic_api_key = _FakeSecretStr("")
        with patch("tools.llm_client.get_settings", return_value=s):
            r = synthesize("example.com", [])
        assert r["risk_level"] == "UNKNOWN"
        assert "unavailable" in r["threat_brief"]
