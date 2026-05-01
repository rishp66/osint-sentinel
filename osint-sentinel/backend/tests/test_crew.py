"""Unit tests for agents/crew.py — all OSINT functions and LLM calls mocked."""

import pytest
from unittest.mock import patch

import agents.crew as crew
from agents.crew import run_scan, _detect_type, _build_tasks


# ─── helpers ─────────────────────────────────────────────────────────────────

def _src(name):
    return {"source": name, "_query_time_ms": 50.0}


MOCK_SYNTH  = {"threat_brief": "Test threat brief.", "risk_score": 30, "risk_level": "MEDIUM"}
MOCK_REPORT = "### Endpoint Summary\nTest endpoint.\n### Threat Assessment\nLow risk."


@pytest.fixture(autouse=True)
def _clear_cache():
    """run_scan caches by target — clear between tests so mocks fire every time."""
    crew._CACHE.clear()
    yield
    crew._CACHE.clear()


# All source functions to mock in run_scan tests
_ALL_SOURCES = [
    "query_whois", "query_virustotal", "query_abuseipdb", "query_shodan",
    "query_otx", "query_ipinfo", "query_dns",
    "query_greynoise", "query_urlscan", "query_hybrid_analysis", "query_rdap",
    "query_circl_cve", "query_threatfox", "query_urlhaus", "query_malwarebazaar",
    "query_pulsedive", "query_cve_mcp",
]


def _patch_all():
    """Context manager stack that mocks every source + LLM call on crew module."""
    patches = [
        patch(f"agents.crew.{name}", return_value=_src(name.replace("query_", "")))
        for name in _ALL_SOURCES
    ]
    patches.append(patch("agents.crew.synthesize", return_value=MOCK_SYNTH))
    patches.append(patch("agents.crew.generate_report", return_value=MOCK_REPORT))
    return patches


def _run_with_mocks(target):
    patches = _patch_all()
    started = [p.start() for p in patches]
    try:
        return run_scan(target), started
    finally:
        for p in patches:
            p.stop()


# ─── _detect_type ────────────────────────────────────────────────────────────

class TestDetectType:
    def test_ipv4(self):
        assert _detect_type("8.8.8.8") == "ip"

    def test_ipv6(self):
        assert _detect_type("2001:4860:4860::8888") == "ip"

    def test_domain(self):
        assert _detect_type("example.com") == "domain"

    def test_url_http(self):
        assert _detect_type("http://example.com/foo") == "url"

    def test_url_https(self):
        assert _detect_type("https://example.com/foo") == "url"

    def test_md5_hash(self):
        assert _detect_type("44d88612fea8a8f36de82e1278abb02f") == "hash"

    def test_sha1_hash(self):
        assert _detect_type("a" * 40) == "hash"

    def test_sha256_hash(self):
        assert _detect_type("a" * 64) == "hash"

    def test_cve_id(self):
        assert _detect_type("CVE-2021-44228") == "cve"

    def test_cve_id_case_insensitive(self):
        assert _detect_type("cve-2021-44228") == "cve"

    def test_non_hex_falls_back_to_domain(self):
        assert _detect_type("zzzzzzzz" * 4) == "domain"  # 32 chars but not hex

    def test_whitespace_stripped(self):
        assert _detect_type("  example.com  ") == "domain"


# ─── _build_tasks ────────────────────────────────────────────────────────────

class TestBuildTasks:
    def test_ip_builds_ip_oriented_sources(self):
        with patch("agents.crew._resolve", return_value="8.8.8.8"):
            tasks = _build_tasks("8.8.8.8", "ip")
        names = set(tasks.keys())
        # Existing host-based sources
        assert {"virustotal", "abuseipdb", "shodan", "otx", "ipinfo", "dns"}.issubset(names)
        # New IP sources
        assert {"greynoise", "rdap", "urlscan", "threatfox", "urlhaus",
                "pulsedive"}.issubset(names)
        # No WHOIS for IPs
        assert "whois" not in names
        # No file-oriented sources
        assert "malwarebazaar" not in names
        assert "hybrid_analysis" not in names
        assert "circl_cve" not in names

    def test_domain_includes_whois(self):
        with patch("agents.crew._resolve", return_value="1.2.3.4"):
            tasks = _build_tasks("example.com", "domain")
        assert "whois" in tasks
        assert "urlscan" in tasks
        assert "threatfox" in tasks
        # When domain resolves successfully, IP sources should also fire
        assert "greynoise" in tasks
        assert "rdap" in tasks

    def test_domain_unresolvable_skips_ip_sources(self):
        with patch("agents.crew._resolve", return_value="nope.invalid"):
            tasks = _build_tasks("nope.invalid", "domain")
        # unresolved → _is_ip check fails → no greynoise/rdap
        assert "greynoise" not in tasks
        assert "rdap" not in tasks
        # domain-level sources still present
        assert "whois" in tasks
        assert "urlscan" in tasks

    def test_url_derives_host_for_host_sources(self):
        with patch("agents.crew._resolve", return_value="1.2.3.4"):
            tasks = _build_tasks("https://evil.example/path", "url")
        assert "whois" in tasks  # host derived from URL
        assert "urlscan" in tasks
        assert "greynoise" in tasks  # resolved IP enables IP-only sources

    def test_hash_builds_file_sources_only(self):
        tasks = _build_tasks("a" * 64, "hash")
        names = set(tasks.keys())
        assert names == {
            "virustotal", "hybrid_analysis", "malwarebazaar",
            "threatfox", "urlhaus", "pulsedive",
        }

    def test_cve_builds_circl_and_cve_mcp(self):
        tasks = _build_tasks("CVE-2021-44228", "cve")
        assert set(tasks.keys()) == {"circl_cve", "cve_mcp"}


# ─── run_scan — integration-style tests with mocked sources ─────────────────

class TestRunScan:
    def test_domain_scan_returns_schema_shape(self):
        result, _ = _run_with_mocks("example.com")
        assert result["target"] == "example.com"
        assert isinstance(result["risk_score"], int)
        assert result["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"}
        assert isinstance(result["sources"], list)
        assert len(result["sources"]) > 0
        assert result["agent_report"] == MOCK_REPORT
        assert result["indicator_type"] == "domain"

    def test_ip_scan_skips_whois(self):
        result, mocks = _run_with_mocks("8.8.8.8")
        # Find the query_whois mock — it should never have been called
        whois_mock = next(m for m in mocks if m._mock_name == "query_whois"
                          or "query_whois" in repr(m))
        # Alternative: confirm no "whois" source appears
        assert "whois" not in {s["source"] for s in result["sources"]}
        assert result["indicator_type"] == "ip"

    def test_hash_scan_fires_only_file_sources(self):
        result, _ = _run_with_mocks("44d88612fea8a8f36de82e1278abb02f")
        names = {s["source"] for s in result["sources"]}
        # Only file-oriented sources should be present
        assert "abuseipdb" not in names
        assert "shodan" not in names
        assert "whois" not in names
        assert "hybrid_analysis" in names
        assert "malwarebazaar" in names
        assert result["indicator_type"] == "hash"

    def test_cve_scan_fires_circl_and_cve_mcp(self):
        result, _ = _run_with_mocks("CVE-2021-44228")
        names = {s["source"] for s in result["sources"]}
        assert "circl_cve" in names
        assert "cve_mcp" in names
        assert result["indicator_type"] == "cve"

    def test_cve_scan_disabled_mcp_still_returns_circl(self):
        """When cve_mcp returns {"error": "disabled"} the scan still succeeds via CIRCL."""
        patches = [
            patch("agents.crew.query_circl_cve", return_value=_src("circl_cve")),
            patch("agents.crew.query_cve_mcp",   return_value={"source": "cve_mcp", "error": "disabled"}),
            patch("agents.crew.synthesize",       return_value=MOCK_SYNTH),
            patch("agents.crew.generate_report",  return_value=MOCK_REPORT),
        ]
        for p in patches:
            p.start()
        try:
            result = run_scan("CVE-2021-44228")
        finally:
            for p in patches:
                p.stop()
        names = {s["source"] for s in result["sources"]}
        assert "circl_cve" in names
        assert result["risk_score"] == MOCK_SYNTH["risk_score"]

    def test_url_scan_routes_to_url_sources(self):
        result, _ = _run_with_mocks("https://phish.example/login")
        names = {s["source"] for s in result["sources"]}
        assert "urlscan" in names
        assert "threatfox" in names
        assert result["indicator_type"] == "url"

    def test_source_exception_recorded_as_error_dict(self):
        patches = _patch_all()
        # Replace query_ipinfo patch with one that raises
        for i, p in enumerate(patches):
            if "query_ipinfo" in str(p.attribute):
                patches[i] = patch("agents.crew.query_ipinfo", side_effect=RuntimeError("ipinfo exploded"))
                break
        started = [p.start() for p in patches]
        try:
            result = run_scan("example.com")
        finally:
            for p in patches:
                p.stop()
        error_srcs = [s for s in result["sources"] if "error" in s]
        assert any(s["source"] == "ipinfo" and "ipinfo exploded" in s["error"]
                   for s in error_srcs)
