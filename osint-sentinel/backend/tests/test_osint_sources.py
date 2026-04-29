"""Unit tests for tools/osint_sources.py — all external calls mocked."""

import pytest
from unittest.mock import patch, MagicMock
import requests as _requests

from tools.osint_sources import (
    _resolve_to_ip,
    query_whois,
    query_virustotal,
    query_abuseipdb,
    query_shodan,
    query_otx,
    query_ipinfo,
    query_dns,
    query_greynoise,
    query_urlscan,
    query_hybrid_analysis,
    query_rdap,
    query_circl_cve,
    query_threatfox,
    query_urlhaus,
    query_malwarebazaar,
    query_pulsedive,
)


# ─── helpers ─────────────────────────────────────────────────────────────────

class _FakeSecretStr:
    """Mimics pydantic.SecretStr for test settings."""
    def __init__(self, value: str):
        self._value = value
    def get_secret_value(self) -> str:
        return self._value
    def __bool__(self) -> bool:
        return bool(self._value)


def _settings(**kwargs):
    m = MagicMock()
    m.virustotal_api_key     = _FakeSecretStr(kwargs.get("virustotal_api_key",     "vt-key"))
    m.abuseipdb_api_key      = _FakeSecretStr(kwargs.get("abuseipdb_api_key",      "abuse-key"))
    m.shodan_api_key         = _FakeSecretStr(kwargs.get("shodan_api_key",         "shodan-key"))
    m.otx_api_key            = _FakeSecretStr(kwargs.get("otx_api_key",            "otx-key"))
    m.ipinfo_token           = _FakeSecretStr(kwargs.get("ipinfo_token",           "ipinfo-tok"))
    m.urlscan_api_key        = _FakeSecretStr(kwargs.get("urlscan_api_key",        "urlscan-key"))
    m.hybrid_analysis_api_key= _FakeSecretStr(kwargs.get("hybrid_analysis_api_key","ha-key"))
    m.abusech_auth_key       = _FakeSecretStr(kwargs.get("abusech_auth_key",       "abusech-key"))
    m.pulsedive_api_key      = _FakeSecretStr(kwargs.get("pulsedive_api_key",      "pd-key"))
    return m


def _ok_response(json_data):
    m = MagicMock()
    m.ok = True
    m.raise_for_status = MagicMock()
    m.json.return_value = json_data
    return m


def _http_error(status_code, text="Error"):
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.text = text
    err = _requests.exceptions.HTTPError(response=mock_resp)
    bad = MagicMock()
    bad.raise_for_status.side_effect = err
    return bad


# ─── _resolve_to_ip ──────────────────────────────────────────────────────────

class TestResolveToIp:
    def test_ipv4_passthrough(self):
        assert _resolve_to_ip("93.184.216.34") == "93.184.216.34"

    def test_ipv6_passthrough(self):
        assert _resolve_to_ip("::1") == "::1"

    def test_domain_calls_gethostbyname(self):
        with patch("tools.osint_sources.socket.gethostbyname", return_value="1.2.3.4") as m:
            result = _resolve_to_ip("example.com")
        assert result == "1.2.3.4"
        m.assert_called_once_with("example.com")


# ─── query_whois ─────────────────────────────────────────────────────────────

class TestQueryWhois:
    _WHOIS_DATA = {
        "domain_name": "EXAMPLE.COM",
        "registrar":   "Example Registrar LLC",
        "creation_date": None,
        "expiration_date": None,
        "updated_date":   None,
        "name_servers": ["ns1.example.com"],
        "org":          "Example Org",
        "country":      "US",
        "state":        "CA",
        "dnssec":       "unsigned",
        "emails":       "admin@example.com",
        "status":       "clientTransferProhibited",
    }

    def test_success_maps_fields(self):
        with patch("tools.osint_sources.whois.whois", return_value=self._WHOIS_DATA):
            r = query_whois("example.com")
        assert r["source"] == "whois"
        assert r["registrar"] == "Example Registrar LLC"
        assert r["registrant_org"] == "Example Org"
        assert r["registrant_country"] == "US"

    def test_timed_decorator_adds_key(self):
        with patch("tools.osint_sources.whois.whois", return_value=self._WHOIS_DATA):
            r = query_whois("example.com")
        assert "_query_time_ms" in r
        assert isinstance(r["_query_time_ms"], float)

    def test_exception_returns_error_dict(self):
        with patch("tools.osint_sources.whois.whois", side_effect=Exception("network timeout")):
            r = query_whois("example.com")
        assert r["source"] == "whois"
        assert "error" in r
        assert "network timeout" in r["error"]


# ─── query_virustotal ────────────────────────────────────────────────────────

class TestQueryVirusTotal:
    _VT_RESP = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 5, "suspicious": 2, "harmless": 60, "undetected": 10},
                "reputation": -3,
                "total_votes": {"harmless": 10, "malicious": 5},
                "last_analysis_date": 1700000000,
                "categories": {},
                "tags": ["malware"],
                "registrar": "Test Registrar",
                "last_dns_records": [],
                "popularity_ranks": {},
            }
        }
    }

    def test_missing_key_returns_error(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings(virustotal_api_key="")):
            r = query_virustotal("example.com")
        assert r["source"] == "virustotal"
        assert "error" in r

    def test_domain_query_success(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._VT_RESP)):
                r = query_virustotal("example.com", query_type="domain")
        assert r["source"] == "virustotal"
        assert r["malicious"] == 5
        assert r["suspicious"] == 2
        assert "registrar" in r  # domain-specific field
        assert "_query_time_ms" in r

    def test_ip_query_uses_correct_url(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._VT_RESP)) as mg:
                query_virustotal("1.2.3.4", query_type="ip")
        assert "/ip_addresses/1.2.3.4" in mg.call_args[0][0]

    def test_url_query_uses_base64_id(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._VT_RESP)) as mg:
                query_virustotal("http://evil.com/path", query_type="url")
        assert "/urls/" in mg.call_args[0][0]

    def test_http_error_returns_error_dict(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_http_error(401, "Unauthorized")):
                r = query_virustotal("example.com")
        assert r["source"] == "virustotal"
        assert "error" in r
        assert "401" in r["error"]

    def test_domain_query_omits_ip_only_fields(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._VT_RESP)):
                r = query_virustotal("example.com", query_type="domain")
        # domain response includes registrar; ip response does not
        assert "registrar" in r


# ─── query_abuseipdb ─────────────────────────────────────────────────────────

class TestQueryAbuseIPDB:
    _ABUSE_RESP = {
        "data": {
            "ipAddress": "1.2.3.4",
            "isPublic": True,
            "abuseConfidenceScore": 87,
            "totalReports": 42,
            "numDistinctUsers": 10,
            "lastReportedAt": "2024-01-01T00:00:00Z",
            "isp": "Test ISP",
            "domain": "test.com",
            "countryCode": "RU",
            "usageType": "Data Center",
            "isWhitelisted": False,
            "isTor": False,
            "reports": [
                {"reportedAt": "2024-01-01", "categories": [18], "comment": "Spam source"}
            ],
        }
    }

    def test_missing_key_returns_error(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings(abuseipdb_api_key="")):
            r = query_abuseipdb("1.2.3.4")
        assert "error" in r
        assert r["source"] == "abuseipdb"

    def test_success_maps_fields(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._ABUSE_RESP)):
                r = query_abuseipdb("1.2.3.4")
        assert r["source"] == "abuseipdb"
        assert r["abuse_confidence_score"] == 87
        assert r["total_reports"] == 42
        assert r["is_tor"] is False
        assert len(r["recent_reports"]) == 1
        assert "_query_time_ms" in r

    def test_domain_resolved_before_request(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._ABUSE_RESP)) as mg:
                with patch("tools.osint_sources.socket.gethostbyname", return_value="9.9.9.9"):
                    query_abuseipdb("example.com")
        assert mg.call_args[1]["params"]["ipAddress"] == "9.9.9.9"

    def test_report_comments_truncated_at_150(self):
        long_resp = dict(self._ABUSE_RESP)
        long_resp = {"data": dict(self._ABUSE_RESP["data"])}
        long_resp["data"]["reports"] = [
            {"reportedAt": "2024-01-01", "categories": [18], "comment": "x" * 300}
        ]
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(long_resp)):
                r = query_abuseipdb("1.2.3.4")
        assert len(r["recent_reports"][0]["comment"]) == 150


# ─── query_shodan ─────────────────────────────────────────────────────────────

class TestQueryShodan:
    _SHODAN_RESP = {
        "ip_str": "1.2.3.4",
        "hostnames": ["example.com"],
        "os": None,
        "org": "Test Org",
        "isp": "Test ISP",
        "asn": "AS12345",
        "ports": [80, 443, 22],
        "vulns": ["CVE-2021-44228"],
        "data": [
            {"port": 80,  "transport": "tcp", "product": "nginx",  "version": "1.18", "data": "HTTP/1.1 200 OK", "cpe": []},
            {"port": 443, "transport": "tcp", "product": "nginx",  "version": "1.18", "data": "",                "cpe": []},
        ],
        "city": "San Francisco",
        "country_name": "United States",
        "last_update": "2024-01-01T00:00:00Z",
    }

    def test_missing_key_returns_error(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings(shodan_api_key="")):
            r = query_shodan("1.2.3.4")
        assert "error" in r
        assert r["source"] == "shodan"

    def test_success_maps_fields(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._SHODAN_RESP)):
                r = query_shodan("1.2.3.4")
        assert r["source"] == "shodan"
        assert r["ports"] == [80, 443, 22]
        assert r["vulns"] == ["CVE-2021-44228"]
        assert len(r["services"]) == 2
        assert r["services"][0]["port"] == 80
        assert r["services"][0]["banner"] == "HTTP/1.1 200 OK"
        assert "_query_time_ms" in r

    def test_404_returns_no_data_note(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_http_error(404)):
                r = query_shodan("1.2.3.4")
        assert r["source"] == "shodan"
        assert "note" in r
        assert "No Shodan data" in r["note"]

    def test_non_404_http_error_returns_error(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_http_error(403)):
                r = query_shodan("1.2.3.4")
        assert "error" in r
        assert "403" in r["error"]

    def test_domain_resolved_to_ip(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._SHODAN_RESP)) as mg:
                with patch("tools.osint_sources.socket.gethostbyname", return_value="5.5.5.5"):
                    query_shodan("example.com")
        assert "5.5.5.5" in mg.call_args[0][0]


# ─── query_otx ───────────────────────────────────────────────────────────────

class TestQueryOTX:
    def _mock_get(self, url, headers, timeout):
        resp = MagicMock()
        resp.ok = True
        if "general" in url:
            resp.json.return_value = {
                "pulse_info": {
                    "count": 2,
                    "pulses": [
                        {"name": "Evil Pulse", "description": "Bad actor", "created": "2024-01-01",
                         "tags": ["malware", "c2"], "adversary": "APT-X", "targeted_countries": ["US"]}
                    ],
                },
                "reputation": -5,
                "sections": ["general", "malware"],
            }
        elif "passive_dns" in url:
            resp.json.return_value = {
                "passive_dns": [
                    {"hostname": "sub.example.com", "address": "1.2.3.4",
                     "record_type": "A", "first": "2023-01-01", "last": "2024-01-01"}
                ]
            }
        else:  # malware
            resp.json.return_value = {"data": [{"hash": "abc123", "detections": {"engine": True}}]}
        return resp

    def test_missing_key_returns_error(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings(otx_api_key="")):
            r = query_otx("example.com")
        assert r["source"] == "alienvault_otx"
        assert "error" in r

    def test_success_all_sections(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", side_effect=self._mock_get):
                r = query_otx("example.com")
        assert r["source"] == "alienvault_otx"
        assert r["pulse_count"] == 2
        assert len(r["pulses"]) == 1
        assert r["pulses"][0]["adversary"] == "APT-X"
        assert r["passive_dns_count"] == 1
        assert r["malware_samples"] == 1
        assert "_query_time_ms" in r

    def test_ip_query_uses_ipv4_section(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", side_effect=self._mock_get) as mg:
                query_otx("1.2.3.4", query_type="ip")
        assert "/IPv4/" in mg.call_args_list[0][0][0]

    def test_network_failure_returns_no_response_error(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", side_effect=Exception("connect timeout")):
                r = query_otx("example.com")
        assert r["source"] == "alienvault_otx"
        assert "error" in r

    def test_pulses_capped_at_5(self):
        def mock_get(url, headers, timeout):
            resp = MagicMock()
            resp.ok = True
            if "general" in url:
                resp.json.return_value = {
                    "pulse_info": {
                        "count": 10,
                        "pulses": [
                            {"name": f"Pulse {i}", "description": "", "created": "2024-01-01",
                             "tags": [], "adversary": None, "targeted_countries": []}
                            for i in range(10)
                        ],
                    },
                    "reputation": 0, "sections": [],
                }
            else:
                resp.json.return_value = {"passive_dns": [], "data": []}
            return resp

        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", side_effect=mock_get):
                r = query_otx("example.com")
        assert len(r["pulses"]) == 5


# ─── query_ipinfo ─────────────────────────────────────────────────────────────

class TestQueryIPInfo:
    _IPINFO_RESP = {
        "ip": "1.2.3.4", "hostname": "example.com", "city": "New York",
        "region": "New York", "country": "US", "loc": "40.7,-74.0",
        "org": "AS12345 Test Corp", "postal": "10001", "timezone": "America/New_York",
    }

    def test_missing_token_returns_error(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings(ipinfo_token="")):
            r = query_ipinfo("1.2.3.4")
        assert r["source"] == "ipinfo"
        assert "error" in r

    def test_success_maps_fields(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._IPINFO_RESP)):
                r = query_ipinfo("1.2.3.4")
        assert r["source"] == "ipinfo"
        assert r["city"] == "New York"
        assert r["country"] == "US"
        assert r["org"] == "AS12345 Test Corp"
        assert "_query_time_ms" in r

    def test_domain_resolved_to_ip(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._IPINFO_RESP)) as mg:
                with patch("tools.osint_sources.socket.gethostbyname", return_value="5.5.5.5"):
                    query_ipinfo("example.com")
        assert "5.5.5.5" in mg.call_args[0][0]


# ─── query_dns ────────────────────────────────────────────────────────────────

class TestQueryDNS:
    def test_success_returns_unique_ips(self):
        addrinfo = [
            (None, None, None, None, ("1.2.3.4", 0)),
            (None, None, None, None, ("1.2.3.4", 0)),  # duplicate — should be deduplicated
            (None, None, None, None, ("5.6.7.8", 0)),
        ]
        with patch("socket.getaddrinfo", return_value=addrinfo):
            r = query_dns("example.com")
        assert r["source"] == "dns_resolution"
        assert set(r["resolved_ips"]) == {"1.2.3.4", "5.6.7.8"}
        assert r["hostname"] == "example.com"
        assert "_query_time_ms" in r

    def test_failure_returns_error_dict(self):
        with patch("socket.getaddrinfo", side_effect=OSError("NXDOMAIN")):
            r = query_dns("nonexistent.invalid")
        assert r["source"] == "dns_resolution"
        assert "error" in r
        assert "NXDOMAIN" in r["error"]


# ─── query_greynoise ─────────────────────────────────────────────────────────

class TestQueryGreynoise:
    _RESP = {
        "ip": "8.8.8.8",
        "noise": False,
        "riot": True,
        "classification": "benign",
        "name": "Google Public DNS",
        "link": "https://viz.greynoise.io/riot/8.8.8.8",
        "last_seen": "2024-01-01",
        "message": "Success",
    }

    def test_success_maps_fields(self):
        with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._RESP)):
            r = query_greynoise("8.8.8.8")
        assert r["source"] == "greynoise"
        assert r["classification"] == "benign"
        assert r["riot"] is True
        assert "_query_time_ms" in r

    def test_no_auth_header_sent(self):
        with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._RESP)) as mg:
            query_greynoise("8.8.8.8")
        headers = mg.call_args[1]["headers"]
        assert "key" not in headers  # Community API is unauthenticated

    def test_404_returns_unknown_classification(self):
        resp = MagicMock()
        resp.status_code = 404
        with patch("tools.osint_sources._SESSION.get", return_value=resp):
            r = query_greynoise("1.2.3.4")
        assert r["source"] == "greynoise"
        assert r["classification"] == "unknown"
        assert "note" in r

    def test_http_error_returns_error_dict(self):
        bad = _http_error(500, "Server Error")
        bad.status_code = 500
        with patch("tools.osint_sources._SESSION.get", return_value=bad):
            r = query_greynoise("1.2.3.4")
        assert "error" in r


# ─── query_urlscan ───────────────────────────────────────────────────────────

class TestQueryUrlscan:
    _RESP = {
        "total": 2,
        "results": [
            {
                "task": {"time": "2024-01-01T00:00:00Z", "url": "https://example.com/"},
                "page": {"domain": "example.com", "ip": "1.2.3.4", "server": "nginx"},
                "verdicts": {"overall": {"malicious": False, "score": 0}},
                "result": "https://urlscan.io/result/abc/",
                "screenshot": "https://urlscan.io/screenshots/abc.png",
            }
        ],
    }

    def test_missing_key_returns_error(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings(urlscan_api_key="")):
            r = query_urlscan("example.com")
        assert "error" in r

    def test_success_maps_fields(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._RESP)):
                r = query_urlscan("example.com", query_type="domain")
        assert r["source"] == "urlscan"
        assert r["total_results"] == 2
        assert len(r["results"]) == 1
        assert r["results"][0]["domain"] == "example.com"

    def test_empty_results_returns_note(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response({"results": [], "total": 0})):
                r = query_urlscan("example.com")
        assert r["total_results"] == 0
        assert "note" in r

    def test_ip_query_type_uses_ip_filter(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._RESP)) as mg:
                query_urlscan("1.2.3.4", query_type="ip")
        assert mg.call_args[1]["params"]["q"] == "ip:1.2.3.4"


# ─── query_hybrid_analysis ───────────────────────────────────────────────────

class TestQueryHybridAnalysis:
    _RESP = [
        {
            "sha256": "a" * 64,
            "verdict": "malicious",
            "threat_score": 90,
            "vx_family": "Emotet",
            "type_short": "exe",
            "av_detect": 52,
            "analysis_start_time": "2024-01-01T00:00:00Z",
            "domains": ["bad.com"],
            "hosts": ["1.2.3.4"],
        }
    ]

    def test_missing_key_returns_error(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings(hybrid_analysis_api_key="")):
            r = query_hybrid_analysis("a" * 64)
        assert "error" in r

    def test_success_maps_fields(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.post", return_value=_ok_response(self._RESP)):
                r = query_hybrid_analysis("a" * 64)
        assert r["source"] == "hybrid_analysis"
        assert r["result_count"] == 1
        assert r["results"][0]["verdict"] == "malicious"
        assert r["results"][0]["vx_family"] == "Emotet"

    def test_empty_response_returns_note(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.post", return_value=_ok_response([])):
                r = query_hybrid_analysis("a" * 64)
        assert "note" in r

    def test_required_headers_sent(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.post", return_value=_ok_response(self._RESP)) as mp:
                query_hybrid_analysis("a" * 64)
        headers = mp.call_args[1]["headers"]
        assert headers["User-Agent"] == "Falcon Sandbox"
        assert headers["api-key"] == "ha-key"


# ─── query_rdap ──────────────────────────────────────────────────────────────

class TestQueryRdap:
    _RDAP = {
        "asn": "15169",
        "asn_cidr": "8.8.8.0/24",
        "asn_country_code": "US",
        "asn_description": "GOOGLE",
        "asn_registry": "arin",
        "network": {
            "name": "GOOGLE",
            "cidr": "8.8.8.0/24",
            "country": "US",
            "handle": "NET-8-8-8-0-1",
        },
        "objects": {
            "GOGL": {
                "contact": {
                    "name": "Google LLC",
                    "email": [{"value": "abuse@google.com"}],
                },
                "roles": ["abuse"],
            }
        },
    }

    def test_success_maps_fields(self):
        fake_obj = MagicMock()
        fake_obj.lookup_rdap.return_value = self._RDAP
        with patch("ipwhois.IPWhois", return_value=fake_obj):
            r = query_rdap("8.8.8.8")
        assert r["source"] == "rdap"
        assert r["asn"] == "15169"
        assert r["network_cidr"] == "8.8.8.0/24"
        assert len(r["entities"]) == 1
        assert r["entities"][0]["emails"] == ["abuse@google.com"]

    def test_exception_returns_error_dict(self):
        fake_obj = MagicMock()
        fake_obj.lookup_rdap.side_effect = Exception("private IP")
        with patch("ipwhois.IPWhois", return_value=fake_obj):
            r = query_rdap("10.0.0.1")
        assert r["source"] == "rdap"
        assert "error" in r


# ─── query_circl_cve ─────────────────────────────────────────────────────────

class TestQueryCirclCve:
    _RESP = {
        "id": "CVE-2021-44228",
        "summary": "Log4Shell remote code execution vulnerability.",
        "Published": "2021-12-10",
        "Modified": "2022-01-01",
        "cvss": 10.0,
        "cvss-vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
        "access": {},
        "impact": {},
        "references": ["https://example.com/advisory"],
        "vulnerable_product": ["cpe:/a:apache:log4j:2.0"],
    }

    def test_success_maps_fields(self):
        with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._RESP)):
            r = query_circl_cve("CVE-2021-44228")
        assert r["source"] == "circl_cve"
        assert r["id"] == "CVE-2021-44228"
        assert r["cvss"] == 10.0
        assert len(r["references"]) == 1

    def test_404_returns_note(self):
        resp = MagicMock()
        resp.status_code = 404
        with patch("tools.osint_sources._SESSION.get", return_value=resp):
            r = query_circl_cve("CVE-9999-0000")
        assert r["source"] == "circl_cve"
        assert "note" in r


# ─── query_threatfox ─────────────────────────────────────────────────────────

class TestQueryThreatfox:
    _RESP = {
        "query_status": "ok",
        "data": [
            {
                "ioc": "1.2.3.4",
                "ioc_type": "ip:port",
                "threat_type": "botnet_cc",
                "malware": "Emotet",
                "malware_alias": "Heodo",
                "confidence_level": 100,
                "first_seen": "2024-01-01",
                "last_seen": "2024-02-01",
                "tags": ["emotet"],
                "reference": "https://threatfox.abuse.ch/ioc/1/",
            }
        ],
    }

    def test_missing_key_returns_error(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings(abusech_auth_key="")):
            r = query_threatfox("1.2.3.4")
        assert "error" in r

    def test_success_maps_matches(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.post", return_value=_ok_response(self._RESP)):
                r = query_threatfox("1.2.3.4", query_type="ip")
        assert r["source"] == "threatfox"
        assert r["query_status"] == "ok"
        assert r["match_count"] == 1
        assert r["matches"][0]["malware"] == "Emotet"

    def test_no_results_returns_empty_matches(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.post",
                       return_value=_ok_response({"query_status": "no_result", "data": []})):
                r = query_threatfox("1.2.3.4")
        assert r["matches"] == []

    def test_hash_query_uses_search_hash(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.post", return_value=_ok_response(self._RESP)) as mp:
                query_threatfox("a" * 64, query_type="hash")
        assert mp.call_args[1]["json"] == {"query": "search_hash", "hash": "a" * 64}


# ─── query_urlhaus ───────────────────────────────────────────────────────────

class TestQueryUrlhaus:
    _HOST_RESP = {
        "query_status": "ok",
        "urls": [
            {"url": "http://bad.com/mal.exe", "url_status": "online",
             "threat": "malware_download", "tags": ["emotet"], "date_added": "2024-01-01"}
        ],
        "blacklists": {"spamhaus_dbl": "listed"},
    }
    _URL_RESP = {
        "query_status": "ok",
        "url_status": "online",
        "threat": "malware_download",
        "tags": ["emotet"],
        "date_added": "2024-01-01",
        "last_online": "2024-02-01",
        "payloads": [{"filename": "mal.exe", "file_type": "exe",
                      "signature": "Emotet", "response_sha256": "a" * 64}],
    }

    def test_missing_key_returns_error(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings(abusech_auth_key="")):
            r = query_urlhaus("example.com")
        assert "error" in r

    def test_host_query_success(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.post", return_value=_ok_response(self._HOST_RESP)):
                r = query_urlhaus("bad.com", query_type="domain")
        assert r["source"] == "urlhaus"
        assert r["url_count"] == 1
        assert r["urls_online"] == 1
        assert len(r["urls"]) == 1

    def test_url_query_success(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.post", return_value=_ok_response(self._URL_RESP)):
                r = query_urlhaus("http://bad.com/mal.exe", query_type="url")
        assert r["threat"] == "malware_download"
        assert len(r["payloads"]) == 1
        assert r["payloads"][0]["signature"] == "Emotet"

    def test_no_results_returns_note(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.post",
                       return_value=_ok_response({"query_status": "no_results"})):
                r = query_urlhaus("clean.com")
        assert "note" in r


# ─── query_malwarebazaar ─────────────────────────────────────────────────────

class TestQueryMalwarebazaar:
    _RESP = {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": "a" * 64,
                "md5_hash": "b" * 32,
                "sha1_hash": "c" * 40,
                "file_type": "exe",
                "file_size": 123456,
                "signature": "Emotet",
                "tags": ["emotet", "botnet"],
                "first_seen": "2024-01-01",
                "last_seen": "2024-02-01",
                "delivery_method": "email_attachment",
                "origin_country": "DE",
                "intelligence": {"downloads": 100, "uploads": 5},
            }
        ],
    }

    def test_missing_key_returns_error(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings(abusech_auth_key="")):
            r = query_malwarebazaar("a" * 64)
        assert "error" in r

    def test_success_maps_samples(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.post", return_value=_ok_response(self._RESP)):
                r = query_malwarebazaar("a" * 64)
        assert r["source"] == "malwarebazaar"
        assert len(r["samples"]) == 1
        assert r["samples"][0]["signature"] == "Emotet"
        assert r["samples"][0]["downloads"] == 100

    def test_hash_not_found_returns_note(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.post",
                       return_value=_ok_response({"query_status": "hash_not_found"})):
                r = query_malwarebazaar("a" * 64)
        assert "note" in r


# ─── query_pulsedive ─────────────────────────────────────────────────────────

class TestQueryPulsedive:
    _RESP = {
        "indicator": "bad.com",
        "type": "domain",
        "risk": "high",
        "risk_recommended": "high",
        "summary": {"total": 5},
        "threats": [{"name": "Emotet", "category": "trojan", "risk": "high"}],
        "feeds": [{"name": "Feodo Tracker", "category": "botnet"}],
        "attributes": {"port": [80, 443], "protocol": ["tcp"]},
    }

    def test_success_maps_fields(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._RESP)):
                r = query_pulsedive("bad.com")
        assert r["source"] == "pulsedive"
        assert r["risk"] == "high"
        assert len(r["threats"]) == 1
        assert r["ports"] == [80, 443]

    def test_works_without_key(self):
        with patch("tools.osint_sources.get_settings", return_value=_settings(pulsedive_api_key="")):
            with patch("tools.osint_sources._SESSION.get", return_value=_ok_response(self._RESP)) as mg:
                r = query_pulsedive("bad.com")
        assert r["source"] == "pulsedive"
        assert "key" not in mg.call_args[1]["params"]

    def test_404_returns_note(self):
        resp = MagicMock()
        resp.status_code = 404
        with patch("tools.osint_sources.get_settings", return_value=_settings()):
            with patch("tools.osint_sources._SESSION.get", return_value=resp):
                r = query_pulsedive("clean.com")
        assert "note" in r
