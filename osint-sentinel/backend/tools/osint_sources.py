"""OSINT source query tools — each function hits one external API and returns structured data."""

import logging
import whois
import requests
from requests.adapters import HTTPAdapter
import time
import socket
import ipaddress
from typing import Any
from config.settings import get_settings
from tools.cve_mcp_client import call_cve_mcp_tool

logger = logging.getLogger(__name__)


def _http_error_msg(e: requests.HTTPError) -> str:
    """Return a generic client-safe error message; log real status internally.

    Do NOT log the request URL — Shodan/IPinfo/Pulsedive carry their API key
    in the query string. Logging the host alone keeps the signal without leak.
    """
    code = e.response.status_code if e.response is not None else 0
    host = ""
    try:
        if e.request is not None and e.request.url:
            from urllib.parse import urlparse

            host = urlparse(e.request.url).hostname or ""
    except Exception:
        host = ""
    logger.warning("upstream HTTP error: status=%d host=%s", code, host)
    if code == 401:
        return "Authentication failed"
    if code == 403:
        return "Access denied"
    if code == 404:
        return "Not found"
    if code == 429:
        return "Rate limited"
    return "Upstream error"


# ─── Performance: shared HTTP session + tight timeouts ───────────────────
# A single keep-alive Session is reused across all source calls so successive
# requests to the same host (e.g. urlscan.io, abuse.ch) skip TCP/TLS handshake.
# requests.Session is thread-safe enough for our parallel ThreadPoolExecutor use.
_SESSION = requests.Session()
_SESSION.trust_env = False  # ignore HTTP_PROXY/HTTPS_PROXY env vars — connect directly
_SESSION.headers.update({"User-Agent": "osint-sentinel/0.1 (+https://github.com)"})
_adapter = HTTPAdapter(pool_connections=32, pool_maxsize=32, max_retries=0)
_SESSION.mount("https://", _adapter)
_SESSION.mount("http://", _adapter)

# Per-API connect/read timeout. The crew has its own 18 s global ceiling, so
# individual sources should fail fast and not eat the whole budget.
_TIMEOUT = 8
_OTX_TIMEOUT = 6  # OTX makes 3 sub-calls in parallel — keep each tight
_HYBRID_TIMEOUT = 12  # Hybrid Analysis is consistently slow


def _resolve_to_ip(target: str) -> str:
    """Return target unchanged if it's already an IP (v4 or v6), else resolve via DNS."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(3)
        try:
            return socket.gethostbyname(target)
        except socket.gaierror as exc:
            logger.debug("DNS gaierror for %s: %s", target, exc)
            raise ValueError(f"DNS resolution failed for {target!r}") from exc
        finally:
            socket.setdefaulttimeout(old_timeout)


def _timed(func):
    """Decorator to measure query time in ms."""

    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = round((time.time() - start) * 1000, 2)
        if isinstance(result, dict):
            result["_query_time_ms"] = elapsed
        return result

    return wrapper


# ─── WHOIS ───────────────────────────────────────────────────────────────


@_timed
def query_whois(target: str) -> dict:
    """Query WHOIS data for a domain. No API key needed."""
    try:
        w = whois.whois(target)
        raw = w if isinstance(w, dict) else w.__dict__

        def _serialize(v: Any) -> Any:
            if hasattr(v, "isoformat"):
                return v.isoformat()
            if isinstance(v, list):
                return [_serialize(i) for i in v]
            return v

        return {
            "source": "whois",
            "domain_name": _serialize(raw.get("domain_name")),
            "registrar": raw.get("registrar"),
            "creation_date": _serialize(raw.get("creation_date")),
            "expiration_date": _serialize(raw.get("expiration_date")),
            "updated_date": _serialize(raw.get("updated_date")),
            "name_servers": _serialize(raw.get("name_servers")),
            "registrant_org": raw.get("org"),
            "registrant_country": raw.get("country"),
            "registrant_state": raw.get("state"),
            "dnssec": raw.get("dnssec"),
            "emails": _serialize(raw.get("emails")),
            "status": _serialize(raw.get("status")),
        }
    except Exception as e:
        return {"source": "whois", "error": str(e)}


# ─── VIRUSTOTAL ──────────────────────────────────────────────────────────


@_timed
def query_virustotal(target: str, query_type: str = "domain") -> dict:
    """Query VirusTotal API v3 for domain/IP/URL reports."""
    settings = get_settings()
    api_key = settings.virustotal_api_key.get_secret_value()
    if not api_key:
        return {"source": "virustotal", "error": "API key not configured"}

    headers = {"x-apikey": api_key}
    base = "https://www.virustotal.com/api/v3"

    try:
        if query_type == "ip":
            url = f"{base}/ip_addresses/{target}"
        elif query_type == "url":
            import base64 as b64

            url_id = b64.urlsafe_b64encode(target.encode()).decode().strip("=")
            url = f"{base}/urls/{url_id}"
        elif query_type in ("file", "hash"):
            url = f"{base}/files/{target}"
        else:
            url = f"{base}/domains/{target}"

        resp = _SESSION.get(url, headers=headers, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        result = {
            "source": "virustotal",
            "detection_stats": stats,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", "N/A"),
            "total_votes": attrs.get("total_votes", {}),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "categories": attrs.get("categories", {}),
            "tags": attrs.get("tags", []),
        }

        if query_type == "domain":
            result["registrar"] = attrs.get("registrar", "N/A")
            result["last_dns_records"] = attrs.get("last_dns_records", [])[:5]
            result["popularity_ranks"] = attrs.get("popularity_ranks", {})
        elif query_type in ("file", "hash"):
            result["file_type"] = attrs.get("type_description")
            result["size"] = attrs.get("size")
            result["md5"] = attrs.get("md5")
            result["sha1"] = attrs.get("sha1")
            result["sha256"] = attrs.get("sha256")
            result["names"] = attrs.get("names", [])[:5]
            result["signature_info"] = attrs.get("signature_info", {})
            result["popular_threat_classification"] = attrs.get(
                "popular_threat_classification", {}
            )

        return result

    except requests.HTTPError as e:
        return {"source": "virustotal", "error": _http_error_msg(e)}
    except Exception as e:
        return {"source": "virustotal", "error": str(e)}


# ─── ABUSEIPDB ───────────────────────────────────────────────────────────


@_timed
def query_abuseipdb(target: str) -> dict:
    """Query AbuseIPDB for IP abuse reports. Resolves domains to IP first."""
    settings = get_settings()
    api_key = settings.abuseipdb_api_key.get_secret_value()
    if not api_key:
        return {"source": "abuseipdb", "error": "API key not configured"}

    try:
        # Resolve domain to IP if needed
        ip = _resolve_to_ip(target)

        resp = _SESSION.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})

        return {
            "source": "abuseipdb",
            "ip_address": data.get("ipAddress"),
            "is_public": data.get("isPublic"),
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "country_code": data.get("countryCode"),
            "usage_type": data.get("usageType"),
            "is_whitelisted": data.get("isWhitelisted"),
            "is_tor": data.get("isTor", False),
            "recent_reports": [
                {
                    "reported_at": r.get("reportedAt"),
                    "categories": r.get("categories", []),
                    "comment": r.get("comment", "")[:150],
                }
                for r in data.get("reports", [])[:5]
            ],
        }
    except Exception as e:
        return {"source": "abuseipdb", "error": str(e)}


# ─── SHODAN ──────────────────────────────────────────────────────────────


@_timed
def query_shodan(target: str) -> dict:
    """Query Shodan for host information (open ports, services, vulns)."""
    settings = get_settings()
    api_key = settings.shodan_api_key.get_secret_value()
    if not api_key:
        return {"source": "shodan", "error": "API key not configured"}

    try:
        # Resolve domain to IP if needed
        ip = _resolve_to_ip(target)

        resp = _SESSION.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": api_key},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        services = []
        for item in data.get("data", [])[:10]:
            services.append(
                {
                    "port": item.get("port"),
                    "transport": item.get("transport"),
                    "product": item.get("product", "unknown"),
                    "version": item.get("version"),
                    "banner": (item.get("data", "") or "")[:200],
                    "cpe": item.get("cpe", []),
                }
            )

        return {
            "source": "shodan",
            "ip": data.get("ip_str"),
            "hostnames": data.get("hostnames", []),
            "os": data.get("os"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "asn": data.get("asn"),
            "ports": data.get("ports", []),
            "vulns": data.get("vulns", [])[:20],
            "services": services,
            "city": data.get("city"),
            "country_name": data.get("country_name"),
            "last_update": data.get("last_update"),
        }
    except requests.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            return {
                "source": "shodan",
                "data": {},
                "note": "No Shodan data for this host",
            }
        return {"source": "shodan", "error": _http_error_msg(e)}
    except Exception as e:
        return {"source": "shodan", "error": str(e)}


# ─── ALIENVAULT OTX ──────────────────────────────────────────────────────


@_timed
def query_otx(target: str, query_type: str = "domain") -> dict:
    """Query AlienVault OTX for threat intelligence pulses."""
    settings = get_settings()
    api_key = settings.otx_api_key.get_secret_value()
    headers = {"X-OTX-API-KEY": api_key} if api_key else {}
    base = "https://otx.alienvault.com/api/v1"
    section = "IPv4" if query_type == "ip" else "domain"
    _timeout = _OTX_TIMEOUT

    def _get(endpoint, hdrs=None):
        try:
            r = _SESSION.get(
                f"{base}/indicators/{section}/{target}/{endpoint}",
                headers=hdrs if hdrs is not None else headers,
                timeout=_timeout,
            )
            return r.json() if r.ok else {}
        except Exception:
            return {}

    try:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=3) as pool:
            f_general = pool.submit(_get, "general")
            f_dns = pool.submit(_get, "passive_dns")
            f_mal = pool.submit(_get, "malware")
            general = f_general.result()
            dns_data = f_dns.result()
            mal_data = f_mal.result()

        # Key rejected/stale or no key configured — retry anonymously
        if not general and api_key:
            logger.warning("OTX key rejected or timed out; retrying anonymously")
            with ThreadPoolExecutor(max_workers=3) as pool:
                f_general = pool.submit(_get, "general", {})
                f_dns = pool.submit(_get, "passive_dns", {})
                f_mal = pool.submit(_get, "malware", {})
                general = f_general.result()
                dns_data = f_dns.result()
                mal_data = f_mal.result()

        if not general:
            return {"source": "alienvault_otx", "error": "No response from OTX"}

        pulses = general.get("pulse_info", {})
        return {
            "source": "alienvault_otx",
            "pulse_count": pulses.get("count", 0),
            "pulses": [
                {
                    "name": p.get("name"),
                    "description": (p.get("description") or "")[:200],
                    "created": p.get("created"),
                    "tags": p.get("tags", [])[:10],
                    "adversary": p.get("adversary"),
                    "targeted_countries": p.get("targeted_countries", []),
                }
                for p in pulses.get("pulses", [])[:5]
            ],
            "passive_dns_count": len(dns_data.get("passive_dns", [])),
            "passive_dns": [
                {
                    "hostname": r.get("hostname"),
                    "address": r.get("address"),
                    "record_type": r.get("record_type"),
                    "first_seen": r.get("first"),
                    "last_seen": r.get("last"),
                }
                for r in dns_data.get("passive_dns", [])[:10]
            ],
            "malware_samples": len(mal_data.get("data", [])),
            "malware": [
                {"hash": m.get("hash"), "detections": m.get("detections")}
                for m in mal_data.get("data", [])[:5]
            ],
            "reputation": general.get("reputation", 0),
            "sections": general.get("sections", []),
        }
    except Exception as e:
        return {"source": "alienvault_otx", "error": str(e)}


# ─── IPINFO ──────────────────────────────────────────────────────────────


@_timed
def query_ipinfo(target: str) -> dict:
    """Query IPinfo for geolocation, ASN, and org data."""
    settings = get_settings()
    token = settings.ipinfo_token.get_secret_value()
    if not token:
        return {"source": "ipinfo", "error": "API token not configured"}

    try:
        # Resolve domain to IP if needed
        ip = _resolve_to_ip(target)

        resp = _SESSION.get(
            f"https://ipinfo.io/{ip}",
            params={"token": token},
            headers={"Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        return {
            "source": "ipinfo",
            "ip": data.get("ip"),
            "hostname": data.get("hostname"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "loc": data.get("loc"),
            "org": data.get("org"),
            "postal": data.get("postal"),
            "timezone": data.get("timezone"),
            "asn": data.get("asn", {}),
            "company": data.get("company", {}),
            "privacy": data.get("privacy", {}),
        }
    except Exception as e:
        return {"source": "ipinfo", "error": str(e)}


# ─── DNS RESOLUTION (bonus utility) ─────────────────────────────────────


@_timed
def query_dns(target: str) -> dict:
    """Basic DNS resolution as a supplementary data source."""
    import socket

    try:
        results = socket.getaddrinfo(target, None)
        ips = list(set(r[4][0] for r in results))
        return {
            "source": "dns_resolution",
            "resolved_ips": ips,
            "hostname": target,
        }
    except Exception as e:
        return {"source": "dns_resolution", "error": str(e)}


# ─── GREYNOISE COMMUNITY ─────────────────────────────────────────────────


@_timed
def query_greynoise(target: str) -> dict:
    """Query GreyNoise Community API — tells you if an IP is a known internet scanner.

    The Community API is free and unauthenticated.
    Docs: https://docs.greynoise.io/docs/using-the-greynoise-community-api
    """
    try:
        ip = _resolve_to_ip(target)
        resp = _SESSION.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            return {
                "source": "greynoise",
                "ip": ip,
                "classification": "unknown",
                "note": "Not observed by GreyNoise",
            }
        resp.raise_for_status()
        data = resp.json()
        return {
            "source": "greynoise",
            "ip": data.get("ip"),
            "noise": data.get("noise"),
            "riot": data.get("riot"),
            "classification": data.get("classification"),
            "name": data.get("name"),
            "link": data.get("link"),
            "last_seen": data.get("last_seen"),
            "message": data.get("message"),
        }
    except requests.HTTPError as e:
        return {"source": "greynoise", "error": _http_error_msg(e)}
    except Exception as e:
        return {"source": "greynoise", "error": str(e)}


# ─── URLSCAN.IO ──────────────────────────────────────────────────────────


@_timed
def query_urlscan(target: str, query_type: str = "domain") -> dict:
    """Search urlscan.io for existing scans of a domain/IP/URL (no submission — fast path)."""
    settings = get_settings()
    api_key = settings.urlscan_api_key.get_secret_value()
    if not api_key:
        return {"source": "urlscan", "error": "API key not configured"}

    # Build a search query matching the indicator type
    if query_type == "ip":
        q = f"ip:{target}"
    elif query_type == "url":
        q = f'page.url:"{target}"'
    else:
        q = f"domain:{target}"

    try:
        resp = _SESSION.get(
            "https://urlscan.io/api/v1/search/",
            headers={"API-Key": api_key},
            params={"q": q, "size": 5},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results", []) or []

        if not results:
            return {
                "source": "urlscan",
                "total_results": 0,
                "note": "No prior scans",
            }

        normalized = []
        for r in results[:5]:
            task = r.get("task", {}) or {}
            page = r.get("page", {}) or {}
            verdicts = (r.get("verdicts", {}) or {}).get("overall", {}) or {}
            normalized.append(
                {
                    "time": task.get("time"),
                    "task_url": task.get("url"),
                    "domain": page.get("domain"),
                    "ip": page.get("ip"),
                    "server": page.get("server"),
                    "malicious": verdicts.get("malicious"),
                    "score": verdicts.get("score"),
                    "result_url": r.get("result"),
                    "screenshot": r.get("screenshot"),
                }
            )

        return {
            "source": "urlscan",
            "total_results": data.get("total", len(results)),
            "results": normalized,
        }
    except requests.HTTPError as e:
        return {"source": "urlscan", "error": _http_error_msg(e)}
    except Exception as e:
        return {"source": "urlscan", "error": str(e)}


# ─── HYBRID ANALYSIS (hash-lookup only) ──────────────────────────────────


@_timed
def query_hybrid_analysis(hash_value: str) -> dict:
    """Look up a file hash in Hybrid Analysis (Falcon Sandbox). No submissions."""
    settings = get_settings()
    api_key = settings.hybrid_analysis_api_key.get_secret_value()
    if not api_key:
        return {"source": "hybrid_analysis", "error": "API key not configured"}

    try:
        resp = _SESSION.post(
            "https://www.hybrid-analysis.com/api/v2/search/hash",
            headers={
                "api-key": api_key,
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Falcon Sandbox",
                "accept": "application/json",
            },
            data={"hash": hash_value},
            timeout=_HYBRID_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()

        if not data:
            return {
                "source": "hybrid_analysis",
                "note": "Hash not found in Hybrid Analysis",
            }

        normalized = []
        for item in data[:3]:
            normalized.append(
                {
                    "sha256": item.get("sha256"),
                    "verdict": item.get("verdict"),
                    "threat_score": item.get("threat_score"),
                    "vx_family": item.get("vx_family"),
                    "type_short": item.get("type_short"),
                    "av_detect": item.get("av_detect"),
                    "analysis_start_time": item.get("analysis_start_time"),
                    "domains": (item.get("domains") or [])[:10],
                    "hosts": (item.get("hosts") or [])[:10],
                }
            )

        return {
            "source": "hybrid_analysis",
            "result_count": len(data),
            "results": normalized,
        }
    except requests.HTTPError as e:
        return {"source": "hybrid_analysis", "error": _http_error_msg(e)}
    except Exception as e:
        return {"source": "hybrid_analysis", "error": str(e)}


# ─── RDAP (via ipwhois — handles all 5 RIRs) ─────────────────────────────


@_timed
def query_rdap(target: str) -> dict:
    """Query RDAP via ipwhois — returns ASN, CIDR, network owner, abuse contacts. Covers all RIRs."""
    try:
        from ipwhois import IPWhois

        ip = _resolve_to_ip(target)
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)

        # Flatten entities into a compact list
        entities = []
        objects = result.get("objects", {}) or {}
        for handle, obj_data in list(objects.items())[:5]:
            contact = obj_data.get("contact", {}) or {}
            emails = contact.get("email", []) or []
            abuse_emails = [e.get("value") for e in emails if e.get("value")]
            entities.append(
                {
                    "handle": handle,
                    "name": contact.get("name"),
                    "roles": obj_data.get("roles", []),
                    "emails": abuse_emails[:3],
                }
            )

        network = result.get("network", {}) or {}
        return {
            "source": "rdap",
            "ip": ip,
            "asn": result.get("asn"),
            "asn_cidr": result.get("asn_cidr"),
            "asn_country_code": result.get("asn_country_code"),
            "asn_description": result.get("asn_description"),
            "asn_registry": result.get("asn_registry"),
            "network_name": network.get("name"),
            "network_cidr": network.get("cidr"),
            "network_country": network.get("country"),
            "network_handle": network.get("handle"),
            "entities": entities,
        }
    except Exception as e:
        return {"source": "rdap", "error": str(e)}


# ─── CIRCL CVE / Vulnerability-Lookup ────────────────────────────────────


@_timed
def query_circl_cve(cve_id: str) -> dict:
    """Look up a CVE by ID via CIRCL's Vulnerability-Lookup. No auth required."""
    try:
        resp = _SESSION.get(
            f"https://vulnerability.circl.lu/api/cve/{cve_id}",
            headers={"Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 404:
            return {"source": "circl_cve", "id": cve_id, "note": "CVE not found"}
        resp.raise_for_status()
        data = resp.json() or {}

        return {
            "source": "circl_cve",
            "id": data.get("id") or cve_id,
            "summary": (data.get("summary") or "")[:500],
            "published": data.get("Published"),
            "modified": data.get("Modified"),
            "cvss": data.get("cvss"),
            "cvss_vector": data.get("cvss-vector"),
            "access": data.get("access"),
            "impact": data.get("impact"),
            "references": (data.get("references") or [])[:10],
            "vulnerable_products": (data.get("vulnerable_product") or [])[:20],
        }
    except requests.HTTPError as e:
        return {"source": "circl_cve", "error": _http_error_msg(e)}
    except Exception as e:
        return {"source": "circl_cve", "error": str(e)}


# ─── THREATFOX (abuse.ch) ────────────────────────────────────────────────


@_timed
def query_threatfox(target: str, query_type: str = "domain") -> dict:
    """Search ThreatFox for an IOC (IP, domain, URL, or hash)."""
    settings = get_settings()
    auth_key = settings.abusech_auth_key.get_secret_value()
    if not auth_key:
        return {"source": "threatfox", "error": "API key not configured"}

    if query_type == "hash":
        payload = {"query": "search_hash", "hash": target}
    else:
        payload = {"query": "search_ioc", "search_term": target}

    try:
        resp = _SESSION.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": auth_key},
            json=payload,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json() or {}
        query_status = data.get("query_status")
        raw_matches = data.get("data") or []

        if query_status != "ok" or not raw_matches:
            return {
                "source": "threatfox",
                "query_status": query_status,
                "matches": [],
                "note": "No matches" if query_status == "no_result" else query_status,
            }

        matches = []
        for m in raw_matches[:5]:
            matches.append(
                {
                    "ioc": m.get("ioc"),
                    "ioc_type": m.get("ioc_type"),
                    "threat_type": m.get("threat_type"),
                    "malware": m.get("malware"),
                    "malware_alias": m.get("malware_alias"),
                    "confidence_level": m.get("confidence_level"),
                    "first_seen": m.get("first_seen"),
                    "last_seen": m.get("last_seen"),
                    "tags": (m.get("tags") or [])[:10],
                    "reference": m.get("reference"),
                }
            )

        return {
            "source": "threatfox",
            "query_status": query_status,
            "match_count": len(raw_matches),
            "matches": matches,
        }
    except requests.HTTPError as e:
        return {"source": "threatfox", "error": _http_error_msg(e)}
    except Exception as e:
        return {"source": "threatfox", "error": str(e)}


# ─── URLHAUS (abuse.ch) ──────────────────────────────────────────────────


@_timed
def query_urlhaus(target: str, query_type: str = "domain") -> dict:
    """Query URLhaus for malware URLs by URL, host (IP/domain), or payload hash."""
    settings = get_settings()
    auth_key = settings.abusech_auth_key.get_secret_value()
    if not auth_key:
        return {"source": "urlhaus", "error": "API key not configured"}

    if query_type == "url":
        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        body = {"url": target}
    elif query_type == "hash":
        # Detect hash length for correct field name
        field = "sha256_hash" if len(target) == 64 else "md5_hash"
        endpoint = "https://urlhaus-api.abuse.ch/v1/payload/"
        body = {field: target}
    else:  # ip or domain
        endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
        body = {"host": target}

    try:
        resp = _SESSION.post(
            endpoint,
            headers={"Auth-Key": auth_key},
            data=body,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json() or {}
        status = data.get("query_status")

        if status != "ok":
            return {
                "source": "urlhaus",
                "query_status": status,
                "note": "No matches" if status == "no_results" else status,
            }

        result: dict = {"source": "urlhaus", "query_status": status}

        if query_type == "url":
            result.update(
                {
                    "url_status": data.get("url_status"),
                    "threat": data.get("threat"),
                    "tags": (data.get("tags") or [])[:10],
                    "date_added": data.get("date_added"),
                    "last_online": data.get("last_online"),
                    "payloads": [
                        {
                            "filename": p.get("filename"),
                            "file_type": p.get("file_type"),
                            "signature": p.get("signature"),
                            "sha256": p.get("response_sha256"),
                        }
                        for p in (data.get("payloads") or [])[:5]
                    ],
                }
            )
        elif query_type == "hash":
            result.update(
                {
                    "file_type": data.get("file_type"),
                    "file_size": data.get("file_size"),
                    "signature": data.get("signature"),
                    "sha256_hash": data.get("sha256_hash"),
                    "md5_hash": data.get("md5_hash"),
                    "first_seen": data.get("first_seen"),
                    "url_count": data.get("url_count"),
                }
            )
        else:
            urls_raw = data.get("urls") or []
            result.update(
                {
                    "urls_online": sum(
                        1 for u in urls_raw if u.get("url_status") == "online"
                    ),
                    "url_count": len(urls_raw),
                    "urls": [
                        {
                            "url": u.get("url"),
                            "url_status": u.get("url_status"),
                            "threat": u.get("threat"),
                            "tags": (u.get("tags") or [])[:5],
                            "date_added": u.get("date_added"),
                        }
                        for u in urls_raw[:5]
                    ],
                    "blacklists": data.get("blacklists", {}),
                }
            )

        return result
    except requests.HTTPError as e:
        return {"source": "urlhaus", "error": _http_error_msg(e)}
    except Exception as e:
        return {"source": "urlhaus", "error": str(e)}


# ─── MALWAREBAZAAR (abuse.ch) ────────────────────────────────────────────


@_timed
def query_malwarebazaar(hash_value: str) -> dict:
    """Look up a malware sample in MalwareBazaar by hash."""
    settings = get_settings()
    auth_key = settings.abusech_auth_key.get_secret_value()
    if not auth_key:
        return {"source": "malwarebazaar", "error": "API key not configured"}

    try:
        resp = _SESSION.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={"Auth-Key": auth_key},
            data={"query": "get_info", "hash": hash_value},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json() or {}
        status = data.get("query_status")

        if status != "ok":
            return {
                "source": "malwarebazaar",
                "query_status": status,
                "note": "Hash not found" if status == "hash_not_found" else status,
            }

        samples = []
        for s in (data.get("data") or [])[:3]:
            intel = s.get("intelligence", {}) or {}
            samples.append(
                {
                    "sha256_hash": s.get("sha256_hash"),
                    "md5_hash": s.get("md5_hash"),
                    "sha1_hash": s.get("sha1_hash"),
                    "file_type": s.get("file_type"),
                    "file_size": s.get("file_size"),
                    "signature": s.get("signature"),
                    "tags": (s.get("tags") or [])[:10],
                    "first_seen": s.get("first_seen"),
                    "last_seen": s.get("last_seen"),
                    "delivery_method": s.get("delivery_method"),
                    "origin_country": s.get("origin_country"),
                    "downloads": intel.get("downloads"),
                    "uploads": intel.get("uploads"),
                }
            )

        return {
            "source": "malwarebazaar",
            "query_status": status,
            "samples": samples,
        }
    except requests.HTTPError as e:
        return {"source": "malwarebazaar", "error": _http_error_msg(e)}
    except Exception as e:
        return {"source": "malwarebazaar", "error": str(e)}


# ─── PULSEDIVE ───────────────────────────────────────────────────────────


@_timed
def query_pulsedive(target: str) -> dict:
    """Query Pulsedive for threat-intel enrichment on an IP, domain, URL, or hash."""
    settings = get_settings()
    api_key = (
        settings.pulsedive_api_key.get_secret_value()
    )  # optional — higher rate limits with key

    params: dict = {"indicator": target, "pretty": "0"}
    if api_key:
        params["key"] = api_key

    try:
        resp = _SESSION.get(
            "https://pulsedive.com/api/info.php",
            params=params,
            timeout=_TIMEOUT,
        )
        # Key rejected — retry anonymously (Pulsedive supports unauthenticated calls)
        if resp.status_code == 401 and api_key:
            logger.warning("Pulsedive API key rejected (401); retrying anonymously")
            params.pop("key", None)
            resp = _SESSION.get(
                "https://pulsedive.com/api/info.php",
                params=params,
                timeout=_TIMEOUT,
            )
        if resp.status_code == 404:
            return {"source": "pulsedive", "note": "Indicator not in Pulsedive"}
        resp.raise_for_status()
        data = resp.json() or {}

        if data.get("error"):
            return {"source": "pulsedive", "note": data.get("error")}

        attributes = data.get("attributes", {}) or {}
        return {
            "source": "pulsedive",
            "indicator": data.get("indicator"),
            "type": data.get("type"),
            "risk": data.get("risk"),
            "risk_recommended": data.get("risk_recommended"),
            "summary": data.get("summary", {}),
            "threats": [
                {
                    "name": t.get("name"),
                    "category": t.get("category"),
                    "risk": t.get("risk"),
                }
                for t in (data.get("threats") or [])[:5]
            ],
            "feeds": [
                {"name": f.get("name"), "category": f.get("category")}
                for f in (data.get("feeds") or [])[:5]
            ],
            "ports": (attributes.get("port") or [])[:10],
            "protocols": (attributes.get("protocol") or [])[:10],
        }
    except requests.HTTPError as e:
        return {"source": "pulsedive", "error": _http_error_msg(e)}
    except Exception as e:
        return {"source": "pulsedive", "error": str(e)}


# ─── CVE MCP SERVER ──────────────────────────────────────────────────────────


@_timed
def query_cve_mcp(cve_id: str) -> dict:
    """Enrich a CVE using cve-mcp-server via the get_cve_summary tool.

    Single call that fetches NVD + EPSS concurrently and includes CISA KEV
    status. Returns a pre-formatted summary string ready for LLM synthesis.
    Returns {"error": "disabled"} when integration is off so _trim_for_llm
    discards it cleanly without penalising the scan.
    """
    settings = get_settings()
    if not settings.cve_mcp_enabled:
        return {"source": "cve_mcp", "error": "disabled"}

    out: dict = {"source": "cve_mcp", "cve_id": cve_id}

    result = call_cve_mcp_tool("get_cve_summary", {"cve_id": cve_id})
    if result["ok"]:
        r = result["result"]
        # Server returns a formatted string; client wraps it as {"text": "..."}
        text = r.get("text", "") if isinstance(r, dict) else str(r)
        out["summary"] = text[:2000]
    else:
        out["error"] = result["error"]

    return out
