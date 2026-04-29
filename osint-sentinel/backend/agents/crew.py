"""Orchestrates parallel OSINT queries then synthesizes results with the LLM."""

import re
import time
import ipaddress
import socket
import threading
import urllib.parse
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from typing import Callable

from tools.osint_sources import (
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
from tools.llm_client import synthesize
from tools.agent_report import generate_report


# Bounded LRU cache: evicts the oldest entry once _CACHE_MAX is exceeded so a
# steady stream of unique targets cannot grow memory without bound. Reads also
# enforce a TTL window before returning a cached result.
_CACHE: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()
_CACHE_LOCK = threading.Lock()
_CACHE_TTL = 300   # seconds — matches CACHE_TTL_SECONDS in .env
_CACHE_MAX = 512   # hard ceiling on number of cached targets

_HASH_RE = re.compile(r"^[a-fA-F0-9]+$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
# A domain label is 1-63 chars, alnum or hyphen, can't start/end with hyphen.
# A valid domain has at least one dot and a TLD of >=2 letters.
_DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


class InvalidTargetError(ValueError):
    """Raised when a user-supplied target fails validation."""


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def validate_target(target: str) -> str:
    """Reject obvious garbage before we spend the OSINT budget on it.

    Returns the normalized target. Raises InvalidTargetError with a user-facing
    message on failure.
    """
    if not target or not target.strip():
        raise InvalidTargetError("Target is empty.")
    t = target.strip()

    # Reject anything with whitespace inside.
    if any(ch.isspace() for ch in t):
        raise InvalidTargetError("Target may not contain spaces.")

    # CVE
    if _CVE_RE.match(t):
        return t.upper()

    # URL — must have a host that itself is a valid domain or IP
    if t.startswith(("http://", "https://")):
        try:
            host = urllib.parse.urlparse(t).hostname or ""
        except Exception:
            raise InvalidTargetError("URL is malformed.")
        if not host:
            raise InvalidTargetError("URL is missing a host.")
        if not (_is_ip(host) or _DOMAIN_RE.match(host)):
            raise InvalidTargetError(f"URL host '{host}' is not a valid domain or IP.")
        return t

    # IP
    if _is_ip(t):
        return t

    # Hash — must be hex AND a known length (md5/sha1/sha256)
    if _HASH_RE.match(t):
        if len(t) in (32, 40, 64):
            return t.lower()
        raise InvalidTargetError(
            f"Hex string is {len(t)} chars — expected 32 (MD5), 40 (SHA-1), or 64 (SHA-256)."
        )

    # Bare number → not a valid target on its own
    if t.replace(".", "").isdigit():
        raise InvalidTargetError("Numeric input is not a valid IP, domain, or hash.")

    # Otherwise, must look like a domain
    if len(t) < 4:
        raise InvalidTargetError("Target is too short to be a valid domain or IP.")
    if "." not in t:
        raise InvalidTargetError("Domain must contain at least one dot (e.g. example.com).")
    if not _DOMAIN_RE.match(t):
        raise InvalidTargetError(
            "Target does not look like a valid domain, IP, URL, file hash, or CVE ID."
        )
    return t.lower()


def _detect_type(target: str) -> str:
    """Classify an indicator as ip / domain / url / hash / cve."""
    t = target.strip()
    if _CVE_RE.match(t):
        return "cve"
    if t.startswith(("http://", "https://")):
        return "url"
    if _is_ip(t):
        return "ip"
    if _HASH_RE.match(t) and len(t) in (32, 40, 64):  # md5, sha1, sha256
        return "hash"
    return "domain"


def _resolve(target: str) -> str:
    """Resolve domain to IP once; return target unchanged if already an IP."""
    if _is_ip(target):
        return target
    try:
        return socket.gethostbyname(target)
    except Exception:
        return target


def _trim_for_llm(sources: list[dict]) -> list[dict]:
    """Return a leaner copy — strip timing metadata and verbose fields the LLM doesn't need.

    Reduces token count by ~40%, which directly speeds up LLM inference.
    Error sources are dropped entirely since they carry no signal.
    """
    trimmed = []
    for src in sources:
        if src.get("error"):
            continue  # no signal in failed sources
        s = {k: v for k, v in src.items() if k != "_query_time_ms"}
        name = s.get("source", "")
        if name == "virustotal":
            s.pop("detection_stats", None)
            s.pop("last_dns_records", None)
            s.pop("popularity_ranks", None)
        elif name == "alienvault_otx":
            s["passive_dns"] = s.get("passive_dns", [])[:5]
            s["pulses"] = s.get("pulses", [])[:3]
            s.pop("sections", None)
        elif name == "abuseipdb":
            s["recent_reports"] = s.get("recent_reports", [])[:3]
        elif name == "shodan":
            s["services"] = s.get("services", [])[:5]
        elif name == "whois":
            s.pop("domain_name", None)
            s.pop("emails", None)
            s.pop("status", None)
        elif name == "dns_resolution":
            continue
        elif name == "urlscan":
            results = s.get("results", []) or []
            for r in results:
                r.pop("screenshot", None)  # URL only, no value as text
            s["results"] = results[:3]
        elif name == "threatfox":
            s["matches"] = s.get("matches", [])[:3]
        elif name == "urlhaus":
            s["urls"] = s.get("urls", [])[:3]
        elif name == "malwarebazaar":
            s["samples"] = s.get("samples", [])[:2]
        elif name == "hybrid_analysis":
            s["results"] = s.get("results", [])[:2]
        elif name == "pulsedive":
            s["threats"] = s.get("threats", [])[:3]
            s["feeds"] = s.get("feeds", [])[:3]
        elif name == "rdap":
            s["entities"] = s.get("entities", [])[:3]
        elif name == "circl_cve":
            s["references"] = s.get("references", [])[:5]
            s["vulnerable_products"] = s.get("vulnerable_products", [])[:10]
        trimmed.append(s)
    return trimmed


def _build_tasks(target: str, indicator_type: str) -> dict[str, Callable[[], dict]]:
    """Map an indicator + its type to the OSINT source queries that apply."""
    tasks: dict[str, Callable[[], dict]] = {}

    # ── CVE — only CIRCL applies ─────────────────────────────────────────
    if indicator_type == "cve":
        tasks["circl_cve"] = lambda: query_circl_cve(target)
        return tasks

    # ── HASH — file-oriented sources only ────────────────────────────────
    if indicator_type == "hash":
        tasks["virustotal"]      = lambda: query_virustotal(target, query_type="file")
        tasks["hybrid_analysis"] = lambda: query_hybrid_analysis(target)
        tasks["malwarebazaar"]   = lambda: query_malwarebazaar(target)
        tasks["threatfox"]       = lambda: query_threatfox(target, query_type="hash")
        tasks["urlhaus"]         = lambda: query_urlhaus(target, query_type="hash")
        tasks["pulsedive"]       = lambda: query_pulsedive(target)
        return tasks

    # ── IP / DOMAIN / URL — derive host + resolved IP for host-based sources
    if indicator_type == "url":
        host = urllib.parse.urlparse(target).hostname or target
    else:
        host = target

    host_is_ip = _is_ip(host)
    resolved_ip = host if host_is_ip else _resolve(host)
    host_qtype = "ip" if host_is_ip else "domain"

    # Existing sources
    tasks["virustotal"] = lambda: query_virustotal(host, query_type=host_qtype)
    tasks["otx"]        = lambda: query_otx(host, query_type=host_qtype)
    tasks["abuseipdb"]  = lambda: query_abuseipdb(resolved_ip)
    tasks["shodan"]     = lambda: query_shodan(resolved_ip)
    tasks["ipinfo"]     = lambda: query_ipinfo(resolved_ip)
    tasks["dns"]        = lambda: query_dns(host)
    if not host_is_ip:
        tasks["whois"] = lambda: query_whois(host)

    # New sources applicable to IP/domain/URL
    tasks["urlscan"]     = lambda: query_urlscan(target, query_type=indicator_type)
    tasks["threatfox"]   = lambda: query_threatfox(target, query_type=indicator_type)
    tasks["urlhaus"]     = lambda: query_urlhaus(target, query_type=indicator_type)
    tasks["pulsedive"]   = lambda: query_pulsedive(target)

    # IP-oriented sources — fire whenever we have a usable IP (direct or resolved)
    if _is_ip(resolved_ip):
        tasks["greynoise"] = lambda: query_greynoise(resolved_ip)
        tasks["rdap"]      = lambda: query_rdap(resolved_ip)

    return tasks


def run_scan(target: str) -> dict:
    """Run all OSINT sources in parallel, then synthesize. Returns ScanResponse-compatible dict.

    Raises InvalidTargetError on garbage input — caller should map to HTTP 422.
    """
    target = validate_target(target)

    # ── Cache check ───────────────────────────────────────────────────────
    with _CACHE_LOCK:
        cached = _CACHE.get(target)
        if cached and time.time() - cached[0] < _CACHE_TTL:
            _CACHE.move_to_end(target)
            return cached[1]
        if cached:
            # Stale entry — drop it so we don't keep a dead reference around.
            _CACHE.pop(target, None)

    indicator_type = _detect_type(target)
    tasks = _build_tasks(target, indicator_type)

    t_start = time.time()
    sources: list[dict] = []

    # Manual lifecycle management: a `with` block on ThreadPoolExecutor blocks
    # on shutdown until every running task finishes, which would defeat the
    # 18 s ceiling whenever an upstream source hangs. Using shutdown(wait=False,
    # cancel_futures=True) lets us return immediately while abandoning slow
    # workers (their per-request timeouts still bound thread lifetime).
    pool = ThreadPoolExecutor(
        max_workers=max(len(tasks), 1),
        thread_name_prefix="osint-source",
    )
    try:
        futures = {pool.submit(fn): name for name, fn in tasks.items()}
        try:
            # 18 s global ceiling — well under the previous 25 s budget so the
            # frontend feels more responsive when one source is slow.
            for future in as_completed(futures, timeout=18):
                try:
                    sources.append(future.result())
                except Exception as exc:
                    name = futures[future]
                    sources.append({"source": name, "error": str(exc)})
        except FuturesTimeoutError:
            # Collect finished results; mark any still-running source as timed out
            done = {f for f in futures if f.done()}
            for f, name in futures.items():
                if f not in done:
                    sources.append({"source": name, "error": "timeout"})
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    # ── Trim before LLM — fewer tokens = faster inference ─────────────────
    llm_sources = _trim_for_llm(sources)

    with ThreadPoolExecutor(max_workers=2) as llm_pool:
        f_synth  = llm_pool.submit(synthesize,      target, llm_sources)
        f_report = llm_pool.submit(generate_report, target, llm_sources)
        try:
            synthesis = f_synth.result(timeout=35)
        except Exception:
            synthesis = {
                "threat_brief": "LLM synthesis unavailable — intelligence data collected above.",
                "risk_score": 0,
                "risk_level": "UNKNOWN",
            }
        try:
            agent_report = f_report.result(timeout=45)
        except Exception:
            agent_report = "_Agent report unavailable — LLM did not respond in time._"

    scan_duration_ms = round((time.time() - t_start) * 1000, 2)

    result = {
        "target": target,
        "risk_score": synthesis["risk_score"],
        "risk_level": synthesis["risk_level"],
        "threat_brief": synthesis["threat_brief"],
        "sources": sources,
        "scan_duration_ms": scan_duration_ms,
        "agent_report": agent_report,
        "indicator_type": indicator_type,
    }

    with _CACHE_LOCK:
        _CACHE[target] = (time.time(), result)
        _CACHE.move_to_end(target)
        while len(_CACHE) > _CACHE_MAX:
            _CACHE.popitem(last=False)
    return result
