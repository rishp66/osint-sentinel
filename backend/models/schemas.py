import ipaddress
import urllib.parse

from pydantic import BaseModel, Field, field_validator
from typing import Any


# Private / reserved networks that must never be scanned (SSRF defense)
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),  # RFC1918
    ipaddress.ip_network("172.16.0.0/12"),  # RFC1918
    ipaddress.ip_network("192.168.0.0/16"),  # RFC1918
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network(
        "169.254.0.0/16"
    ),  # Link-local (includes cloud metadata 169.254.169.254)
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    ipaddress.ip_network("0.0.0.0/8"),  # "This" network
    ipaddress.ip_network("100.64.0.0/10"),  # Shared address space (CGN)
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]


def is_blocked_ip(ip_str: str) -> bool:
    """Return True if the IP falls in a private/reserved/link-local range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in net for net in _BLOCKED_NETWORKS)


# NOTE: DNS-rebinding SSRF protection (resolving a hostname and blocking
# private/reserved addresses) lives in agents/crew.py:run_scan, which runs
# inside asyncio.to_thread. Doing it here would issue blocking getaddrinfo
# calls on the FastAPI event loop (CLAUDE.md §14 violation).


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=2048)

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        t = v.strip()
        if not t:
            raise ValueError("Target must not be empty.")

        # Check if target is a direct IP
        try:
            ipaddress.ip_address(t)
            if is_blocked_ip(t):
                raise ValueError(
                    f"Target IP {t} is in a private/reserved range and cannot be scanned."
                )
            return t
        except ValueError as e:
            if "private/reserved" in str(e):
                raise
            # Not an IP — continue checking other formats

        # Check URL targets — only literal-IP host check here.
        # DNS-resolution SSRF check happens in crew.py off the event loop.
        if t.startswith(("http://", "https://")):
            parsed = urllib.parse.urlparse(t)
            if parsed.scheme not in ("http", "https"):
                raise ValueError("Only http:// and https:// URL schemes are allowed.")
            host = parsed.hostname
            if host and is_blocked_ip(host):
                raise ValueError(
                    f"URL host {host} is in a private/reserved range and cannot be scanned."
                )
            return t
        elif "://" in t:
            raise ValueError("Only http:// and https:// URL schemes are allowed.")

        return t


class ScanResponse(BaseModel):
    target: str
    risk_score: int  # 0-100
    risk_level: str  # LOW / MEDIUM / HIGH / CRITICAL
    threat_brief: str  # LLM-synthesized summary
    sources: list[dict[str, Any]]
    scan_duration_ms: float
    agent_report: str = ""  # Full markdown report from the analyst agent
    indicator_type: str = ""  # ip / domain / url / hash / cve
