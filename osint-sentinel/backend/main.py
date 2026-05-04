import asyncio
import logging
import secrets
import threading
import time
from collections import OrderedDict
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from models.schemas import ScanRequest, ScanResponse
from agents.crew import run_scan, InvalidTargetError
from config.settings import Settings, get_settings

logger = logging.getLogger("osint_sentinel")

# ── In-memory rate limiter (per-IP, 10 req/min) ───────────────────────────
# OrderedDict + cap prevents unbounded memory growth from one-off client IPs.
_RATE_WINDOW = 60  # seconds
_RATE_MAX = 10  # requests per window
_RATE_BUCKET_MAX = 4096  # ceiling on tracked client IPs
_rate_hits: "OrderedDict[str, list[float]]" = OrderedDict()
_rate_lock = threading.Lock()


def _client_ip(request: Request) -> str:
    """Return the originating client IP, honoring trusted proxy headers
    (X-Forwarded-For, X-Real-IP) only when explicitly enabled in settings.

    Without this, deployments behind a proxy/load balancer would see every
    request as coming from the proxy's socket address and either bucket all
    users into one rate-limit window or trust spoofable headers by default.
    """
    settings = get_settings()
    if settings.trust_proxy_headers:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            # Leftmost entry is the original client (per RFC 7239 convention).
            ip = xff.split(",")[0].strip()
            if ip:
                return ip
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
    return request.client.host if request.client else "unknown"


def _is_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    with _rate_lock:
        hits = _rate_hits.get(ip, [])
        hits = [t for t in hits if now - t < _RATE_WINDOW]
        if len(hits) >= _RATE_MAX:
            _rate_hits[ip] = hits
            _rate_hits.move_to_end(ip)
            return True
        hits.append(now)
        _rate_hits[ip] = hits
        _rate_hits.move_to_end(ip)
        while len(_rate_hits) > _RATE_BUCKET_MAX:
            _rate_hits.popitem(last=False)
        return False


def _cors_allow_origins(settings: Settings) -> list[str]:
    """Never use wildcard origins — even in DEBUG — to avoid permissive CORS."""
    configured = settings.cors_origin_list()
    if configured:
        return configured
    if not settings.debug:
        logger.warning(
            "CORS_ORIGINS is not set and DEBUG=false. "
            "No browser origins will be permitted. Set CORS_ORIGINS in production."
        )
        return []
    return [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:4173",
        "http://localhost:4173",
    ]


def require_api_key_if_configured(request: Request) -> None:
    """When API_KEY is set in the environment, require Bearer or X-API-Key."""
    settings = get_settings()
    expected = settings.api_key.get_secret_value()
    if not expected:
        return
    auth = request.headers.get("Authorization") or ""
    x_key = request.headers.get("X-API-Key") or ""
    token = ""
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
    elif x_key:
        token = x_key.strip()
    if not token or not secrets.compare_digest(token, expected):
        client_ip = request.client.host if request.client else "unknown"
        logger.warning("auth failure: ip=%s path=%s", client_ip, request.url.path)
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


# ── Startup validation ─────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings = get_settings()

    provider = settings.llm_provider.lower()
    _key_checks: dict[str, bool] = {
        "ollama": True,  # no key needed for local Ollama
        "groq": bool(settings.groq_api_key.get_secret_value()),
        "anthropic": bool(settings.anthropic_api_key.get_secret_value()),
        "lightning": bool(settings.lightning_api_key.get_secret_value()),
    }
    if provider not in _key_checks:
        raise RuntimeError(
            f"Unknown LLM_PROVIDER={provider!r}. "
            "Expected: ollama, groq, anthropic, lightning."
        )
    if not _key_checks[provider]:
        raise RuntimeError(
            f"LLM_PROVIDER={provider} but the required API key is not set."
        )

    optional_keys = {
        "VirusTotal": settings.virustotal_api_key.get_secret_value(),
        "AbuseIPDB": settings.abuseipdb_api_key.get_secret_value(),
        "Shodan": settings.shodan_api_key.get_secret_value(),
        "AlienVault OTX": settings.otx_api_key.get_secret_value(),
        "IPinfo": settings.ipinfo_token.get_secret_value(),
        "urlscan.io": settings.urlscan_api_key.get_secret_value(),
        "Hybrid Analysis": settings.hybrid_analysis_api_key.get_secret_value(),
        "abuse.ch": settings.abusech_auth_key.get_secret_value(),
        "Pulsedive": settings.pulsedive_api_key.get_secret_value(),
    }
    missing = [name for name, val in optional_keys.items() if not val]
    if missing:
        logger.warning("OSINT sources disabled (no API key): %s", ", ".join(missing))

    yield


_settings_init = get_settings()
app = FastAPI(
    title="OSINT Sentinel",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs" if _settings_init.debug else None,
    redoc_url="/redoc" if _settings_init.debug else None,
    openapi_url="/openapi.json" if _settings_init.debug else None,
)

# ── CORS ────────────────────────────────────────────────────────────────────
# DEBUG does not enable wildcard origins; use CORS_ORIGINS or local defaults.
_cors_origins = _cors_allow_origins(_settings_init)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)


# ── Security headers ───────────────────────────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        # COEP: require-corp would break cross-origin asset loading; omit by default.
        response.headers["Cross-Origin-Resource-Policy"] = "same-site"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "connect-src 'self' https://www.virustotal.com https://api.abuseipdb.com "
            "https://api.shodan.io https://otx.alienvault.com https://ipinfo.io "
            "https://urlscan.io https://api.greynoise.io https://www.hybrid-analysis.com "
            "https://threatfox-api.abuse.ch https://urlhaus-api.abuse.ch "
            "https://mb-api.abuse.ch https://pulsedive.com https://api.groq.com "
            "https://lightning.ai; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "frame-ancestors 'none';"
        )
        return response


app.add_middleware(SecurityHeadersMiddleware)


# ── Routes ─────────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
def root():
    if get_settings().debug:
        return RedirectResponse(url="/docs")
    return RedirectResponse(url="/health")


@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
async def scan(
    request: Request,
    req: ScanRequest,
    _auth: None = Depends(require_api_key_if_configured),
):
    client_ip = _client_ip(request)
    if _is_rate_limited(client_ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Try again in a minute."},
            headers={"Retry-After": "60"},
        )

    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=422, detail="Target must not be empty.")
    try:
        result = await asyncio.to_thread(run_scan, target)
        logger.info(
            "scan completed: ip=%s target=%s risk=%s score=%d duration_ms=%.0f",
            client_ip,
            target,
            result["risk_level"],
            result["risk_score"],
            result["scan_duration_ms"],
        )
        return Response(
            content=ScanResponse(**result).model_dump_json(),
            media_type="application/json",
            headers={
                "Cache-Control": "no-store, no-cache",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
    except InvalidTargetError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
