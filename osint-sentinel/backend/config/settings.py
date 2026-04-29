from functools import lru_cache
from pydantic import SecretStr
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    virustotal_api_key: SecretStr = SecretStr("")
    abuseipdb_api_key: SecretStr = SecretStr("")
    shodan_api_key: SecretStr = SecretStr("")
    otx_api_key: SecretStr = SecretStr("")
    ipinfo_token: SecretStr = SecretStr("")
    anthropic_api_key: SecretStr = SecretStr("")
    lightning_api_key: SecretStr = SecretStr("")

    # LLM provider routing (ollama | groq | anthropic | lightning)
    llm_provider: str = "lightning"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    groq_api_key: SecretStr = SecretStr("")
    groq_model: str = "llama-3.3-70b-versatile"

    # New OSINT sources
    # GreyNoise Community API is free and unauthenticated — no key needed.
    urlscan_api_key: SecretStr = SecretStr("")
    hybrid_analysis_api_key: SecretStr = SecretStr("")
    abusech_auth_key: SecretStr = SecretStr("")          # Shared by ThreatFox + URLhaus + MalwareBazaar
    pulsedive_api_key: SecretStr = SecretStr("")

    debug: bool = False

    # ── Deployment: comma-separated list of allowed origins for the browser.
    # Example for production:
    #   CORS_ORIGINS=https://sentinel.example.com,https://www.sentinel.example.com
    # Leave empty to fall back to local dev defaults (localhost:5173/4173).
    cors_origins: str = ""

    # ── Deployment: when running behind a reverse proxy / load balancer
    # (Cloudflare, nginx, fly.io, etc.), set this to "true" so the rate
    # limiter and access logging trust the leftmost X-Forwarded-For / the
    # X-Real-IP header instead of the proxy's own socket address.
    # Only enable when you actually have a trusted proxy in front, otherwise
    # clients can spoof their identity.
    trust_proxy_headers: bool = False

    model_config = {"env_file": ".env", "case_sensitive": False, "extra": "ignore"}

    def cors_origin_list(self) -> list[str]:
        """Parse `cors_origins` into a clean list. Empty string → []."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
