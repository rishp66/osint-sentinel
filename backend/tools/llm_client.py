"""LLM provider router — ollama | groq | anthropic | lightning.

All LLM calls in the project route through this module (CLAUDE.md §8, §14).
"""

import json
import logging
import re

import httpx

from config.settings import get_settings
from agents.definitions import SYNTHESIS_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


# ─── provider backends ────────────────────────────────────────────────────────


def _call_openai_compatible(
    url: str,
    api_key: str | None,
    model: str,
    system_prompt: str,
    user_content: str,
    max_tokens: int,
    timeout: int = 30,
) -> str:
    """Shared path for Ollama, Groq, and Lightning (all OpenAI-compatible)."""
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        with httpx.Client(trust_env=False) as client:
            resp = client.post(
                url,
                headers=headers,
                content=json.dumps(
                    {
                        "model": model,
                        "max_tokens": max_tokens,
                        "messages": [
                            {
                                "role": "system",
                                "content": [{"type": "text", "text": system_prompt}],
                            },
                            {
                                "role": "user",
                                "content": [{"type": "text", "text": user_content}],
                            },
                        ],
                    }
                ),
                timeout=float(timeout),
            )
            resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        logger.warning("LLM API HTTP error: status=%d host=%s", e.response.status_code, e.request.url.host)
        raise RuntimeError(f"LLM API error: HTTP {e.response.status_code}") from None
    return json.loads(resp.content)["choices"][0]["message"]["content"].strip()


def _call_anthropic(
    api_key: str,
    system_prompt: str,
    user_content: str,
    max_tokens: int,
    timeout: int = 60,
) -> str:
    """Anthropic Messages API — SDK imported conditionally (CLAUDE.md §8)."""
    import anthropic  # conditional import — not a hard top-level dependency

    client = anthropic.Anthropic(api_key=api_key, timeout=float(timeout))
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=max_tokens,
        system=system_prompt,
        messages=[{"role": "user", "content": user_content}],
    )
    return response.content[0].text.strip()


# ─── router ───────────────────────────────────────────────────────────────────


def call_llm(
    system_prompt: str,
    user_content: str,
    max_tokens: int = 400,
    timeout: int = 30,
) -> str:
    """Route to the configured LLM provider and return raw text.

    Raises on missing keys or HTTP errors — callers must handle exceptions.
    """
    settings = get_settings()
    provider = settings.llm_provider.lower()

    if provider == "ollama":
        url = f"{settings.ollama_base_url.rstrip('/')}/v1/chat/completions"
        return _call_openai_compatible(
            url,
            None,
            settings.ollama_model,
            system_prompt,
            user_content,
            max_tokens,
            timeout=max(timeout, 60),
        )

    if provider == "groq":
        key = settings.groq_api_key.get_secret_value()
        if not key:
            raise ValueError("GROQ_API_KEY not configured but LLM_PROVIDER=groq")
        return _call_openai_compatible(
            "https://api.groq.com/openai/v1/chat/completions",
            key,
            settings.groq_model,
            system_prompt,
            user_content,
            max_tokens,
            timeout=timeout,
        )

    if provider == "anthropic":
        key = settings.anthropic_api_key.get_secret_value()
        if not key:
            raise ValueError(
                "ANTHROPIC_API_KEY not configured but LLM_PROVIDER=anthropic"
            )
        return _call_anthropic(
            key, system_prompt, user_content, max_tokens, timeout=timeout
        )

    if provider == "lightning":
        key = settings.lightning_api_key.get_secret_value().strip()
        if not key:
            raise ValueError(
                "LIGHTNING_API_KEY not configured but LLM_PROVIDER=lightning"
            )
        return _call_openai_compatible(
            "https://lightning.ai/api/v1/chat/completions",
            key,
            "lightning-ai/gemma-4-31B-it",
            system_prompt,
            user_content,
            max_tokens,
            timeout=timeout,
        )

    raise ValueError(f"Unknown LLM_PROVIDER: {provider!r}")


# ─── public API ───────────────────────────────────────────────────────────────


def synthesize(target: str, sources: list[dict], timeout: int = 30) -> dict:
    """Return {'threat_brief': str, 'risk_score': int, 'risk_level': str}.

    Raises when the provider cannot be reached or is not configured so callers
    can fall back to deterministic scoring from raw source data.
    """
    user_content = (
        f"Target: {target}\n\n"
        "<source_data>\n"
        f"{json.dumps(sources, default=str)}\n"
        "</source_data>"
    )

    try:
        raw = call_llm(SYNTHESIS_SYSTEM_PROMPT, user_content, max_tokens=400, timeout=timeout)
        # Extract JSON from fenced block regardless of preamble text
        m = _JSON_FENCE_RE.search(raw)
        if m:
            raw = m.group(1).strip()
        elif raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1].strip() if len(parts) >= 3 else raw
    except Exception as e:
        logger.error("LLM synthesis failed: %s", e)
        raise RuntimeError("LLM synthesis failed") from e

    try:
        result = json.loads(raw)
        score = max(0, min(100, int(result.get("risk_score", 0))))
        level = score_to_level(score)
        return {
            "threat_brief": result.get("threat_brief", "No threat brief available."),
            "risk_score": score,
            "risk_level": result.get("risk_level", level),
        }
    except (json.JSONDecodeError, KeyError, ValueError):
        return {"threat_brief": raw, "risk_score": 0, "risk_level": "UNKNOWN"}


def score_to_level(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"
