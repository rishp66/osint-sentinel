"""OSINT Sentinel agent — generates a full structured threat intelligence report in markdown.

All LLM calls route through tools/llm_client (CLAUDE.md §8, §14).
"""

import json
import logging

from tools.llm_client import call_llm
from agents.definitions import AGENT_SYSTEM_PROMPT

logger = logging.getLogger(__name__)


def generate_report(target: str, sources: list[dict], timeout: int = 40) -> str:
    """Call the LLM with the full analyst prompt and return a markdown report string."""
    user_content = (
        f"Target: {target}\n\n"
        "<source_data>\n"
        f"{json.dumps(sources, default=str)}\n"
        "</source_data>"
    )

    try:
        raw = call_llm(
            AGENT_SYSTEM_PROMPT, user_content, max_tokens=1000, timeout=timeout
        )
        # Strip code fence if the model wraps its markdown output
        if raw.startswith("```"):
            raw = raw.split("```", 2)[1]
            if "\n" in raw:
                first_line, rest = raw.split("\n", 1)
                if first_line.strip().lower() in ("markdown", "md", ""):
                    raw = rest
            raw = raw.strip()
        return raw
    except Exception as e:
        logger.error("Agent report generation failed: %s", e)
        return "_Agent report temporarily unavailable._"
