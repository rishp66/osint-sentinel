"""Thin stdio-based MCP client for cve-mcp-server.

Communicates with the server over its stdin/stdout using the JSON-RPC 2.0
framing that FastMCP / the MCP protocol specifies.  No inbound network port
is opened: the child process is spawned locally, receives requests on stdin,
and writes responses to stdout.

Security notes:
- The subprocess inherits only the env vars explicitly forwarded (NVD_API_KEY,
  GITHUB_TOKEN, and the keys already held by the parent via settings).  The
  Cursor sandbox proxy variables (HTTP_PROXY / HTTPS_PROXY) are explicitly
  cleared so the child connects directly, matching the parent session policy.
- All CVE ID inputs are validated before being sent to the subprocess.
- The client is intentionally single-use-per-call (spawn → call → terminate)
  to avoid state leakage between unrelated scans.  A subprocess pool can be
  added later if latency becomes a concern.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from typing import Any

from config.settings import get_settings

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


# ─── Internal helpers ─────────────────────────────────────────────────────────

def _build_env() -> dict[str, str]:
    """Return an environment dict for the MCP child process.

    Only essential variables are forwarded; proxy settings are suppressed so
    the child connects directly (matching `_SESSION.trust_env = False` policy).
    """
    settings = get_settings()
    env: dict[str, str] = {}

    # Propagate PATH and Python-essential vars
    for key in ("PATH", "HOME", "LANG", "LC_ALL", "PYTHONPATH", "VIRTUAL_ENV",
                "PYTHONUTF8", "PYTHONIOENCODING"):
        if key in os.environ:
            env[key] = os.environ[key]

    # CVE-specific API keys
    nvd = settings.nvd_api_key.get_secret_value()
    if nvd:
        env["NVD_API_KEY"] = nvd

    gh = settings.cve_github_token.get_secret_value()
    if gh:
        env["GITHUB_TOKEN"] = gh

    # Forward threat-intel keys that cve-mcp-server can also use
    for attr, var in (
        ("virustotal_api_key",  "VIRUSTOTAL_KEY"),
        ("abuseipdb_api_key",   "ABUSEIPDB_KEY"),
        ("shodan_api_key",      "SHODAN_KEY"),
    ):
        val = getattr(settings, attr).get_secret_value()
        if val:
            env[var] = val

    # Explicitly suppress proxy env vars — never forward
    env["HTTP_PROXY"]  = ""
    env["HTTPS_PROXY"] = ""
    env["http_proxy"]  = ""
    env["https_proxy"] = ""

    return env


def _rpc(method: str, params: dict[str, Any]) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 request object."""
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }


def _read_response(proc: "subprocess.Popen[bytes]", timeout: float) -> dict[str, Any]:
    """Read one JSON-RPC response from the child's stdout, with a deadline.

    FastMCP / MCP protocol writes one JSON object per line to stdout.
    Lines that look like log/banner output (don't start with '{') are skipped.
    """
    deadline = time.monotonic() + timeout
    buf = b""

    # Use a background reader thread so we can honour the deadline without
    # blocking the calling thread indefinitely on a hung subprocess.
    result: list[bytes] = []
    exc_holder: list[Exception] = []

    def _reader() -> None:
        try:
            for raw in proc.stdout:  # type: ignore[union-attr]
                line = raw.strip()
                if line.startswith(b"{"):
                    result.append(line)
                    return
        except Exception as e:
            exc_holder.append(e)

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    t.join(timeout=max(0.0, deadline - time.monotonic()))

    if exc_holder:
        raise exc_holder[0]
    if not result:
        raise TimeoutError("No JSON-RPC response received within deadline")

    return json.loads(result[0])


# ─── Public interface ──────────────────────────────────────────────────────────

def call_cve_mcp_tool(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Spawn the cve-mcp-server, invoke one tool, return its result dict.

    Returns a dict with ``{"ok": True, "result": ...}`` on success or
    ``{"ok": False, "error": str}`` on any failure so callers always get a
    safe dict back and never need to catch exceptions.
    """
    cve_id = arguments.get("cve_id", "")
    if cve_id and not _CVE_RE.match(str(cve_id)):
        return {"ok": False, "error": f"Invalid CVE ID format: {cve_id!r}"}

    settings = get_settings()

    if not settings.cve_mcp_enabled:
        return {"ok": False, "error": "cve-mcp integration is disabled (CVE_MCP_ENABLED=false)"}

    workdir = settings.cve_mcp_workdir.strip() or None
    if workdir:
        workdir = os.path.realpath(workdir)
        if not os.path.isdir(workdir):
            return {"ok": False, "error": f"CVE_MCP_WORKDIR does not exist: {workdir!r}"}

    command = settings.cve_mcp_command.strip() or "python"
    extra_args = settings.cve_mcp_args.strip().split() if settings.cve_mcp_args.strip() else ["-m", "cve_mcp.server"]
    cmd = [command] + extra_args

    timeout = float(settings.cve_mcp_timeout_seconds)
    env = _build_env()

    proc: subprocess.Popen[bytes] | None = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=workdir,
            env=env,
            bufsize=0,
        )

        # MCP initialize handshake
        init_req = _rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "osint-sentinel", "version": "0.1"},
        })
        proc.stdin.write((json.dumps(init_req) + "\n").encode())  # type: ignore[union-attr]
        proc.stdin.flush()  # type: ignore[union-attr]
        _read_response(proc, timeout=min(5.0, timeout))

        # Notify initialized
        notif = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        proc.stdin.write((json.dumps(notif) + "\n").encode())  # type: ignore[union-attr]
        proc.stdin.flush()  # type: ignore[union-attr]

        # Issue the actual tool call
        call_req = _rpc("tools/call", {"name": tool_name, "arguments": arguments})
        proc.stdin.write((json.dumps(call_req) + "\n").encode())  # type: ignore[union-attr]
        proc.stdin.flush()  # type: ignore[union-attr]

        response = _read_response(proc, timeout=timeout)

        if "error" in response:
            rpc_err = response["error"]
            msg = rpc_err.get("message", str(rpc_err)) if isinstance(rpc_err, dict) else str(rpc_err)
            return {"ok": False, "error": f"MCP tool error: {msg}"}

        content = response.get("result", {})
        # FastMCP wraps text results in a list of content blocks
        if isinstance(content, dict) and "content" in content:
            blocks = content["content"]
            if isinstance(blocks, list) and blocks:
                text = blocks[0].get("text", "")
                try:
                    return {"ok": True, "result": json.loads(text)}
                except (json.JSONDecodeError, TypeError):
                    return {"ok": True, "result": {"text": text}}
        return {"ok": True, "result": content}

    except TimeoutError:
        return {"ok": False, "error": f"cve-mcp tool '{tool_name}' timed out after {timeout}s"}
    except FileNotFoundError:
        return {"ok": False, "error": f"cve-mcp command not found: {command!r}"}
    except Exception as exc:
        return {"ok": False, "error": f"cve-mcp unexpected error: {exc}"}
    finally:
        if proc is not None:
            try:
                proc.stdin.close()  # type: ignore[union-attr]
            except Exception:
                pass
            try:
                proc.terminate()
            except Exception:
                pass
