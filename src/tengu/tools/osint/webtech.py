"""WhatWeb web technology fingerprinting tool wrapper."""

from __future__ import annotations

import json
import time

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_url

logger = structlog.get_logger(__name__)


async def whatweb_scan(
    ctx: Context,
    target: str,
    aggression: int = 1,
    cookie: str = "",
    timeout: int | None = None,
) -> dict:
    """Detect web technologies, CMS, frameworks, and WAF using WhatWeb.

    Args:
        target: Target URL to fingerprint (e.g. https://example.com).
        aggression: Aggression level 1-4 (1=passive/stealthy, 3=aggressive, 4=heavy).
        cookie: Session cookie for authenticated fingerprinting (e.g. "PHPSESSID=abc123").
        timeout: Override default timeout in seconds.

    Returns:
        Detected technologies, plugins, versions, and confidence levels.

    Note:
        - Aggression level 1 sends a single request (safe for production).
        - Aggression 3+ sends many requests and may trigger WAF/IDS alerts.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params = {"target": target, "aggression": aggression, "cookie": cookie}

    target = sanitize_url(target)
    aggression = max(1, min(aggression, 4))

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("whatweb", target, str(exc))
        raise

    tool_path = resolve_tool_path("whatweb")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        f"--aggression={aggression}",
        "--log-json=-",
        "--no-errors",
    ]

    if cookie:
        sanitized_cookie = cookie.replace("\r", "").replace("\n", "").replace("\x00", "")
        args.append(f"--cookie={sanitized_cookie}")

    args.append(target)

    await ctx.report_progress(0, 100, f"Starting WhatWeb fingerprinting on {target}...")

    async with rate_limited("whatweb"):
        start = time.monotonic()
        await audit.log_tool_call("whatweb", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("whatweb", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing WhatWeb results...")

    plugins = []
    detected_url = target
    http_status = None

    def _ingest(entry: dict) -> None:
        nonlocal detected_url, http_status
        detected_url = entry.get("target", detected_url)
        if entry.get("http_status") is not None:
            http_status = entry.get("http_status")
        plugin_data = entry.get("plugins", {})
        if not isinstance(plugin_data, dict):
            return
        for plugin_name, plugin_info in plugin_data.items():
            info = plugin_info if isinstance(plugin_info, dict) else {}
            versions = info.get("version", [])
            string = info.get("string", [])
            plugins.append(
                {
                    "name": plugin_name,
                    "version": versions[0] if versions else None,
                    "detail": string[0] if string else None,
                }
            )

    # whatweb --log-json emits a single JSON document — an ARRAY of result
    # objects, pretty-printed across MULTIPLE lines (the opening "[" is on its
    # own line). The old parser did json.loads() per line, so "[" threw, the
    # whole result fell through to the text fallback (which appended the entire
    # JSON blob as one bogus "technology"), and http_status was left None.
    # Confirmed live against whatweb 0.6.4 / Mutillidae. Parse the whole stdout
    # first; only then fall back.
    parsed = False
    try:
        data = json.loads(stdout)
        entries = data if isinstance(data, list) else [data]
        for entry in entries:
            if isinstance(entry, dict):
                _ingest(entry)
        parsed = True
    except (json.JSONDecodeError, ValueError, AttributeError):
        # Second try: JSONL (one JSON object/array per line) for whatweb builds
        # that emit that instead of a pretty-printed array.
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        _ingest(entry)
                parsed = True
            elif isinstance(data, dict):
                _ingest(data)
                parsed = True

    if not parsed and not plugins:
        # Last resort: whatweb printed non-JSON (e.g. plain text) — keep the
        # old best-effort so a fingerprint isn't lost entirely.
        for line in stdout.splitlines():
            if "[" in line and "]" in line:
                plugins.append({"name": line.strip(), "version": None, "detail": None})

    await ctx.report_progress(100, 100, "WhatWeb complete")
    await audit.log_tool_call(
        "whatweb", target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "whatweb",
        "target": detected_url,
        "http_status": http_status,
        "aggression": aggression,
        "command": " ".join(args),
        "duration_seconds": round(duration, 2),
        "plugins_found": len(plugins),
        "technologies": plugins,
        "raw_output": stdout,
    }
