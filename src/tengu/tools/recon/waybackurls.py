"""Waybackurls — fetch known URLs from the Wayback Machine for a domain."""

from __future__ import annotations

import time

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_target

logger = structlog.get_logger(__name__)


def _parse_waybackurls_output(output: str) -> list[str]:
    urls = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("http://") or line.startswith("https://"):
            urls.append(line)
    return list(dict.fromkeys(urls))  # deduplicate, preserve order


async def waybackurls_fetch(
    ctx: Context,
    target: str,
    timeout: int | None = None,
) -> dict:
    """Fetch all URLs ever crawled for a domain from the Wayback Machine (archive.org).

    Uses tomnomnom/waybackurls to pull historical URLs, revealing endpoints,
    parameters, and paths that may no longer be linked but still exist on the server.

    Args:
        target: Target domain or URL (e.g. "https://example.com" or "example.com").
        timeout: Override scan timeout in seconds.

    Returns:
        List of discovered historical URLs.

    Note:
        - Target must be in tengu.toml [targets].allowed_hosts.
        - Requires internet access to reach archive.org.
    """
    cfg = get_config()
    audit = get_audit_logger()

    params: dict[str, object] = {"target": target}

    target = sanitize_target(target)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("waybackurls", target, str(exc))
        raise

    tool_path = resolve_tool_path("waybackurls")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    # waybackurls reads the domain from stdin: echo domain | waybackurls
    # We pass it as a positional argument instead using the -no-subs flag
    # to scope results to the exact domain only (no subdomains).
    args = [tool_path, "-no-subs", target]

    await ctx.report_progress(0, 100, f"Fetching Wayback Machine URLs for {target}...")

    async with rate_limited("waybackurls"):
        start = time.monotonic()
        await audit.log_tool_call("waybackurls", target, params, result="started")
        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call(
                "waybackurls", target, params, result="failed", error=str(exc)
            )
            raise
        duration = time.monotonic() - start

    await audit.log_tool_call(
        "waybackurls", target, params, result="completed", duration_seconds=duration
    )
    await ctx.report_progress(100, 100, "Wayback Machine fetch complete")

    urls = _parse_waybackurls_output(stdout)

    return {
        "tool": "waybackurls",
        "target": target,
        "duration_seconds": round(duration, 2),
        "urls_found": len(urls),
        "urls": urls,
    }
