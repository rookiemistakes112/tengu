"""Commix OS command injection testing tool wrapper.

IMPORTANT: Commix is a highly intrusive tool. Its use requires explicit
authorization from the target owner.
"""

from __future__ import annotations

import re
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


async def commix_scan(
    ctx: Context,
    url: str,
    method: str = "GET",
    data: str = "",
    level: int = 1,
    forms: bool = False,
    timeout: int | None = None,
) -> dict:
    """Test a URL for OS command injection vulnerabilities using Commix.

    IMPORTANT: The target parameter is named 'url' (not 'target').
    Always call as: commix_scan(url="https://example.com/ping?host=test")

    Commix (command injection exploiter) automates the detection of OS command
    injection flaws in web applications. Requires explicit authorization.

    Args:
        url: Target URL to test (e.g. "https://example.com/ping?host=test").
             MUST be named 'url' (not 'target').
        method: HTTP method: GET or POST.
        data: POST data string (e.g. "param=value").
        level: Detection level (1-3). Default: 1.
        forms: Auto-discover and test HTML forms on the target page.
        timeout: Override scan timeout in seconds.

    Returns:
        Command injection test results with vulnerable parameters and evidence.

    Note:
        - This tool requires explicit authorization from the target owner.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {"url": url, "method": method, "level": level, "forms": forms}

    url = sanitize_url(url)
    method = method.upper()
    if method not in ("GET", "POST"):
        method = "GET"

    level = max(1, min(level, 3))

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("commix", url, str(exc))
        raise

    tool_path = resolve_tool_path("commix")
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    safe_data = ""
    if data:
        safe_data = re.sub(r"[;&|`$<>()\{\}]", "", data)

    # commix v4.1 ignores -u and reads targets from stdin.
    # Pass the URL via stdin_data; omit -u entirely.
    args = [tool_path, "--batch", "--output-dir=/tmp/commix_tengu"]
    stdin_payload = (url + "\n").encode()

    if level > 1:
        args.extend([f"--level={level}"])

    if forms:
        args.append("--crawl=2")

    if method == "POST" and safe_data:
        args.extend(["--data", safe_data])
    elif method == "POST":
        args.extend(["--method", "POST"])

    # Stealth: inject --proxy flag if proxy is active
    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url:
        args = stealth.inject_proxy_flags("commix", args)

    await ctx.report_progress(0, 100, f"Starting Commix scan on {url}...")

    async with rate_limited("commix"):
        start = time.monotonic()
        await audit.log_tool_call("commix", url, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(
                args, timeout=effective_timeout, stdin_data=stdin_payload
            )
        except Exception as exc:
            await audit.log_tool_call("commix", url, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing Commix results...")

    findings = _parse_commix_output(stdout)

    await ctx.report_progress(100, 100, "Command injection test complete")
    await audit.log_tool_call("commix", url, params, result="completed", duration_seconds=duration)

    return {
        "tool": "commix",
        "url": url,
        "method": method,
        "level": level,
        "duration_seconds": round(duration, 2),
        "vulnerable": findings["vulnerable"],
        "evidence": findings["evidence"],
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }


def _parse_commix_output(output: str) -> dict:
    """Parse Commix stdout for key findings."""
    evidence = []
    vulnerable = False

    for line in output.splitlines():
        line_lower = line.lower()
        # Only confirmed findings count — commix startup banner contains "injection"
        # as normal text, so matching that word alone causes universal false positives.
        is_confirmed = (
            ("[+]" in line and "injectable" in line_lower)
            or ("[+]" in line and "vulnerable" in line_lower)
            or ("parameter" in line_lower and "injectable" in line_lower)
        )
        if is_confirmed:
            evidence.append(line.strip())
            vulnerable = True

    return {"vulnerable": vulnerable, "evidence": evidence[:20]}
