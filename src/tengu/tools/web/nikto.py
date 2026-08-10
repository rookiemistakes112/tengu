"""Nikto web server scanner tool wrapper."""

from __future__ import annotations

import re
import time

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.exceptions import ScanTimeoutError
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_url

logger = structlog.get_logger(__name__)


async def nikto_scan(
    ctx: Context,
    target: str,
    tuning: str = "x6",
    ssl: bool = False,
    port: int | None = None,
    timeout: int | None = None,
) -> dict:
    """Scan a web server for vulnerabilities using Nikto.

    Nikto checks for outdated server software, dangerous files/programs,
    default credentials, and server misconfigurations.

    Args:
        target: URL or host to scan.
        tuning: Nikto tuning options to control scan types:
                0=File Upload, 1=Interesting File, 2=Misconfiguration,
                3=Information Disclosure, 4=Injection, 5=Remote File Retrieval,
                6=Denial of Service, 7=Remote File Retrieval (server),
                8=Command Execution, 9=SQL Injection, a=Authentication Bypass,
                b=Software Identification, c=Remote Source Inclusion, x=Reverse Tuning.
                Default "x6" = everything except DoS.
        ssl: Force SSL mode.
        port: Target port (auto-detected from URL if not specified).
        timeout: Override scan timeout in seconds.

    Returns:
        List of vulnerability findings with descriptions and references.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {"target": target, "tuning": tuning, "ssl": ssl, "port": port}

    target = sanitize_url(target)

    # Validate tuning string — only valid tuning chars allowed
    if not re.match(r"^[0-9a-cx]+$", tuning.lower()):
        tuning = "x6"

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("nikto", target, str(exc))
        raise

    tool_path = resolve_tool_path("nikto", cfg.tools.paths.nikto)
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    # -Format json / -output were tried and confirmed broken in this nikto
    # build (2.6.0): no output file is ever produced regardless of flag
    # combination (-o vs -output, with/without explicit -Format, .json
    # extension inference) — silent failure, not a stdout-vs-file quirk.
    # Parsing nikto's plain-text stdout report is the only path that
    # actually works; see _parse_nikto_output.
    args = [
        tool_path,
        "-h",
        target,
        "-Tuning",
        tuning,
        "-nointeractive",
    ]

    if ssl:
        args.append("-ssl")

    if port is not None and 1 <= port <= 65535:
        args.extend(["-port", str(port)])

    # Stealth: inject -useproxy flag if proxy is active
    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url:
        args = stealth.inject_proxy_flags("nikto", args)

    await ctx.report_progress(0, 100, f"Starting Nikto scan on {target}...")

    timed_out = False
    async with rate_limited("nikto"):
        start = time.monotonic()
        await audit.log_tool_call("nikto", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except ScanTimeoutError as exc:
            # A slow-but-working scan still found real things before running
            # out of time — salvage them instead of discarding the whole
            # scan. Verified live: nikto against even a small local target
            # needs ~5x a previously-too-short timeout; every prior run
            # silently returned nothing because this path used to re-raise.
            timed_out = True
            stdout = exc.partial_stdout
            await audit.log_tool_call(
                "nikto", target, params, result="timed_out",
                error=f"partial results salvaged, {len(stdout)} chars captured",
            )
        except Exception as exc:
            await audit.log_tool_call("nikto", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing Nikto results...")

    findings = _parse_nikto_output(stdout)

    await ctx.report_progress(100, 100, "Scan complete")
    if not timed_out:
        await audit.log_tool_call(
            "nikto", target, params, result="completed", duration_seconds=duration
        )

    return {
        "tool": "nikto",
        "target": target,
        "duration_seconds": round(duration, 2),
        "timed_out": timed_out,
        "findings_count": len(findings),
        "findings": findings,
        "raw_output": stdout[:5000],
    }


_FINDING_LINE = re.compile(r"^\+\s*\[(?P<id>[^\]]+)\]\s*(?P<rest>.*)$")
_LEADING_PATH = re.compile(r"^(?P<url>/\S*?):\s*(?P<message>.*)$")


def _parse_nikto_output(output: str) -> list[dict]:
    """Parse Nikto's plain-text stdout report.

    Nikto's -Format/-output flags for structured (JSON/XML/CSV) output were
    tried and confirmed broken in this build (2.6.0) — no output file is
    ever produced regardless of flag combination. Plain-text stdout is the
    only format this tool actually emits, so that's what gets parsed.

    Only lines carrying a bracketed plugin/OSVDB ID (e.g. "+ [750500] ...")
    are real findings. Nikto also prints unbracketed "+ "-prefixed banner
    and summary lines ("+ Target IP: ...", "+ 1 host(s) tested", "+ No CGI
    Directories found...") which look identical to a naive "starts with +"
    scan but aren't findings at all — treating them as findings previously
    inflated the count with pure noise (verified live: nikto reported "14
    items" while the naive scraper counted 24 "findings").
    """
    findings = []
    for line in output.splitlines():
        line = line.strip()
        match = _FINDING_LINE.match(line)
        if not match:
            continue

        finding_id = match.group("id")
        rest = match.group("rest")
        path_match = _LEADING_PATH.match(rest)
        if path_match:
            url = path_match.group("url")
            message = path_match.group("message")
        else:
            url = ""
            message = rest

        findings.append(
            {
                "id": finding_id,
                "osvdb": "",
                "method": "",
                "url": url,
                "message": message,
                "references": [],
            }
        )

    return findings
