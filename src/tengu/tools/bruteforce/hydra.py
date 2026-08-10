"""Hydra network service brute force tool wrapper.

IMPORTANT: This is a destructive tool. Requires explicit authorization.
Account lockouts, IDS alerts, and network disruption may result.
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
from tengu.security.sanitizer import sanitize_target, sanitize_wordlist_path

logger = structlog.get_logger(__name__)

_SUPPORTED_SERVICES = {
    "ssh",
    "ftp",
    "http-get",
    "http-get-form",
    "http-post-form",
    "https-get",
    "https-get-form",
    "https-post-form",
    "smb",
    "rdp",
    "telnet",
    "mysql",
    "mssql",
    "postgresql",
    "smtp",
    "pop3",
    "imap",
    "ldap",
    "vnc",
    "snmp",
    "redis",
    "mongodb",
}


async def hydra_attack(
    ctx: Context,
    target: str,
    service: str,
    userlist: str,
    passlist: str,
    port: int | None = None,
    threads: int = 16,
    stop_on_success: bool = True,
    form_path: str | None = None,
    form_params: str | None = None,
    timeout: int | None = None,
) -> dict:
    """Perform a credential brute force attack using Hydra.

    WARNING: This is a destructive operation that may trigger account lockouts,
    IDS/IPS alerts, and log entries on the target system. Only use with
    explicit written authorization from the target system owner.

    Args:
        target: Target IP or hostname.
        service: Service protocol to attack (e.g. "ssh", "ftp", "http-post-form").
        userlist: Path to username list file.
        passlist: Path to password list file.
        port: Override default port for the service.
        threads: Number of parallel attack threads (default: 16, max: 64).
        stop_on_success: Stop after finding the first valid credential pair.
        form_path: Required for *-form services (http-post-form, http-get-form,
            https-post-form, https-get-form) — the login form's URL path
            (e.g. "/login.php").
        form_params: Required for *-form services — Hydra's form-module
            argument in "<post_data>:<failure_string>" syntax, with ^USER^
            and ^PASS^ placeholders (e.g.
            "username=^USER^&password=^PASS^:Invalid credentials"). Combined
            with form_path into Hydra's full module argument:
            "<form_path>:<form_params>".
        timeout: Override scan timeout in seconds.

    Returns:
        List of discovered valid credentials.

    Note:
        - Requires explicit human authorization before execution.
        - Consider rate limiting to avoid lockouts.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {"target": target, "service": service, "threads": threads}

    target = sanitize_target(target)
    service = service.lower().strip()

    if service not in _SUPPORTED_SERVICES:
        return {
            "tool": "hydra",
            "error": f"Unsupported service '{service}'. Supported: {', '.join(sorted(_SUPPORTED_SERVICES))}",
        }

    is_form_service = service.endswith("-form")
    if is_form_service and not (form_path and form_params):
        return {
            "tool": "hydra",
            "error": (
                f"Service '{service}' requires both form_path and form_params "
                "(Hydra's *-form modules need a module argument in "
                "'<path>:<post_data>:<failure_string>' syntax — there is no "
                "sensible default login path/params to fall back to)."
            ),
        }

    userlist = sanitize_wordlist_path(userlist)
    passlist = sanitize_wordlist_path(passlist)
    threads = max(1, min(threads, 64))

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("hydra", target, str(exc))
        raise

    tool_path = resolve_tool_path("hydra", cfg.tools.paths.hydra)
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        target,
        service,
        "-L",
        userlist,
        "-P",
        passlist,
        "-t",
        str(threads),
    ]

    if stop_on_success:
        args.append("-f")

    if port and 1 <= port <= 65535:
        args.extend(["-s", str(port)])

    if is_form_service:
        # Hydra's *-form modules take a single extra positional argument:
        # "<path>:<post_data_with_^USER^/^PASS^_placeholders>:<failure_string>".
        # form_params already carries the "<post_data>:<failure_string>" half
        # (that's the caller-facing contract) — this just prepends the path.
        # No shell is involved (create_subprocess_exec, not shell=True) so
        # this can't be used for shell injection, but CRLF could still
        # corrupt Hydra's own argument parsing or spoof audit log lines.
        safe_path = form_path.replace("\r", "").replace("\n", "").replace("\x00", "")
        safe_params = form_params.replace("\r", "").replace("\n", "").replace("\x00", "")
        module_arg = f"{safe_path}:{safe_params}"
        args.append(module_arg)
        params["form_module"] = module_arg

    # Output format for easier parsing
    args.extend(["-o", "/dev/stdout"])

    await ctx.report_progress(0, 100, f"Starting Hydra attack on {target} ({service})...")

    async with rate_limited("hydra"):
        start = time.monotonic()
        await audit.log_tool_call("hydra", target, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("hydra", target, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    credentials = _parse_hydra_output(stdout)

    await ctx.report_progress(100, 100, "Brute force attack complete")
    await audit.log_tool_call(
        "hydra", target, params, result="completed", duration_seconds=duration
    )

    return {
        "tool": "hydra",
        "target": target,
        "service": service,
        "duration_seconds": round(duration, 2),
        "valid_credentials_found": len(credentials),
        "credentials": credentials,
        "raw_output_excerpt": stdout[-2000:],
    }


def _parse_hydra_output(output: str) -> list[dict]:
    """Parse Hydra output for valid credentials.

    Real Hydra output (verified live, v9.7) is
    "[port][service] host: HOST   login: USER   password: PASS" — the
    previous pattern assumed "login:" followed "[.+?]" directly with no
    "host: HOST" in between, so it never matched a single real credential
    line; valid_credentials_found was always 0 regardless of what Hydra
    actually found. Matches the pattern already used (and already correct)
    in agents/auth_failures_agent.py's own parse_hydra_output — that one
    works because it deliberately re-parses this same raw output instead of
    trusting this function's result.
    """
    credentials = []

    for line in output.splitlines():
        m = re.search(
            r"\[\d+\]\[\S+\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)",
            line,
            re.IGNORECASE,
        )
        if m:
            pw = m.group(2)
            masked = pw[:2] + "***" + pw[-1:] if len(pw) > 3 else "***"
            credentials.append(
                {
                    "username": m.group(1),
                    "password": masked,
                    "password_length": len(pw),
                    "found": True,
                    "raw_line": "[credential found - see audit log]",
                }
            )

    return credentials
