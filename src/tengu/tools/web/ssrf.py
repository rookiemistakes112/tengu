"""SSRF testing tool — wraps SSRFmap by swisskyrepo.

SSRFmap: https://github.com/swisskyrepo/SSRFmap
Installed at /opt/SSRFmap/ssrfmap.py inside the Tengu Kali container.
"""

from __future__ import annotations

import os
import re
import tempfile
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.sanitizer import sanitize_url

logger = structlog.get_logger(__name__)

# SSRFmap modules to run — covers cloud metadata across major providers
_MODULES = "aws,gce,azure,digitalocean,alibaba"

# Default SSRF-prone parameter names to probe when none is specified
_SSRF_PARAM_NAMES = ["url", "uri", "link", "redirect", "next", "callback", "src", "host"]

# Parses SSRFmap's "[!]" finding lines
_FINDING_RE = re.compile(r"\[!\]\s*(.+)", re.IGNORECASE)

# Severity heuristic based on which module triggered
_MODULE_SEVERITY = {
    "aws":          "critical",
    "gce":          "critical",
    "azure":        "critical",
    "digitalocean": "critical",
    "alibaba":      "critical",
    "readfiles":    "high",
    "portscan":     "high",
}


async def ssrf_tester(
    ctx: Context,  # type: ignore[type-arg]
    target: str,
    payloads: list[str] | None = None,  # accepted for API compatibility, SSRFmap uses its own
    parameter: str = "",
    timeout: int = 120,
) -> dict:  # type: ignore[type-arg]
    """Test a URL for Server-Side Request Forgery (SSRF) vulnerabilities using SSRFmap.

    SSRFmap (https://github.com/swisskyrepo/SSRFmap) by swisskyrepo probes
    URL parameters with cloud metadata payloads (AWS, GCP, Azure, DigitalOcean,
    Alibaba) and detects both reflected and error-based SSRF.

    Args:
        target: Target URL to test (with or without existing query parameters).
        payloads: Ignored — SSRFmap uses its own built-in payload modules.
                  Accepted for API compatibility with the SSRFAgent caller.
        parameter: Specific query parameter to inject into. If empty, tries
                   common SSRF-prone names (url, uri, link, redirect, next,
                   callback, src, host) or any existing query parameters.
        timeout: Scan timeout in seconds per parameter probe. Default: 120.

    Returns:
        SSRF scan results with a findings list. Each finding includes the
        matched URL, severity, description, and a curl command to reproduce.

    Note:
        - Requires SSRFmap installed at cfg.tools.paths.ssrfmap
          (default: /opt/SSRFmap/ssrfmap.py).
        - If SSRFmap is not installed, returns an error result.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {
        "target":    target,
        "parameter": parameter,
        "timeout":   timeout,
    }

    target = sanitize_url(target)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("ssrf_tester", target, str(exc))
        raise

    ssrfmap_path = cfg.tools.paths.ssrfmap or "/opt/SSRFmap/ssrfmap.py"
    if not os.path.isfile(ssrfmap_path):
        msg = f"SSRFmap not found at {ssrfmap_path} — rebuild the Tengu Docker image"
        logger.warning("ssrf_tester: SSRFmap missing", path=ssrfmap_path)
        await audit.log_tool_call("ssrf_tester", target, params, result="failed", error=msg)
        return {"tool": "ssrf_tester", "target": target, "error": msg, "findings": []}

    # Determine which parameters to probe
    parsed = urlparse(target)
    existing_params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
    if parameter:
        params_to_probe = [parameter]
    elif existing_params:
        params_to_probe = existing_params
    else:
        params_to_probe = _SSRF_PARAM_NAMES

    await ctx.report_progress(0, len(params_to_probe), f"Starting SSRFmap on {target}...")
    await audit.log_tool_call("ssrf_tester", target, params, result="started")

    findings: list[dict[str, object]] = []
    seen_keys: set[str] = set()
    scan_start = time.monotonic()

    for i, param_name in enumerate(params_to_probe):
        if time.monotonic() - scan_start > timeout * len(params_to_probe):
            break

        req_file = _build_request_file(target, param_name)
        try:
            args = [
                "python3",
                ssrfmap_path,
                "-r", req_file,
                "-p", param_name,
                "-m", _MODULES,
            ]

            logger.info("ssrf_tester: running SSRFmap", target=target, param=param_name)
            t0 = time.monotonic()
            stdout, stderr, _ = await run_command(args, timeout=timeout)
            elapsed = time.monotonic() - t0
            logger.info(
                "ssrf_tester: SSRFmap finished",
                param=param_name,
                elapsed=round(elapsed, 1),
            )

            _parse_ssrfmap_output(stdout, target, param_name, findings, seen_keys)

        except Exception as exc:
            logger.warning("ssrf_tester: SSRFmap error", param=param_name, error=str(exc))
        finally:
            _cleanup(req_file)

        await ctx.report_progress(i + 1, len(params_to_probe), f"Probed parameter '{param_name}'")

    duration = time.monotonic() - scan_start
    await ctx.report_progress(
        len(params_to_probe), len(params_to_probe), "SSRF scan complete"
    )
    await audit.log_tool_call(
        "ssrf_tester", target, params, result="completed", duration_seconds=duration
    )

    logger.info(
        "ssrf_tester complete",
        target=target,
        findings=len(findings),
        duration=round(duration, 2),
    )

    return {
        "tool":             "ssrf_tester",
        "target":           target,
        "duration_seconds": round(duration, 2),
        "findings_count":   len(findings),
        "findings":         findings,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_request_file(target: str, param_name: str) -> str:
    """Write a Burp-style HTTP request file for SSRFmap and return its path."""
    parsed = urlparse(target)
    host = parsed.hostname or target

    # Ensure the parameter exists in the query string with a placeholder value
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param_name] = ["http://placeholder.ssrf/"]
    new_query = urlencode({k: v[0] for k, v in qs.items()})
    path_with_qs = (parsed.path or "/") + ("?" + new_query if new_query else "")

    request_lines = [
        f"GET {path_with_qs} HTTP/1.1",
        f"Host: {host}",
        "User-Agent: Mozilla/5.0 (compatible; SSRFmap)",
        "Accept: */*",
        "Connection: close",
        "",
        "",
    ]

    fd, path = tempfile.mkstemp(suffix=".txt", prefix="ssrfmap_")
    with os.fdopen(fd, "w") as f:
        f.write("\r\n".join(request_lines))
    return path


def _parse_ssrfmap_output(
    output: str,
    target: str,
    param_name: str,
    findings: list[dict[str, object]],
    seen_keys: set[str],
) -> None:
    """Extract SSRF findings from SSRFmap's stdout."""
    current_module = "unknown"

    for line in output.splitlines():
        # Track which module is currently running
        module_match = re.search(r"Running module[:\s]+(\w+)", line, re.IGNORECASE)
        if module_match:
            current_module = module_match.group(1).lower()
            continue

        finding_match = _FINDING_RE.search(line)
        if not finding_match:
            continue

        detail = finding_match.group(1).strip()
        severity = _MODULE_SEVERITY.get(current_module, "high")

        # Extract payload URL from the finding line if present
        url_match = re.search(r"https?://\S+", detail)
        payload = url_match.group(0) if url_match else detail

        dedup_key = f"{current_module}|{param_name}|{payload}"
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        title = f"SSRF — {current_module.upper()} Metadata Exposure"
        description = (
            f"SSRFmap detected SSRF via the '{param_name}' parameter on {target}. "
            f"Module '{current_module}' confirmed the server fetched {payload}."
        )
        curl_cmd = (
            f"curl -sk '{target}' --get --data-urlencode '{param_name}={payload}'"
        )

        findings.append({
            "title":       title,
            "severity":    severity,
            "matched_url": target,
            "description": description,
            "payload":     payload,
            "curl_command": curl_cmd,
            "evidence":    detail,
            "parameter":   param_name,
            "blind":       False,
        })

        logger.info(
            "ssrf finding",
            title=title,
            severity=severity,
            target=target,
            param=param_name,
            module=current_module,
        )


def _cleanup(path: str) -> None:
    """Remove a temp file, ignoring errors."""
    try:
        os.unlink(path)
    except OSError:
        pass
