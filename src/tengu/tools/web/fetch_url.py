"""Generic authenticated HTTP GET fetch using httpx (pure Python).

Hellfire's agents (recon_agent.py, injection_agent.py, misconfiguration_agent.py,
logging_failures_agent.py) call this for form discovery, LFI/param/REST-path
probing, OpenAPI spec discovery, exploit-confirmation evidence, and A09
(logging/monitoring failures) HTTP-response collection — none of which need a
specialised security tool, just a basic authenticated GET returning status +
body. This didn't exist as a registered MCP tool at all until now; every one
of those call sites was failing silently.
"""

from __future__ import annotations

import httpx
import structlog
from fastmcp import Context

from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.sanitizer import sanitize_url

logger = structlog.get_logger(__name__)

# Response bodies are capped to keep MCP payloads and downstream token
# budgets bounded — callers that need a specific fragment (a stack trace,
# a form, a JSON spec) only need the leading portion in practice.
_MAX_BODY_BYTES = 50_000


async def fetch_url(
    ctx: Context,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout_seconds: int = 15,
    follow_redirects: bool = True,
) -> dict:
    """Fetch a single URL and return its status code, body, and headers.

    A generic authenticated HTTP request — not a vulnerability scanner. Used
    by other agents for form discovery, direct exploit confirmation, and
    response-content analysis where a full scanning tool would be overkill.

    Args:
        url: Target URL to fetch.
        method: HTTP method — GET, POST, HEAD, etc.
        headers: Additional request headers (e.g. {"Cookie": "PHPSESSID=..."}
                 for authenticated requests, {"Accept": "application/json"}).
        body: Raw request body, sent as-is (e.g. a pre-encoded
              "username=admin&password=admin123" form body, or a JSON
              string) — the caller is responsible for setting a matching
              Content-Type header. None (the default) sends no body, same
              as before this parameter existed.
        timeout_seconds: HTTP request timeout in seconds.
        follow_redirects: Follow HTTP redirects to the final destination.

    Returns:
        {"tool": "fetch_url", "url": <final URL>, "status_code": int,
         "body": str (truncated to 50KB), "headers": dict, "error": str|None}
    """
    audit = get_audit_logger()
    params = {"url": url, "method": method}

    url = sanitize_url(url)

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("fetch_url", url, str(exc))
        raise

    await ctx.report_progress(0, 1, f"Fetching {url}...")

    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    try:
        async with stealth.create_http_client(
            follow_redirects=follow_redirects,
            timeout=timeout_seconds,
            verify=False,  # allow self-signed certs during pentesting
        ) as client:
            response = await client.request(method, url, headers=headers, content=body)
    except httpx.RequestError as exc:
        await audit.log_tool_call("fetch_url", url, params, result="failed", error=str(exc))
        return {
            "tool": "fetch_url",
            "url": url,
            "status_code": 0,
            "body": "",
            "headers": {},
            "error": str(exc),
        }

    await ctx.report_progress(1, 1, "Fetch complete")
    await audit.log_tool_call("fetch_url", url, params, result="completed")

    body = response.text
    truncated = len(body.encode("utf-8", errors="ignore")) > _MAX_BODY_BYTES
    if truncated:
        body = body[:_MAX_BODY_BYTES]

    return {
        "tool": "fetch_url",
        "url": str(response.url),
        "status_code": response.status_code,
        "body": body,
        "body_truncated": truncated,
        "headers": dict(response.headers),
        "error": None,
    }
