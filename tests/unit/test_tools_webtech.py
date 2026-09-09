"""Unit tests for the whatweb_scan async tool (webtech fingerprinting)."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

TOOL_MODULE = "tengu.tools.osint.webtech"


def _make_rate_limited_mock():
    mock_rl = MagicMock()

    @asynccontextmanager
    async def _fake(*args, **kwargs):
        yield

    mock_rl.side_effect = _fake
    return mock_rl


def _make_fixtures(*, allowlist_raises=False, run_stdout="", run_stderr="", run_rc=0):
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()

    cfg = MagicMock()
    cfg.tools.defaults.scan_timeout = 300

    audit = MagicMock()
    audit.log_tool_call = AsyncMock()
    audit.log_target_blocked = AsyncMock()

    allowlist = MagicMock()
    if allowlist_raises:
        allowlist.check.side_effect = ValueError("blocked")
    else:
        allowlist.check.return_value = None

    return {
        "ctx": ctx,
        "cfg": cfg,
        "audit": audit,
        "allowlist": allowlist,
        "run_return": (run_stdout, run_stderr, run_rc),
    }


def _make_whatweb_json_line(
    target="http://example.com",
    http_status=200,
    plugins=None,
):
    """Build a valid WhatWeb JSON-per-line entry."""
    if plugins is None:
        plugins = {}
    entry = {
        "target": target,
        "http_status": http_status,
        "plugins": plugins,
    }
    return json.dumps([entry])


async def _call_whatweb(mocks, target="http://example.com", aggression=1, cookie="", timeout=None):
    from tengu.tools.osint.webtech import whatweb_scan

    with (
        patch(f"{TOOL_MODULE}.get_config", return_value=mocks["cfg"]),
        patch(f"{TOOL_MODULE}.get_audit_logger", return_value=mocks["audit"]),
        patch(f"{TOOL_MODULE}.make_allowlist_from_config", return_value=mocks["allowlist"]),
        patch(f"{TOOL_MODULE}.resolve_tool_path", return_value="/usr/bin/whatweb"),
        patch(f"{TOOL_MODULE}.sanitize_url", side_effect=lambda u: u),
        patch(f"{TOOL_MODULE}.run_command", new=AsyncMock(return_value=mocks["run_return"])),
        patch(f"{TOOL_MODULE}.rate_limited", new=_make_rate_limited_mock()),
    ):
        return await whatweb_scan(mocks["ctx"], target, aggression=aggression, cookie=cookie, timeout=timeout)


# ---------------------------------------------------------------------------
# TestWhatweb
# ---------------------------------------------------------------------------


class TestWhatweb:
    async def test_aggression_clamped_min(self):
        mocks = _make_fixtures()
        result = await _call_whatweb(mocks, aggression=0)
        assert result["aggression"] == 1
        assert "--aggression=1" in result["command"]

    async def test_aggression_clamped_max(self):
        mocks = _make_fixtures()
        result = await _call_whatweb(mocks, aggression=5)
        assert result["aggression"] == 4
        assert "--aggression=4" in result["command"]

    async def test_json_output_parsed(self):
        plugins = {
            "Apache": {"version": ["2.4.51"], "string": ["Apache/2.4.51"]},
        }
        stdout = _make_whatweb_json_line(plugins=plugins)
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_whatweb(mocks)
        assert result["plugins_found"] == 1
        plugin = result["technologies"][0]
        assert plugin["name"] == "Apache"
        assert plugin["version"] == "2.4.51"
        assert plugin["detail"] == "Apache/2.4.51"

    async def test_plugin_no_version(self):
        plugins = {"WordPress": {"version": [], "string": ["wp-content"]}}
        stdout = _make_whatweb_json_line(plugins=plugins)
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_whatweb(mocks)
        assert result["technologies"][0]["version"] is None

    async def test_plugin_no_detail(self):
        plugins = {"PHP": {"version": ["8.1"], "string": []}}
        stdout = _make_whatweb_json_line(plugins=plugins)
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_whatweb(mocks)
        assert result["technologies"][0]["detail"] is None
        assert result["technologies"][0]["version"] == "8.1"

    async def test_fallback_plain_text_parsed(self):
        stdout = "http://example.com [200 OK] Apache[2.4], PHP[8.1]\n"
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_whatweb(mocks)
        # Falls back to plain text; lines containing [ and ] become entries
        assert result["plugins_found"] >= 1
        assert result["technologies"][0]["version"] is None

    async def test_multiple_plugins_extracted(self):
        plugins = {
            "Apache": {"version": ["2.4"], "string": []},
            "PHP": {"version": ["8.0"], "string": ["PHP/8.0"]},
            "WordPress": {"version": [], "string": []},
        }
        stdout = _make_whatweb_json_line(plugins=plugins)
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_whatweb(mocks)
        assert result["plugins_found"] == 3
        names = {t["name"] for t in result["technologies"]}
        assert {"Apache", "PHP", "WordPress"} == names

    async def test_allowlist_blocked_raises(self):
        mocks = _make_fixtures(allowlist_raises=True)
        with pytest.raises(ValueError, match="blocked"):
            await _call_whatweb(mocks, target="http://blocked.com")

    async def test_returns_correct_structure(self):
        mocks = _make_fixtures()
        result = await _call_whatweb(mocks)
        for key in (
            "tool",
            "target",
            "http_status",
            "aggression",
            "command",
            "duration_seconds",
            "plugins_found",
            "technologies",
            "raw_output",
        ):
            assert key in result, f"Missing key: {key}"
        assert result["tool"] == "whatweb"

    async def test_http_status_extracted_from_json(self):
        stdout = _make_whatweb_json_line(http_status=403)
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_whatweb(mocks)
        assert result["http_status"] == 403

    async def test_cookie_included_in_command(self):
        mocks = _make_fixtures()
        result = await _call_whatweb(mocks, cookie="PHPSESSID=abc123; security=low")
        assert "--cookie=PHPSESSID=abc123; security=low" in result["command"]

    async def test_no_cookie_flag_when_cookie_empty(self):
        mocks = _make_fixtures()
        result = await _call_whatweb(mocks)
        assert "--cookie=" not in result["command"]

    async def test_cookie_strips_crlf_and_null(self):
        mocks = _make_fixtures()
        result = await _call_whatweb(mocks, cookie="PHPSESSID=abc\r\n123\x00")
        assert "--cookie=PHPSESSID=abc123" in result["command"]
        assert "\r" not in result["command"]
        assert "\n" not in result["command"]


class TestWhatwebMultilineOutput:
    """Regression: whatweb --log-json emits a JSON ARRAY pretty-printed across
    MULTIPLE lines (opening '[' on its own line). The original parser did
    json.loads() per line, so '[' threw and the entire result fell through to a
    text fallback that recorded the whole JSON blob as one bogus 'technology'
    with http_status left None. Confirmed live against whatweb 0.6.4 / Mutillidae
    (http_status None wrongly flagged the target unreachable downstream). The
    single-line fixtures the other tests use never exercised this."""

    @pytest.mark.asyncio
    async def test_pretty_printed_array_parses_status_and_plugins(self):
        entry = {
            "target": "http://mutillidae.local",
            "http_status": 200,
            "plugins": {
                "Apache": {"version": ["2.4.67"], "string": []},
                "PHP": {"version": ["8.5.7"], "string": ["PHP/8.5.7"]},
                "HTML5": {},
            },
        }
        stdout = json.dumps([entry], indent=2)  # real multi-line shape
        assert stdout.splitlines()[0].strip() == "["
        mocks = _make_fixtures(run_stdout=stdout)
        result = await _call_whatweb(mocks, target="http://mutillidae.local")

        assert result["http_status"] == 200
        assert result["plugins_found"] == 3
        by_name = {p["name"]: p for p in result["technologies"]}
        assert by_name["Apache"]["version"] == "2.4.67"
        assert by_name["PHP"]["version"] == "8.5.7"
        # the whole-blob bogus technology must NOT appear
        assert not any(t["name"].strip().startswith(("[", "{")) for t in result["technologies"])

    @pytest.mark.asyncio
    async def test_bare_object_output_also_parses(self):
        """Defensive: some builds emit a bare object, not an array."""
        entry = {"target": "http://t", "http_status": 200,
                 "plugins": {"nginx": {"version": ["1.25"], "string": []}}}
        mocks = _make_fixtures(run_stdout=json.dumps(entry))
        result = await _call_whatweb(mocks, target="http://t")
        assert result["http_status"] == 200
        assert result["technologies"][0]["name"] == "nginx"
