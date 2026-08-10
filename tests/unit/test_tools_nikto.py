"""Unit tests for Nikto web scanner output parser and async nikto_scan function.

Nikto's -Format/-output flags for structured output (JSON/XML/CSV) were
verified live to be broken in the 2.6.0 build this project ships — no
output file is ever produced regardless of flag combination (-o vs
-output, with/without explicit -Format, .json extension inference all
tested). The tool wrapper no longer requests structured output at all and
parses plain-text stdout exclusively — that's the only format nikto
actually emits.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import ScanTimeoutError
from tengu.tools.web.nikto import _parse_nikto_output, nikto_scan

# ---------------------------------------------------------------------------
# TestParseNiktoOutput
# ---------------------------------------------------------------------------


class TestParseNiktoOutput:
    def test_empty_string_returns_empty(self):
        assert _parse_nikto_output("") == []

    def test_bracketed_finding_extracted(self):
        text = "+ [700001] /test: Server leaks information"
        result = _parse_nikto_output(text)
        assert len(result) == 1
        assert result[0]["id"] == "700001"

    def test_message_extracted(self):
        text = "+ [700001] /test: Apache version disclosure"
        result = _parse_nikto_output(text)
        assert result[0]["message"] == "Apache version disclosure"

    def test_url_extracted(self):
        text = "+ [700001] /admin/config.php: something found"
        result = _parse_nikto_output(text)
        assert result[0]["url"] == "/admin/config.php"

    def test_finding_without_leading_path_has_empty_url(self):
        # Not every finding message starts with a "/path:" prefix — nikto's
        # own outdated-software notices are just prose after the ID.
        text = "+ [600050] Apache/2.4.25 appears to be outdated (current is at least 2.4.66)."
        result = _parse_nikto_output(text)
        assert result[0]["url"] == ""
        assert result[0]["message"] == "Apache/2.4.25 appears to be outdated (current is at least 2.4.66)."

    def test_multiple_findings(self):
        text = "\n".join(
            f"+ [{i}] /test: finding {i}" for i in range(5)
        )
        result = _parse_nikto_output(text)
        assert len(result) == 5

    def test_metadata_banner_lines_excluded(self):
        """Nikto's scan-metadata lines look identical to findings under a
        naive "starts with +" scan but carry no bracketed ID — verified live
        these were previously counted as findings (24 "findings" vs nikto's
        own self-reported 14 items)."""
        text = "\n".join([
            "+ Target IP:          172.20.0.2",
            "+ Target Hostname:    dvwa.local",
            "+ Target Port:        80",
            "+ Platform:           Linux/Unix",
            "+ Start Time:         2026-08-10 09:11:53 (GMT0)",
            "+ Server: Apache/2.4.25 (Debian)",
            "+ ERROR: Failed to check for updates: 403",
            "+ No CGI Directories found (use '-C all' to force check all possible dirs). CGI tests skipped.",
            "+ End Time:           2026-08-10 09:17:16 (GMT0) (323 seconds)",
            "+ 1 host(s) tested",
        ])
        assert _parse_nikto_output(text) == []

    def test_only_real_findings_counted_among_mixed_output(self):
        text = "\n".join([
            "+ Target IP:          172.20.0.2",
            "+ [750500] /config/: Directory indexing found.",
            "+ No CGI Directories found (use '-C all' to force check all possible dirs). CGI tests skipped.",
            "+ [006333] /login.php: Admin login page/section found.",
            "+ 1 host(s) tested",
        ])
        result = _parse_nikto_output(text)
        assert len(result) == 2
        assert {f["id"] for f in result} == {"750500", "006333"}

    def test_non_plus_lines_excluded(self):
        text = "- Nikto v2.6.0\n+ [95] /: Server: Apache/2.4.49\n[INFO] scan complete"
        result = _parse_nikto_output(text)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Helpers for nikto_scan tests
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_nikto_config(scan_timeout=300, nikto_path=None):
    cfg = MagicMock()
    cfg.tools.defaults.scan_timeout = scan_timeout
    cfg.tools.paths.nikto = nikto_path
    return cfg


def _make_rate_limited_mock():
    mock_rl_ctx = MagicMock()
    mock_rl_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    mock_rl_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_rl_ctx


# ---------------------------------------------------------------------------
# TestNiktoScan
# ---------------------------------------------------------------------------


class TestNiktoScan:
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    async def test_nikto_blocked_url(self, mock_audit_fn, mock_allowlist_fn, mock_config, mock_ctx):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.side_effect = Exception("Blocked")
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_target_blocked = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        with pytest.raises(Exception, match="Blocked"):
            await nikto_scan(mock_ctx, "https://example.com")

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_tuning_flag(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await nikto_scan(mock_ctx, "https://example.com", tuning="1234")
        args = mock_run.call_args[0][0]
        assert "-Tuning" in args
        t_idx = args.index("-Tuning")
        assert args[t_idx + 1] == "1234"

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_ssl_flag(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await nikto_scan(mock_ctx, "https://example.com", ssl=True)
        args = mock_run.call_args[0][0]
        assert "-ssl" in args

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_custom_port(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        await nikto_scan(mock_ctx, "https://example.com", port=8080)
        args = mock_run.call_args[0][0]
        assert "-port" in args
        p_idx = args.index("-port")
        assert args[p_idx + 1] == "8080"

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_stealth_proxy(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)

        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = True
        mock_stealth_layer.proxy_url = "http://127.0.0.1:8080"
        mock_stealth_layer.inject_proxy_flags.side_effect = lambda tool, args: (
            args + ["-useproxy", "http://127.0.0.1:8080"]
        )
        mock_stealth.return_value = mock_stealth_layer

        await nikto_scan(mock_ctx, "https://example.com")
        args = mock_run.call_args[0][0]
        assert "-useproxy" in args

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_output_parsing(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        nikto_text = "+ [700001] /: Apache server version disclosure"
        mock_run.return_value = (nikto_text, "", 0)

        result = await nikto_scan(mock_ctx, "https://example.com")
        assert result["findings_count"] == 1
        assert result["findings"][0]["message"] == "Apache server version disclosure"
        assert result["timed_out"] is False

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_default_scan(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        result = await nikto_scan(mock_ctx, "https://example.com")
        args = mock_run.call_args[0][0]
        # Nikto requires -h flag
        assert "-h" in args
        assert result["tool"] == "nikto"

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_run_error(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        mock_run.side_effect = Exception("nikto not found")

        with pytest.raises(Exception, match="nikto not found"):
            await nikto_scan(mock_ctx, "https://example.com")

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_tool_key(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_run.return_value = ("", "", 0)
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        result = await nikto_scan(mock_ctx, "https://example.com")
        assert result["tool"] == "nikto"

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_timeout_salvages_partial_findings(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        """A scan that runs out of time has still found real things along the
        way — verified live nikto needs ~5x a previously-too-short timeout,
        and every run before this fix silently returned nothing. The
        executor now surfaces whatever stdout was captured before the kill
        via ScanTimeoutError.partial_stdout instead of losing it."""
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        partial_output = "+ [750500] /config/: Directory indexing found."
        mock_run.side_effect = ScanTimeoutError("nikto", 400, partial_stdout=partial_output)

        result = await nikto_scan(mock_ctx, "https://example.com")

        assert result["timed_out"] is True
        assert result["findings_count"] == 1
        assert result["findings"][0]["id"] == "750500"

    @patch("tengu.tools.web.nikto.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.web.nikto.get_config")
    @patch("tengu.tools.web.nikto.make_allowlist_from_config")
    @patch("tengu.tools.web.nikto.get_audit_logger")
    @patch("tengu.tools.web.nikto.resolve_tool_path", return_value="/usr/bin/nikto")
    @patch("tengu.tools.web.nikto.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_nikto_timeout_with_no_partial_output_returns_empty_not_raise(
        self,
        mock_stealth,
        mock_rl,
        mock_resolve,
        mock_audit_fn,
        mock_allowlist_fn,
        mock_config,
        mock_run,
        mock_ctx,
    ):
        mock_config.return_value = _make_nikto_config()
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit
        mock_rl.return_value = _make_rate_limited_mock()
        mock_stealth_layer = MagicMock()
        mock_stealth_layer.enabled = False
        mock_stealth_layer.proxy_url = None
        mock_stealth.return_value = mock_stealth_layer

        mock_run.side_effect = ScanTimeoutError("nikto", 400)

        result = await nikto_scan(mock_ctx, "https://example.com")

        assert result["timed_out"] is True
        assert result["findings_count"] == 0
        assert result["findings"] == []
