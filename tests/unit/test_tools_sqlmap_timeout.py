"""Unit tests for sqlmap_scan's timeout-salvage behavior.

sqlmap previously re-raised ScanTimeoutError, discarding every finding a
slow-but-working scan had already made before being killed — unlike
nikto.py/ffuf.py, which salvage exc.partial_stdout instead. This mirrors
that same fix for sqlmap.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.exceptions import ScanTimeoutError
from tengu.tools.injection.sqlmap import sqlmap_scan


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_sqlmap_config(scan_timeout=600, sqlmap_path=None):
    cfg = MagicMock()
    cfg.tools.defaults.scan_timeout = scan_timeout
    cfg.tools.paths.sqlmap = sqlmap_path
    return cfg


def _make_rate_limited_mock():
    mock_rl_ctx = MagicMock()
    mock_rl_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    mock_rl_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_rl_ctx


class TestSqlmapScanTimeout:
    @patch("tengu.tools.injection.sqlmap.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.injection.sqlmap.get_config")
    @patch("tengu.tools.injection.sqlmap.make_allowlist_from_config")
    @patch("tengu.tools.injection.sqlmap.get_audit_logger")
    @patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap")
    @patch("tengu.tools.injection.sqlmap.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_sqlmap_timeout_salvages_partial_findings(
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
        mock_config.return_value = _make_sqlmap_config()
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

        partial_output = (
            "sqlmap identified the following injection point(s)\n"
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
            "parameter 'id' is vulnerable\n"
            "back-end DBMS: MySQL >= 5.0.12\n"
        )
        mock_run.side_effect = ScanTimeoutError("sqlmap", 600, partial_stdout=partial_output)

        result = await sqlmap_scan(mock_ctx, "https://example.com/?id=1")

        assert result["timed_out"] is True
        assert result["vulnerable"] is True
        assert result["vulnerable_parameters"] == ["id"]
        assert result["dbms"] == "MySQL >= 5.0.12"

    @patch("tengu.tools.injection.sqlmap.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.injection.sqlmap.get_config")
    @patch("tengu.tools.injection.sqlmap.make_allowlist_from_config")
    @patch("tengu.tools.injection.sqlmap.get_audit_logger")
    @patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap")
    @patch("tengu.tools.injection.sqlmap.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_sqlmap_timeout_with_no_partial_output_returns_empty_not_raise(
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
        mock_config.return_value = _make_sqlmap_config()
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

        mock_run.side_effect = ScanTimeoutError("sqlmap", 600)

        result = await sqlmap_scan(mock_ctx, "https://example.com/?id=1")

        assert result["timed_out"] is True
        assert result["vulnerable"] is False
        assert result["vulnerable_parameters"] == []

    @patch("tengu.tools.injection.sqlmap.run_command", new_callable=AsyncMock)
    @patch("tengu.tools.injection.sqlmap.get_config")
    @patch("tengu.tools.injection.sqlmap.make_allowlist_from_config")
    @patch("tengu.tools.injection.sqlmap.get_audit_logger")
    @patch("tengu.tools.injection.sqlmap.resolve_tool_path", return_value="/usr/bin/sqlmap")
    @patch("tengu.tools.injection.sqlmap.rate_limited")
    @patch("tengu.stealth.get_stealth_layer")
    async def test_sqlmap_no_timeout_reports_timed_out_false(
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
        mock_config.return_value = _make_sqlmap_config()
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
        mock_run.return_value = ("", "", 0)

        result = await sqlmap_scan(mock_ctx, "https://example.com/?id=1")

        assert result["timed_out"] is False
