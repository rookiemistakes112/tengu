"""Unit tests for commix_scan: validation, sanitization, and output parsing."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.injection.commix import _parse_commix_output

_MOD = "tengu.tools.injection.commix"


def _make_ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_rate_limited_mock() -> MagicMock:
    mock = MagicMock()
    mock.return_value.__aenter__ = AsyncMock(return_value=None)
    mock.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock


def _make_audit_mock() -> MagicMock:
    audit = MagicMock()
    audit.log_tool_call = AsyncMock()
    audit.log_target_blocked = AsyncMock()
    return audit


def _mock_stealth(enabled: bool = False, proxy_url: str = "") -> MagicMock:
    stealth = MagicMock()
    stealth.enabled = enabled
    stealth.proxy_url = proxy_url
    stealth.inject_proxy_flags = MagicMock(
        side_effect=lambda tool, args: args + ["--proxy", proxy_url]
    )
    return stealth


@pytest.fixture
def ctx():
    return _make_ctx()


async def _run_commix(
    ctx,
    url="https://example.com/ping?host=test",
    method="GET",
    data="",
    level=1,
    stdout="",
    stderr="",
    returncode=0,
    blocked=False,
):
    from tengu.tools.injection.commix import commix_scan

    rate_limited_mock = _make_rate_limited_mock()
    audit_mock = _make_audit_mock()
    cfg_mock = MagicMock()
    cfg_mock.tools.defaults.scan_timeout = 300
    allowlist_mock = MagicMock()
    if blocked:
        allowlist_mock.check.side_effect = Exception("Target not allowed")

    with (
        patch(f"{_MOD}.get_config", return_value=cfg_mock),
        patch(f"{_MOD}.get_audit_logger", return_value=audit_mock),
        patch(f"{_MOD}.rate_limited", rate_limited_mock),
        patch(f"{_MOD}.sanitize_url", return_value=url),
        patch(f"{_MOD}.resolve_tool_path", return_value="/usr/bin/commix"),
        patch(f"{_MOD}.make_allowlist_from_config", return_value=allowlist_mock),
        patch(f"{_MOD}.run_command", new=AsyncMock(return_value=(stdout, stderr, returncode))),
        patch("tengu.stealth.get_stealth_layer", return_value=_mock_stealth()),
    ):
        return await commix_scan(ctx, url, method=method, data=data, level=level)


class TestCommixScan:
    async def test_returns_tool_key(self, ctx):
        result = await _run_commix(ctx)
        assert result["tool"] == "commix"

    async def test_level_clamped_max(self, ctx):
        result = await _run_commix(ctx, level=10)
        assert result["level"] <= 3

    async def test_level_clamped_min(self, ctx):
        result = await _run_commix(ctx, level=0)
        assert result["level"] >= 1

    async def test_invalid_method_defaults_to_get(self, ctx):
        result = await _run_commix(ctx, method="PATCH")
        assert result["method"] == "GET"

    async def test_blocked_raises(self, ctx):
        with pytest.raises(Exception, match="Target not allowed"):
            await _run_commix(ctx, blocked=True)

    async def test_vulnerable_detected(self, ctx):
        out = "[+] The 'host' parameter appears to be injectable via OS command injection\n"
        result = await _run_commix(ctx, stdout=out)
        assert result["vulnerable"] is True

    async def test_not_vulnerable(self, ctx):
        result = await _run_commix(ctx, stdout="[-] No injection found")
        assert result["vulnerable"] is False

    async def test_return_keys_present(self, ctx):
        result = await _run_commix(ctx)
        for key in ("tool", "url", "method", "level", "duration_seconds", "vulnerable", "evidence"):
            assert key in result


class TestParseCommixOutput:
    def test_empty_output(self):
        result = _parse_commix_output("")
        assert result["vulnerable"] is False
        assert result["evidence"] == []

    def test_vulnerable_detected_by_plus(self):
        result = _parse_commix_output("[+] The parameter is injectable")
        assert result["vulnerable"] is True
        assert len(result["evidence"]) > 0

    def test_case_insensitive_vulnerable(self):
        # commix's real confirmation phrase, upper-cased — matching is case-insensitive.
        result = _parse_commix_output(
            "(GET) parameter 'ip' APPEARS TO BE INJECTABLE VIA (results-based) command injection technique."
        )
        assert result["vulnerable"] is True

    def test_evidence_capped_at_20(self):
        line = "(GET) parameter 'ip' appears to be injectable via technique {i}"
        output = "\n".join(line.format(i=i) for i in range(30))
        result = _parse_commix_output(output)
        assert len(result["evidence"]) <= 20

    # --- Regression: commix v4.1 heuristic false positives (DVWA, 2026-09-11) ---
    # The old matcher keyed on "parameter"+"injectable", which matched commix's
    # NEGATIVE heuristic line "<param> might not be injectable" and flagged every
    # scanned URL as vulnerable (~93% false positives against DVWA).

    def test_heuristic_negative_is_not_vulnerable(self):
        # This exact shape (minus ANSI) came back vulnerable:true for all 14 URLs.
        line = (
            "[warning] Heuristic (basic) tests show that GET parameter "
            "'name' might not be injectable."
        )
        result = _parse_commix_output(line)
        assert result["vulnerable"] is False
        assert result["evidence"] == []

    def test_heuristic_maybe_injectable_is_not_confirmed(self):
        # "might be injectable" is a guess commix prints before it actually tests;
        # only "appears to be injectable via <technique>" confirms an exploit.
        line = (
            "[info] Heuristic (basic) test shows that GET parameter "
            "'ip' might be injectable (possible OS: 'Unix-like')."
        )
        result = _parse_commix_output(line)
        assert result["vulnerable"] is False

    def test_self_flagged_false_positive_is_not_vulnerable(self):
        line = "[warning] False positive or unexploitable injection point has been detected."
        result = _parse_commix_output(line)
        assert result["vulnerable"] is False

    def test_confirmed_injectable_via_is_vulnerable(self):
        line = (
            "[info] (GET) parameter 'ip' appears to be injectable via "
            "(results-based) command injection technique."
        )
        result = _parse_commix_output(line)
        assert result["vulnerable"] is True
        assert len(result["evidence"]) == 1

    def test_negative_amid_confirmation_still_confirms(self):
        # A real scan prints both the early negative heuristic for other params
        # AND the confirmation for the injectable one — the confirmation wins.
        output = (
            "[warning] Heuristic (basic) tests show that GET parameter 'a' might not be injectable.\n"
            "[info] (GET) parameter 'ip' appears to be injectable via (results-based) technique.\n"
        )
        result = _parse_commix_output(output)
        assert result["vulnerable"] is True
        assert len(result["evidence"]) == 1
