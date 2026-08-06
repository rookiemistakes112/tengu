"""Unit tests for the generic fetch_url tool."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from tengu.tools.web.fetch_url import _MAX_BODY_BYTES, fetch_url


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _make_stealth_client_with_response(response):
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.request = AsyncMock(return_value=response)

    mock_stealth_layer = MagicMock()
    mock_stealth_layer.create_http_client.return_value = mock_client

    return mock_stealth_layer, mock_client


def _make_response(status_code=200, text="hello", url="https://example.com", headers=None):
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.text = text
    mock_response.url = url
    mock_response.headers = headers or {"content-type": "text/html"}
    return mock_response


class TestFetchUrl:
    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.fetch_url.make_allowlist_from_config")
    @patch("tengu.tools.web.fetch_url.get_audit_logger")
    async def test_blocked_url_raises(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.side_effect = Exception("Target blocked")
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_target_blocked = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        with pytest.raises(Exception, match="Target blocked"):
            await fetch_url(mock_ctx, "https://example.com")

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.fetch_url.make_allowlist_from_config")
    @patch("tengu.tools.web.fetch_url.get_audit_logger")
    async def test_request_error_returns_error_dict_not_raise(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.request = AsyncMock(side_effect=httpx.RequestError("connection refused"))

        mock_stealth_layer = MagicMock()
        mock_stealth_layer.create_http_client.return_value = mock_client
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await fetch_url(mock_ctx, "https://example.com")
        assert result["tool"] == "fetch_url"
        assert result["status_code"] == 0
        assert result["error"] is not None

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.fetch_url.make_allowlist_from_config")
    @patch("tengu.tools.web.fetch_url.get_audit_logger")
    async def test_successful_fetch_returns_status_and_body(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_response = _make_response(status_code=200, text="<html>hi</html>")
        mock_stealth_layer, _ = _make_stealth_client_with_response(mock_response)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await fetch_url(mock_ctx, "https://example.com")
        assert result["tool"] == "fetch_url"
        assert result["status_code"] == 200
        assert result["body"] == "<html>hi</html>"
        assert result["error"] is None
        assert result["body_truncated"] is False

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.fetch_url.make_allowlist_from_config")
    @patch("tengu.tools.web.fetch_url.get_audit_logger")
    async def test_headers_forwarded_to_request(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_response = _make_response()
        mock_stealth_layer, mock_client = _make_stealth_client_with_response(mock_response)
        mock_stealth_fn.return_value = mock_stealth_layer

        cookie_headers = {"Cookie": "PHPSESSID=abc123; security=low"}
        await fetch_url(mock_ctx, "https://example.com", headers=cookie_headers)

        mock_client.request.assert_awaited_once_with("GET", "https://example.com", headers=cookie_headers)

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.fetch_url.make_allowlist_from_config")
    @patch("tengu.tools.web.fetch_url.get_audit_logger")
    async def test_large_body_is_truncated(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        big_body = "a" * (_MAX_BODY_BYTES + 500)
        mock_response = _make_response(text=big_body)
        mock_stealth_layer, _ = _make_stealth_client_with_response(mock_response)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await fetch_url(mock_ctx, "https://example.com")
        assert result["body_truncated"] is True
        assert len(result["body"]) == _MAX_BODY_BYTES

    @patch("tengu.stealth.get_stealth_layer")
    @patch("tengu.tools.web.fetch_url.make_allowlist_from_config")
    @patch("tengu.tools.web.fetch_url.get_audit_logger")
    async def test_response_headers_returned_as_dict(
        self, mock_audit_fn, mock_allowlist_fn, mock_stealth_fn, mock_ctx
    ):
        mock_allowlist = MagicMock()
        mock_allowlist.check.return_value = None
        mock_allowlist_fn.return_value = mock_allowlist

        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        mock_audit_fn.return_value = mock_audit

        mock_response = _make_response(headers={"set-cookie": "session=xyz", "content-type": "application/json"})
        mock_stealth_layer, _ = _make_stealth_client_with_response(mock_response)
        mock_stealth_fn.return_value = mock_stealth_layer

        result = await fetch_url(mock_ctx, "https://example.com")
        assert result["headers"]["content-type"] == "application/json"
