"""Unit tests for Tengu custom exceptions."""

from __future__ import annotations

import pytest

from tengu.exceptions import (
    ConfigError,
    InvalidInputError,
    MetasploitConnectionError,
    RateLimitError,
    ScanTimeoutError,
    TargetNotAllowedError,
    TenguError,
    ToolExecutionError,
    ToolNotFoundError,
    ZAPConnectionError,
)


class TestTenguError:
    def test_is_exception(self):
        err = TenguError("base error")
        assert isinstance(err, Exception)

    def test_message(self):
        err = TenguError("something failed")
        assert "something failed" in str(err)


class TestTargetNotAllowedError:
    def test_is_tengu_error(self):
        err = TargetNotAllowedError("10.0.0.1")
        assert isinstance(err, TenguError)

    def test_target_attribute(self):
        err = TargetNotAllowedError("evil.com")
        assert err.target == "evil.com"

    def test_message_includes_target(self):
        err = TargetNotAllowedError("192.168.1.1")
        assert "192.168.1.1" in str(err)

    def test_reason_included_when_provided(self):
        err = TargetNotAllowedError("10.0.0.1", reason="blocklisted")
        assert "blocklisted" in str(err)

    def test_no_reason_omits_colon(self):
        err = TargetNotAllowedError("10.0.0.1")
        assert str(err).endswith("not allowed")

    def test_can_be_raised_and_caught(self):
        with pytest.raises(TargetNotAllowedError):
            raise TargetNotAllowedError("127.0.0.1")


class TestToolNotFoundError:
    def test_is_tengu_error(self):
        err = ToolNotFoundError("nmap")
        assert isinstance(err, TenguError)

    def test_tool_attribute(self):
        err = ToolNotFoundError("sqlmap")
        assert err.tool == "sqlmap"

    def test_message_includes_tool(self):
        err = ToolNotFoundError("nuclei")
        assert "nuclei" in str(err)

    def test_message_includes_install_hint(self):
        err = ToolNotFoundError("hydra")
        assert "install" in str(err).lower() or "make" in str(err).lower()


class TestToolExecutionError:
    def test_is_tengu_error(self):
        err = ToolExecutionError("nmap", 1)
        assert isinstance(err, TenguError)

    def test_tool_attribute(self):
        err = ToolExecutionError("sqlmap", 2)
        assert err.tool == "sqlmap"

    def test_returncode_attribute(self):
        err = ToolExecutionError("nmap", 127)
        assert err.returncode == 127

    def test_stderr_attribute(self):
        err = ToolExecutionError("ffuf", 1, stderr="command not found")
        assert err.stderr == "command not found"

    def test_message_includes_returncode(self):
        err = ToolExecutionError("nmap", 255)
        assert "255" in str(err)

    def test_stderr_truncated_at_500_chars(self):
        long_stderr = "x" * 1000
        err = ToolExecutionError("tool", 1, stderr=long_stderr)
        # Message should not include all 1000 chars
        assert len(str(err)) < 1100


class TestScanTimeoutError:
    def test_is_tengu_error(self):
        err = ScanTimeoutError("nmap", 300)
        assert isinstance(err, TenguError)

    def test_tool_attribute(self):
        err = ScanTimeoutError("masscan", 60)
        assert err.tool == "masscan"

    def test_timeout_attribute(self):
        err = ScanTimeoutError("nuclei", 120)
        assert err.timeout == 120

    def test_message_includes_tool_and_timeout(self):
        err = ScanTimeoutError("nmap", 300)
        assert "nmap" in str(err)
        assert "300" in str(err)

    def test_partial_output_defaults_empty(self):
        err = ScanTimeoutError("nmap", 300)
        assert err.partial_stdout == ""
        assert err.partial_stderr == ""

    def test_partial_output_stored(self):
        err = ScanTimeoutError(
            "nikto", 400,
            partial_stdout="+ [750500] /config/: Directory indexing found.",
            partial_stderr="some warning",
        )
        assert err.partial_stdout == "+ [750500] /config/: Directory indexing found."
        assert err.partial_stderr == "some warning"


class TestRateLimitError:
    def test_is_tengu_error(self):
        err = RateLimitError()
        assert isinstance(err, TenguError)

    def test_default_message(self):
        err = RateLimitError()
        assert "rate" in str(err).lower() or "limit" in str(err).lower()

    def test_custom_message(self):
        err = RateLimitError("Too many requests, slow down")
        assert "slow down" in str(err)


class TestInvalidInputError:
    def test_is_tengu_error(self):
        err = InvalidInputError("target", "'; DROP TABLE --")
        assert isinstance(err, TenguError)

    def test_field_attribute(self):
        err = InvalidInputError("domain", "evil; rm -rf /")
        assert err.field == "domain"

    def test_value_attribute(self):
        err = InvalidInputError("target", "bad_value")
        assert err.value == "bad_value"

    def test_message_includes_field_and_value(self):
        err = InvalidInputError("ip", "not.an.ip")
        assert "ip" in str(err)
        assert "not.an.ip" in str(err)

    def test_reason_included_when_provided(self):
        err = InvalidInputError("url", "ftp://x", reason="only http/https allowed")
        assert "only http/https allowed" in str(err)


class TestConfigError:
    def test_is_tengu_error(self):
        err = ConfigError("bad config")
        assert isinstance(err, TenguError)


class TestMetasploitConnectionError:
    def test_is_tengu_error(self):
        err = MetasploitConnectionError("localhost:55553")
        assert isinstance(err, TenguError)

    def test_message_includes_host(self):
        err = MetasploitConnectionError("10.0.0.5:55553")
        assert "10.0.0.5" in str(err)

    def test_reason_included_when_provided(self):
        err = MetasploitConnectionError("localhost", reason="connection refused")
        assert "connection refused" in str(err)


class TestZAPConnectionError:
    def test_is_tengu_error(self):
        err = ZAPConnectionError("http://localhost:8080")
        assert isinstance(err, TenguError)

    def test_message_includes_url(self):
        err = ZAPConnectionError("http://localhost:8080")
        assert "localhost" in str(err)

    def test_reason_included_when_provided(self):
        err = ZAPConnectionError("http://zap:8080", reason="API key invalid")
        assert "API key invalid" in str(err)
