"""Unit tests for AuditLogger and _redact_sensitive helper."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from tengu.security.audit import _SENSITIVE_KEYS, AuditLogger, _redact_sensitive

# ---------------------------------------------------------------------------
# TestRedactSensitive
# ---------------------------------------------------------------------------


class TestRedactSensitive:
    def test_non_sensitive_keys_preserved(self):
        params = {"target": "10.0.0.1", "port": 80}
        result = _redact_sensitive(params)
        assert result == params

    def test_password_redacted(self):
        params = {"password": "supersecret"}
        result = _redact_sensitive(params)
        assert result["password"] == "[REDACTED]"

    def test_token_redacted(self):
        params = {"token": "my-api-token"}
        result = _redact_sensitive(params)
        assert result["token"] == "[REDACTED]"

    def test_api_key_redacted(self):
        params = {"api_key": "sk-abc123"}
        result = _redact_sensitive(params)
        assert result["api_key"] == "[REDACTED]"

    def test_passlist_redacted(self):
        params = {"passlist": "/path/to/rockyou.txt"}
        result = _redact_sensitive(params)
        assert result["passlist"] == "[REDACTED]"

    def test_credentials_redacted(self):
        params = {"credentials": "admin:password"}
        result = _redact_sensitive(params)
        assert result["credentials"] == "[REDACTED]"

    def test_cookie_redacted(self):
        params = {"cookie": "PHPSESSID=abc123; security=low"}
        result = _redact_sensitive(params)
        assert result["cookie"] == "[REDACTED]"

    def test_case_insensitive_key_matching(self):
        params = {"PASSWORD": "secret", "Token": "tok"}
        result = _redact_sensitive(params)
        assert result["PASSWORD"] == "[REDACTED]"
        assert result["Token"] == "[REDACTED]"

    def test_empty_params_returns_empty(self):
        assert _redact_sensitive({}) == {}

    def test_mixed_params(self):
        params = {"target": "10.0.0.1", "password": "pw123", "port": 22}
        result = _redact_sensitive(params)
        assert result["target"] == "10.0.0.1"
        assert result["password"] == "[REDACTED]"
        assert result["port"] == 22


# ---------------------------------------------------------------------------
# TestSensitiveKeys
# ---------------------------------------------------------------------------


class TestSensitiveKeys:
    def test_is_frozenset(self):
        assert isinstance(_SENSITIVE_KEYS, frozenset)

    def test_password_present(self):
        assert "password" in _SENSITIVE_KEYS

    def test_token_present(self):
        assert "token" in _SENSITIVE_KEYS

    def test_api_key_present(self):
        assert "api_key" in _SENSITIVE_KEYS

    def test_cookie_present(self):
        assert "cookie" in _SENSITIVE_KEYS

    def test_all_lowercase(self):
        for key in _SENSITIVE_KEYS:
            assert key == key.lower()


# ---------------------------------------------------------------------------
# TestAuditLogger
# ---------------------------------------------------------------------------


class TestAuditLogger:
    def _make_logger(self) -> tuple[AuditLogger, Path]:
        tmp = tempfile.mktemp(suffix=".jsonl")
        logger = AuditLogger(tmp)
        return logger, Path(tmp)

    @pytest.mark.asyncio
    async def test_log_tool_call_creates_file(self):
        audit, path = self._make_logger()
        await audit.log_tool_call("nmap", "10.0.0.1", {"port": 80})
        assert path.exists()

    @pytest.mark.asyncio
    async def test_log_tool_call_writes_json(self):
        audit, path = self._make_logger()
        await audit.log_tool_call("nmap", "10.0.0.1", {"port": 80})
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["tool"] == "nmap"
        assert record["target"] == "10.0.0.1"

    @pytest.mark.asyncio
    async def test_log_tool_call_event_type(self):
        audit, path = self._make_logger()
        await audit.log_tool_call("nuclei", "example.com", {})
        record = json.loads(path.read_text().strip())
        assert record["event"] == "tool_call"

    @pytest.mark.asyncio
    async def test_log_tool_call_with_error(self):
        audit, path = self._make_logger()
        await audit.log_tool_call("nmap", "10.0.0.1", {}, result="failed", error="timeout")
        record = json.loads(path.read_text().strip())
        assert record["error"] == "timeout"

    @pytest.mark.asyncio
    async def test_log_tool_call_with_duration(self):
        audit, path = self._make_logger()
        await audit.log_tool_call("nmap", "10.0.0.1", {}, duration_seconds=12.345)
        record = json.loads(path.read_text().strip())
        assert record["duration_seconds"] == 12.345

    @pytest.mark.asyncio
    async def test_log_target_blocked(self):
        audit, path = self._make_logger()
        await audit.log_target_blocked("nmap", "127.0.0.1", "loopback blocked")
        record = json.loads(path.read_text().strip())
        assert record["event"] == "target_blocked"
        assert record["reason"] == "loopback blocked"

    @pytest.mark.asyncio
    async def test_log_rate_limit(self):
        audit, path = self._make_logger()
        await audit.log_rate_limit("nmap", "exceeded 5 req/s")
        record = json.loads(path.read_text().strip())
        assert record["event"] == "rate_limit"
        assert "exceeded" in record["details"]

    @pytest.mark.asyncio
    async def test_multiple_records_appended(self):
        audit, path = self._make_logger()
        await audit.log_tool_call("nmap", "10.0.0.1", {})
        await audit.log_tool_call("nuclei", "10.0.0.2", {})
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 2

    @pytest.mark.asyncio
    async def test_sensitive_params_redacted_in_log(self):
        audit, path = self._make_logger()
        await audit.log_tool_call("hydra", "10.0.0.1", {"password": "hunter2", "target": "ssh"})
        record = json.loads(path.read_text().strip())
        assert record["params"]["password"] == "[REDACTED]"
        assert record["params"]["target"] == "ssh"

    @pytest.mark.asyncio
    async def test_timestamp_present(self):
        audit, path = self._make_logger()
        await audit.log_tool_call("nmap", "10.0.0.1", {})
        record = json.loads(path.read_text().strip())
        assert "timestamp" in record
        assert "T" in record["timestamp"]  # ISO format
