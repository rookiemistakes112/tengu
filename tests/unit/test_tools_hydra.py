"""Unit tests for Hydra brute-force tool: attack function, parser, and constants."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.bruteforce.hydra import _SUPPORTED_SERVICES, _parse_hydra_output


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _mock_config():
    cfg = MagicMock()
    cfg.tools.paths.hydra = ""
    cfg.tools.defaults.scan_timeout = 300
    return cfg


def _setup_rate_limited_mock():
    mock_rl_ctx = MagicMock()
    mock_rl_ctx.__aenter__ = AsyncMock(return_value=MagicMock())
    mock_rl_ctx.__aexit__ = AsyncMock(return_value=False)
    return mock_rl_ctx


# ---------------------------------------------------------------------------
# TestHydraAttack — async tests for hydra_attack function
# ---------------------------------------------------------------------------


class TestHydraAttack:
    async def test_hydra_blocked_target(self, mock_ctx):
        """Allowlist raises — exception re-raised."""
        from tengu.tools.bruteforce.hydra import hydra_attack

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_target_blocked = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        with (
            patch("tengu.tools.bruteforce.hydra.get_config", return_value=_mock_config()),
            patch("tengu.tools.bruteforce.hydra.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.bruteforce.hydra.resolve_tool_path", return_value="/usr/bin/hydra"),
            patch("tengu.tools.bruteforce.hydra.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.bruteforce.hydra.sanitize_wordlist_path", side_effect=lambda x: x),
            patch("tengu.tools.bruteforce.hydra.make_allowlist_from_config") as mock_allowlist,
        ):
            allowlist_instance = MagicMock()
            allowlist_instance.check.side_effect = PermissionError("Target blocked")
            mock_allowlist.return_value = allowlist_instance

            with pytest.raises(PermissionError, match="Target blocked"):
                await hydra_attack(mock_ctx, "192.168.1.1", "ssh", "/users.txt", "/pass.txt")

    async def test_hydra_invalid_service(self, mock_ctx):
        """Unsupported service returns error dict."""
        from tengu.tools.bruteforce.hydra import hydra_attack

        with patch("tengu.tools.bruteforce.hydra.get_config", return_value=_mock_config()):
            result = await hydra_attack(
                mock_ctx, "192.168.1.1", "unsupportedprotocol", "/tmp/u.txt", "/tmp/p.txt"
            )

        assert "error" in result
        assert "Unsupported service" in result["error"]

    async def test_hydra_valid_service_ssh(self, mock_ctx):
        """service='ssh' runs hydra successfully."""
        from tengu.tools.bruteforce.hydra import hydra_attack

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_target_blocked = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        with (
            patch("tengu.tools.bruteforce.hydra.get_config", return_value=_mock_config()),
            patch("tengu.tools.bruteforce.hydra.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.bruteforce.hydra.resolve_tool_path", return_value="/usr/bin/hydra"),
            patch("tengu.tools.bruteforce.hydra.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.bruteforce.hydra.sanitize_wordlist_path", side_effect=lambda x: x),
            patch("tengu.tools.bruteforce.hydra.make_allowlist_from_config") as mock_allowlist,
            patch(
                "tengu.tools.bruteforce.hydra.run_command",
                AsyncMock(return_value=("output", "", 0)),
            ),
        ):
            mock_allowlist.return_value.check.return_value = None

            result = await hydra_attack(mock_ctx, "192.168.1.1", "ssh", "/tmp/u.txt", "/tmp/p.txt")

        assert result["tool"] == "hydra"
        assert result["service"] == "ssh"

    async def test_hydra_custom_port(self, mock_ctx):
        """port=2222 includes -s 2222 in command args."""
        from tengu.tools.bruteforce.hydra import hydra_attack

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        captured_args: list = []

        async def fake_run(args, timeout):
            captured_args.extend(args)
            return ("", "", 0)

        with (
            patch("tengu.tools.bruteforce.hydra.get_config", return_value=_mock_config()),
            patch("tengu.tools.bruteforce.hydra.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.bruteforce.hydra.resolve_tool_path", return_value="/usr/bin/hydra"),
            patch("tengu.tools.bruteforce.hydra.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.bruteforce.hydra.sanitize_wordlist_path", side_effect=lambda x: x),
            patch("tengu.tools.bruteforce.hydra.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.bruteforce.hydra.run_command", fake_run),
        ):
            mock_allowlist.return_value.check.return_value = None
            await hydra_attack(
                mock_ctx, "192.168.1.1", "ssh", "/tmp/u.txt", "/tmp/p.txt", port=2222
            )

        assert "-s" in captured_args
        assert "2222" in captured_args

    async def test_hydra_threads_clamped(self, mock_ctx):
        """threads=500 clamped to max 64."""
        from tengu.tools.bruteforce.hydra import hydra_attack

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        captured_args: list = []

        async def fake_run(args, timeout):
            captured_args.extend(args)
            return ("", "", 0)

        with (
            patch("tengu.tools.bruteforce.hydra.get_config", return_value=_mock_config()),
            patch("tengu.tools.bruteforce.hydra.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.bruteforce.hydra.resolve_tool_path", return_value="/usr/bin/hydra"),
            patch("tengu.tools.bruteforce.hydra.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.bruteforce.hydra.sanitize_wordlist_path", side_effect=lambda x: x),
            patch("tengu.tools.bruteforce.hydra.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.bruteforce.hydra.run_command", fake_run),
        ):
            mock_allowlist.return_value.check.return_value = None
            await hydra_attack(
                mock_ctx, "192.168.1.1", "ssh", "/tmp/u.txt", "/tmp/p.txt", threads=500
            )

        t_idx = captured_args.index("-t")
        assert int(captured_args[t_idx + 1]) <= 64

    async def test_hydra_stop_on_success(self, mock_ctx):
        """stop_on_success=True includes -f flag in args."""
        from tengu.tools.bruteforce.hydra import hydra_attack

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        captured_args: list = []

        async def fake_run(args, timeout):
            captured_args.extend(args)
            return ("", "", 0)

        with (
            patch("tengu.tools.bruteforce.hydra.get_config", return_value=_mock_config()),
            patch("tengu.tools.bruteforce.hydra.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.bruteforce.hydra.resolve_tool_path", return_value="/usr/bin/hydra"),
            patch("tengu.tools.bruteforce.hydra.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.bruteforce.hydra.sanitize_wordlist_path", side_effect=lambda x: x),
            patch("tengu.tools.bruteforce.hydra.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.bruteforce.hydra.run_command", fake_run),
        ):
            mock_allowlist.return_value.check.return_value = None
            await hydra_attack(
                mock_ctx, "192.168.1.1", "ssh", "/tmp/u.txt", "/tmp/p.txt", stop_on_success=True
            )

        assert "-f" in captured_args

    async def test_hydra_credentials_found(self, mock_ctx):
        """Hydra output with valid credential line is parsed into credentials list."""
        from tengu.tools.bruteforce.hydra import hydra_attack

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        hydra_output = "[22][ssh] host: 192.168.1.1   login: admin   password: secret\n"

        with (
            patch("tengu.tools.bruteforce.hydra.get_config", return_value=_mock_config()),
            patch("tengu.tools.bruteforce.hydra.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.bruteforce.hydra.resolve_tool_path", return_value="/usr/bin/hydra"),
            patch("tengu.tools.bruteforce.hydra.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.bruteforce.hydra.sanitize_wordlist_path", side_effect=lambda x: x),
            patch("tengu.tools.bruteforce.hydra.make_allowlist_from_config") as mock_allowlist,
            patch(
                "tengu.tools.bruteforce.hydra.run_command",
                AsyncMock(return_value=(hydra_output, "", 0)),
            ),
        ):
            mock_allowlist.return_value.check.return_value = None
            result = await hydra_attack(mock_ctx, "192.168.1.1", "ssh", "/tmp/u.txt", "/tmp/p.txt")

        assert result["valid_credentials_found"] >= 1
        assert result["credentials"][0]["username"] == "admin"
        assert result["credentials"][0]["password"] == "se***t"  # masked

    async def test_hydra_no_credentials_found(self, mock_ctx):
        """Output has no valid creds — credentials=[]."""
        from tengu.tools.bruteforce.hydra import hydra_attack

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        with (
            patch("tengu.tools.bruteforce.hydra.get_config", return_value=_mock_config()),
            patch("tengu.tools.bruteforce.hydra.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.bruteforce.hydra.resolve_tool_path", return_value="/usr/bin/hydra"),
            patch("tengu.tools.bruteforce.hydra.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.bruteforce.hydra.sanitize_wordlist_path", side_effect=lambda x: x),
            patch("tengu.tools.bruteforce.hydra.make_allowlist_from_config") as mock_allowlist,
            patch(
                "tengu.tools.bruteforce.hydra.run_command",
                AsyncMock(return_value=("[ERROR] No passwords found", "", 1)),
            ),
        ):
            mock_allowlist.return_value.check.return_value = None
            result = await hydra_attack(mock_ctx, "192.168.1.1", "ftp", "/tmp/u.txt", "/tmp/p.txt")

        assert result["credentials"] == []
        assert result["valid_credentials_found"] == 0

    async def test_hydra_tool_key(self, mock_ctx):
        """Result has tool='hydra'."""
        from tengu.tools.bruteforce.hydra import hydra_attack

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        with (
            patch("tengu.tools.bruteforce.hydra.get_config", return_value=_mock_config()),
            patch("tengu.tools.bruteforce.hydra.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.bruteforce.hydra.resolve_tool_path", return_value="/usr/bin/hydra"),
            patch("tengu.tools.bruteforce.hydra.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.bruteforce.hydra.sanitize_wordlist_path", side_effect=lambda x: x),
            patch("tengu.tools.bruteforce.hydra.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.bruteforce.hydra.run_command", AsyncMock(return_value=("", "", 0))),
        ):
            mock_allowlist.return_value.check.return_value = None
            result = await hydra_attack(mock_ctx, "192.168.1.1", "ssh", "/tmp/u.txt", "/tmp/p.txt")

        assert result["tool"] == "hydra"

    async def test_hydra_form_service_requires_form_path_and_params(self, mock_ctx):
        """*-form services need Hydra's module argument built from form_path
        + form_params — there's no sensible default login path/params, so
        this must fail loudly rather than run hydra without them (which
        would either error cryptically or hang waiting on stdin)."""
        from tengu.tools.bruteforce.hydra import hydra_attack

        with patch("tengu.tools.bruteforce.hydra.get_config", return_value=_mock_config()):
            result = await hydra_attack(
                mock_ctx, "192.168.1.1", "http-post-form", "/tmp/u.txt", "/tmp/p.txt"
            )

        assert "error" in result
        assert "form_path" in result["error"]

    async def test_hydra_form_service_builds_module_arg(self, mock_ctx):
        """Task 5.2.2 follow-up: form_path/form_params didn't exist as
        hydra_attack parameters at all — auth_failures_agent has always sent
        them into the void. Hydra's *-form modules need a single extra
        positional arg: "<path>:<post_data>:<failure_string>"."""
        from tengu.tools.bruteforce.hydra import hydra_attack

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        captured_args: list = []

        async def fake_run(args, timeout):
            captured_args.extend(args)
            return ("", "", 0)

        with (
            patch("tengu.tools.bruteforce.hydra.get_config", return_value=_mock_config()),
            patch("tengu.tools.bruteforce.hydra.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.bruteforce.hydra.resolve_tool_path", return_value="/usr/bin/hydra"),
            patch("tengu.tools.bruteforce.hydra.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.bruteforce.hydra.sanitize_wordlist_path", side_effect=lambda x: x),
            patch("tengu.tools.bruteforce.hydra.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.bruteforce.hydra.run_command", fake_run),
        ):
            mock_allowlist.return_value.check.return_value = None
            await hydra_attack(
                mock_ctx, "192.168.1.1", "http-post-form", "/tmp/u.txt", "/tmp/p.txt",
                form_path="/login",
                form_params="username=^USER^&password=^PASS^:Invalid credentials",
            )

        assert "/login:username=^USER^&password=^PASS^:Invalid credentials" in captured_args

    async def test_hydra_form_module_arg_strips_crlf(self, mock_ctx):
        from tengu.tools.bruteforce.hydra import hydra_attack

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()
        captured_args: list = []

        async def fake_run(args, timeout):
            captured_args.extend(args)
            return ("", "", 0)

        with (
            patch("tengu.tools.bruteforce.hydra.get_config", return_value=_mock_config()),
            patch("tengu.tools.bruteforce.hydra.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.bruteforce.hydra.resolve_tool_path", return_value="/usr/bin/hydra"),
            patch("tengu.tools.bruteforce.hydra.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.bruteforce.hydra.sanitize_wordlist_path", side_effect=lambda x: x),
            patch("tengu.tools.bruteforce.hydra.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.bruteforce.hydra.run_command", fake_run),
        ):
            mock_allowlist.return_value.check.return_value = None
            await hydra_attack(
                mock_ctx, "192.168.1.1", "http-post-form", "/tmp/u.txt", "/tmp/p.txt",
                form_path="/login\r\ninjected",
                form_params="username=^USER^&password=^PASS^:Invalid credentials",
            )

        joined = " ".join(captured_args)
        assert "\r" not in joined
        assert "\n" not in joined

    async def test_hydra_audit_logged(self, mock_ctx):
        """audit.log_tool_call is called."""
        from tengu.tools.bruteforce.hydra import hydra_attack

        mock_rl_ctx = _setup_rate_limited_mock()
        mock_audit = AsyncMock()
        mock_audit.log_tool_call = AsyncMock()

        with (
            patch("tengu.tools.bruteforce.hydra.get_config", return_value=_mock_config()),
            patch("tengu.tools.bruteforce.hydra.get_audit_logger", return_value=mock_audit),
            patch("tengu.tools.bruteforce.hydra.resolve_tool_path", return_value="/usr/bin/hydra"),
            patch("tengu.tools.bruteforce.hydra.rate_limited", return_value=mock_rl_ctx),
            patch("tengu.tools.bruteforce.hydra.sanitize_wordlist_path", side_effect=lambda x: x),
            patch("tengu.tools.bruteforce.hydra.make_allowlist_from_config") as mock_allowlist,
            patch("tengu.tools.bruteforce.hydra.run_command", AsyncMock(return_value=("", "", 0))),
        ):
            mock_allowlist.return_value.check.return_value = None
            await hydra_attack(mock_ctx, "192.168.1.1", "ssh", "/tmp/u.txt", "/tmp/p.txt")

        assert mock_audit.log_tool_call.call_count >= 1


# ---------------------------------------------------------------------------
# TestSupportedServices
# ---------------------------------------------------------------------------


class TestSupportedServices:
    def test_ssh_present(self):
        assert "ssh" in _SUPPORTED_SERVICES

    def test_ftp_present(self):
        assert "ftp" in _SUPPORTED_SERVICES

    def test_smb_present(self):
        assert "smb" in _SUPPORTED_SERVICES

    def test_rdp_present(self):
        assert "rdp" in _SUPPORTED_SERVICES

    def test_mysql_present(self):
        assert "mysql" in _SUPPORTED_SERVICES

    def test_http_get_present(self):
        assert "http-get" in _SUPPORTED_SERVICES

    def test_http_post_form_present(self):
        assert "http-post-form" in _SUPPORTED_SERVICES

    def test_http_get_form_present(self):
        """auth_failures_agent.py has always conditionally supported this
        service (checks for it explicitly), but it was missing from this
        set entirely — any attempt to use it was rejected before even
        reaching argument construction."""
        assert "http-get-form" in _SUPPORTED_SERVICES

    def test_all_lowercase(self):
        for svc in _SUPPORTED_SERVICES:
            assert svc == svc.lower()

    def test_at_least_ten_services(self):
        assert len(_SUPPORTED_SERVICES) >= 10

    def test_is_set_or_frozenset(self):
        assert isinstance(_SUPPORTED_SERVICES, (set, frozenset))


# ---------------------------------------------------------------------------
# TestParseHydraOutput
# ---------------------------------------------------------------------------


class TestParseHydraOutput:
    """Fixtures use real Hydra v9.7 output format, verified live against a
    successful DVWA crack: "[port][service] host: HOST   login: USER
    password: PASS". The previous fixtures ("[ssh][192.168.1.1:22] login: ...",
    no "host:" field) didn't match any real Hydra output — a genuine live
    crack (admin:123456 against DVWA) still came back as
    valid_credentials_found: 0 until this was fixed."""

    def test_empty_string_returns_empty(self):
        assert _parse_hydra_output("") == []

    def test_no_match_returns_empty(self):
        output = "[INFO] Attacking ssh\n[STATUS] 10 of 100 done\n"
        assert _parse_hydra_output(output) == []

    def test_single_credential_extracted(self):
        output = "[22][ssh] host: 192.168.1.1   login: admin   password: secret123"
        result = _parse_hydra_output(output)
        assert len(result) == 1
        assert result[0]["username"] == "admin"
        assert result[0]["password"] == "se***3"  # masked: se + *** + last char

    def test_raw_line_redacted(self):
        line = "[21][ftp] host: 10.0.0.5   login: ftpuser   password: p@ss"
        result = _parse_hydra_output(line)
        assert result[0]["raw_line"] == "[credential found - see audit log]"

    def test_multiple_credentials(self):
        output = (
            "[22][ssh] host: 10.0.0.1   login: user1   password: pass1\n"
            "[3389][rdp] host: 10.0.0.2   login: user2   password: pass2\n"
        )
        result = _parse_hydra_output(output)
        assert len(result) == 2
        assert result[0]["username"] == "user1"
        assert result[1]["username"] == "user2"

    def test_case_insensitive_pattern(self):
        output = "[80][http] Host: 192.168.0.1   Login: webadmin   Password: hunter2"
        result = _parse_hydra_output(output)
        assert len(result) == 1
        assert result[0]["username"] == "webadmin"

    def test_non_matching_lines_skipped(self):
        output = "[INFO] Starting attack\n[ERROR] Connection refused\n"
        assert _parse_hydra_output(output) == []

    def test_mixed_lines_only_matches_extracted(self):
        output = (
            "Hydra v9.7 starting...\n"
            "[22][ssh] host: 10.0.0.1   login: root   password: toor\n"
            "[STATUS] Attack finished.\n"
        )
        result = _parse_hydra_output(output)
        assert len(result) == 1
        assert result[0]["username"] == "root"
        assert result[0]["password"] == "to***r"  # masked

    def test_real_dvwa_crack_output_parsed(self):
        """The exact output captured from a live successful crack against
        DVWA this session — the concrete regression case."""
        output = (
            "[80][http-post-form] host: dvwa.local   "
            "misc: /login.php:username=^USER^&password=^PASS^&Login=Login:Login failed   "
            "login: admin   password: 123456\n"
            "[80][http-post-form] host: dvwa.local   login: admin   password: 123456\n"
        )
        result = _parse_hydra_output(output)
        assert len(result) >= 1
        assert result[0]["username"] == "admin"
