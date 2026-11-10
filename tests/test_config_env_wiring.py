"""Documented environment variables must actually reach the running app.

pydantic-settings v2 ignores Pydantic v1's ``Field(env=...)`` and falls back to
the upper-cased field name. Every documented variable was therefore dead
configuration: Docker Compose wired ``OBSIDIOS_TARGET``, but the daemon still
scanned 192.168.1.0/24; an operator raised SHIELD's block-storm cap and the
guard kept refusing at the default of 10.
"""
import asyncio

from config.settings import (
    AISettings,
    AlertSettings,
    DashboardSettings,
    ScanSettings,
    ShieldSettings,
)


class FakeDB:
    def __init__(self, count=0):
        self.count = count

    async def fetch_val(self, _sql, _params=(), default=None):
        return self.count


class TestScanSettings:
    def test_documented_scan_variables_are_honoured(self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_TARGET", "10.77.0.0/16")
        monkeypatch.setenv("OBSIDIOS_SCAN_INTERVAL", "123")
        monkeypatch.setenv("OBSIDIOS_SCAN_PROFILE", "GHOST")
        monkeypatch.setenv("OBSIDIOS_SCAN_CONCURRENCY", "7")
        monkeypatch.setenv("OBSIDIOS_ARP_TIMEOUT", "9.5")
        monkeypatch.setenv("OBSIDIOS_WIRELESS", "0")

        scan = ScanSettings(_env_file=None)

        assert scan.target_network == "10.77.0.0/16"
        assert scan.scan_interval_seconds == 123
        assert scan.scan_profile == "GHOST"
        assert scan.scan_concurrency == 7
        assert scan.arp_timeout == 9.5
        assert scan.enable_wireless is False

    def test_nmap_override_wins_over_the_profile(self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_NMAP_ARGS", "-sV -T4 -p 22,443")
        monkeypatch.setenv("OBSIDIOS_SCAN_PROFILE", "GHOST")

        scan = ScanSettings(_env_file=None)

        assert scan.active_nmap_args == "-sV -T4 -p 22,443"


class TestShieldSettings:
    def test_documented_limits_reach_the_guard(self, monkeypatch):
        """`SHIELD_MAX_ACTIONS_PER_HOUR=2` must refuse the third block.

        The settings object used to stay at 10 and override the environment
        value inside `_shield_guard`, so an operator could never tighten (or
        loosen) the block-storm cap.
        """
        from config.settings import is_ip_allowlisted, parse_shield_allowlist
        from shield import reconfigurer as sh

        monkeypatch.setenv("SHIELD_DRY_RUN", "0")
        monkeypatch.setenv("SHIELD_MAX_ACTIONS_PER_HOUR", "2")
        monkeypatch.setenv("SHIELD_ALLOWLIST", "")
        cfg = ShieldSettings(_env_file=None)
        monkeypatch.setattr(
            sh, "_shield_cfg",
            lambda: (cfg, parse_shield_allowlist, is_ip_allowlisted),
        )
        monkeypatch.setattr(sh, "db", FakeDB(count=2))

        allowed, reason = asyncio.run(sh._shield_guard("10.20.0.5", "BLOCK_IP"))

        assert allowed is False
        assert "2/2" in reason

    def test_dry_run_default_still_fails_closed(self, monkeypatch):
        monkeypatch.delenv("SHIELD_DRY_RUN", raising=False)

        assert ShieldSettings(_env_file=None).dry_run is True


class TestOtherSettings:
    def test_alert_webhook_is_read_from_the_documented_name(self, monkeypatch):
        monkeypatch.setenv(
            "OBSIDIOS_DISCORD_WEBHOOK", "https://discord.com/api/webhooks/1/a")
        monkeypatch.setenv("OBSIDIOS_TELEGRAM_TOKEN", "token")
        monkeypatch.setenv("OBSIDIOS_TELEGRAM_CHAT", "chat")

        alerts = AlertSettings(_env_file=None)

        assert alerts.discord_webhook_url.endswith("/1/a")
        assert (alerts.telegram_bot_token, alerts.telegram_chat_id) == (
            "token", "chat")

    def test_dashboard_bind_and_debug_are_read_from_documented_names(
            self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_DASH_HOST", "0.0.0.0")
        monkeypatch.setenv("OBSIDIOS_DASH_PORT", "9099")
        monkeypatch.setenv("OBSIDIOS_DASH_DEBUG", "1")

        dash = DashboardSettings(_env_file=None)

        assert dash.host == "0.0.0.0"
        assert dash.port == 9099
        assert dash.debug is True

    def test_ai_model_override_is_honoured(self, monkeypatch):
        monkeypatch.setenv("OBSIDIOS_AI_MODEL", "claude-sonnet-4-5")
        monkeypatch.setenv("OBSIDIOS_AI_MAX_TOKENS", "1234")

        ai = AISettings(_env_file=None)

        assert ai.model == "claude-sonnet-4-5"
        assert ai.max_tokens == 1234


class TestDotenvSource:
    def test_env_file_values_are_matched_through_aliases(
            self, tmp_path, monkeypatch):
        monkeypatch.delenv("OBSIDIOS_TARGET", raising=False)
        monkeypatch.delenv("SHIELD_MAX_ACTIONS_PER_HOUR", raising=False)
        env_file = tmp_path / "operator.env"
        env_file.write_text(
            "OBSIDIOS_TARGET=10.55.0.0/16\n"
            "SHIELD_MAX_ACTIONS_PER_HOUR=3\n"
        )

        assert ScanSettings(_env_file=str(env_file)).target_network == \
            "10.55.0.0/16"
        assert ShieldSettings(_env_file=str(env_file)).max_actions_per_hour == 3


class TestCliWiring:
    def test_dash_help_shows_the_documented_bind_defaults(self):
        """The CLI must consume OBSIDIOS_DASH_HOST/PORT, not hardcoded values.

        Click evaluates option defaults at import time, so a subprocess is the
        only honest way to prove the env value reaches the bind address.
        """
        import os
        import pathlib
        import subprocess
        import sys

        repo = pathlib.Path(__file__).resolve().parent.parent
        env = os.environ.copy()
        env.update({
            "OBSIDIOS_ENV": "dev",
            "OBSIDIOS_DASH_HOST": "127.0.0.9",
            "OBSIDIOS_DASH_PORT": "9091",
        })

        proc = subprocess.run(
            [sys.executable, "obsidios.py", "dash", "--help"],
            cwd=repo, env=env, capture_output=True, text=True, timeout=60,
        )

        assert proc.returncode == 0, proc.stderr
        assert "127.0.0.9" in proc.stdout
        assert "9091" in proc.stdout

