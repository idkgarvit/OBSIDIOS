"""Notification-delivery regressions.

Alerts are the last line of defence: a payload Discord rejects, or a buffer
that drops events on a transient failure, means an operator never hears about
an intrusion.
"""
import asyncio

import pytest

from alerts import notifier


@pytest.fixture(autouse=True)
def _clean_state(monkeypatch):
    monkeypatch.setattr(notifier, "_cooldowns", {})
    monkeypatch.setattr(notifier, "_buffer", notifier.defaultdict(list))
    monkeypatch.setattr(notifier, "_delivery_failures", {})
    yield


class TestCooldown:
    def test_first_call_passes_and_repeat_is_suppressed(self):
        assert notifier.check_cooldown("sentinel:10.0.0.1→10.0.0.2", 60) is True
        assert notifier.check_cooldown("sentinel:10.0.0.1→10.0.0.2", 60) is False

    def test_distinct_keys_are_independent(self):
        assert notifier.check_cooldown("a", 60) is True
        assert notifier.check_cooldown("b", 60) is True

    def test_expired_key_is_reusable(self):
        notifier._cooldowns["k"] = 0
        assert notifier.check_cooldown("k", 1) is True

    def test_map_is_bounded(self, monkeypatch):
        monkeypatch.setattr(notifier, "_MAX_COOLDOWN_KEYS", 8)
        for i in range(50):
            notifier.check_cooldown(f"k{i}", 60)
        assert len(notifier._cooldowns) <= 8

    def test_expired_keys_are_pruned_before_the_map_is_cleared(
            self, monkeypatch):
        """A full map of stale keys should not clear the live entries."""
        monkeypatch.setattr(notifier, "_MAX_COOLDOWN_KEYS", 2)
        notifier._cooldowns.update({"old1": 0, "old2": 0})
        assert notifier.check_cooldown("new", 60) is True
        assert "old1" not in notifier._cooldowns
        assert "old2" not in notifier._cooldowns
        assert "new" in notifier._cooldowns


class TestConsolidatedBatch:
    def test_batch_never_exceeds_discords_field_limit(self, monkeypatch):
        sent = []

        async def fake_send(**kwargs):
            sent.append(kwargs)

        monkeypatch.setattr(notifier, "send_alert", fake_send)
        items = [
            {"title": f"event {i}", "message": "x", "color": 1, "fields": None, "footer": None}
            for i in range(40)
        ]
        asyncio.run(notifier._send_consolidated("critical_cves", items))

        assert len(sent) == 1
        assert len(sent[0]["fields"]) <= 25
        assert "more" in sent[0]["fields"][-1]["name"]

    def test_batch_never_exceeds_discords_embed_size_limit(self, monkeypatch):
        """A batch full of long findings must fit Discord's 6000-char embed.

        The field-count and per-value caps allowed ~24k characters, so Discord
        rejected the entire batch and every alert in it was retried then lost.
        """
        sent = []

        async def fake_send(**kwargs):
            sent.append(kwargs)

        monkeypatch.setattr(notifier, "send_alert", fake_send)
        items = [
            {
                "title": f"event {i}", "message": "x" * 200, "color": 1,
                "fields": [
                    {"name": "n" * 60, "value": "v" * 100} for _ in range(8)
                ],
            }
            for i in range(10)
        ]
        asyncio.run(notifier._send_consolidated("critical_cves", items))

        payload = sent[0]
        total = (
            len(payload["title"]) + len(payload["message"])
            + len(payload["footer"])
            + sum(len(f["name"]) + len(f["value"]) for f in payload["fields"])
        )
        assert total <= notifier._DISCORD_EMBED_CHAR_LIMIT
        assert all(len(f["value"]) <= 1024 for f in payload["fields"])
        assert "more" in payload["fields"][-1]["name"]

    def test_batch_under_the_limit_is_kept_whole(self, monkeypatch):
        sent = []

        async def fake_send(**kwargs):
            sent.append(kwargs)

        monkeypatch.setattr(notifier, "send_alert", fake_send)
        items = [
            {"title": f"event {i}", "message": "x", "color": 1}
            for i in range(3)
        ]
        asyncio.run(notifier._send_consolidated("wireless", items))
        assert len(sent[0]["fields"]) == 3
        assert all("more" not in f["name"] for f in sent[0]["fields"])

    def test_empty_batch_is_a_successful_noop(self):
        assert asyncio.run(
            notifier._send_consolidated("wireless", [])) is True

    def test_zero_budget_keeps_the_truncation_notice(self, monkeypatch):
        """A budget smaller than the labels must still produce a valid embed."""
        monkeypatch.setattr(notifier, "_DISCORD_EMBED_CHAR_LIMIT", 100)
        sent = []

        async def fake_send(**kwargs):
            sent.append(kwargs)
            return True

        monkeypatch.setattr(notifier, "send_alert", fake_send)
        items = [{"title": f"e{i}", "message": "x"} for i in range(3)]

        asyncio.run(notifier._send_consolidated("wireless", items))

        assert sent[0]["fields"] == [{
            "name": "... and 3 more",
            "value": "Truncated due to Discord embed size limit",
            "inline": False,
        }]


class TestBuffer:
    def test_buffer_is_bounded_per_category(self, monkeypatch):
        monkeypatch.setattr(notifier, "_MAX_BUFFERED_PER_CATEGORY", 5)
        for i in range(20):
            asyncio.run(notifier.buffer_alert("wireless", title=str(i)))
        assert len(notifier._buffer["wireless"]) == 5
        assert notifier._buffer["wireless"][-1]["title"] == "19"

    def test_string_colour_is_resolved(self):
        asyncio.run(notifier.buffer_alert("wireless", title="x", color="HIGH"))
        assert notifier._buffer["wireless"][0]["color"] == notifier._COLORS["high"]

    def test_flush_empty_category_is_a_noop(self):
        asyncio.run(notifier.flush_alerts("wireless"))
        assert notifier._buffer["wireless"] == []

    def test_multi_item_flush_retries_when_batch_delivery_fails(
            self, monkeypatch):
        asyncio.run(notifier.buffer_alert("wireless", title="one"))
        asyncio.run(notifier.buffer_alert("wireless", title="two"))

        async def silent_failure(**_kwargs):
            return False

        monkeypatch.setattr(notifier, "send_alert", silent_failure)
        asyncio.run(notifier.flush_alerts("wireless"))

        assert [i["title"] for i in notifier._buffer["wireless"]] == [
            "one", "two"]
        assert notifier._delivery_failures["wireless"] == 1

    def test_flush_failure_keeps_alerts_buffered(self, monkeypatch):
        asyncio.run(notifier.buffer_alert("wireless", title="keep me"))

        async def broken(**kwargs):
            raise RuntimeError("webhook down")

        monkeypatch.setattr(notifier, "send_alert", broken)
        asyncio.run(notifier.flush_alerts("wireless"))

        assert notifier._buffer["wireless"][0]["title"] == "keep me"

    def test_successful_flush_clears_the_buffer(self, monkeypatch):
        asyncio.run(notifier.buffer_alert("wireless", title="one"))

        async def ok(**kwargs):
            return None

        monkeypatch.setattr(notifier, "send_alert", ok)
        asyncio.run(notifier.flush_alerts("wireless"))
        assert notifier._buffer["wireless"] == []

    def test_flush_retry_does_not_duplicate_on_repeated_failure(self, monkeypatch):
        asyncio.run(notifier.buffer_alert("wireless", title="one"))

        async def broken(**kwargs):
            raise RuntimeError("down")

        monkeypatch.setattr(notifier, "send_alert", broken)
        asyncio.run(notifier.flush_alerts("wireless"))
        asyncio.run(notifier.flush_alerts("wireless"))
        assert len(notifier._buffer["wireless"]) == 1


class TestPayloadSafety:
    def test_mass_mentions_are_defused(self):
        cleaned = notifier._clean("@everyone buy crypto @here")
        assert "@everyone" not in cleaned
        assert "@here" not in cleaned

    def test_control_characters_are_removed(self):
        cleaned = notifier._clean("a\x00b\x07c\x1bd")
        assert cleaned == "abcd"

    def test_length_is_bounded(self):
        assert len(notifier._clean("x" * 5000, 100)) == 100

    def test_none_cleans_to_empty(self):
        assert notifier._clean(None) == ""

    def test_discord_webhook_validation(self):
        valid = "https://discord.com/api/webhooks/123/abc"
        assert notifier._valid_discord_webhook(valid) is True
        assert notifier._valid_discord_webhook("") is False
        assert notifier._valid_discord_webhook("http://discord.com/api/webhooks/1/a") is False
        assert notifier._valid_discord_webhook("https://evil.example/api/webhooks/1/a") is False
        assert notifier._valid_discord_webhook(
            "https://discord.com.evil.example/api/webhooks/1/a"
        ) is False
        assert notifier._valid_discord_webhook(
            "https://user:pass@discord.com/api/webhooks/1/a"
        ) is False
        assert notifier._valid_discord_webhook(
            "https://discord.com:8443/api/webhooks/1/a"
        ) is False
        # A non-numeric port raises ValueError inside urlparse.
        assert notifier._valid_discord_webhook(
            "https://discord.com:not-a-port/api/webhooks/1/a"
        ) is False


class TestDeliveryOutcome:
    def test_send_alert_reports_a_failed_channel(self, monkeypatch):
        monkeypatch.setattr(notifier, "get_discord_webhook",
                            lambda: "https://discord.com/api/webhooks/1/a")
        monkeypatch.setattr(notifier, "get_telegram_creds", lambda: ("", ""))

        async def boom(*_a, **_k):
            raise notifier.DeliveryError("Discord returned 500")

        monkeypatch.setattr(notifier, "_send_discord", boom)
        assert asyncio.run(notifier.send_alert("t")) is False

    def test_send_alert_reports_success_when_a_channel_accepts(self, monkeypatch):
        monkeypatch.setattr(notifier, "get_discord_webhook",
                            lambda: "https://discord.com/api/webhooks/1/a")
        monkeypatch.setattr(notifier, "get_telegram_creds", lambda: ("", ""))

        async def ok(*_a, **_k):
            return None

        monkeypatch.setattr(notifier, "_send_discord", ok)
        assert asyncio.run(notifier.send_alert("t")) is True

    def test_untrusted_webhook_does_not_block_telegram(self, monkeypatch):
        """A poisoned Discord URL must not silence a working Telegram bot."""
        monkeypatch.setattr(notifier, "get_discord_webhook",
                            lambda: "https://evil.example/api/webhooks/1/a")
        monkeypatch.setattr(notifier, "get_telegram_creds",
                            lambda: ("123456:abcdefghijklmnopqrstuvwxyz012345", "-1001"))
        called = []

        async def tg(*_a, **_k):
            called.append(True)

        monkeypatch.setattr(notifier, "_send_telegram", tg)
        assert asyncio.run(notifier.send_alert("t")) is False
        assert called == [True]

    def test_no_channels_configured_counts_as_delivered(self, monkeypatch):
        monkeypatch.setattr(notifier, "get_discord_webhook", lambda: "")
        monkeypatch.setattr(notifier, "get_telegram_creds", lambda: ("", ""))
        assert asyncio.run(notifier.send_alert("t")) is True

    def test_invalid_telegram_credentials_fail_closed(self, monkeypatch):
        monkeypatch.setattr(notifier, "get_discord_webhook", lambda: "")
        monkeypatch.setattr(
            notifier, "get_telegram_creds", lambda: ("short", "-1001"))
        assert asyncio.run(notifier.send_alert("t")) is False

    def test_string_colour_is_resolved(self, monkeypatch):
        monkeypatch.setattr(notifier, "get_discord_webhook", lambda: "")
        monkeypatch.setattr(notifier, "get_telegram_creds", lambda: ("", ""))
        assert asyncio.run(notifier.send_alert("t", color="HIGH")) is True

    def test_false_return_triggers_retry_then_bounded_drop(self, monkeypatch):
        asyncio.run(notifier.buffer_alert("wireless", title="keep me"))

        async def silent_failure(**_kwargs):
            return False

        monkeypatch.setattr(notifier, "send_alert", silent_failure)
        asyncio.run(notifier.flush_alerts("wireless"))
        assert notifier._buffer["wireless"][0]["title"] == "keep me"

        asyncio.run(notifier.flush_alerts("wireless"))
        assert len(notifier._buffer["wireless"]) == 1

        # Third consecutive failure drops the batch instead of retrying forever.
        asyncio.run(notifier.flush_alerts("wireless"))
        assert notifier._buffer["wireless"] == []

    def test_success_resets_the_failure_counter(self, monkeypatch):
        asyncio.run(notifier.buffer_alert("wireless", title="one"))

        async def silent_failure(**_kwargs):
            return False

        monkeypatch.setattr(notifier, "send_alert", silent_failure)
        asyncio.run(notifier.flush_alerts("wireless"))
        assert notifier._delivery_failures["wireless"] == 1

        async def ok(**_kwargs):
            return True

        monkeypatch.setattr(notifier, "send_alert", ok)
        asyncio.run(notifier.flush_alerts("wireless"))
        assert "wireless" not in notifier._delivery_failures
        assert notifier._buffer["wireless"] == []


class TestEnvFileDegradation:
    def test_missing_env_file_is_an_empty_override_list(self, monkeypatch):
        monkeypatch.setattr(
            notifier.pathlib.Path, "exists", lambda _self: False)
        assert notifier._env_file_lines() == []

    def test_unreadable_env_file_falls_back_instead_of_breaking_alerts(
            self, monkeypatch):
        """A root-owned `.env` must not turn every alert into a traceback."""
        monkeypatch.setattr(notifier.pathlib.Path, "exists", lambda _self: True)

        def denied(_self):
            raise PermissionError("permission denied")

        monkeypatch.setattr(notifier.pathlib.Path, "read_text", denied)
        monkeypatch.setattr(notifier.alert_cfg, "discord_webhook_url", "")
        monkeypatch.setattr(notifier.alert_cfg, "telegram_bot_token", "")
        monkeypatch.setattr(notifier.alert_cfg, "telegram_chat_id", "")
        monkeypatch.setenv(
            "OBSIDIOS_DISCORD_WEBHOOK", "https://discord.com/api/webhooks/1/a")

        assert notifier.get_discord_webhook() == (
            "https://discord.com/api/webhooks/1/a")
        assert notifier.get_telegram_creds() == ("", "")

        delivered = []

        async def ok(*_args, **_kwargs):
            delivered.append(True)

        monkeypatch.setattr(notifier, "_send_discord", ok)
        assert asyncio.run(notifier.send_alert("t")) is True
        assert delivered == [True]


class TestMalformedBatch:
    def test_non_dict_items_do_not_poison_the_batch(self, monkeypatch):
        sent = []

        async def fake_send(**kwargs):
            sent.append(kwargs)
            return True

        monkeypatch.setattr(notifier, "send_alert", fake_send)
        items = ["oops", {"title": "ok", "message": "x", "color": 1}, None]
        assert asyncio.run(notifier._send_consolidated("wireless", items)) is True
        assert len(sent) == 1
        assert len(sent[0]["fields"]) == 1
        assert "ok" in sent[0]["fields"][0]["value"]

    def test_non_dict_fields_are_skipped(self, monkeypatch):
        sent = []

        async def fake_send(**kwargs):
            sent.append(kwargs)
            return True

        monkeypatch.setattr(notifier, "send_alert", fake_send)
        items = [{"title": "t", "message": "m", "color": 1,
                  "fields": ["junk", {"name": "n", "value": "v"}]}]
        assert asyncio.run(notifier._send_consolidated("wireless", items)) is True
        assert "n: v" in sent[0]["fields"][0]["value"]

    def test_exactly_24_items_do_not_claim_zero_more(self, monkeypatch):
        sent = []

        async def fake_send(**kwargs):
            sent.append(kwargs)
            return True

        monkeypatch.setattr(notifier, "send_alert", fake_send)
        items = [{"title": f"e{i}", "message": "x", "color": 1} for i in range(24)]
        asyncio.run(notifier._send_consolidated("wireless", items))
        assert len(sent[0]["fields"]) == 24
        assert all("more" not in f["name"] for f in sent[0]["fields"])


class TestConfigResolution:
    def test_configured_discord_url_wins_over_env(self, monkeypatch):
        monkeypatch.setattr(
            notifier.alert_cfg, "discord_webhook_url",
            "https://discord.com/api/webhooks/1/config")
        monkeypatch.setattr(notifier, "_env_file_lines", lambda: [
            "OBSIDIOS_DISCORD_WEBHOOK=https://discord.com/api/webhooks/2/env"])
        monkeypatch.setenv(
            "OBSIDIOS_DISCORD_WEBHOOK",
            "https://discord.com/api/webhooks/3/process")

        assert notifier.get_discord_webhook() == (
            "https://discord.com/api/webhooks/1/config")

    def test_env_file_overrides_config_and_process_env(self, monkeypatch):
        token = "12345:" + "a" * 30
        monkeypatch.setattr(notifier.alert_cfg, "discord_webhook_url", "")
        monkeypatch.setattr(notifier.alert_cfg, "telegram_bot_token", "old")
        monkeypatch.setattr(notifier.alert_cfg, "telegram_chat_id", "1")
        monkeypatch.setattr(notifier, "_env_file_lines", lambda: [
            "OBSIDIOS_DISCORD_WEBHOOK='https://discord.com/api/webhooks/2/b'",
            f"OBSIDIOS_TELEGRAM_TOKEN='{token}'",
            "OBSIDIOS_TELEGRAM_CHAT='-1001'",
        ])
        monkeypatch.setenv(
            "OBSIDIOS_DISCORD_WEBHOOK",
            "https://discord.com/api/webhooks/3/process")

        assert notifier.get_discord_webhook() == (
            "https://discord.com/api/webhooks/2/b")
        assert notifier.get_telegram_creds() == (token, "-1001")


class _FakeResponse:
    def __init__(self, status):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False


class _FakeSession:
    def __init__(self, status, error=None):
        self.status = status
        self.error = error
        self.posts = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    def post(self, url, **kwargs):
        if self.error is not None:
            raise self.error
        self.posts.append((url, kwargs))
        return _FakeResponse(self.status)


def _install_fake_session(monkeypatch, status=204, error=None):
    sessions = []

    def factory(timeout=None):
        session = _FakeSession(status, error)
        sessions.append(session)
        return session

    monkeypatch.setattr(notifier.aiohttp, "ClientSession", factory)
    return sessions


class TestDiscordDelivery:
    def test_payload_is_bounded_and_defanged(self, monkeypatch):
        sessions = _install_fake_session(monkeypatch, status=204)
        fields = [{"name": "n" * 300, "value": "v" * 2000, "inline": True},
                  "junk", {"name": "", "value": ""}]
        fields += [{"name": f"n{i}", "value": "v"} for i in range(30)]

        asyncio.run(notifier._send_discord(
            "t" * 300, "m" * 5000, 12345,
            "https://discord.com/api/webhooks/1/a", fields, "f" * 3000))

        url, kwargs = sessions[0].posts[0]
        assert url == "https://discord.com/api/webhooks/1/a"
        assert kwargs["allow_redirects"] is False
        payload = kwargs["json"]
        embed = payload["embeds"][0]
        assert payload["username"] == "OBSIDIOS"
        assert len(embed["title"]) == 256
        assert len(embed["description"]) == 4096
        assert len(embed["footer"]["text"]) == 2048
        assert embed["timestamp"].endswith("Z")
        assert len(embed["fields"]) == 24
        assert len(embed["fields"][0]["name"]) == 256
        assert len(embed["fields"][0]["value"]) == 1024
        assert embed["fields"][0]["inline"] is True
        assert embed["fields"][1]["name"] == "field"
        assert embed["fields"][1]["value"] == "-"

    def test_rejected_status_raises_delivery_error(self, monkeypatch):
        _install_fake_session(monkeypatch, status=500)

        with pytest.raises(notifier.DeliveryError, match="500"):
            asyncio.run(notifier._send_discord(
                "t", "m", 1, "https://discord.com/api/webhooks/1/a"))

    def test_transport_error_never_leaks_the_webhook(self, monkeypatch):
        _install_fake_session(
            monkeypatch,
            error=RuntimeError("boom https://discord.com/api/webhooks/SECRET"))

        with pytest.raises(notifier.DeliveryError) as excinfo:
            asyncio.run(notifier._send_discord(
                "t", "m", 1, "https://discord.com/api/webhooks/SECRET"))

        message = str(excinfo.value)
        assert "RuntimeError" in message
        assert "boom" not in message
        assert "SECRET" not in message


class TestTelegramDelivery:
    def test_payload_escapes_html(self, monkeypatch):
        token = "12345:" + "a" * 30
        sessions = _install_fake_session(monkeypatch, status=200)

        asyncio.run(notifier._send_telegram(
            "<b>title</b>", "<script>alert(1)</script>", token, "-1001"))

        url, kwargs = sessions[0].posts[0]
        assert url == f"https://api.telegram.org/bot{token}/sendMessage"
        payload = kwargs["json"]
        assert payload["chat_id"] == "-1001"
        assert payload["parse_mode"] == "HTML"
        assert payload["disable_web_page_preview"] is True
        assert "&lt;b&gt;title&lt;/b&gt;" in payload["text"]
        assert "&lt;script&gt;" in payload["text"]
        assert "<script>" not in payload["text"]

    def test_rejected_status_raises_delivery_error(self, monkeypatch):
        _install_fake_session(monkeypatch, status=401)

        with pytest.raises(notifier.DeliveryError, match="401"):
            asyncio.run(notifier._send_telegram(
                "t", "m", "12345:" + "a" * 30, "-1001"))

    def test_transport_error_never_leaks_the_token(self, monkeypatch):
        token = "12345:" + "a" * 30
        _install_fake_session(monkeypatch, error=RuntimeError(token))

        with pytest.raises(notifier.DeliveryError) as excinfo:
            asyncio.run(notifier._send_telegram("t", "m", token, "-1001"))

        message = str(excinfo.value)
        assert "RuntimeError" in message
        assert token not in message
