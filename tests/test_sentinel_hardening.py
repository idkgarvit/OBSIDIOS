"""SENTINEL pipeline hardening regressions.

Covers the failures that silently lose alerts or burn a CPU core:
* deactivated-but-still-deployed FORGE rules must still match,
* non-string / malformed eve.json fields must not drop an alert,
* a dead webhook must not stop SHIELD,
* the Suricata monitor must notice an exited process at stderr EOF,
* the tailer must not skip alerts written during startup.
"""
import asyncio
import json
import sys
import time

from chronicle import db
from dashboard.app import run_async
from sentinel import runner as sr


def _entry(**overrides):
    entry = {
        "event_type": "alert",
        "timestamp": "2026-11-04T06:00:00.000000+0000",
        "src_ip": "10.10.0.5",
        "dest_ip": "10.10.0.9",
        "src_port": 41000,
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature_id": 9000001,
            "severity": 1,
            "signature": "ET MALWARE Test",
        },
    }
    for key, value in overrides.items():
        if key == "alert" and isinstance(value, dict):
            entry["alert"].update(value)
        else:
            entry[key] = value
    return entry


def _line(**overrides) -> str:
    return json.dumps(_entry(**overrides))


class TestParseEveAlert:
    def test_valid_alert_is_normalized(self):
        parsed = sr._parse_eve_alert(_line())
        assert parsed["src_ip"] == "10.10.0.5"
        assert parsed["dst_ip"] == "10.10.0.9"
        assert parsed["protocol"] == "tcp"
        assert parsed["rule_sid"] == 9000001
        assert parsed["severity"] == 1
        assert parsed["message"] == "ET MALWARE Test"
        assert parsed["alerted_at"] > 0

    def test_severity_is_clamped_and_string_sid_accepted(self):
        parsed = sr._parse_eve_alert(_line(alert={"severity": 99, "signature_id": "9000002"}))
        assert parsed["rule_sid"] == 9000002
        assert parsed["severity"] == 4

    def test_non_string_signature_is_coerced(self):
        parsed = sr._parse_eve_alert(_line(alert={"signature": 12345}))
        assert parsed["message"] == "12345"

    def test_alert_payload_must_be_a_dict(self):
        assert sr._parse_eve_alert(_line(alert=[1, 2, 3])) is None

    def test_non_string_source_ip_is_rejected(self):
        assert sr._parse_eve_alert(_line(src_ip=123)) is None

    def test_zero_sid_is_rejected(self):
        assert sr._parse_eve_alert(_line(alert={"signature_id": 0})) is None

    def test_non_alert_event_is_ignored(self):
        assert sr._parse_eve_alert(_line(event_type="flow")) is None

    def test_non_object_json_is_ignored(self):
        """Valid JSON that is not an object used to raise AttributeError."""
        for raw in ("null", "[1, 2, 3]", '"alert"', "42"):
            assert sr._parse_eve_alert(raw) is None

    def test_unusable_ports_become_null(self):
        parsed = sr._parse_eve_alert(
            _line(src_port={"x": 1}, dest_port="not-a-port"))
        assert parsed["src_port"] is None
        assert parsed["dst_port"] is None

    def test_numeric_string_ports_are_coerced(self):
        parsed = sr._parse_eve_alert(_line(src_port="41000", dest_port="443"))
        assert parsed["src_port"] == 41000
        assert parsed["dst_port"] == 443

    def test_missing_ports_stay_null(self):
        parsed = sr._parse_eve_alert(_line(src_port=None, dest_port=None))
        assert parsed["src_port"] is None
        assert parsed["dst_port"] is None


class TestAttackPathMatching:
    def test_malformed_steps_do_not_crash(self, monkeypatch):
        class FakeDB:
            async def fetch_all(self, *_a, **_k):
                return [
                    {"id": 1, "attacker_roi": 1.0,
                     "path_json": json.dumps([1, None, {"ip": "10.10.0.9"}])},
                    {"id": 2, "attacker_roi": 2.0,
                     "path_json": json.dumps([{"ip": "10.10.0.5"}, {"ip": "10.10.0.9"}])},
                ]

        monkeypatch.setattr(sr, "db", FakeDB())
        match = asyncio.run(sr._match_attack_path("10.10.0.5", "10.10.0.9"))
        assert match == {"id": 2, "roi": 2.0}

    def test_direction_matters(self, monkeypatch):
        class FakeDB:
            async def fetch_all(self, *_a, **_k):
                return [{"id": 1, "attacker_roi": 1.0,
                         "path_json": json.dumps([{"ip": "10.10.0.9"}, {"ip": "10.10.0.5"}])}]

        monkeypatch.setattr(sr, "db", FakeDB())
        assert asyncio.run(sr._match_attack_path("10.10.0.5", "10.10.0.9")) is None


class TestForgeRuleLookup:
    def test_inactive_rule_still_matches_until_redeploy(self):
        """is_active is intent for the next write, not current sensor state."""

        async def scenario():
            await db.init()
            await db.execute("DELETE FROM forge_rules WHERE rule_sid=?", (9000999,))
            await db.execute(
                "INSERT INTO forge_rules (rule_sid, rule_text, rule_category, is_active) "
                "VALUES (?,?,?,0)",
                (9000999, "alert tcp any any -> any any (sid:9000999;)", "test"),
            )
            try:
                return await sr._match_forge_rule(9000999)
            finally:
                await db.execute("DELETE FROM forge_rules WHERE rule_sid=?", (9000999,))

        row = run_async(scenario())
        assert row is not None
        assert row["id"]
        assert "9000999" in row["rule_text"]


class TestAlertPipeline:
    def _patch_sources(self, monkeypatch, shield_calls):
        async def fake_rule(_sid):
            return {"id": 7, "mitre_technique": "T1071", "attack_path_id": None}

        async def fake_path(_src, _dst):
            return None

        async def fake_write(_alert):
            return 55

        async def fake_shield(alert):
            shield_calls.append(alert)

        monkeypatch.setattr(sr, "_match_forge_rule", fake_rule)
        monkeypatch.setattr(sr, "_match_attack_path", fake_path)
        monkeypatch.setattr(sr, "_write_alert", fake_write)

        import shield.reconfigurer as shield_mod

        monkeypatch.setattr(shield_mod, "respond_to_sentinel_alert", fake_shield)

    def test_notifier_failure_does_not_skip_shield(self, monkeypatch):
        shield_calls = []
        self._patch_sources(monkeypatch, shield_calls)

        import alerts.notifier as notifier

        async def boom(**_kwargs):
            raise RuntimeError("webhook down")

        monkeypatch.setattr(notifier, "check_cooldown", lambda *_a, **_k: True)
        monkeypatch.setattr(notifier, "send_alert", boom)

        asyncio.run(sr._process_alert(_line()))
        assert len(shield_calls) == 1
        assert shield_calls[0]["src_ip"] == "10.10.0.5"
        assert shield_calls[0]["protocol"] == "tcp"

    def test_cooldown_failure_still_notifies_and_responds(self, monkeypatch):
        shield_calls = []
        self._patch_sources(monkeypatch, shield_calls)
        sent = []

        import alerts.notifier as notifier

        def broken_cooldown(*_a, **_k):
            raise RuntimeError("redis down")

        async def fake_send(**kwargs):
            sent.append(kwargs)

        monkeypatch.setattr(notifier, "check_cooldown", broken_cooldown)
        monkeypatch.setattr(notifier, "send_alert", fake_send)

        asyncio.run(sr._process_alert(_line()))
        assert sent
        assert shield_calls

    def test_cooldown_silences_webhook_but_not_shield(self, monkeypatch):
        """A suppressed notification must not leave the attack path open."""
        shield_calls = []
        self._patch_sources(monkeypatch, shield_calls)
        sent = []

        import alerts.notifier as notifier

        monkeypatch.setattr(notifier, "check_cooldown", lambda *_a, **_k: False)

        async def fake_send(**kwargs):
            sent.append(kwargs)

        monkeypatch.setattr(notifier, "send_alert", fake_send)

        asyncio.run(sr._process_alert(_line()))
        assert sent == []
        assert len(shield_calls) == 1

    def test_unknown_sid_is_still_dropped(self, monkeypatch):
        async def no_rule(_sid):
            return None

        wrote = []

        async def fake_write(alert):
            wrote.append(alert)
            return 1

        monkeypatch.setattr(sr, "_match_forge_rule", no_rule)
        monkeypatch.setattr(sr, "_write_alert", fake_write)
        asyncio.run(sr._process_alert(_line()))
        assert wrote == []


class TestSuricataMonitor:
    def test_exited_process_is_detected_at_stderr_eof(self, monkeypatch):
        async def no_notify(**_kwargs):
            return None

        monkeypatch.setattr(sr, "_notify", no_notify)

        async def scenario():
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-c", "pass",
                stderr=asyncio.subprocess.PIPE,
            )
            await proc.wait()
            return await asyncio.wait_for(
                sr._monitor_suricata(proc, asyncio.Event()), timeout=3
            )

        # False = caller should restart. The old implementation spun forever
        # on EOF because it only checked returncode inside the timeout branch.
        assert asyncio.run(scenario()) is False


class TestEveTailer:
    def test_alerts_written_after_start_are_not_skipped(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sr, "POLL_INTERVAL", 0.05)
        seen = []

        async def fake_process(line):
            seen.append(line)

        monkeypatch.setattr(sr, "_process_alert", fake_process)

        async def scenario():
            path = tmp_path / "eve.json"
            old = _line(alert={"signature": "OLD"}) + "\n"
            path.write_text(old)
            start_offset = path.stat().st_size
            with path.open("a") as fh:
                fh.write(_line(alert={"signature": "NEW"}) + "\n")

            event = asyncio.Event()
            task = asyncio.create_task(
                sr._tail_eve(str(path), event, start_offset=start_offset)
            )
            for _ in range(40):
                if seen:
                    break
                await asyncio.sleep(0.05)
            event.set()
            await asyncio.wait_for(task, timeout=3)
            return [json.loads(line)["alert"]["signature"] for line in seen]

        assert asyncio.run(scenario()) == ["NEW"]

    def test_partial_line_is_retried_instead_of_dropped(self, tmp_path, monkeypatch):
        """Suricata appends atomically-ish; a half-written line must not vanish."""
        monkeypatch.setattr(sr, "POLL_INTERVAL", 0.02)
        seen = []

        async def fake_process(line):
            seen.append(line)

        monkeypatch.setattr(sr, "_process_alert", fake_process)

        async def scenario():
            path = tmp_path / "eve.json"
            payload = _line(alert={"signature": "SPLIT"}) + "\n"
            path.write_text(payload[: len(payload) // 2])

            event = asyncio.Event()
            task = asyncio.create_task(sr._tail_eve(str(path), event))
            await asyncio.sleep(0.15)
            assert seen == [], "partial line must not be processed"

            with path.open("a") as fh:
                fh.write(payload[len(payload) // 2:])
            for _ in range(40):
                if seen:
                    break
                await asyncio.sleep(0.02)
            event.set()
            await asyncio.wait_for(task, timeout=3)
            return seen

        lines = asyncio.run(scenario())
        assert len(lines) == 1
        assert json.loads(lines[0])["alert"]["signature"] == "SPLIT"

    def test_rotation_to_a_new_inode_is_followed(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sr, "POLL_INTERVAL", 0.02)
        seen = []

        async def fake_process(line):
            seen.append(json.loads(line)["alert"]["signature"])

        monkeypatch.setattr(sr, "_process_alert", fake_process)

        async def scenario():
            path = tmp_path / "eve.json"
            path.write_text("")

            event = asyncio.Event()
            task = asyncio.create_task(sr._tail_eve(str(path), event))
            await asyncio.sleep(0.1)

            rotated = tmp_path / "eve.json.1"
            with path.open("a") as fh:
                fh.write(_line(alert={"signature": "BEFORE"}) + "\n")
            for _ in range(40):
                if "BEFORE" in seen:
                    break
                await asyncio.sleep(0.02)

            path.rename(rotated)
            path.write_text(_line(alert={"signature": "AFTER"}) + "\n")
            for _ in range(60):
                if "AFTER" in seen:
                    break
                await asyncio.sleep(0.02)
            event.set()
            await asyncio.wait_for(task, timeout=3)
            return seen

        assert asyncio.run(scenario()) == ["BEFORE", "AFTER"]

    def test_unlink_between_stat_and_open_does_not_kill_the_tailer(
            self, tmp_path, monkeypatch):
        monkeypatch.setattr(sr, "POLL_INTERVAL", 0.02)
        seen = []

        async def fake_process(line):
            seen.append(line)

        monkeypatch.setattr(sr, "_process_alert", fake_process)

        real_open = open
        state = {"raised": False}

        def flaky_open(*args, **kwargs):
            if not state["raised"]:
                state["raised"] = True
                raise FileNotFoundError("rotated away")
            return real_open(*args, **kwargs)

        monkeypatch.setattr(sr, "open", flaky_open, raising=False)

        async def scenario():
            path = tmp_path / "eve.json"
            path.write_text(_line() + "\n")
            event = asyncio.Event()
            task = asyncio.create_task(sr._tail_eve(str(path), event))
            for _ in range(60):
                if seen:
                    break
                await asyncio.sleep(0.02)
            event.set()
            await asyncio.wait_for(task, timeout=3)
            return seen

        assert len(asyncio.run(scenario())) == 1


def test_parse_timestamp_handles_utc_offset_without_colon():
    parsed = sr._parse_timestamp("2026-11-04T06:00:00.000000+0000")
    assert abs(parsed - sr._parse_timestamp("2026-11-04T06:00:00+00:00")) < 1


def test_parse_timestamp_falls_back_to_now():
    before = time.time()
    assert sr._parse_timestamp("not-a-date") >= before


class TestStartupTeardown:
    def test_missing_suricata_still_closes_the_database(self, monkeypatch, tmp_path):
        """`return` on spawn failure used to skip db.close() entirely."""
        closed = []

        class FakeDB:
            async def init(self):
                return None

            async def close(self):
                closed.append(True)

        async def no_proc(*_args, **_kwargs):
            return None

        monkeypatch.setattr(sr, "db", FakeDB())
        monkeypatch.setattr(sr, "_spawn_suricata", no_proc)

        asyncio.run(sr.start_sentinel(iface="eth0", log_dir=str(tmp_path)))
        assert closed == [True]
