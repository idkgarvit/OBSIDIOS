"""SENTINEL eve.json tailing and supervisor regressions.

Rotation, truncation and a crashed tailer must never silently stop alert
processing or take the Suricata supervisor down with them.
"""
import asyncio
import json

from chronicle import db
from dashboard.app import run_async
from sentinel import runner as sr


def _line(signature="TEST", **overrides):
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
            "signature": signature,
        },
    }
    entry.update({
        key: value for key, value in overrides.items() if key != "alert"
    })
    if "alert" in overrides:
        entry["alert"].update(overrides["alert"])
    return json.dumps(entry)


class TestEveTailerEdges:
    def _patch_process(self, monkeypatch):
        seen = []

        async def fake_process(line):
            seen.append(json.loads(line)["alert"]["signature"])

        monkeypatch.setattr(sr, "_process_alert", fake_process)
        monkeypatch.setattr(sr, "POLL_INTERVAL", 0.02)
        return seen

    async def _wait_for(self, predicate, attempts=150, delay=0.02):
        for _ in range(attempts):
            if predicate():
                return True
            await asyncio.sleep(delay)
        return False

    def test_copy_truncate_rotation_in_the_same_inode_is_recovered(
            self, tmp_path, monkeypatch):
        seen = self._patch_process(monkeypatch)

        async def scenario():
            path = tmp_path / "eve.json"
            path.write_text(
                _line("OLD1") + "\n" + _line("OLD2") + "\n"
            )
            event = asyncio.Event()
            task = asyncio.create_task(
                sr._tail_eve(str(path), event, start_offset=0)
            )

            assert await self._wait_for(lambda: "OLD2" in seen)

            # "w" truncates in place, keeping the inode but making the file
            # shorter than the reader's offset.
            path.write_text(_line("NEW") + "\n")
            assert await self._wait_for(lambda: "NEW" in seen)

            event.set()
            await asyncio.wait_for(task, timeout=3)
            return list(seen)

        assert asyncio.run(scenario()) == ["OLD1", "OLD2", "NEW"]

    def test_start_offset_past_eof_reads_the_file_from_the_start(
            self, tmp_path, monkeypatch):
        seen = self._patch_process(monkeypatch)

        async def scenario():
            path = tmp_path / "eve.json"
            path.write_text(_line("RECOVERED") + "\n")
            event = asyncio.Event()
            task = asyncio.create_task(
                sr._tail_eve(str(path), event, start_offset=10_000)
            )
            assert await self._wait_for(lambda: "RECOVERED" in seen)
            event.set()
            await asyncio.wait_for(task, timeout=3)
            return list(seen)

        assert asyncio.run(scenario()) == ["RECOVERED"]

    def test_alerts_written_while_waiting_for_the_file_are_processed(
            self, tmp_path, monkeypatch):
        seen = self._patch_process(monkeypatch)

        async def scenario():
            path = tmp_path / "eve.json"
            event = asyncio.Event()
            task = asyncio.create_task(
                sr._tail_eve(str(path), event, start_offset=0)
            )
            await asyncio.sleep(0.05)
            path.write_text(_line("LATE_START") + "\n")

            assert await self._wait_for(lambda: "LATE_START" in seen, attempts=200)
            event.set()
            await asyncio.wait_for(task, timeout=3)
            return list(seen)

        assert asyncio.run(scenario()) == ["LATE_START"]

    def test_one_failing_alert_does_not_stop_the_tailer(
            self, tmp_path, monkeypatch):
        seen = []

        async def flaky_process(line):
            if "BOOM" in line:
                raise RuntimeError("alert pipeline exploded")
            seen.append(json.loads(line)["alert"]["signature"])

        monkeypatch.setattr(sr, "_process_alert", flaky_process)
        monkeypatch.setattr(sr, "POLL_INTERVAL", 0.02)

        async def scenario():
            path = tmp_path / "eve.json"
            path.write_text(_line("BOOM") + "\n" + _line("AFTER") + "\n")
            event = asyncio.Event()
            task = asyncio.create_task(
                sr._tail_eve(str(path), event, start_offset=0)
            )
            for _ in range(150):
                if "AFTER" in seen:
                    break
                await asyncio.sleep(0.02)
            event.set()
            await asyncio.wait_for(task, timeout=3)
            return seen

        assert asyncio.run(scenario()) == ["AFTER"]

    def test_blank_lines_are_ignored(self, tmp_path, monkeypatch):
        seen = self._patch_process(monkeypatch)

        async def scenario():
            path = tmp_path / "eve.json"
            path.write_text("\n\n" + _line("REAL") + "\n")
            event = asyncio.Event()
            task = asyncio.create_task(
                sr._tail_eve(str(path), event, start_offset=0)
            )
            for _ in range(150):
                if seen:
                    break
                await asyncio.sleep(0.02)
            event.set()
            await asyncio.wait_for(task, timeout=3)
            return seen

        assert asyncio.run(scenario()) == ["REAL"]


class TestProcessAlertRejectsGarbage:
    def test_invalid_json_line_is_ignored(self):
        # No DB/network access should be attempted for a non-JSON line.
        asyncio.run(sr._process_alert("not-json"))

    def test_non_numeric_signature_id_is_dropped(self):
        parsed = sr._parse_eve_alert(json.dumps({
            "event_type": "alert",
            "src_ip": "10.10.0.5",
            "dest_ip": "10.10.0.9",
            "alert": {"signature_id": "abc", "severity": 1},
        }))
        assert parsed is None

    def test_non_numeric_severity_defaults_to_one(self):
        parsed = sr._parse_eve_alert(json.dumps({
            "event_type": "alert",
            "src_ip": "10.10.0.5",
            "dest_ip": "10.10.0.9",
            "alert": {"signature_id": 1, "severity": "high"},
        }))
        assert parsed["severity"] == 1

    def test_numeric_timestamp_is_preserved(self):
        assert sr._parse_timestamp(1234.5) == 1234.5


class FakeProc:
    def __init__(self, returncode=0):
        self.returncode = returncode
        self.pid = 1234


class TestSuricataSupervisor:
    def test_missing_binary_returns_none(self, monkeypatch):
        async def missing(*_a, **_k):
            raise FileNotFoundError("suricata")

        monkeypatch.setattr(sr.asyncio, "create_subprocess_exec", missing)
        assert asyncio.run(sr._spawn_suricata(["suricata"], asyncio.Event())) is None

    def test_unexpected_spawn_error_returns_none(self, monkeypatch):
        async def broken(*_a, **_k):
            raise PermissionError("not executable")

        monkeypatch.setattr(sr.asyncio, "create_subprocess_exec", broken)
        assert asyncio.run(sr._spawn_suricata(["suricata"], asyncio.Event())) is None

    def test_spawned_process_is_returned(self, monkeypatch):
        proc = FakeProc(returncode=None)

        async def spawned(*_a, **_k):
            return proc

        monkeypatch.setattr(sr.asyncio, "create_subprocess_exec", spawned)
        assert asyncio.run(sr._spawn_suricata(["suricata"], asyncio.Event())) is proc

    def test_invalid_target_network_falls_back_to_a_safe_home_net(self, monkeypatch):
        monkeypatch.setattr(sr.settings.scan, "target_network", "not-a-network")
        cmd = sr._build_suricata_cmd("eth0", "/tmp/logs", "/tmp/s.yaml")
        assert "vars.address-groups.HOME_NET=192.168.0.0/16" in cmd

    def test_valid_target_network_is_forwarded(self, monkeypatch):
        monkeypatch.setattr(sr.settings.scan, "target_network", "10.9.0.0/16")
        cmd = sr._build_suricata_cmd("eth0", "/tmp/logs", "/tmp/s.yaml")
        assert "vars.address-groups.HOME_NET=10.9.0.0/16" in cmd

    def test_dashboard_target_wins_for_home_net(self, monkeypatch):
        async def saved(_sql, _params=(), default=None):
            return "10.55.0.0/16"

        monkeypatch.setattr(sr.settings.scan, "target_network", "192.168.1.0/24")
        monkeypatch.setattr(sr.db, "fetch_val", saved)

        assert asyncio.run(sr._resolve_home_net()) == "10.55.0.0/16"

    def test_unreadable_target_falls_back_to_the_environment(self, monkeypatch):
        async def broken(_sql, _params=(), default=None):
            raise RuntimeError("database is locked")

        monkeypatch.setattr(sr.settings.scan, "target_network", "10.9.0.0/16")
        monkeypatch.setattr(sr.db, "fetch_val", broken)

        assert asyncio.run(sr._resolve_home_net()) == "10.9.0.0/16"

    def test_monitor_returns_true_when_shutdown_is_set(self):
        event = asyncio.Event()
        event.set()
        assert asyncio.run(sr._monitor_suricata(FakeProc(), event)) is True

    def test_tailer_crash_does_not_kill_the_supervisor(self, monkeypatch, tmp_path):
        spawned = []
        closed = []

        async def fake_spawn(_cmd, _event):
            spawned.append(True)
            return FakeProc()

        async def fake_tail(*_a, **_k):
            raise RuntimeError("tailer exploded")

        calls = {"monitor": 0}

        async def fake_monitor(_proc, event):
            calls["monitor"] += 1
            if calls["monitor"] >= 2:
                event.set()
                return True
            return False

        class FakeDB:
            async def init(self):
                return None

            async def close(self):
                closed.append(True)

        monkeypatch.setattr(sr, "db", FakeDB())
        monkeypatch.setattr(sr, "_spawn_suricata", fake_spawn)
        monkeypatch.setattr(sr, "_tail_eve", fake_tail)
        monkeypatch.setattr(sr, "_monitor_suricata", fake_monitor)
        monkeypatch.setattr(sr, "SURICATA_START_WAIT", 0)
        monkeypatch.setattr(sr, "SURICATA_RESTART_DELAY", 0)

        asyncio.run(sr.start_sentinel(iface="eth0", log_dir=str(tmp_path)))

        # Before the fix the tailer exception escaped start_sentinel after the
        # first monitor loop, so Suricata was never restarted.
        assert len(spawned) == 2
        assert closed == [True]


class TestRealDatabasePipeline:
    def test_alert_is_persisted_with_resolved_forge_rule(self, monkeypatch):
        import alerts.notifier as notifier
        import shield.reconfigurer as shield_mod

        sent = []
        shield_calls = []

        monkeypatch.setattr(notifier, "check_cooldown", lambda *_a, **_k: True)

        async def fake_send(**kwargs):
            sent.append(kwargs)

        async def fake_shield(alert):
            shield_calls.append(alert)

        monkeypatch.setattr(notifier, "send_alert", fake_send)
        monkeypatch.setattr(shield_mod, "respond_to_sentinel_alert", fake_shield)

        async def no_path(*_a, **_k):
            return None

        monkeypatch.setattr(sr, "_match_attack_path", no_path)

        sid = 9000777

        async def scenario():
            await db.init()
            await db.execute("DELETE FROM sentinel_alerts WHERE rule_sid=?", (sid,))
            await db.execute("DELETE FROM forge_rules WHERE rule_sid=?", (sid,))
            rule = await db.execute_returning(
                "INSERT INTO forge_rules (rule_sid, rule_text, rule_category, is_active) "
                "VALUES (?,?,?,1) RETURNING id",
                (sid, f"alert tcp any any -> any any (sid:{sid};)", "test"),
            )
            try:
                await sr._process_alert(_line(
                    "REAL DB", src_ip="10.10.0.5", dest_ip="10.10.0.9",
                    alert={"signature_id": sid, "severity": 2},
                ))
                row = await db.fetch_one(
                    "SELECT * FROM sentinel_alerts WHERE rule_sid=?", (sid,)
                )
                missing = await sr._match_forge_rule(sid + 1)
            finally:
                await db.execute(
                    "DELETE FROM sentinel_alerts WHERE rule_sid=?", (sid,)
                )
                await db.execute(
                    "DELETE FROM forge_rules WHERE rule_sid=?", (sid,)
                )
            return rule, row, missing

        rule, row, missing = run_async(scenario())

        assert row is not None
        assert row["forge_rule_id"] == rule["id"]
        assert row["src_ip"] == "10.10.0.5"
        assert row["dst_ip"] == "10.10.0.9"
        assert row["dst_port"] == 443
        assert row["protocol"] == "tcp"
        assert row["severity"] == 2
        assert row["predicted"] == 0
        assert row["message"] == "REAL DB"
        assert missing is None
        assert sent and shield_calls
