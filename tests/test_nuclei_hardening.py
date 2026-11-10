"""IRIS/Nuclei hardening regressions.

Nuclei output is untrusted: severity strings, CVE identifiers, ports and IPs
all arrive from a scanner we do not control. Malformed lines must be skipped,
fabricated CVE IDs must not enter the CVE table, and the reported finding
count must reflect what was actually stored.
"""
import asyncio
import json
import os
import types

import pytest

from iris import nuclei_scanner as nuclei


class FakeDB:
    def __init__(self, host=True, port=None):
        self.host = host
        self.port = port
        self.cve_params = []
        self.executed = []
        self.fetched = []

    async def execute_returning(self, sql, params=()):
        self.cve_params.append(params)
        return {"id": 11}

    async def execute(self, sql, params=()):
        self.executed.append((sql, params))

    async def fetch_one(self, sql, params=()):
        self.fetched.append((sql, params))
        if "FROM hosts" in sql:
            return {"id": 1} if self.host else None
        return self.port


class FakeProcess:
    def __init__(self, stdout: bytes):
        self.stdout = stdout
        self.killed = False
        self.waited = False

    async def communicate(self):
        return self.stdout, b""

    def kill(self):
        self.killed = True

    async def wait(self):
        self.waited = True


@pytest.fixture
def spawn(monkeypatch):
    """Install a fake nuclei subprocess; returns an object to inspect calls."""
    state = {"calls": 0, "process": None}

    def install(stdout: bytes):
        async def fake_spawn(*_cmd, **_kwargs):
            state["calls"] += 1
            state["process"] = FakeProcess(stdout)
            return state["process"]

        monkeypatch.setattr(nuclei.asyncio, "create_subprocess_exec", fake_spawn)
        return state

    return install


class TestRunScan:
    def test_invalid_lines_are_skipped_and_valid_ones_stored(self, spawn, monkeypatch):
        state = spawn(
            b'{"template-id":"a","info":{"severity":"high"}}\n'
            b"not json\n"
            b'{"template-id":"b","info":{"severity":"low"}}\n'
        )
        processed = []

        async def fake_process(data):
            processed.append(data["template-id"])

        monkeypatch.setattr(nuclei, "_process_nuclei_finding", fake_process)
        asyncio.run(nuclei.run_nuclei_scan(["10.44.0.1"]))
        assert processed == ["a", "b"]
        assert state["calls"] == 1

    def test_one_bad_finding_does_not_stop_the_rest(self, spawn, monkeypatch):
        spawn(
            b'{"template-id":"bad"}\n'
            b'{"template-id":"good"}\n'
        )
        processed = []

        async def fake_process(data):
            if data["template-id"] == "bad":
                raise RuntimeError("schema drift")
            processed.append(data["template-id"])

        monkeypatch.setattr(nuclei, "_process_nuclei_finding", fake_process)
        asyncio.run(nuclei.run_nuclei_scan(["10.44.0.1"]))
        assert processed == ["good"]

    def test_only_valid_ips_reach_the_target_file(self, spawn, monkeypatch, tmp_path):
        spawn(b"")
        target_path = tmp_path / "targets.txt"

        def fake_mkstemp(**_kwargs):
            fd = os.open(target_path, os.O_RDWR | os.O_CREAT, 0o600)
            return fd, str(target_path)

        monkeypatch.setattr(
            nuclei, "tempfile", types.SimpleNamespace(mkstemp=fake_mkstemp)
        )
        monkeypatch.setattr(nuclei.os, "remove", lambda _p: None)
        asyncio.run(nuclei.run_nuclei_scan(["not-an-ip", "10.44.0.1", "999.1.1.1"]))

        assert target_path.read_text().splitlines() == ["10.44.0.1"]

    def test_no_valid_targets_spawns_nothing(self, spawn, monkeypatch):
        state = spawn(b"")
        asyncio.run(nuclei.run_nuclei_scan(["nope", "also-nope"]))
        assert state["calls"] == 0

    def test_timeout_kills_the_process(self, spawn, monkeypatch):
        state = spawn(b"")

        class HangingProcess(FakeProcess):
            async def communicate(self):
                await asyncio.sleep(5)
                return b"", b""

        async def hanging(*_cmd, **_kwargs):
            state["calls"] += 1
            state["process"] = HangingProcess(b"")
            return state["process"]

        monkeypatch.setattr(nuclei.asyncio, "create_subprocess_exec", hanging)
        monkeypatch.setattr(nuclei, "NUCLEI_TIMEOUT_SECONDS", 0.05)
        asyncio.run(nuclei.run_nuclei_scan(["10.44.0.1"]))
        assert state["process"].killed is True
        assert state["process"].waited is True


def _finding(**overrides):
    finding = {
        "template-id": "exposed-panel",
        "ip": "10.44.0.5",
        "port": 80,
        "info": {"severity": "medium", "description": "panel exposed"},
    }
    finding.update(overrides)
    return finding


class TestFindingMapping:
    def test_non_dict_is_ignored(self, monkeypatch):
        fake = FakeDB()
        monkeypatch.setattr(nuclei, "db", fake)
        asyncio.run(nuclei._process_nuclei_finding(["not", "a", "dict"]))
        assert fake.cve_params == []

    def test_fabricated_cve_is_rejected(self, monkeypatch):
        fake = FakeDB(port=None)
        monkeypatch.setattr(nuclei, "db", fake)
        asyncio.run(nuclei._process_nuclei_finding(_finding(
            info={"severity": "high",
                  "classification": {"cve-id": ["CVE-2024-0001", "not-a-cve"]}},
        )))
        assert fake.cve_params[0][0] == "CVE-2024-0001"

    @pytest.mark.parametrize("candidate", [
        "not-a-cve", "CVE-24-1", "CVE-2024-12", "2024-1234", "CVE-2024-12345678x",
    ])
    def test_malformed_cve_falls_back_to_namespaced_template_id(
            self, candidate, monkeypatch):
        fake = FakeDB()
        monkeypatch.setattr(nuclei, "db", fake)
        asyncio.run(nuclei._process_nuclei_finding(_finding(
            info={"severity": "high", "classification": {"cve-id": candidate}},
        )))
        assert fake.cve_params[0][0] == "NUCLEI-exposed-panel"

    def test_non_string_cve_is_rejected(self, monkeypatch):
        fake = FakeDB()
        monkeypatch.setattr(nuclei, "db", fake)
        asyncio.run(nuclei._process_nuclei_finding(_finding(
            info={"severity": "high", "classification": {"cve-id": {"nested": 1}}},
        )))
        assert fake.cve_params[0][0] == "NUCLEI-exposed-panel"

    def test_cve_is_uppercased_and_trimmed(self, monkeypatch):
        fake = FakeDB()
        monkeypatch.setattr(nuclei, "db", fake)
        asyncio.run(nuclei._process_nuclei_finding(_finding(
            info={"severity": "high", "classification": {"cve-id": " cve-2024-99999 "}},
        )))
        assert fake.cve_params[0][0] == "CVE-2024-99999"

    def test_unknown_severity_maps_to_low(self, monkeypatch):
        fake = FakeDB()
        monkeypatch.setattr(nuclei, "db", fake)
        asyncio.run(nuclei._process_nuclei_finding(_finding(
            info={"severity": "banana"},
        )))
        assert fake.cve_params[0][2] == "LOW"

    def test_invalid_ip_skips_port_linking(self, monkeypatch):
        fake = FakeDB(port={"id": 2, "service": "http", "product": "nginx", "cpe": None})
        monkeypatch.setattr(nuclei, "db", fake)
        asyncio.run(nuclei._process_nuclei_finding(_finding(ip="not-an-ip")))
        assert fake.cve_params
        assert not any("FROM hosts" in sql for sql, _ in fake.fetched)

    def test_generic_protocol_without_product_is_not_linked(self, monkeypatch):
        fake = FakeDB(port={"id": 2, "service": "tcp", "product": None, "cpe": None})
        monkeypatch.setattr(nuclei, "db", fake)
        asyncio.run(nuclei._process_nuclei_finding(_finding(ip="10.44.0.5", port=80)))
        assert not any("port_cves" in sql for sql, _ in fake.executed)

    def test_product_identified_service_is_linked(self, monkeypatch):
        fake = FakeDB(port={"id": 2, "service": "http", "product": "nginx", "cpe": None})
        monkeypatch.setattr(nuclei, "db", fake)
        asyncio.run(nuclei._process_nuclei_finding(_finding(ip="10.44.0.5", port=80)))
        assert any("port_cves" in sql for sql, _ in fake.executed)

    def test_out_of_range_port_is_not_linked(self, monkeypatch):
        fake = FakeDB(port={"id": 2, "service": "ssh", "product": "OpenSSH", "cpe": None})
        monkeypatch.setattr(nuclei, "db", fake)
        asyncio.run(nuclei._process_nuclei_finding(_finding(ip="10.44.0.5", port=70000)))
        assert not any("port_cves" in sql for sql, _ in fake.executed)

    def test_missing_info_does_not_crash(self, monkeypatch):
        fake = FakeDB()
        monkeypatch.setattr(nuclei, "db", fake)
        finding = _finding()
        del finding["info"]
        asyncio.run(nuclei._process_nuclei_finding(finding))
        assert fake.cve_params[0][2] == "INFO"
        assert json.dumps(fake.cve_params[0][0])
