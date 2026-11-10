"""ORACLE hardening regressions: TAGNN.

TAGNN must not duplicate a prediction on every run or crash on sparse data.
"""
import asyncio

from oracle import tagnn


class FakeTagnnDB:
    def __init__(self, hosts, ports, existing=None, insert_id=5):
        self.hosts = hosts
        self.ports = ports
        self.existing = existing
        self.insert_id = insert_id
        self.executed = []
        self.inserted = []
        self.fetched = []

    async def fetch_all(self, sql, params=()):
        if "FROM hosts" in sql:
            return self.hosts
        if "FROM ports" in sql:
            return self.ports
        return []

    async def fetch_one(self, sql, params=()):
        self.fetched.append((sql, params))
        return self.existing

    async def execute(self, sql, params=()):
        self.executed.append((sql, params))

    async def execute_returning(self, sql, params=()):
        self.inserted.append((sql, params))
        return {"id": self.insert_id} if self.insert_id else None


def _host(id_, ip, risk=1.0, value=1.0):
    return {"id": id_, "ip": ip, "risk_score": risk, "asset_value": value}


def _port(host_id, port):
    return {"host_id": host_id, "port": port, "service": "ssh"}


class TestTagnn:
    def test_predictions_are_persisted(self, monkeypatch):
        hosts = [
            _host(1, "10.44.0.1", value=1.0),
            _host(2, "10.44.0.2", value=9.0),
            _host(3, "10.44.0.3", value=5.0),
        ]
        ports = [_port(2, 22), _port(2, 445), _port(3, 443)]
        fake = FakeTagnnDB(hosts, ports)
        monkeypatch.setattr(tagnn, "db", fake)
        monkeypatch.setenv("OBSIDIOS_GATEWAY", "192.168.1.1")

        predictions = asyncio.run(tagnn.run_tagnn_prediction())
        assert predictions
        assert {p["target"] for p in predictions} == {"10.44.0.2", "10.44.0.3"}
        assert all("TAGNN" in p["narrative"] for p in predictions)
        assert fake.inserted
        assert any("INSERT INTO attack_paths" in sql for sql, _ in fake.inserted)

    def test_gateway_is_never_a_target(self, monkeypatch):
        hosts = [
            _host(1, "192.168.1.1", value=100.0),
            _host(2, "10.44.0.2", value=9.0),
            _host(3, "10.44.0.3", value=8.0),
        ]
        ports = [_port(1, 22), _port(2, 22), _port(3, 22)]
        monkeypatch.setattr(tagnn, "db", FakeTagnnDB(hosts, ports))
        monkeypatch.setenv("OBSIDIOS_GATEWAY", "192.168.1.1")

        predictions = asyncio.run(tagnn.run_tagnn_prediction())
        assert predictions
        assert all(p["target"] != "192.168.1.1" for p in predictions)
        assert any(p["entry"] == "192.168.1.1" for p in predictions)

    def test_existing_prediction_is_refreshed_not_duplicated(self, monkeypatch):
        hosts = [
            _host(1, "10.44.0.1", value=1.0),
            _host(2, "10.44.0.2", value=9.0),
        ]
        ports = [_port(2, 22)]
        fake = FakeTagnnDB(hosts, ports, existing={"id": 42})
        monkeypatch.setattr(tagnn, "db", fake)
        monkeypatch.setenv("OBSIDIOS_GATEWAY", "192.168.1.1")

        asyncio.run(tagnn.run_tagnn_prediction())
        assert fake.inserted == []
        assert any("UPDATE attack_paths" in sql and "simulated_at" in sql
                   for sql, _ in fake.executed)

    def test_all_predictions_retired_when_none_persist(self, monkeypatch):
        hosts = [
            _host(1, "10.44.0.1"),
            _host(2, "10.44.0.2", value=9.0),
        ]
        ports = [_port(2, 22)]
        fake = FakeTagnnDB(hosts, ports, insert_id=None)
        monkeypatch.setattr(tagnn, "db", fake)
        monkeypatch.setenv("OBSIDIOS_GATEWAY", "192.168.1.1")

        asyncio.run(tagnn.run_tagnn_prediction())
        retire = [(sql, params) for sql, params in fake.executed
                  if "is_active=0" in sql and "TAGNN" in sql]
        assert retire
        assert "NOT IN" not in retire[-1][0]

    def test_sparse_data_does_not_crash(self, monkeypatch):
        hosts = [
            {"id": 1, "ip": "10.44.0.1", "risk_score": None, "asset_value": None},
            {"id": 2, "ip": "10.44.0.2", "risk_score": None, "asset_value": None},
        ]
        fake = FakeTagnnDB(hosts, [_port(2, 22)])
        monkeypatch.setattr(tagnn, "db", fake)
        predictions = asyncio.run(tagnn.run_tagnn_prediction())
        assert isinstance(predictions, list)

    def test_single_host_returns_empty(self, monkeypatch):
        fake = FakeTagnnDB([_host(1, "10.44.0.1")], [])
        monkeypatch.setattr(tagnn, "db", fake)
        assert asyncio.run(tagnn.run_tagnn_prediction()) == []
        assert fake.executed == []
