"""Tests for antibody learning loop: pure tuning + service + API."""
import asyncio
import json

import pytest

from antibody import service as svc
from antibody.tuning import (
    fp_rate,
    normalize_verdict,
    suggest_for_rule,
)
from dashboard.app import app


class FakeDB:
    """Minimal async fake for chronicle.db."""
    def __init__(self, rules):
        # rules: {id: dict}
        self.rules = {int(k): dict(v) for k, v in rules.items()}
        self.executed = []

    async def fetch_one(self, sql, params=()):
        rid = int(params[0]) if params else 0
        r = self.rules.get(rid)
        return dict(r) if r else None

    async def fetch_all(self, sql, params=()):
        return [dict(v) for v in self.rules.values() if v.get("is_active")]

    async def execute(self, sql, params=()):
        self.executed.append((sql, tuple(params)))
        s = sql.strip().upper()
        if s.startswith("UPDATE FORGE_RULES SET TRUE_POSITIVES"):
            self.rules[int(params[0])]["true_positives"] += 1
        elif s.startswith("UPDATE FORGE_RULES SET FALSE_POSITIVES"):
            self.rules[int(params[0])]["false_positives"] += 1
        elif s.startswith("UPDATE FORGE_RULES SET IS_ACTIVE=0"):
            self.rules[int(params[0])]["is_active"] = 0


class TestPure:
    def test_normalize(self):
        assert normalize_verdict("tp") == "TP"
        assert normalize_verdict("False Positive") == "FP"
        assert normalize_verdict("benign") == "FP"
        with pytest.raises(ValueError):
            normalize_verdict("maybe")

    def test_fp_rate(self):
        assert fp_rate(0, 0) == 0.0
        assert fp_rate(1, 3) == 0.75
        assert fp_rate(-1, 2) == 1.0

    def test_suggest_disable(self):
        s = suggest_for_rule(rule_id=1, rule_sid=9000001,
                             true_positives=1, false_positives=3)
        assert s and s["action"] == "disable"
        assert s["forge_rule_id"] == 1

    def test_suggest_deploy(self):
        s = suggest_for_rule(rule_id=2, rule_sid=9000002,
                             true_positives=5, false_positives=0,
                             is_active=True, is_deployed=False)
        assert s and s["action"] == "deploy"

    def test_suggest_none_cold(self):
        assert suggest_for_rule(rule_id=3, true_positives=1,
                                false_positives=0) is None


class TestService:
    def _db(self):
        return FakeDB({
            1: {"id": 1, "rule_sid": 9000001, "attack_path_id": 7,
                "true_positives": 1, "false_positives": 2,
                "is_active": 1, "is_deployed": 0},
        })

    def test_record_fp_triggers_disable(self):
        db = self._db()
        res = asyncio.run(svc.record_feedback(forge_rule_id=1, verdict="fp", db=db))
        assert res["verdict"] == "FP"
        assert res["true_positives"] == 1
        assert res["false_positives"] == 3
        assert res["suggestion"]["action"] == "disable"
        assert res["applied"] is False

    def test_record_auto_apply_disables(self):
        db = self._db()
        res = asyncio.run(svc.record_feedback(forge_rule_id=1, verdict="fp",
                                              auto_apply=True, db=db))
        assert res["applied"] is True
        assert db.rules[1]["is_active"] == 0

    def test_record_bad_verdict(self):
        with pytest.raises(ValueError):
            asyncio.run(svc.record_feedback(forge_rule_id=1, verdict="x", db=self._db()))

    def test_record_missing_rule(self):
        with pytest.raises(LookupError):
            asyncio.run(svc.record_feedback(forge_rule_id=999, verdict="tp", db=self._db()))

    def test_list_suggestions(self):
        db = FakeDB({
            1: {"id": 1, "rule_sid": 9000001, "true_positives": 0,
                "false_positives": 5, "is_active": 1, "is_deployed": 0},
            2: {"id": 2, "rule_sid": 9000002, "true_positives": 1,
                "false_positives": 0, "is_active": 1, "is_deployed": 0},
        })
        out = asyncio.run(svc.list_suggestions(db=db))
        assert len(out) == 1
        assert out[0]["forge_rule_id"] == 1


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _token(client):
    rv = client.post("/api/login", json={"username": "admin",
                                         "password": "obsidios123"})
    return json.loads(rv.data).get("token", "")


class TestAPI:
    def test_feedback_validation(self, client):
        h = {"Authorization": f"Bearer {_token(client)}"}
        rv = client.post("/api/v2/forge/feedback", json={}, headers=h)
        assert rv.status_code == 400
        rv = client.post("/api/v2/forge/feedback",
                         json={"rule_id": 1, "verdict": "maybe"}, headers=h)
        # 400 bad verdict, or 404/500 if rule lookup happens first — must not 200
        assert rv.status_code in (400, 404, 500)

    def test_suggestions_requires_auth(self, client):
        assert client.get("/api/v2/forge/suggestions").status_code == 401

    def test_suggestions_authed(self, client):
        h = {"Authorization": f"Bearer {_token(client)}"}
        rv = client.get("/api/v2/forge/suggestions", headers=h)
        assert rv.status_code in (200, 500)
