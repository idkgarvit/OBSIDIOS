"""Tests for oracle modules — posture scoring, exploit validator, Claude client."""
from oracle.posture_score import _generate_recommendations
from iris.exploit_validator import get_exploit_link, KNOWN_EXPLOITS
from oracle.claude_client import _count_by_key, _fallback_narrative, _fallback_remediation


class TestGenerateRecommendations:
    def test_critical_cves_triggers_urgent(self):
        recs = _generate_recommendations(
            {"critical_cves": 3, "high_cves": 0, "total_cves": 3},
            {"active_paths": 0, "active_alerts": 0},
            {"critical": 0, "total": 0},
        )
        assert any("URGENT" in r for r in recs)

    def test_attack_paths_trigger_high_priority(self):
        recs = _generate_recommendations(
            {"critical_cves": 0, "high_cves": 0, "total_cves": 0},
            {"active_paths": 6, "active_alerts": 0},
            {"critical": 0, "total": 0},
        )
        assert any("High priority" in r for r in recs)

    def test_critical_anomalies(self):
        recs = _generate_recommendations(
            {"critical_cves": 0, "high_cves": 0, "total_cves": 0},
            {"active_paths": 0, "active_alerts": 0},
            {"critical": 2, "total": 5},
        )
        assert any("Investigate" in r for r in recs)

    def test_all_clear(self):
        recs = _generate_recommendations(
            {"critical_cves": 0, "high_cves": 0, "total_cves": 0},
            {"active_paths": 0, "active_alerts": 0},
            {"critical": 0, "total": 0},
        )
        assert any("Continue monitoring" in r for r in recs)

    def test_multiple_recommendations(self):
        recs = _generate_recommendations(
            {"critical_cves": 2, "high_cves": 1, "total_cves": 3},
            {"active_paths": 8, "active_alerts": 0},
            {"critical": 3, "total": 10},
        )
        assert len(recs) >= 2


class TestGetExploitLink:
    def test_known_exploit(self):
        result = get_exploit_link("CVE-2017-0144")
        assert result["title"] is not None
        assert result["edb_id"] is not None

    def test_unknown_exploit(self):
        result = get_exploit_link("CVE-2024-99999")
        assert result["edb_id"] is None
        assert result["msf_module"] is None

    def test_case_insensitive(self):
        assert get_exploit_link("cve-2017-0144") == get_exploit_link("CVE-2017-0144")

    def test_known_exploits_fully_formed(self):
        """Every entry in KNOWN_EXPLOITS should have required fields."""
        for cve_id, info in KNOWN_EXPLOITS.items():
            assert "title" in info, f"{cve_id} missing title"
            assert cve_id.startswith("CVE-"), f"{cve_id} invalid format"


class TestCountByKey:
    def test_count_by_service(self):
        items = [
            {"service": "ssh", "port": 22},
            {"service": "ssh", "port": 2222},
            {"service": "http", "port": 80},
        ]
        result = _count_by_key(items, "service")
        assert result == {"ssh": 2, "http": 1}

    def test_empty_list(self):
        assert _count_by_key([], "service") == {}

    def test_missing_key_skipped(self):
        items = [{"a": 1}, {"a": 2}, {"b": 3}]
        result = _count_by_key(items, "a")
        # Missing 'a' key defaults to "UNKNOWN"
        assert result == {1: 1, 2: 1, "UNKNOWN": 1}


class TestFallbackNarrative:
    def test_empty_context(self):
        narrative = _fallback_narrative({
            "hosts": [{"ip": "10.0.0.1", "risk_score": 50, "os": "Linux",
                       "cves": [{"cve_id": "CVE-2024-0001", "cvss_v3": 5.0}],
                       "ports": [{"port": 80}]}],
            "attack_paths": [],
            "total_rules": 0,
        })
        assert isinstance(narrative, str)
        assert len(narrative) > 0

    def test_with_hosts(self):
        context = {
            "hosts": [{"ip": "10.0.0.1", "risk_score": 75, "os": "Linux",
                       "cves": [{"cve_id": "CVE-2024-0001", "cvss_v3": 9.0}],
                       "ports": [{"port": 22, "service": "ssh"}]}],
            "attack_paths": [],
            "total_rules": 5,
        }
        narrative = _fallback_narrative(context)
        assert "10.0.0.1" in narrative

    def test_with_attack_paths(self):
        context = {
            "hosts": [{"ip": "10.0.0.1", "risk_score": 50, "os": "Linux",
                       "cves": [], "ports": [{"port": 22}]}],
            "attack_paths": [{"steps": [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}],
                              "total_steps": 2, "est_minutes": 16}],
            "total_rules": 3,
        }
        narrative = _fallback_narrative(context)
        assert isinstance(narrative, str)


class TestFallbackRemediation:
    def test_empty_hosts(self):
        remediation = _fallback_remediation({"hosts": []})
        assert isinstance(remediation, str)

    def test_with_cves(self):
        context = {
            "hosts": [
                {"ip": "10.0.0.1", "cves": [{"id": "CVE-2024-0001", "cvss": 9.1}]},
            ],
        }
        remediation = _fallback_remediation(context)
        assert "CVE-2024-0001" in remediation