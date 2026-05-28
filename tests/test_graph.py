"""Tests for iris/graph_builder.py — pure function tests."""
import networkx as nx
from iris.graph_builder import (
    _compute_risk, _build_edges, export_for_dashboard,
    get_highest_value_targets, get_most_exposed_entries, apply_shield_block,
)


def _make_node(overrides: dict | None = None) -> dict:
    """Helper to create a default graph node dict for _compute_risk."""
    node = {
        "cves": [],
        "ports": [],
        "asset_value": 5,
    }
    if overrides:
        node.update(overrides)
    return node


class TestComputeRisk:
    def test_no_cves_no_ports(self):
        """A host with no CVEs and no ports should have base risk from asset_value."""
        risk = _compute_risk(_make_node({"asset_value": 5}))
        assert risk == 5.0

    def test_max_cvss_10(self):
        """A host with a CVSS 10 CVE should get high risk."""
        risk = _compute_risk(_make_node({
            "cves": [{"effective_cvss": 10.0, "severity": "CRITICAL", "exploit_status": "LIKELY_VULNERABLE"}],
        }))
        assert risk == 39.0  # cve(4*6=24) + port(0) + exploit(10) + asset(5) = 39

    def test_confirmed_exploit_boosts_risk(self):
        """CONFIRMED_EXPLOITABLE gets 20 exploit points instead of 10."""
        risk = _compute_risk(_make_node({
            "cves": [{"effective_cvss": 10.0, "severity": "CRITICAL", "exploit_status": "CONFIRMED_EXPLOITABLE"}],
        }))
        assert risk == 49.0  # cve(4*6=24) + port(0) + exploit(20) + asset(5) = 49

    def test_multiple_cves_accumulates(self):
        """Multiple CVEs should accumulate severity weight, not just take max CVSS."""
        risk = _compute_risk(_make_node({
            "cves": [
                {"effective_cvss": 2.0, "severity": "LOW", "exploit_status": "UNVERIFIED"},
                {"effective_cvss": 9.0, "severity": "HIGH", "exploit_status": "CONFIRMED_EXPLOITABLE"},
            ],
        }))
        # raw = 0.5(LOW) + 2(HIGH) = 2.5 → cve = min(2.5*6, 50) = 15 + port(0) + exploit(20) + asset(5) = 40
        assert risk == 40.0

    def test_port_count_increases_risk(self):
        """More open ports should increase risk up to the 20-port cap."""
        ports_20 = [{"port": i} for i in range(20)]
        risk = _compute_risk(_make_node({"ports": ports_20, "asset_value": 5}))
        assert risk == 25.0  # cve(0) + port(20) + exploit(0) + asset(5) = 25

    def test_asset_value_scales(self):
        """Higher asset value should increase risk."""
        low = _compute_risk(_make_node({"asset_value": 1}))
        high = _compute_risk(_make_node({"asset_value": 10}))
        assert low < high

    def test_null_asset_value(self):
        """NULL/None asset_value should default to 5."""
        risk = _compute_risk(_make_node({"asset_value": None}))
        assert risk == 5.0  # asset: (5/10)*10 = 5

    def test_fallback_cvss_when_no_severity(self):
        """Missing severity should infer weight from effective_cvss."""
        risk = _compute_risk(_make_node({
            "cves": [{"effective_cvss": 7.5, "exploit_status": "THEORETICAL"}],
        }))
        # raw = (7.5/10)*2 = 1.5 → cve = min(1.5*6, 50) = 9 + port(0) + exploit(0) + asset(5) = 14
        assert risk == 14.0


class TestBuildEdges:
    def test_empty_graph(self):
        g = nx.DiGraph()
        _build_edges(g)
        assert g.number_of_edges() == 0

    def test_single_node_no_edges(self):
        g = nx.DiGraph()
        g.add_node(1, ip="10.0.0.1", ports=[], cves=[])
        _build_edges(g)
        assert g.number_of_edges() == 0

    def test_edge_between_connected_hosts(self):
        g = nx.DiGraph()
        g.add_node(1, ip="10.0.0.1", ports=[{"port": 22}], cves=[])
        g.add_node(2, ip="10.0.0.2", ports=[{"port": 80}], cves=[{"effective_cvss": 5.0, "exploit_status": "UNVERIFIED"}])
        _build_edges(g)
        # Both directions: node 1 has pivot port 22, node 2 has CVEs
        assert g.has_edge(1, 2)
        assert g.has_edge(2, 1)

    def test_bidirectional_pivot_ports(self):
        """Both hosts with pivot ports should get bidirectional edges."""
        g = nx.DiGraph()
        g.add_node(1, ip="10.0.0.1", ports=[{"port": 22}], cves=[])
        g.add_node(2, ip="10.0.0.2", ports=[{"port": 445}], cves=[])
        _build_edges(g)
        assert g.has_edge(1, 2)
        assert g.has_edge(2, 1)

    def test_edge_weight_from_cvss(self):
        """Edge weight should be inversely proportional to CVSS."""
        g = nx.DiGraph()
        g.add_node(1, ip="10.0.0.1", ports=[{"port": 22}], cves=[])
        g.add_node(2, ip="10.0.0.2", ports=[], cves=[{"effective_cvss": 10.0}])
        _build_edges(g)
        edge_data = g.get_edge_data(1, 2)
        assert edge_data is not None
        assert "weight" in edge_data
        assert edge_data["weight"] < 100  # High CVSS = low cost


class TestExportForDashboard:
    def test_empty_graph(self):
        from iris.graph_builder import _graph
        _graph.clear()
        result = export_for_dashboard()
        assert result == {"nodes": [], "links": []}

    def test_populated_graph(self):
        from iris.graph_builder import _graph
        _graph.clear()
        _graph.add_node(1, ip="10.0.0.1", risk_score=50, asset_value=5, cves=[{"cve_id": "CVE-2024-0001"}], ports=[{"port": 80}])
        result = export_for_dashboard()
        assert len(result["nodes"]) == 1
        n = result["nodes"][0]
        assert n["ip"] == "10.0.0.1"
        assert n["risk"] == 50
        assert n["asset"] == 5
        assert n["cve_count"] == 1
        assert n["port_count"] == 1


class TestGetHighestValueTargets:
    def test_no_nodes(self):
        from iris.graph_builder import _graph
        _graph.clear()
        assert get_highest_value_targets() == []

    def test_returns_sorted(self):
        from iris.graph_builder import _graph
        _graph.clear()
        _graph.add_node(1, ip="10.0.0.1", asset_value=5, ports=[], cves=[])
        _graph.add_node(2, ip="10.0.0.2", asset_value=10, ports=[], cves=[])
        _graph.add_node(3, ip="10.0.0.3", asset_value=1, ports=[], cves=[])
        targets = get_highest_value_targets(top_n=2)
        assert len(targets) == 2
        assert targets[0]["asset_value"] == 10
        assert targets[1]["asset_value"] == 5


class TestGetMostExposedEntries:
    def test_no_nodes(self):
        from iris.graph_builder import _graph
        _graph.clear()
        assert get_most_exposed_entries() == []

    def test_returns_sorted(self):
        from iris.graph_builder import _graph
        _graph.clear()
        _graph.add_node(1, ip="10.0.0.1", risk_score=90, asset_value=5, ports=[], cves=[])
        _graph.add_node(2, ip="10.0.0.2", risk_score=10, asset_value=5, ports=[], cves=[])
        entries = get_most_exposed_entries()
        assert entries[0]["risk_score"] == 90


class TestApplyShieldBlock:
    def test_removes_edge(self):
        from iris.graph_builder import _graph
        _graph.clear()
        _graph.add_edge(1, 2)
        assert _graph.has_edge(1, 2)
        apply_shield_block(1, 2)
        assert not _graph.has_edge(1, 2)

    def test_noop_if_no_edge(self):
        from iris.graph_builder import _graph
        _graph.clear()
        _graph.add_node(1, ip="10.0.0.1", ports=[], cves=[])
        _graph.add_node(2, ip="10.0.0.2", ports=[], cves=[])
        apply_shield_block(1, 2)  # Should not raise
        assert not _graph.has_edge(1, 2)