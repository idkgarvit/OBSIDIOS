"""Tests for phantom/path_finder.py — MITRE ATT&CK mapping and kill chains."""
import math
import networkx as nx
from phantom.path_finder import (
    _get_technique_for_node, MITRE_MAP, CVE_TECHNIQUE_MAP, _find_kill_chains
)
from chronicle.models import AttackStep


class TestGetTechniqueForNode:
    def test_cve_mapping_takes_priority(self):
        """CVE_TECHNIQUE_MAP matches should be preferred over port-based."""
        node = {
            "cves": [{"cve_id": "CVE-2017-0144", "effective_cvss": 10.0}],
            "ports": [{"port": 80}],
        }
        tech, tactic, desc = _get_technique_for_node(node)
        assert tech == "T1210"

    def test_port_based_mapping(self):
        """Port 22 should map to SSH lateral movement."""
        node = {"cves": [], "ports": [{"port": 22}]}
        tech, tactic, desc = _get_technique_for_node(node)
        assert tech == "T1021.004"

    def test_rdp_port_mapping(self):
        """Port 3389 should map to RDP lateral movement."""
        node = {"cves": [], "ports": [{"port": 3389}]}
        tech, tactic, desc = _get_technique_for_node(node)
        assert tech == "T1021.001"

    def test_smb_port_mapping(self):
        """Port 445 should map to SMB lateral movement."""
        node = {"cves": [], "ports": [{"port": 445}]}
        tech, _, _ = _get_technique_for_node(node)
        assert tech == "T1021.002"

    def test_fallback_generic(self):
        """Unknown ports should fall back to generic T1059."""
        node = {"cves": [], "ports": [{"port": 9999}]}
        tech, tactic, desc = _get_technique_for_node(node)
        assert tech == "T1059"

    def test_no_ports_no_cves(self):
        """Empty node should fall back to generic."""
        node = {"cves": [], "ports": []}
        tech, _, _ = _get_technique_for_node(node)
        assert tech == "T1059"

    def test_multiple_cves_takes_first_match(self):
        """First matching CVE in CVE_TECHNIQUE_MAP should be used."""
        node = {
            "cves": [
                {"cve_id": "CVE-2014-6271", "effective_cvss": 10.0},
                {"cve_id": "CVE-2017-0144", "effective_cvss": 9.0},
            ],
            "ports": [],
        }
        tech, _, _ = _get_technique_for_node(node)
        assert tech == "T1190"  # Shellshock comes first

    def test_unknown_cve_with_ports(self):
        """CVE not in map should fall through to port-based mapping."""
        node = {
            "cves": [{"cve_id": "CVE-2024-99999", "effective_cvss": 5.0}],
            "ports": [{"port": 22}],
        }
        tech, _, _ = _get_technique_for_node(node)
        assert tech == "T1021.004"  # SSH


class TestCveTechniqueMap:
    """Validate that CVE_TECHNIQUE_MAP entries are well-formed."""

    def test_all_entries_have_technique_and_tactic(self):
        for cve_id, (tech, tactic) in CVE_TECHNIQUE_MAP.items():
            assert cve_id.startswith("CVE-"), f"{cve_id} doesn't start with CVE-"
            assert len(tech) > 0, f"{cve_id} has empty technique"
            assert len(tactic) > 0, f"{cve_id} has empty tactic"

    def test_notable_cves_present(self):
        """Well-known CVEs should be present in the map."""
        assert "CVE-2017-0144" in CVE_TECHNIQUE_MAP  # EternalBlue
        assert "CVE-2021-44228" in CVE_TECHNIQUE_MAP  # Log4Shell
        assert "CVE-2014-6271" in CVE_TECHNIQUE_MAP  # Shellshock


class TestMitreMap:
    """Validate that MITRE_MAP entries are well-formed."""

    def test_all_entries_have_valid_structure(self):
        for port_set, technique, tactic, description in MITRE_MAP:
            assert isinstance(port_set, set), f"port_set is not a set: {port_set}"
            assert all(isinstance(p, int) for p in port_set), f"non-int port in {port_set}"
            assert technique.startswith("T"), f"technique doesn't start with T: {technique}"
            assert len(tactic) > 0
            assert len(description) > 0

    def test_no_duplicate_ports(self):
        """Each port should appear in at most one MITRE_MAP entry (by design)."""
        all_ports = []
        for port_set, _, _, _ in MITRE_MAP:
            all_ports.extend(port_set)
        assert len(all_ports) == len(set(all_ports)), "Duplicate ports in MITRE_MAP"


class TestFindKillChains:
    def test_empty_graph(self):
        g = nx.DiGraph()
        paths = _find_kill_chains(g, [], [], max_paths=10)
        assert paths == []

    def test_single_hop_path(self):
        """A directly reachable host with a high-value target."""
        g = nx.DiGraph()
        g.add_node(1, ip="10.0.0.1", ports=[{"port": 22}], cves=[], asset_value=5)
        g.add_node(2, ip="10.0.0.2", ports=[], cves=[{"cve_id": "CVE-2017-0144", "effective_cvss": 10.0, "exploit_status": "CONFIRMED_EXPLOITABLE"}], asset_value=10)
        _build_test_edges(g)
        entries = [{"id": 1, **g.nodes[1]}]
        targets = [{"id": 2, **g.nodes[2]}]
        paths = _find_kill_chains(g, entries, targets, max_paths=10)
        assert len(paths) > 0
        assert paths[0].target_host_id == 2
        assert paths[0].total_steps >= 2

    def test_no_path_disconnected(self):
        """Disconnected hosts should produce no paths."""
        g = nx.DiGraph()
        g.add_node(1, ip="10.0.0.1", ports=[], cves=[], asset_value=5)
        g.add_node(2, ip="10.0.0.2", ports=[], cves=[], asset_value=10)
        entries = [{"id": 1, **g.nodes[1]}]
        targets = [{"id": 2, **g.nodes[2]}]
        paths = _find_kill_chains(g, entries, targets, max_paths=10)
        assert paths == []

    def test_attacker_roi_scoring(self):
        """Higher asset value / lower cost path should give higher ROI."""
        g = nx.DiGraph()
        g.add_node(1, ip="10.0.0.1", ports=[{"port": 22}], cves=[], asset_value=5)
        g.add_node(2, ip="10.0.0.2", ports=[], cves=[{"effective_cvss": 5.0, "exploit_status": "UNVERIFIED"}], asset_value=10)
        g.add_edge(1, 2, weight=10)
        entries = [{"id": 1, **g.nodes[1]}]
        targets = [{"id": 2, **g.nodes[2]}]
        paths = _find_kill_chains(g, entries, targets, max_paths=10)
        # ROI = (10 * 10.0) / max(10, 0.1) = 10.0
        assert any(math.isclose(p.attacker_roi, 10.0, rel_tol=1e-9) for p in paths)

    def test_max_paths_limit(self):
        """Only max_paths should be returned."""
        g = nx.DiGraph()
        for i in range(10):
            g.add_node(i, ip=f"10.0.0.{i}", ports=([{"port": 22}] if i % 2 == 0 else []),
                       cves=([{"effective_cvss": 5.0, "exploit_status": "UNVERIFIED"}] if i % 2 == 1 else []),
                       asset_value=5)
        for i in range(0, 9, 2):
            g.add_edge(i, i + 1, weight=10)
        entries = [{"id": i, **g.nodes[i]} for i in range(0, 9, 2)]
        targets = [{"id": i, **g.nodes[i]} for i in range(1, 10, 2)]
        paths = _find_kill_chains(g, entries, targets, max_paths=3)
        assert len(paths) <= 3


def _build_test_edges(g: nx.DiGraph):
    """Helper to add edges that allow testing."""
    g.add_edge(1, 2, weight=10)