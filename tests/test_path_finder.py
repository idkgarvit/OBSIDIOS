"""Tests for phantom/path_finder.py — MITRE ATT&CK mapping and kill chains."""
import asyncio
import math

import networkx as nx

from phantom.path_finder import CVE_TECHNIQUE_MAP, MITRE_MAP, _find_kill_chains, _get_technique_for_node


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

class TestSimulationRobustness:
    def test_null_asset_value_does_not_abort_path_finding(self):
        """A legacy host with NULL asset_value must still produce a path."""
        g = nx.DiGraph()
        g.add_node(1, ip="10.0.0.1", ports=[{"port": 22}], cves=[],
                   asset_value=None)
        g.add_node(2, ip="10.0.0.2", ports=[], cves=[],
                   asset_value=None)
        g.add_edge(1, 2, weight=10)
        entries = [{"id": 1, **g.nodes[1]}]
        targets = [{"id": 2, **g.nodes[2]}]
        paths = _find_kill_chains(g, entries, targets, max_paths=5)
        assert len(paths) == 1
        # NULL is treated as the documented default asset value (5).
        assert math.isclose(paths[0].attacker_roi, 5.0, rel_tol=1e-9)

    def test_simulation_survives_total_persistence_failure(self, monkeypatch):
        """If no path can be stored, the run must not raise on max()."""
        from phantom import path_finder as pf

        g = nx.DiGraph()
        g.add_node(1, ip="10.0.0.1", asset_value=5)
        g.add_node(2, ip="10.0.0.2", asset_value=9)
        g.add_edge(1, 2, weight=10)

        monkeypatch.setattr(pf, "get_graph", lambda: g)
        monkeypatch.setattr(pf, "get_most_exposed_entries", lambda top_n=5: [
            {"id": 1, **g.nodes[1]}])
        monkeypatch.setattr(pf, "get_highest_value_targets", lambda top_n=3: [
            {"id": 2, **g.nodes[2]}])

        async def no_store(_path):
            return None

        monkeypatch.setattr(pf, "_persist_path", no_store)
        monkeypatch.setattr(pf, "_print_paths", lambda _paths: None)

        result = asyncio.run(pf.run_simulation(max_paths=5))
        assert result.total_paths == 0
        assert result.highest_roi == 0.0


class TestMalformedGraphData:
    """Graph attributes come from DB rows and may be NULL or wrong-typed."""

    def test_technique_lookup_tolerates_null_and_bad_entries(self):
        assert _get_technique_for_node({"cves": None, "ports": None})[0] == "T1059"
        assert _get_technique_for_node(
            {"cves": [None, "x", {"cve_id": None}],
             "ports": [None, "x", {"port": None}]}
        )[0] == "T1059"

    def test_string_port_numbers_still_match_mitre(self):
        node = {"cves": [], "ports": [{"port": "22"}, {"port": "junk"}]}
        assert _get_technique_for_node(node)[0] == "T1021.004"

    def test_non_dict_entries_and_missing_ids_are_skipped(self):
        g = nx.DiGraph()
        g.add_node(1, ip="10.0.0.1")
        g.add_node(2, ip="10.0.0.2")
        g.add_edge(1, 2, weight=10)

        assert _find_kill_chains(g, [None, "x", {}], [{"id": 2}], max_paths=1) == []
        assert _find_kill_chains(g, [{"id": 1}], [None, {}], max_paths=1) == []
        assert _find_kill_chains(g, "@not-a-list", [{"id": 2}], max_paths=1) == []

    def test_string_cvss_and_asset_value_are_coerced(self):
        """A string score used to raise TypeError in the ``>`` comparison."""
        g = nx.DiGraph()
        g.add_node(1, ip="10.0.0.1", ports=[{"port": 22}], cves=[])
        g.add_node(2, ip="10.0.0.2", ports=[], asset_value="7",
                   cves=[{"cve_id": "CVE-2024-1111", "effective_cvss": "9.8"}])
        g.add_edge(1, 2, weight=10)

        paths = _find_kill_chains(
            g, [{"id": 1, **g.nodes[1]}], [{"id": 2, **g.nodes[2]}], max_paths=1)

        assert len(paths) == 1
        assert math.isclose(paths[0].attacker_roi, 7.0, rel_tol=1e-9)
        assert paths[0].steps[-1].cve_id == "CVE-2024-1111"

    def test_nan_score_is_ignored(self):
        g = nx.DiGraph()
        g.add_node(1, ip="10.0.0.1", ports=[{"port": 22}], cves=[])
        g.add_node(2, ip="10.0.0.2", ports=[], asset_value=5,
                   cves=[{"cve_id": "CVE-2024-2222", "effective_cvss": float("nan")}])
        g.add_edge(1, 2, weight=10)

        paths = _find_kill_chains(
            g, [{"id": 1, **g.nodes[1]}], [{"id": 2, **g.nodes[2]}], max_paths=1)

        assert len(paths) == 1
        assert paths[0].steps[-1].cve_id is None

    def test_node_without_ip_still_produces_a_step(self):
        g = nx.DiGraph()
        g.add_node(1)
        g.add_node(2, ip="10.0.0.2")
        g.add_edge(1, 2, weight=10)

        paths = _find_kill_chains(
            g, [{"id": 1}], [{"id": 2, **g.nodes[2]}], max_paths=1)

        assert len(paths) == 1
        assert paths[0].steps[0].ip == "host-1"
        assert paths[0].steps[-1].ip == "10.0.0.2"


class _RecordingDB:
    def __init__(self):
        self.calls = []

    async def execute(self, sql, params=()):
        self.calls.append((sql, params))


def _two_node_graph() -> nx.DiGraph:
    g = nx.DiGraph()
    g.add_node(1, ip="10.0.0.1", ports=[{"port": 22}], cves=[], asset_value=5)
    g.add_node(2, ip="10.0.0.2", ports=[], cves=[], asset_value=9)
    g.add_edge(1, 2, weight=10)
    return g


class TestStalePathRetirement:
    def test_empty_simulation_retires_every_active_path(self, monkeypatch):
        """A completed run that finds nothing must deactivate old paths."""
        from phantom import path_finder as pf

        g = nx.DiGraph()
        g.add_node(1, ip="10.0.0.1", ports=[])
        g.add_node(2, ip="10.0.0.2", ports=[])
        # No edge: the graph is built, but no path is reachable.

        monkeypatch.setattr(pf, "get_graph", lambda: g)
        monkeypatch.setattr(pf, "get_most_exposed_entries",
                            lambda top_n=5: [{"id": 1, **g.nodes[1]}])
        monkeypatch.setattr(pf, "get_highest_value_targets",
                            lambda top_n=3: [{"id": 2, **g.nodes[2]}])
        monkeypatch.setattr(pf, "_print_paths", lambda _paths: None)

        fake_db = _RecordingDB()
        monkeypatch.setattr(pf, "db", fake_db)

        result = asyncio.run(pf.run_simulation(max_paths=5))

        assert result.total_paths == 0
        assert fake_db.calls == [
            ("UPDATE attack_paths SET is_active=0 WHERE is_active=1", ())
        ]

    def test_one_unwritable_path_does_not_discard_the_rest(self, monkeypatch):
        from phantom import path_finder as pf

        g = nx.DiGraph()
        g.add_node(1, ip="10.0.0.1", ports=[{"port": 22}], cves=[], asset_value=5)
        g.add_node(2, ip="10.0.0.2", ports=[], cves=[], asset_value=5)
        g.add_node(3, ip="10.0.0.3", ports=[], cves=[], asset_value=5)
        g.add_edge(1, 2, weight=10)
        g.add_edge(1, 3, weight=20)

        monkeypatch.setattr(pf, "get_graph", lambda: g)
        monkeypatch.setattr(pf, "get_most_exposed_entries",
                            lambda top_n=5: [{"id": 1, **g.nodes[1]}])
        monkeypatch.setattr(pf, "get_highest_value_targets",
                            lambda top_n=3: [{"id": 2, **g.nodes[2]},
                                             {"id": 3, **g.nodes[3]}])
        monkeypatch.setattr(pf, "_print_paths", lambda _paths: None)

        async def store(path):
            if path.target_host_id == 2:
                raise RuntimeError("disk is on fire")
            return 900 + path.target_host_id

        monkeypatch.setattr(pf, "_persist_path", store)
        fake_db = _RecordingDB()
        monkeypatch.setattr(pf, "db", fake_db)

        result = asyncio.run(pf.run_simulation(max_paths=5))

        assert [p.target_host_id for p in result.paths] == [3]
        assert result.total_paths == 1
        assert len(fake_db.calls) == 1
        sql, params = fake_db.calls[0]
        assert "id NOT IN (?)" in sql
        assert params == (903,)

    def test_no_persisted_path_keeps_the_previous_rows(self, monkeypatch):
        """A total write failure must not blank the existing kill chains."""
        from phantom import path_finder as pf

        g = _two_node_graph()
        monkeypatch.setattr(pf, "get_graph", lambda: g)
        monkeypatch.setattr(pf, "get_most_exposed_entries",
                            lambda top_n=5: [{"id": 1, **g.nodes[1]}])
        monkeypatch.setattr(pf, "get_highest_value_targets",
                            lambda top_n=3: [{"id": 2, **g.nodes[2]}])
        monkeypatch.setattr(pf, "_print_paths", lambda _paths: None)

        async def store(_path):
            return None

        monkeypatch.setattr(pf, "_persist_path", store)
        fake_db = _RecordingDB()
        monkeypatch.setattr(pf, "db", fake_db)

        result = asyncio.run(pf.run_simulation(max_paths=5))

        assert result.total_paths == 0
        assert fake_db.calls == []

    def test_retirement_helper_against_the_real_database(self):
        import uuid

        from chronicle import db
        from dashboard.app import run_async
        from phantom.path_finder import _retire_stale_paths

        octet = uuid.uuid4().int % 200 + 20
        ip_a = f"10.92.{octet}.1"
        ip_b = f"10.92.{octet}.2"

        async def scenario():
            await db.init()
            path_ids = []
            try:
                for ip in (ip_a, ip_b):
                    await db.execute(
                        "INSERT INTO hosts (ip, is_active) VALUES (?, 1)", (ip,))
                host_ids = [
                    await db.fetch_val("SELECT id FROM hosts WHERE ip=?", (ip,))
                    for ip in (ip_a, ip_b)
                ]
                for entry, target in ((host_ids[0], host_ids[1]),
                                      (host_ids[1], host_ids[0])):
                    await db.execute(
                        "INSERT INTO attack_paths"
                        " (entry_host_id, target_host_id, path_json, is_active)"
                        " VALUES (?,?,?,1)",
                        (entry, target, "[]"))
                rows = await db.fetch_all(
                    "SELECT id FROM attack_paths WHERE entry_host_id IN (?,?)"
                    " ORDER BY id", tuple(host_ids))
                path_ids = [row["id"] for row in rows]
                assert len(path_ids) == 2

                await _retire_stale_paths([path_ids[0]])
                states = await db.fetch_all(
                    "SELECT id, is_active FROM attack_paths"
                    " WHERE id IN (?,?) ORDER BY id", tuple(path_ids))
                first_pass = {row["id"]: row["is_active"] for row in states}

                await _retire_stale_paths([])
                states = await db.fetch_all(
                    "SELECT id, is_active FROM attack_paths"
                    " WHERE id IN (?,?) ORDER BY id", tuple(path_ids))
                second_pass = {row["id"]: row["is_active"] for row in states}
                return path_ids, first_pass, second_pass
            finally:
                for path_id in path_ids:
                    await db.execute(
                        "DELETE FROM attack_paths WHERE id=?", (path_id,))
                await db.execute(
                    "DELETE FROM hosts WHERE ip IN (?,?)", (ip_a, ip_b))

        path_ids, first_pass, second_pass = run_async(scenario())

        assert first_pass[path_ids[0]] == 1
        assert first_pass[path_ids[1]] == 0
        assert second_pass == {path_ids[0]: 0, path_ids[1]: 0}


def test_print_paths_escapes_untrusted_host_data(monkeypatch, capsys):
    """Collector-supplied text must never be parsed as Rich markup.

    A step IP containing `[/]` raised MarkupError after the paths had already
    been persisted, aborting the scan cycle.
    """
    from chronicle.models import AttackPath, AttackStep
    from phantom.path_finder import _print_paths

    monkeypatch.setenv("COLUMNS", "200")
    path = AttackPath(
        steps=[
            AttackStep(
                host_id=1, ip="10.0.0.1[/]",
                technique="T1021.004[/]", tactic="Lateral [bold]Movement",
                cve_id="CVE-2021-44228[/]",
            ),
            AttackStep(
                host_id=2, ip="10.0.0.2",
                technique="T1059", tactic="Execution",
            ),
        ],
        total_steps=2,
        attacker_roi=9.5,
        estimated_time_minutes=12,
    )

    _print_paths([path])

    out = capsys.readouterr().out
    assert "10.0.0.1[/]" in out
    assert "T1021.004[/]" in out
