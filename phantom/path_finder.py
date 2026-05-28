"""
phantom/path_finder.py
───────────────────────
PHANTOM — Autonomous red AI agent.

Finds the most dangerous attack paths through your network using:
  • Dijkstra shortest-path on the attack graph (lowest cost = easiest path)
  • MITRE ATT&CK technique mapping per step
  • Attacker ROI scoring (asset value vs effort)
  • Claude API for human-readable attack narratives

The output feeds directly into FORGE for Suricata rule generation.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field

import networkx as nx
from loguru import logger

from chronicle import db
from chronicle.models import AttackPath, AttackStep
from iris.graph_builder import get_graph, get_highest_value_targets, get_most_exposed_entries


# ── MITRE ATT&CK technique mapping ────────────────────────────────────────────
# Maps service/port patterns → MITRE technique + tactic
# Format: (port_or_service_pattern) → (technique_id, tactic, description)
MITRE_MAP: list[tuple[set, str, str, str]] = [
    ({21},          "T1021.002", "Lateral Movement",   "SMB/Windows Admin Shares via FTP staging"),
    ({22},          "T1021.004", "Lateral Movement",   "Remote Services: SSH"),
    ({23},          "T1021.004", "Lateral Movement",   "Remote Services: Telnet (cleartext)"),
    ({80, 443, 8080},"T1190",   "Initial Access",      "Exploit Public-Facing Application"),
    ({445},         "T1021.002", "Lateral Movement",   "Remote Services: SMB/Windows Admin Shares"),
    ({3389},        "T1021.001", "Lateral Movement",   "Remote Services: Remote Desktop Protocol"),
    ({5985, 5986},  "T1021.006", "Lateral Movement",   "Remote Services: WinRM"),
    ({1433, 3306, 5432}, "T1078","Defense Evasion",    "Valid Accounts: Database credential abuse"),
    ({6667, 6668},  "T1071.003", "Command and Control","Application Layer Protocol: IRC"),
    ({4444, 4445},  "T1571",    "Command and Control", "Non-Standard Port: Likely reverse shell"),
    ({139},         "T1557.001", "Credential Access",  "LLMNR/NBT-NS Poisoning via NetBIOS"),
    ({2049},        "T1049",    "Discovery",           "Network Share Discovery: NFS"),
    ({512, 513, 514},"T1021",   "Lateral Movement",   "Remote Services: r-services (rexec/rlogin/rsh)"),
    ({8180, 8443},  "T1190",    "Initial Access",      "Exploit Public-Facing Web Application"),
]

# CVE-to-technique overrides (specific CVEs map to specific techniques)
CVE_TECHNIQUE_MAP: dict[str, tuple[str, str]] = {
    "CVE-2004-2687": ("T1210", "Lateral Movement"),       # distcc RCE
    "CVE-2007-2447": ("T1210", "Lateral Movement"),       # Samba username RCE
    "CVE-2009-3103": ("T1210", "Lateral Movement"),       # SMB2 RCE
    "CVE-2011-2523": ("T1210", "Initial Access"),         # vsftpd backdoor
    "CVE-2012-1823": ("T1190", "Initial Access"),         # PHP CGI RCE
    "CVE-2014-6271": ("T1190", "Initial Access"),         # Shellshock
    "CVE-2021-44228": ("T1190", "Initial Access"),        # Log4Shell
    "CVE-2017-0144": ("T1210", "Lateral Movement"),       # EternalBlue
    "CVE-2019-0708": ("T1210", "Lateral Movement"),       # BlueKeep RDP
}


def _get_technique_for_node(node_data: dict) -> tuple[str, str, str]:
    """
    Determine the most relevant MITRE technique for attacking this node.
    Priority: confirmed CVE mapping → port-based mapping → generic
    """
    # Check CVEs first — most specific
    for cve in node_data.get("cves", []):
        cve_id = cve.get("cve_id", "")
        if cve_id in CVE_TECHNIQUE_MAP:
            tech, tactic = CVE_TECHNIQUE_MAP[cve_id]
            return tech, tactic, f"Exploit {cve_id}"

    # Port-based mapping
    ports = {p["port"] for p in node_data.get("ports", [])}
    for port_set, technique, tactic, desc in MITRE_MAP:
        if ports & port_set:
            return technique, tactic, desc

    return "T1059", "Execution", "Command and Scripting Interpreter"


@dataclass
class SimulationResult:
    """Full result of one PHANTOM simulation run."""
    paths:          list[AttackPath] = field(default_factory=list)
    total_paths:    int              = 0
    highest_roi:    float            = 0.0
    simulated_at:   float            = field(default_factory=time.time)
    summary:        str              = ""


# ─────────────────────────────────────────────────────────────────────────────
# Core path finding
# ─────────────────────────────────────────────────────────────────────────────

def _find_kill_chains(
    graph: nx.DiGraph,
    entry_nodes: list[dict],
    target_nodes: list[dict],
    max_paths: int = 10,
    max_depth: int = 6,
) -> list[dict]:
    """
    Find the most dangerous attack paths using Dijkstra.

    For each entry→target pair, finds the shortest (lowest cost) path.
    Cost = attack difficulty (lower = easier for attacker).

    Returns list of raw path dicts ready for DB insertion.
    """
    raw_paths = []

    for entry in entry_nodes:
        entry_id = entry["id"]

        for target in target_nodes:
            target_id = target["id"]

            if entry_id == target_id:
                continue

            try:
                # Dijkstra finds lowest-cost (easiest) path for attacker
                path_nodes = nx.dijkstra_path(
                    graph, entry_id, target_id, weight="weight"
                )
                path_cost = nx.dijkstra_path_length(
                    graph, entry_id, target_id, weight="weight"
                ) if len(path_nodes) <= max_depth else 0.0
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

            if len(path_nodes) > max_depth:
                continue

            # Build steps
            steps = []
            for node_id in path_nodes:
                node_data = graph.nodes[node_id]
                technique, tactic, desc = _get_technique_for_node(node_data)

                # Find best CVE for this step
                best_cve = None
                best_score = 0.0
                for cve in node_data.get("cves", []):
                    score = cve.get("effective_cvss") or cve.get("cvss_v3") or 0.0
                    if score > best_score:
                        best_score = score
                        best_cve   = cve.get("cve_id")

                steps.append(AttackStep(
                    host_id     = node_id,
                    ip          = node_data["ip"],
                    technique   = technique,
                    tactic      = tactic,
                    cve_id      = best_cve,
                    description = desc,
                ))

            # Attacker ROI = target asset value / path cost
            # High-value target that's cheap to reach = high ROI
            roi = (target.get("asset_value", 5) * 10.0) / max(path_cost, 0.1)

            # Estimate time based on number of steps and exploitability
            est_time = len(steps) * 8.0  # rough: 8 min per hop

            path = AttackPath(
                entry_host_id          = entry_id,
                target_host_id         = target_id,
                steps                  = steps,
                total_steps            = len(steps),
                attacker_roi           = round(roi, 3),
                estimated_time_minutes = round(est_time, 1),
                is_active              = True,
            )
            raw_paths.append(path)

    # Sort by attacker ROI descending — most dangerous first
    raw_paths.sort(key=lambda p: p.attacker_roi, reverse=True)
    return raw_paths[:max_paths]


# ─────────────────────────────────────────────────────────────────────────────
# Persist attack paths to CHRONICLE
# ─────────────────────────────────────────────────────────────────────────────

async def _persist_path(path: AttackPath) -> int | None:
    """Insert one attack path, return its DB id."""
    steps_json = json.dumps([
        {
            "host_id":    s.host_id,
            "ip":         s.ip,
            "technique":  s.technique,
            "tactic":     s.tactic,
            "cve_id":     s.cve_id,
            "description": s.description,
        }
        for s in path.steps
    ])

    row = await db.execute_returning(
        """INSERT INTO attack_paths
           (entry_host_id, target_host_id, path_json, total_steps,
            attacker_roi, estimated_time_minutes, is_active)
           VALUES (?,?,?,?,?,?,1) RETURNING id""",
        (
            path.entry_host_id,
            path.target_host_id,
            steps_json,
            path.total_steps,
            path.attacker_roi,
            path.estimated_time_minutes,
        ),
    )
    return row["id"] if row else None


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

async def run_simulation(max_paths: int = 10) -> SimulationResult:
    """
    Full PHANTOM simulation pipeline:
      1. Load live network graph
      2. Identify entry points (most exposed) and targets (highest value)
      3. Run Dijkstra kill chain finder
      4. Persist paths to CHRONICLE
      5. Return SimulationResult for FORGE to consume

    This is what feeds FORGE's rule generator.
    """
    result = SimulationResult()
    graph  = get_graph()

    if graph.number_of_nodes() == 0:
        logger.warning("[PHANTOM] Graph is empty — run IRIS scan first")
        return result

    logger.info(f"[PHANTOM] Simulating on graph: "
                f"{graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")

    # ── Get entry points and targets ───────────────────────────────────
    entries = get_most_exposed_entries(top_n=5)
    targets = get_highest_value_targets(top_n=3)

    # If no high-value targets defined, use all nodes as targets
    if not targets:
        targets = [
            {"id": nid, **data}
            for nid, data in graph.nodes(data=True)
        ]

    # Filter out gateway/router as an attack target (infrastructure, not a target)
    gateway_ip = os.environ.get('OBSIDIOS_GATEWAY', '192.168.1.1')
    targets = [t for t in targets if t.get('ip') != gateway_ip]

    if not entries:
        logger.warning("[PHANTOM] No entry points found")
        return result

    logger.info(f"[PHANTOM] Entry points: {len(entries)}, Targets: {len(targets)}")

    # ── Find kill chains ───────────────────────────────────────────────
    t0    = time.perf_counter()
    paths = _find_kill_chains(graph, entries, targets, max_paths=max_paths)
    elapsed = time.perf_counter() - t0

    if not paths:
        logger.warning("[PHANTOM] No attack paths found — check graph edges")
        return result

    # ── Persist and build result ───────────────────────────────────────
    for path in paths:
        path_id = await _persist_path(path)
        if path_id:
            path.id = path_id
            result.paths.append(path)

    result.total_paths = len(result.paths)
    result.highest_roi = max(p.attacker_roi for p in result.paths)

    logger.success(
        f"[PHANTOM] Simulation complete: {result.total_paths} kill chains found "
        f"in {elapsed*1000:.0f}ms | Highest ROI: {result.highest_roi:.1f}"
    )

    # Print attack paths to terminal
    _print_paths(result.paths)

    return result


def _print_paths(paths: list[AttackPath]) -> None:
    """Pretty-print attack paths to terminal."""
    from rich.console import Console
    from rich.table import Table
    console = Console()

    console.print("\n[bold red]━━━ PHANTOM: ATTACK PATHS DISCOVERED ━━━[/]\n")

    for i, path in enumerate(paths, 1):
        entry_ip  = path.steps[0].ip if path.steps else "?"
        target_ip = path.steps[-1].ip if path.steps else "?"

        console.print(
            f"  [bold cyan]Path #{i}[/]  "
            f"[white]{entry_ip}[/] → [red]{target_ip}[/]  "
            f"[yellow]{path.total_steps} hops[/]  "
            f"ROI: [red]{path.attacker_roi:.1f}[/]  "
            f"Est. time: [yellow]{path.estimated_time_minutes:.0f}min[/]"
        )

        for j, step in enumerate(path.steps):
            prefix = "  └─" if j == len(path.steps) - 1 else "  ├─"
            cve_str = f"[red]{step.cve_id}[/]" if step.cve_id else "[dim]no CVE[/]"
            console.print(
                f"     {prefix} [cyan]{step.ip:<18}[/] "
                f"[yellow]{step.technique}[/] "
                f"({step.tactic}) {cve_str}"
            )
        console.print()
