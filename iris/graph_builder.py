"""iris/graph_builder.py — NetworkX attack graph"""
from __future__ import annotations

import asyncio
import json
import math
import os
from typing import Any

import networkx as nx
from loguru import logger

from chronicle import db

_graph: nx.DiGraph = nx.DiGraph()
_graph_lock = asyncio.Lock()


def _numeric(value: Any, default: float = 0.0) -> float:
    """Coerce a DB/JSON attribute to a finite float without ever raising.

    Graph nodes are assembled from SQLite rows, so ``NULL``, a numeric string
    left by an older writer, or ``NaN`` can all show up here. Sorting or
    dividing those values directly raised and aborted the whole graph rebuild.
    """
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default

async def rebuild_graph() -> nx.DiGraph:
    async with _graph_lock:
        g = nx.DiGraph()
        hosts = await db.fetch_all("SELECT * FROM hosts WHERE is_active = 1")
        for h in hosts:
            g.add_node(h["id"], ip=h["ip"], mac=h["mac"], os_name=h["os_name"],
                       risk_score=h["risk_score"], asset_value=h["asset_value"],
                       vendor=h["vendor"], ports=[], cves=[])
        ports = await db.fetch_all("SELECT host_id,port,service,version,cpe FROM ports WHERE state='open'")
        for p in ports:
            if p["host_id"] in g.nodes:
                g.nodes[p["host_id"]]["ports"].append({"port":p["port"],"service":p["service"],"version":p["version"],"cpe":p["cpe"]})
        cves = await db.fetch_all(
            "SELECT pc.port_id,p.host_id,c.cve_id,c.cvss_v3,c.severity,pc.exploit_status,pc.effective_cvss "
            "FROM port_cves pc JOIN ports p ON p.id=pc.port_id JOIN cves c ON c.id=pc.cve_id "
            "WHERE pc.verified_status IS NULL OR pc.verified_status != 'NOT_AFFECTED'")
        for cv in cves:
            hid = cv["host_id"]
            if hid in g.nodes:
                g.nodes[hid]["cves"].append({"cve_id":cv["cve_id"],"cvss_v3":cv["cvss_v3"] or 0.0,
                    "severity":cv["severity"],"exploit_status":cv["exploit_status"],
                    "effective_cvss":cv["effective_cvss"] or cv["cvss_v3"] or 0.0})
        for nid in g.nodes:
            risk = _compute_risk(g.nodes[nid])
            g.nodes[nid]["risk_score"] = risk

        _build_edges(g)
        _graph.clear(); _graph.update(g)

        # Write risk scores back to DB so report shows correct values.
        # One transaction for all hosts: a /16 sweep updates thousands of rows
        # and a per-row commit makes the graph rebuild needlessly slow.
        await db.executemany(
            "UPDATE hosts SET risk_score=? WHERE id=?",
            [(g.nodes[nid]["risk_score"], nid) for nid in g.nodes],
        )

        # Store graph in DB for dashboard to consume
        cache = export_for_dashboard()
        await db.execute(
            "INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)",
            ("graph_cache", json.dumps(cache))
        )

        logger.info(f"[GRAPH] {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")
        return _graph

def _compute_risk(node: dict[str, Any]) -> float:
    cves = [cv for cv in (node.get("cves") or []) if isinstance(cv, dict)]
    raw_ports = node.get("ports")
    ports = [p for p in raw_ports if isinstance(p, dict)] if isinstance(raw_ports, list) else []
    asset_value = _numeric(node.get("asset_value")) or 5.0

    sev_weights = {"CRITICAL": 4, "HIGH": 2, "MEDIUM": 1, "LOW": 0.5}
    raw = 0.0
    for cv in cves:
        sev = cv.get("severity", "")
        if sev in sev_weights:
            raw += sev_weights[sev]
        else:
            cvss = _numeric(cv.get("effective_cvss")) or _numeric(cv.get("cvss_v3"))
            raw += (cvss / 10) * 2
    cve_score = min(raw * 6, 50)

    port_score = min(len(ports) / 20, 1.0) * 20

    statuses = [cv.get("exploit_status", "") for cv in cves]
    # VERIFIED/PUBLIC_EXPLOIT/MSF_AVAILABLE are the statuses the exploit
    # validator actually writes; omitting them meant a confirmed weaponised CVE
    # scored lower than a merely likely one.
    if any(s in ("CONFIRMED_EXPLOITABLE", "VERIFIED", "PUBLIC_EXPLOIT", "MSF_AVAILABLE")
           for s in statuses):
        exploit_score = 20
    elif "LIKELY_VULNERABLE" in statuses:
        exploit_score = 10
    else:
        exploit_score = 0

    asset_score = (asset_value / 10) * 10

    return round(min(cve_score + port_score + exploit_score + asset_score, 100), 2)

def _build_edges(g: nx.DiGraph) -> None:
    pivot_services = {22, 445, 3389, 5985, 5986, 23, 21}

    # Precompute the exploitable destinations once. The previous nested loop
    # rebuilt a port set for every (src, dst) pair, which is O(n^2) set churn:
    # on a /16 sweep with thousands of hosts the graph rebuild stalled for
    # minutes. Edges only ever point at exploitable hosts, so iterate those.
    candidates: list[tuple[int, float]] = []
    for dst_id, dst_data in g.nodes(data=True):
        dst_ports = {
            _numeric(p.get("port"), -1)
            for p in (dst_data.get("ports") or [])
            if isinstance(p, dict)
        }
        dst_cves = [cv for cv in (dst_data.get("cves") or []) if isinstance(cv, dict)]
        if bool(dst_ports & pivot_services) or dst_cves:
            best_cvss = max(
                (_numeric(cv.get("effective_cvss")) or _numeric(cv.get("cvss_v3"))
                 for cv in dst_cves),
                default=0.1,
            )
            candidates.append((dst_id, round(100.0 / max(best_cvss * 0.5, 0.01), 4)))

    if not candidates:
        return
    for src_id in g.nodes:
        for dst_id, cost in candidates:
            if src_id != dst_id:
                g.add_edge(src_id, dst_id, weight=cost)

def get_graph() -> nx.DiGraph: return _graph

def export_for_dashboard() -> dict:
    ip_by_id = {nid: d.get("ip", str(nid)) for nid, d in _graph.nodes(data=True)}
    return {
        "nodes": [{"id":ip_by_id[nid],"ip":ip_by_id[nid],"risk":d.get("risk_score",0),
                   "os":d.get("os_name") or d.get("vendor") or "Unknown",
                   "asset":d.get("asset_value",5),"cve_count":len(d.get("cves") or []),
                   "port_count":len(d.get("ports") or [])} for nid,d in _graph.nodes(data=True)],
        "links": [{"source": ip_by_id[u], "target": ip_by_id[v]} for u, v in _graph.edges()],
    }


def get_highest_value_targets(top_n: int = 5, gateway_ip: str | None = None) -> list[dict]:
    """Return N hosts with highest asset_value — PHANTOM's crown jewels."""
    if gateway_ip is None:
        gateway_ip = os.environ.get('OBSIDIOS_GATEWAY', '192.168.1.1')
    nodes = [
        (nid, data) for nid, data in _graph.nodes(data=True)
        if data.get('ip') != gateway_ip
    ]
    # A NULL/legacy asset_value must not make this sort raise TypeError.
    # NULL is the documented default (5), matching _compute_risk.
    nodes.sort(
        key=lambda x: _numeric(x[1].get("asset_value")) or 5.0,
        reverse=True,
    )
    return [{"id": nid, **data} for nid, data in nodes[:top_n]]


def get_most_exposed_entries(top_n: int = 10) -> list[dict]:
    """Return hosts most exposed to attack — highest risk_score."""
    nodes = list(_graph.nodes(data=True))
    nodes.sort(key=lambda x: _numeric(x[1].get("risk_score")), reverse=True)
    return [{"id": nid, **data} for nid, data in nodes[:top_n]]


def apply_shield_block(src_id: int, dst_id: int) -> None:
    """Remove edge when SHIELD blocks a path."""
    if _graph.has_edge(src_id, dst_id):
        _graph.remove_edge(src_id, dst_id)
        logger.info(f"[IRIS/GRAPH] Edge {src_id}→{dst_id} removed by SHIELD")

