"""iris/graph_builder.py — NetworkX attack graph"""
from __future__ import annotations
import asyncio, json, os
from typing import Any
import networkx as nx
from loguru import logger
from chronicle import db

_graph: nx.DiGraph = nx.DiGraph()
_graph_lock = asyncio.Lock()

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

        # Write risk scores back to DB so report shows correct values
        for nid in g.nodes:
            await db.execute(
                "UPDATE hosts SET risk_score=? WHERE id=?",
                (g.nodes[nid]["risk_score"], nid)
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
    cves = node.get("cves", [])
    ports = node.get("ports", [])
    asset_value = node.get("asset_value") or 5

    sev_weights = {"CRITICAL": 4, "HIGH": 2, "MEDIUM": 1, "LOW": 0.5}
    raw = 0
    for cv in cves:
        sev = cv.get("severity", "")
        if sev in sev_weights:
            raw += sev_weights[sev]
        else:
            cvss = cv.get("effective_cvss", 0) or cv.get("cvss_v3", 0) or 0
            raw += (cvss / 10) * 2
    cve_score = min(raw * 6, 50)

    port_score = min(len(ports) / 20, 1.0) * 20

    statuses = [cv.get("exploit_status", "") for cv in cves]
    exploit_score = 20 if "CONFIRMED_EXPLOITABLE" in statuses else (
                    10 if "LIKELY_VULNERABLE" in statuses else 0)

    asset_score = (asset_value / 10) * 10

    return round(min(cve_score + port_score + exploit_score + asset_score, 100), 2)

def _build_edges(g: nx.DiGraph) -> None:
    pivot_services = {22, 445, 3389, 5985, 5986, 23, 21}
    nodes = list(g.nodes(data=True))
    for src_id, src_data in nodes:
        src_ports = {p["port"] for p in src_data.get("ports",[])}
        can_pivot = bool(src_ports & pivot_services)
        for dst_id, dst_data in nodes:
            if src_id == dst_id: continue
            dst_ports = {p["port"] for p in dst_data.get("ports",[])}
            if bool(dst_ports & pivot_services) or can_pivot or dst_data.get("cves"):
                best_cvss = max((cv["effective_cvss"] for cv in dst_data.get("cves",[])), default=0.1)
                cost = round(100.0 / max(best_cvss * 0.5, 0.01), 4)
                g.add_edge(src_id, dst_id, weight=cost)

def get_graph() -> nx.DiGraph: return _graph

def export_for_dashboard() -> dict:
    ip_by_id = {nid: d.get("ip", str(nid)) for nid, d in _graph.nodes(data=True)}
    return {
        "nodes": [{"id":ip_by_id[nid],"ip":ip_by_id[nid],"risk":d.get("risk_score",0),
                   "os":d.get("os_name") or d.get("vendor") or "Unknown",
                   "asset":d.get("asset_value",5),"cve_count":len(d.get("cves",[])),
                   "port_count":len(d.get("ports",[]))} for nid,d in _graph.nodes(data=True)],
    }


def get_highest_value_targets(top_n: int = 5, gateway_ip: str | None = None) -> list[dict]:
    """Return N hosts with highest asset_value — PHANTOM's crown jewels."""
    if gateway_ip is None:
        gateway_ip = os.environ.get('OBSIDIOS_GATEWAY', '192.168.1.1')
    nodes = [
        (nid, data) for nid, data in _graph.nodes(data=True)
        if data.get('ip') != gateway_ip
    ]
    nodes.sort(key=lambda x: x[1].get("asset_value", 0), reverse=True)
    return [{"id": nid, **data} for nid, data in nodes[:top_n]]


def get_most_exposed_entries(top_n: int = 10) -> list[dict]:
    """Return hosts most exposed to attack — highest risk_score."""
    nodes = list(_graph.nodes(data=True))
    nodes.sort(key=lambda x: x[1].get("risk_score", 0), reverse=True)
    return [{"id": nid, **data} for nid, data in nodes[:top_n]]


def apply_shield_block(src_id: int, dst_id: int) -> None:
    """Remove edge when SHIELD blocks a path."""
    if _graph.has_edge(src_id, dst_id):
        _graph.remove_edge(src_id, dst_id)
        logger.info(f"[IRIS/GRAPH] Edge {src_id}→{dst_id} removed by SHIELD")

