"""
oracle/tagnn.py
────────────────────────────
Topological Attack Graph Neural Network (TAGNN) - Lite Implementation

Predicts attack paths based purely on network topology and structural vulnerabilities,
identifying potential zero-day lateral movement paths even when no known CVEs exist.
"""
from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from typing import Any

import networkx as nx
from loguru import logger

from chronicle import db


async def run_tagnn_prediction() -> list[dict[str, Any]]:
    """Analyze network topology to predict zero-day attack paths."""
    logger.info("[ORACLE/TAGNN] Initializing Topological Attack Graph prediction...")
    
    hosts = await db.fetch_all('SELECT id, ip, risk_score, asset_value FROM hosts WHERE is_active=1')
    ports = await db.fetch_all('SELECT host_id, port, service FROM ports WHERE state="open"')
    
    if not hosts or len(hosts) < 2:
        logger.warning("[ORACLE/TAGNN] Not enough hosts for topological analysis.")
        return []
        
    G = nx.DiGraph()

    # 1. Build the baseline graph
    port_counts: dict[int, int] = defaultdict(int)
    for p in ports:
        port_counts[p['host_id']] += 1

    for h in hosts:
        # Calculate a structural embedding score (mock GNN feature vector)
        G.add_node(h['id'], ip=h['ip'], risk=h['risk_score'],
                   value=h['asset_value'], ports=port_counts.get(h['id'], 0))
        
    # 2. Infer connections (simulating self-attention / message passing)
    for h1 in hosts:
        for h2 in hosts:
            if h1['id'] == h2['id']: continue

            # Predict lateral movement probability based on open ports and risk
            # High-risk nodes with many open ports are more likely to be connected/exploitable
            target_port_count = port_counts.get(h2['id'], 0)
            if target_port_count:
                risk = float(h2['risk_score'] or 0)
                weight = 1.0 / (target_port_count * (risk + 1))
                G.add_edge(h1['id'], h2['id'], weight=weight)
                
    # 3. Calculate Structural Vulnerability using Centrality (GNN-lite feature)
    centrality = nx.betweenness_centrality(G, weight='weight')
    
    # 4. Predict Zero-Day Paths to high-value assets (excluding gateway)
    gateway_ip = os.environ.get('OBSIDIOS_GATEWAY', '192.168.1.1')
    targets = sorted(
        [h for h in hosts if h['ip'] != gateway_ip],
        key=lambda x: x['asset_value'] or 0, reverse=True
    )[:3]
    if not targets:
        return []

    # Entry points: the gateway (when it is an observed host) plus the most
    # structurally central hosts. The old ".1" suffix heuristic misclassified
    # ordinary addresses such as 10.20.30.41 and missed real gateways.
    entry_points = [h for h in hosts if h['ip'] == gateway_ip]
    entry_ids = {e['id'] for e in entry_points}
    ranked = sorted(hosts, key=lambda h: centrality.get(h['id'], 0), reverse=True)
    for h in ranked:
        if h['id'] not in entry_ids:
            entry_points.append(h)
            entry_ids.add(h['id'])
        if len(entry_points) >= 5:
            break

    predictions = []
    seen: set[tuple] = set()

    for entry in entry_points:
        for target in targets:
            if entry['id'] == target['id']: continue
            try:
                path = nx.shortest_path(G, source=entry['id'], target=target['id'], weight='weight')

                # Format path
                path_json = []
                for step_id in path:
                    node_data = G.nodes[step_id]
                    path_json.append({'ip': node_data['ip'], 'type': 'TOPOLOGICAL_HOPS'})

                key = (entry['ip'], target['ip'], json.dumps(path_json, sort_keys=True))
                if key in seen:
                    continue
                seen.add(key)

                predictions.append({
                    'entry': entry['ip'],
                    'target': target['ip'],
                    'path_json': json.dumps(path_json),
                    'narrative': f"TAGNN Zero-Day Prediction: Attacker exploits topological centrality of {entry['ip']} to reach high-value asset {target['ip']}.",
                    'roi': round(centrality.get(entry['id'], 0) * 100, 2),
                    'estimated_time_minutes': len(path) * 8.0,
                })

            except nx.NetworkXNoPath:
                pass

    logger.success(f"[ORACLE/TAGNN] Predicted {len(predictions)} zero-day topological paths.")

    # Persist predictions to attack_paths (refresh matching rows instead of
    # appending a duplicate copy of the same prediction on every run).
    persisted_ids: list[int] = []
    for pred in predictions:
        entry_id = next((h['id'] for h in hosts if h['ip'] == pred['entry']), None)
        target_id = next((h['id'] for h in hosts if h['ip'] == pred['target']), None)
        if entry_id is None or target_id is None:
            continue
        existing = await db.fetch_one(
            """SELECT id FROM attack_paths
               WHERE is_active=1 AND entry_host_id=? AND target_host_id=?
                 AND path_json=? LIMIT 1""",
            (entry_id, target_id, pred['path_json']),
        )
        if existing:
            await db.execute(
                """UPDATE attack_paths
                   SET narrative=?, attacker_roi=?, estimated_time_minutes=?,
                       simulated_at=?
                   WHERE id=?""",
                (pred['narrative'], pred['roi'],
                 pred['estimated_time_minutes'], time.time(), existing['id']),
            )
            persisted_ids.append(existing['id'])
        else:
            row = await db.execute_returning(
                """INSERT INTO attack_paths
                   (entry_host_id, target_host_id, path_json, narrative,
                    attacker_roi, estimated_time_minutes, is_active)
                   VALUES (?, ?, ?, ?, ?, ?, 1) RETURNING id""",
                (entry_id, target_id, pred['path_json'], pred['narrative'],
                 pred['roi'], pred['estimated_time_minutes']),
            )
            if row:
                persisted_ids.append(row['id'])

    # Retire TAGNN predictions that are no longer produced by the topology.
    if persisted_ids:
        placeholders = ",".join("?" for _ in persisted_ids)
        await db.execute(
            f"UPDATE attack_paths SET is_active=0 "  # nosec B608 - placeholders only
            f"WHERE is_active=1 AND narrative LIKE 'TAGNN%' "
            f"AND id NOT IN ({placeholders})",
            tuple(persisted_ids),
        )
    else:
        await db.execute(
            "UPDATE attack_paths SET is_active=0 "
            "WHERE is_active=1 AND narrative LIKE 'TAGNN%'"
        )

    return predictions
