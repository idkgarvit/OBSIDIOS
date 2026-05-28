"""
oracle/tagnn.py
────────────────────────────
Topological Attack Graph Neural Network (TAGNN) - Lite Implementation

Predicts attack paths based purely on network topology and structural vulnerabilities,
identifying potential zero-day lateral movement paths even when no known CVEs exist.
"""
from __future__ import annotations
import networkx as nx
import json
import os
from typing import Any, List
from loguru import logger
from chronicle import db

async def run_tagnn_prediction() -> List[dict[str, Any]]:
    """Analyze network topology to predict zero-day attack paths."""
    logger.info("[ORACLE/TAGNN] Initializing Topological Attack Graph prediction...")
    
    hosts = await db.fetch_all('SELECT id, ip, risk_score, asset_value FROM hosts WHERE is_active=1')
    ports = await db.fetch_all('SELECT host_id, port, service FROM ports WHERE state="open"')
    
    if not hosts or len(hosts) < 2:
        logger.warning("[ORACLE/TAGNN] Not enough hosts for topological analysis.")
        return []
        
    G = nx.DiGraph()
    host_map = {h['id']: dict(h) for h in hosts}
    
    # 1. Build the baseline graph
    for h in hosts:
        # Calculate a structural embedding score (mock GNN feature vector)
        host_ports = [p for p in ports if p['host_id'] == h['id']]
        G.add_node(h['id'], ip=h['ip'], risk=h['risk_score'], value=h['asset_value'], ports=len(host_ports))
        
    # 2. Infer connections (simulating self-attention / message passing)
    for h1 in hosts:
        for h2 in hosts:
            if h1['id'] == h2['id']: continue
            
            # Predict lateral movement probability based on open ports and risk
            # High-risk nodes with many open ports are more likely to be connected/exploitable
            target_ports = [p for p in ports if p['host_id'] == h2['id']]
            if target_ports:
                weight = 1.0 / (len(target_ports) * (h2['risk_score'] + 1))
                G.add_edge(h1['id'], h2['id'], weight=weight)
                
    # 3. Calculate Structural Vulnerability using Centrality (GNN-lite feature)
    centrality = nx.betweenness_centrality(G, weight='weight')
    
    # 4. Predict Zero-Day Paths to high-value assets (excluding gateway)
    gateway_ip = os.environ.get('OBSIDIOS_GATEWAY', '192.168.1.1')
    targets = sorted(
        [h for h in hosts if h['ip'] != gateway_ip],
        key=lambda x: x['asset_value'], reverse=True
    )[:3]
    entry_points = [h for h in hosts if h['ip'].endswith('.1') or centrality.get(h['id'], 0) > 0.1]
    
    if not entry_points:
        entry_points = [hosts[0]]
        
    predictions = []
    
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
                
                predictions.append({
                    'entry': entry['ip'],
                    'target': target['ip'],
                    'path_json': json.dumps(path_json),
                    'narrative': f"TAGNN Zero-Day Prediction: Attacker exploits topological centrality of {entry['ip']} to reach high-value asset {target['ip']}.",
                    'roi': round(centrality.get(entry['id'], 0) * 100, 2)
                })
                
            except nx.NetworkXNoPath:
                pass
                
    logger.success(f"[ORACLE/TAGNN] Predicted {len(predictions)} zero-day topological paths.")
    
    # Persist predictions to attack_paths
    for pred in predictions:
        entry_id = None
        target_id = None
        for h in hosts:
            if h['ip'] == pred['entry']:
                entry_id = h['id']
            if h['ip'] == pred['target']:
                target_id = h['id']
        await db.execute(
            """INSERT INTO attack_paths (entry_host_id, target_host_id, path_json, narrative, attacker_roi, estimated_time_minutes, is_active)
               VALUES (?, ?, ?, ?, ?, ?, 1)""",
            (entry_id, target_id, pred['path_json'], pred['narrative'], pred['roi'],
             pred.get('estimated_time_minutes') or pred.get('est_minutes') or 0)
        )
        
    return predictions
