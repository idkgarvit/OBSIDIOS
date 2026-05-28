"""
oracle/claude_client.py

ORACLE — The AI Brain of OBSIDIOS.

Uses Claude API to synthesize everything IRIS, PHANTOM, and FORGE
produced into three outputs:

  1. Attack Narrative  — "Here is exactly how your network gets owned,
                          written from an attacker's perspective"
  2. Remediation Brief — Specific fix commands per vulnerability
  3. Pentest Report    — Full professional PDF/HTML report
"""
from __future__ import annotations

import json
import os
import time
from typing import Any


from loguru import logger

from chronicle import db
from config.settings import ai as ai_cfg


# ── Result cache (avoid redundant AI calls on every page load) ──────────────
_CACHE_TTL = 300  # 5 minutes

_cache: dict[str, dict] = {
    "narrative":  {"result": None, "ts": 0, "hash": ""},
    "remediation": {"result": None, "ts": 0, "hash": ""},
}

def _cache_get(key: str, data_hash: str) -> str | None:
    entry = _cache.get(key)
    if entry and entry["result"] and time.time() - entry["ts"] < _CACHE_TTL and entry["hash"] == data_hash:
        return entry["result"]
    return None

def _cache_set(key: str, result: str, data_hash: str):
    _cache[key] = {"result": result, "ts": time.time(), "hash": data_hash}

def _data_hash(context: dict) -> str:
    """Quick hash of network context to detect meaningful changes."""
    host_count = len(context.get("hosts", []))
    cve_count = sum(len(h.get("cves", [])) for h in context.get("hosts", []))
    return f"{host_count}:{cve_count}"

async def _has_recent_scan() -> bool:
    """Check if a scan completed within the last hour."""
    row = await db.fetch_one("SELECT finished_at FROM scans WHERE status='DONE' ORDER BY finished_at DESC LIMIT 1")
    if not row or not row["finished_at"]:
        return False
    return time.time() - row["finished_at"] < 3600

# ── Claude client (lazy init) ──────────────────────────────────────────────
_client = None

def _get_client(use_fallback=False):
    global _client
    if use_fallback:
        if ai_cfg.openai_api_key:
            import openai
            return openai.OpenAI(api_key=ai_cfg.openai_api_key, base_url=ai_cfg.openai_base_url)
        if ai_cfg.anthropic_api_key:
            import anthropic
            return anthropic.Anthropic(api_key=ai_cfg.anthropic_api_key)
        return None
    if _client is not None:
        return _client
    import openai

    if ai_cfg.nvidia_api_key:
        _client = openai.OpenAI(api_key=ai_cfg.nvidia_api_key, base_url=ai_cfg.nvidia_base_url)
    elif ai_cfg.openai_api_key:
        _client = openai.OpenAI(api_key=ai_cfg.openai_api_key, base_url=ai_cfg.openai_base_url)
    elif ai_cfg.anthropic_api_key:
        import anthropic
        _client = anthropic.Anthropic(api_key=ai_cfg.anthropic_api_key)

    return _client

# ─────────────────────────────────────────────────────────────────────────────
# Data loader — pulls everything from CHRONICLE
# ─────────────────────────────────────────────────────────────────────────────

async def _load_network_context() -> dict[str, Any]:
    """Load full network state from DB for Oracle context."""

    hosts = await db.fetch_all(
        "SELECT ip, mac, os_name, risk_score, asset_value, vendor FROM hosts WHERE is_active=1"
    )
    ports = await db.fetch_all(
        """SELECT h.ip, p.port, p.service, p.version, p.protocol
           FROM ports p JOIN hosts h ON h.id = p.host_id
           WHERE p.state='open' ORDER BY h.ip, p.port"""
    )
    cves = await db.fetch_all(
        """SELECT h.ip, c.cve_id, c.cvss_v3, c.severity, c.description
           FROM cves c
           JOIN port_cves pc ON pc.cve_id = c.id
           JOIN ports p      ON p.id = pc.port_id
           JOIN hosts h      ON h.id = p.host_id
           ORDER BY c.cvss_v3 DESC NULLS LAST"""
    )
    # Only show paths from the most recent simulation (avoid accumulation)
    latest_sim_time = await db.fetch_val(
        "SELECT MAX(simulated_at) FROM attack_paths WHERE is_active=1"
    )
    paths = await db.fetch_all(
        """SELECT id, entry_host_id, target_host_id, path_json,
                  total_steps, attacker_roi, estimated_time_minutes
           FROM attack_paths WHERE is_active=1
           AND simulated_at >= ?
           ORDER BY attacker_roi DESC""",
        (latest_sim_time - 60,) if latest_sim_time else (0,)
    )
    rules = await db.fetch_all(
        """SELECT DISTINCT rule_sid, rule_category, mitre_technique, rule_text
           FROM forge_rules WHERE is_active=1
           ORDER BY rule_category, rule_sid"""
    )

    # Build structured context
    host_map: dict[str, dict] = {}
    for h in hosts:
        host_map[h["ip"]] = {
            "ip":          h["ip"],
            "os":          h["os_name"] or h["vendor"] or "Linux/Unknown",
            "risk_score":  h["risk_score"],
            "asset_value": h["asset_value"],
            "vendor":      h["vendor"],
            "ports":       [],
            "cves":        [],
        }

    for p in ports:
        if p["ip"] in host_map:
            host_map[p["ip"]]["ports"].append(
                f"{p['port']}/{p['protocol']} ({p['service']} {p['version'] or ''})"
            )

    for c in cves:
        if c["ip"] in host_map:
            host_map[c["ip"]]["cves"].append({
                "id":       c["cve_id"],
                "cvss":     c["cvss_v3"],
                "severity": c["severity"],
                "desc":     (c["description"] or "")[:200],
            })

    # Parse attack paths
    parsed_paths = []
    for p in paths:
        try:
            steps = json.loads(p["path_json"])
        except Exception:
            steps = []
        parsed_paths.append({
            "id":         p["id"],
            "steps":      steps,
            "total_steps": p["total_steps"],
            "roi":         p["attacker_roi"],
            "est_minutes": p["estimated_time_minutes"],
        })

    return {
        "hosts":        list(host_map.values()),
        "attack_paths": parsed_paths,
        "total_cves":   len(cves),
        "total_rules":  len(rules),
        "rules_by_cat": _count_by_key([dict(r) for r in rules], "rule_category"),
    }


def _count_by_key(items: list[dict], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        k = item.get(key, "UNKNOWN")
        counts[k] = counts.get(k, 0) + 1
    return counts


# ─────────────────────────────────────────────────────────────────────────────
# ORACLE Output 1 — Attack Narrative
# ─────────────────────────────────────────────────────────────────────────────

async def generate_attack_narrative(context: dict | None = None) -> str:
    """
    Generate a plain-English attack narrative — the story of how
    your network gets breached, written from an attacker's perspective.
    """
    if context is None:
        context = await _load_network_context()

    # Cache check: skip AI call if data hasn't changed and cache is fresh
    dh = _data_hash(context)
    cached = _cache_get("narrative", dh)
    if cached is not None:
        return cached

    # Data guard: no hosts or no recent scan = nothing to analyze
    if not context.get("hosts") or not await _has_recent_scan():
        if not context.get("hosts"):
            result = "No scan data available yet. Run a scan first."
        else:
            result = "AI analysis requires a recent scan. Run a scan to generate."
        _cache_set("narrative", result, dh)
        return result

    if not ai_cfg.anthropic_api_key and not os.getenv("GROQ_API_KEY"):
        result = _fallback_narrative(context)
        _cache_set("narrative", result, dh)
        return result

    hosts_summary = "\n".join([
        f"  - {h['ip']} | OS: {h['os']} | Risk: {h['risk_score']}/100 | "
        f"Open ports: {len(h['ports'])} | CVEs: {len(h['cves'])}"
        for h in context["hosts"]
    ])

    cves_detail = ""
    for h in context["hosts"]:
        if h["cves"]:
            cves_detail += f"\n  {h['ip']} CVEs:\n"
            for c in h["cves"]:
                cves_detail += f"    - {c['id']} (CVSS: {c['cvss']}, {c['severity']}) — {c['desc'][:120]}\n"

    paths_summary = ""
    for p in context["attack_paths"][:3]:
        steps = " → ".join(
            f"{s.get('ip','?')} ({s.get('technique','?')})"
            for s in p["steps"]
        )
        paths_summary += (
            f"\n  Path #{p['id']}: {steps}\n"
            f"  ROI: {p['roi']:.1f} | Est. time: {p['est_minutes']:.0f} min\n"
        )

    prompt = f"""You are an expert penetration tester writing an attack narrative for a security assessment report.

Based on the following network scan data, write a compelling, technical attack narrative from an attacker's perspective. 
This should read like a real pentest report's "Attack Scenario" section.

NETWORK DATA:
Hosts discovered:
{hosts_summary}

Detected CVEs (use ONLY these — do NOT invent any CVE IDs):{cves_detail}

Top attack paths simulated by PHANTOM:
{paths_summary}

Total CVEs mapped: {context['total_cves']}

Write a 3-4 paragraph attack narrative that:
1. Describes the initial foothold an attacker would gain
2. Explains the lateral movement path through the network  
3. Describes what the attacker achieves at the end
4. Uses specific IPs, CVEs, and techniques from the data above
5. Reads like a professional pentest report

CRITICAL RULES:
- You MUST ONLY reference CVE IDs listed in "Detected CVEs" above
- Do NOT invent or fabricate any CVE IDs, IP addresses, or vulnerabilities
- If no CVEs are listed, describe the attack based on open ports and services only
- Be specific, technical, and direct"""

    try:
        client = _get_client()
        if client is None:
            result = _fallback_narrative(context)
            _cache_set("narrative", result, dh)
            return result

        # Detect client type and call accordingly
        if hasattr(client, 'messages'):
            # Claude API
            message = client.messages.create(
                model    = ai_cfg.model,
                max_tokens = 1024,
                messages = [{"role": "user", "content": prompt}]
            )
            narrative = message.content[0].text
        else:
            # NVIDIA / OpenAI-compatible API
            message = client.chat.completions.create(
                model    = ai_cfg.nvidia_model or "meta/llama-3.1-8b-instruct",
                max_tokens = 1024,
                messages = [{"role": "user", "content": prompt}]
            )
            narrative = message.choices[0].message.content

        logger.success("[ORACLE] Attack narrative generated")
        _cache_set("narrative", narrative, dh)
        return narrative
    except Exception as exc:
        exc_str = str(exc)
        is_rate_limit = '429' in exc_str or 'rate_limit' in exc_str.lower()
        if is_rate_limit:
            if ai_cfg.openai_api_key:
                try:
                    import openai
                    fb = openai.OpenAI(api_key=ai_cfg.openai_api_key, base_url=ai_cfg.openai_base_url)
                    msg = fb.chat.completions.create(
                        model=ai_cfg.openai_model, max_tokens=1024,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    logger.success("[ORACLE] Attack narrative generated (OpenAI)")
                    result = msg.choices[0].message.content
                    _cache_set("narrative", result, dh)
                    return result
                except Exception as exc2:
                    logger.warning(f"[ORACLE] OpenAI fallback failed: {exc2}")
            if ai_cfg.anthropic_api_key:
                try:
                    import anthropic
                    fb = anthropic.Anthropic(api_key=ai_cfg.anthropic_api_key)
                    msg = fb.messages.create(
                        model=ai_cfg.model, max_tokens=1024,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    logger.success("[ORACLE] Attack narrative generated (Anthropic)")
                    result = msg.content[0].text
                    _cache_set("narrative", result, dh)
                    return result
                except Exception as exc3:
                    logger.warning(f"[ORACLE] Anthropic fallback failed: {exc3}")
        logger.warning(f"[ORACLE] API error: {exc} — using fallback")
        result = _fallback_narrative(context)
        _cache_set("narrative", result, dh)
        return result

def _fallback_narrative(context: dict) -> str:
    """Fallback narrative when no API key is set."""
    hosts = context["hosts"]
    paths = context["attack_paths"]

    # Sort by CVE count then port count — risk_score may be 0 if not calculated
    most_vulnerable = max(hosts, key=lambda h: (len(h["cves"]), len(h["ports"]))) if hosts else None
    top_path        = paths[0] if paths else None

    narrative = "ATTACK NARRATIVE (Generated without AI — add ANTHROPIC_API_KEY for full narrative)\n\n"

    if most_vulnerable:
        narrative += (
            f"The most vulnerable host is {most_vulnerable['ip']} "
            f"(Risk Score: {most_vulnerable['risk_score']}/100) running "
            f"{most_vulnerable['os']} with {len(most_vulnerable['cves'])} known CVEs "
            f"across {len(most_vulnerable['ports'])} open ports.\n\n"
        )

    if top_path and top_path["steps"]:
        entry = top_path["steps"][0].get("ip", "?")
        target = top_path["steps"][-1].get("ip", "?")
        narrative += (
            f"PHANTOM's highest-ROI attack path begins at {entry} and "
            f"reaches {target} in {top_path['total_steps']} steps, "
            f"estimated completion time: {(top_path.get('est_minutes') or 0):.0f} minutes.\n\n"
        )

    narrative += (
        f"FORGE has generated {context['total_rules']} custom Suricata detection rules "
        f"to monitor for these specific attack patterns on this network."
    )

    return narrative


# ─────────────────────────────────────────────────────────────────────────────
# ORACLE Output 2 — Remediation Brief
# ─────────────────────────────────────────────────────────────────────────────

async def generate_remediation(context: dict | None = None) -> str:
    """Generate specific remediation commands for discovered vulnerabilities."""
    if context is None:
        context = await _load_network_context()

    # Cache check: skip AI call if data hasn't changed and cache is fresh
    dh = _data_hash(context)
    cached = _cache_get("remediation", dh)
    if cached is not None:
        return cached

    # Data guard: no hosts or no recent scan = nothing to remediate
    if not context.get("hosts") or not await _has_recent_scan():
        if not context.get("hosts"):
            result = "No scan data available yet. Run a scan first."
        else:
            result = "AI analysis requires a recent scan. Run a scan to generate."
        _cache_set("remediation", result, dh)
        return result

    # Build CVE list
    all_cves = []
    for h in context["hosts"]:
        for cve in h.get("cves", [])[:5]:  # Top 5 per host
            all_cves.append(f"{h['ip']} | {cve['id']} | CVSS:{cve['cvss']} | {cve['desc'][:100]}")

    if not all_cves:
        result = "No known or critical CVEs found. Keep network monitored."
        _cache_set("remediation", result, dh)
        return result

    if not ai_cfg.anthropic_api_key and not os.getenv("GROQ_API_KEY"):
        result = _fallback_remediation(context)
        _cache_set("remediation", result, dh)
        return result

    prompt = f"""You are a security engineer writing remediation guidance for a pentest report.

For each vulnerability below, provide ONE specific, actionable fix command or step.
Be concise — one line per CVE maximum. Use actual Linux/Windows commands where applicable.

VULNERABILITIES (only respond to these — do NOT add any others):
{chr(10).join(all_cves[:15])}

Format each line as:
[IP] [CVE-ID]: <specific fix command or action>

CRITICAL RULES:
- Respond ONLY for the CVE IDs listed above — do NOT add any others
- Focus on the highest CVSS scores first
- Be specific and technical"""

    try:
        client = _get_client()
        if client is None:
            result = _fallback_remediation(context)
            _cache_set("remediation", result, dh)
            return result
        if hasattr(client, 'messages'):
            message = client.messages.create(
                model=ai_cfg.model, max_tokens=1024,
                messages=[{"role": "user", "content": prompt}]
            )
            result_text = message.content[0].text
        else:
            message = client.chat.completions.create(
                model=ai_cfg.nvidia_model or "meta/llama-3.1-8b-instruct", max_tokens=1024,
                messages=[{"role": "user", "content": prompt}]
            )
            result_text = message.choices[0].message.content
        logger.success("[ORACLE] Remediation brief generated")
        _cache_set("remediation", result_text, dh)
        return result_text
    except Exception as exc:
        exc_str = str(exc)
        is_rate_limit = '429' in exc_str or 'rate_limit' in exc_str.lower()
        if is_rate_limit:
            if ai_cfg.openai_api_key:
                try:
                    import openai
                    fb = openai.OpenAI(api_key=ai_cfg.openai_api_key, base_url=ai_cfg.openai_base_url)
                    msg = fb.chat.completions.create(
                        model=ai_cfg.openai_model, max_tokens=1024,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    logger.success("[ORACLE] Remediation brief generated (OpenAI)")
                    result = msg.choices[0].message.content
                    _cache_set("remediation", result, dh)
                    return result
                except Exception as exc2:
                    logger.warning(f"[ORACLE] OpenAI fallback failed: {exc2}")
            if ai_cfg.anthropic_api_key:
                try:
                    import anthropic
                    fb = anthropic.Anthropic(api_key=ai_cfg.anthropic_api_key)
                    msg = fb.messages.create(
                        model=ai_cfg.model, max_tokens=1024,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    logger.success("[ORACLE] Remediation brief generated (Anthropic)")
                    result = msg.content[0].text
                    _cache_set("remediation", result, dh)
                    return result
                except Exception as exc3:
                    logger.warning(f"[ORACLE] Anthropic fallback failed: {exc3}")
        logger.warning(f"[ORACLE] Claude API error: {exc} — using fallback")
        result = _fallback_remediation(context)
        _cache_set("remediation", result, dh)
        return result


def _fallback_remediation(context: dict) -> str:
    lines = ["REMEDIATION BRIEF\n"]
    for h in context["hosts"]:
        for cve in h.get("cves", [])[:3]:
            lines.append(f"  {h['ip']} | {cve['id']} (CVSS:{cve['cvss']}): Patch immediately")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# ORACLE Output 3 — Full HTML Pentest Report
# ─────────────────────────────────────────────────────────────────────────────

async def generate_report(output_path: str = "reports/output/pentest_report.html") -> str:
    """
    Generate a full professional HTML pentest report.
    Combines all OBSIDIOS data into a single deliverable.
    """
    import os
    from datetime import datetime

    context     = await _load_network_context()
    narrative   = await generate_attack_narrative(context)
    remediation = await generate_remediation(context)
    timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build host rows
    host_rows = ""
    for h in context["hosts"]:
        risk    = h["risk_score"]
        color   = "#ff4444" if risk > 70 else "#ffaa00" if risk > 40 else "#44ff88"
        host_rows += f"""
        <tr>
            <td><code>{h['ip']}</code></td>
            <td>{h['os']}</td>
            <td>{len(h['ports'])}</td>
            <td>{len(h['cves'])}</td>
            <td><span style="color:{color};font-weight:bold">{risk:.1f}/100</span></td>
        </tr>"""

    # Build CVE rows
    cve_rows = ""
    for h in context["hosts"]:
        for cve in h.get("cves", []):
            sev   = cve.get("severity", "UNKNOWN")
            color = {"CRITICAL":"#ff0000","HIGH":"#ff6600",
                     "MEDIUM":"#ffaa00","LOW":"#88cc00"}.get(sev, "#888888")
            cve_rows += f"""
        <tr>
            <td><code>{h['ip']}</code></td>
            <td><a href="https://nvd.nist.gov/vuln/detail/{cve['id']}"
                   target="_blank">{cve['id']}</a></td>
            <td>{cve.get('cvss') or 'N/A'}</td>
            <td style="color:{color};font-weight:bold">{sev}</td>
            <td>{cve.get('desc','')[:100]}</td>
        </tr>"""

    # Build attack path rows
    path_rows = ""
    for p in context["attack_paths"]:
        steps_html = " → ".join(
            f"<code>{s.get('ip','?')}</code>"
            for s in p["steps"]
        )
        techniques = ", ".join(set(
            s.get("technique", "") for s in p["steps"] if s.get("technique")
        ))
        path_rows += f"""
        <tr>
            <td>#{p['id']}</td>
            <td>{steps_html}</td>
            <td>{p['total_steps']}</td>
            <td>{(p.get('roi') or 0):.2f}</td>
            <td>{(p.get('est_minutes') or 0):.0f} min</td>
            <td><small>{techniques}</small></td>
        </tr>"""

    # Remediation as HTML
    remediation_html = remediation.replace("\n", "<br>")
    narrative_html   = narrative.replace("\n", "<br>")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OBSIDIOS Pentest Report — {timestamp}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #0a0a0f;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .header {{
            background: linear-gradient(135deg, #1a0000, #2d0000);
            border-bottom: 2px solid #ff4444;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            color: #ff4444;
            letter-spacing: 4px;
            text-transform: uppercase;
        }}
        .header p {{ color: #888; margin-top: 8px; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 30px; }}
        .section {{
            background: #111118;
            border: 1px solid #222233;
            border-radius: 8px;
            margin: 24px 0;
            overflow: hidden;
        }}
        .section-header {{
            background: #1a1a2e;
            padding: 16px 24px;
            border-bottom: 1px solid #222233;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .section-header h2 {{
            font-size: 1.1em;
            color: #ff4444;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        .section-body {{ padding: 24px; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9em;
        }}
        th {{
            background: #1a1a2e;
            color: #888;
            padding: 10px 14px;
            text-align: left;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75em;
            letter-spacing: 1px;
        }}
        td {{
            padding: 10px 14px;
            border-bottom: 1px solid #1a1a2e;
            vertical-align: top;
        }}
        tr:hover td {{ background: #15151f; }}
        code {{
            background: #1a1a2e;
            color: #00ffcc;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
        }}
        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            padding: 24px;
        }}
        .stat {{
            background: #1a1a2e;
            border-radius: 6px;
            padding: 20px;
            text-align: center;
        }}
        .stat .value {{
            font-size: 2em;
            font-weight: bold;
            color: #ff4444;
        }}
        .stat .label {{
            color: #666;
            font-size: 0.8em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 4px;
        }}
        .narrative {{
            background: #0d0d1a;
            border-left: 3px solid #ff4444;
            padding: 20px;
            border-radius: 0 6px 6px 0;
            line-height: 1.8;
            color: #ccc;
        }}
        .remediation {{
            background: #0d1a0d;
            border-left: 3px solid #44ff88;
            padding: 20px;
            border-radius: 0 6px 6px 0;
            font-family: monospace;
            font-size: 0.85em;
            color: #88ff88;
            white-space: pre-wrap;
        }}
        .footer {{
            text-align: center;
            padding: 30px;
            color: #333;
            font-size: 0.8em;
            border-top: 1px solid #1a1a2e;
            margin-top: 40px;
        }}
        a {{ color: #4488ff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>

<div class="header">
    <h1>⚡ OBSIDIOS</h1>
    <p>Autonomous Network Security Assessment Report</p>
    <p style="color:#555;font-size:0.85em;margin-top:8px">Generated: {timestamp}</p>
</div>

<div class="container">

    <!-- Executive Summary -->
    <div class="section">
        <div class="section-header">
            <h2>📊 Executive Summary</h2>
        </div>
        <div class="stat-grid">
            <div class="stat">
                <div class="value">{len(context['hosts'])}</div>
                <div class="label">Hosts Discovered</div>
            </div>
            <div class="stat">
                <div class="value">{sum(len(h['ports']) for h in context['hosts'])}</div>
                <div class="label">Open Ports</div>
            </div>
            <div class="stat">
                <div class="value">{context['total_cves']}</div>
                <div class="label">CVEs Mapped</div>
            </div>
            <div class="stat">
                <div class="value">{len(context['attack_paths'])}</div>
                <div class="label">Kill Chains</div>
            </div>
            <div class="stat">
                <div class="value">{context['total_rules']}</div>
                <div class="label">IDS Rules Forged</div>
            </div>
        </div>
    </div>

    <!-- Attack Narrative -->
    <div class="section">
        <div class="section-header">
            <h2>👻 Attack Narrative (PHANTOM)</h2>
        </div>
        <div class="section-body">
            <div class="narrative">{narrative_html}</div>
        </div>
    </div>

    <!-- Host Inventory -->
    <div class="section">
        <div class="section-header">
            <h2>🔭 Host Inventory (IRIS)</h2>
        </div>
        <div class="section-body">
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>OS</th>
                        <th>Open Ports</th>
                        <th>CVEs</th>
                        <th>Risk Score</th>
                    </tr>
                </thead>
                <tbody>{host_rows}</tbody>
            </table>
        </div>
    </div>

    <!-- CVE Table -->
    <div class="section">
        <div class="section-header">
            <h2>🔴 Vulnerabilities (CVE Mapper)</h2>
        </div>
        <div class="section-body">
            <table>
                <thead>
                    <tr>
                        <th>Host</th>
                        <th>CVE ID</th>
                        <th>CVSS</th>
                        <th>Severity</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>{cve_rows if cve_rows else '<tr><td colspan="5" style="text-align:center;color:#444">No CVEs linked yet</td></tr>'}</tbody>
            </table>
        </div>
    </div>

    <!-- Attack Paths -->
    <div class="section">
        <div class="section-header">
            <h2>⚡ Attack Paths (PHANTOM)</h2>
        </div>
        <div class="section-body">
            <table>
                <thead>
                    <tr>
                        <th>Path</th>
                        <th>Kill Chain</th>
                        <th>Steps</th>
                        <th>Attacker ROI</th>
                        <th>Est. Time</th>
                        <th>Techniques</th>
                    </tr>
                </thead>
                <tbody>{path_rows if path_rows else '<tr><td colspan="6" style="text-align:center;color:#444">No paths — run phantom command first</td></tr>'}</tbody>
            </table>
        </div>
    </div>

    <!-- Remediation -->
    <div class="section">
        <div class="section-header">
            <h2>🛡️ Remediation (ORACLE)</h2>
        </div>
        <div class="section-body">
            <div class="remediation">{remediation_html}</div>
        </div>
    </div>

</div>

<div class="footer">
    Generated by OBSIDIOS — Autonomous Network Security Platform<br>
    PHANTOM Kill Chain Simulator | FORGE Rule Generator | ORACLE AI Brain
</div>

</body>
</html>"""

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        f.write(html)

    logger.success(f"[ORACLE] Pentest report saved → {output_path}")
    return output_path