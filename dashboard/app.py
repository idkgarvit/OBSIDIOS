import asyncio
import csv
import io
import json
import socket
import time
import os
import threading
import concurrent.futures
import jwt
import datetime
from functools import wraps

from flask import Flask, render_template, jsonify, request, Response
from flask_socketio import SocketIO
from dashboard import db_sync as db
from loguru import logger

# Background event loop daemon — one loop reused across all requests
_bg_loop: asyncio.AbstractEventLoop | None = None
_bg_loop_lock = threading.Lock()
_bg_loop_ready = threading.Event()

def _run_bg_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    global _bg_loop
    _bg_loop = loop
    _bg_loop_ready.set()
    loop.run_forever()

def _ensure_bg_loop():
    global _bg_loop
    if _bg_loop is not None:
        return
    with _bg_loop_lock:
        if _bg_loop is not None:
            return
        t = threading.Thread(target=_run_bg_loop, daemon=True)
        t.start()
    # Wait for bg loop to be ready before scheduling anything on it
    _bg_loop_ready.wait(timeout=5)

def _pre_init_db():
    """Pre-initialise chronicle.db on the bg loop so first request
    doesn't trigger init() while daemon may hold a lock."""
    from chronicle import db as chronicle_db
    fut = asyncio.run_coroutine_threadsafe(chronicle_db.init(), _bg_loop)
    try:
        fut.result(timeout=30.0)
        logger.success("[DASHBOARD] Pre-initialised chronicle.db on bg loop")
    except Exception as e:
        logger.warning(f"[DASHBOARD] Pre-init chronicle.db failed: {e}")

def run_async(coro, timeout=120.0):
    _ensure_bg_loop()
    fut = asyncio.run_coroutine_threadsafe(coro, _bg_loop)
    try:
        return fut.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        fut.cancel()
        raise TimeoutError(f"Operation timed out after {timeout}s")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'obsidios-secret-fallback-for-dev')
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True

# Pre-init the async DB connection pool at import time so
# oracle endpoints don't compete with the daemon for write locks
_ensure_bg_loop()
t = threading.Thread(target=_pre_init_db, daemon=True)
t.start()

def socketio_log_sink(message):
    try:
        # Avoid recursion and only send relevant logs
        msg = message.strip()
        # Extract level from loguru format if possible or just send as INFO
        # Loguru message is already formatted. We might want to parse it or send raw.
        level = 'INFO'
        if '[SUCCESS]' in msg or '✓' in msg: level = 'OK'
        elif '[WARNING]' in msg or '!' in msg: level = 'WARN'
        elif '[ERROR]' in msg or 'FAIL' in msg: level = 'CRIT'
        
        socketio.emit('log_event', {'level': level, 'message': msg}, namespace='/')
    except:
        pass

logger.add(socketio_log_sink, level='INFO', format='{message}', backtrace=False, diagnose=False)

socketio = SocketIO(app, async_mode='threading', cors_allowed_origins=os.environ.get('CORS_ORIGINS', '*'))

_rate_limit_store = {}
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 50

def check_auth(username, password):
    expected_user = os.environ.get('DASHBOARD_USER', 'admin')
    expected_pass = os.environ.get('DASHBOARD_PASS', 'obsidios123')
    return username == expected_user and password == expected_pass


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Token is missing'}), 401
        try:
            jwt.decode(token.split(' ')[1], app.config['SECRET_KEY'], algorithms=['HS256'])
        except Exception:
            return jsonify({'error': 'Token is invalid'}), 401
        return f(*args, **kwargs)
    return decorated

def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = request.remote_addr
        now = time.time()
        if client_ip not in _rate_limit_store:
            _rate_limit_store[client_ip] = []
        _rate_limit_store[client_ip] = [t for t in _rate_limit_store[client_ip] if now - t < RATE_LIMIT_WINDOW]
        if len(_rate_limit_store[client_ip]) >= RATE_LIMIT_MAX:
            return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429
        _rate_limit_store[client_ip].append(now)
        return f(*args, **kwargs)
    return decorated

@app.route('/api/login', methods=['POST'])
@rate_limit
def login():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing credentials'}), 400
    if check_auth(data['username'], data['password']):
        token = jwt.encode({'user': data['username'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401


def sync_calculate_global_posture():
    try:
        hosts = db.fetch_all("SELECT risk_score FROM hosts WHERE is_active=1 AND ip IS NOT NULL AND ip != ''")
        if not hosts: return 100.0
        avg_risk = sum(h['risk_score'] for h in hosts) / len(hosts)
        path_count = db.fetch_val('SELECT COUNT(*) FROM attack_paths WHERE is_active=1', default=0)
        anom_count = db.fetch_val('SELECT COUNT(*) FROM anomalies WHERE acknowledged=0', default=0)
        sev_counts = db.fetch_all(
            "SELECT c.severity, COUNT(*) as cnt FROM port_cves pc "
            "JOIN cves c ON c.id=pc.cve_id GROUP BY c.severity"
        )
        sev_weights = {'CRITICAL': 4, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0.5}
        cve_weight = sum(sev_weights.get(r['severity'], 0) * r['cnt'] for r in sev_counts)

        score = 100.0
        score -= avg_risk * 0.3
        score -= min(path_count, 10) * 1.5
        score -= min(cve_weight, 30) * 1.0
        score -= min(anom_count, 5) * 2.0

        return round(max(0.0, min(100.0, score)), 1)
    except Exception as e:
        logger.error(f'Posture calc failed: {e}')
        return 0.0

@app.after_request
def add_no_cache(response):
    response.headers['Cache-Control'] = 'no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/v2/stats')
@requires_auth
def api_stats_v2():
    try:
        hosts = db.fetch_val("SELECT COUNT(*) FROM hosts WHERE is_active=1 AND ip IS NOT NULL AND ip != ''")
        ports = db.fetch_val('SELECT COUNT(*) FROM ports WHERE state="open"')
        cves = db.fetch_val('SELECT COUNT(*) FROM cves')
        paths = db.fetch_val('SELECT COUNT(*) FROM attack_paths WHERE is_active=1')
        diffs = db.fetch_all('SELECT diff_type, detail, severity FROM scan_diffs ORDER BY created_at DESC LIMIT 15')
        total_scans = db.fetch_val("SELECT COUNT(*) FROM scans WHERE status='DONE'", default=0)
        is_scanning = db.fetch_val("SELECT COUNT(*) FROM scans WHERE status='RUNNING'", default=0) > 0
        scanner_enabled = db.fetch_val("SELECT value FROM system_settings WHERE key='scanner_enabled'", default='0') == '1'
        scan_phase = db.fetch_val("SELECT value FROM system_settings WHERE key='scan_phase'", default='')
        posture = sync_calculate_global_posture()
        
        total_hosts = db.fetch_val('SELECT COUNT(*) FROM hosts')
        offline = db.fetch_val('SELECT COUNT(*) FROM hosts WHERE is_active=0', default=0)
        critical_cves = db.fetch_val("SELECT COUNT(*) FROM cves WHERE severity='CRITICAL'")
        active_anomalies = db.fetch_val("SELECT COUNT(*) FROM anomalies WHERE acknowledged=0")
        shield_blocks = db.fetch_val("SELECT COUNT(*) FROM shield_actions WHERE is_active=1")

        return jsonify({
            'posture': posture, 'hosts': hosts or 0, 'online': hosts or 0, 'offline': offline or 0,
            'ports': ports or 0, 'cves': cves or 0, 'paths': paths or 0,
            'total_scans': total_scans, 'is_scanning': is_scanning, 'scanner_enabled': scanner_enabled,
            'recent_diffs': diffs, 'total_hosts': total_hosts or 0, 'critical_cves': critical_cves or 0,
            'active_anomalies': active_anomalies or 0, 'shield_blocks': shield_blocks or 0,
            'scan_phase': scan_phase or '',
            'alerts': critical_cves or 0, 'api_version': 'v2', 'timestamp': time.time()
        })
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
@requires_auth
def api_stats(): return api_stats_v2()



@app.route('/api/v2/graph')
@requires_auth
def api_graph_v2():
    try:
        # Prefer daemon's rich NetworkX node data from cache
        cached = db.fetch_val("SELECT value FROM system_settings WHERE key='graph_cache'")
        if cached:
            graph = json.loads(cached)
            nodes = graph.get('nodes', [])
        else:
            hosts = db.fetch_all('SELECT id, ip, risk_score, os_name, vendor FROM hosts WHERE is_active=1')
            nodes = [{'id': h['ip'], 'risk': h['risk_score'] or 0, 'os': h['os_name'] or h['vendor'] or 'Unknown'} for h in hosts]
        
        # Build simplified links: gateway-star + attack-path edges
        active_ips = [n['id'] for n in nodes]
        links = []
        if not active_ips:
            return jsonify({'nodes': [], 'links': [], 'blast_radius': []})
        gw = next((ip for ip in active_ips if ip.endswith('.1')), active_ips[0])

        # Every non-gateway node gets a PHYSICAL link to gateway
        links = [{'source': gw, 'target': ip, 'type': 'PHYSICAL'} for ip in active_ips if ip != gw]

        # Overlay KILL_CHAIN links from attack paths (additional edges)
        latest = db.fetch_val('SELECT MAX(simulated_at) FROM attack_paths')
        if latest:
            paths = db.fetch_all('SELECT path_json FROM attack_paths WHERE simulated_at >= ?', (latest-604800,))
            seen = set()
            for p in paths:
                steps = json.loads(p['path_json'])
                for i in range(len(steps)-1):
                    s, d = steps[i]['ip'], steps[i+1]['ip']
                    if s in active_ips and d in active_ips and d != gw:
                        key = f'{s}->{d}'
                        if key not in seen:
                            seen.add(key)
                            links.append({'source': s, 'target': d, 'type': 'KILL_CHAIN'})
        
        active_ips = {n['id'] for n in nodes}
        # Blast Radius: hosts with critical CVEs and their neighbors
        blast_radius = []
        critical = db.fetch_all(
            "SELECT DISTINCT h.ip, h.risk_score, c.cve_id, c.severity "
            "FROM hosts h JOIN ports p ON p.host_id = h.id "
            "JOIN port_cves pc ON pc.port_id = p.id "
            "JOIN cves c ON c.id = pc.cve_id "
            "WHERE h.is_active=1 AND pc.dismissed=0 AND (h.risk_score > 70 OR c.severity='CRITICAL' OR (c.cvss_v3 IS NOT NULL AND c.cvss_v3 >= 9.0))"
        )
        critical_ips = set()
        for row in critical:
            critical_ips.add(row['ip'])
            blast_radius.append({'ip': row['ip'], 'risk': row['risk_score'], 'cve_id': row['cve_id'], 'severity': row['severity'], 'is_source': True})
        
        risk_map = {n['id']: n.get('risk', 0) for n in nodes}
        for link in links:
            s, d = link.get('source', ''), link.get('target', '')
            if s in critical_ips and d not in critical_ips:
                blast_radius.append({'ip': d, 'risk': risk_map.get(d, 0), 'cve_id': None, 'severity': 'EXPOSED', 'is_source': False})
            elif d in critical_ips and s not in critical_ips:
                blast_radius.append({'ip': s, 'risk': risk_map.get(s, 0), 'cve_id': None, 'severity': 'EXPOSED', 'is_source': False})
        
        return jsonify({'nodes': nodes, 'links': links, 'blast_radius': blast_radius})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v2/details/anomalous_ports')
@requires_auth
def api_anomalous_ports():
    try:
        from oracle.attacker_view import get_anomalous_ports
        result = run_async(get_anomalous_ports(), timeout=60)
        return jsonify({'data': result, 'count': len(result)})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/v2/details/hosts')
@requires_auth
def api_details_hosts():
    try:
        hosts = db.fetch_all('SELECT ip, mac, hostname, os_name, vendor, risk_score, asset_value, last_seen FROM hosts WHERE is_active=1 ORDER BY risk_score DESC')
        return jsonify({'data': hosts})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/v2/details/ports')
@requires_auth
def api_details_ports():
    try:
        ports = db.fetch_all('SELECT h.ip, p.port, p.protocol, p.service, p.version, p.state FROM ports p JOIN hosts h ON h.id = p.host_id WHERE p.state="open"')
        return jsonify({'data': ports})
    except Exception as e: return jsonify({'error': str(e)}), 500


@app.route('/api/v2/details/paths')
@requires_auth
def api_details_paths():
    try:
        res = db.fetch_all('SELECT attacker_roi, path_json, narrative FROM attack_paths WHERE is_active=1 ORDER BY attacker_roi DESC LIMIT 10')
        return jsonify({'data': res})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/v2/config/target', methods=['GET', 'POST'])
@requires_auth
def api_target():
    if request.method == 'GET':
        t = db.fetch_val("SELECT value FROM system_settings WHERE key='target_network'", default="")
        p = db.fetch_val("SELECT value FROM system_settings WHERE key='scan_profile'", default="FAST")
        return jsonify({'target': t, 'profile': p})
    else:

        data = request.json
        if not data or not isinstance(data.get('target'), str) or not isinstance(data.get('profile'), str):
            return jsonify({'error': 'Invalid input parameters'}), 400
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('target_network', ?)", (data.get('target'),))
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('scan_profile', ?)", (data.get('profile'),))
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('scanner_enabled', '1')")
        return jsonify({'status': 'success', 'scanner_enabled': True})

@app.route('/api/v2/config/schedule', methods=['GET', 'POST'])
@requires_auth
def api_schedule():
    if request.method == 'GET':
        f = db.fetch_val("SELECT value FROM system_settings WHERE key='schedule_frequency'", default="")
        t = db.fetch_val("SELECT value FROM system_settings WHERE key='schedule_time'", default="02:00")
        e = db.fetch_val("SELECT value FROM system_settings WHERE key='schedule_enabled'", default="0")
        return jsonify({'frequency': f, 'time': t, 'enabled': e == '1', 'next_run': 'Tomorrow at ' + t})
    else:
        data = request.json
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('schedule_frequency', ?)", (data.get('frequency'),))
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('schedule_time', ?)", (data.get('time'),))
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('schedule_enabled', ?)", ('1' if data.get('enabled') else '0',))
        return jsonify({'status': 'success'})

@app.route('/api/v2/config/targets', methods=['GET', 'POST'])
@requires_auth
def api_targets():
    if request.method == 'GET':
        targets = db.fetch_all('SELECT * FROM saved_targets ORDER BY created_at DESC')
        return jsonify({'targets': targets})
    else:
        data = request.json
        db.execute("INSERT INTO saved_targets (name, target_cidr, scan_profile) VALUES (?, ?, ?)", (data.get('name'), data.get('target'), data.get('profile')))
        return jsonify({'status': 'success'})

@app.route('/api/v2/config/targets/<int:tid>/use', methods=['POST'])
@requires_auth
def api_use_target(tid):
    t = db.fetch_one('SELECT * FROM saved_targets WHERE id=?', (tid,))
    if t:
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('target_network', ?)", (t['target_cidr'],))
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('scan_profile', ?)", (t['scan_profile'],))
        return jsonify({'status': 'success'})
    return jsonify({'error': 'not found'}), 404


@app.route('/api/v2/shield/actions')
@requires_auth
def api_shield_actions():
    try:
        active = request.args.get('active', '1')
        res = db.fetch_all('SELECT id, taken_at, action_type, target_ip, rule_applied, justification FROM shield_actions WHERE is_active = ? ORDER BY taken_at DESC LIMIT 5', (active,))
        return jsonify({'data': res})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/v2/shield/revert/<int:aid>', methods=['POST'])
@requires_auth
def api_shield_revert(aid):
    try:
        db.execute('UPDATE shield_actions SET is_active=0, reverted_at=? WHERE id=?', (time.time(), aid))
        return jsonify({'status': 'success'})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/v2/config/detect-network')
@requires_auth
def api_detect():
    from config.network_detector import detect_network
    return jsonify(detect_network())

@app.route('/api/v2/export/<format_type>', methods=['GET'])
@requires_auth
def api_export_data(format_type):
    try:
        data_type = request.args.get('type', 'hosts')
        if data_type == 'hosts':
            data = db.fetch_all('SELECT ip, mac, hostname, os_name, risk_score, asset_value FROM hosts WHERE is_active=1')
            headers = ['ip', 'mac', 'hostname', 'os_name', 'risk_score', 'asset_value']
        elif data_type == 'cves':
            data = db.fetch_all('SELECT h.ip, c.cve_id, c.cvss_v3, c.severity FROM cves c JOIN port_cves pc ON pc.cve_id = c.id JOIN ports p ON p.id = pc.port_id JOIN hosts h ON h.id = p.host_id')
            headers = ['ip', 'cve_id', 'cvss_v3', 'severity']
        else: return jsonify({'error': 'invalid type'}), 400
        
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=headers)
        writer.writeheader()
        for row in data: writer.writerow(row)
        return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': f'attachment; filename={data_type}.csv'})
    except Exception as e: return jsonify({'error': str(e)}), 500


@app.route('/api/v2/cves')
@requires_auth
def api_all_cves_v2():
    try:
        res = db.fetch_all('''
            SELECT
                h.ip,
                c.cve_id,
                c.cvss_v3,
                c.severity,
                c.description,
                p.port,
                p.service,
                pc.verified_status,
                pc.detected_version,
                pc.dismissed,
                pc.port_id,
                pc.cve_id as cve_db_id
            FROM cves c
            JOIN port_cves pc ON pc.cve_id = c.id
            JOIN ports p ON p.id = pc.port_id
            JOIN hosts h ON h.id = p.host_id
            WHERE pc.dismissed = 0
              AND h.is_active = 1
            ORDER BY c.cvss_v3 DESC
        ''')
        return jsonify({'data': res})
    except Exception as e:
        logger.error(f'CVE API failed: {e}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/v2/cves/dismiss/<int:port_id>/<int:cve_id>', methods=['POST'])
@requires_auth
def api_dismiss_cve(port_id, cve_id):
    try:
        current = db.fetch_val(
            'SELECT dismissed FROM port_cves WHERE port_id=? AND cve_id=?',
            (port_id, cve_id), default=0
        )
        new_val = 0 if current else 1
        db.execute(
            'UPDATE port_cves SET dismissed=? WHERE port_id=? AND cve_id=?',
            (new_val, port_id, cve_id)
        )
        return jsonify({'status': 'success', 'dismissed': bool(new_val)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/v2/cves/reverify', methods=['POST'])
@requires_auth
def api_reverify_cves():
    try:
        from iris.cve_mapper import verify_all_cves
        result = run_async(verify_all_cves(), timeout=120)
        return jsonify({'status': 'success', 'updated': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/v2/system/retention', methods=['GET', 'POST'])
@requires_auth
def api_retention():
    """Get or set data retention days. Persisted in system_settings."""
    try:
        if request.method == 'POST':
            days = request.json.get('days', 30) if request.json else 30
            db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('retention_days', ?)", (str(days),))
            return jsonify({'status': 'success', 'days': days})
        current = db.fetch_val("SELECT value FROM system_settings WHERE key='retention_days'", default="30")
        return jsonify({'days': int(current)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/v2/system/prune', methods=['POST'])
@requires_auth
def api_prune():
    """Delete scans and associated data older than N days. Saves days as new retention."""
    try:
        days = request.json.get('days', 30) if request.json else 30
        # Persist as new retention setting
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('retention_days', ?)", (str(days),))
        cutoff = time.time() - (days * 86400)
        old_scans = db.fetch_val('SELECT COUNT(*) FROM scans WHERE finished_at < ?', (cutoff,), default=0)
        db.execute('DELETE FROM scan_diffs WHERE scan_id IN (SELECT id FROM scans WHERE finished_at < ?)', (cutoff,))
        db.execute('DELETE FROM scans WHERE finished_at < ?', (cutoff,))
        db.execute('DELETE FROM behavioral_events WHERE ts < ?', (cutoff,))
        db.execute('DELETE FROM anomalies WHERE acknowledged = 1 AND detected_at < ?', (cutoff,))
        return jsonify({'status': 'success', 'deleted_scans': old_scans, 'cutoff_days': days})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/actions/toggle_scanner', methods=['POST'])
@requires_auth
def api_toggle_scanner():
    try:
        data = request.get_json() or {}
        # If enabled is provided in json, use it, otherwise toggle
        current = db.fetch_val("SELECT value FROM system_settings WHERE key='scanner_enabled'", default='0')
        new_val = data.get('enabled')
        if new_val is None:
            new_val = '0' if current == '1' else '1'
        else:
            new_val = '1' if new_val else '0'
        
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('scanner_enabled', ?)", (new_val,))
        return jsonify({'status': 'success', 'enabled': new_val == '1'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/actions/scan', methods=['POST'])
@requires_auth
def trigger_scan():
    try:
        # Cancel any running scan first
        db.execute("UPDATE scans SET status='CANCELLED' WHERE status='RUNNING'")
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('manual_trigger', '1')")
        socketio.emit('scan_progress', {'status': 'running', 'message': 'Scan trigger sent to daemon...'})
        return jsonify({'status': 'success', 'message': 'Scan triggered'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/actions/cancel_scan', methods=['POST'])
@requires_auth
def cancel_scan():
    try:
        db.execute("UPDATE scans SET status='CANCELLED' WHERE status='RUNNING'")
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('scanner_enabled', '0')")
        socketio.emit('scan_progress', {'status': 'complete', 'message': 'Scan cancelled'})
        return jsonify({'status': 'success', 'message': 'Scan cancelled'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


_net_prev: dict[str, dict] = {}
_net_prev_time: float = 0
_lat_cache: dict[str, float] = {'val': 0, 'at': 0}

def _parse_net_dev():
    stats = {}
    with open('/proc/net/dev') as f:
        for line in f.readlines()[2:]:
            parts = line.strip().split()
            if not parts:
                continue
            iface = parts[0].rstrip(':')
            stats[iface] = {
                'rx_bytes': int(parts[1]), 'rx_packets': int(parts[2]),
                'tx_bytes': int(parts[9]), 'tx_packets': int(parts[10]),
            }
    return stats

def _get_latency():
    now = time.time()
    if now - _lat_cache.get('at', 0) < 3 and _lat_cache.get('val', 0) > 0:
        return _lat_cache['val']
    try:
        gw = os.environ.get('OBSIDIOS_GATEWAY', '192.168.1.1')
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        t0 = time.time()
        s.connect((gw, 80))
        ms = (time.time() - t0) * 1000
        s.close()
        _lat_cache.update({'val': round(ms, 1), 'at': now})
        return round(ms, 1)
    except Exception:
        return 0

@app.route('/api/network/stats')
@requires_auth
def api_network_stats():
    global _net_prev, _net_prev_time
    try:
        stats = _parse_net_dev()
        eth = stats.get('eth0', {})
        now = time.time()
        dt = now - _net_prev_time if _net_prev_time else 1
        prev = _net_prev.get('eth0', {})

        if prev:
            rx_b = max(0, eth.get('rx_bytes', 0) - prev.get('rx_bytes', 0))
            tx_b = max(0, eth.get('tx_bytes', 0) - prev.get('tx_bytes', 0))
            rx_p = max(0, eth.get('rx_packets', 0) - prev.get('rx_packets', 0))
            tx_p = max(0, eth.get('tx_packets', 0) - prev.get('tx_packets', 0))
        else:
            rx_b = tx_b = rx_p = tx_p = 0

        _net_prev['eth0'] = eth
        _net_prev_time = now

        total_bytes = (rx_b + tx_b) / dt
        total_packets = (rx_p + tx_p) / dt

        return jsonify({
            'packets_per_sec': round(total_packets, 1),
            'bytes_per_sec': round(total_bytes, 1),
            'bandwidth_mbps': round(total_bytes * 8 / 1_000_000, 2),
            'latency_ms': round(_get_latency(), 1),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v2/alerts/config', methods=['GET', 'POST'])
@requires_auth
def api_alert_config():
    if request.method == 'GET':
        c = db.fetch_val("SELECT value FROM system_settings WHERE key='alert_critical_discord'", default="1")
        h = db.fetch_val("SELECT value FROM system_settings WHERE key='alert_high_dashboard'", default="1")
        return jsonify({'critical_to_discord': c == '1', 'high_to_dashboard': h == '1'})
    else:
        data = request.json
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('alert_critical_discord', ?)", ('1' if data.get('critical_to_discord') else '0',))
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('alert_high_dashboard', ?)", ('1' if data.get('high_to_dashboard') else '0',))
        return jsonify({'status': 'success'})






@app.route('/api/v2/forge/rules')
@requires_auth
def api_forge_rules():
    try:
        rules = db.fetch_all('SELECT id, rule_sid, rule_text, rule_category, mitre_technique, is_deployed, is_active, true_positives, false_positives, created_at FROM forge_rules ORDER BY created_at DESC LIMIT 50')
        return jsonify({'data': rules, 'count': len(rules)})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/v2/forge/deploy/<int:rid>', methods=['POST'])
@requires_auth
def api_forge_deploy(rid):
    try:
        rule = db.fetch_one('SELECT is_deployed FROM forge_rules WHERE id=?', (rid,))
        if not rule: return jsonify({'error': 'Rule not found'}), 404
        new_val = 0 if rule['is_deployed'] else 1
        db.execute('UPDATE forge_rules SET is_deployed=? WHERE id=?', (new_val, rid))
        return jsonify({'status': 'success', 'is_deployed': bool(new_val)})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/v2/cves/exploit_status')
@requires_auth
def api_cve_exploit_status():
    try:
        data = db.fetch_all('SELECT h.ip, c.cve_id, c.cvss_v3, c.severity, pc.exploit_status, pc.msf_module FROM port_cves pc JOIN cves c ON c.id = pc.cve_id JOIN ports p ON p.id = pc.port_id JOIN hosts h ON h.id = p.host_id WHERE pc.exploit_status != "THEORETICAL" ORDER BY c.cvss_v3 DESC')
        return jsonify({'data': data, 'count': len(data)})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/v2/offensive/attack_vectors')
@requires_auth
def api_attack_vectors():
    try:
        from oracle.attacker_view import generate_attacker_view
        result = run_async(generate_attacker_view(), timeout=120)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/api/v2/export/pdf')
@requires_auth
def api_export_pdf():
    try:
        from weasyprint import HTML
        # Gather data
        hosts = db.fetch_all('SELECT ip, mac, hostname, os_name, risk_score, asset_value FROM hosts WHERE is_active=1 ORDER BY risk_score DESC')
        cves = db.fetch_all("SELECT h.ip, c.cve_id, c.cvss_v3, c.severity, c.description FROM cves c JOIN port_cves pc ON pc.cve_id = c.id JOIN ports p ON p.id = pc.port_id JOIN hosts h ON h.id = p.host_id ORDER BY c.cvss_v3 DESC LIMIT 50")
        summary = db.fetch_all("SELECT c.severity, COUNT(*) as cnt FROM cves c JOIN port_cves pc ON pc.cve_id = c.id GROUP BY c.severity")
        total_hosts = db.fetch_val('SELECT COUNT(*) FROM hosts WHERE is_active=1', default=0)
        total_cves = db.fetch_val('SELECT COUNT(*) FROM port_cves', default=0)
        total_paths = db.fetch_val('SELECT COUNT(*) FROM attack_paths WHERE is_active=1', default=0)
        
        sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for r in summary:
            sev_counts[r['severity']] = r['cnt']
        
        cves_rows = ""
        for r in cves:
            sev_color = "#f16479" if r['severity'] == 'CRITICAL' else "#f59e0b" if r['severity'] == 'HIGH' else "#5b8dee" if r['severity'] == 'MEDIUM' else "#8492a8"
            cves_rows += f"<tr><td>{r['ip']}</td><td>{r['cve_id']}</td><td style='color:{sev_color}'>{r['severity']}</td><td>{r['cvss_v3'] or 'N/A'}</td><td style='font-size:9px;max-width:250px'>{r['description'] or ''}</td></tr>\n"
        
        hosts_rows = "".join(f"<tr><td>{h['ip']}</td><td>{h['mac'] or '-'}</td><td>{h['hostname'] or '-'}</td><td>{h['os_name'] or 'Unknown'}</td><td>{h['risk_score'] or 0}</td></tr>\n" for h in hosts)
        
        critical_pct = round(sev_counts['CRITICAL'] / max(total_cves, 1) * 100, 1)
        high_pct = round(sev_counts['HIGH'] / max(total_cves, 1) * 100, 1)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>OBSIDIOS Security Report</title>
<style>
@page {{ margin: 1.5cm; @top-center {{ content: "OBSIDIOS — Security Assessment Report"; font-size: 9px; color: #555; }} @bottom-center {{ content: "Page " counter(page); font-size: 9px; color: #555; }} }}
body {{ font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; font-size: 11px; color: #222; line-height: 1.5; }}
h1 {{ font-size: 22px; color: #1a1a2e; border-bottom: 3px solid #5b8dee; padding-bottom: 8px; }}
h2 {{ font-size: 16px; color: #1a1a2e; margin-top: 24px; border-bottom: 1px solid #ddd; padding-bottom: 4px; }}
table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
th, td {{ text-align: left; padding: 6px 8px; border-bottom: 1px solid #eee; font-size: 10px; }}
th {{ background: #1a1a2e; color: white; font-weight: 600; }}
tr:nth-child(even) {{ background: #f8f8fc; }}
.summary-grid {{ display: flex; gap: 12px; margin: 16px 0; }}
.summary-card {{ flex: 1; padding: 12px; border-radius: 6px; text-align: center; }}
.summary-card h3 {{ margin: 0 0 4px; font-size: 24px; }}
.summary-card p {{ margin: 0; font-size: 10px; opacity: 0.8; }}
.card-red {{ background: #fff0f0; color: #c0392b; }} .card-blue {{ background: #f0f4ff; color: #2c6fbb; }} .card-green {{ background: #f0fff4; color: #27ae60; }} .card-orange {{ background: #fff8f0; color: #d4870b; }}
.footer {{ margin-top: 32px; padding-top: 12px; border-top: 1px solid #ddd; font-size: 9px; color: #888; }}
.tag {{ display: inline-block; padding: 1px 6px; border-radius: 2px; font-size: 9px; font-weight: bold; }}
.tag-crit {{ background: #f16479; color: white; }} .tag-high {{ background: #f59e0b; color: white; }} .tag-med {{ background: #5b8dee; color: white; }} .tag-low {{ background: #8492a8; color: white; }}
</style></head>
<body>
<h1>OBSIDIOS — Executive Security Report</h1>
<p style="font-size:11px;color:#555">Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} | Target: {db.fetch_val('SELECT value FROM system_settings WHERE key=\'target_network\'', default='N/A')}</p>

<div class="summary-grid">
  <div class="summary-card card-red"><h3>{sev_counts['CRITICAL']}</h3><p>Critical CVEs</p></div>
  <div class="summary-card card-orange"><h3>{sev_counts['HIGH']}</h3><p>High CVEs</p></div>
  <div class="summary-card card-blue"><h3>{total_hosts}</h3><p>Active Hosts</p></div>
  <div class="summary-card card-green"><h3>{total_paths}</h3><p>Attack Paths</p></div>
</div>

<h2>Executive Summary</h2>
<p>This report covers {total_hosts} active hosts with {total_cves} identified vulnerabilities ({sev_counts['CRITICAL']} critical, {sev_counts['HIGH']} high, {sev_counts['MEDIUM']} medium, {sev_counts['LOW']} low). {total_paths} adversarial attack paths were simulated.</p>
<p><strong>Risk Profile:</strong> {critical_pct}% of vulnerabilities are critical severity, {high_pct}% are high severity. Prioritize remediation of critical CVEs with active exploit paths.</p>

<h2>Host Inventory</h2>
<table><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>OS</th><th>Risk</th></tr></thead><tbody>{hosts_rows}</tbody></table>

<h2>Vulnerability Details (Top 50 by CVSS)</h2>
<table><thead><tr><th>Host</th><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr></thead><tbody>{cves_rows}</tbody></table>

<h2>Methodology</h2>
<p>Scanning was performed using Nmap with ARP discovery, service fingerprinting, and OS detection. CVEs were mapped via NVD API. Attack paths were simulated using Dijkstra-based traversal of MITRE ATT&CK techniques. All data is stored in OBSIDIOS' tactical database.</p>

<div class="footer">
<p>OBSIDIOS Autonomous Security Platform — This report is auto-generated.</p>
</div>
</body></html>"""
        pdf = HTML(string=html).write_pdf()
        return Response(pdf, mimetype='application/pdf', headers={'Content-Disposition': 'attachment; filename=obsidios_report.pdf'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v2/iris/scan_wireless', methods=['POST'])
@requires_auth
def api_scan_wireless():
    try:
        from iris.wired_scanner import run_wireless_scan
        run_async(run_wireless_scan(), timeout=30)
        return jsonify({'status': 'success', 'message': 'Wireless scan triggered'})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/v2/iris/osint')
@requires_auth
def api_osint():
    try:
        findings = db.fetch_all('SELECT * FROM osint_findings ORDER BY discovered_at DESC LIMIT 20')
        return jsonify({'data': findings})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/v2/iris/wireless')
@requires_auth
def api_wireless():
    try:
        threats = db.fetch_all('SELECT * FROM wireless_threats WHERE is_active=1 ORDER BY detected_at DESC')
        return jsonify({'data': threats})
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/v2/sentinel/alerts')
@requires_auth
def api_sentinel_alerts():
    try:
        alerts = db.fetch_all('''
            SELECT sa.id, sa.alerted_at, sa.rule_sid, sa.src_ip, sa.dst_ip,
                   sa.dst_port, sa.protocol, sa.severity, sa.message,
                   sa.predicted, sa.acknowledged, fr.rule_category
            FROM sentinel_alerts sa
            LEFT JOIN forge_rules fr ON fr.rule_sid = sa.rule_sid
            ORDER BY sa.alerted_at DESC LIMIT 50
        ''')
        return jsonify({'data': alerts, 'count': len(alerts)})
    except Exception as e: return jsonify({'error': str(e)}), 500





@app.route('/api/v2/oracle/compliance')
@requires_auth
def api_compliance():
    try:
        from oracle.compliance_mapper import map_compliance
        framework = request.args.get('framework', 'PCI-DSS')
        res = run_async(map_compliance(framework))
        return jsonify(res)
    except Exception as e: return jsonify({'error': str(e)}), 500

@app.route('/api/v2/oracle/ai_brief')
@requires_auth
def api_ai_brief():
    """Return the latest AI attack narrative + remediation brief from claude_client."""
    last_err = None
    for attempt in range(2):
        try:
            from oracle.claude_client import generate_attack_narrative, generate_remediation
            narrative = run_async(generate_attack_narrative(), timeout=90)
            remediation = run_async(generate_remediation(), timeout=90)
            return jsonify({'narrative': narrative, 'remediation': remediation})
        except Exception as e:
            last_err = e
            if 'database is locked' in str(e) and attempt == 0:
                logger.warning(f'[DASHBOARD] AI brief DB locked, retrying...')
                time.sleep(1)
                continue
            break
    logger.error(f'AI brief failed: {last_err}')
    return jsonify({'error': str(last_err)}), 500


@app.route('/api/v2/oracle/patch_priority')
@requires_auth
def api_patch_priority():
    try:
        from oracle.patch_prioritizer import generate_patch_priority
        res = run_async(generate_patch_priority())
        return jsonify(res)
    except Exception as e: return jsonify({'error': str(e)}), 500


def run_dashboard(host='0.0.0.0', port=8080):
    # Eagerly initialise chronicle.db (not db_sync) so first read doesn't trigger DDL
    try:
        from chronicle import db as chronicle_db
        run_async(chronicle_db.init(), timeout=30)
    except Exception as e:
        logger.warning(f'[DASHBOARD] DB init on startup: {e} — will retry on first request')

    socketio.run(app, host=host, port=port, allow_unsafe_werkzeug=True, use_reloader=False)


if __name__ == '__main__': run_dashboard()
