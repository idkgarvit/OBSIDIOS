import asyncio
import concurrent.futures
import csv
import datetime
import html
import io
import ipaddress
import json
import os
import re
import secrets
import socket
import threading
import time
from functools import wraps

import jwt
from flask import Flask, Response, g, jsonify, render_template, request
from flask_socketio import SocketIO
from loguru import logger

from chronicle.live_state import alert_is_actionable, path_is_live
from dashboard import db_sync as db

# Every "current exposure" number joins the same three facts: the host is
# still active, its service is still open, and the finding was not dismissed
# or verified as not affecting the detected version.
_LIVE_CVE_SQL = (
    "FROM port_cves pc "
    "JOIN cves c ON c.id = pc.cve_id "
    "JOIN ports p ON p.id = pc.port_id "
    "JOIN hosts h ON h.id = p.host_id "
    "WHERE h.is_active = 1 AND p.state = 'open' "
    "AND COALESCE(pc.dismissed, 0) = 0 "
    "AND COALESCE(pc.verified_status, '') != 'NOT_AFFECTED'"
)


def _active_ips_sync() -> set[str]:
    rows = db.fetch_all(
        "SELECT ip FROM hosts WHERE is_active=1 AND ip IS NOT NULL AND ip != ''"
    ) or []
    return {_row_get(row, 'ip') for row in rows if _row_get(row, 'ip')}


def _live_path_rows_sync() -> list:
    """Active attack paths whose every hop is still an active host."""
    active = _active_ips_sync()
    rows = db.fetch_all(
        "SELECT * FROM attack_paths WHERE is_active=1 ORDER BY attacker_roi DESC"
    ) or []
    return [
        row for row in rows
        if path_is_live(_row_get(row, 'path_json'), active)
    ]


def _live_path_ids_sync() -> set[int]:
    return {
        path_id for path_id in (_row_get(row, 'id') for row in _live_path_rows_sync())
        if path_id is not None
    }


def _actionable_unacked_alerts_sync() -> list[dict]:
    """Unacknowledged alerts that still describe reachable exposure."""
    active = _active_ips_sync()
    live_ids = _live_path_ids_sync()
    rows = db.fetch_all(
        "SELECT * FROM sentinel_alerts WHERE acknowledged=0"
    ) or []
    return [row for row in rows if alert_is_actionable(row, active, live_ids)]


def _alert_severity(row, default: int = 3) -> int:
    """Numeric Suricata severity, defaulting malformed rows to INFO.

    The dashboard renders ``severity <= 1`` as CRITICAL; a stray string in
    the column must not make the context endpoint fail.
    """
    try:
        return int(_row_get(row, 'severity') or default)
    except (TypeError, ValueError):
        return default

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
        _load_revoked_tokens()
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
def _resolve_app_secret() -> str:
    for k in ('OBSIDIOS_SECRET', 'SECRET_KEY'):
        v = os.environ.get(k, '').strip()
        if v:
            return v
    try:
        from config.settings import dash as _dash
        if _dash.secret_key:
            return _dash.secret_key
    except Exception:
        pass
    return ''
_WEAK_APP_SECRETS = {
    '', 'changeme', 'obsidios123', 'admin', 'password',
    'obsidios-secret-fallback-for-dev',
    'obsidios-secret-fallback-for-dev-only-do-not-use-in-prod',
}


def _secure_app_secret() -> str:
    """Return a strong signing key, or fail closed in production.

    Importing ``dashboard.app`` must never silently fall back to a public,
    well-known JWT signing key when OBSIDIOS_ENV=production. The CLI guard is
    not enough: operators can launch Gunicorn directly.
    """
    secret = _resolve_app_secret()
    env = os.environ.get('OBSIDIOS_ENV', 'dev').strip().lower()
    production = env in ('prod', 'production')
    if len(secret) < 32 or secret in _WEAK_APP_SECRETS:
        if production:
            raise RuntimeError(
                'OBSIDIOS_SECRET must be at least 32 random characters in production; '
                "generate one with: python3 -c 'import secrets; print(secrets.token_urlsafe(48))'"
            )
        logger.warning("[DASHBOARD] OBSIDIOS_SECRET not set or weak — set 32+ random bytes. Dev-only fallback in use.")
        return 'obsidios-secret-fallback-for-dev-only-do-not-use-in-prod'
    return secret


app.config['SECRET_KEY'] = _secure_app_secret()
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.jinja_env.auto_reload = True

def socketio_log_sink(message):
    try:
        msg = message.strip()
        level = 'INFO'
        if '[SUCCESS]' in msg or '✓' in msg: level = 'OK'
        elif '[WARNING]' in msg or '!' in msg: level = 'WARN'
        elif '[ERROR]' in msg or 'FAIL' in msg: level = 'CRIT'
        # Only authenticated dashboard sessions receive log streams.
        socketio.emit('log_event', {'level': level, 'message': msg},
                      namespace='/', to='authenticated')
    except Exception:
        pass

logger.add(socketio_log_sink, level='INFO', format='{message}', backtrace=False, diagnose=False)

_CORS_ORIGINS = [o.strip() for o in os.environ.get(
    'CORS_ORIGINS', 'http://localhost:8080,http://127.0.0.1:8080').split(',') if o.strip()]
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins=_CORS_ORIGINS,
                    manage_session=False)

_rate_limit_store: dict[str, list[float]] = {}
_rate_limit_lock = threading.Lock()
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 50
_LOGIN_FAILS: dict[str, list[float]] = {}
_LOGIN_FAILS_LOCK = threading.Lock()
LOGIN_LOCKOUT_THRESHOLD = 5
LOGIN_LOCKOUT_SECONDS = 300
_MAX_TRACKED_CLIENTS = 10_000

ACCESS_TTL_SECONDS = 900  # 15 min
REFRESH_TTL_SECONDS = 7 * 24 * 3600  # 7 days
_REVOKED_JTIS: dict[str, float] = {}  # jti -> exp (in-memory denylist)
_REVOKED_LOCK = threading.Lock()


def _client_ip() -> str:
    """Client address for rate limiting/lockout.

    X-Forwarded-For is only honoured when OBSIDIOS_TRUST_PROXY=1, otherwise a
    client can trivially rotate the header and bypass lockouts.
    """
    if os.environ.get('OBSIDIOS_TRUST_PROXY', '').strip().lower() in ('1', 'true', 'yes'):
        fwd = request.headers.get('X-Forwarded-For', '')
        if fwd:
            # The trusted proxy appends the address it actually saw, so the
            # right-most entry is the one an attacker cannot spoof. Taking the
            # left-most entry would let a client rotate X-Forwarded-For and
            # bypass login lockouts/rate limits.
            candidate = fwd.split(',')[-1].strip()
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                pass
    return request.remote_addr or 'unknown'


_AUDIT_RETENTION_DAYS = 365


def _audit(action: str, *, target=None, detail=None, outcome: str = 'success',
           actor: str | None = None, role: str | None = None) -> None:
    """Append one state-changing action to the operator audit trail.

    Best effort by design: an audit write must never turn a successful
    operation into an error. The authenticated identity comes from the JWT
    claims already validated by the auth decorator.
    """
    try:
        who = actor if actor is not None else getattr(g, 'user', 'system')
        r = role if role is not None else getattr(g, 'role', '')
        db.execute(
            'INSERT INTO audit_log (actor, role, action, target, detail, ip, outcome) '
            'VALUES (?,?,?,?,?,?,?)',
            (
                str(who or 'unknown')[:128],
                str(r or '')[:16],
                str(action)[:64],
                None if target is None else str(target)[:256],
                None if detail is None else str(detail)[:2000],
                _client_ip()[:64],
                str(outcome)[:16],
            ),
        )
        # Keep the trail bounded without a background job; the delete is
        # indexed and runs rarely.
        if secrets.randbelow(200) == 0:
            db.execute(
                'DELETE FROM audit_log WHERE ts < ?',
                (time.time() - _AUDIT_RETENTION_DAYS * 86400,),
            )
    except Exception as exc:
        logger.warning(f'[AUDIT] Could not record {action}: {exc}')


def _prune_auth_stores() -> None:
    now = time.time()
    with _REVOKED_LOCK:
        for jti, exp in list(_REVOKED_JTIS.items()):
            if exp < now:
                _REVOKED_JTIS.pop(jti, None)
    with _LOGIN_FAILS_LOCK:
        if len(_LOGIN_FAILS) > _MAX_TRACKED_CLIENTS:
            for ip, stamps in list(_LOGIN_FAILS.items()):
                if not stamps or stamps[-1] < now - LOGIN_LOCKOUT_SECONDS:
                    _LOGIN_FAILS.pop(ip, None)
    with _rate_limit_lock:
        if len(_rate_limit_store) > _MAX_TRACKED_CLIENTS:
            for ip, stamps in list(_rate_limit_store.items()):
                if not stamps or stamps[-1] < now - RATE_LIMIT_WINDOW:
                    _rate_limit_store.pop(ip, None)


_REVOKED_CREATE_SQL = (
    "CREATE TABLE IF NOT EXISTS revoked_tokens "
    "(jti TEXT PRIMARY KEY, expires_at REAL NOT NULL)"
)


def _persist_revocation(jti: str, exp: float) -> None:
    try:
        conn = db.get_db_conn()
        try:
            conn.execute(_REVOKED_CREATE_SQL)
            conn.execute(
                'INSERT OR REPLACE INTO revoked_tokens (jti, expires_at) VALUES (?, ?)',
                (jti, float(exp)),
            )
            conn.execute('DELETE FROM revoked_tokens WHERE expires_at < ?', (time.time(),))
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        logger.warning(f'[AUTH] Could not persist token revocation: {e}')


def _revoke_jti(jti: str, exp: float) -> None:
    """Revoke a token in memory and persist it so a restart cannot revive it."""
    if not jti:
        return
    with _REVOKED_LOCK:
        _REVOKED_JTIS[jti] = float(exp)
    _persist_revocation(jti, exp)


def _consume_jti(jti: str, exp: float) -> bool:
    """Atomically revoke a single-use token.

    Two refreshes racing with the same token must not both succeed: the
    check-then-revoke in the old code was a TOCTOU window that let one
    refresh token mint two sessions.
    """
    if not jti:
        return True
    with _REVOKED_LOCK:
        if jti in _REVOKED_JTIS:
            return False
        _REVOKED_JTIS[jti] = float(exp)
    _persist_revocation(jti, exp)
    return True


def _load_revoked_tokens() -> None:
    """Rehydrate the revocation denylist after a dashboard restart."""
    try:
        conn = db.get_db_conn()
        try:
            conn.execute(_REVOKED_CREATE_SQL)
            rows = conn.execute(
                'SELECT jti, expires_at FROM revoked_tokens WHERE expires_at > ?',
                (time.time(),),
            ).fetchall()
            conn.commit()
        finally:
            conn.close()
        with _REVOKED_LOCK:
            for row in rows:
                # One malformed legacy row must not stop the rest from being
                # rehydrated: a skipped valid token would stay usable.
                try:
                    jti = row['jti']
                    expires_at = float(row['expires_at'])
                except (KeyError, TypeError, ValueError):
                    continue
                if isinstance(jti, str) and jti:
                    _REVOKED_JTIS[jti] = expires_at
        if rows:
            logger.info(f'[AUTH] Loaded {len(rows)} revoked token(s) from disk')
    except Exception as e:
        logger.warning(f'[AUTH] Could not load revoked tokens: {e}')


# Pre-init the async DB connection pool at import time so oracle endpoints
# don't compete with the daemon for write locks. Start this only after the
# auth stores exist: the init thread also rehydrates the revocation denylist.
_ensure_bg_loop()
t = threading.Thread(target=_pre_init_db, daemon=True)
t.start()


def _is_locked_out(ip: str) -> bool:
    now = time.time()
    with _LOGIN_FAILS_LOCK:
        fails = [t for t in _LOGIN_FAILS.get(ip, []) if now - t < LOGIN_LOCKOUT_SECONDS]
        _LOGIN_FAILS[ip] = fails
        return len(fails) >= LOGIN_LOCKOUT_THRESHOLD


def _record_login_fail(ip: str) -> None:
    now = time.time()
    with _LOGIN_FAILS_LOCK:
        _LOGIN_FAILS.setdefault(ip, []).append(now)
    _prune_auth_stores()

_WEAK_PASSWORDS = {"", "obsidios123", "admin", "password", "changeme", "change-me-immediately"}


def _is_production() -> bool:
    return os.environ.get('OBSIDIOS_ENV', 'dev').strip().lower() in ('prod', 'production')


def _operator_creds() -> tuple[str, str]:
    user = os.environ.get('DASHBOARD_USER', 'admin')
    pw = os.environ.get('DASHBOARD_PASS', '')
    if not pw and not _is_production():
        pw = 'obsidios123'  # dev-only fallback; prod fails closed (see below)
    return user, pw


def _viewer_creds() -> tuple[str, str] | None:
    user = os.environ.get('VIEWER_USER', '').strip()
    pw = os.environ.get('VIEWER_PASS', '').strip()
    if user and pw:
        return user, pw
    return None


def check_auth(username, password) -> str | None:
    """Validate credentials. Returns role ('operator'/'viewer') or None."""
    import hmac
    ou, op = _operator_creds()
    if username == ou and op and hmac.compare_digest(str(password), str(op)):
        if _is_production() and (not op or op in _WEAK_PASSWORDS):
            return None  # fail closed in prod even if env default leaked
        return 'operator'
    vc = _viewer_creds()
    if vc and username == vc[0] and hmac.compare_digest(str(password), str(vc[1])):
        return 'viewer'
    return None


def _issue_tokens(username: str, role: str) -> dict:
    now = datetime.datetime.now(datetime.UTC)
    access_jti = secrets.token_hex(16)
    refresh_jti = secrets.token_hex(16)
    access = jwt.encode(
        {'user': username, 'role': role, 'iss': 'obsidios', 'type': 'access',
         'jti': access_jti, 'exp': now + datetime.timedelta(seconds=ACCESS_TTL_SECONDS)},
        app.config['SECRET_KEY'], algorithm='HS256')
    refresh = jwt.encode(
        {'user': username, 'role': role, 'iss': 'obsidios', 'type': 'refresh',
         'jti': refresh_jti, 'exp': now + datetime.timedelta(seconds=REFRESH_TTL_SECONDS)},
        app.config['SECRET_KEY'], algorithm='HS256')
    return {
        'token': access, 'user': username, 'role': role,
        'expires_in': ACCESS_TTL_SECONDS,
        'refresh_expires_in': REFRESH_TTL_SECONDS,
        '_refresh_token': refresh,  # consumed by _set_refresh_cookie, never serialised
    }


def _set_refresh_cookie(response, refresh_token: str):
    response.set_cookie(
        'obsidios_refresh', refresh_token,
        max_age=REFRESH_TTL_SECONDS, httponly=True, secure=_is_production(),
        samesite='Strict', path='/api/v2',
    )
    return response


def _clear_refresh_cookie(response):
    response.delete_cookie('obsidios_refresh', path='/api/v2', httponly=True,
                           secure=_is_production(), samesite='Strict')
    return response


def _decode_token(raw: str) -> dict:
    payload = jwt.decode(raw, app.config['SECRET_KEY'], algorithms=['HS256'],
                         options={'require': ['exp', 'iss']})
    if payload.get('iss') != 'obsidios':
        raise ValueError('bad issuer')
    jti = payload.get('jti', '')
    with _REVOKED_LOCK:
        revoked = bool(jti and jti in _REVOKED_JTIS)
    if revoked:
        raise ValueError('revoked')
    return payload


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Token is missing'}), 401
        try:
            payload = _decode_token(token.split(' ', 1)[1])
            if payload.get('type', 'access') != 'access':
                return jsonify({'error': 'Token is invalid'}), 401
            g.user = payload.get('user', '')
            g.role = payload.get('role', 'viewer')  # fail closed for role-less legacy tokens
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except Exception:
            return jsonify({'error': 'Token is invalid'}), 401
        return f(*args, **kwargs)
    return decorated


def requires_operator(f):
    @wraps(f)
    @requires_auth
    def decorated(*args, **kwargs):
        if getattr(g, 'role', '') != 'operator':
            return jsonify({'error': 'Operator role required'}), 403
        return f(*args, **kwargs)
    return decorated


def requires_operator_write(f):
    """Read endpoints stay available to viewers; mutations require operator."""
    @wraps(f)
    @requires_auth
    def decorated(*args, **kwargs):
        if request.method not in ('GET', 'HEAD', 'OPTIONS') and getattr(g, 'role', '') != 'operator':
            return jsonify({'error': 'Operator role required'}), 403
        return f(*args, **kwargs)
    return decorated


def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        client_ip = _client_ip()
        now = time.time()
        with _rate_limit_lock:
            stamps = [t for t in _rate_limit_store.get(client_ip, []) if now - t < RATE_LIMIT_WINDOW]
            if len(stamps) >= RATE_LIMIT_MAX:
                return jsonify({'error': 'Rate limit exceeded. Try again later.'}), 429
            stamps.append(now)
            _rate_limit_store[client_ip] = stamps
        if len(_rate_limit_store) > _MAX_TRACKED_CLIENTS:
            _prune_auth_stores()
        return f(*args, **kwargs)
    return decorated

@app.route('/api/health', methods=['GET'])
def health():
    """Unauthenticated liveness probe for Docker/K8s. No DB dependency."""
    return jsonify({'status': 'ok', 'service': 'obsidios-dash'}), 200


@app.route('/api/readyz', methods=['GET'])
def readyz():
    """Readiness probe: liveness + DB reachable. 200 ready, 503 not ready."""
    try:
        db.fetch_val('SELECT 1', default=None)
        return jsonify({'status': 'ready', 'service': 'obsidios-dash'}), 200
    except Exception as e:
        logger.warning(f'[READYZ] database check failed: {e}')
        return jsonify({'status': 'not-ready', 'service': 'obsidios-dash'}), 503


@app.route('/metrics', methods=['GET'])
@app.route('/api/v2/metrics', methods=['GET'])
def metrics():
    """Prometheus exposition. Token-gated unless OBSIDIOS_METRICS_PUBLIC=1."""
    public = os.environ.get('OBSIDIOS_METRICS_PUBLIC', '').strip().lower() in ('1', 'true', 'yes')
    token = os.environ.get('OBSIDIOS_METRICS_TOKEN', '').strip()
    if not public:
        supplied = request.headers.get('Authorization', '')
        supplied = supplied[7:] if supplied.startswith('Bearer ') else ''
        if not token or not secrets.compare_digest(supplied, token):
            return jsonify({'error': 'Unauthorized'}), 401
    try:
        hosts = db.fetch_val(
            'SELECT COUNT(*) FROM hosts WHERE is_active=1', default=0) or 0
        ports = db.fetch_val(
            "SELECT COUNT(*) FROM ports p JOIN hosts h ON h.id = p.host_id "
            "WHERE p.state='open' AND h.is_active=1", default=0) or 0
        cves = db.fetch_val(
            f"SELECT COUNT(DISTINCT pc.cve_id) {_LIVE_CVE_SQL}", default=0) or 0
        paths = len(_live_path_rows_sync())
        blocks = db.fetch_val('SELECT COUNT(*) FROM shield_actions WHERE is_active=1', default=0) or 0
        posture = 0.0
        try:
            posture = float(sync_calculate_global_posture() or 0)
        except Exception:
            pass
        body = (
            "# HELP obsidios_hosts_active Active hosts\n# TYPE obsidios_hosts_active gauge\n"
            f"obsidios_hosts_active {hosts}\n"
            "# HELP obsidios_open_ports Open ports\n# TYPE obsidios_open_ports gauge\n"
            f"obsidios_open_ports {ports}\n"
            "# HELP obsidios_cves_total CVEs\n# TYPE obsidios_cves_total gauge\n"
            f"obsidios_cves_total {cves}\n"
            "# HELP obsidios_attack_paths_active Active attack paths\n# TYPE obsidios_attack_paths_active gauge\n"
            f"obsidios_attack_paths_active {paths}\n"
            "# HELP obsidios_shield_blocks_active Active SHIELD blocks\n# TYPE obsidios_shield_blocks_active gauge\n"
            f"obsidios_shield_blocks_active {blocks}\n"
            "# HELP obsidios_posture_score Global posture 0-100\n# TYPE obsidios_posture_score gauge\n"
            f"obsidios_posture_score {posture}\n"
        )
        return Response(body, mimetype='text/plain; version=0.0.4')
    except Exception as e:
        logger.warning(f'[METRICS] collection failed: {e}')
        return Response("# error collecting metrics\n", mimetype='text/plain', status=503)


def _do_login():
    client_ip = _client_ip()
    if _is_locked_out(client_ip):
        return jsonify({'error': 'Too many failed attempts. Try again later.'}), 429
    data = request.get_json(silent=True) or {}
    username = data.get('username')
    password = data.get('password')
    if not isinstance(username, str) or not isinstance(password, str) or not username or not password:
        return jsonify({'error': 'Missing credentials'}), 400
    if len(username) > 128 or len(password) > 512:
        return jsonify({'error': 'Invalid credentials'}), 401
    role = check_auth(username, password)
    if role:
        with _LOGIN_FAILS_LOCK:
            _LOGIN_FAILS.pop(client_ip, None)
        tokens = _issue_tokens(username, role)
        refresh_token = tokens.pop('_refresh_token')
        try:
            db.execute("INSERT INTO system_settings(key,value) VALUES('last_login_'+?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (username, str(time.time())))
        except Exception:
            pass
        logger.info(f"[AUTH] Login success user={username} role={role} ip={client_ip}")
        _audit('AUTH_LOGIN', target=username, detail=f'role={role}',
               actor=username, role=role)
        return _set_refresh_cookie(jsonify(tokens), refresh_token)
    _record_login_fail(client_ip)
    logger.warning(f"[AUTH] Login failed user={username} ip={client_ip}")
    _audit('AUTH_LOGIN_FAILED', target=username, outcome='failure',
           actor=username, role='')
    return jsonify({'error': 'Invalid credentials'}), 401


@socketio.on('connect')
def _socket_connect(auth):
    """Authenticate Socket.IO sessions; unauthenticated clients are rejected."""
    from flask_socketio import join_room
    token = ''
    if isinstance(auth, dict):
        token = auth.get('token', '') or ''
    if not token:
        token = request.args.get('token', '') or ''
    if not token:
        return False
    try:
        payload = _decode_token(token)
        if payload.get('type', 'access') != 'access':
            return False
    except Exception:
        return False
    join_room('authenticated')
    return True


@app.route('/api/login', methods=['POST'])
@rate_limit
def login():
    """Legacy login — kept for dashboard JS compat. Returns short-lived access + refresh."""
    return _do_login()


@app.route('/api/v2/login', methods=['POST'])
@rate_limit
def login_v2():
    return _do_login()


@app.route('/api/v2/refresh', methods=['POST'])
@rate_limit
def refresh():
    data = request.get_json(silent=True) or {}
    raw = request.cookies.get('obsidios_refresh', '') or data.get('refresh_token', '')
    if not raw:
        return jsonify({'error': 'refresh_token required'}), 400
    try:
        payload = _decode_token(raw)
        if payload.get('type') != 'refresh':
            return jsonify({'error': 'Token is invalid'}), 401
        old_jti = payload.get('jti', '')
        if old_jti and not _consume_jti(
            old_jti, float(payload.get('exp', time.time() + 60))
        ):
            return jsonify({'error': 'Refresh token already used'}), 401
        tokens = _issue_tokens(payload.get('user', ''), payload.get('role', 'viewer'))
        refresh_token = tokens.pop('_refresh_token')
        _prune_auth_stores()
        return _set_refresh_cookie(jsonify(tokens), refresh_token)
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except Exception:
        return jsonify({'error': 'Token is invalid'}), 401


@app.route('/api/v2/logout', methods=['POST'])
@requires_auth
def logout():
    token = (request.headers.get('Authorization', '') or '')
    raw = token.split(' ', 1)[1] if ' ' in token else ''
    try:
        payload = jwt.decode(raw, app.config['SECRET_KEY'], algorithms=['HS256'],
                             options={'verify_exp': False})
        jti = payload.get('jti', '')
        if jti:
            _revoke_jti(jti, float(payload.get('exp', time.time() + 60)))
    except Exception:
        pass
    rraw = request.cookies.get('obsidios_refresh', '')
    if rraw:
        try:
            rp = jwt.decode(rraw, app.config['SECRET_KEY'], algorithms=['HS256'],
                            options={'verify_exp': False})
            if rp.get('jti'):
                _revoke_jti(rp['jti'], float(rp.get('exp', time.time() + 60)))
        except Exception:
            pass
    _prune_auth_stores()
    logger.info(f"[AUTH] Logout user={getattr(g, 'user', '')}")
    _audit('AUTH_LOGOUT', target=getattr(g, 'user', ''))
    return _clear_refresh_cookie(jsonify({'status': 'success'}))


def sync_calculate_global_posture():
    try:
        hosts = db.fetch_all("SELECT risk_score FROM hosts WHERE is_active=1 AND ip IS NOT NULL AND ip != ''")
        if not hosts: return 100.0
        avg_risk = sum(h['risk_score'] for h in hosts) / len(hosts)
        path_count = len(_live_path_rows_sync())
        anom_count = db.fetch_val(
            "SELECT COUNT(*) FROM anomalies a JOIN hosts h ON h.id = a.host_id "
            "WHERE a.acknowledged = 0 AND h.is_active = 1",
            default=0,
        )
        # Dismissed findings, NOT_AFFECTED verdicts, closed ports and retired
        # hosts must not drag the headline score down: the dashboard shows the
        # same filtered set everywhere else.
        sev_counts = db.fetch_all(
            "SELECT c.severity, COUNT(*) as cnt FROM port_cves pc "
            "JOIN cves c ON c.id=pc.cve_id "
            "JOIN ports p ON p.id=pc.port_id "
            "JOIN hosts h ON h.id=p.host_id "
            "WHERE h.is_active=1 AND p.state='open' "
            "AND COALESCE(pc.dismissed,0)=0 "
            "AND COALESCE(pc.verified_status,'') != 'NOT_AFFECTED' "
            "GROUP BY c.severity"
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

_ALLOWED_PROFILES: set[str] = set()
_FREQUENCIES = {'hourly', 'daily', 'weekly', 'monthly'}
_SCHEDULE_TIME_RE = re.compile(r'^([01]\d|2[0-3]):[0-5]\d$')


def _allowed_profiles() -> set[str]:
    global _ALLOWED_PROFILES
    if not _ALLOWED_PROFILES:
        try:
            from config.settings import scan as _scan
            _ALLOWED_PROFILES = set(_scan.SCAN_PROFILES.keys())
        except Exception:
            _ALLOWED_PROFILES = {'FAST', 'STEALTH', 'GHOST', 'STEALTH_IDLE'}
    return _ALLOWED_PROFILES


def _clean_text(value, max_len: int = 255) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > max_len:
        return None
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        return None
    return value


def _validated_target(value) -> tuple[str | None, str | None]:
    target = _clean_text(value, 64)
    if not target:
        return None, 'Target must be a valid CIDR or IP'
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return None, 'Target must be a valid CIDR or IP'
    # Store the canonical network (host bits cleared), matching the CLI.
    canonical = str(network)
    from config.settings import validate_target_cidr
    ok, reason = validate_target_cidr(canonical)
    if not ok:
        return None, reason
    return canonical, None


def _validated_profile(value) -> str | None:
    profile = _clean_text(value, 32)
    if not profile:
        return None
    profile = profile.upper()
    return profile if profile in _allowed_profiles() else None


def _validated_days(value) -> int | None:
    try:
        days = int(value)
    except (TypeError, ValueError):
        return None
    return days if 1 <= days <= 3650 else None


_STALE_SCAN_SECONDS = 12 * 3600  # GHOST can legitimately run for ~4 hours


def _reap_stale_running_scans() -> int:
    """Expire RUNNING rows left behind by a crashed daemon or CLI.

    Without this, one crashed sweep made every future trigger answer 409 and
    left the dashboard showing SCANNING forever.
    """
    cutoff = time.time() - _STALE_SCAN_SECONDS
    stale = db.fetch_val(
        "SELECT COUNT(*) FROM scans WHERE status='RUNNING' AND started_at < ?",
        (cutoff,), default=0) or 0
    if stale:
        db.execute(
            "UPDATE scans SET status='CANCELLED' "
            "WHERE status='RUNNING' AND started_at < ?", (cutoff,))
    return stale


def _next_run_estimate(frequency: str, time_value: str, enabled: bool) -> str | None:
    """Local-time estimate of the daemon's next cron fire, or None.

    The scheduler's hourly job is an interval anchored to daemon start, which
    the dashboard cannot see; returning None is truthful. Daily/weekly/monthly
    are cron jobs, so their next fire is deterministic from the saved time.
    APScheduler defaults to the host's local timezone, so the estimate does too.
    """
    if not enabled or frequency not in _FREQUENCIES or frequency == 'hourly':
        return None
    parts = time_value.split(':') if isinstance(time_value, str) else []
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        return None
    hour, minute = int(parts[0]), int(parts[1])
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        return None

    now = datetime.datetime.now().astimezone().replace(
        second=0, microsecond=0)
    if frequency == 'daily':
        candidate = now.replace(hour=hour, minute=minute)
        if candidate <= now:
            candidate += datetime.timedelta(days=1)
    elif frequency == 'weekly':
        candidate = now.replace(hour=hour, minute=minute)
        candidate += datetime.timedelta(days=(0 - candidate.weekday()) % 7)
        if candidate <= now:
            candidate += datetime.timedelta(days=7)
    else:  # monthly — the scheduler runs on the 1st at HH:MM
        candidate = now.replace(day=1, hour=hour, minute=minute)
        if candidate <= now:
            year = candidate.year + (1 if candidate.month == 12 else 0)
            month = 1 if candidate.month == 12 else candidate.month + 1
            candidate = candidate.replace(year=year, month=month)
    return candidate.isoformat()


def _internal_error(exc: Exception):
    logger.exception(f'[DASHBOARD] Unhandled endpoint error: {exc}')
    return jsonify({'error': 'Internal server error'}), 500


@app.after_request
def add_no_cache(response):
    response.headers['Cache-Control'] = 'no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=()'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    # Scripts are external only; styles keep 'unsafe-inline' for the SPA's
    # attribute-level styling. No CDN origins are allowed.
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; base-uri 'none'; object-src 'none'; "
        "frame-ancestors 'none'; form-action 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self' data:; "
        "img-src 'self' data:; connect-src 'self'"
    )
    if _is_production():
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.route('/')
def index(): return render_template('index.html')

@app.route('/api/v2/stats')
@requires_auth
def api_stats_v2():
    try:
        hosts = db.fetch_val("SELECT COUNT(*) FROM hosts WHERE is_active=1 AND ip IS NOT NULL AND ip != ''")
        # A closed port or an offline host is history, not current exposure.
        ports = db.fetch_val(
            "SELECT COUNT(*) FROM ports p JOIN hosts h ON h.id = p.host_id "
            "WHERE p.state = 'open' AND h.is_active = 1"
        )
        cves = db.fetch_val(f"SELECT COUNT(DISTINCT pc.cve_id) {_LIVE_CVE_SQL}")
        # Attack paths are only live while every hop still exists.
        paths = len(_live_path_rows_sync())
        diffs = db.fetch_all('SELECT diff_type, detail, severity FROM scan_diffs ORDER BY created_at DESC LIMIT 15')
        total_scans = db.fetch_val("SELECT COUNT(*) FROM scans WHERE status='DONE'", default=0)
        is_scanning = db.fetch_val("SELECT COUNT(*) FROM scans WHERE status='RUNNING'", default=0) > 0
        scanner_enabled = db.fetch_val("SELECT value FROM system_settings WHERE key='scanner_enabled'", default='0') == '1'
        scan_phase = db.fetch_val("SELECT value FROM system_settings WHERE key='scan_phase'", default='')
        posture = sync_calculate_global_posture()

        total_hosts = db.fetch_val('SELECT COUNT(*) FROM hosts')
        offline = db.fetch_val('SELECT COUNT(*) FROM hosts WHERE is_active=0', default=0)
        critical_cves = db.fetch_val(
            f"SELECT COUNT(DISTINCT pc.cve_id) {_LIVE_CVE_SQL} "
            "AND c.severity = 'CRITICAL'"
        )
        active_anomalies = db.fetch_val(
            "SELECT COUNT(*) FROM anomalies a JOIN hosts h ON h.id = a.host_id "
            "WHERE a.acknowledged = 0 AND h.is_active = 1"
        )
        shield_blocks = db.fetch_val("SELECT COUNT(*) FROM shield_actions WHERE is_active=1")
        # The top-bar chip is labelled "Alerts", not "Critical CVEs": show the
        # unacknowledged Sentinel queue instead of reusing the CVE total.
        alerts = len(_actionable_unacked_alerts_sync())

        return jsonify({
            'posture': posture, 'hosts': hosts or 0, 'online': hosts or 0, 'offline': offline or 0,
            'ports': ports or 0, 'cves': cves or 0, 'paths': paths or 0,
            'total_scans': total_scans, 'is_scanning': is_scanning, 'scanner_enabled': scanner_enabled,
            'recent_diffs': diffs, 'total_hosts': total_hosts or 0, 'critical_cves': critical_cves or 0,
            'active_anomalies': active_anomalies or 0, 'shield_blocks': shield_blocks or 0,
            'scan_phase': scan_phase or '',
            'alerts': alerts, 'api_version': 'v2', 'timestamp': time.time()
        })
    except Exception as e:
        return _internal_error(e)

@app.route('/api/stats')
@requires_auth
def api_stats(): return api_stats_v2()


@app.route('/api/v2/context')
@requires_auth
def api_context():
    """Small, always-visible operational context for the dashboard banner."""
    try:
        from config import settings as _settings
        target = db.fetch_val(
            "SELECT value FROM system_settings WHERE key='target_network'", default=""
        ) or _settings.scan.target_network
        profile = db.fetch_val(
            "SELECT value FROM system_settings WHERE key='scan_profile'", default="FAST"
        ) or "FAST"
        scanner_enabled = db.fetch_val(
            "SELECT value FROM system_settings WHERE key='scanner_enabled'", default='0'
        ) == '1'
        last_scan = db.fetch_one(
            "SELECT scan_type, started_at, finished_at, status FROM scans "
            "ORDER BY started_at DESC LIMIT 1"
        )
        is_scanning = db.fetch_val(
            "SELECT COUNT(*) FROM scans WHERE status='RUNNING'", default=0
        ) > 0
        unacked = _actionable_unacked_alerts_sync()
        critical = [row for row in unacked if _alert_severity(row) <= 1]
        return jsonify({
            'target': target,
            'profile': profile,
            'scanner_enabled': scanner_enabled,
            'is_scanning': is_scanning,
            'last_scan': last_scan,
            'user': getattr(g, 'user', ''),
            'role': getattr(g, 'role', 'viewer'),
            'shield_dry_run': bool(_settings.shield_cfg.dry_run),
            'shield_auto_quarantine': bool(_settings.shield_cfg.auto_quarantine),
            'unacknowledged_alerts': len(unacked),
            'critical_alerts': len(critical),
            # Monotonic alert id, so acking the newest critical alert cannot
            # hide the arrival of the next one from the audible cue.
            'last_critical_alert_id': max(
                (_row_get(row, 'id', 0) or 0) for row in critical
            ) if critical else 0,
            'active_blocks': db.fetch_val(
                "SELECT COUNT(*) FROM shield_actions WHERE is_active=1", default=0
            ) or 0,
            'server_time': time.time(),
        })
    except Exception as e:
        return _internal_error(e)



@app.route('/api/v2/graph')
@requires_auth
def api_graph_v2():
    try:
        # The cache is written by the daemon after a scan. It can be older than
        # a sweep that just marked hosts offline, so only its entries for hosts
        # that are active right now may reach the topology.
        active_hosts = [
            host for host in (db.fetch_all(
                "SELECT ip, risk_score, os_name, vendor, hostname, device "
                "FROM hosts "
                "WHERE is_active=1 AND ip IS NOT NULL AND ip != '' ORDER BY ip"
            ) or [])
            if isinstance(host.get('ip'), str) and host['ip'].strip()
        ]
        active_ips = [h['ip'] for h in active_hosts]
        if not active_ips:
            return jsonify({'nodes': [], 'links': [], 'blast_radius': []})

        cache_by_ip: dict[str, dict] = {}
        cached = db.fetch_val("SELECT value FROM system_settings WHERE key='graph_cache'")
        if cached:
            try:
                graph = json.loads(cached)
                if isinstance(graph, dict) and isinstance(graph.get('nodes'), list):
                    # Cached nodes are untrusted JSON written by another
                    # process; a junk entry used to 500 the whole graph.
                    for node in graph['nodes']:
                        if (
                            isinstance(node, dict)
                            and isinstance(node.get('id'), str)
                            and node['id'].strip()
                        ):
                            cache_by_ip[node['id']] = node
            except (ValueError, TypeError) as exc:
                logger.warning(f"[DASHBOARD] Ignoring corrupt graph cache: {exc}")

        nodes = []
        for host in active_hosts:
            ip = host['ip']
            # The cache is written by the daemon after a scan and can predate
            # the identity columns. Fresh DB identity must win; cached runtime
            # fields (asset, cve_count, blast metadata) are still useful.
            node = dict(cache_by_ip.get(ip) or {})
            node['id'] = ip
            node['risk'] = (host['risk_score'] if host.get('risk_score') is not None
                            else node.get('risk', 0))
            node['os'] = (host.get('os_name') or host.get('vendor')
                          or node.get('os') or 'Unknown')
            for field in ('hostname', 'vendor', 'device'):
                # The DB is current state. If a rescan cleared the vendor
                # (the MAC changed), keep it cleared instead of reviving the
                # stale cache value. Absent columns (older callers) stay absent.
                if field not in host:
                    continue
                value = host.get(field)
                if isinstance(value, str) and value.strip():
                    node[field] = value.strip()
                elif field in node:
                    node[field] = ''
            nodes.append(node)
        active_set = set(active_ips)

        # Build simplified links: gateway-star + attack-path edges
        links = []
        gw = next((ip for ip in active_ips if ip.endswith('.1')), active_ips[0])

        # Every non-gateway node gets a PHYSICAL link to gateway
        links = [{'source': gw, 'target': ip, 'type': 'PHYSICAL'} for ip in active_ips if ip != gw]

        # Overlay KILL_CHAIN links from live attack paths (additional edges).
        # A path that still mentions an offline host is retired history and
        # must not keep drawing edges through the surviving hops. Reuse the
        # host list already fetched above instead of asking SQLite twice.
        paths = db.fetch_all(
            'SELECT path_json FROM attack_paths WHERE is_active=1 '
            'ORDER BY attacker_roi DESC'
        ) or []
        seen = set()
        for p in paths:
            path_json = _row_get(p, 'path_json')
            if not path_is_live(path_json, active_set):
                continue
            try:
                steps = json.loads(path_json or '')
            except (ValueError, TypeError):
                # One truncated row must not hide the entire graph.
                continue
            if not isinstance(steps, list):
                continue
            for i in range(len(steps)-1):
                if not (isinstance(steps[i], dict) and isinstance(steps[i+1], dict)):
                    continue
                s, d = steps[i].get('ip'), steps[i+1].get('ip')
                if s in active_set and d in active_set and d != gw:
                    key = f'{s}->{d}'
                    if key not in seen:
                        seen.add(key)
                        links.append({'source': s, 'target': d, 'type': 'KILL_CHAIN'})
        
        # Blast Radius: hosts with critical CVEs and their neighbors
        blast_radius = []
        critical = db.fetch_all(
            "SELECT DISTINCT h.ip, h.risk_score, c.cve_id, c.severity "
            "FROM hosts h JOIN ports p ON p.host_id = h.id "
            "JOIN port_cves pc ON pc.port_id = p.id "
            "JOIN cves c ON c.id = pc.cve_id "
            "WHERE h.is_active=1 AND p.state='open' "
            "AND COALESCE(pc.dismissed,0)=0 "
            "AND COALESCE(pc.verified_status,'') != 'NOT_AFFECTED' "
            "AND (h.risk_score > 70 OR c.severity='CRITICAL' "
            "OR (c.cvss_v3 IS NOT NULL AND c.cvss_v3 >= 9.0))"
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
        return _internal_error(e)


@app.route('/api/v2/details/anomalous_ports')
@requires_auth
def api_anomalous_ports():
    try:
        from oracle.attacker_view import get_anomalous_ports
        result = run_async(get_anomalous_ports(), timeout=60)
        return jsonify({'data': result, 'count': len(result)})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/details/hosts')
@requires_auth
def api_details_hosts():
    try:
        hosts = db.fetch_all('SELECT ip, mac, hostname, os_name, vendor, device, risk_score, asset_value, last_seen FROM hosts WHERE is_active=1 ORDER BY risk_score DESC')
        return jsonify({'data': hosts})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/details/ports')
@requires_auth
def api_details_ports():
    try:
        state = (request.args.get('state') or 'open').strip().lower()
        if state not in ('open', 'filtered', 'closed', 'all'):
            return jsonify({'error': 'Invalid port state'}), 400
        sql = ('SELECT h.ip, h.risk_score, p.port, p.protocol, p.service, '
               'p.version, p.state '
               'FROM ports p JOIN hosts h ON h.id = p.host_id '
               'WHERE h.is_active = 1')
        params = ()
        if state != 'all':
            sql += ' AND p.state = ?'
            params = (state,)
        ports = db.fetch_all(sql, params)
        return jsonify({'data': ports})
    except Exception as e:
        return _internal_error(e)


@app.route('/api/v2/details/paths')
@requires_auth
def api_details_paths():
    try:
        # A path is only a prediction about the network that exists now.
        # Retired hosts must not keep supplying "attack paths" to the UI.
        res = [
            {
                'attacker_roi': _row_get(row, 'attacker_roi'),
                'path_json': _row_get(row, 'path_json'),
                'narrative': _row_get(row, 'narrative'),
            }
            for row in _live_path_rows_sync()[:10]
        ]
        return jsonify({'data': res})
    except Exception as e:
        return _internal_error(e)


@app.route('/api/v2/details/host')
@requires_auth
def api_host_detail():
    """Everything known about one host, keyed by IP, for the drill-down drawer."""
    ip = (request.args.get('ip') or '').strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({'error': 'Valid IP address required'}), 400
    try:
        host = db.fetch_one(
            'SELECT id, ip, mac, hostname, os_name, vendor, device, risk_score, '
            'asset_value, first_seen, last_seen FROM hosts '
            'WHERE ip=? AND is_active=1', (ip,)
        )
        if not host:
            return jsonify({'error': 'Host not found'}), 404
        hid = host['id']
        ports = db.fetch_all(
            'SELECT port, protocol, state, service, product, version, extra_info '
            'FROM ports WHERE host_id=? ORDER BY port', (hid,)
        )
        cves = db.fetch_all('''
            SELECT c.cve_id, c.cvss_v3, c.severity, c.description,
                   pc.verified_status, pc.detected_version, pc.exploit_status,
                   p.port, p.service
            FROM port_cves pc
            JOIN cves c ON c.id = pc.cve_id
            JOIN ports p ON p.id = pc.port_id
            WHERE p.host_id=? AND p.state='open'
              AND COALESCE(pc.dismissed, 0) = 0
              AND COALESCE(pc.verified_status, '') != 'NOT_AFFECTED'
            ORDER BY c.cvss_v3 DESC
        ''', (hid,))
        alerts = db.fetch_all(
            'SELECT id, alerted_at, rule_sid, src_ip, dst_ip, dst_port, severity, '
            'message, predicted, acknowledged FROM sentinel_alerts '
            'WHERE src_ip=? OR dst_ip=? ORDER BY alerted_at DESC LIMIT 25',
            (ip, ip)
        )
        blocks = db.fetch_all(
            'SELECT id, taken_at, action_type, target_ip, target_port, rule_applied, '
            'justification, is_active FROM shield_actions '
            'WHERE target_ip=? ORDER BY taken_at DESC LIMIT 25', (ip,)
        )
        return jsonify({
            'host': host, 'ports': ports, 'cves': cves,
            'alerts': alerts, 'blocks': blocks,
        })
    except Exception as e:
        return _internal_error(e)


def _event_ts(value) -> float:
    """Coerce a DB timestamp for sorting; legacy rows may hold junk."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


@app.route('/api/v2/audit/timeline')
@requires_auth
def api_audit_timeline():
    """One chronological feed of scans, detections, blocks and generated rules."""
    limit = request.args.get('limit', 100, type=int) or 100
    limit = max(1, min(limit, 500))
    try:
        events = []
        for r in db.fetch_all(
            'SELECT id, scan_type, target, started_at, finished_at, status, '
            'hosts_found, ports_found, cves_found FROM scans '
            'ORDER BY started_at DESC LIMIT ?', (limit,)
        ):
            events.append({
                'kind': 'SCAN', 'ts': r['started_at'], 'id': r['id'],
                'title': f"Scan {r['scan_type'] or ''}".strip(),
                'detail': str(r['target'] or ''),
                'status': r['status'] or '',
                'host': None,
                'counts': {
                    'hosts': r['hosts_found'], 'ports': r['ports_found'],
                    'cves': r['cves_found'],
                },
            })
        for r in db.fetch_all(
            'SELECT id, taken_at, action_type, target_ip, target_port, rule_applied, '
            'justification, is_active FROM shield_actions '
            'ORDER BY taken_at DESC LIMIT ?', (limit,)
        ):
            events.append({
                'kind': 'SHIELD', 'ts': r['taken_at'], 'id': r['id'],
                'title': str(r['action_type'] or ''),
                'detail': str(r['justification'] or r['rule_applied'] or ''),
                'status': 'ACTIVE' if r['is_active'] else 'REVERTED',
                'host': r['target_ip'],
                'counts': None,
            })
        active = _active_ips_sync()
        live_ids = _live_path_ids_sync()
        for r in db.fetch_all(
            'SELECT id, alerted_at, rule_sid, src_ip, dst_ip, dst_port, severity, '
            'message, predicted, acknowledged, attack_path_id FROM sentinel_alerts '
            'ORDER BY alerted_at DESC LIMIT ?', (limit,)
        ):
            if r['acknowledged']:
                alert_status = 'ACKED'
            elif not alert_is_actionable(r, active, live_ids):
                # History stays visible, but a prediction for a gone path is
                # not an open action item.
                alert_status = 'STALE'
            else:
                alert_status = 'OPEN'
            events.append({
                'kind': 'ALERT', 'ts': r['alerted_at'], 'id': r['id'],
                'title': f"SID {r['rule_sid']}" if r['rule_sid'] else 'Suricata alert',
                'detail': str(r['message'] or ''),
                'status': alert_status,
                'host': r['src_ip'],
                'severity': r['severity'],
                'counts': None,
            })
        for r in db.fetch_all(
            'SELECT id, created_at, rule_sid, rule_category, mitre_technique, '
            'is_deployed, is_active, delivered_at FROM forge_rules '
            'ORDER BY created_at DESC LIMIT ?', (limit,)
        ):
            events.append({
                'kind': 'FORGE', 'ts': r['created_at'], 'id': r['id'],
                'title': str(r['rule_category'] or '') + ' rule',
                'detail': f"SID {r['rule_sid']} · {r['mitre_technique'] or 'unmapped'}",
                # Only a rule that is still active and was in a written
                # ruleset is deployed; a retired path's rule is history.
                'status': ('RETIRED' if not r['is_active']
                           else 'DEPLOYED' if r['delivered_at'] else 'STAGED'),
                'host': None,
                'counts': None,
            })
        events.sort(key=lambda e: _event_ts(e['ts']), reverse=True)
        events = events[:limit]
        return jsonify({'data': events, 'count': len(events)})
    except Exception as e:
        return _internal_error(e)


@app.route('/api/v2/audit/log')
@requires_operator
def api_audit_log():
    """Who changed what, when, and from where.

    Operator-only: the audit trail names accounts, client IPs and the exact
    configuration that was changed, which a read-only viewer has no need for.
    """
    try:
        limit = request.args.get('limit', 200, type=int) or 200
        limit = max(1, min(limit, 500))
        action = (request.args.get('action') or '').strip()[:64]
        actor = (request.args.get('actor') or '').strip()[:128]

        # Static SQL (no interpolation) so a filter value can never alter the
        # statement; an empty filter matches every row.
        rows = db.fetch_all(
            'SELECT id, ts, actor, role, action, target, detail, ip, outcome '
            'FROM audit_log '
            "WHERE (? = '' OR action = ?) AND (? = '' OR actor = ?) "
            'ORDER BY ts DESC, id DESC LIMIT ?',
            (action, action, actor, actor, limit),
        )
        actions = [
            r['action'] for r in db.fetch_all(
                'SELECT DISTINCT action FROM audit_log ORDER BY action'
            )
        ]
        return jsonify({'data': rows, 'count': len(rows), 'actions': actions})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/config/target', methods=['GET', 'POST'])
@requires_operator_write
def api_target():
    try:
        if request.method == 'GET':
            t = db.fetch_val("SELECT value FROM system_settings WHERE key='target_network'", default="")
            p = db.fetch_val("SELECT value FROM system_settings WHERE key='scan_profile'", default="FAST")
            return jsonify({'target': t, 'profile': p})
        data = request.get_json(silent=True) or {}
        target, err = _validated_target(data.get('target'))
        if err:
            return jsonify({'error': err}), 400
        profile = _validated_profile(data.get('profile'))
        if not profile:
            return jsonify({'error': 'Unknown scan profile'}), 400
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('target_network', ?)", (target,))
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('scan_profile', ?)", (profile,))
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('scanner_enabled', '1')")
        logger.info(f"[CONFIG] target={target} profile={profile} by={getattr(g, 'user', '')}")
        _audit('TARGET_UPDATE', target=target, detail=f'profile={profile}')
        return jsonify({'status': 'success', 'target': target, 'profile': profile, 'scanner_enabled': True})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/config/schedule', methods=['GET', 'POST'])
@requires_operator_write
def api_schedule():
    try:
        if request.method == 'GET':
            f = db.fetch_val("SELECT value FROM system_settings WHERE key='schedule_frequency'", default="") or ""
            t = db.fetch_val("SELECT value FROM system_settings WHERE key='schedule_time'", default="02:00") or "02:00"
            e = db.fetch_val("SELECT value FROM system_settings WHERE key='schedule_enabled'", default="0") or "0"
            enabled = e == '1'
            return jsonify({
                'frequency': f,
                'time': t,
                'enabled': enabled,
                'next_run': _next_run_estimate(f, t, enabled),
            })
        data = request.get_json(silent=True) or {}
        frequency = data.get('frequency') or ''
        if frequency and frequency not in _FREQUENCIES:
            return jsonify({'error': 'Invalid schedule frequency'}), 400
        schedule_time = data.get('time', '02:00')
        if not isinstance(schedule_time, str) or not _SCHEDULE_TIME_RE.match(schedule_time):
            return jsonify({'error': 'Schedule time must be HH:MM (local time)'}), 400
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('schedule_frequency', ?)", (frequency,))
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('schedule_time', ?)", (schedule_time,))
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('schedule_enabled', ?)", ('1' if data.get('enabled') else '0',))
        _audit('SCHEDULE_UPDATE', target=frequency or 'disabled',
               detail=f'time={schedule_time} enabled={bool(data.get("enabled"))}')
        return jsonify({'status': 'success'})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/config/targets', methods=['GET', 'POST'])
@requires_operator_write
def api_targets():
    try:
        if request.method == 'GET':
            targets = db.fetch_all('SELECT * FROM saved_targets ORDER BY created_at DESC')
            return jsonify({'targets': targets})
        data = request.get_json(silent=True) or {}
        name = _clean_text(data.get('name'), 64)
        if not name:
            return jsonify({'error': 'Name is required (max 64 chars)'}), 400
        target, err = _validated_target(data.get('target'))
        if err:
            return jsonify({'error': err}), 400
        profile = _validated_profile(data.get('profile'))
        if not profile:
            return jsonify({'error': 'Unknown scan profile'}), 400
        db.execute("INSERT INTO saved_targets (name, target_cidr, scan_profile) VALUES (?, ?, ?)", (name, target, profile))
        _audit('TARGET_SAVE', target=target, detail=f'name={name} profile={profile}')
        return jsonify({'status': 'success'})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/config/targets/<int:tid>/use', methods=['POST'])
@requires_operator
def api_use_target(tid):
    try:
        t = db.fetch_one('SELECT * FROM saved_targets WHERE id=?', (tid,))
        if t:
            target, err = _validated_target(t['target_cidr'])
            profile = _validated_profile(t['scan_profile'])
            if err or not profile:
                return jsonify({'error': 'Saved target is no longer valid'}), 400
            db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('target_network', ?)", (target,))
            db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('scan_profile', ?)", (profile,))
            _audit('TARGET_USE', target=target,
                   detail=f'saved_id={tid} name={t.get("name", "")} profile={profile}')
            return jsonify({'status': 'success'})
        return jsonify({'error': 'not found'}), 404
    except Exception as e:
        return _internal_error(e)


@app.route('/api/v2/shield/actions')
@requires_auth
def api_shield_actions():
    try:
        active = request.args.get('active', '1')
        res = db.fetch_all('SELECT id, taken_at, action_type, target_ip, rule_applied, justification FROM shield_actions WHERE is_active = ? ORDER BY taken_at DESC LIMIT 5', (active,))
        return jsonify({'data': res})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/shield/revert/<int:aid>', methods=['POST'])
@requires_operator
def api_shield_revert(aid):
    try:
        from flask import g

        if not db.fetch_one('SELECT id FROM shield_actions WHERE id=?', (aid,)):
            return jsonify({'error': 'not found'}), 404
        # Actually remove the iptables rule, not just the DB flag. If rollback
        # fails the row stays active on purpose: clearing it would give the
        # operator false assurance that traffic is no longer blocked.
        from shield.reconfigurer import revert_action
        ok = run_async(revert_action(aid, reverted_by=getattr(g, 'user', 'HUMAN')), timeout=30)
        if ok:
            _audit('SHIELD_REVERT', target=f'action:{aid}')
            return jsonify({'status': 'success'})
        _audit('SHIELD_REVERT', target=f'action:{aid}', outcome='failure',
               detail='rollback failed; block remains active')
        return jsonify({'error': 'Shield rollback failed; block remains active'}), 500
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/config/detect-network')
@requires_auth
def api_detect():
    try:
        from config.network_detector import detect_network
        return jsonify(detect_network())
    except Exception as e:
        return _internal_error(e)

def _row_get(row, key, default=None):
    """Read a column from an aiosqlite.Row (sqlite3.Row) or a plain dict.

    CHRONICLE returns sqlite3.Row objects, which support ``row[key]`` but have
    no ``.get``. Calling ``.get`` 500'd every non-empty CSV/PDF export.
    """
    try:
        value = row[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if value is None else value


def _csv_safe(value):
    """Neutralise spreadsheet formula injection (=, +, -, @ and control prefixes)."""
    if value is None:
        return ''
    text = str(value)
    if text and text[0] in ('=', '+', '-', '@', '\t', '\r', '\n'):
        return "'" + text
    return text


@app.route('/api/v2/export/<format_type>', methods=['GET'])
@requires_auth
def api_export_data(format_type):
    try:
        if format_type != 'csv':
            return jsonify({'error': 'unsupported format'}), 404
        data_type = request.args.get('type', 'hosts')
        if data_type == 'hosts':
            data = db.fetch_all('SELECT ip, mac, hostname, os_name, vendor, device, risk_score, asset_value FROM hosts WHERE is_active=1')
            headers = ['ip', 'mac', 'hostname', 'os_name', 'vendor', 'device', 'risk_score', 'asset_value']
        elif data_type == 'cves':
            # Match what the CVE page shows: dismissed false positives and
            # retired hosts must not reappear in the export.
            data = db.fetch_all(
                'SELECT h.ip, c.cve_id, c.cvss_v3, c.severity FROM cves c '
                'JOIN port_cves pc ON pc.cve_id = c.id '
                'JOIN ports p ON p.id = pc.port_id '
                'JOIN hosts h ON h.id = p.host_id '
                "WHERE COALESCE(pc.dismissed, 0) = 0 "
                "AND h.is_active = 1 AND p.state = 'open' "
                "AND COALESCE(pc.verified_status, '') != 'NOT_AFFECTED'"
            )
            headers = ['ip', 'cve_id', 'cvss_v3', 'severity']
        else:
            return jsonify({'error': 'invalid type'}), 400

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=headers)
        writer.writeheader()
        for row in data:
            writer.writerow({k: _csv_safe(_row_get(row, k)) for k in headers})
        return Response(output.getvalue(), mimetype='text/csv',
                        headers={'Content-Disposition': f'attachment; filename={data_type}.csv'})
    except Exception as e:
        return _internal_error(e)


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
            WHERE COALESCE(pc.dismissed, 0) = 0
              AND h.is_active = 1
              AND p.state = 'open'
              AND COALESCE(pc.verified_status, '') != 'NOT_AFFECTED'
            ORDER BY c.cvss_v3 DESC
        ''')
        return jsonify({'data': res})
    except Exception as e:
        logger.error(f'CVE API failed: {e}')
        return _internal_error(e)

@app.route('/api/v2/cves/dismiss/<int:port_id>/<int:cve_id>', methods=['POST'])
@requires_operator
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
        _audit('CVE_DISMISS', target=f'{cve_id}@{port_id}',
               detail=f'dismissed={bool(new_val)}')
        return jsonify({'status': 'success', 'dismissed': bool(new_val)})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/cves/reverify', methods=['POST'])
@requires_operator
def api_reverify_cves():
    try:
        from iris.cve_mapper import verify_all_cves
        result = run_async(verify_all_cves(), timeout=120)
        _audit('CVE_REVERIFY', detail=f'updated={result}')
        return jsonify({'status': 'success', 'updated': result})
    except Exception as e:
        return _internal_error(e)

def _retention_days_or_default(raw) -> int:
    """Coerce a stored retention value to a usable number of days.

    `fetch_val(..., default=30)` only covers a missing row; a legacy/manual row
    can hold NULL or junk, which used to raise TypeError/ValueError out of GET.
    """
    try:
        days = int(raw)
    except (TypeError, ValueError):
        return 30
    return days if 1 <= days <= 3650 else 30


@app.route('/api/v2/system/retention', methods=['GET', 'POST'])
@requires_operator_write
def api_retention():
    """Get or set data retention days. Persisted in system_settings."""
    try:
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            days = _validated_days(data.get('days'))
            if days is None:
                return jsonify({'error': 'Retention must be 1-3650 days'}), 400
            db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('retention_days', ?)", (str(days),))
            _audit('RETENTION_UPDATE', target=f'{days}d')
            return jsonify({'status': 'success', 'days': days})
        current = db.fetch_val("SELECT value FROM system_settings WHERE key='retention_days'", default="30")
        return jsonify({'days': _retention_days_or_default(current)})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/system/prune', methods=['POST'])
@requires_operator
def api_prune():
    """Delete scans and associated data older than N days. Saves days as new retention."""
    try:
        data = request.get_json(silent=True) or {}
        days = _validated_days(data.get('days'))
        if days is None:
            return jsonify({'error': 'Retention must be 1-3650 days'}), 400
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('retention_days', ?)", (str(days),))
        cutoff = time.time() - (days * 86400)
        # Cancelled/failed scans never get finished_at, so ageing on that column
        # alone retained them forever. Fall back to started_at for any scan that
        # never completed (including a crashed RUNNING row, which otherwise keeps
        # `is_scanning` true and blocks new triggers indefinitely).
        old_scan_eq = 'COALESCE(finished_at, started_at) < ?'
        old_scans = db.fetch_val(
            f'SELECT COUNT(*) FROM scans WHERE {old_scan_eq}', (cutoff,), default=0)  # nosec B608 - static fragment
        db.execute(
            f'DELETE FROM scan_diffs WHERE scan_id IN '
            f'(SELECT id FROM scans WHERE {old_scan_eq})', (cutoff,))  # nosec B608 - static fragment
        db.execute(f'DELETE FROM scans WHERE {old_scan_eq}', (cutoff,))  # nosec B608 - static fragment
        db.execute('DELETE FROM behavioral_events WHERE ts < ?', (cutoff,))
        db.execute('DELETE FROM anomalies WHERE acknowledged = 1 AND detected_at < ?', (cutoff,))
        logger.info(f"[RETENTION] Pruned {old_scans} scans older than {days}d by={getattr(g, 'user', '')}")
        _audit('DATA_PRUNE', detail=f'deleted_scans={old_scans} cutoff_days={days}')
        return jsonify({'status': 'success', 'deleted_scans': old_scans, 'cutoff_days': days})
    except Exception as e:
        return _internal_error(e)


@app.route('/api/actions/toggle_scanner', methods=['POST'])
@app.route('/api/v2/actions/toggle_scanner', methods=['POST'])
@requires_operator
def api_toggle_scanner():
    try:
        data = request.get_json(silent=True) or {}
        current = db.fetch_val("SELECT value FROM system_settings WHERE key='scanner_enabled'", default='0')
        new_val = data.get('enabled')
        if new_val is None:
            new_val = '0' if current == '1' else '1'
        else:
            new_val = '1' if new_val else '0'

        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('scanner_enabled', ?)", (new_val,))
        _audit('SCANNER_TOGGLE', detail=f'enabled={new_val == "1"}')
        return jsonify({'status': 'success', 'enabled': new_val == '1'})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/actions/scan', methods=['POST'])
@app.route('/api/v2/actions/scan', methods=['POST'])
@requires_operator
def trigger_scan():
    try:
        # A row left RUNNING by a crashed process must not lock scanning out
        # forever; expire it before deciding whether a live sweep is running.
        _reap_stale_running_scans()
        # Cancelling the in-flight row here used to let two nmap sweeps run at
        # once and mislabel the first one. Tell the operator the truth instead;
        # the daemon consumes one trigger as soon as the current cycle ends.
        running = db.fetch_val(
            "SELECT COUNT(*) FROM scans WHERE status='RUNNING'", default=0) or 0
        if running:
            return jsonify({
                'status': 'running',
                'error': 'A scan is already running',
            }), 409
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('manual_trigger', '1')")
        socketio.emit('scan_progress', {'status': 'running', 'message': 'Scan trigger sent to daemon...'}, to='authenticated')
        logger.info(f"[SCAN] Manual scan triggered by={getattr(g, 'user', '')}")
        _audit('SCAN_TRIGGER')
        return jsonify({'status': 'success', 'message': 'Scan triggered'})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/actions/cancel_scan', methods=['POST'])
@app.route('/api/v2/actions/cancel_scan', methods=['POST'])
@requires_operator
def cancel_scan():
    try:
        db.execute("UPDATE scans SET status='CANCELLED' WHERE status='RUNNING'")
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('scanner_enabled', '0')")
        socketio.emit('scan_progress', {'status': 'complete', 'message': 'Scan cancelled'}, to='authenticated')
        logger.info(f"[SCAN] Scan cancelled by={getattr(g, 'user', '')}")
        _audit('SCAN_CANCEL')
        return jsonify({
            'status': 'success',
            'message': 'Scanner paused; the running sweep is marked cancelled and its results will be discarded',
        })
    except Exception as e:
        return _internal_error(e)


_net_prev: dict[str, dict] = {}
_net_prev_time: float = 0
_net_lock = threading.Lock()
_lat_cache: dict[str, float] = {'val': 0, 'at': 0}
_lat_lock = threading.Lock()

def _capture_iface() -> str:
    """The interface OBSIDIOS actually watches (configurable, not always eth0)."""
    return os.environ.get("OBSIDIOS_CAPTURE_IFACE") or "eth0"


def _parse_net_dev(path: str = '/proc/net/dev') -> dict:
    stats = {}
    try:
        with open(path) as f:
            lines = f.readlines()[2:]
    except OSError:
        return stats
    for line in lines:
        parts = line.strip().split()
        # A malformed line must not blank the whole network panel.
        if len(parts) < 11:
            continue
        iface = parts[0].rstrip(':')
        try:
            stats[iface] = {
                'rx_bytes': int(parts[1]), 'rx_packets': int(parts[2]),
                'tx_bytes': int(parts[9]), 'tx_packets': int(parts[10]),
            }
        except ValueError:
            continue
    return stats

def _get_latency():
    now = time.time()
    with _lat_lock:
        if now - _lat_cache.get('at', 0) < 30:
            return _lat_cache.get('val', 0)
    gw = os.environ.get('OBSIDIOS_GATEWAY', '192.168.1.1')
    ms = 0.0
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.25)
        t0 = time.time()
        s.connect((gw, 80))
        ms = (time.time() - t0) * 1000
    except Exception:
        ms = 0.0
    finally:
        if s is not None:
            try: s.close()
            except Exception: pass
    with _lat_lock:
        _lat_cache.update({'val': round(ms, 1), 'at': now})
    return round(ms, 1)

@app.route('/api/network/stats')
@requires_auth
def api_network_stats():
    global _net_prev, _net_prev_time
    try:
        iface = _capture_iface()
        stats = _parse_net_dev()
        current = stats.get(iface, {})
        with _net_lock:
            now = time.time()
            # A minimum interval keeps two rapid polls from dividing by ~0 and
            # reporting an absurd spike.
            dt = max(now - _net_prev_time, 0.5) if _net_prev_time else 1.0
            # Only compare against a previous sample of the SAME interface.
            prev = _net_prev.get(iface, {})

            if prev:
                rx_b = max(0, current.get('rx_bytes', 0) - prev.get('rx_bytes', 0))
                tx_b = max(0, current.get('tx_bytes', 0) - prev.get('tx_bytes', 0))
                rx_p = max(0, current.get('rx_packets', 0) - prev.get('rx_packets', 0))
                tx_p = max(0, current.get('tx_packets', 0) - prev.get('tx_packets', 0))
            else:
                rx_b = tx_b = rx_p = tx_p = 0

            _net_prev[iface] = current
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
        return _internal_error(e)


@app.route('/api/v2/alerts/config', methods=['GET', 'POST'])
@requires_operator_write
def api_alert_config():
    try:
        if request.method == 'GET':
            c = db.fetch_val("SELECT value FROM system_settings WHERE key='alert_critical_discord'", default="1")
            h = db.fetch_val("SELECT value FROM system_settings WHERE key='alert_high_dashboard'", default="1")
            return jsonify({'critical_to_discord': c == '1', 'high_to_dashboard': h == '1'})
        data = request.get_json(silent=True) or {}
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('alert_critical_discord', ?)", ('1' if data.get('critical_to_discord') else '0',))
        db.execute("INSERT OR REPLACE INTO system_settings (key, value) VALUES ('alert_high_dashboard', ?)", ('1' if data.get('high_to_dashboard') else '0',))
        _audit('ALERT_CONFIG',
               detail=f'critical_to_discord={bool(data.get("critical_to_discord"))} '
                      f'high_to_dashboard={bool(data.get("high_to_dashboard"))}')
        return jsonify({'status': 'success'})
    except Exception as e:
        return _internal_error(e)






def _delivery_payload(delivery=None) -> dict | None:
    """Serialize a RuleDelivery or the most recent recorded attempt."""
    if delivery is not None:
        payload = delivery.as_dict()
        payload['state'] = delivery.state
        return payload
    row = db.fetch_one(
        'SELECT attempted_at, ok, rule_count, path, error, reload_ok, reload_output '
        'FROM forge_delivery ORDER BY id DESC LIMIT 1'
    )
    if not row:
        return None
    reload_ok = row['reload_ok']
    if not row['ok']:
        state = 'FAILED'
    elif not row['rule_count']:
        state = 'EMPTY'
    elif reload_ok is None:
        state = 'WRITTEN'
    else:
        state = 'DEPLOYED' if reload_ok else 'WRITTEN_NO_RELOAD'
    return {
        'ok': bool(row['ok']),
        'rule_count': row['rule_count'] or 0,
        'path': row['path'],
        'error': row['error'],
        'written_at': row['attempted_at'],
        'reload_ok': None if reload_ok is None else bool(reload_ok),
        'reload_output': row['reload_output'],
        'quarantined': [],
        'state': state,
    }


@app.route('/api/v2/forge/rules')
@requires_auth
def api_forge_rules():
    try:
        rules = db.fetch_all('SELECT id, rule_sid, rule_text, rule_category, mitre_technique, is_deployed, is_active, delivered_at, true_positives, false_positives, created_at FROM forge_rules ORDER BY created_at DESC LIMIT 50')
        return jsonify({'data': rules, 'count': len(rules),
                        'delivery': _delivery_payload()})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/forge/deploy/<int:rid>', methods=['POST'])
@requires_operator
def api_forge_deploy(rid):
    """Include or exclude one rule, then rewrite the live ruleset.

    Flipping a flag is not deployment: the file Suricata reads has to change
    for the change to mean anything.
    """
    try:
        from forge.rule_generator import write_rules_file
        rule = db.fetch_one(
            'SELECT is_active, operator_excluded FROM forge_rules WHERE id=?',
            (rid,),
        )
        if not rule: return jsonify({'error': 'Rule not found'}), 404
        # Keep the operator's original intent so a failed write restores it
        # exactly. Deriving it from the toggle direction used to turn a merely
        # inactive rule into an explicitly excluded one (and vice versa).
        old_active = 1 if rule.get('is_active') else 0
        old_excluded = 1 if rule.get('operator_excluded') else 0
        new_val = 0 if old_active else 1
        # An explicit exclusion must survive regeneration, so record intent.
        db.execute(
            'UPDATE forge_rules SET is_active=?, operator_excluded=? WHERE id=?',
            (new_val, 0 if new_val else 1, rid),
        )
        try:
            delivery = run_async(write_rules_file(), timeout=60)
        except Exception:
            db.execute(
                'UPDATE forge_rules SET is_active=?, operator_excluded=? WHERE id=?',
                (old_active, old_excluded, rid),
            )
            raise
        payload = _delivery_payload(delivery)
        if not delivery.ok:
            # Keep the DB consistent with the ruleset that is still live.
            db.execute(
                'UPDATE forge_rules SET is_active=?, operator_excluded=? WHERE id=?',
                (old_active, old_excluded, rid),
            )
            _audit('FORGE_RULE_EDIT', target=f'rule:{rid}',
                   outcome='failure', detail=delivery.error)
            return jsonify({'status': 'error', 'is_active': bool(1 - new_val),
                            'delivery': payload}), 500
        _audit('FORGE_RULE_EDIT', target=f'rule:{rid}',
               detail=('included' if new_val else 'excluded') +
                      f' state={delivery.state} rules={delivery.rule_count}')
        return jsonify({'status': 'success', 'is_active': bool(new_val),
                        'delivery': payload})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/forge/rewrite', methods=['POST'])
@requires_operator
def api_forge_rewrite():
    """Re-render the active ruleset and ask the sensor to reload it."""
    try:
        from forge.rule_generator import write_rules_file
        delivery = run_async(write_rules_file(), timeout=60)
        payload = _delivery_payload(delivery)
        _audit('FORGE_REWRITE',
               detail=f'state={delivery.state} rules={delivery.rule_count}'
                      + (f' error={delivery.error}' if delivery.error else ''),
               outcome='success' if delivery.ok else 'failure')
        return jsonify({'status': 'success' if delivery.ok else 'error',
                        'delivery': payload}), (200 if delivery.ok else 500)
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/forge/feedback', methods=['POST'])
@requires_operator
def api_forge_feedback():
    """Record TP/FP verdict -> bump counters, store feedback, return suggestion."""
    try:
        data = request.get_json(silent=True) or {}
        rule_id = data.get('rule_id') or data.get('forge_rule_id') or data.get('id')
        verdict = data.get('verdict', '')
        if not rule_id:
            return jsonify({'error': 'rule_id required'}), 400
        if verdict not in ('tp', 'fp'):
            return jsonify({'error': 'verdict must be tp or fp'}), 400
        auto_apply = bool(data.get('auto_apply', False))
        from antibody.service import record_feedback
        result = run_async(record_feedback(
            forge_rule_id=int(rule_id),
            verdict=str(verdict),
            note=str(data.get('note', '') or '')[:1000],
            sentinel_alert_id=data.get('sentinel_alert_id'),
            attack_path_id=data.get('attack_path_id'),
            auto_apply=auto_apply,
        ), timeout=30)
        _audit('FORGE_FEEDBACK', target=f'rule:{rule_id}',
               detail=f'verdict={verdict} auto_apply={auto_apply}')
        return jsonify(result)
    except (TypeError, ValueError) as e:
        return jsonify({'error': str(e)}), 400
    except LookupError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/forge/suggestions')
@requires_auth
def api_forge_suggestions():
    """List auto-tune suggestions for noisy/reliable rules."""
    try:
        from antibody.service import list_suggestions
        suggestions = run_async(list_suggestions(), timeout=30)
        return jsonify({'data': suggestions, 'count': len(suggestions)})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/cves/exploit_status')
@requires_auth
def api_cve_exploit_status():
    try:
        # Metadata only (no UI path), but it must agree with every other
        # finding view: dismissed false positives and NOT_AFFECTED verdicts
        # are not live exploitable exposure.
        data = db.fetch_all(
            'SELECT h.ip, c.cve_id, c.cvss_v3, c.severity, pc.exploit_status, '
            'pc.msf_module FROM port_cves pc '
            'JOIN cves c ON c.id = pc.cve_id '
            'JOIN ports p ON p.id = pc.port_id '
            'JOIN hosts h ON h.id = p.host_id '
            "WHERE pc.exploit_status != ? "
            'AND COALESCE(pc.dismissed,0) = 0 '
            "AND COALESCE(pc.verified_status,'') != 'NOT_AFFECTED' "
            "AND h.is_active = 1 AND p.state = 'open' "
            'ORDER BY c.cvss_v3 DESC', ('THEORETICAL',))
        return jsonify({'data': data, 'count': len(data)})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/offensive/attack_vectors')
@requires_auth
def api_attack_vectors():
    try:
        from oracle.attacker_view import generate_attacker_view
        result = run_async(generate_attacker_view(), timeout=120)
        return jsonify(result)
    except Exception as e:
        return _internal_error(e)



@app.route('/api/v2/export/pdf', methods=['GET', 'POST'])
@requires_auth
def api_export_pdf():
    try:
        from weasyprint import HTML
        # Gather data
        hosts = db.fetch_all('SELECT ip, mac, hostname, os_name, risk_score, asset_value FROM hosts WHERE is_active=1 ORDER BY risk_score DESC')
        # The report must agree with the dashboard: dismissed findings,
        # NOT_AFFECTED verdicts and retired hosts are not "open" exposure.
        cves = db.fetch_all(
            "SELECT h.ip, c.cve_id, c.cvss_v3, c.severity, c.description "
            "FROM cves c "
            "JOIN port_cves pc ON pc.cve_id = c.id "
            "JOIN ports p ON p.id = pc.port_id "
            "JOIN hosts h ON h.id = p.host_id "
            "WHERE h.is_active = 1 AND p.state = 'open' "
            "AND COALESCE(pc.dismissed, 0) = 0 "
            "AND COALESCE(pc.verified_status, '') != 'NOT_AFFECTED' "
            "ORDER BY c.cvss_v3 DESC LIMIT 50"
        )
        summary = db.fetch_all(
            "SELECT c.severity, COUNT(DISTINCT pc.cve_id) as cnt FROM cves c "
            "JOIN port_cves pc ON pc.cve_id = c.id "
            "JOIN ports p ON p.id = pc.port_id "
            "JOIN hosts h ON h.id = p.host_id "
            "WHERE h.is_active = 1 AND p.state = 'open' "
            "AND COALESCE(pc.dismissed, 0) = 0 "
            "AND COALESCE(pc.verified_status, '') != 'NOT_AFFECTED' "
            "GROUP BY c.severity"
        )
        total_hosts = db.fetch_val('SELECT COUNT(*) FROM hosts WHERE is_active=1', default=0)
        total_cves = db.fetch_val(
            "SELECT COUNT(DISTINCT pc.cve_id) FROM cves c "
            "JOIN port_cves pc ON pc.cve_id = c.id "
            "JOIN ports p ON p.id = pc.port_id "
            "JOIN hosts h ON h.id = p.host_id "
            "WHERE h.is_active = 1 AND p.state = 'open' "
            "AND COALESCE(pc.dismissed, 0) = 0 "
            "AND COALESCE(pc.verified_status, '') != 'NOT_AFFECTED'",
            default=0,
        )
        total_paths = len(_live_path_rows_sync())
        
        sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0,
                      'INFO': 0}
        for r in summary:
            # Severity is nullable and legacy rows (or INFO/NONE findings) are
            # valid. Indexing the dict directly 500'd the whole export on the
            # first row outside the four headline buckets.
            severity = str(_row_get(r, 'severity') or '').strip().upper()
            if severity in sev_counts:
                # COUNT(*) should be an integer, but legacy/migrated rows are
                # not trustworthy enough to crash the whole report over.
                try:
                    sev_counts[severity] += int(_row_get(r, 'cnt') or 0)
                except (TypeError, ValueError):
                    logger.warning(
                        f"[DASHBOARD] Ignoring unreadable {severity} count: "
                        f"{_row_get(r, 'cnt')!r}"
                    )
        
        cves_rows = ""
        for r in cves:
            sev = html.escape(str(r['severity'] or ''))
            sev_color = "#f16479" if r['severity'] == 'CRITICAL' else "#f59e0b" if r['severity'] == 'HIGH' else "#5b8dee" if r['severity'] == 'MEDIUM' else "#8492a8"
            cves_rows += (
                f"<tr><td>{html.escape(str(r['ip'] or ''))}</td>"
                f"<td>{html.escape(str(r['cve_id'] or ''))}</td>"
                f"<td style='color:{sev_color}'>{sev}</td>"
                f"<td>{html.escape(str(r['cvss_v3'] if r['cvss_v3'] is not None else 'N/A'))}</td>"
                f"<td style='font-size:9px;max-width:250px'>{html.escape(str(r['description'] or ''))}</td></tr>\n"
            )

        hosts_rows = "".join(
            f"<tr><td>{html.escape(str(h['ip'] or ''))}</td>"
            f"<td>{html.escape(str(h['mac'] or '-'))}</td>"
            f"<td>{html.escape(str(h['hostname'] or '-'))}</td>"
            f"<td>{html.escape(str(h['os_name'] or 'Unknown'))}</td>"
            f"<td>{html.escape(str(h['risk_score'] or 0))}</td></tr>\n"
            for h in hosts
        )
        
        critical_pct = round(sev_counts['CRITICAL'] / max(total_cves, 1) * 100, 1)
        high_pct = round(sev_counts['HIGH'] / max(total_cves, 1) * 100, 1)
        
        html_doc = f"""<!DOCTYPE html>
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
<p style="font-size:11px;color:#555">Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} | Target: {html.escape(str(db.fetch_val('SELECT value FROM system_settings WHERE key=\'target_network\'', default='N/A')))}</p>

<div class="summary-grid">
  <div class="summary-card card-red"><h3>{sev_counts['CRITICAL']}</h3><p>Critical CVEs</p></div>
  <div class="summary-card card-orange"><h3>{sev_counts['HIGH']}</h3><p>High CVEs</p></div>
  <div class="summary-card card-blue"><h3>{total_hosts}</h3><p>Active Hosts</p></div>
  <div class="summary-card card-green"><h3>{total_paths}</h3><p>Attack Paths</p></div>
</div>

<h2>Executive Summary</h2>
<p>This report covers {total_hosts} active hosts with {total_cves} distinct CVEs ({sev_counts['CRITICAL']} critical, {sev_counts['HIGH']} high, {sev_counts['MEDIUM']} medium, {sev_counts['LOW']} low, {sev_counts['INFO']} informational). {total_paths} adversarial attack paths are currently active.</p>
<p><strong>Risk Profile:</strong> {critical_pct}% of CVEs are critical severity, {high_pct}% are high severity. Prioritize remediation of critical CVEs affecting active hosts.</p>

<h2>Host Inventory</h2>
<table><thead><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>OS</th><th>Risk</th></tr></thead><tbody>{hosts_rows}</tbody></table>

<h2>Vulnerability Details (Top 50 findings by CVSS)</h2>
<table><thead><tr><th>Host</th><th>CVE</th><th>Severity</th><th>CVSS</th><th>Description</th></tr></thead><tbody>{cves_rows}</tbody></table>

<h2>Methodology</h2>
<p>Scanning was performed using Nmap with ARP discovery, service fingerprinting, and OS detection. CVEs were mapped via NVD API. Attack paths were simulated using Dijkstra-based traversal of MITRE ATT&CK techniques. All data is stored in OBSIDIOS' tactical database.</p>

<div class="footer">
<p>OBSIDIOS Autonomous Security Platform — This report is auto-generated.</p>
</div>
</body></html>"""
        pdf = HTML(string=html_doc).write_pdf()
        # Exporting the vulnerability report is a disclosure event worth
        # recording, even though it changes no state.
        _audit('EXPORT_REPORT',
               detail=f'hosts={total_hosts} cves={total_cves} bytes={len(pdf)}')
        return Response(pdf, mimetype='application/pdf', headers={'Content-Disposition': 'attachment; filename=obsidios_report.pdf'})
    except Exception as e:
        return _internal_error(e)


@app.route('/api/v2/iris/scan_wireless', methods=['POST'])
@requires_operator
def api_scan_wireless():
    try:
        from iris.wired_scanner import run_wireless_scan
        run_async(run_wireless_scan(), timeout=30)
        _audit('WIRELESS_SCAN')
        return jsonify({'status': 'success', 'message': 'Wireless scan triggered'})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/iris/osint')
@requires_auth
def api_osint():
    try:
        findings = db.fetch_all('SELECT * FROM osint_findings ORDER BY discovered_at DESC LIMIT 20')
        return jsonify({'data': findings})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/iris/wireless')
@requires_auth
def api_wireless():
    try:
        threats = db.fetch_all('SELECT * FROM wireless_threats WHERE is_active=1 ORDER BY detected_at DESC')
        return jsonify({'data': threats})
    except Exception as e:
        return _internal_error(e)

@app.route('/api/v2/sentinel/alerts')
@requires_auth
def api_sentinel_alerts():
    try:
        alerts = [dict(row) for row in (db.fetch_all('''
            SELECT sa.id, sa.alerted_at, sa.rule_sid, sa.src_ip, sa.dst_ip,
                   sa.dst_port, sa.protocol, sa.severity, sa.message,
                   sa.predicted, sa.acknowledged, sa.attack_path_id,
                   fr.rule_category
            FROM sentinel_alerts sa
            LEFT JOIN forge_rules fr ON fr.rule_sid = sa.rule_sid
            ORDER BY sa.alerted_at DESC LIMIT 50
        ''') or [])]
        # Mark predictions that no longer point at a live path/host. The
        # Sentinel page keeps the history, but the action queue and KPI must
        # not ask the operator to investigate a machine that is gone.
        active = _active_ips_sync()
        live_ids = _live_path_ids_sync()
        for alert in alerts:
            alert['src_active'] = alert.get('src_ip') in active
            alert['dst_active'] = alert.get('dst_ip') in active
            alert['actionable'] = alert_is_actionable(alert, active, live_ids)
        return jsonify({'data': alerts, 'count': len(alerts)})
    except Exception as e:
        return _internal_error(e)


@app.route('/api/v2/sentinel/alerts/ack_all', methods=['POST'])
@requires_operator
def api_sentinel_ack_all():
    try:
        pending = db.fetch_val(
            'SELECT COUNT(*) FROM sentinel_alerts WHERE acknowledged=0', default=0
        )
        db.execute(
            'UPDATE sentinel_alerts SET acknowledged=1 WHERE acknowledged=0'
        )
        logger.info(f"[SENTINEL] All alerts acknowledged by={getattr(g, 'user', '')}")
        _audit('SENTINEL_ACK_ALL', detail=f'acknowledged={pending}')
        return jsonify({'status': 'success', 'acknowledged': pending})
    except Exception as e:
        return _internal_error(e)


@app.route('/api/v2/sentinel/alerts/<int:aid>/ack', methods=['POST'])
@requires_operator
def api_sentinel_ack(aid):
    try:
        if not db.fetch_one('SELECT id FROM sentinel_alerts WHERE id=?', (aid,)):
            return jsonify({'error': 'not found'}), 404
        db.execute('UPDATE sentinel_alerts SET acknowledged=1 WHERE id=?', (aid,))
        logger.info(f"[SENTINEL] Alert {aid} acknowledged by={getattr(g, 'user', '')}")
        _audit('SENTINEL_ACK', target=f'alert:{aid}')
        return jsonify({'status': 'success'})
    except Exception as e:
        return _internal_error(e)





@app.route('/api/v2/oracle/compliance')
@requires_auth
def api_compliance():
    try:
        from oracle.compliance_mapper import map_compliance
        framework = request.args.get('framework', 'PCI-DSS')
        res = run_async(map_compliance(framework))
        return jsonify(res)
    except Exception as e:
        return _internal_error(e)

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
                logger.warning('[DASHBOARD] AI brief DB locked, retrying...')
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
    except Exception as e:
        return _internal_error(e)


def run_dashboard(host=None, port=None):
    from config import settings as _settings

    # Resolve the documented bind variables when no explicit address was given
    # (``python -m dashboard.app`` and programmatic callers).
    host = host or _settings.dash.host
    port = int(port or _settings.dash.port)
    # Eagerly initialise chronicle.db (not db_sync) so first read doesn't trigger DDL
    try:
        from chronicle import db as chronicle_db
        run_async(chronicle_db.init(), timeout=30)
    except Exception as e:
        logger.warning(f'[DASHBOARD] DB init on startup: {e} — will retry on first request')

    if _is_production():
        # Socket.IO threading mode works under gthread workers; keep a single
        # worker so long-polling sessions stay sticky without a message queue.
        import gunicorn.app.base

        class _DashboardApp(gunicorn.app.base.BaseApplication):
            def load_config(self):
                options = {
                    'bind': f'{host}:{port}',
                    'worker_class': 'gthread',
                    'workers': 1,
                    'threads': 8,
                    'timeout': 120,
                    'graceful_timeout': 30,
                    'accesslog': '-',
                    'errorlog': '-',
                }
                for key, value in options.items():
                    self.cfg.set(key, value)

            def load(self):
                return app

        logger.info(f'Starting Gunicorn (gthread) on {host}:{port}')
        _DashboardApp().run()
        return

    logger.warning('[DASHBOARD] Development server — set OBSIDIOS_ENV=production for Gunicorn')
    socketio.run(app, host=host, port=port, allow_unsafe_werkzeug=True, use_reloader=False)


if __name__ == '__main__': run_dashboard()
