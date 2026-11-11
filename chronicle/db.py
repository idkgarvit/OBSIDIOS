import asyncio
import atexit
import threading
from collections.abc import AsyncGenerator, Iterable, Sequence
from contextlib import asynccontextmanager
from typing import Any

import aiosqlite
from loguru import logger

from chronicle.schema import SCHEMA_SQL
from config import settings


class _CrossLoopLock:
    """Async mutex that is safe to await from more than one event loop.

    `asyncio.Lock` is bound to the loop of whoever waits first. If that loop
    releases while a waiter is parked on another loop, the waiter's future is
    resolved without waking its loop (`Future.set_result` is not thread-safe),
    so the waiter sleeps until something else happens to wake it — forever in
    a quiet process. `db.close()` on a CLI loop while the dashboard's
    background loop runs `init()` is exactly that case.

    Only `init()`/`close()` use this lock, so a short poll is cheaper than
    moving the critical section onto a worker thread.
    """

    _POLL_SECONDS = 0.01

    def __init__(self) -> None:
        self._lock = threading.Lock()

    def locked(self) -> bool:
        return self._lock.locked()

    async def __aenter__(self) -> "_CrossLoopLock":
        while not self._lock.acquire(blocking=False):
            await asyncio.sleep(self._POLL_SECONDS)
        return self

    async def __aexit__(self, *_exc: object) -> None:
        self._lock.release()


_read_pool: list[aiosqlite.Connection] = []
_write_conn: aiosqlite.Connection | None = None
_initialized: bool = False
_init_lock = _CrossLoopLock()
_write_lock = asyncio.Lock()

_rotator = 0
_READ_POOL_SIZE = 8


def _worker_alive(conn: aiosqlite.Connection | None) -> bool:
    """Return True only if this connection can still run a query.

    An aiosqlite worker exits when it cannot hand a result back to the loop
    that issued the query (that loop was closed or cancelled). The proxy keeps
    `_running == True` and its queue still accepts work, so a liveness check
    has to look at the thread itself; queueing to a dead worker hangs forever.
    """
    if conn is None:
        return False
    thread = getattr(conn, "_thread", None)
    return bool(
        getattr(conn, "_running", False)
        and thread is not None
        and thread.is_alive()
    )


def _pool_healthy() -> bool:
    return (
        _initialized
        and _worker_alive(_write_conn)
        and len(_read_pool) == _READ_POOL_SIZE
        and all(_worker_alive(conn) for conn in _read_pool)
    )


def _discard_conn(conn: aiosqlite.Connection | None) -> None:
    """Drop a connection whose worker is gone, without awaiting a dead thread."""
    if conn is None:
        return
    sql_conn = getattr(conn, "_connection", None)
    conn._connection = None
    conn._running = False
    if sql_conn is not None:
        try:
            sql_conn.close()
        except Exception as exc:  # noqa: BLE001 - disposal must never raise
            logger.debug(f"[CHRONICLE] Discarding dead connection: {exc}")
    try:
        conn.stop()
    except Exception:  # noqa: BLE001 - no loop to publish the stop future
        pass


async def _dispose_conn(conn: aiosqlite.Connection | None) -> None:
    if conn is None:
        return
    if not _worker_alive(conn):
        _discard_conn(conn)
        return
    try:
        await asyncio.wait_for(conn.close(), timeout=5.0)
    except asyncio.CancelledError:
        _discard_conn(conn)
        raise
    except Exception as exc:  # noqa: BLE001 - a stuck worker is still disposed
        logger.warning(f"[CHRONICLE] Forcing stale connection closed: {exc}")
        _discard_conn(conn)


def _stop_worker_threads() -> None:
    """Stop pooled workers at interpreter exit.

    aiosqlite threads inherit daemon status from their creator, so CLI workers
    are non-daemon and would keep the process alive after an early exit.
    """
    for conn in [c for c in [_write_conn, *_read_pool] if c is not None]:
        try:
            conn.stop()
        except Exception:  # noqa: BLE001 - shutdown must never raise
            pass


atexit.register(_stop_worker_threads)


FK_INDEXES_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_pcve_cve ON port_cves(cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_diffs_cve ON scan_diffs(cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_diffs_port ON scan_diffs(port_id)",
    "CREATE INDEX IF NOT EXISTS idx_paths_target ON attack_paths(target_host_id)",
    "CREATE INDEX IF NOT EXISTS idx_forge_anomaly ON forge_rules(anomaly_id)",
    "CREATE INDEX IF NOT EXISTS idx_forge_path ON forge_rules(attack_path_id)",
    "CREATE INDEX IF NOT EXISTS idx_honeypots_path ON ghost_honeypots(attack_path_id)",
    "CREATE INDEX IF NOT EXISTS idx_ghostint_honeypot ON ghost_interactions(honeypot_id)",
    "CREATE INDEX IF NOT EXISTS idx_salerts_path ON sentinel_alerts(attack_path_id)",
    "CREATE INDEX IF NOT EXISTS idx_salerts_rule ON sentinel_alerts(forge_rule_id)",
    "CREATE INDEX IF NOT EXISTS idx_antibody_alert ON antibody_feedback(sentinel_alert_id)",
    "CREATE INDEX IF NOT EXISTS idx_antibody_rule ON antibody_feedback(forge_rule_id)",
    "CREATE INDEX IF NOT EXISTS idx_antibody_path ON antibody_feedback(attack_path_id)",
]

# Columns added after v1 shipped. Applied idempotently to every database,
# including existing installs (the old code only ran these on fresh DBs).
COLUMN_MIGRATIONS: dict[str, list[tuple[str, str]]] = {
    "port_cves": [
        ("verified_status", "TEXT DEFAULT 'UNVERIFIED'"),
        ("detected_version", "TEXT"),
        ("dismissed", "INTEGER DEFAULT 0"),
    ],
    "shield_actions": [
        ("src_ip", "TEXT"),
    ],
    "hosts": [
        ("offline_since", "REAL"),
        ("device", "TEXT"),
    ],
    "forge_rules": [
        ("delivered_at", "REAL"),
        ("operator_excluded", "INTEGER NOT NULL DEFAULT 0"),
    ],
}

# Whole-table forward migrations for existing databases (SCHEMA_SQL covers
# fresh installs; these statements must stay idempotent).
FORWARD_MIGRATIONS_SQL = [
    """CREATE TABLE IF NOT EXISTS forge_sid_sequence (
           id       INTEGER PRIMARY KEY CHECK (id = 1),
           next_sid INTEGER NOT NULL
       )""",
    """INSERT OR IGNORE INTO forge_sid_sequence (id, next_sid)
       SELECT 1, COALESCE(MAX(rule_sid), 8999999) + 1 FROM forge_rules""",
    """CREATE TABLE IF NOT EXISTS revoked_tokens (
           jti        TEXT PRIMARY KEY,
           expires_at REAL NOT NULL
       )""",
    """CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires
       ON revoked_tokens(expires_at)""",
    # v3: truthful FORGE delivery state.
    """CREATE TABLE IF NOT EXISTS forge_delivery (
           id            INTEGER PRIMARY KEY,
           attempted_at  REAL    NOT NULL,
           ok            INTEGER NOT NULL,
           rule_count    INTEGER NOT NULL DEFAULT 0,
           path          TEXT,
           error         TEXT,
           reload_ok     INTEGER,
           reload_output TEXT
       )""",
    """CREATE INDEX IF NOT EXISTS idx_forge_delivery_at
       ON forge_delivery(attempted_at DESC)""",
    # v4: operator action audit trail.
    """CREATE TABLE IF NOT EXISTS audit_log (
           id         INTEGER PRIMARY KEY,
           ts         REAL    NOT NULL DEFAULT (unixepoch('now','subsec')),
           actor      TEXT    NOT NULL,
           role       TEXT    NOT NULL DEFAULT '',
           action     TEXT    NOT NULL,
           target     TEXT,
           detail     TEXT,
           ip         TEXT,
           outcome    TEXT    NOT NULL DEFAULT 'success'
       )""",
    """CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC)""",
    """CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor, ts DESC)""",
]


async def _apply_forward_migrations(conn: aiosqlite.Connection) -> None:
    for sql in FORWARD_MIGRATIONS_SQL:
        try:
            await conn.execute(sql)
        except aiosqlite.OperationalError as e:
            logger.warning(f"[CHRONICLE] Forward migration failed ({sql.splitlines()[0]}): {e}")


async def _apply_column_migrations(conn: aiosqlite.Connection) -> None:
    for table, columns in COLUMN_MIGRATIONS.items():
        try:
            async with conn.execute(f"PRAGMA table_info({table})") as cur:
                existing = {row[1] for row in await cur.fetchall()}
        except aiosqlite.OperationalError:
            continue
        for name, ddl in columns:
            if name in existing:
                continue
            try:
                await conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
                logger.info(f"[CHRONICLE] Migrated {table}.{name}")
            except aiosqlite.OperationalError as e:
                logger.warning(f"[CHRONICLE] Could not add {table}.{name}: {e}")

async def _connect(db_path) -> aiosqlite.Connection:
    # check_same_thread=False allows disposal to close the sqlite handle from
    # the current thread once the worker that created it is gone.
    conn = await aiosqlite.connect(
        db_path, timeout=30.0, check_same_thread=False)
    conn.row_factory = aiosqlite.Row
    return conn


async def _apply_pragma(conn: aiosqlite.Connection, pragma: str) -> None:
    for attempt in range(3):
        try:
            await conn.execute(pragma)
            return
        except aiosqlite.OperationalError as e:
            if 'database is locked' in str(e) and attempt < 2:
                await asyncio.sleep(0.5 * (attempt + 1))
                continue
            raise


async def _open_write_conn(db_path) -> aiosqlite.Connection:
    conn = await _connect(db_path)
    try:
        for pragma in (
            "PRAGMA journal_mode=WAL",
            "PRAGMA busy_timeout=5000",
            "PRAGMA synchronous=NORMAL",
            "PRAGMA foreign_keys=ON",
        ):
            await _apply_pragma(conn, pragma)
    except BaseException:
        await _dispose_conn(conn)
        raise
    return conn


async def _open_read_conn(db_path) -> aiosqlite.Connection:
    conn = await _connect(db_path)
    try:
        await _apply_pragma(conn, "PRAGMA busy_timeout=5000")
        await _apply_pragma(conn, "PRAGMA foreign_keys=ON")
    except BaseException:
        await _dispose_conn(conn)
        raise
    return conn


async def _initialise_schema(conn: aiosqlite.Connection) -> None:
    # The schema is entirely IF NOT EXISTS. Replaying it on every boot repairs
    # a database whose first initialisation died halfway: the old hosts-only
    # probe then declared it complete and never created the missing tables.
    schema_present = False
    try:
        async with conn.execute("SELECT COUNT(*) FROM hosts") as cur:
            await cur.fetchone()
        schema_present = True
    except aiosqlite.OperationalError:
        pass
    logger.info(
        "[CHRONICLE] Schema present, verifying migrations" if schema_present
        else "[CHRONICLE] Creating schema"
    )

    # executescript() issues an implicit COMMIT, so it must not run inside
    # transaction(); the migration steps below are transactional.
    await conn.executescript(SCHEMA_SQL)
    async with _transaction_on(conn):
        await _apply_column_migrations(conn)
        await _apply_forward_migrations(conn)
        for idx_sql in FK_INDEXES_SQL:
            try:
                await conn.execute(idx_sql)
            except aiosqlite.OperationalError:
                pass
        try:
            await conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_version"
                " (version INTEGER PRIMARY KEY, applied_at REAL NOT NULL"
                " DEFAULT (unixepoch('now','subsec')))")
            from chronicle.schema import SCHEMA_VERSION
            await conn.execute(
                "INSERT OR IGNORE INTO schema_version (version) VALUES (?)",
                (int(SCHEMA_VERSION),))
        except aiosqlite.OperationalError:
            pass


async def init():
    global _write_conn, _initialized, _read_pool
    if _pool_healthy():
        return
    async with _init_lock:
        if _pool_healthy():
            return

        db_path = settings.db.db_path

        if _initialized and _worker_alive(_write_conn):
            # The write engine is sound; repair only the poisoned readers.
            dead = [c for c in _read_pool if not _worker_alive(c)]
            _read_pool = [c for c in _read_pool if _worker_alive(c)]
            for conn in dead:
                await _dispose_conn(conn)
            while len(_read_pool) < _READ_POOL_SIZE:
                _read_pool.append(await _open_read_conn(db_path))
            while len(_read_pool) > _READ_POOL_SIZE:
                await _dispose_conn(_read_pool.pop())
            logger.warning("[CHRONICLE] Repaired dead read connections")
            return

        # Full rebuild: first boot, a partial initialisation, or a write
        # worker that can no longer answer. Detach the globals first so a
        # failed rebuild cannot leave a half-live engine behind.
        stale = [c for c in [_write_conn, *_read_pool] if c is not None]
        _write_conn = None
        _read_pool = []
        _initialized = False
        for conn in stale:
            await _dispose_conn(conn)

        logger.info(f"[CHRONICLE] Initialising database at {db_path}")
        write_conn = await _open_write_conn(db_path)
        _write_conn = write_conn
        try:
            await _initialise_schema(write_conn)
            read_pool = []
            try:
                for _ in range(_READ_POOL_SIZE):
                    read_pool.append(await _open_read_conn(db_path))
            except BaseException:
                for conn in read_pool:
                    await _dispose_conn(conn)
                raise
        except BaseException:
            _write_conn = None
            await _dispose_conn(write_conn)
            raise

        _read_pool = read_pool
        _initialized = True
        logger.success("[CHRONICLE] Database engine online")


async def _ensure_clean_txn(conn: aiosqlite.Connection) -> None:
    """Safety helper to rollback any dangling transaction before a new one."""
    if conn.in_transaction:
        try:
            await conn.rollback()
        except Exception:  # noqa: BLE001 - best effort cleanup
            pass


@asynccontextmanager
async def _transaction_on(
    conn: aiosqlite.Connection,
) -> AsyncGenerator[aiosqlite.Connection]:
    await _ensure_clean_txn(conn)
    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            await conn.execute("BEGIN IMMEDIATE")
            last_exc = None
            break
        except aiosqlite.OperationalError as e:
            last_exc = e
            if 'database is locked' in str(e) and attempt < 2:
                await asyncio.sleep(0.5 * (attempt + 1))
                continue
            break
    if last_exc is not None:
        raise last_exc
    try:
        yield conn
        await conn.commit()
    except BaseException:
        try:
            await conn.rollback()
        except Exception:
            pass
        raise


async def _ensure_write_conn() -> aiosqlite.Connection:
    conn = _write_conn
    if _initialized and _worker_alive(conn):
        return conn
    await init()
    conn = _write_conn
    if not _worker_alive(conn):
        raise RuntimeError("CHRONICLE write connection is unavailable")
    return conn


@asynccontextmanager
async def transaction() -> AsyncGenerator[aiosqlite.Connection]:
    """
    Context manager for a write transaction.
    Acquires the write lock and uses BEGIN IMMEDIATE with retry.

    Only BEGIN is retried. Retrying after `yield` is impossible for an async
    generator: the caller's exception is thrown in at the yield point and a
    second yield turns a lock contention error into "generator didn't stop".
    Resolve the connection *inside* the lock: a rebuild triggered by another
    coroutine can dispose the writer while this one waits, and a handle
    captured earlier would then fail with "no active connection".
    """
    async with _write_lock:
        conn = await _ensure_write_conn()
        async with _transaction_on(conn) as active:
            yield active

async def _rollback_quietly(conn: aiosqlite.Connection) -> None:
    """Roll back without masking the failure that triggered the cleanup."""
    try:
        await conn.rollback()
    except BaseException:  # noqa: BLE001 - preserve the caller's exception
        pass


async def _run_write(
    sql: str,
    params: Sequence[Any],
    *,
    mode: str,
) -> aiosqlite.Row | None:
    """Run one write statement with lock retries and guaranteed cleanup.

    Only ``BEGIN IMMEDIATE`` lock contention is retried. Every other failure
    (IntegrityError, ProgrammingError, cancellation, ...) used to escape with
    the transaction still open, so the next writer inherited a half-applied
    transaction. Roll back on *every* exception before re-raising.
    """
    async with _write_lock:
        conn = await _ensure_write_conn()
        for attempt in range(3):
            await _ensure_clean_txn(conn)
            try:
                await conn.execute("BEGIN IMMEDIATE")
                row = None
                if mode == "returning":
                    async with conn.execute(sql, params) as cur:
                        row = await cur.fetchone()
                elif mode == "many":
                    await conn.executemany(sql, params)
                else:
                    await conn.execute(sql, params)
                await conn.commit()
                return row
            except BaseException as exc:
                await _rollback_quietly(conn)
                if (isinstance(exc, aiosqlite.OperationalError)
                        and 'database is locked' in str(exc)
                        and attempt < 2):
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                if isinstance(exc, aiosqlite.OperationalError):
                    logger.error(f"[CHRONICLE] {mode} write failed: {exc}")
                raise
    return None


async def execute_returning(sql: str, params: Sequence[Any] = ()) -> aiosqlite.Row | None:
    return await _run_write(sql, params, mode="returning")


async def execute(sql: str, params: Sequence[Any] = ()) -> None:
    await _run_write(sql, params, mode="execute")


async def executemany(sql: str, params: Sequence[Sequence[Any]]) -> None:
    await _run_write(sql, params, mode="many")

async def fetch_one(sql: str, params: Sequence[Any] = ()) -> aiosqlite.Row | None:
    node = await _get_read_conn()
    async with node.execute(sql, params) as cur:
        return await cur.fetchone()

async def fetch_all(sql: str, params: Sequence[Any] = ()) -> Iterable[aiosqlite.Row]:
    node = await _get_read_conn()
    async with node.execute(sql, params) as cur:
        return await cur.fetchall()

async def fetch_val(sql: str, params: Sequence[Any] = (), default=None) -> Any:
    row = await fetch_one(sql, params)
    return row[0] if row else default

async def _get_read_conn() -> aiosqlite.Connection:
    global _rotator
    if not _pool_healthy():
        await init()
    if not _read_pool:
        raise RuntimeError("CHRONICLE read pool is unavailable")
    _rotator = (_rotator + 1) % len(_read_pool)
    return _read_pool[_rotator]

async def close():
    global _read_pool, _write_conn, _initialized
    async with _init_lock:
        stale = [c for c in [_write_conn, *_read_pool] if c is not None]
        _read_pool = []
        _write_conn = None
        _initialized = False
        for conn in stale:
            await _dispose_conn(conn)
