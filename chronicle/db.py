import asyncio
import aiosqlite
import pathlib
import time
from typing import Any, Sequence, Iterable, AsyncGenerator
from contextlib import asynccontextmanager
from loguru import logger
from config import settings
from chronicle.schema import SCHEMA_SQL

_read_pool: list[aiosqlite.Connection] = []
_write_conn: aiosqlite.Connection | None = None
_initialized: bool = False
_init_lock = asyncio.Lock()
_write_lock = asyncio.Lock()

_rotator = 0

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

async def init():
    global _write_conn, _initialized, _read_pool
    if _initialized: return
    async with _init_lock:
        if _initialized: return

    db_path = settings.db.db_path
    logger.info(f"[CHRONICLE] Initialising database at {db_path}")

    _write_conn = await aiosqlite.connect(db_path, timeout=30.0)
    _write_conn.row_factory = aiosqlite.Row

    for pragma in (
        "PRAGMA journal_mode=WAL",
        "PRAGMA busy_timeout=5000",
        "PRAGMA synchronous=NORMAL",
        "PRAGMA foreign_keys=ON",
    ):
        for attempt in range(3):
            try:
                await _write_conn.execute(pragma)
                break
            except aiosqlite.OperationalError as e:
                if 'database is locked' in str(e) and attempt < 2:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                raise

    schema_exists = False
    try:
        async with _write_conn.execute("SELECT COUNT(*) FROM hosts") as cur:
            await cur.fetchone()
        schema_exists = True
    except aiosqlite.OperationalError:
        pass

    if not schema_exists:
        async with transaction():
            await _write_conn.executescript(SCHEMA_SQL)

        async with transaction():
            for col_sql in (
                "ALTER TABLE port_cves ADD COLUMN verified_status TEXT DEFAULT 'UNVERIFIED'",
                "ALTER TABLE port_cves ADD COLUMN detected_version TEXT",
                "ALTER TABLE port_cves ADD COLUMN dismissed INTEGER DEFAULT 0",
            ):
                try:
                    await _write_conn.execute(col_sql)
                except aiosqlite.OperationalError:
                    pass

        async with transaction():
            await _write_conn.execute('CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT)')
            await _write_conn.execute('INSERT OR IGNORE INTO system_settings (key, value) VALUES ("scanner_enabled", "0")')
    else:
        logger.info("[CHRONICLE] Schema already exists, skipping creation")
        # Apply missing FK indices on existing schema
        async with transaction():
            for idx_sql in FK_INDEXES_SQL:
                try:
                    await _write_conn.execute(idx_sql)
                except aiosqlite.OperationalError:
                    pass

    for _ in range(8):
        conn = await aiosqlite.connect(db_path, timeout=30.0)
        conn.row_factory = aiosqlite.Row
        for attempt in range(3):
            try:
                await conn.execute("PRAGMA busy_timeout=5000")
                await conn.execute("PRAGMA foreign_keys=ON")
                break
            except aiosqlite.OperationalError as e:
                if 'database is locked' in str(e) and attempt < 2:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                raise
        _read_pool.append(conn)

    _initialized = True
    logger.success("[CHRONICLE] Database engine online")

async def _ensure_clean_txn():
    """Safety helper to rollback any dangling transaction before a new one."""
    assert _write_conn is not None
    if _write_conn.in_transaction:
        try: await _write_conn.rollback()
        except: pass

@asynccontextmanager
async def transaction() -> AsyncGenerator[aiosqlite.Connection, None]:
    """
    Context manager for a write transaction.
    Acquires the write lock and uses BEGIN IMMEDIATE with retry.
    """
    assert _write_conn is not None
    async with _write_lock:
        await _ensure_clean_txn()
        last_exc = None
        for attempt in range(3):
            try:
                await _write_conn.execute("BEGIN IMMEDIATE")
                yield _write_conn
                await _write_conn.commit()
                return
            except aiosqlite.OperationalError as e:
                if 'database is locked' in str(e) and attempt < 2:
                    last_exc = e
                    try: await _write_conn.rollback()
                    except: pass
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                try: await _write_conn.rollback()
                except: pass
                raise
            except Exception as e:
                try: await _write_conn.rollback()
                except: pass
                raise
        # All retries exhausted
        raise last_exc  # type: ignore[misc]

async def execute_returning(sql: str, params: Sequence[Any] = ()) -> aiosqlite.Row | None:
    assert _write_conn is not None
    async with _write_lock:
        for attempt in range(3):
            await _ensure_clean_txn()
            try:
                await _write_conn.execute("BEGIN IMMEDIATE")
                async with _write_conn.execute(sql, params) as cur:
                    row = await cur.fetchone()
                await _write_conn.commit()
                return row
            except aiosqlite.OperationalError as e:
                if 'database is locked' in str(e) and attempt < 2:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                try: await _write_conn.rollback()
                except: pass
                logger.error(f"[CHRONICLE] execute_returning failed: {e}")
                raise

async def execute(sql: str, params: Sequence[Any] = ()) -> None:
    assert _write_conn is not None
    async with _write_lock:
        for attempt in range(3):
            await _ensure_clean_txn()
            try:
                await _write_conn.execute("BEGIN IMMEDIATE")
                await _write_conn.execute(sql, params)
                await _write_conn.commit()
                return
            except aiosqlite.OperationalError as e:
                if 'database is locked' in str(e) and attempt < 2:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                try: await _write_conn.rollback()
                except: pass
                raise

async def executemany(sql: str, params: Sequence[Sequence[Any]]) -> None:
    assert _write_conn is not None
    async with _write_lock:
        for attempt in range(3):
            await _ensure_clean_txn()
            try:
                await _write_conn.execute("BEGIN IMMEDIATE")
                await _write_conn.executemany(sql, params)
                await _write_conn.commit()
                return
            except aiosqlite.OperationalError as e:
                if 'database is locked' in str(e) and attempt < 2:
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                try: await _write_conn.rollback()
                except: pass
                raise

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

async def _get_read_conn():
    global _rotator
    if not _read_pool:
        await init()
    if not _read_pool:
        return None
    _rotator = (_rotator + 1) % len(_read_pool)
    return _read_pool[_rotator]

async def close():
    global _read_pool, _write_conn, _initialized
    if _write_conn: await _write_conn.close()
    for c in _read_pool: await c.close()
    _read_pool = []
    _write_conn = None
    _initialized = False
