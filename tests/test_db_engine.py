"""Database-engine regressions.

The engine underpins every other guarantee. Two failure modes matter:
a half-initialised database that is never repaired, and a transaction helper
that claims to retry but instead corrupts the exception path.
"""
import asyncio
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import aiosqlite
import pytest

from chronicle import db as cdb
from chronicle.schema import SCHEMA_SQL, SCHEMA_VERSION
from dashboard.app import run_async

ROOT = Path(__file__).resolve().parent.parent


async def _no_sleep(_seconds):
    return None


class TestTransaction:
    def test_body_exception_rolls_back_without_masking_the_error(self):
        marker = f"txn-test-{uuid.uuid4().hex}"

        async def scenario():
            await cdb.init()
            try:
                async with cdb.transaction():
                    await cdb._write_conn.execute(
                        "INSERT INTO audit_log (actor, action) VALUES (?, ?)",
                        (marker, "TEST"),
                    )
                    raise RuntimeError("boom")
            except RuntimeError as exc:
                assert str(exc) == "boom"
            except BaseException as exc:  # noqa: BLE001 - regression guard
                raise AssertionError(
                    f"transaction masked the body error with {type(exc).__name__}"
                ) from exc
            return await cdb.fetch_one(
                "SELECT id FROM audit_log WHERE actor=?", (marker,)
            )

        assert run_async(scenario()) is None

    def test_committed_transaction_is_visible(self):
        marker = f"txn-test-{uuid.uuid4().hex}"

        async def scenario():
            await cdb.init()
            async with cdb.transaction():
                await cdb._write_conn.execute(
                    "INSERT INTO audit_log (actor, action) VALUES (?, ?)",
                    (marker, "TEST"),
                )
            return await cdb.fetch_one(
                "SELECT id FROM audit_log WHERE actor=?", (marker,)
            )

        assert run_async(scenario()) is not None

    def test_lock_contention_is_retried(self, monkeypatch):
        """BEGIN IMMEDIATE contention must retry, then succeed."""
        attempts = {"n": 0}

        async def scenario():
            await cdb.init()
            real_execute = cdb._write_conn.execute

            async def flaky(sql, *args, **kwargs):
                if sql == "BEGIN IMMEDIATE":
                    attempts["n"] += 1
                    if attempts["n"] < 3:
                        import aiosqlite
                        raise aiosqlite.OperationalError("database is locked")
                return await real_execute(sql, *args, **kwargs)

            monkeypatch.setattr(cdb._write_conn, "execute", flaky)
            monkeypatch.setattr(cdb.asyncio, "sleep", _no_sleep)
            async with cdb.transaction():
                await real_execute(
                    "INSERT INTO audit_log (actor, action) VALUES (?, ?)",
                    ("retry", "TEST"),
                )

        run_async(scenario())
        assert attempts["n"] == 3


def _run_in_child(
    db_path: Path, body: str, timeout: float = 120
) -> subprocess.CompletedProcess:
    """Run `body` in a fresh interpreter pointed at `db_path`.

    The child always exits with os._exit so aiosqlite's worker threads cannot
    keep the process alive after a failure.
    """
    script = f"""
import asyncio, os, sys
from config import settings
settings.db.db_path = {str(db_path)!r}
from chronicle import db

async def main():
{body}

try:
    asyncio.run(main())
finally:
    sys.stdout.flush()
    os._exit(0)
"""
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=timeout, cwd=str(ROOT),
    )


class TestSchemaRepair:
    def test_missing_table_is_recreated_on_next_boot(self, tmp_path):
        """A DB that died after `hosts` must still gain every later table."""
        db_path = tmp_path / "partial.db"
        conn = sqlite3.connect(db_path)
        conn.executescript(SCHEMA_SQL)
        # Simulate an initialisation that died before the later tables were
        # created (the old hosts-only probe then never repaired it).
        conn.execute("DROP TABLE cves")
        conn.commit()
        conn.close()

        proc = _run_in_child(db_path, """
    await db.init()
    row = await db.fetch_one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='cves'"
    )
    print("CVES_TABLE", bool(row))
    print("AUDIT_TABLE", bool(await db.fetch_one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
    )))
    await db.close()
""")
        assert "CVES_TABLE True" in proc.stdout, proc.stdout + proc.stderr
        assert "AUDIT_TABLE True" in proc.stdout, proc.stdout + proc.stderr

    def test_schema_version_is_recorded(self, tmp_path):
        db_path = tmp_path / "fresh.db"
        proc = _run_in_child(db_path, """
    await db.init()
    print("VERSION", await db.fetch_val("SELECT MAX(version) FROM schema_version"))
    await db.close()
""")
        assert f"VERSION {SCHEMA_VERSION}" in proc.stdout, proc.stdout + proc.stderr

    def test_init_is_idempotent(self, tmp_path):
        db_path = tmp_path / "twice.db"
        proc = _run_in_child(db_path, """
    await db.init()
    await db.close()
    await db.init()
    print("SECOND_INIT", await db.fetch_val("SELECT COUNT(*) FROM schema_version"))
""")
        assert "SECOND_INIT 1" in proc.stdout, proc.stdout + proc.stderr


class TestPoolResilience:
    """Poisoned connection pools must be rebuilt, not awaited forever.

    An aiosqlite worker exits when it tries to hand a result back to a calling
    loop that has already closed. The connection object still looks usable
    (`_running` is True and the queue accepts work), so every later query
    queues a function that no thread will ever execute and the caller hangs
    indefinitely. These regressions kill a worker on purpose and demand that
    the engine notices before using the handle.
    """

    @staticmethod
    def _kill_worker(conn):
        """Stop an aiosqlite worker without marking the proxy closed."""
        import aiosqlite.core as core

        conn._tx.put_nowait((None, lambda: core._STOP_RUNNING_SENTINEL))
        conn._thread.join(timeout=5)
        assert not conn._thread.is_alive()

    def test_dead_write_worker_is_rebuilt_instead_of_hanging(self, tmp_path):
        db_path = tmp_path / "dead-write.db"
        proc = _run_in_child(db_path, """
    import aiosqlite.core as core

    await db.init()
    victim = db._write_conn
    victim._tx.put_nowait((None, lambda: core._STOP_RUNNING_SENTINEL))
    victim._thread.join(timeout=5)
    print("WRITE_WORKER_DEAD", not victim._thread.is_alive())
    try:
        await asyncio.wait_for(
            db.execute(
                "INSERT INTO audit_log (actor, action)"
                " VALUES ('dead-write','TEST')"),
            timeout=5)
        print("WRITE_RECOVERED", True)
    except asyncio.TimeoutError:
        print("WRITE_RECOVERED", False)
    print("ROW_VISIBLE", bool(await db.fetch_val(
        "SELECT id FROM audit_log WHERE actor='dead-write'")))
""", timeout=45)
        assert "WRITE_WORKER_DEAD True" in proc.stdout, proc.stdout + proc.stderr
        assert "WRITE_RECOVERED True" in proc.stdout, proc.stdout + proc.stderr
        assert "ROW_VISIBLE True" in proc.stdout, proc.stdout + proc.stderr

    def test_dead_read_worker_is_replaced_before_use(self, tmp_path):
        db_path = tmp_path / "dead-read.db"
        proc = _run_in_child(db_path, """
    import aiosqlite.core as core

    await db.init()
    victim = db._read_pool[0]
    victim._tx.put_nowait((None, lambda: core._STOP_RUNNING_SENTINEL))
    victim._thread.join(timeout=5)
    # Make the next read pick the poisoned connection.
    db._rotator = len(db._read_pool) - 1
    print("READ_WORKER_DEAD", not victim._thread.is_alive())
    try:
        value = await asyncio.wait_for(db.fetch_val("SELECT 1"), timeout=5)
        print("READ_VALUE", value)
    except asyncio.TimeoutError:
        print("READ_VALUE timeout")
    print("POOL_SIZE", len(db._read_pool))
    print("VICTIM_POOLED", victim in db._read_pool)
""", timeout=45)
        assert "READ_WORKER_DEAD True" in proc.stdout, proc.stdout + proc.stderr
        assert "READ_VALUE 1" in proc.stdout, proc.stdout + proc.stderr
        assert "POOL_SIZE 8" in proc.stdout, proc.stdout + proc.stderr
        assert "VICTIM_POOLED False" in proc.stdout, proc.stdout + proc.stderr

    def test_concurrent_init_builds_exactly_one_pool(self, tmp_path):
        db_path = tmp_path / "concurrent-init.db"
        proc = _run_in_child(db_path, """
    await asyncio.gather(*[db.init() for _ in range(4)])
    print("READ_POOL", len(db._read_pool))
    print("INITIALIZED", db._initialized)
""")
        assert "READ_POOL 8" in proc.stdout, proc.stdout + proc.stderr
        assert "INITIALIZED True" in proc.stdout, proc.stdout + proc.stderr


class TestPoolLifecycle:
    """Repair and disposal paths must be cheap, leak-free and loud on failure."""

    def test_reader_repair_keeps_the_live_write_engine(self):
        """Only readers died, so rebuilding the schema would be wasted work."""
        async def scenario():
            await cdb.init()
            writer = cdb._write_conn
            victim = cdb._read_pool[0]
            TestPoolResilience._kill_worker(victim)
            await cdb.init()
            return writer, victim

        writer, victim = run_async(scenario())

        assert cdb._write_conn is writer
        assert cdb._worker_alive(writer)
        assert len(cdb._read_pool) == cdb._READ_POOL_SIZE
        assert all(cdb._worker_alive(conn) for conn in cdb._read_pool)
        assert victim not in cdb._read_pool

    @pytest.mark.parametrize("opener", ["_open_read_conn", "_open_write_conn"])
    def test_connection_is_closed_when_pragma_setup_fails(
            self, monkeypatch, opener):
        """A half-configured connection must not leak its worker or handle."""
        async def boom(_conn, _pragma):
            raise aiosqlite.OperationalError("disk I/O error")

        opened = {}

        async def scenario():
            conn = await cdb._connect(cdb.settings.db.db_path)
            opened["conn"] = conn

            async def reuse(_path):
                return conn

            monkeypatch.setattr(cdb, "_connect", reuse)
            monkeypatch.setattr(cdb, "_apply_pragma", boom)
            with pytest.raises(aiosqlite.OperationalError):
                await getattr(cdb, opener)(cdb.settings.db.db_path)

        run_async(scenario())

        conn = opened["conn"]
        assert conn._connection is None
        assert not conn._running

    def test_pragma_retries_only_transient_locks(self, monkeypatch):
        class Flaky:
            def __init__(self, failures, message="database is locked"):
                self.calls = 0
                self.failures = failures
                self.message = message

            async def execute(self, _pragma):
                self.calls += 1
                if self.calls <= self.failures:
                    raise aiosqlite.OperationalError(self.message)

        monkeypatch.setattr(cdb.asyncio, "sleep", _no_sleep)

        transient = Flaky(2)
        run_async(cdb._apply_pragma(transient, "PRAGMA busy_timeout=5000"))
        assert transient.calls == 3

        permanent = Flaky(3, "no such table: nope")
        with pytest.raises(aiosqlite.OperationalError):
            run_async(cdb._apply_pragma(permanent, "PRAGMA busy_timeout=5000"))
        assert permanent.calls == 1

        exhausted = Flaky(3)
        with pytest.raises(aiosqlite.OperationalError):
            run_async(cdb._apply_pragma(exhausted, "PRAGMA busy_timeout=5000"))
        assert exhausted.calls == 3

    def test_unrecoverable_engine_raises_instead_of_returning_none(
            self, monkeypatch):
        """A failed rebuild must fail the caller, not hand back a null handle."""

        async def scenario():
            async def broken_init():
                return None

            monkeypatch.setattr(cdb, "init", broken_init)
            monkeypatch.setattr(cdb, "_initialized", False)
            monkeypatch.setattr(cdb, "_write_conn", None)
            monkeypatch.setattr(cdb, "_read_pool", [])
            with pytest.raises(
                    RuntimeError, match="write connection is unavailable"):
                await cdb._ensure_write_conn()
            with pytest.raises(RuntimeError, match="read pool is unavailable"):
                await cdb._get_read_conn()

        run_async(scenario())

    def test_exit_hook_stops_every_worker_and_never_raises(self, monkeypatch):
        """Non-daemon aiosqlite threads must not outlive the process."""
        class FakeConn:
            def __init__(self, fail=False):
                self.stopped = False
                self.fail = fail

            def stop(self):
                self.stopped = True
                if self.fail:
                    raise RuntimeError("no running event loop")

        writer, reader, broken = FakeConn(), FakeConn(), FakeConn(fail=True)
        monkeypatch.setattr(cdb, "_write_conn", writer)
        monkeypatch.setattr(cdb, "_read_pool", [reader, broken])

        cdb._stop_worker_threads()

        assert writer.stopped
        assert reader.stopped
        assert broken.stopped

    def test_writer_queued_behind_a_rebuild_uses_the_new_connection(self):
        """A writer must resolve its connection after winning the write lock.

        Otherwise a rebuild that happens while it waits can dispose the handle
        it captured, and the queued write fails with `Connection closed`.
        """
        async def scenario():
            await cdb.init()
            old = cdb._write_conn
            await cdb._write_lock.acquire()
            task = asyncio.create_task(cdb.execute(
                "INSERT INTO audit_log (actor, action)"
                " VALUES ('rebuild-race','TEST')"))
            try:
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                # Simulate a concurrent rebuild swapping the writer.
                cdb._write_conn = None
                cdb._initialized = False
                await cdb._dispose_conn(old)
                cdb._write_conn = await cdb._open_write_conn(
                    cdb.settings.db.db_path)
                cdb._initialized = True
            finally:
                cdb._write_lock.release()
            await asyncio.wait_for(task, timeout=5)
            return await cdb.fetch_val(
                "SELECT COUNT(*) FROM audit_log WHERE actor='rebuild-race'")

        assert run_async(scenario()) == 1

    def test_dispose_forces_a_wedged_connection_out_of_the_pool(self):
        """A close() that raises must still leave an unusable handle discarded."""
        class Wedged:
            _running = True
            _connection = object()
            _thread = type("T", (), {"is_alive": lambda self: True})()

            def __init__(self):
                self.stopped = False

            async def close(self):
                raise RuntimeError("worker wedged")

            def stop(self):
                self.stopped = True

        conn = Wedged()
        run_async(cdb._dispose_conn(conn))

        assert conn._connection is None
        assert conn._running is False
        assert conn.stopped is True

    def test_cancelled_dispose_still_discards_the_worker(self):
        class Slow:
            _running = True
            _connection = None
            _thread = type("T", (), {"is_alive": lambda self: True})()

            def __init__(self):
                self.stopped = False

            async def close(self):
                await asyncio.sleep(3600)

            def stop(self):
                self.stopped = True

        async def scenario():
            conn = Slow()
            task = asyncio.create_task(cdb._dispose_conn(conn))
            await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            return conn

        conn = run_async(scenario())
        assert conn._connection is None
        assert conn._running is False
        assert conn.stopped is True

    def test_absent_connections_are_safely_ignored(self):
        assert cdb._worker_alive(None) is False
        cdb._discard_conn(None)
        run_async(cdb._dispose_conn(None))

    def test_failed_rebuild_leaves_no_half_live_engine_and_recovers(
            self, monkeypatch):
        """A boot that dies halfway must expose no stale handles and retry."""
        async def scenario():
            await cdb.init()
            real_open_read = cdb._open_read_conn
            calls = {"n": 0}

            async def failing_open(path):
                calls["n"] += 1
                if calls["n"] == 3:
                    raise RuntimeError("cannot open reader")
                return await real_open_read(path)

            # Force the full-rebuild path: a dead writer cannot be repaired.
            TestPoolResilience._kill_worker(cdb._write_conn)
            monkeypatch.setattr(cdb, "_open_read_conn", failing_open)
            try:
                with pytest.raises(RuntimeError, match="cannot open reader"):
                    await cdb.init()
                assert cdb._write_conn is None
                assert cdb._initialized is False
                assert cdb._read_pool == []
            finally:
                monkeypatch.setattr(cdb, "_open_read_conn", real_open_read)
                await cdb.init()
            return await cdb.fetch_val("SELECT 1")

        assert run_async(scenario()) == 1

    @pytest.mark.parametrize(
        "helper", ["transaction", "execute", "execute_returning", "executemany"])
    def test_write_helpers_fail_loudly_after_lock_retries(
            self, monkeypatch, helper):
        """Three failed BEGINs must raise, even if rollback also fails."""
        async def scenario():
            await cdb.init()
            conn = await cdb._ensure_write_conn()

            async def always_locked(_sql, *_args, **_kwargs):
                raise aiosqlite.OperationalError("database is locked")

            async def broken_rollback():
                raise RuntimeError("rollback failed")

            monkeypatch.setattr(conn, "execute", always_locked)
            monkeypatch.setattr(conn, "rollback", broken_rollback)
            monkeypatch.setattr(cdb.asyncio, "sleep", _no_sleep)

            with pytest.raises(aiosqlite.OperationalError, match="locked"):
                if helper == "transaction":
                    async with cdb.transaction():
                        pass
                elif helper == "execute":
                    await cdb.execute(
                        "INSERT INTO audit_log (actor) VALUES ('locked')")
                elif helper == "execute_returning":
                    await cdb.execute_returning("SELECT 1")
                else:
                    await cdb.executemany(
                        "INSERT INTO audit_log (actor) VALUES (?)",
                        [("locked",)])

        run_async(scenario())

    @pytest.mark.parametrize("helper", ["execute", "execute_returning", "executemany"])
    def test_non_operational_error_rolls_back_before_it_escapes(self, helper):
        """IntegrityError used to leave the write connection in a transaction."""
        async def scenario():
            await cdb.init()
            conn = await cdb._ensure_write_conn()
            with pytest.raises(aiosqlite.IntegrityError):
                if helper == "execute":
                    await cdb.execute("INSERT INTO audit_log (actor) VALUES (NULL)")
                elif helper == "execute_returning":
                    await cdb.execute_returning(
                        "INSERT INTO audit_log (actor) VALUES (NULL)")
                else:
                    await cdb.executemany(
                        "INSERT INTO audit_log (actor) VALUES (?)", [(None,)])
            return conn.in_transaction

        assert run_async(scenario()) is False

    def test_cancellation_rolls_back_before_it_propagates(self, monkeypatch):
        """A cancelled write must not hold the transaction until the next write."""
        async def scenario():
            await cdb.init()
            conn = await cdb._ensure_write_conn()
            real_execute = conn.execute
            calls = {"n": 0}

            async def cancelling_execute(sql, params=()):
                calls["n"] += 1
                if calls["n"] == 2:  # first call is BEGIN IMMEDIATE
                    raise asyncio.CancelledError()
                return await real_execute(sql, params)

            monkeypatch.setattr(conn, "execute", cancelling_execute)
            try:
                with pytest.raises(asyncio.CancelledError):
                    await cdb.execute(
                        "INSERT INTO audit_log (actor) VALUES ('cancelled')")
            finally:
                monkeypatch.setattr(conn, "execute", real_execute)
            return conn.in_transaction, await cdb.fetch_val(
                "SELECT COUNT(*) FROM audit_log WHERE actor='cancelled'")

        assert run_async(scenario()) == (False, 0)

    def test_broken_rollback_does_not_mask_the_body_error_and_is_repaired(
            self, monkeypatch):
        """Cleanup failures must not hide the caller's error or wedge the DB."""
        marker = f"txn-test-{uuid.uuid4().hex}"

        async def scenario():
            await cdb.init()
            conn = await cdb._ensure_write_conn()
            real_rollback = conn.rollback

            async def broken_rollback():
                raise RuntimeError("rollback failed")

            monkeypatch.setattr(conn, "rollback", broken_rollback)
            with pytest.raises(RuntimeError, match="body failed"):
                async with cdb.transaction():
                    raise RuntimeError("body failed")

            # The failed rollback left a transaction open. The next write must
            # notice and repair it rather than fail with "within a transaction".
            monkeypatch.setattr(conn, "rollback", real_rollback)
            await cdb.execute(
                "INSERT INTO audit_log (actor, action) VALUES (?, 'TEST')",
                (marker,))
            return await cdb.fetch_val(
                "SELECT COUNT(*) FROM audit_log WHERE actor=?", (marker,))

        assert run_async(scenario()) == 1

    def test_legacy_table_missing_an_indexed_column_still_boots(self, tmp_path):
        """One unobtainable optional index must not brick the whole install."""
        db_path = tmp_path / "legacy-index.db"
        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE port_cves"
            " (id INTEGER PRIMARY KEY, port_id INTEGER, exploit_status TEXT)")
        conn.commit()
        conn.close()

        proc = _run_in_child(db_path, """
    await db.init()
    print("BOOTED", True)
    print("HOSTS_TABLE", bool(await db.fetch_one(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='hosts'")))
""")
        assert "BOOTED True" in proc.stdout, proc.stdout + proc.stderr
        assert "HOSTS_TABLE True" in proc.stdout, proc.stdout + proc.stderr

    def test_init_lock_wakes_a_waiter_on_another_event_loop(self):
        """close() runs on the CLI loop while dashboard init() holds the lock.

        An asyncio.Lock resolves the waiter's future from the holder's loop,
        which does not wake the waiter's loop: close() then hangs forever.
        """
        holder_loop = asyncio.new_event_loop()
        acquired = threading.Event()
        release = threading.Event()

        def hold():
            asyncio.set_event_loop(holder_loop)

            async def scenario():
                async with cdb._init_lock:
                    acquired.set()
                    while not release.is_set():
                        await asyncio.sleep(0.01)

            holder_loop.run_until_complete(scenario())
            holder_loop.close()

        thread = threading.Thread(target=hold)
        thread.start()
        try:
            assert acquired.wait(2)

            async def waiter():
                async with cdb._init_lock:
                    return time.monotonic()

            async def contend():
                started = time.monotonic()
                task = asyncio.create_task(waiter())
                await asyncio.sleep(0.1)  # let the waiter park on the lock
                release.set()
                acquired_at = await asyncio.wait_for(task, 2)
                return acquired_at - started

            elapsed = asyncio.run(contend())
            assert elapsed < 1.0, f"waiter woke after {elapsed:.2f}s"
        finally:
            release.set()
            thread.join(2)
            assert not thread.is_alive()

    def test_close_is_idempotent_and_the_engine_can_reopen(self, tmp_path):
        db_path = tmp_path / "reopen.db"
        proc = _run_in_child(db_path, """
    await db.init()
    await db.close()
    await db.close()
    await db.init()
    print("REOPENED", await db.fetch_val("SELECT 1"))
    await db.close()
""")
        assert "REOPENED 1" in proc.stdout, proc.stdout + proc.stderr


