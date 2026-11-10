"""Tests for chronicle/backup.py — online backup, rotation, safe restore."""
import sqlite3
import time
import types

import pytest

from chronicle import backup as backup_mod
from chronicle.backup import backup_db, list_backups, prune_old, restore_db


def _seed_db(path, n=3):
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as c:
        c.execute("CREATE TABLE IF NOT EXISTS hosts (id INTEGER PRIMARY KEY, ip TEXT)")
        c.execute("DELETE FROM hosts")
        c.executemany("INSERT INTO hosts (ip) VALUES (?)", [(f"10.0.0.{i}",) for i in range(1, n + 1)])
        c.commit()


def test_backup_and_restore(tmp_path):
    src = tmp_path / "obsidios.db"
    _seed_db(src, n=3)
    dest_dir = tmp_path / "backups"

    out = backup_db(src, dest_dir, keep=7)
    assert out.exists()
    with sqlite3.connect(str(out)) as c:
        assert c.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 3
        assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

    # mutate src, then restore
    with sqlite3.connect(str(src)) as c:
        c.execute("DELETE FROM hosts")
        c.commit()
    restore_db(out, src)
    with sqlite3.connect(str(src)) as c:
        assert c.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 3
    # safety .bak left behind
    assert list(src.parent.glob("obsidios.db.pre-restore-*.bak"))


def test_restore_safety_copy_includes_uncheckpointed_wal_rows(tmp_path):
    """The pre-restore .bak must not silently drop WAL-only transactions."""
    dest = tmp_path / "live.db"
    live = sqlite3.connect(str(dest))
    try:
        live.execute("PRAGMA journal_mode=WAL")
        live.execute("PRAGMA wal_autocheckpoint=0")
        live.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY, ip TEXT)")
        live.executemany(
            "INSERT INTO hosts (ip) VALUES (?)",
            [(f"10.9.0.{i}",) for i in range(1, 21)],
        )
        live.commit()
        wal = dest.with_name(dest.name + "-wal")
        assert wal.exists() and wal.stat().st_size > 0

        src = tmp_path / "source.db"
        _seed_db(src, n=1)
        backup = backup_db(src, tmp_path / "backups")

        restore_db(backup, dest)
    finally:
        live.close()

    [safety] = dest.parent.glob("live.db.pre-restore-*.bak")
    with sqlite3.connect(str(safety)) as c:
        assert c.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 20
        assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    # The restore itself still installed the backup, not the old WAL state.
    with sqlite3.connect(str(dest)) as c:
        assert c.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 1
        assert c.execute("SELECT ip FROM hosts").fetchone()[0] == "10.0.0.1"


def test_rotation_keeps_newest(tmp_path):
    dest = tmp_path / "b"
    dest.mkdir()
    for i in range(5):
        (dest / f"obsidios-2025010{i}-120000.db").touch()
        time.sleep(0.01)
    pruned = prune_old(dest, keep=3)
    assert len(pruned) == 2
    assert len(list_backups(dest)) == 3


def test_failed_backup_leaves_no_bogus_backup_file(tmp_path):
    """A corrupt source must not leave a 0-byte entry that rotation counts."""
    src = tmp_path / "bad.db"
    src.write_bytes(b"this is not a sqlite database")
    dest_dir = tmp_path / "backups"
    dest_dir.mkdir()
    real = dest_dir / "obsidios-20250101-120000.db"
    real.write_bytes(b"real backup")

    with pytest.raises(sqlite3.DatabaseError):
        backup_db(src, dest_dir, keep=1)

    assert list_backups(dest_dir) == [real]
    assert not list(dest_dir.glob("*.tmp"))


def test_backup_missing_src(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        backup_db(tmp_path / "nope.db", tmp_path / "b")


def test_backup_keep_zero_still_keeps_the_new_backup(tmp_path):
    """Reporting success for a file the rotation just deleted is a lie."""
    src = tmp_path / "obsidios.db"
    _seed_db(src)
    dest_dir = tmp_path / "backups"
    dest_dir.mkdir()
    stale = dest_dir / "obsidios-20200101-000000.db"
    stale.write_bytes(b"old")

    out = backup_db(src, dest_dir, keep=0)

    assert out.exists()
    assert not stale.exists()
    assert list_backups(dest_dir) == [out]


def test_list_backups_missing_directory_is_empty(tmp_path):
    assert list_backups(tmp_path / "does-not-exist") == []


def test_prune_keep_zero_removes_everything(tmp_path):
    dest = tmp_path / "b"
    dest.mkdir()
    only = dest / "obsidios-20250101-120000.db"
    only.touch()

    assert prune_old(dest, keep=0) == [only]
    assert list_backups(dest) == []


def test_restore_creates_a_missing_destination(tmp_path):
    src = tmp_path / "obsidios.db"
    _seed_db(src, n=2)
    out = backup_db(src, tmp_path / "backups")

    dest = tmp_path / "new" / "nested" / "obsidios.db"
    restore_db(out, dest)

    with sqlite3.connect(str(dest)) as c:
        assert c.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 2
    # Nothing existed before, so there is nothing to preserve.
    assert list(dest.parent.glob("*.pre-restore-*.bak")) == []


def test_restore_requires_an_existing_backup(tmp_path):
    with pytest.raises(FileNotFoundError):
        restore_db(tmp_path / "missing.db", tmp_path / "dest.db")


def test_restore_refuses_a_bad_integrity_result_before_touching_dest(
        tmp_path, monkeypatch):
    """A backup that fails the check must not overwrite a healthy database."""
    backup = tmp_path / "obsidios-20250101-120000.db"
    backup.write_bytes(b"placeholder")
    dest = tmp_path / "live.db"
    dest.write_bytes(b"precious")

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, _sql):
            return self

        def fetchone(self):
            return ("database disk image is malformed",)

    monkeypatch.setattr(
        backup_mod,
        "sqlite3",
        types.SimpleNamespace(connect=lambda *_a, **_k: FakeConn(),
                              DatabaseError=sqlite3.DatabaseError),
    )

    with pytest.raises(ValueError, match="integrity check failed"):
        restore_db(backup, dest)

    assert dest.read_bytes() == b"precious"


def test_restore_preserves_a_non_sqlite_destination_byte_for_byte(tmp_path):
    """A corrupt live DB is exactly what the safety copy must preserve."""
    src = tmp_path / "source.db"
    _seed_db(src, n=1)
    backup = backup_db(src, tmp_path / "backups")
    dest = tmp_path / "live.db"
    corrupt = b"this is not a sqlite database"
    dest.write_bytes(corrupt)

    restore_db(backup, dest)

    [safety] = dest.parent.glob("live.db.pre-restore-*.bak")
    assert safety.read_bytes() == corrupt
    with sqlite3.connect(str(dest)) as c:
        assert c.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 1


def test_restore_rejects_corrupt(tmp_path):
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"not a database")
    with pytest.raises(ValueError):
        restore_db(bad, tmp_path / "dest.db")
