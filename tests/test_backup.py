"""Tests for chronicle/backup.py — online backup, rotation, safe restore."""
import sqlite3
import time

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


def test_rotation_keeps_newest(tmp_path):
    dest = tmp_path / "b"
    dest.mkdir()
    for i in range(5):
        (dest / f"obsidios-2025010{i}-120000.db").touch()
        time.sleep(0.01)
    pruned = prune_old(dest, keep=3)
    assert len(pruned) == 2
    assert len(list_backups(dest)) == 3


def test_backup_missing_src(tmp_path):
    import pytest
    with pytest.raises(FileNotFoundError):
        backup_db(tmp_path / "nope.db", tmp_path / "b")


def test_restore_rejects_corrupt(tmp_path):
    import pytest
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"not a database")
    with pytest.raises(ValueError):
        restore_db(bad, tmp_path / "dest.db")
