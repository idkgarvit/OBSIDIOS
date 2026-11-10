"""chronicle/backup.py — online SQLite backup + rotation + safe restore.

Uses sqlite3 online backup API (WAL-safe, no need to stop daemon).
Backups land in reports/backups/obsidios-YYYYmmdd-HHMMSS.db by default.
"""
from __future__ import annotations

import re
import shutil
import sqlite3
import time
from pathlib import Path

BACKUP_RE = re.compile(r"obsidios-(\d{8}-\d{6})\.db$")


def backup_filename(ts: float | None = None) -> str:
    return "obsidios-" + time.strftime("%Y%m%d-%H%M%S", time.localtime(ts or time.time())) + ".db"


def backup_db(src: str | Path, dest_dir: str | Path, keep: int = 7) -> Path:
    """Online backup src DB into dest_dir. Returns backup path. Prunes to `keep` newest."""
    src = Path(src)
    dest_dir = Path(dest_dir)
    if not src.exists():
        raise FileNotFoundError(f"source DB not found: {src}")
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / backup_filename()
    # Build under a temp name and publish atomically: a failed backup must not
    # leave a partial obsidios-*.db that rotation counts as a real backup.
    tmp = dest.with_name(dest.name + ".tmp")
    try:
        with sqlite3.connect(str(src), timeout=30) as sconn:
            sconn.execute("PRAGMA busy_timeout=5000")
            with sqlite3.connect(str(tmp), timeout=30) as dconn:
                sconn.backup(dconn)
        # integrity check on the copy before publishing it
        with sqlite3.connect(str(tmp), timeout=30) as c:
            row = c.execute("PRAGMA integrity_check").fetchone()
        if not row or str(row[0]).lower() != "ok":
            raise ValueError(f"backup integrity check failed: {row}")
        tmp.replace(dest)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    # keep=0 would delete the backup just produced and still return its path
    # as a successful backup. Always retain the file this call created.
    prune_old(dest_dir, keep=max(int(keep), 1))
    return dest


def list_backups(dest_dir: str | Path) -> list[Path]:
    dest_dir = Path(dest_dir)
    if not dest_dir.exists():
        return []
    return sorted((p for p in dest_dir.glob("obsidios-*.db") if BACKUP_RE.search(p.name)),
                  key=lambda p: p.name)


def prune_old(dest_dir: str | Path, keep: int = 7) -> list[Path]:
    """Delete oldest backups beyond `keep`. Returns deleted paths."""
    keep = max(int(keep), 0)
    backups = list_backups(dest_dir)
    if len(backups) <= keep:
        return []
    doomed = backups[:len(backups) - keep]
    for p in doomed:
        p.unlink(missing_ok=True)
    return doomed


def _is_readable_sqlite(path: Path) -> bool:
    try:
        with sqlite3.connect(str(path), timeout=30) as conn:
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
        return True
    except sqlite3.DatabaseError:
        return False


def _online_copy(src: Path, dest: Path) -> None:
    with sqlite3.connect(str(src), timeout=30) as sconn, \
            sqlite3.connect(str(dest), timeout=30) as dconn:
        sconn.backup(dconn)


def _snapshot_db(src: Path, dest: Path) -> None:
    """Write a self-contained snapshot of src to dest.

    A plain byte copy of the main file omits transactions still sitting in the
    -wal sidecar; in WAL mode that can lose the schema and every recent write.
    The online backup API reads through the WAL and writes one standalone DB.
    Non-SQLite sources are preserved with a byte-for-byte copy plus sidecars.
    """
    if not _is_readable_sqlite(src):
        shutil.copy2(src, dest)
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(src) + suffix)
            if sidecar.exists():
                shutil.copy2(sidecar, Path(str(dest) + suffix))
        return
    try:
        _online_copy(src, dest)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise


def restore_db(backup_file: str | Path, dest: str | Path) -> Path:
    """Restore backup over dest DB. Safety: dest is moved to dest.pre-restore-<ts>.bak first."""
    backup_file = Path(backup_file)
    dest = Path(dest)
    if not backup_file.exists():
        raise FileNotFoundError(f"backup not found: {backup_file}")
    try:
        with sqlite3.connect(str(backup_file), timeout=30) as c:
            row = c.execute("PRAGMA integrity_check").fetchone()
    except sqlite3.DatabaseError as e:
        raise ValueError(f"refusing restore: not a valid SQLite DB ({e})")
    if not row or str(row[0]).lower() != "ok":
        raise ValueError("refusing restore: backup integrity check failed")
    if dest.exists():
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
        safety = dest.with_name(dest.name + f".pre-restore-{stamp}.bak")
        _snapshot_db(dest, safety)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
    if _is_readable_sqlite(dest):
        # Restore through SQLite rather than overwriting the file under a live
        # connection: a daemon holding the old WAL would otherwise checkpoint
        # its stale frames back over the restored file when it closes.
        _online_copy(backup_file, dest)
    else:
        # A corrupt destination has no live readers whose WAL we must respect.
        for suffix in ("-shm", "-wal", "-journal"):
            Path(str(dest) + suffix).unlink(missing_ok=True)
        tmp = dest.with_name(dest.name + ".restore.tmp")
        try:
            shutil.copy2(backup_file, tmp)
            tmp.replace(dest)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    return dest
