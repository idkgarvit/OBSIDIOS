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
    with sqlite3.connect(str(src), timeout=30) as sconn:
        sconn.execute("PRAGMA busy_timeout=5000")
        with sqlite3.connect(str(dest), timeout=30) as dconn:
            sconn.backup(dconn)
    # integrity check on the copy
    with sqlite3.connect(str(dest), timeout=30) as c:
        row = c.execute("PRAGMA integrity_check").fetchone()
        if not row or str(row[0]).lower() != "ok":
            dest.unlink(missing_ok=True)
            raise ValueError(f"backup integrity check failed: {row}")
    prune_old(dest_dir, keep=keep)
    return dest


def list_backups(dest_dir: str | Path) -> list[Path]:
    dest_dir = Path(dest_dir)
    if not dest_dir.exists():
        return []
    return sorted((p for p in dest_dir.glob("obsidios-*.db") if BACKUP_RE.search(p.name)),
                  key=lambda p: p.name)


def prune_old(dest_dir: str | Path, keep: int = 7) -> list[Path]:
    """Delete oldest backups beyond `keep`. Returns deleted paths."""
    backups = list_backups(dest_dir)
    if len(backups) <= max(int(keep), 0):
        return []
    doomed = backups[:len(backups) - int(keep)]
    for p in doomed:
        p.unlink(missing_ok=True)
    return doomed


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
        shutil.copy2(dest, safety)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(backup_file, dest)
    # remove -shm/-wal sidecars so the restored DB opens cleanly
    for suffix in ("-shm", "-wal", "-journal"):
        sidecar = Path(str(dest) + suffix)
        if sidecar.exists():
            sidecar.unlink()
    return dest
