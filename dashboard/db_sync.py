import sqlite3
import time
from config import settings

def get_db_conn():
    db_path = settings.db.db_path
    conn = sqlite3.connect(db_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA busy_timeout=5000')
    conn.execute('PRAGMA foreign_keys=ON')
    return conn

def fetch_all(sql, params=()):
    conn = get_db_conn()
    try:
        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()

def fetch_one(sql, params=()):
    conn = get_db_conn()
    try:
        row = conn.execute(sql, params).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()

def fetch_val(sql, params=(), default=None):
    row = fetch_one(sql, params)
    if row:
        return list(row.values())[0]
    return default

def execute(sql, params=()):
    for attempt in range(3):
        conn = None
        try:
            conn = get_db_conn()
            conn.execute('BEGIN IMMEDIATE')
            conn.execute(sql, params)
            conn.commit()
            return
        except sqlite3.OperationalError as e:
            if conn is not None:
                try: conn.rollback()
                except: pass
            if 'database is locked' in str(e) and attempt < 2:
                time.sleep(0.5 * (attempt + 1))
                continue
            raise
        finally:
            if conn is not None:
                conn.close()
