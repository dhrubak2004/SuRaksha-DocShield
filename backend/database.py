"""
SuRaksha DocShield — Hash Registry (SQLite, fully offline)
"""
import sqlite3
import hashlib
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "docshield.db"


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS document_hashes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256      TEXT UNIQUE NOT NULL,
            filename    TEXT,
            status      TEXT,          -- GENUINE / FLAGGED
            score       REAL,
            metadata    TEXT,          -- JSON blob
            created_at  TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sha256      TEXT,
            action      TEXT,
            details     TEXT,
            created_at  TEXT
        )
    """)
    conn.commit()
    conn.close()


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def lookup_hash(sha256: str) -> dict | None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM document_hashes WHERE sha256=?", (sha256,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            "id": row[0], "sha256": row[1], "filename": row[2],
            "status": row[3], "score": row[4],
            "metadata": json.loads(row[5]) if row[5] else {},
            "created_at": row[6]
        }
    return None


def register_hash(sha256: str, filename: str, status: str, score: float, metadata: dict):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO document_hashes (sha256, filename, status, score, metadata, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (sha256, filename, status, score, json.dumps(metadata), datetime.utcnow().isoformat()))
        conn.commit()
    except sqlite3.IntegrityError:
        pass          # duplicate — already registered
    finally:
        conn.close()


def log_audit(sha256: str, action: str, details: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO audit_log (sha256, action, details, created_at)
        VALUES (?, ?, ?, ?)
    """, (sha256, action, details, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()


# Seed a few known-fraudulent hashes for demo purposes
KNOWN_FRAUD_HASHES = set()

init_db()
