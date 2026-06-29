"""
SuRaksha DocShield — Layer 3: Cryptographic Hash Verification
SHA-256 + local mini-blockchain simulation. Fully offline.
"""
from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
import sqlite3

DB_PATH = Path(__file__).parent.parent.parent / "data" / "docshield.db"


# ─────────────────────────────────────────────
# Mini-blockchain block
# ─────────────────────────────────────────────
def _get_last_block_hash() -> str:
    """Get the hash of the last block in our mini-chain."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT sha256 FROM document_hashes ORDER BY id DESC LIMIT 1")
        row = c.fetchone()
        conn.close()
        return row[0] if row else "0" * 64   # genesis
    except Exception:
        return "0" * 64


def _make_block(doc_hash: str, filename: str, timestamp: float) -> dict:
    prev_hash = _get_last_block_hash()
    block_data = f"{prev_hash}{doc_hash}{filename}{timestamp}"
    block_hash = hashlib.sha256(block_data.encode()).hexdigest()
    return {
        "prev_hash": prev_hash,
        "doc_hash": doc_hash,
        "block_hash": block_hash,
        "timestamp": timestamp,
        "filename": filename
    }


# ─────────────────────────────────────────────
# Result container
# ─────────────────────────────────────────────
@dataclass
class HashResult:
    sha256: str = ""
    integrity_score: float = 100.0   # 0-100
    is_duplicate: bool = False
    previous_record: dict | None = None
    blockchain_block: dict = field(default_factory=dict)
    flags: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────
# Known fraud hashes (demo seed list)
# ─────────────────────────────────────────────
KNOWN_FRAUD_HASHES = {
    # Add real fraud hashes here in production
    "0000000000000000000000000000000000000000000000000000000000000000",
}


# ─────────────────────────────────────────────
# Main verification
# ─────────────────────────────────────────────
def verify_hash(raw_bytes: bytes, filename: str) -> HashResult:
    result = HashResult()
    result.sha256 = hashlib.sha256(raw_bytes).hexdigest()

    timestamp = time.time()
    result.blockchain_block = _make_block(result.sha256, filename, timestamp)

    # Check known fraud list
    if result.sha256 in KNOWN_FRAUD_HASHES:
        result.integrity_score = 0.0
        result.flags.append("⚠ Hash matches known fraudulent document registry")
        return result

    # Check local registry for duplicate
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT filename, status, score, created_at FROM document_hashes WHERE sha256=?",
                  (result.sha256,))
        row = c.fetchone()
        conn.close()
    except Exception:
        row = None

    if row:
        result.is_duplicate = True
        result.previous_record = {
            "filename": row[0],
            "status": row[1],
            "score": row[2],
            "created_at": row[3]
        }
        if row[1] == "FLAGGED":
            result.integrity_score = 10.0
            result.flags.append(f"⚠ Duplicate of a previously FLAGGED document (seen: {row[3]})")
        else:
            result.integrity_score = 95.0   # identical to a known-genuine doc
            result.flags.append(f"ℹ Duplicate of a previously seen document (seen: {row[3]})")
    else:
        result.integrity_score = 100.0   # first time seen — hash clean

    return result
