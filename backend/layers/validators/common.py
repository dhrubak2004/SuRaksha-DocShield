"""
Common utilities for all document validators.
"""
from __future__ import annotations
import re
from datetime import datetime

CURRENT_YEAR = 2026

def extract_dates(text: str) -> list[tuple[int, int, int]]:
    """Returns list of (day, month, year) tuples found in text."""
    dates = []
    patterns = [
        r'\b(\d{1,2})[\/\-\.](\d{1,2})[\/\-\.](\d{4})\b',
        r'\b(\d{1,2})[\/\-\.](\d{1,2})[\/\-\.](\d{2})\b',
        r'\b(\d{4})[\/\-\.](\d{1,2})[\/\-\.](\d{1,2})\b',
    ]
    for pat in patterns:
        for m in re.finditer(pat, text):
            g = m.groups()
            try:
                d, mo, y = int(g[0]), int(g[1]), int(g[2])
                if y < 100:
                    y += 2000
                dates.append((d, mo, y))
            except ValueError:
                pass
    return dates


def extract_amounts(text: str) -> list[float]:
    """Extract INR amounts from text."""
    amounts = []
    for raw in re.findall(r'(?:Rs\.?|INR|₹)\s?([\d,]+(?:\.\d{1,2})?)', text):
        try:
            amounts.append(float(raw.replace(',', '')))
        except ValueError:
            pass
    return amounts


def check_future_dates(text: str) -> list[str]:
    flags = []
    for d, mo, y in extract_dates(text):
        if y > CURRENT_YEAR:
            flags.append(f"🚨 Future date detected ({d:02d}/{mo:02d}/{y}) — document cannot be from the future")
    return flags


def check_placeholder_text(text: str) -> list[str]:
    PATTERNS = [
        (r'\bLorem\s+ipsum\b', "Lorem ipsum placeholder text detected"),
        (r'\b(?:John|Jane)\s+Doe\b', "Generic placeholder name (John/Jane Doe) detected"),
        (r'\bXXXX[\s\-]?XXXX[\s\-]?XXXX\b', "XXXX placeholder number detected"),
        (r'\b0000[\s\-]?0000[\s\-]?0000\b', "All-zero placeholder number detected"),
        (r'\b(?:test|sample|dummy|fake|demo)\s+(?:document|certificate|card)\b', "Test/sample/dummy/fake label found"),
        (r'\bDD[\/\-]MM[\/\-]YYYY\b', "Unfilled date template (DD/MM/YYYY) found"),
        (r'\bNAME\s+HERE\b|\bFULL\s+NAME\b', "Unfilled name placeholder found"),
    ]
    flags = []
    for pattern, message in PATTERNS:
        if re.search(pattern, text, re.I):
            flags.append(f"🚨 {message}")
    return flags
