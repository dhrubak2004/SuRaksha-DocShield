"""Aadhaar Card Validator"""
from __future__ import annotations
import re
from .common import check_future_dates, check_placeholder_text

_VERHOEFF_D = [
    [0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],
    [3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],
    [6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],
    [9,8,7,6,5,4,3,2,1,0],
]
_VERHOEFF_P = [
    [0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],
    [8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],
    [2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8],
]

def _verhoeff_check(number: str) -> bool:
    digits = [int(d) for d in reversed(re.sub(r'[\s\-]', '', number))]
    c = 0
    for i, digit in enumerate(digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][digit]]
    return c == 0

FAKE_AADHAAR = {
    "123456789012","000000000000","111111111111","999999999999",
    "123412341234","000011112222","111122223333","123456789010","987654321098",
    "234567890123","345678901234","456789012345",
}

def validate(text: str) -> tuple[float, list[str]]:
    flags = []
    penalty = 0.0

    flags.extend(check_placeholder_text(text))
    flags.extend(check_future_dates(text))

    numbers = re.findall(r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b', text)
    if not numbers:
        flags.append("⚠️ No 12-digit Aadhaar number found in document")
        penalty += 30
        return max(0.0, 100.0 - penalty), flags

    for raw in numbers:
        digits = re.sub(r'[\s\-]', '', raw)

        if digits in FAKE_AADHAAR:
            flags.append(f"🚨 Aadhaar {raw} is a known fake/placeholder number")
            penalty += 70

        if not _verhoeff_check(digits):
            flags.append(f"🚨 Aadhaar {raw} fails Verhoeff checksum — mathematically invalid")
            penalty += 60

        if digits[0] in ('0', '1'):
            flags.append(f"🚨 Aadhaar {raw} starts with '{digits[0]}' — invalid (must start 2–9)")
            penalty += 50

        if len(set(digits)) <= 2:
            flags.append(f"⚠️ Aadhaar {raw} uses only {len(set(digits))} unique digits — suspicious")
            penalty += 40

    # UIDAI mention check
    if not re.search(r'uidai|unique\s+identification\s+authority', text, re.I):
        flags.append("⚠️ UIDAI authority name not found on document")
        penalty += 10

    return max(0.0, 100.0 - penalty), flags


CHECKS = [
    "Verhoeff checksum on 12-digit Aadhaar number",
    "Known fake/placeholder number blacklist",
    "First digit validity (must be 2–9)",
    "Sequential/repetitive digit detection",
    "UIDAI authority name presence",
    "Future date detection",
    "Placeholder text detection",
]
