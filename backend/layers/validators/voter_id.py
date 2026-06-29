"""Voter ID (EPIC) Validator"""
from __future__ import annotations
import re
from .common import check_future_dates, check_placeholder_text

# EPIC number: 3 letters + 7 digits
EPIC_RE = re.compile(r'\b([A-Z]{3})(\d{7})\b')

FAKE_EPIC = {'ABC0000000','XYZ1234567','AAA0000001','ZZZ9999999'}

def validate(text: str) -> tuple[float, list[str]]:
    flags = []
    penalty = 0.0

    flags.extend(check_placeholder_text(text))
    flags.extend(check_future_dates(text))

    epics = EPIC_RE.findall(text)
    if not epics:
        if re.search(r'election\s+commission|voter|elector|epic', text, re.I):
            flags.append("🚨 Voter ID detected but no valid EPIC number (ABC1234567 format) found")
            penalty += 45
    else:
        for letters, digits in epics:
            full = letters + digits
            if full in FAKE_EPIC:
                flags.append(f"🚨 EPIC number {full} is a known fake/placeholder")
                penalty += 70
            if len(set(digits)) == 1:
                flags.append(f"🚨 EPIC number {full} has all identical digits — likely fake")
                penalty += 50
            if len(set(letters)) == 1:
                flags.append(f"⚠️ EPIC number {full} has all identical letters — suspicious")
                penalty += 30

    # Election Commission mention
    if not re.search(r'election\s+commission\s+of\s+india|e\.?c\.?i', text, re.I):
        if re.search(r'voter|electoral|elector', text, re.I):
            flags.append("⚠️ Election Commission of India not mentioned on Voter ID")
            penalty += 15

    # Part number / serial number
    if not re.search(r'part\s+no|serial\s+no|sl\.?\s*no', text, re.I):
        if re.search(r'voter|electoral', text, re.I):
            flags.append("⚠️ No part/serial number found on Voter ID")
            penalty += 10

    return max(0.0, 100.0 - penalty), flags


CHECKS = [
    "EPIC number format (3 letters + 7 digits)",
    "Known fake EPIC number blacklist",
    "Repeated digit/letter detection",
    "Election Commission of India mention",
    "Part/serial number presence",
    "Future date / placeholder text detection",
]
