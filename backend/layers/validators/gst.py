"""GST Certificate Validator"""
from __future__ import annotations
import re
from .common import check_future_dates, check_placeholder_text

# GSTIN: 2-digit state code + 10-char PAN + 1 entity number + Z + 1 check
GSTIN_RE = re.compile(r'\b(\d{2})([A-Z]{3}[PCHABGJLFTE][A-Z]\d{4}[A-Z])(\d)Z([A-Z\d])\b')

VALID_STATE_CODES_GST = {
    '01','02','03','04','05','06','07','08','09','10',
    '11','12','13','14','15','16','17','18','19','20',
    '21','22','23','24','25','26','27','28','29','30',
    '31','32','33','34','35','36','37','38',
}

def validate(text: str) -> tuple[float, list[str]]:
    flags = []
    penalty = 0.0

    flags.extend(check_placeholder_text(text))
    flags.extend(check_future_dates(text))

    gstins = GSTIN_RE.findall(text)
    if not gstins:
        if re.search(r'gst|goods\s+and\s+services\s+tax|gstin', text, re.I):
            flags.append("🚨 GST document detected but no valid GSTIN (15-character format) found")
            penalty += 50
    else:
        for state_code, pan, entity, check in gstins:
            if state_code not in VALID_STATE_CODES_GST:
                flags.append(f"🚨 GSTIN state code '{state_code}' is invalid")
                penalty += 45
            full_gstin = f"{state_code}{pan}{entity}Z{check}"
            if full_gstin.upper() in ('07AABCU9603R1ZX', '29AABCU9603R1ZX'):
                flags.append(f"🚨 GSTIN {full_gstin} is a known test/demo number")
                penalty += 70

    # Certificate number
    if not re.search(r'certificate\s+(?:of\s+)?registration|reg(?:istration)?\s+no', text, re.I):
        if re.search(r'gst|gstin', text, re.I):
            flags.append("⚠️ No GST registration certificate number found")
            penalty += 15

    # Effective date
    if not re.search(r'effective\s+date|date\s+of\s+registration|valid\s+from', text, re.I):
        if re.search(r'gst', text, re.I):
            flags.append("⚠️ No effective/registration date found on GST certificate")
            penalty += 10

    return max(0.0, 100.0 - penalty), flags


CHECKS = [
    "GSTIN 15-character format validation",
    "State code validity (01–38)",
    "Embedded PAN format check",
    "Known test/demo GSTIN blacklist",
    "Registration certificate number presence",
    "Effective/registration date presence",
    "Future date / placeholder text detection",
]
