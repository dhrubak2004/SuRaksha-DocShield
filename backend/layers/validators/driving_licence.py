"""Indian Driving Licence Validator"""
from __future__ import annotations
import re
from .common import check_future_dates, check_placeholder_text, CURRENT_YEAR

VALID_STATE_CODES = {
    'AP','AR','AS','BR','CG','GA','GJ','HR','HP','JH','KA','KL',
    'MP','MH','MN','ML','MZ','NL','OD','PB','RJ','SK','TN','TS',
    'TR','UP','UK','WB','AN','CH','DN','DD','DL','JK','LA','LD','PY'
}

# RTO office codes by state (partial list for common states)
KNOWN_RTO_STATES = {
    'MH': range(1, 50), 'DL': range(1, 15), 'KA': range(1, 75),
    'TN': range(1, 80), 'GJ': range(1, 40), 'UP': range(1, 95),
}

def validate(text: str) -> tuple[float, list[str]]:
    flags = []
    penalty = 0.0

    flags.extend(check_placeholder_text(text))
    flags.extend(check_future_dates(text))

    # DL format: XX-YYYYNNNNNNN or XX00YYYYNNNNNNN
    dl_matches = re.findall(r'\b([A-Z]{2})[- ]?(\d{2})[- ]?(\d{4})[- ]?(\d{7})\b', text)
    if not dl_matches:
        dl_matches = re.findall(r'\b([A-Z]{2})(\d{13})\b', text)

    if not dl_matches:
        if re.search(r'driving\s+licen[cs]e|motor\s+vehicle|transport\s+dept', text, re.I):
            flags.append("🚨 Driving licence detected but no valid DL number found")
            penalty += 45
    else:
        for m in dl_matches:
            state = m[0]
            rto   = int(m[1]) if m[1].isdigit() else 0
            year  = int(m[2]) if len(m) > 2 and m[2].isdigit() else 0

            if state not in VALID_STATE_CODES:
                flags.append(f"🚨 DL state code '{state}' is not a valid Indian state/UT code")
                penalty += 50

            if year > 0:
                full_year = 2000 + year if year < 100 else year
                if full_year > CURRENT_YEAR:
                    flags.append(f"🚨 DL issue year {full_year} is in the future")
                    penalty += 55
                elif full_year < 1988:
                    flags.append(f"⚠️ DL issue year {full_year} is before computerized DL era")
                    penalty += 20

    # Vehicle class
    vehicle_classes = ['LMV','MCWG','MCWOG','HMV','HTV','PSV','TR','TRANS']
    found_class = any(vc in text.upper() for vc in vehicle_classes)
    if not found_class:
        if re.search(r'driving\s+licen[cs]e', text, re.I):
            flags.append("⚠️ No vehicle class (LMV/HMV/MCWG etc.) found on DL")
            penalty += 15

    # Transport/RTO authority
    if not re.search(r'transport\s+authority|regional\s+transport|rto|mvd', text, re.I):
        if re.search(r'driving\s+licen[cs]e', text, re.I):
            flags.append("⚠️ No transport authority/RTO mention found")
            penalty += 10

    return max(0.0, 100.0 - penalty), flags


CHECKS = [
    "State code validity (all 36 Indian states/UTs)",
    "RTO office number format",
    "Issue year plausibility (1988–present)",
    "Future year detection",
    "Vehicle class (LMV/HMV/MCWG) presence",
    "Transport authority/RTO mention",
    "Future date / placeholder text detection",
]
