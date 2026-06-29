"""Indian Passport Validator"""
from __future__ import annotations
import re
from .common import check_future_dates, check_placeholder_text

def _mrz_check_digit(data: str) -> int:
    weights = [7, 3, 1]
    char_map = {str(i): i for i in range(10)}
    char_map.update({chr(c): c - 55 for c in range(65, 91)})
    char_map['<'] = 0
    return sum(char_map.get(c, 0) * weights[i % 3] for i, c in enumerate(data)) % 10

VALID_PASSPORT_STARTS = set('ABCDEFGHJKLMNPRSTUVWXYZ')  # I/O/Q rarely used

def validate(text: str) -> tuple[float, list[str]]:
    flags = []
    penalty = 0.0

    flags.extend(check_placeholder_text(text))
    flags.extend(check_future_dates(text))

    passport_nums = re.findall(r'\b([A-Z])(\d{7})\b', text)
    if not passport_nums:
        if re.search(r'passport|republic\s+of\s+india|ministry\s+of\s+external', text, re.I):
            flags.append("🚨 Passport document detected but no valid passport number (A1234567 format) found")
            penalty += 55
    else:
        for letter, digits in passport_nums:
            if letter not in VALID_PASSPORT_STARTS:
                flags.append(f"⚠️ Passport number starts with unusual letter '{letter}'")
                penalty += 20
            if len(set(digits)) == 1:
                flags.append(f"🚨 Passport number {letter}{digits} has all identical digits — likely fake")
                penalty += 50
            if digits in ('0000000', '1234567', '9999999'):
                flags.append(f"🚨 Passport number {letter}{digits} is a known placeholder")
                penalty += 60

    # MRZ line check (44 characters for TD3 format)
    mrz_lines = re.findall(r'[A-Z0-9<]{30,44}', text)
    for line in mrz_lines:
        if len(line) == 44:
            # Validate check digit on passport number (positions 44–52 in line 2)
            if re.match(r'^[A-Z0-9<]{44}$', line):
                # Try check digit on the number section
                num_section = line[0:9]
                check = int(line[9]) if line[9].isdigit() else -1
                if check >= 0 and _mrz_check_digit(num_section) != check:
                    flags.append("🚨 MRZ check digit validation failed — document may be forged")
                    penalty += 45

    # Country code check
    if not re.search(r'\bIND\b|INDIA|Republic of India', text, re.I):
        if re.search(r'passport', text, re.I):
            flags.append("⚠️ Country code 'IND' or 'India' not found on passport")
            penalty += 15

    return max(0.0, 100.0 - penalty), flags


CHECKS = [
    "Passport number format (letter + 7 digits)",
    "Valid starting letter (not I/O/Q)",
    "Repeated digit detection in passport number",
    "Known placeholder number blacklist",
    "MRZ line check digit validation",
    "Country code (IND/India) presence",
    "Future date / placeholder text detection",
]
