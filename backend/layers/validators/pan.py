"""PAN Card Validator"""
from __future__ import annotations
import re
from .common import check_future_dates, check_placeholder_text

# Strict valid PAN: 3 letters + valid entity char + letter + 4 digits + letter
PAN_STRICT_RE = re.compile(r'\b([A-Z]{3})([PCHABGJLFTE])([A-Z])(\d{4})([A-Z])\b')

# Loose PAN: any 10-char alphanumeric that looks like a PAN (catches malformed ones)
PAN_LOOSE_RE  = re.compile(r'\b([A-Z]{5})(\d{4})([A-Z])\b')

PAN_TYPE_MAP = {
    'P':'Individual','C':'Company','H':'HUF','A':'AOP','B':'BOI',
    'G':'Government','J':'Artificial Juridical Person','L':'Local Authority',
    'F':'Firm','T':'Trust','E':'LLP',
}

VALID_ENTITY_CHARS = set('PCHABGJLFTE')

FAKE_PANS = {
    "ABCDE1234F","AAAAA0000A","ZZZZZ9999Z","ABCDE0000A",
    "PQRST1234U","TESTP1234A","XXXXX0000X","PPPPP0000P",
}

def validate(
    text: str,
    image=None,
    ocr_boxes=None,
    metadata=None,
    template_result=None
) -> tuple[float, list[str]]:
    flags = []
    penalty = 0.0

    flags.extend(check_placeholder_text(text))
    flags.extend(check_future_dates(text))

    is_pan_card = bool(re.search(
        r'permanent\s+account\s+number|income\s+tax\s+dep|pan\s+card|govt\.?\s+of\s+india',
        text, re.I
    ))

    # First try strict match
    strict_pans = PAN_STRICT_RE.findall(text)

    # Also try loose match to catch invalid entity char PANs
    loose_pans  = PAN_LOOSE_RE.findall(text)

    if not strict_pans and not loose_pans:
        if is_pan_card:
            flags.append("🚨 PAN card detected but no PAN number found")
            penalty += 55
        return max(0.0, 100.0 - penalty), flags

    # Check strict matches
    for m in strict_pans:
        pan = "".join(m)
        if pan in FAKE_PANS:
            flags.append(f"🚨 PAN {pan} is a known fake/placeholder")
            penalty += 70
        if m[3] == "0000":
            flags.append(f"🚨 PAN {pan}: digit section is 0000 — invalid")
            penalty += 40
        if len(set(m[0])) == 1:
            flags.append(f"⚠️ PAN {pan}: first 3 letters are identical — suspicious")
            penalty += 25

    # Check loose matches for invalid entity character
    for m in loose_pans:
        pan = "".join(m)
        entity_char = pan[3]  # 4th character
        if entity_char not in VALID_ENTITY_CHARS:
            flags.append(
                f"🚨 PAN {pan}: 4th character '{entity_char}' is not a valid entity type "
                f"(must be one of P/C/H/A/B/G/J/L/F/T/E) — PAN number is invalid"
            )
            penalty += 60

        if pan in FAKE_PANS:
            flags.append(f"🚨 PAN {pan} is a known fake/placeholder")
            penalty += 70

        # Digit section 0000
        if m[1] == "0000":
            flags.append(f"🚨 PAN {pan}: digit section is 0000 — invalid")
            penalty += 40

    # Income Tax dept mention
    if not re.search(r'income\s+tax|govt\.?\s+of\s+india', text, re.I):
        flags.append("⚠️ Income Tax / Govt of India not mentioned on document")
        penalty += 10

    return max(0.0, 100.0 - penalty), flags


CHECKS = [
    "PAN format validation (AAAAA0000A)",
    "4th character entity type validation (P/C/H/A/B/G/J/L/F/T/E)",
    "Malformed PAN detection (invalid entity char like S/D/I/K etc.)",
    "Known fake PAN number blacklist",
    "Digit section validity (not 0000)",
    "Repeated first-3-letter detection",
    "Income Tax / Govt of India authority mention",
    "Future date / placeholder text detection",
]