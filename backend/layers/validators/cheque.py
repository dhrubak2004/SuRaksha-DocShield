"""Cheque Validator"""
from __future__ import annotations
import re
from .common import check_future_dates, check_placeholder_text

def validate(text: str) -> tuple[float, list[str]]:
    flags = []
    penalty = 0.0

    flags.extend(check_placeholder_text(text))
    flags.extend(check_future_dates(text))

    # MICR code (9 digits at bottom of cheque)
    micr = re.findall(r'\b\d{9}\b', text)
    if not micr:
        flags.append("⚠️ No MICR code (9-digit) found on cheque")
        penalty += 20
    else:
        for m in micr:
            if len(set(m)) == 1:
                flags.append(f"🚨 MICR code {m} is all same digit — fake")
                penalty += 50

    # Cheque number (6 digits)
    cheque_no = re.findall(r'\b\d{6}\b', text)
    if not cheque_no:
        flags.append("⚠️ No 6-digit cheque number found")
        penalty += 15

    # Payee name
    if not re.search(r'pay(?:ee)?\s*:|pay\s+to\s+(?:the\s+)?order', text, re.I):
        flags.append("⚠️ No payee field found on cheque")
        penalty += 15

    # Amount in words
    if not re.search(r'rupees?\s+\w+|in\s+words', text, re.I):
        flags.append("⚠️ Amount in words not found on cheque")
        penalty += 15

    # IFSC
    ifsc = re.findall(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', text)
    if not ifsc:
        flags.append("⚠️ No IFSC code found on cheque")
        penalty += 10

    # Signature line
    if not re.search(r'sign(?:ature)?|authoris(?:ed)?\s+sign', text, re.I):
        flags.append("⚠️ No signature field found on cheque")
        penalty += 10

    return max(0.0, 100.0 - penalty), flags


CHECKS = [
    "MICR code (9-digit) presence and validity",
    "6-digit cheque number presence",
    "Payee name field presence",
    "Amount in words presence",
    "IFSC code presence",
    "Signature field presence",
    "Future date / placeholder text detection",
]
CHEQUE_CHECKS = CHECKS