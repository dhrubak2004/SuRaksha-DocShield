"""Bank Statement Validator"""
from __future__ import annotations
import re
from .common import check_future_dates, check_placeholder_text

FAKE_ACCOUNTS = {'1234567890','0000000000','9999999999','1111111111','1234567891'}

def validate(text: str) -> tuple[float, list[str]]:
    flags = []
    penalty = 0.0

    flags.extend(check_placeholder_text(text))
    flags.extend(check_future_dates(text))

    # IFSC: 4 letters + 0 + 6 alphanumeric
    ifsc = re.findall(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', text)
    if not ifsc:
        if re.search(r'bank\s+statement|account\s+statement|passbook', text, re.I):
            flags.append("⚠️ No valid IFSC code found in bank statement")
            penalty += 25
    else:
        # Known fake IFSCs
        for code in ifsc:
            if code in ('SBIN0000000', 'HDFC0000000', 'ICIC0000000'):
                flags.append(f"🚨 IFSC code {code} is a known test/placeholder value")
                penalty += 50

    # Account number (9-18 digits)
    acc_nums = re.findall(r'\b\d{9,18}\b', text)
    for acc in acc_nums:
        if acc in FAKE_ACCOUNTS:
            flags.append(f"🚨 Account number {acc} is a known placeholder")
            penalty += 60
        if len(set(acc)) == 1:
            flags.append(f"🚨 Account number {acc} is all same digit — definitely fake")
            penalty += 65

    # Transaction count
    txn_rows = re.findall(r'\b(?:debit|credit|dr|cr|withdrawal|deposit)\b', text, re.I)
    if len(txn_rows) < 2:
        flags.append("⚠️ Fewer than 2 debit/credit entries — statement may be incomplete or fabricated")
        penalty += 20

    # Opening/closing balance
    has_opening = bool(re.search(r'opening\s+balance|balance\s+b/f|balance\s+b\.f', text, re.I))
    has_closing = bool(re.search(r'closing\s+balance|balance\s+c/f|balance\s+c\.f', text, re.I))
    if not (has_opening and has_closing):
        flags.append("⚠️ Opening or closing balance not found — incomplete statement")
        penalty += 20

    # Bank name / branch
    if not re.search(r'bank|financial\s+institution', text, re.I):
        flags.append("⚠️ No bank name found on statement")
        penalty += 15

    # Account holder name
    if not re.search(r'account\s+(?:name|holder)|name\s*:', text, re.I):
        flags.append("⚠️ Account holder name not found")
        penalty += 10

    return max(0.0, 100.0 - penalty), flags


CHECKS = [
    "IFSC code format validation (4 letters + 0 + 6 alphanumeric)",
    "Known placeholder IFSC blacklist",
    "Account number placeholder/all-same-digit detection",
    "Minimum transaction count (≥2 entries)",
    "Opening and closing balance presence",
    "Bank name presence",
    "Account holder name presence",
    "Future date / placeholder text detection",
]
BANK_STATEMENT_CHECKS = CHECKS
CHEQUE_CHECKS = CHECKS