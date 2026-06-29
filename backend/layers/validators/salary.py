"""Salary Slip / Pay Slip Validator"""
from __future__ import annotations
import re
from .common import check_future_dates, check_placeholder_text, extract_amounts, CURRENT_YEAR

def validate(text: str) -> tuple[float, list[str]]:
    flags = []
    penalty = 0.0

    flags.extend(check_placeholder_text(text))
    flags.extend(check_future_dates(text))

    amounts = extract_amounts(text)

    if amounts:
        max_amt = max(amounts)
        min_amt = min(amounts)

        # Implausibly zero
        if 0.0 in amounts:
            flags.append("🚨 Zero salary amount found — document likely incomplete or fake")
            penalty += 35

        # All perfectly round
        non_trivial = [a for a in amounts if a > 1000]
        if non_trivial and all(a % 10000 == 0 for a in non_trivial):
            flags.append("⚠️ All amounts are exact multiples of ₹10,000 — suspiciously round")
            penalty += 20

        # Implausibly large
        if max_amt > 10_000_000:
            flags.append(f"⚠️ Amount ₹{max_amt:,.0f} is unusually large — verify")
            penalty += 15

        # Gross vs net check: try to find gross and net salary
        gross_match = re.search(r'gross\s+(?:salary|pay|income)[^\d]*([\d,]+)', text, re.I)
        net_match   = re.search(r'net\s+(?:salary|pay|take[\s\-]?home)[^\d]*([\d,]+)', text, re.I)
        if gross_match and net_match:
            try:
                gross = float(gross_match.group(1).replace(',', ''))
                net   = float(net_match.group(1).replace(',', ''))
                if net > gross:
                    flags.append(f"🚨 Net salary (₹{net:,.0f}) exceeds gross (₹{gross:,.0f}) — mathematically impossible")
                    penalty += 60
            except ValueError:
                pass

    else:
        flags.append("🚨 No INR amounts found in salary slip")
        penalty += 40

    # Month/year
    months = re.findall(
        r'\b(January|February|March|April|May|June|July|August|September|October|November|December|'
        r'Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b',
        text, re.I
    )
    if not months:
        flags.append("⚠️ No month name found on salary slip")
        penalty += 15

    # Employer details
    if not re.search(r'(?:company|employer|organisation|ltd|pvt|llp|inc|corp)', text, re.I):
        flags.append("⚠️ No employer/company name found")
        penalty += 15

    # Employee name/ID
    if not re.search(r'employee\s+(?:name|id|code|no)', text, re.I):
        flags.append("⚠️ No employee name/ID field found")
        penalty += 10

    # PF / ESI / TDS (real slips always show deductions)
    if not re.search(r'\b(?:pf|provident\s+fund|epf|esi|tds|professional\s+tax)\b', text, re.I):
        flags.append("⚠️ No statutory deductions (PF/ESI/TDS) found — may be fabricated slip")
        penalty += 20

    return max(0.0, 100.0 - penalty), flags


CHECKS = [
    "Gross vs net salary mathematical consistency",
    "Zero salary detection",
    "Suspiciously round amounts",
    "Month/year presence",
    "Employer/company name presence",
    "Employee name/ID field presence",
    "Statutory deductions (PF/ESI/TDS) presence",
    "Future date / placeholder text detection",
]
