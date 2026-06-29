"""Additional document validators: Passbook, Property, Birth Certificate, ITR, FD, Loan"""
from __future__ import annotations
import re
from .common import check_future_dates, check_placeholder_text, extract_amounts, CURRENT_YEAR


# ─── PASSBOOK ────────────────────────────────────────────────────────
def validate_passbook(text: str) -> tuple[float, list[str]]:
    flags = list(check_placeholder_text(text)) + list(check_future_dates(text))
    penalty = 0.0

    if not re.findall(r'\b[A-Z]{4}0[A-Z0-9]{6}\b', text):
        flags.append("⚠️ No IFSC code found in passbook")
        penalty += 20

    if not re.search(r'account\s+(?:no|number)|a/c\s+no', text, re.I):
        flags.append("⚠️ No account number field found in passbook")
        penalty += 15

    if not re.search(r'balance', text, re.I):
        flags.append("⚠️ No balance column found in passbook")
        penalty += 20

    txns = re.findall(r'\b(?:debit|credit|dr|cr)\b', text, re.I)
    if len(txns) < 1:
        flags.append("⚠️ No transactions found in passbook")
        penalty += 25

    return max(0.0, 100.0 - penalty), flags

PASSBOOK_CHECKS = [
    "IFSC code presence",
    "Account number field presence",
    "Balance column presence",
    "Transaction entries presence",
    "Future date / placeholder text detection",
]


# ─── PROPERTY DOC ─────────────────────────────────────────────────────
def validate_property(text: str) -> tuple[float, list[str]]:
    flags = list(check_placeholder_text(text)) + list(check_future_dates(text))
    penalty = 0.0

    if not re.search(r'survey\s+(?:no|number|#)', text, re.I):
        flags.append("⚠️ No survey number found in property document")
        penalty += 20

    if not re.search(r'reg(?:istration)?\s+(?:no|number|#)', text, re.I):
        flags.append("⚠️ No registration number found")
        penalty += 20

    if not re.search(r'stamp\s+duty|e-?stamp|franking', text, re.I):
        flags.append("⚠️ No stamp duty mention — may be unregistered")
        penalty += 15

    if not re.search(r'sub[\s\-]?registrar|registrar\s+(?:of\s+)?(?:assurances|office)', text, re.I):
        flags.append("⚠️ No sub-registrar office mentioned")
        penalty += 10

    if not re.search(r'schedule\s+of\s+property|boundaries|bounded\s+by', text, re.I):
        flags.append("⚠️ No property schedule/boundaries description found")
        penalty += 10

    amounts = extract_amounts(text)
    if not amounts:
        flags.append("⚠️ No sale consideration amount found in property document")
        penalty += 15

    return max(0.0, 100.0 - penalty), flags

PROPERTY_CHECKS = [
    "Survey number presence",
    "Registration number presence",
    "Stamp duty / e-stamp mention",
    "Sub-registrar office mention",
    "Property boundaries/schedule description",
    "Sale consideration amount presence",
    "Future date / placeholder text detection",
]


# ─── BIRTH CERTIFICATE ───────────────────────────────────────────────
def validate_birth_certificate(text: str) -> tuple[float, list[str]]:
    flags = list(check_placeholder_text(text)) + list(check_future_dates(text))
    penalty = 0.0

    if not re.search(r'registrar|municipal|corporation|panchayat|birth\s+(?:and\s+)?death', text, re.I):
        flags.append("⚠️ No registrar/municipal authority mentioned on birth certificate")
        penalty += 25

    if not re.search(r'registration\s+(?:no|number)|cert(?:ificate)?\s+(?:no|number)', text, re.I):
        flags.append("⚠️ No certificate registration number found")
        penalty += 20

    if not re.search(r'date\s+of\s+birth|born\s+on', text, re.I):
        flags.append("⚠️ No date of birth found on birth certificate")
        penalty += 20

    if not re.search(r'father|mother|parent', text, re.I):
        flags.append("⚠️ No parent/guardian name found on birth certificate")
        penalty += 15

    if not re.search(r'place\s+of\s+birth|born\s+at|hospital|nursing\s+home', text, re.I):
        flags.append("⚠️ No place of birth found")
        penalty += 10

    return max(0.0, 100.0 - penalty), flags

BIRTH_CERT_CHECKS = [
    "Registrar/municipal authority mention",
    "Certificate registration number",
    "Date of birth field",
    "Parent/guardian name",
    "Place of birth",
    "Future date / placeholder text detection",
]


# ─── ITR (Income Tax Return) ──────────────────────────────────────────
def validate_itr(text: str) -> tuple[float, list[str]]:
    flags = list(check_placeholder_text(text)) + list(check_future_dates(text))
    penalty = 0.0

    # Acknowledgement number: 15 digits
    ack_nums = re.findall(r'\b\d{15}\b', text)
    if not ack_nums:
        flags.append("⚠️ No ITR acknowledgement number (15 digits) found")
        penalty += 30
    else:
        for a in ack_nums:
            if len(set(a)) == 1:
                flags.append(f"🚨 Acknowledgement number {a} is all same digit — fake")
                penalty += 55

    # Assessment year
    if not re.search(r'assessment\s+year|A\.?Y\.?\s*20\d{2}', text, re.I):
        flags.append("⚠️ No assessment year (AY) found in ITR")
        penalty += 20

    # PAN
    pan = re.findall(r'\b[A-Z]{3}[PCHABGJLFTE][A-Z]\d{4}[A-Z]\b', text)
    if not pan:
        flags.append("⚠️ No PAN number found in ITR document")
        penalty += 25

    # Gross total income
    if not re.search(r'gross\s+total\s+income|total\s+income|taxable\s+income', text, re.I):
        flags.append("⚠️ No income figure found in ITR")
        penalty += 15

    # CPC/e-filing portal
    if not re.search(r'cpc|income\s+tax\s+dept|e-?filing|efiling', text, re.I):
        flags.append("⚠️ No CPC/e-filing authority found — may not be official ITR")
        penalty += 15

    return max(0.0, 100.0 - penalty), flags

ITR_CHECKS = [
    "15-digit acknowledgement number presence and validity",
    "Assessment year (AY) presence",
    "PAN number presence",
    "Gross/total income figure",
    "CPC/e-filing authority mention",
    "Future date / placeholder text detection",
]


# ─── FIXED DEPOSIT RECEIPT ───────────────────────────────────────────
def validate_fd_receipt(text: str) -> tuple[float, list[str]]:
    flags = list(check_placeholder_text(text)) + list(check_future_dates(text))
    penalty = 0.0

    # FD/deposit number
    if not re.search(r'(?:fd|deposit|receipt)\s+(?:no|number|#)', text, re.I):
        flags.append("⚠️ No FD/deposit number found")
        penalty += 20

    amounts = extract_amounts(text)
    if not amounts:
        flags.append("🚨 No principal amount found in FD receipt")
        penalty += 40
    else:
        if max(amounts) < 1000:
            flags.append("⚠️ FD principal amount is less than ₹1,000 — unusually small")
            penalty += 15

    # Rate of interest
    if not re.search(r'(?:rate\s+of\s+interest|interest\s+rate|roi|p\.?a\.?)\s*[:\-]?\s*\d', text, re.I):
        flags.append("⚠️ No interest rate found on FD receipt")
        penalty += 15

    # Maturity date/amount
    if not re.search(r'maturity\s+(?:date|amount|value)', text, re.I):
        flags.append("⚠️ No maturity date/amount found on FD receipt")
        penalty += 15

    # Bank/NBFC name
    if not re.search(r'bank|nbfc|financial\s+(?:institution|services)', text, re.I):
        flags.append("⚠️ No bank/financial institution name found")
        penalty += 15

    return max(0.0, 100.0 - penalty), flags

FD_CHECKS = [
    "FD/deposit number presence",
    "Principal amount presence and plausibility",
    "Interest rate presence",
    "Maturity date/amount presence",
    "Bank/NBFC name presence",
    "Future date / placeholder text detection",
]


# ─── LOAN DOCUMENT ───────────────────────────────────────────────────
def validate_loan_doc(text: str) -> tuple[float, list[str]]:
    flags = list(check_placeholder_text(text)) + list(check_future_dates(text))
    penalty = 0.0

    # Loan account number
    if not re.search(r'loan\s+(?:account\s+)?(?:no|number|#|id)', text, re.I):
        flags.append("⚠️ No loan account number found")
        penalty += 20

    amounts = extract_amounts(text)
    if not amounts:
        flags.append("🚨 No loan amount found")
        penalty += 40

    # EMI
    if not re.search(r'emi|equated\s+monthly\s+install', text, re.I):
        flags.append("⚠️ No EMI details found in loan document")
        penalty += 15

    # Tenure
    if not re.search(r'tenure|term|period\s+of\s+loan', text, re.I):
        flags.append("⚠️ No loan tenure/term found")
        penalty += 10

    # Borrower name
    if not re.search(r'borrower|applicant|customer\s+name', text, re.I):
        flags.append("⚠️ No borrower name found")
        penalty += 15

    # Lender
    if not re.search(r'bank|nbfc|lender|financier', text, re.I):
        flags.append("⚠️ No lender/bank name found in loan document")
        penalty += 15

    # Sanction letter / disbursement
    if not re.search(r'sanction|disburse|disbursement', text, re.I):
        if not re.search(r'agreement|deed', text, re.I):
            flags.append("⚠️ No sanction/disbursement or agreement mention")
            penalty += 10

    return max(0.0, 100.0 - penalty), flags

LOAN_CHECKS = [
    "Loan account number presence",
    "Loan amount presence",
    "EMI details presence",
    "Loan tenure/term presence",
    "Borrower name presence",
    "Lender/bank name presence",
    "Sanction/disbursement/agreement mention",
    "Future date / placeholder text detection",
]
