"""
SuRaksha DocShield — Document-Specific Validator (v2)
Routes to per-document validator modules. Covers 14 document types.
"""
from __future__ import annotations
from layers.template_validator import validate_template
import re
import numpy as np
import cv2
from dataclasses import dataclass, field
from PIL import Image

from .validators.common import check_placeholder_text, check_future_dates
from .validators import aadhaar, pan, passport, driving_licence, voter_id, gst, salary
from .validators.bank_statement import validate as validate_bank_statement, BANK_STATEMENT_CHECKS
from .validators.cheque import validate as validate_cheque, CHEQUE_CHECKS
from .validators.others import (
    validate_passbook,  PASSBOOK_CHECKS,
    validate_property,  PROPERTY_CHECKS,
    validate_birth_certificate, BIRTH_CERT_CHECKS,
    validate_itr,       ITR_CHECKS,
    validate_fd_receipt, FD_CHECKS,
    validate_loan_doc,  LOAN_CHECKS,
)

# ─────────────────────────────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────────────────────────────
@dataclass
class DocValidationResult:
    doc_type: str = "UNKNOWN"
    doc_score: float = 100.0      # 0-100, 100 = clean
    flags: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    checks_performed: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────
# Document type detector
# ─────────────────────────────────────────────────────────────────────
_TYPE_MAP = [
    ("AADHAAR",        r'aadhaar|aadhar|uidai|unique\s+identification\s+authority'),
    ("PAN",            r'permanent\s+account\s+number|pan\s+card|income\s+tax\s+dep'),
    ("PASSPORT",       r'passport|ministry\s+of\s+external\s+affairs|place\s+of\s+birth'),
    ("DRIVING_LICENCE",r'driving\s+licen[cs]e|motor\s+vehicles?\s+act|transport\s+dep'),
    ("VOTER_ID",       r'election\s+commission|electoral|epic|voter'),
    ("GST",            r'\bgstin\b|goods\s+and\s+services\s+tax|gst\s+certif'),
    ("SALARY_SLIP",    r'salary\s+slip|pay\s+slip|payslip|salary\s+certif|pay\s+stub'),
    ("ITR",            r'income\s+tax\s+return|itr[\s\-]|acknowledgement\s+number|assessment\s+year'),
    ("BANK_STATEMENT", r'bank\s+statement|account\s+statement|statement\s+of\s+account'),
    ("PASSBOOK",       r'passbook|savings\s+(?:bank\s+)?account|pass\s+book'),
    ("CHEQUE",         r'\bcheque\b|\bcheck\b|pay\s+to\s+(?:the\s+)?order|bearer'),
    ("FD_RECEIPT",     r'fixed\s+deposit|fd\s+receipt|term\s+deposit|recurring\s+deposit'),
    ("LOAN_DOC",       r'loan\s+agreement|sanction\s+letter|loan\s+account|emi\s+schedule'),
    ("PROPERTY_DOC",   r'sale\s+deed|property|survey\s+number|sub[\s\-]?registrar|stamp\s+duty'),
    ("BIRTH_CERT",     r'birth\s+certif|date\s+of\s+birth\s+certif|born\s+on'),
    ("INCOME_DOC",     r'income\s+certif|salary\s+certif|form\s+16|form\s+26as'),
]

def detect_doc_type(text: str) -> str:
    tl = text.lower()
    for doc_type, pattern in _TYPE_MAP:
        if re.search(pattern, tl):
            return doc_type
    return "GENERIC"


# ─────────────────────────────────────────────────────────────────────
# Photo region: avatar / AI illustration detector
# ─────────────────────────────────────────────────────────────────────
def _detect_avatar_photo(image: Image.Image) -> tuple[bool, float]:
    arr = np.array(image.convert("RGB"))
    h, w = arr.shape[:2]
    photo_region = arr[int(h*0.2):int(h*0.8), int(w*0.05):int(w*0.35)]
    if photo_region.size == 0:
        return False, 0.0

    resized = cv2.resize(photo_region, (50, 50))
    pixels = resized.reshape(-1, 3)
    unique_colours = len(np.unique(pixels, axis=0))

    gray = cv2.cvtColor(photo_region, cv2.COLOR_RGB2GRAY)
    local_var = cv2.Laplacian(gray, cv2.CV_64F).var()

    hsv = cv2.cvtColor(photo_region, cv2.COLOR_RGB2HSV)
    skin_mask = cv2.inRange(hsv, np.array([0, 20, 70]), np.array([25, 255, 255]))
    skin_pixels = photo_region[skin_mask > 0]
    skin_uniformity = 0.0
    if len(skin_pixels) > 100:
        skin_std = np.std(skin_pixels.astype(float), axis=0).mean()
        skin_uniformity = max(0, 1 - skin_std / 50)

    score = 0.0
    if unique_colours < 150:   score += 40
    elif unique_colours < 300: score += 20
    if local_var < 200:        score += 30
    elif local_var < 500:      score += 15
    if skin_uniformity > 0.7:  score += 30

    return score >= 55, min(score, 100.0)


# ─────────────────────────────────────────────────────────────────────
# Checks + routing tables
# ─────────────────────────────────────────────────────────────────────
ID_CARD_TYPES = {"AADHAAR", "PAN", "PASSPORT", "DRIVING_LICENCE", "VOTER_ID"}

_VALIDATOR_MAP = {
    "AADHAAR":         (aadhaar.validate,               aadhaar.CHECKS),
    "PAN":             (pan.validate,                   pan.CHECKS),
    "PASSPORT":        (passport.validate,              passport.CHECKS),
    "DRIVING_LICENCE": (driving_licence.validate,       driving_licence.CHECKS),
    "VOTER_ID":        (voter_id.validate,              voter_id.CHECKS),
    "GST":             (gst.validate,                   gst.CHECKS),
    "SALARY_SLIP":     (salary.validate,                salary.CHECKS),
    "BANK_STATEMENT":  (validate_bank_statement,        BANK_STATEMENT_CHECKS),
    "PASSBOOK":        (validate_passbook,              PASSBOOK_CHECKS),
    "CHEQUE":          (validate_cheque,                CHEQUE_CHECKS),
    "FD_RECEIPT":      (validate_fd_receipt,            FD_CHECKS),
    "LOAN_DOC":        (validate_loan_doc,              LOAN_CHECKS),
    "PROPERTY_DOC":    (validate_property,              PROPERTY_CHECKS),
    "BIRTH_CERT":      (validate_birth_certificate,     BIRTH_CERT_CHECKS),
    "ITR":             (validate_itr,                   ITR_CHECKS),
}

GENERIC_CHECKS_LIST = ["Placeholder text detection (Lorem ipsum, XXXX, test/demo labels)", "Future date detection"]


# ─────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────
def validate_document(text: str, image: Image.Image, ocr_boxes=None, metadata=None) -> DocValidationResult:
    result = DocValidationResult()
    doc_type = detect_doc_type(text)
    result.doc_type = doc_type

    all_flags: list[str] = []
    total_penalty: float = 0.0

    # Generic checks always run
    all_flags.extend(check_placeholder_text(text))
    all_flags.extend(check_future_dates(text))

    # Photo region analysis for ID cards
    if doc_type in ID_CARD_TYPES:
        is_avatar, avatar_conf = _detect_avatar_photo(image)
        result.details["avatar_confidence"] = avatar_conf
        if is_avatar:
            all_flags.append(
                f"🚨 Photo region appears to be a cartoon/avatar/AI illustration "
                f"(confidence {avatar_conf:.0f}%) — not a real photograph"
            )
            total_penalty += 45

    # Per-document validation
    if doc_type in _VALIDATOR_MAP:
        validator_fn, checks = _VALIDATOR_MAP[doc_type]
        template_result = validate_template(image, doc_type)
        score, flags = validator_fn(text=text,image=image,template_result=template_result) 
        all_flags.extend(flags)
        total_penalty += (100.0 - score)
        result.checks_performed = checks
    else:
        result.checks_performed = GENERIC_CHECKS_LIST

    # Generic placeholder penalty already counted via flags above
    generic_penalty = len([f for f in all_flags if "placeholder" in f.lower() or "Lorem" in f]) * 40
    total_penalty += generic_penalty

    result.flags = all_flags
    result.doc_score = max(0.0, 100.0 - total_penalty)
    return result