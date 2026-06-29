"""
SuRaksha DocShield — Penalty-Based Risk Scoring Engine (v3)

Architecture:
  - Start at 100
  - Deduct weighted penalties for each failed rule
  - Hard caps enforce maximums when critical failures occur
  - Hash integrity only detects duplicates/blacklist — never inflates score
  - Visual tampering is separate from authenticity
  - Genuine docs score 90+, fabricated docs score <30

Import strategy: uses importlib to avoid sys.path fragility on Windows.
"""
from __future__ import annotations
import sys
import importlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# ── Ensure backend root is on sys.path (works on Windows + Linux) ────
_BACKEND = Path(__file__).resolve().parent.parent   # .../docshield/backend
_LAYERS  = Path(__file__).resolve().parent          # .../docshield/backend/layers

for _p in [str(_BACKEND), str(_LAYERS)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from .visual_forensics import VisualResult
from .semantic_nlp     import SemanticResult
from .crypto_hash      import HashResult
from .doc_validator    import DocValidationResult


# ════════════════════════════════════════════════════════════════════
# CONFIGURATION  — all tuneable values in one place
# ════════════════════════════════════════════════════════════════════

# Penalty per severity level
PENALTIES = {
    "CRITICAL": 65,   # checksum fail, mathematically impossible
    "HIGH":     35,   # format invalid, known fake number
    "MEDIUM":   15,   # suspicious pattern, missing recommended field
    "LOW":       5,   # missing optional field
}

# Hard caps: when a rule triggers this key, final score cannot exceed the value
HARD_CAPS = {
    "aadhaar_verhoeff":      20,
    "aadhaar_known_fake":    15,
    "pan_invalid_entity":    30,
    "pan_known_fake":        20,
    "passport_mrz_fail":     20,
    "gst_invalid_gstin":     25,
    "salary_impossible":     35,
    "cheque_mismatch":       20,
    "duplicate_known_fraud": 10,
    "dummy_document":        15,
    "ela_severe_tamper":     45,
    "copy_move_severe":      50,
}

# ELA thresholds — genuine scans naturally have some ELA noise
ELA_SEVERE   = 55    # clear manipulation → CRITICAL
ELA_HIGH     = 30    # possible editing → HIGH
ELA_NOISE    = 12    # scan/compression noise → ignore (no penalty)

# Copy-move thresholds
CM_SEVERE    = 45
CM_HIGH      = 20

# Dummy/sample document patterns
DUMMY_PATTERNS = [
    (r"\bSAMPLE\b",              "CRITICAL", "SAMPLE watermark"),
    (r"\bSPECIMEN\b",            "CRITICAL", "SPECIMEN watermark"),
    (r"\bNOT\s+VALID\b",         "CRITICAL", "NOT VALID watermark"),
    (r"\bFOR\s+TRAINING\b",      "CRITICAL", "FOR TRAINING label"),
    (r"\bDUMMY\b",               "CRITICAL", "DUMMY label"),
    (r"\bLorem\s+ipsum\b",       "CRITICAL", "Lorem ipsum placeholder"),
    (r"\bXXXXXXX+\b",            "CRITICAL", "XXXXXXX placeholder"),
    (r"\bTEST\s+ONLY\b",         "HIGH",     "TEST ONLY label"),
    (r"\bDEMO\b",                "HIGH",     "DEMO label"),
    (r"\b123456789012\b",        "CRITICAL", "Known fake Aadhaar 123456789012"),
    (r"\b000000000000\b",        "CRITICAL", "All-zero placeholder"),
    (r"\b111111111111\b",        "CRITICAL", "All-ones placeholder"),
    (r"\bDD[\/\-]MM[\/\-]YYYY\b","HIGH",     "Unfilled date template DD/MM/YYYY"),
    (r"\bNAME\s+HERE\b",         "HIGH",     "Unfilled NAME HERE placeholder"),
]

# 5-tier risk categories
RISK_CATEGORIES = [
    (90, "VERIFIED GENUINE",   "LOW",      "✅ Document appears authentic. Proceed with standard due diligence."),
    (75, "LIKELY GENUINE",     "LOW",      "✅ Document likely authentic. Minor manual review recommended."),
    (50, "NEEDS REVIEW",       "MEDIUM",   "⚠️ Significant issues found. Manual review by senior underwriter required before processing."),
    (25, "HIGH RISK",          "HIGH",     "🚨 Multiple validation failures. Senior underwriter review mandatory. Do NOT process without verification."),
    (0,  "LIKELY FRAUDULENT",  "CRITICAL", "🚨 Document likely fraudulent. REJECT immediately and escalate to fraud investigation team."),
]

def _risk_category(score: float) -> tuple[str, str, str]:
    for threshold, label, risk, rec in RISK_CATEGORIES:
        if score >= threshold:
            return label, risk, rec
    return "LIKELY FRAUDULENT", "CRITICAL", RISK_CATEGORIES[-1][3]


# ════════════════════════════════════════════════════════════════════
# RULE RESULT  — single validation finding
# ════════════════════════════════════════════════════════════════════

@dataclass
class RuleResult:
    rule_name:        str
    severity:         str          # CRITICAL / HIGH / MEDIUM / LOW / PASS
    penalty:          float
    reason:           str
    passed:           bool = True
    hard_cap_key:     Optional[str] = None
    suggested_action: str = ""

    @classmethod
    def ok(cls, name: str, reason: str) -> "RuleResult":
        return cls(rule_name=name, severity="PASS", penalty=0.0, reason=reason, passed=True)

    @classmethod
    def fail(cls, name: str, severity: str, reason: str,
             penalty: Optional[float] = None,
             cap_key: Optional[str] = None,
             action: str = "") -> "RuleResult":
        p = penalty if penalty is not None else float(PENALTIES.get(severity, 15))
        return cls(rule_name=name, severity=severity, penalty=p,
                   reason=reason, passed=False,
                   hard_cap_key=cap_key, suggested_action=action)


# ════════════════════════════════════════════════════════════════════
# RULE MODULES  — each returns list[RuleResult]
# ════════════════════════════════════════════════════════════════════

import re as _re

def _dummy_rules(text: str) -> list[RuleResult]:
    rules = []
    for pattern, severity, label in DUMMY_PATTERNS:
        if _re.search(pattern, text, _re.I):
            rules.append(RuleResult.fail(
                "dummy_marker", severity,
                f"🚨 {label} detected — document is a sample/test copy",
                penalty=float(PENALTIES[severity]),
                cap_key="dummy_document",
                action="Reject — this is a training/sample document, not a real one",
            ))
    if not rules:
        rules.append(RuleResult.ok("dummy_marker", "✅ No dummy/sample markers detected"))
    return rules


def _future_date_rules(text: str) -> list[RuleResult]:
    rules = []
    for m in _re.finditer(r'\b(\d{1,2})[\/\-\.](\d{1,2})[\/\-\.](\d{4})\b', text):
        try:
            y = int(m.group(3))
            if y > 2026:
                rules.append(RuleResult.fail(
                    "future_date", "CRITICAL",
                    f"🚨 Future date {m.group()} found — document cannot be from {y}",
                    action="Reject — document contains an impossible future date",
                ))
        except ValueError:
            pass
    if not rules:
        rules.append(RuleResult.ok("future_date", "✅ No future dates detected"))
    return rules


def _visual_rules(visual: VisualResult) -> list[RuleResult]:
    rules = []
    ela = visual.ela_score

    if ela >= ELA_SEVERE:
        rules.append(RuleResult.fail(
            "ela_tamper", "CRITICAL",
            f"🚨 ELA score {ela:.1f}/100 — strong evidence of image manipulation",
            penalty=60.0, cap_key="ela_severe_tamper",
            action="Document image has been edited — reject",
        ))
    elif ela >= ELA_HIGH:
        rules.append(RuleResult.fail(
            "ela_tamper", "HIGH",
            f"⚠️ ELA score {ela:.1f}/100 — possible image editing",
            penalty=28.0,
        ))
    elif ela >= ELA_NOISE:
        rules.append(RuleResult.fail(
            "ela_tamper", "LOW",
            f"ℹ️ ELA score {ela:.1f}/100 — minor compression artefacts (normal for scans)",
            penalty=3.0,
        ))
    else:
        rules.append(RuleResult.ok("ela_tamper",
            f"✅ ELA score {ela:.1f}/100 — no tampering detected"))

    cm = visual.copy_move_score
    if cm >= CM_SEVERE:
        rules.append(RuleResult.fail(
            "copy_move", "CRITICAL",
            f"🚨 Copy-move score {cm:.1f}/100 — cloned regions detected",
            penalty=55.0, cap_key="copy_move_severe",
            action="Document contains duplicated regions — tampered",
        ))
    elif cm >= CM_HIGH:
        rules.append(RuleResult.fail(
            "copy_move", "HIGH",
            f"⚠️ Copy-move score {cm:.1f}/100 — suspicious region duplication",
            penalty=25.0,
        ))
    else:
        rules.append(RuleResult.ok("copy_move",
            f"✅ Copy-move score {cm:.1f}/100 — no duplication"))

    meta = visual.metadata_score
    if meta >= 50:
        rules.append(RuleResult.fail(
            "metadata", "HIGH",
            f"⚠️ Metadata anomaly {meta:.1f}/100 — EXIF/PDF metadata suspicious",
            penalty=20.0,
        ))
    elif meta >= 20:
        rules.append(RuleResult.fail(
            "metadata", "LOW",
            f"ℹ️ Metadata score {meta:.1f}/100 — minor inconsistency",
            penalty=4.0,
        ))
    else:
        rules.append(RuleResult.ok("metadata",
            f"✅ Metadata score {meta:.1f}/100 — no anomalies"))

    return rules


def _hash_rules(hash_result: HashResult) -> list[RuleResult]:
    """
    Hash only detects duplicates / blacklisted entries.
    A UNIQUE hash is neutral — it does NOT add authenticity points.
    """
    rules = []
    if hash_result.is_duplicate:
        prev = hash_result.previous_record or {}
        prev_status = prev.get("status", "?")
        penalty = 55.0 if prev_status == "FRAUD" else 30.0
        cap = "duplicate_known_fraud" if prev_status == "FRAUD" else None
        rules.append(RuleResult.fail(
            "duplicate_hash", "HIGH" if not cap else "CRITICAL",
            f"{'🚨' if cap else '⚠️'} SHA-256 matches prior submission: "
            f"{prev.get('filename','?')} (was: {prev_status})",
            penalty=penalty, cap_key=cap,
            action="Investigate duplicate submission",
        ))
    else:
        rules.append(RuleResult.ok("hash_unique",
            "✅ Document hash is unique — not seen before (neutral)"))
    return rules


def _semantic_rules(semantic: SemanticResult) -> list[RuleResult]:
    """OCR quality check. Low word count = unreliable extraction = penalty."""
    rules = []
    if semantic.ocr_result:
        wc = len(semantic.ocr_result.text.split())
        if wc < 5:
            rules.append(RuleResult.fail(
                "ocr_quality", "MEDIUM",
                f"⚠️ OCR extracted only {wc} words — document may be blank or unreadable",
                penalty=12.0,
                action="Try higher resolution scan or pre-process the image",
            ))
        else:
            rules.append(RuleResult.ok("ocr_quality",
                f"✅ OCR extracted {wc} words (confidence separate from authenticity)"))

    for issue in getattr(semantic, "inconsistencies", []):
        rules.append(RuleResult.fail(
            "semantic_inconsistency", "MEDIUM",
            f"⚠️ {issue}", penalty=float(PENALTIES["MEDIUM"]),
        ))
    return rules


def _doc_specific_rules(text: str, doc_type: str) -> list[RuleResult]:
    """
    Route to existing per-document validators, convert flags → RuleResult.
    Reuses all existing validator modules unchanged.
    """
    try:
        from layers.validators import (
            aadhaar, pan, passport, driving_licence, voter_id, gst, salary
        )
        from layers.validators.bank_statement import validate as _bank
        from layers.validators.cheque        import validate as _cheque
        from layers.validators.others import (
            validate_passbook        as _passbook,
            validate_property        as _property,
            validate_birth_certificate as _birth,
            validate_itr             as _itr,
            validate_fd_receipt      as _fd,
            validate_loan_doc        as _loan,
        )
    except ImportError as e:
        return [RuleResult.ok("import_error",
            f"⚠️ Could not load validators: {e}")]

    _MAP = {
        "AADHAAR":         aadhaar.validate,
        "PAN":             pan.validate,
        "PASSPORT":        passport.validate,
        "DRIVING_LICENCE": driving_licence.validate,
        "VOTER_ID":        voter_id.validate,
        "GST":             gst.validate,
        "SALARY_SLIP":     salary.validate,
        "BANK_STATEMENT":  _bank,
        "CHEQUE":          _cheque,
        "PASSBOOK":        _passbook,
        "PROPERTY_DOC":    _property,
        "BIRTH_CERT":      _birth,
        "ITR":             _itr,
        "FD_RECEIPT":      _fd,
        "LOAN_DOC":        _loan,
    }

    fn = _MAP.get(doc_type)
    if not fn:
        return [RuleResult.ok("no_validator",
            f"ℹ️ No specific validator for doc type: {doc_type}")]

    _score, flags = fn(text)
    return _flags_to_rules(flags, doc_type)


def _flags_to_rules(flags: list[str], doc_type: str) -> list[RuleResult]:
    """Convert validator flag strings → RuleResult with correct severity + hard cap."""
    rules = []
    dt = doc_type.lower()

    for flag in flags:
        is_critical = flag.startswith("🚨")
        is_warning  = flag.startswith("⚠️")

        if not (is_critical or is_warning):
            continue

        # Determine severity
        flag_low = flag.lower()
        if is_critical:
            severity = "CRITICAL" if any(k in flag_low for k in [
                "verhoeff", "mathematically", "known fake", "impossible",
                "known placeholder", "future date", "entity type",
                "mrz check", "invalid gstin", "net salary",
            ]) else "HIGH"
        else:
            severity = "MEDIUM"

        penalty = float(PENALTIES[severity])

        # Hard cap mapping
        cap_key = None
        if "verhoeff" in flag_low:
            cap_key = "aadhaar_verhoeff"
        elif "known fake" in flag_low and doc_type == "AADHAAR":
            cap_key = "aadhaar_known_fake"
        elif "known fake" in flag_low and doc_type == "PAN":
            cap_key = "pan_known_fake"
        elif "entity type" in flag_low or "4th character" in flag_low:
            cap_key = "pan_invalid_entity"
        elif "mrz check digit" in flag_low:
            cap_key = "passport_mrz_fail"
        elif "invalid gstin" in flag_low or "gstin state" in flag_low:
            cap_key = "gst_invalid_gstin"
        elif "net salary" in flag_low and "exceeds gross" in flag_low:
            cap_key = "salary_impossible"

        action = ""
        if severity == "CRITICAL":
            action = "Reject and escalate to fraud team"
        elif severity == "HIGH":
            action = "Manual review required"

        rules.append(RuleResult.fail(
            f"{dt}_rule", severity, flag,
            penalty=penalty, cap_key=cap_key, action=action,
        ))

    if not rules:
        rules.append(RuleResult.ok(
            f"{dt}_validation",
            f"✅ All {doc_type} document-specific checks passed"
        ))

    return rules


# ════════════════════════════════════════════════════════════════════
# AUTHENTICITY REPORT  — backward-compatible with dashboard
# ════════════════════════════════════════════════════════════════════

@dataclass
class AuthenticityReport:
    # Sub-scores for gauge display (0-100)
    visual_score:       float = 0.0
    semantic_score:     float = 0.0
    hash_score:         float = 100.0   # hash is neutral unless duplicate/fraud
    doc_specific_score: float = 100.0
    final_score:        float = 0.0

    verdict:    str = "UNKNOWN"
    risk_level: str = "LOW"

    all_flags:          list[str]  = field(default_factory=list)
    suspicious_regions: list[dict] = field(default_factory=list)
    explanation:        list[str]  = field(default_factory=list)
    recommendation:     str = ""

    sha256:           str  = ""
    is_duplicate:     bool = False
    previous_record:  dict | None = None
    blockchain_block: dict = field(default_factory=dict)
    entities:         dict = field(default_factory=dict)
    ocr_text:         str  = ""
    ocr_engine:       str  = ""
    doc_type:         str  = "UNKNOWN"
    doc_validation_flags: list[str] = field(default_factory=list)

    # Penalty engine fields
    failed_rules:     list[RuleResult] = field(default_factory=list)
    passed_rules:     list[RuleResult] = field(default_factory=list)
    hard_cap_applied: Optional[float]  = None
    total_penalty:    float = 0.0
    ocr_word_count:   int   = 0


# ════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ════════════════════════════════════════════════════════════════════

def compute_score(
    visual: VisualResult,
    semantic: SemanticResult,
    hash_result: HashResult,
    doc_validation: DocValidationResult | None = None,
) -> AuthenticityReport:

    report = AuthenticityReport()

    ocr_text = ""
    if semantic.ocr_result:
        ocr_text          = semantic.ocr_result.text
        report.ocr_engine = semantic.ocr_result.engine
        report.ocr_word_count = len(ocr_text.split())

    doc_type        = doc_validation.doc_type if doc_validation else "UNKNOWN"
    report.doc_type = doc_type

    # ── Collect all rules ────────────────────────────────────────────
    all_rules: list[RuleResult] = []
    all_rules += _dummy_rules(ocr_text)
    all_rules += _future_date_rules(ocr_text)

    v_rules = _visual_rules(visual)
    all_rules += v_rules

    all_rules += _hash_rules(hash_result)
    all_rules += _semantic_rules(semantic)

    doc_rules = _doc_specific_rules(ocr_text, doc_type)
    all_rules += doc_rules

    # ── Compute penalty and hard cap ─────────────────────────────────
    total_penalty = 0.0
    hard_cap: Optional[float] = None
    failed: list[RuleResult] = []
    passed: list[RuleResult] = []

    for rule in all_rules:
        if rule.passed:
            passed.append(rule)
        else:
            failed.append(rule)
            total_penalty += rule.penalty
            if rule.hard_cap_key and rule.hard_cap_key in HARD_CAPS:
                cap = float(HARD_CAPS[rule.hard_cap_key])
                if hard_cap is None or cap < hard_cap:
                    hard_cap = cap

    raw_score    = max(0.0, 100.0 - total_penalty)
    final_score  = min(raw_score, hard_cap) if hard_cap is not None else raw_score

    # ── Populate report ──────────────────────────────────────────────
    report.final_score    = final_score
    report.total_penalty  = total_penalty
    report.hard_cap_applied = hard_cap
    report.failed_rules   = failed
    report.passed_rules   = passed

    verdict, risk_level, recommendation = _risk_category(final_score)
    report.verdict         = verdict
    report.risk_level      = risk_level
    report.recommendation  = recommendation

    # Sub-scores for gauges
    v_pen  = sum(r.penalty for r in v_rules if not r.passed)
    d_pen  = sum(r.penalty for r in doc_rules if not r.passed)

    report.visual_score       = max(0.0, 100.0 - v_pen * 1.4)
    report.semantic_score     = max(0.0, 100.0 - (12.0 if report.ocr_word_count < 5 else 0.0))
    report.hash_score         = 0.0 if hash_result.is_duplicate else 100.0
    report.doc_specific_score = max(0.0, 100.0 - d_pen * 1.2)

    # Flags and regions
    report.all_flags            = [r.reason for r in failed]
    report.doc_validation_flags = doc_validation.flags if doc_validation else []
    report.suspicious_regions   = visual.suspicious_regions

    # Hash / blockchain (display only — not scoring)
    report.sha256           = hash_result.sha256
    report.is_duplicate     = hash_result.is_duplicate
    report.previous_record  = hash_result.previous_record
    report.blockchain_block = hash_result.blockchain_block

    # OCR / entities
    report.entities = semantic.entities
    if semantic.ocr_result:
        report.ocr_text = semantic.ocr_result.text[:2000]

    # XAI explanation
    _build_explanation(report)
    return report


def _build_explanation(r: AuthenticityReport):
    exp = []
    exp.append(f"**Score: 100 − {r.total_penalty:.0f} penalty = {r.final_score:.1f}**")

    if r.hard_cap_applied is not None:
        exp.append(f"🔒 Hard cap: score capped at {r.hard_cap_applied:.0f} due to critical failure")

    exp.append("---")
    if r.failed_rules:
        exp.append(f"**Deductions ({len(r.failed_rules)} rules failed):**")
        for rule in r.failed_rules:
            icon = "🚨" if rule.severity in ("CRITICAL", "HIGH") else "⚠️"
            exp.append(f"{icon} [{rule.severity}] {rule.reason}  −{rule.penalty:.0f} pts")
            if rule.suggested_action:
                exp.append(f"   → {rule.suggested_action}")
    else:
        exp.append("✅ No penalties — all rules passed")

    exp.append("---")
    exp.append(f"**Passed ({len(r.passed_rules)} rules):**")
    for rule in r.passed_rules[:8]:
        exp.append(f"✅ {rule.reason}")

    r.explanation = exp
