"""
Document-specific rule adapters.
Wraps existing validators (aadhaar.py, pan.py, etc.) into RuleResult format.
Does NOT rewrite validator logic — reuses it entirely.
"""
from __future__ import annotations
import re
import sys
from pathlib import Path

# Ensure validators are importable
_VALIDATORS_PATH = Path(__file__).resolve().parent.parent / "layers"
if str(_VALIDATORS_PATH) not in sys.path:
    sys.path.insert(0, str(_VALIDATORS_PATH.parent))

from .base_rules import RuleResult
from .config import SEVERITY


def _flags_to_rules(flags: list[str], doc_score: float, doc_type: str) -> list[RuleResult]:
    """Convert existing validator flags into RuleResult objects."""
    rules = []
    for flag in flags:
        if flag.startswith("🚨"):
            severity = "CRITICAL" if any(k in flag for k in [
                "checksum", "mathematically", "known fake", "impossible",
                "invalid", "placeholder", "fake", "future date"
            ]) else "HIGH"
            # Map to hard cap if applicable
            hard_cap_key = None
            if "verhoeff" in flag.lower():      hard_cap_key = "aadhaar_verhoeff_fail"
            if "known fake" in flag.lower() and doc_type == "AADHAAR": hard_cap_key = "aadhaar_known_fake"
            if "known fake" in flag.lower() and doc_type == "PAN":     hard_cap_key = "pan_known_fake"
            if "entity type" in flag.lower():   hard_cap_key = "pan_invalid_entity_char"
            if "mrz check digit" in flag.lower(): hard_cap_key = "passport_mrz_fail"
            if "gstin" in flag.lower():          hard_cap_key = "gst_invalid_gstin"
            if "gross" in flag.lower() and "net" in flag.lower(): hard_cap_key = "salary_gross_net_impossible"

            rules.append(RuleResult.fail_rule(
                rule_name=f"{doc_type.lower()}_validation",
                severity=severity,
                reason=flag,
                penalty=float(SEVERITY[severity]),
                hard_cap_key=hard_cap_key,
                suggested_action="Reject and escalate to fraud team" if severity == "CRITICAL" else "Manual review required",
            ))
        elif flag.startswith("⚠️"):
            rules.append(RuleResult.fail_rule(
                rule_name=f"{doc_type.lower()}_check",
                severity="MEDIUM",
                reason=flag,
                penalty=float(SEVERITY["MEDIUM"]),
            ))

    if not flags:
        rules.append(RuleResult.pass_rule(
            f"{doc_type.lower()}_validation",
            f"✅ All {doc_type} document-specific checks passed"
        ))

    return rules


def run_doc_rules(text: str, doc_type: str) -> list[RuleResult]:
    """
    Route to the correct existing validator and convert output to RuleResult list.
    Reuses all existing validator modules — no logic duplicated.
    """
    try:
        from layers.validators import aadhaar, pan, passport, driving_licence, voter_id, gst, salary
        from layers.validators.bank_statement import validate as validate_bank, BANK_STATEMENT_CHECKS
        from layers.validators.cheque import validate as validate_cheque, CHEQUE_CHECKS
        from layers.validators.others import (
            validate_passbook, validate_property, validate_birth_certificate,
            validate_itr, validate_fd_receipt, validate_loan_doc,
        )
    except ImportError:
        return [RuleResult.pass_rule("doc_validator_import", "⚠️ Validator modules not loaded")]

    validator_map = {
        "AADHAAR":         aadhaar.validate,
        "PAN":             pan.validate,
        "PASSPORT":        passport.validate,
        "DRIVING_LICENCE": driving_licence.validate,
        "VOTER_ID":        voter_id.validate,
        "GST":             gst.validate,
        "SALARY_SLIP":     salary.validate,
        "BANK_STATEMENT":  validate_bank,
        "CHEQUE":          validate_cheque,
        "PASSBOOK":        validate_passbook,
        "PROPERTY_DOC":    validate_property,
        "BIRTH_CERT":      validate_birth_certificate,
        "ITR":             validate_itr,
        "FD_RECEIPT":      validate_fd_receipt,
        "LOAN_DOC":        validate_loan_doc,
    }

    validator_fn = validator_map.get(doc_type)
    if not validator_fn:
        return [RuleResult.pass_rule("doc_validator", f"ℹ️ No specific validator for {doc_type}")]

    score, flags = validator_fn(text)
    return _flags_to_rules(flags, score, doc_type)
