"""
SuRaksha DocShield — Risk Engine Configuration
All penalty values are defined here. Do not hardcode in validators.
"""

# ── Severity penalty ranges ───────────────────────────────────────────
SEVERITY = {
    "CRITICAL": 60,   # mathematically impossible, checksum fail, known fraud hash
    "HIGH":     35,   # format invalid, known fake, missing critical field
    "MEDIUM":   18,   # suspicious pattern, minor format issue
    "LOW":      7,    # missing optional field, minor inconsistency
}

# ── Hard-fail caps (max authenticity score when condition is true) ────
HARD_CAPS = {
    "aadhaar_verhoeff_fail":        20,
    "aadhaar_qr_mismatch":          25,
    "aadhaar_known_fake":           15,
    "pan_invalid_entity_char":      30,
    "pan_known_fake":               20,
    "passport_mrz_fail":            20,
    "bank_balance_incorrect":       25,
    "salary_gross_net_impossible":  35,
    "property_no_registration":     40,
    "cheque_words_digits_mismatch": 20,
    "gst_invalid_gstin":            25,
    "duplicate_hash":               30,
    "dummy_document_markers":       15,
    "copy_move_detected":           55,
    "ela_high_tamper":              50,
}

# ── Dummy / sample document markers ──────────────────────────────────
DUMMY_MARKERS = [
    (r'\bSAMPLE\b',               "CRITICAL", "SAMPLE watermark detected"),
    (r'\bSPECIMEN\b',             "CRITICAL", "SPECIMEN watermark detected"),
    (r'\bDEMO\b',                 "HIGH",     "DEMO label detected"),
    (r'\bDUMMY\b',                "CRITICAL", "DUMMY label detected"),
    (r'\bNOT\s+VALID\b',          "CRITICAL", "NOT VALID watermark detected"),
    (r'\bFOR\s+TRAINING\b',       "CRITICAL", "FOR TRAINING label detected"),
    (r'\bTEST\s+ONLY\b',          "HIGH",     "TEST ONLY label detected"),
    (r'\bLorem\s+ipsum\b',        "CRITICAL", "Lorem ipsum placeholder text"),
    (r'\bXXXXXXX+\b',             "CRITICAL", "XXXXXXX placeholder detected"),
    (r'\bAAAAAAAA+\b',             "HIGH",     "AAAAAAAA placeholder detected"),
    (r'\b123456789012\b',          "CRITICAL", "Known fake Aadhaar placeholder"),
    (r'\b000000000000\b',          "CRITICAL", "All-zero placeholder number"),
    (r'\b111111111111\b',          "CRITICAL", "All-ones placeholder number"),
    (r'\bDD[\/\-]MM[\/\-]YYYY\b', "HIGH",     "Unfilled date template"),
    (r'\bNAME\s+HERE\b',          "HIGH",     "Unfilled name placeholder"),
    (r'\b(?:John|Jane)\s+Doe\b',  "MEDIUM",   "Generic placeholder name"),
]

# ── Risk category labels ──────────────────────────────────────────────
RISK_CATEGORIES = [
    (90, "VERIFIED_GENUINE",   "LOW",      "✅ Document appears authentic. Proceed with standard due diligence."),
    (75, "LIKELY_GENUINE",     "LOW",      "✅ Document likely authentic. Minor review recommended."),
    (50, "NEEDS_REVIEW",       "MEDIUM",   "⚠️ Manual review required before processing."),
    (25, "HIGH_RISK",          "HIGH",     "🚨 High risk. Senior underwriter review mandatory. Do not process without verification."),
    (0,  "LIKELY_FRAUDULENT",  "CRITICAL", "🚨 Document likely fraudulent. REJECT and escalate to fraud team immediately."),
]

def get_risk_category(score: float) -> tuple[str, str, str]:
    """Returns (verdict_label, risk_level, recommendation)."""
    for threshold, label, risk, rec in RISK_CATEGORIES:
        if score >= threshold:
            return label, risk, rec
    return "LIKELY_FRAUDULENT", "CRITICAL", RISK_CATEGORIES[-1][3]
