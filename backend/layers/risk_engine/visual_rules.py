"""
Visual forensics rules.
Wraps existing visual_forensics layer output into RuleResult objects.
"""
from __future__ import annotations
from .base_rules import RuleResult
from .config import SEVERITY


def visual_rules(visual_result) -> list[RuleResult]:
    """Convert VisualResult into RuleResult list."""
    rules = []

    # ELA
    ela = visual_result.ela_score
    if ela >= 60:
        rules.append(RuleResult.fail_rule(
            rule_name="ela_tamper",
            severity="CRITICAL",
            reason=f"🚨 ELA score {ela:.1f}/100 — strong evidence of image manipulation",
            penalty=55.0,
            hard_cap_key="ela_high_tamper",
            suggested_action="Document image has been edited — reject",
        ))
    elif ela >= 35:
        rules.append(RuleResult.fail_rule(
            rule_name="ela_tamper",
            severity="HIGH",
            reason=f"⚠️ ELA score {ela:.1f}/100 — possible image editing detected",
            penalty=30.0,
        ))
    elif ela >= 15:
        rules.append(RuleResult.fail_rule(
            rule_name="ela_tamper",
            severity="LOW",
            reason=f"ℹ️ ELA score {ela:.1f}/100 — minor compression inconsistency (may be normal for scans)",
            penalty=5.0,
        ))
    else:
        rules.append(RuleResult.pass_rule("ela_tamper", f"✅ ELA score {ela:.1f}/100 — no significant tampering"))

    # Copy-move
    cm = visual_result.copy_move_score
    if cm >= 40:
        rules.append(RuleResult.fail_rule(
            rule_name="copy_move",
            severity="CRITICAL",
            reason=f"🚨 Copy-move score {cm:.1f}/100 — duplicated regions detected (cloned content)",
            penalty=50.0,
            hard_cap_key="copy_move_detected",
            suggested_action="Document contains cloned regions — likely tampered",
        ))
    elif cm >= 20:
        rules.append(RuleResult.fail_rule(
            rule_name="copy_move",
            severity="HIGH",
            reason=f"⚠️ Copy-move score {cm:.1f}/100 — suspicious region duplication",
            penalty=25.0,
        ))
    else:
        rules.append(RuleResult.pass_rule("copy_move", f"✅ Copy-move score {cm:.1f}/100 — no duplication detected"))

    # Metadata
    meta = visual_result.metadata_score
    if meta >= 50:
        rules.append(RuleResult.fail_rule(
            rule_name="metadata",
            severity="HIGH",
            reason=f"⚠️ Metadata anomaly score {meta:.1f}/100 — EXIF/PDF metadata suspicious",
            penalty=20.0,
        ))
    elif meta >= 20:
        rules.append(RuleResult.fail_rule(
            rule_name="metadata",
            severity="LOW",
            reason=f"ℹ️ Metadata score {meta:.1f}/100 — minor metadata inconsistency",
            penalty=5.0,
        ))
    else:
        rules.append(RuleResult.pass_rule("metadata", f"✅ Metadata score {meta:.1f}/100 — no anomalies"))

    # Existing flags from visual layer
    for flag in visual_result.flags:
        if flag not in [r.reason for r in rules]:
            rules.append(RuleResult.fail_rule(
                rule_name="visual_flag",
                severity="MEDIUM",
                reason=f"⚠️ {flag}",
                penalty=float(SEVERITY["MEDIUM"]),
            ))

    return rules


def hash_rules(hash_result) -> list[RuleResult]:
    """Convert HashResult into RuleResult list."""
    rules = []

    if hash_result.is_duplicate:
        prev = hash_result.previous_record or {}
        rules.append(RuleResult.fail_rule(
            rule_name="duplicate_hash",
            severity="HIGH",
            reason=f"⚠️ Document SHA-256 matches a previous submission: {prev.get('filename','?')} (status: {prev.get('status','?')})",
            penalty=35.0,
            hard_cap_key="duplicate_hash",
            suggested_action="Investigate why same document was submitted before",
        ))
    else:
        rules.append(RuleResult.pass_rule("duplicate_hash", "✅ Document hash is unique — not previously seen"))

    for flag in hash_result.flags:
        rules.append(RuleResult.fail_rule(
            rule_name="hash_flag",
            severity="HIGH",
            reason=f"⚠️ {flag}",
            penalty=float(SEVERITY["HIGH"]),
        ))

    return rules


def semantic_rules(semantic_result) -> list[RuleResult]:
    """Convert SemanticResult into RuleResult list (keep OCR confidence separate from authenticity)."""
    rules = []

    # OCR quality
    if semantic_result.ocr_result:
        word_count = len(semantic_result.ocr_result.text.split())
        if word_count < 5:
            rules.append(RuleResult.fail_rule(
                rule_name="ocr_quality",
                severity="MEDIUM",
                reason=f"⚠️ OCR extracted only {word_count} words — may indicate blank/image-only document",
                penalty=12.0,
                suggested_action="Try higher resolution scan",
            ))
        else:
            rules.append(RuleResult.pass_rule("ocr_quality", f"✅ OCR extracted {word_count} words"))

    # Semantic inconsistencies from existing layer
    for issue in (semantic_result.inconsistencies if hasattr(semantic_result, 'inconsistencies') else []):
        rules.append(RuleResult.fail_rule(
            rule_name="semantic_inconsistency",
            severity="MEDIUM",
            reason=f"⚠️ {issue}",
            penalty=float(SEVERITY["MEDIUM"]),
        ))

    if not rules:
        rules.append(RuleResult.pass_rule("semantic", "✅ Semantic analysis found no inconsistencies"))

    return rules
