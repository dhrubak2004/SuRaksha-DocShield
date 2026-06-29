"""
Common rules applied to ALL documents regardless of type.
"""
from __future__ import annotations
import re
from .base_rules import RuleResult
from .config import DUMMY_MARKERS, SEVERITY

CURRENT_YEAR = 2026


def dummy_document_rules(text: str) -> list[RuleResult]:
    """Detect SAMPLE/SPECIMEN/DEMO/TEST/Lorem ipsum markers."""
    rules = []
    found_any = False

    for pattern, severity, description in DUMMY_MARKERS:
        if re.search(pattern, text, re.I):
            found_any = True
            rules.append(RuleResult.fail_rule(
                rule_name="dummy_marker",
                severity=severity,
                reason=f"🚨 {description}",
                penalty=float(SEVERITY[severity]),
                hard_cap_key="dummy_document_markers",
                suggested_action="Reject document — appears to be a sample/test document",
            ))

    if not found_any:
        rules.append(RuleResult.pass_rule("dummy_marker", "✅ No dummy/sample markers detected"))

    return rules


def future_date_rules(text: str) -> list[RuleResult]:
    """Detect dates that are in the future."""
    rules = []
    date_patterns = [
        r'\b(\d{1,2})[\/\-\.](\d{1,2})[\/\-\.](\d{4})\b',
        r'\b(\d{4})[\/\-\.](\d{1,2})[\/\-\.](\d{1,2})\b',
    ]
    found_future = False
    for pat in date_patterns:
        for m in re.finditer(pat, text):
            g = m.groups()
            try:
                parts = [int(x) for x in g]
                year = max(parts)
                if year > CURRENT_YEAR:
                    found_future = True
                    rules.append(RuleResult.fail_rule(
                        rule_name="future_date",
                        severity="CRITICAL",
                        reason=f"🚨 Future date {m.group()} detected — document cannot be from the future",
                        hard_cap_key=None,
                        suggested_action="Verify document date — may be forged or post-dated",
                    ))
                    break
            except ValueError:
                pass
        if found_future:
            break

    if not found_future:
        rules.append(RuleResult.pass_rule("future_date", "✅ No future dates detected"))

    return rules


def ocr_confidence_rule(ocr_text: str, engine: str) -> list[RuleResult]:
    """Check OCR quality — low text = unreliable extraction."""
    word_count = len(ocr_text.split()) if ocr_text else 0
    if word_count < 5:
        return [RuleResult.fail_rule(
            rule_name="ocr_quality",
            severity="MEDIUM",
            reason=f"⚠️ OCR extracted only {word_count} words — text extraction may be unreliable",
            suggested_action="Try higher resolution scan or different OCR engine",
        )]
    return [RuleResult.pass_rule("ocr_quality", f"✅ OCR extracted {word_count} words via {engine}")]
