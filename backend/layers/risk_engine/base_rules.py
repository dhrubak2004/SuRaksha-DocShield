"""
SuRaksha DocShield — Rule Engine Base
Every validator returns a list of RuleResult objects.
The engine aggregates them into a final penalty-based score.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
import logging

from .config import SEVERITY, HARD_CAPS, get_risk_category

logger = logging.getLogger(__name__)


@dataclass
class RuleResult:
    """A single validation rule result."""
    rule_name:        str
    severity:         str          # CRITICAL / HIGH / MEDIUM / LOW / PASS
    penalty:          float        # points deducted (0 if passed)
    reason:           str          # human-readable explanation
    passed:           bool = True
    hard_cap_key:     Optional[str] = None   # key into HARD_CAPS if this triggers a cap
    bounding_boxes:   list[dict] = field(default_factory=list)
    suggested_action: str = ""

    @classmethod
    def pass_rule(cls, rule_name: str, reason: str) -> "RuleResult":
        return cls(rule_name=rule_name, severity="PASS", penalty=0.0, reason=reason, passed=True)

    @classmethod
    def fail_rule(
        cls,
        rule_name: str,
        severity: str,
        reason: str,
        penalty: Optional[float] = None,
        hard_cap_key: Optional[str] = None,
        suggested_action: str = "",
    ) -> "RuleResult":
        p = penalty if penalty is not None else float(SEVERITY.get(severity, 10))
        return cls(
            rule_name=rule_name,
            severity=severity,
            penalty=p,
            reason=reason,
            passed=False,
            hard_cap_key=hard_cap_key,
            suggested_action=suggested_action,
        )


@dataclass
class RiskReport:
    """Final aggregated risk report from the rule engine."""
    start_score:       float = 100.0
    total_penalty:     float = 0.0
    hard_cap_applied:  Optional[float] = None
    final_score:       float = 100.0

    verdict:           str = "UNKNOWN"
    risk_level:        str = "LOW"
    recommendation:    str = ""

    rules:             list[RuleResult] = field(default_factory=list)
    failed_rules:      list[RuleResult] = field(default_factory=list)
    passed_rules:      list[RuleResult] = field(default_factory=list)

    # Sub-scores for display
    visual_score:      float = 100.0
    semantic_score:    float = 100.0
    hash_score:        float = 100.0
    doc_specific_score:float = 100.0

    # Metadata
    doc_type:          str = "UNKNOWN"
    ocr_text:          str = ""
    ocr_engine:        str = ""
    entities:          dict = field(default_factory=dict)
    sha256:            str = ""
    is_duplicate:      bool = False
    previous_record:   Optional[dict] = None
    blockchain_block:  dict = field(default_factory=dict)
    suspicious_regions:list[dict] = field(default_factory=list)
    ela_image:         object = None   # numpy array, optional


class RiskEngine:
    """
    Aggregates RuleResult objects into a RiskReport.
    Uses penalty-based scoring starting from 100.
    Hard caps override the final score when critical failures occur.
    """

    def __init__(self):
        self._rules: list[RuleResult] = []
        self._hard_cap: Optional[float] = None

    def add_rules(self, rules: list[RuleResult]):
        self._rules.extend(rules)

    def add_rule(self, rule: RuleResult):
        self._rules.append(rule)

    def compute(self) -> RiskReport:
        report = RiskReport()
        report.rules = self._rules

        total_penalty = 0.0
        failed = []
        passed = []

        for rule in self._rules:
            if rule.passed:
                passed.append(rule)
            else:
                failed.append(rule)
                total_penalty += rule.penalty
                # Check hard cap
                if rule.hard_cap_key and rule.hard_cap_key in HARD_CAPS:
                    cap = float(HARD_CAPS[rule.hard_cap_key])
                    if self._hard_cap is None or cap < self._hard_cap:
                        self._hard_cap = cap
                        logger.debug(f"Hard cap set to {cap} by rule '{rule.rule_name}'")

        report.failed_rules = failed
        report.passed_rules = passed
        report.total_penalty = total_penalty

        raw_score = max(0.0, 100.0 - total_penalty)

        if self._hard_cap is not None:
            report.hard_cap_applied = self._hard_cap
            report.final_score = min(raw_score, self._hard_cap)
        else:
            report.final_score = raw_score

        verdict, risk_level, recommendation = get_risk_category(report.final_score)
        report.verdict         = verdict
        report.risk_level      = risk_level
        report.recommendation  = recommendation

        return report
