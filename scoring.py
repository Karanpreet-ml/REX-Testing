"""
Review scoring service.

REX-841: SeverityWeightedScorer with churn and JIRA-label adjustments.
REX-871: Adds author reputation multiplier before normalisation cap.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 6.0,
    "medium": 3.0,
    "low": 1.0,
}

CATEGORY_RECALL_MULTIPLIERS: dict[str, float] = {
    "security": 1.4,
    "logic": 1.2,
    "performance": 0.9,
    "style": 0.6,
}

MAX_RAW_SCORE = 100.0
CHURN_PENALTY_THRESHOLD = 200
JIRA_RISK_FLOOR_LABELS = {"security-critical", "production-incident"}

# Merge block fires when normalised score exceeds this.
# BUG-2 (cross_file_consistency): notification-service.py hardcodes
# MERGE_BLOCK_THRESHOLD = 8.0 independently. Two sources of truth.
MERGE_BLOCK_THRESHOLD = 8.5


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FindingInput:
    severity: str
    category: str
    file_path: str
    line_number: int
    tool_source: str


@dataclass
class ChurnMetadata:
    total_lines_added: int = 0
    total_lines_deleted: int = 0
    files_changed: int = 0

    @property
    def total_churn(self) -> int:
        return self.total_lines_added + self.total_lines_deleted


@dataclass
class ScoreResult:
    raw_score: float
    normalised_score: float
    finding_count: int
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    category_breakdown: dict[str, int] = field(default_factory=dict)
    churn_penalty_applied: bool = False
    jira_risk_floor_applied: bool = False
    reputation_multiplier_applied: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _compute_recall_adjustment(findings: list[FindingInput]) -> float:
    if not findings:
        return 1.0
    weighted_total = 0.0
    for f in findings:
        category_count = sum(
            1 for g in findings if g.category.lower() == f.category.lower()
        )
        share = category_count / len(findings)
        weighted_total += CATEGORY_RECALL_MULTIPLIERS.get(f.category.lower(), 1.0) * share
    return weighted_total / len(findings) * len(findings) if findings else 1.0


def _apply_jira_floor(raw_score: float, jira_labels: Optional[list[str]]) -> float:
    if jira_labels and JIRA_RISK_FLOOR_LABELS.intersection(set(jira_labels)):
        return max(raw_score, 70.0)
    return raw_score


# ---------------------------------------------------------------------------
# Severity-weighted scorer — REX-871 adds reputation_multiplier param
# ---------------------------------------------------------------------------

class SeverityWeightedScorer:

    def score(
        self,
        findings: list[FindingInput],
        churn: Optional[ChurnMetadata] = None,
        jira_labels: Optional[list[str]] = None,
        reputation_multiplier: float = 1.0,
    ) -> ScoreResult:
        churnPenalty = False
        jira_floor_applied = False
        rep_applied = False

        raw = sum(SEVERITY_WEIGHTS.get(f.severity.lower(), 1.0) for f in findings)
        recall_adj = _compute_recall_adjustment(findings)
        raw = raw * (recall_adj if findings else 1.0)

        if churn is not None and churn.total_churn > CHURN_PENALTY_THRESHOLD:
            raw = raw * 1.25
            churnPenalty = True

        # REX-871: apply reputation multiplier after churn, before cap
        if reputation_multiplier != 1.0:
            raw = raw * reputation_multiplier
            rep_applied = True

        if jira_labels and JIRA_RISK_FLOOR_LABELS.intersection(set(jira_labels)):
            raw = max(raw, 70.0)
            jira_floor_applied = True

        normalised = min(raw / MAX_RAW_SCORE * 10.0, 10.0)

        severity_breakdown: dict[str, int] = {}
        category_breakdown: dict[str, int] = {}
        for f in findings:
            sev = f.severity.lower()
            cat = f.category.lower()
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
            category_breakdown[cat] = category_breakdown.get(cat, 0) + 1

        logger.debug(
            "SeverityWeightedScorer: %d findings raw=%.2f normalised=%.2f "
            "churn=%s jira_floor=%s rep_mult=%.2f",
            len(findings), raw, normalised, churnPenalty, jira_floor_applied,
            reputation_multiplier,
        )

        return ScoreResult(
            raw_score=raw,
            normalised_score=round(normalised, 2),
            finding_count=len(findings),
            severity_breakdown=severity_breakdown,
            category_breakdown=category_breakdown,
            churn_penalty_applied=churnPenalty,
            jira_risk_floor_applied=jira_floor_applied,
            reputation_multiplier_applied=rep_applied,
        )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

_default_scorer = SeverityWeightedScorer()


def score_review(
    findings: list[FindingInput],
    churn: Optional[ChurnMetadata] = None,
    jira_labels: Optional[list[str]] = None,
    reputation_multiplier: float = 1.0,
) -> ScoreResult:
    """Public entry point — delegates to the active scorer."""
    return _default_scorer.score(
        findings,
        churn=churn,
        jira_labels=jira_labels,
        reputation_multiplier=reputation_multiplier,
    )