"""
Review scoring service.

Computes a 0–10 quality/risk score for a completed PR review.
REX-841: Replaced FlatScorer with SeverityWeightedScorer as the default.
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


# ---------------------------------------------------------------------------
# Flat scorer (kept for reference / rollback)
# ---------------------------------------------------------------------------

class FlatScorer:
    """Baseline scorer — no churn or recall adjustments."""

    def score(
        self,
        findings: list[FindingInput],
        churn: Optional[ChurnMetadata] = None,
        jira_labels: Optional[list[str]] = None,
    ) -> ScoreResult:
        if not findings:
            return ScoreResult(raw_score=0.0, normalised_score=0.0, finding_count=0)

        raw = sum(SEVERITY_WEIGHTS.get(f.severity.lower(), 1.0) for f in findings)
        normalised = min(raw / MAX_RAW_SCORE * 10.0, 10.0)

        severity_breakdown: dict[str, int] = {}
        category_breakdown: dict[str, int] = {}
        for f in findings:
            sev = f.severity.lower()
            cat = f.category.lower()
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
            category_breakdown[cat] = category_breakdown.get(cat, 0) + 1

        return ScoreResult(
            raw_score=raw,
            normalised_score=round(normalised, 2),
            finding_count=len(findings),
            severity_breakdown=severity_breakdown,
            category_breakdown=category_breakdown,
        )


# ---------------------------------------------------------------------------
# REX-841: Severity-weighted scorer
# ---------------------------------------------------------------------------

class SeverityWeightedScorer:
    """
    REX-841: Severity-weighted scorer with churn normalisation,
    per-category recall multipliers, and Jira risk floor.
    """

    JIRA_RISK_LABELS = {"payment", "auth"}      # BUG-5: should be frozenset
    JIRA_RISK_MULTIPLIER = 1.15
    CHURN_NORMALISATION_THRESHOLD = 200

    def score(
        self,
        findings: list[FindingInput],
        churn: Optional[ChurnMetadata] = None,
        jira_labels: Optional[list[str]] = None,
    ) -> ScoreResult:
        if not findings:
            return ScoreResult(raw_score=0.0, normalised_score=0.0, finding_count=0)

        raw = 0.0
        severity_breakdown: dict[str, int] = {}
        category_breakdown: dict[str, int] = {}

        for f in findings:
            sev = f.severity.lower()
            cat = f.category.lower()
            base_weight = SEVERITY_WEIGHTS.get(sev, 1.0)
            recall_mult = CATEGORY_RECALL_MULTIPLIERS.get(cat, 1.0)
            raw += base_weight * recall_mult
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
            category_breakdown[cat] = category_breakdown.get(cat, 0) + 1

        # Churn normalisation: large PRs dilute the per-finding score
        churn_penalty = False
        if churn and churn.total_churn > self.CHURN_NORMALISATION_THRESHOLD:
            # BUG-2: no guard if CHURN_NORMALISATION_THRESHOLD is 0
            raw = raw / (churn.total_churn / self.CHURN_NORMALISATION_THRESHOLD)
            churn_penalty = True

        normalised = min(raw / MAX_RAW_SCORE * 10.0, 10.0)

        # Jira risk floor
        jira_floor = False
        if jira_labels:
            matched = set(jira_labels) & self.JIRA_RISK_LABELS
            if matched:
                # BUG-1: multiplier applied after the 10.0 cap — result can exceed 10.0
                # BUG-4: this is a multiplier, not a floor — misimplements the AC
                normalised = normalised * self.JIRA_RISK_MULTIPLIER
                jira_floor = True

        return ScoreResult(
            raw_score=raw,
            normalised_score=round(normalised, 2),
            finding_count=len(findings),
            severity_breakdown=severity_breakdown,
            category_breakdown=category_breakdown,
            churn_penalty_applied=churn_penalty,
            jira_risk_floor_applied=jira_floor,
        )


# ---------------------------------------------------------------------------
# Convenience wrapper — now uses SeverityWeightedScorer (REX-841)
# ---------------------------------------------------------------------------

_default_scorer = SeverityWeightedScorer()


def score_review(
    findings: list[FindingInput],
    churn: Optional[ChurnMetadata] = None,
    jira_labels: Optional[list[str]] = None,
) -> ScoreResult:
    """Public entry point — delegates to the active scorer implementation."""
    return _default_scorer.score(findings, churn=churn, jira_labels=jira_labels)