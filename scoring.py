"""
Review scoring service.

Computes a 0–10 quality/risk score for a completed PR review.
Currently uses a flat severity-weight sum normalised by finding count.

REX-841 will introduce SeverityWeightedScorer with churn and recall adjustments.
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
    severity: str          # critical | high | medium | low
    category: str          # security | logic | performance | style | ...
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
    normalised_score: float       # 0.0 – 10.0
    finding_count: int
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    category_breakdown: dict[str, int] = field(default_factory=dict)
    churn_penalty_applied: bool = False
    jira_risk_floor_applied: bool = False


# ---------------------------------------------------------------------------
# Flat scorer (current / main branch)
# ---------------------------------------------------------------------------

class FlatScorer:
    """
    Baseline scorer: sum of severity weights, normalised to 0–10.

    No churn or recall adjustments (those are REX-841).
    """

    def score(
        self,
        findings: list[FindingInput],
        churn: Optional[ChurnMetadata] = None,  # accepted but ignored until REX-841
        jira_labels: Optional[list[str]] = None,  # accepted but ignored until REX-841
    ) -> ScoreResult:
        if not findings:
            return ScoreResult(
                raw_score=0.0,
                normalised_score=0.0,
                finding_count=0,
            )

        raw = sum(SEVERITY_WEIGHTS.get(f.severity.lower(), 1.0) for f in findings)
        normalised = min(raw / MAX_RAW_SCORE * 10.0, 10.0)

        severity_breakdown: dict[str, int] = {}
        category_breakdown: dict[str, int] = {}
        for f in findings:
            sev = f.severity.lower()
            cat = f.category.lower()
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1
            category_breakdown[cat] = category_breakdown.get(cat, 0) + 1

        logger.debug(
            "FlatScorer: %d findings → raw=%.2f normalised=%.2f",
            len(findings), raw, normalised,
        )

        return ScoreResult(
            raw_score=raw,
            normalised_score=round(normalised, 2),
            finding_count=len(findings),
            severity_breakdown=severity_breakdown,
            category_breakdown=category_breakdown,
        )


# ---------------------------------------------------------------------------
# Convenience wrapper used by the rest of the system
# ---------------------------------------------------------------------------

_default_scorer = FlatScorer()


def score_review(
    findings: list[FindingInput],
    churn: Optional[ChurnMetadata] = None,
    jira_labels: Optional[list[str]] = None,
) -> ScoreResult:
    """Public entry point — delegates to the active scorer implementation."""
    return _default_scorer.score(findings, churn=churn, jira_labels=jira_labels)