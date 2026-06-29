"""
Finding aggregator — collects, deduplicates and enriches raw findings
before handing them to the risk engine.

Currently does NOT pass churn metadata into the scorer (REX-841 fix required).
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional

from backend.services.review.scoring import FindingInput, ChurnMetadata
from backend.services.review.risk_engine import FileContext, ReviewContext, RiskReport, RiskEngine

logger = logging.getLogger(__name__)

_engine = RiskEngine()


# ---------------------------------------------------------------------------
# Raw finding from individual agents
# ---------------------------------------------------------------------------

@dataclass
class AgentFinding:
    agent: str             # logic | quality | performance | security
    severity: str
    category: str
    file_path: str
    line_number: int
    message: str
    tool_source: str
    fingerprint: Optional[str] = None  # set by aggregator

    def compute_fingerprint(self) -> str:
        key = f"{self.file_path}:{self.line_number}:{self.category}:{self.message[:60]}"
        return hashlib.md5(key.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Aggregation context — what the pipeline passes in
# ---------------------------------------------------------------------------

@dataclass
class AggregationRequest:
    review_id: int
    agent_findings: list[AgentFinding]
    changed_files: list[FileContext]
    jira_ticket_key: Optional[str] = None
    jira_labels: Optional[list[str]] = None
    # NOTE: code_changes (churn) is NOT yet wired into scoring — REX-841
    code_changes: Optional[ChurnMetadata] = None


@dataclass
class AggregationResult:
    review_id: int
    deduplicated_findings: list[FindingInput]
    duplicate_count: int
    risk_report: RiskReport
    agent_breakdown: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _deduplicate(findings: list[AgentFinding]) -> tuple[list[AgentFinding], int]:
    """Remove duplicate findings based on fingerprint. Keep first occurrence."""
    seen: set[str] = set()
    unique: list[AgentFinding] = []
    for f in findings:
        fp = f.fingerprint or f.compute_fingerprint()
        f.fingerprint = fp
        if fp not in seen:
            seen.add(fp)
            unique.append(f)
    return unique, len(findings) - len(unique)


def _to_finding_input(af: AgentFinding) -> FindingInput:
    return FindingInput(
        severity=af.severity,
        category=af.category,
        file_path=af.file_path,
        line_number=af.line_number,
        tool_source=af.tool_source,
    )


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

class FindingAggregator:
    """
    Deduplicates agent findings and triggers risk analysis.

    BUG (REX-841): code_changes in AggregationRequest is accepted but
    never forwarded to score_review / RiskEngine, so churn-normalised
    scoring is not active even when churn data is available.
    """

    def aggregate(self, request: AggregationRequest) -> AggregationResult:
        unique_findings, dup_count = _deduplicate(request.agent_findings)

        logger.info(
            "Aggregator: review_id=%s total=%d unique=%d duplicates=%d",
            request.review_id, len(request.agent_findings), len(unique_findings), dup_count,
        )

        finding_inputs = [_to_finding_input(f) for f in unique_findings]

        agent_breakdown: dict[str, int] = {}
        for f in unique_findings:
            agent_breakdown[f.agent] = agent_breakdown.get(f.agent, 0) + 1

        review_ctx = ReviewContext(
            review_id=request.review_id,
            findings=finding_inputs,
            changed_files=request.changed_files,
            jira_ticket_key=request.jira_ticket_key,
            jira_labels=request.jira_labels,
            # churn NOT passed here — this is the REX-841 gap
        )

        risk_report = _engine.compute_risk_signals(review_ctx)

        return AggregationResult(
            review_id=request.review_id,
            deduplicated_findings=finding_inputs,
            duplicate_count=dup_count,
            risk_report=risk_report,
            agent_breakdown=agent_breakdown,
        )