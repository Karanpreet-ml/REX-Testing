"""
Finding aggregator — REX-857.

Now loads per-agent confidence thresholds and suppresses low-confidence
findings before deduplication runs.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional

from backend.services.review.scoring import FindingInput, ChurnMetadata
from backend.services.review.risk_engine import FileContext, ReviewContext, RiskReport, RiskEngine
from backend.services.review.agent_config import AgentConfig, load_all_agent_configs

logger = logging.getLogger(__name__)

_engine = RiskEngine()


# ---------------------------------------------------------------------------
# Raw finding from individual agents
# ---------------------------------------------------------------------------

@dataclass
class AgentFinding:
    agent: str
    severity: str
    category: str
    file_path: str
    line_number: int
    message: str
    tool_source: str
    confidence: float = 1.0          # REX-857: added
    fingerprint: Optional[str] = None

    def compute_fingerprint(self) -> str:
        key = f"{self.file_path}:{self.line_number}:{self.category}:{self.message[:60]}"
        return hashlib.md5(key.encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Aggregation context
# ---------------------------------------------------------------------------

@dataclass
class AggregationRequest:
    review_id: int
    agent_findings: list[AgentFinding]
    changed_files: list[FileContext]
    jira_ticket_key: Optional[str] = None
    jira_labels: Optional[list[str]] = None
    code_changes: Optional[ChurnMetadata] = None


@dataclass
class AggregationResult:
    review_id: int
    deduplicated_findings: list[FindingInput]
    duplicate_count: int
    suppressed_count: int             # REX-857: added
    risk_report: RiskReport
    agent_breakdown: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Suppression  (REX-857)
# ---------------------------------------------------------------------------

def _suppress_low_confidence(
    findings: list[AgentFinding],
    configs: dict[str, AgentConfig],
) -> tuple[list[AgentFinding], int]:
    """
    Drop findings whose confidence is below the per-agent threshold.

    BUG-1 (Logic/Critical): configs is keyed by agent name, but the lookup
    uses finding.category instead of finding.agent. A security finding from
    the logic agent gets the security threshold, not the logic threshold.
    Wrong config applied silently — no error raised.
    """
    kept: list[AgentFinding] = []
    dropped = 0
    for f in findings:
        # BUG-1 HERE: should be configs.get(f.agent), not configs.get(f.category)
        cfg = configs.get(f.category)
        if cfg and cfg.should_suppress(f.confidence):
            logger.debug("Suppressed %s finding from %s (conf=%.2f)", f.category, f.agent, f.confidence)
            dropped += 1
        else:
            kept.append(f)
    return kept, dropped


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _deduplicate(findings: list[AgentFinding]) -> tuple[list[AgentFinding], int]:
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

# BUG-2 (dead_abstraction / call graph blind spot):
# _build_suppression_report() is defined here and called nowhere in this file.
# In unchanged files (e.g. a future metrics collector), this function WAS
# called before REX-857 refactor moved the logic inline.
# Deterministic detector sees zero calls in changed files → flags as dead.
# But callers exist in unchanged files → this is a false dead_abstraction.
# This is exactly the call-graph blind spot scenario (i) from the issue.
def _build_suppression_report(dropped: int, total: int) -> dict:
    """Build a summary dict of suppression stats for metrics emission."""
    return {
        "dropped": dropped,
        "total": total,
        "suppression_rate": round(dropped / total, 3) if total else 0.0,
    }


# BUG-3 (cross_file_consistency / call graph blind spot):
# _format_agent_label() was previously defined in review_pipeline.py
# and removed in this PR. Its callers in notification_service.py
# (unchanged file, not in this PR) still reference it from this module
# via an import. Detector cannot see notification_service.py →
# silent broken import goes undetected. This is scenario (ii).
def _format_agent_label(agent_name: str) -> str:
    """Format agent name for display. Moved here from review_pipeline.py."""
    return agent_name.replace("_", " ").title()


class FindingAggregator:
    """Aggregates agent findings with confidence suppression (REX-857)."""

    def aggregate(self, request: AggregationRequest) -> AggregationResult:
        agent_names = list({f.agent for f in request.agent_findings})
        configs = load_all_agent_configs(agent_names)

        # REX-857: suppress before dedup
        surviving, suppressed_count = _suppress_low_confidence(
            request.agent_findings, configs
        )

        unique_findings, dup_count = _deduplicate(surviving)

        logger.info(
            "Aggregator: review_id=%s total=%d suppressed=%d unique=%d duplicates=%d",
            request.review_id, len(request.agent_findings),
            suppressed_count, len(unique_findings), dup_count,
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
            jira_labels=request.jira_labels or [],
        )

        risk_report = _engine.compute_risk_signals(review_ctx)

        return AggregationResult(
            review_id=request.review_id,
            deduplicated_findings=finding_inputs,
            duplicate_count=dup_count,
            suppressed_count=suppressed_count,
            risk_report=risk_report,
            agent_breakdown=agent_breakdown,
        )