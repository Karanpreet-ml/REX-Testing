"""
Finding aggregator — REX-863.

Writes result to ReviewCache after aggregation on cache miss.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional

from backend.services.review.scoring import FindingInput, ChurnMetadata
from backend.services.review.risk_engine import FileContext, ReviewContext, RiskReport, RiskEngine
from backend.services.review.agent_config import AgentConfig, load_all_agent_configs
from backend.services.review.review_cache import ReviewCache
from backend.services.review.settings import load_cache_config

logger = logging.getLogger(__name__)

_engine = RiskEngine()
_cache = ReviewCache(load_cache_config())


# ---------------------------------------------------------------------------
# Data classes
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
    confidence: float = 1.0
    fingerprint: Optional[str] = None

    def compute_fingerprint(self) -> str:
        key = f"{self.file_path}:{self.line_number}:{self.category}:{self.message[:60]}"
        return hashlib.md5(key.encode()).hexdigest()[:12]


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
    suppressed_count: int
    risk_report: RiskReport
    agent_breakdown: dict[str, int] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Suppression
# ---------------------------------------------------------------------------

def _suppress_low_confidence(
    findings: list[AgentFinding],
    configs: dict[str, AgentConfig],
) -> tuple[list[AgentFinding], int]:
    kept: list[AgentFinding] = []
    dropped = 0
    for f in findings:
        cfg = configs.get(f.agent)
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

class FindingAggregator:
    """Aggregates findings and writes result to cache on miss."""

    def aggregate(
        self,
        request: AggregationRequest,
        cache_key: Optional[str] = None,
    ) -> AggregationResult:
        agent_names = list({f.agent for f in request.agent_findings})
        configs = load_all_agent_configs(agent_names)

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

        result = AggregationResult(
            review_id=request.review_id,
            deduplicated_findings=finding_inputs,
            duplicate_count=dup_count,
            suppressed_count=suppressed_count,
            risk_report=risk_report,
            agent_breakdown=agent_breakdown,
        )

        if cache_key is not None:
            _cache.set(cache_key, result)

        return result