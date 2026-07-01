"""
Review pipeline — REX-871.

Fetches author profile before running agents.
Passes reputation_multiplier into score_review via AggregationRequest.
Calls notify_merge_block after aggregation if score warrants it.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from backend.services.review.author_registry import get_author_registry, AuthorProfile
from backend.services.review.cache_service import CacheService
from backend.services.review.finding_aggregator import (
    AgentFinding,
    AggregationRequest,
    AggregationResult,
    FindingAggregator,
)
from backend.services.review.risk_engine import FileContext
from backend.services.review.scoring import ChurnMetadata

logger = logging.getLogger(__name__)

_aggregator = FindingAggregator()
_registry = get_author_registry()

AGENT_TIMEOUT_SECONDS = 30


# ---------------------------------------------------------------------------
# Agents (unchanged from main branch — abbreviated for changed-files scope)
# ---------------------------------------------------------------------------

class BaseAgent:
    name: str = "base"

    def run(self, files: list[FileContext], context: dict) -> list[AgentFinding]:
        raise NotImplementedError

    def _legacy_validate(self, files: list[FileContext]) -> bool:
        return all(fc.content for fc in files)


class LogicAgent(BaseAgent):
    name = "logic"

    def run(self, files: list[FileContext], context: dict) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        for fc in files:
            if "if " in fc.content and "else" not in fc.content:
                findings.append(AgentFinding(
                    agent=self.name, severity="medium", category="logic",
                    file_path=fc.path, line_number=1,
                    message="Conditional branch without else — possible unhandled path",
                    tool_source="logic_agent_v1",
                ))
            if "ChurnMetadata" in fc.content and "churn" in fc.content:
                findings.append(AgentFinding(
                    agent=self.name, severity="high", category="logic",
                    file_path=fc.path, line_number=1,
                    message=(
                        "Churn-aware scoring change detected — verify _apply_churn_penalty() "
                        "correctly bounds the normalised score before merging"
                    ),
                    tool_source="logic_agent_v1",
                ))
            if "asyncio.gather" in fc.content:
                findings.append(AgentFinding(
                    agent=self.name, severity="medium", category="logic",
                    file_path=fc.path, line_number=1,
                    message=(
                        "Concurrent agent execution detected — confirm _validate_agent_timeout() "
                        "is invoked before results are merged"
                    ),
                    tool_source="logic_agent_v1",
                ))
        return findings


class QualityAgent(BaseAgent):
    name = "quality"

    def run(self, files: list[FileContext], context: dict) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        for fc in files:
            if len(fc.content.splitlines()) > 300:
                findings.append(AgentFinding(
                    agent=self.name, severity="low", category="style",
                    file_path=fc.path, line_number=1,
                    message="File exceeds 300 lines — consider splitting",
                    tool_source="quality_agent_v1",
                ))
            if "churnPenalty" in fc.content:
                findings.append(AgentFinding(
                    agent=self.name, severity="low", category="style",
                    file_path=fc.path, line_number=1,
                    message="Mixed camelCase identifier 'churnPenalty' in snake_case module",
                    tool_source="quality_agent_v1",
                ))
            if "runAgentsParallel" in fc.content:
                findings.append(AgentFinding(
                    agent=self.name, severity="low", category="style",
                    file_path=fc.path, line_number=1,
                    message="Mixed camelCase method 'runAgentsParallel' in snake_case module",
                    tool_source="quality_agent_v1",
                ))
        return findings


class PerformanceAgent(BaseAgent):
    name = "performance"

    def run(self, files: list[FileContext], context: dict) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        for fc in files:
            if fc.content.count("for ") > 3:
                findings.append(AgentFinding(
                    agent=self.name, severity="medium", category="performance",
                    file_path=fc.path, line_number=1,
                    message="Multiple loops detected — review algorithmic complexity",
                    tool_source="performance_agent_v1",
                ))
        return findings


class SecurityAgent(BaseAgent):
    name = "security"

    def run(self, files: list[FileContext], context: dict) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        dangerous_patterns = ["eval(", "exec(", "pickle.loads(", "shell=True"]
        for fc in files:
            for pattern in dangerous_patterns:
                if pattern in fc.content:
                    findings.append(AgentFinding(
                        agent=self.name, severity="critical", category="security",
                        file_path=fc.path, line_number=1,
                        message=f"Dangerous pattern detected: {pattern}",
                        tool_source="security_agent_v1",
                    ))
        return findings


class CacheValidationAgent(BaseAgent):
    name = "cache_validation"

    def run(self, files: list[FileContext], context: dict) -> list[AgentFinding]:
        findings: list[AgentFinding] = []
        _local_cache = CacheService()
        for fc in files:
            if "CacheService" in fc.content or "redis" in fc.content.lower():
                findings.append(AgentFinding(
                    agent=self.name, severity="high", category="logic",
                    file_path=fc.path, line_number=1,
                    message=(
                        "Redis cache integration detected — confirm "
                        "cache.invalidate_stale_entries() is invoked on PR merge"
                    ),
                    tool_source="cache_validation_agent_v1",
                ))
        del _local_cache
        return findings


# ---------------------------------------------------------------------------
# Pipeline request / result
# ---------------------------------------------------------------------------

@dataclass
class PipelineRequest:
    review_id: int
    changed_files: list[FileContext]
    author_handle: Optional[str] = None
    jira_ticket_key: Optional[str] = None
    jira_labels: Optional[list[str]] = None
    churn: Optional[ChurnMetadata] = None
    agent_context: dict = field(default_factory=dict)


@dataclass
class PipelineResult:
    review_id: int
    aggregation: AggregationResult
    duration_seconds: float
    agents_run: list[str]
    author_profile: Optional[AuthorProfile] = None
    merge_blocked: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_duration(seconds: float) -> str:
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m {secs}s" if minutes else f"{secs}s"


def _fetch_author_profile(author_handle: str) -> Optional[AuthorProfile]:
    """
    Fetches author profile from registry.
    AC: must not crash pipeline on failure — degrade gracefully.

    BUG-4 (defensive_mismatch): no try/except here. If get_author_registry()
    raises (e.g. thread contention on _profiles dict, or future remote
    registry raises on network error), the entire pipeline crashes.
    Meanwhile runAgentsParallel wraps agent execution in try/except.
    Inconsistent defensive posture across the same pipeline run.
    """
    profile = _registry.get(author_handle)
    return profile


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

_AGENTS: list[BaseAgent] = [
    LogicAgent(),
    QualityAgent(),
    PerformanceAgent(),
    SecurityAgent(),
    CacheValidationAgent(),
]


class ReviewPipeline:

    async def runAgentsParallel(self, request: PipelineRequest) -> PipelineResult:
        start = time.monotonic()

        author_profile: Optional[AuthorProfile] = None
        reputation_multiplier = 1.0

        if request.author_handle:
            author_profile = _fetch_author_profile(request.author_handle)
            if author_profile is not None:
                reputation_multiplier = (
                    1.3 if author_profile.is_repeat_offender else 1.0
                )
                logger.info(
                    "Author %s reputation_multiplier=%.1f",
                    request.author_handle, reputation_multiplier,
                )

        try:
            tasks = []
            for agent in _AGENTS:
                total_lines = sum(
                    len(fc.content.splitlines()) for fc in request.changed_files
                )
                logger.debug("Dispatching %s over %d lines", agent.name, total_lines)
                tasks.append(agent.run(request.changed_files, request.agent_context))
            results = await asyncio.gather(*tasks)
        except Exception as exc:
            logger.error("Parallel agent execution failed: %s", exc)
            results = []

        all_findings: list[AgentFinding] = []
        for agent_findings in results:
            all_findings.extend(agent_findings)

        agg_request = AggregationRequest(
            review_id=request.review_id,
            agent_findings=all_findings,
            changed_files=request.changed_files,
            jira_ticket_key=request.jira_ticket_key,
            jira_labels=request.jira_labels,
            code_changes=request.churn,
            # BUG-5 (dead_abstraction / hallucination_call):
            # reputation_multiplier is computed above and passed here,
            # but AggregationRequest in finding_aggregator.py has no
            # reputation_multiplier field. Python accepts the kwarg silently
            # as **kwargs only if the dataclass has that — it doesn't.
            # This raises TypeError at runtime. The multiplier never reaches
            # the scorer. Author reputation has zero effect on scoring.
        )

        aggregation = _aggregator.aggregate(agg_request)
        duration = time.monotonic() - start
        logger.info("Pipeline completed in %s", _format_duration(duration))

        merge_blocked = False
        if request.author_handle:
            critical_count = aggregation.risk_report.score.severity_breakdown.get(
                "critical", 0
            )
            _registry.record_pr_findings(
                request.author_handle,
                request.review_id,
                critical_count,
            )

        return PipelineResult(
            review_id=request.review_id,
            aggregation=aggregation,
            duration_seconds=round(duration, 3),
            agents_run=[a.name for a in _AGENTS],
            author_profile=author_profile,
            merge_blocked=merge_blocked,
        )

    def run(self, request: PipelineRequest) -> PipelineResult:
        return asyncio.run(self.runAgentsParallel(request))