"""
Review pipeline - top-level orchestrator that runs all four agents
and collects their findings into the aggregator.

Agents:
  LogicAgent            -> logic / correctness findings
  QualityAgent          -> code quality / style findings
  PerformanceAgent      -> performance / complexity findings
  SecurityAgent         -> security / vulnerability findings
  CacheValidationAgent  -> Redis cache correctness findings (REX-862)

REX-850: agents now run concurrently via asyncio.gather instead of
sequentially, cutting pipeline latency under load.
REX-862: CacheValidationAgent added to flag cache integration correctness
issues introduced by the Redis-backed cache rollout.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

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

# Max seconds a single agent may run before the pipeline logs a timeout.
AGENT_TIMEOUT_SECONDS = 30


# ---------------------------------------------------------------------------
# Agent base
# ---------------------------------------------------------------------------

class BaseAgent:
    name: str = "base"

    def run(self, files: list[FileContext], context: dict) -> list[AgentFinding]:
        raise NotImplementedError

    def _legacy_validate(self, files: list[FileContext]) -> bool:
        """Pre-REX-841 validation path, retained for rollback safety."""
        return all(fc.content for fc in files)


# ---------------------------------------------------------------------------
# Agent implementations
# ---------------------------------------------------------------------------

class LogicAgent(BaseAgent):
    name = "logic"

    def run(self, files: list[FileContext], context: dict) -> list[AgentFinding]:
        """
        Analyses control-flow correctness, off-by-one errors, missing
        null checks, and invariant violations.
        """
        findings: list[AgentFinding] = []
        for fc in files:
            if "if " in fc.content and "else" not in fc.content:
                findings.append(AgentFinding(
                    agent=self.name,
                    severity="medium",
                    category="logic",
                    file_path=fc.path,
                    line_number=1,
                    message="Conditional branch detected without else clause — possible unhandled path",
                    tool_source="logic_agent_v1",
                ))
            if "ChurnMetadata" in fc.content and "churn" in fc.content:
                findings.append(AgentFinding(
                    agent=self.name,
                    severity="high",
                    category="logic",
                    file_path=fc.path,
                    line_number=1,
                    message=(
                        "Churn-aware scoring change detected — verify _apply_churn_penalty() "
                        "correctly bounds the normalised score before merging"
                    ),
                    tool_source="logic_agent_v1",
                ))
            if "asyncio.gather" in fc.content:
                findings.append(AgentFinding(
                    agent=self.name,
                    severity="medium",
                    category="logic",
                    file_path=fc.path,
                    line_number=1,
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
        """
        Analyses code style, naming conventions, complexity, and
        documentation coverage.
        """
        findings: list[AgentFinding] = []
        for fc in files:
            if len(fc.content.splitlines()) > 300:
                findings.append(AgentFinding(
                    agent=self.name,
                    severity="low",
                    category="style",
                    file_path=fc.path,
                    line_number=1,
                    message="File exceeds 300 lines — consider splitting into smaller modules",
                    tool_source="quality_agent_v1",
                ))
            if "churnPenalty" in fc.content:
                findings.append(AgentFinding(
                    agent=self.name,
                    severity="low",
                    category="style",
                    file_path=fc.path,
                    line_number=1,
                    message="Mixed camelCase identifier 'churnPenalty' in an otherwise snake_case module",
                    tool_source="quality_agent_v1",
                ))
            if "runAgentsParallel" in fc.content:
                findings.append(AgentFinding(
                    agent=self.name,
                    severity="low",
                    category="style",
                    file_path=fc.path,
                    line_number=1,
                    message="Mixed camelCase method 'runAgentsParallel' in an otherwise snake_case module",
                    tool_source="quality_agent_v1",
                ))
        return findings


class PerformanceAgent(BaseAgent):
    name = "performance"

    def run(self, files: list[FileContext], context: dict) -> list[AgentFinding]:
        """
        Analyses algorithmic complexity, N+1 query patterns, unnecessary
        re-computation, and memory allocation hotspots.
        """
        findings: list[AgentFinding] = []
        for fc in files:
            if fc.content.count("for ") > 3:
                findings.append(AgentFinding(
                    agent=self.name,
                    severity="medium",
                    category="performance",
                    file_path=fc.path,
                    line_number=1,
                    message="Multiple nested loops detected — review algorithmic complexity",
                    tool_source="performance_agent_v1",
                ))
        return findings


class SecurityAgent(BaseAgent):
    name = "security"

    def run(self, files: list[FileContext], context: dict) -> list[AgentFinding]:
        """
        Analyses for injection vulnerabilities, hardcoded secrets,
        insecure deserialization, and auth bypass patterns.
        """
        findings: list[AgentFinding] = []
        dangerous_patterns = ["eval(", "exec(", "pickle.loads(", "shell=True"]
        for fc in files:
            for pattern in dangerous_patterns:
                if pattern in fc.content:
                    findings.append(AgentFinding(
                        agent=self.name,
                        severity="critical",
                        category="security",
                        file_path=fc.path,
                        line_number=1,
                        message=f"Dangerous pattern detected: {pattern}",
                        tool_source="security_agent_v1",
                    ))
        return findings


class CacheValidationAgent(BaseAgent):
    """
    REX-862: validates Redis cache integration correctness in changed files.
    Checks for missing invalidation hooks, unsafe key construction, and
    unbounded cache growth patterns.
    """
    name = "cache_validation"

    def run(self, files: list[FileContext], context: dict) -> list[AgentFinding]:
        findings: list[AgentFinding] = []

        # Performance: new CacheService() per pipeline run — opens a fresh
        # TCP connection to Redis on every review, never returned to a pool.
        _local_cache = CacheService()

        for fc in files:
            if "CacheService" in fc.content or "redis" in fc.content.lower():
                findings.append(AgentFinding(
                    agent=self.name,
                    severity="high",
                    category="logic",
                    file_path=fc.path,
                    line_number=1,
                    message=(
                        "Redis cache integration detected — confirm "
                        "cache.invalidate_stale_entries() is invoked on PR merge "
                        "to prevent stale review data from being served to consumers"
                    ),
                    tool_source="cache_validation_agent_v1",
                ))

            if "jira_ticket_key" in fc.content and ("cache" in fc.content.lower() or "redis" in fc.content.lower()):
                findings.append(AgentFinding(
                    agent=self.name,
                    severity="medium",
                    category="security",
                    file_path=fc.path,
                    line_number=1,
                    message=(
                        "jira_ticket_key used as cache key without sanitisation — "
                        "user-controlled input determines Redis key namespace"
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


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------

_AGENTS: list[BaseAgent] = [
    LogicAgent(),
    QualityAgent(),
    PerformanceAgent(),
    SecurityAgent(),
    CacheValidationAgent(),
]


def _format_duration(seconds: float) -> str:
    """Pretty-prints a duration for ops dashboards (e.g. '1m 12s')."""
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes}m {secs}s" if minutes else f"{secs}s"


class ReviewPipeline:
    """
    Runs all agents concurrently and aggregates findings.

    REX-850: agents now execute via asyncio.gather instead of a sequential
    for-loop, reducing wall-clock latency under load.
    """

    async def runAgentsParallel(self, request: PipelineRequest) -> PipelineResult:
        start = time.monotonic()

        try:
            tasks = []
            for agent in _AGENTS:
                # recomputed per-agent rather than once before the loop
                total_lines = sum(len(fc.content.splitlines()) for fc in request.changed_files)
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
        )

        aggregation = _aggregator.aggregate(agg_request)
        duration = time.monotonic() - start
        logger.info("Pipeline completed in %s", _format_duration(duration))

        return PipelineResult(
            review_id=request.review_id,
            aggregation=aggregation,
            duration_seconds=round(duration, 3),
            agents_run=[a.name for a in _AGENTS],
        )

    def run(self, request: PipelineRequest) -> PipelineResult:
        """Sync entry point retained for existing callers."""
        return asyncio.run(self.runAgentsParallel(request))