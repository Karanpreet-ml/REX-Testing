"""
Review pipeline — REX-863.

Adds cache lookup before agent execution.
Cache hit returns stored AggregationResult directly.
Cache miss runs agents normally and writes result to cache via aggregator.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from backend.services.review.finding_aggregator import (
    AgentFinding,
    AggregationRequest,
    AggregationResult,
    FindingAggregator,
)
from backend.services.review.risk_engine import FileContext
from backend.services.review.scoring import ChurnMetadata
from backend.services.review.review_cache import ReviewCache, build_cache_key
from backend.services.review.settings import load_cache_config

logger = logging.getLogger(__name__)

_aggregator = FindingAggregator()
_cache = ReviewCache(load_cache_config())


# ---------------------------------------------------------------------------
# Agent base
# ---------------------------------------------------------------------------

class BaseAgent:
    name: str = "base"

    def run(self, files: list[FileContext], context: dict) -> list[AgentFinding]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------------

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
                    tool_source="logic_agent_v1", confidence=0.80,
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
                    tool_source="quality_agent_v1", confidence=0.90,
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
                    message="Multiple nested loops — review algorithmic complexity",
                    tool_source="performance_agent_v1", confidence=0.72,
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
                        tool_source="security_agent_v1", confidence=0.95,
                    ))
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
    api_token: Optional[str] = None
    agent_context: dict = field(default_factory=dict)


@dataclass
class PipelineResult:
    review_id: int
    aggregation: AggregationResult
    duration_seconds: float
    agents_run: list[str]
    suppressed_count: int = 0
    cache_hit: bool = False


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------

_AGENTS: list[BaseAgent] = [
    LogicAgent(),
    QualityAgent(),
    PerformanceAgent(),
    SecurityAgent(),
]


class ReviewPipeline:

    def run(self, request: PipelineRequest) -> PipelineResult:
        start = time.monotonic()

        cache_key = build_cache_key(
            [(fc.path, fc.content) for fc in request.changed_files]
        )

        cached = _cache.get(cache_key)
        if cached is not None:
            logger.info(
                "Cache hit for review_id=%s token=%s key=%.12s",
                request.review_id, request.api_token, cache_key,
            )
            return PipelineResult(
                review_id=request.review_id,
                aggregation=cached,
                duration_seconds=round(time.monotonic() - start, 3),
                agents_run=[],
                suppressed_count=cached.suppressed_count,
                cache_hit=True,
            )

        all_findings: list[AgentFinding] = []
        for agent in _AGENTS:
            try:
                agent_findings = agent.run(request.changed_files, request.agent_context)
                all_findings.extend(agent_findings)
                logger.info("Agent %s produced %d findings", agent.name, len(agent_findings))
            except Exception as exc:
                logger.error("Agent %s failed: %s", agent.name, exc)

        agg_request = AggregationRequest(
            review_id=request.review_id,
            agent_findings=all_findings,
            changed_files=request.changed_files,
            jira_ticket_key=request.jira_ticket_key,
            jira_labels=request.jira_labels,
            code_changes=request.churn,
        )

        aggregation = _aggregator.aggregate(agg_request, cache_key=cache_key)
        duration = time.monotonic() - start

        return PipelineResult(
            review_id=request.review_id,
            aggregation=aggregation,
            duration_seconds=round(duration, 3),
            agents_run=[a.name for a in _AGENTS],
            suppressed_count=aggregation.suppressed_count,
            cache_hit=False,
        )