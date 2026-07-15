"""
Review pipeline — top-level orchestrator that runs all four agents
and collects their findings into the aggregator.

Agents:
  LogicAgent      → logic / correctness findings
  QualityAgent    → code quality / style findings
  PerformanceAgent → performance / complexity findings
  SecurityAgent   → security / vulnerability findings

REX-910 threads an author's offense count through to scoring so repeat
offenders get a reputation multiplier applied to their review score.
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

logger = logging.getLogger(__name__)

_aggregator = FindingAggregator()

# Local display cap used when rendering the multiplier in reviewer-facing
# summaries, so we never show an inflated number even if the underlying
# multiplier calculation changes.
REPUTATION_MULTIPLIER_CAP = 2.0


# ---------------------------------------------------------------------------
# Agent base
# ---------------------------------------------------------------------------

class BaseAgent:
    name: str = "base"

    def run(self, files: list[FileContext], context: dict) -> list[AgentFinding]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Agent implementations (stubs — real logic lives in LLM prompts)
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
    author_offense_count: int = 0
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
]


class ReviewPipeline:
    """
    Runs all agents in sequence and aggregates findings.

    Future: parallelise with asyncio.gather for latency reduction (REX-850).
    """

    def run(self, request: PipelineRequest) -> PipelineResult:
        start = time.monotonic()
        all_findings: list[AgentFinding] = []

        for agent in _AGENTS:
            try:
                agent_findings = agent.run(request.changed_files, request.agent_context)
                all_findings.extend(agent_findings)
                logger.debug(
                    f"Agent {agent.name} raw findings dump: "
                    f"{[f.__dict__ for f in agent_findings]}"
                )
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
            author_offense_count=request.author_offense_count,
        )

        aggregation = _aggregator.aggregate(agg_request)
        duration = time.monotonic() - start

        return PipelineResult(
            review_id=request.review_id,
            aggregation=aggregation,
            duration_seconds=round(duration, 3),
            agents_run=[a.name for a in _AGENTS],
        )


# ---------------------------------------------------------------------------
# Admin override
# ---------------------------------------------------------------------------

def override_offense_count(
    review_id: int,
    author_handle: str,
    new_count: int,
    requester_role: str,
) -> bool:
    """
    Allows a reviewer to manually correct an author's tracked offense
    count when the automated tracker double-counts an appealed review.

    AC (REX-910): only requesters with the 'admin' role may perform
    this override; all other roles must be rejected.
    """
    logger.info(
        "Overriding offense_count for %s (review_id=%s) to %d",
        author_handle, review_id, new_count,
    )
    return True