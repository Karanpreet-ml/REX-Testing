"""
AI Risk signal detection engine.

Analyses a completed review to flag known failure modes:
  - hallucination_call  : finding references a function that does not exist in the diff
  - dead_abstraction    : a helper is defined but never invoked in the changed files
  - defensive_mismatch  : error-handling pattern differs across related changed files
  - cross_file_consistency : type/contract used in file A conflicts with definition in file B

These signals are purely heuristic — they surface candidates for human review.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from backend.services.review.scoring import FindingInput, ChurnMetadata, score_review, ScoreResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FileContext:
    path: str
    content: str           # full text of the changed file
    added_lines: int = 0
    deleted_lines: int = 0


@dataclass
class ReviewContext:
    review_id: int
    findings: list[FindingInput]
    changed_files: list[FileContext]
    jira_ticket_key: Optional[str] = None
    jira_labels: Optional[list[str]] = None

    @property
    def churn(self) -> ChurnMetadata:
        return ChurnMetadata(
            total_lines_added=sum(f.added_lines for f in self.changed_files),
            total_lines_deleted=sum(f.deleted_lines for f in self.changed_files),
            files_changed=len(self.changed_files),
        )


@dataclass
class RiskSignal:
    signal_type: str       # hallucination_call | dead_abstraction | ...
    description: str
    affected_file: Optional[str] = None
    severity: str = "medium"


@dataclass
class RiskReport:
    review_id: int
    score: ScoreResult
    signals: list[RiskSignal] = field(default_factory=list)
    has_high_risk: bool = False

    @property
    def signal_types(self) -> list[str]:
        return [s.signal_type for s in self.signals]


# ---------------------------------------------------------------------------
# Signal detectors
# ---------------------------------------------------------------------------

def _detect_hallucination_calls(ctx: ReviewContext) -> list[RiskSignal]:
    """
    Flag any finding whose message references a function name that cannot be
    found in any of the changed files.
    """
    signals: list[RiskSignal] = []
    all_content = "\n".join(fc.content for fc in ctx.changed_files)

    for finding in ctx.findings:
        # Look for "function_name(" patterns in the finding message
        refs = re.findall(r"\b([a-z_][a-z0-9_]*)\s*\(", finding.message.lower())
        for ref in refs:
            if ref in {"if", "for", "while", "return", "raise", "print", "len", "str", "int"}:
                continue
            pattern = rf"\bdef\s+{re.escape(ref)}\s*\("
            if not re.search(pattern, all_content, re.IGNORECASE):
                signals.append(RiskSignal(
                    signal_type="hallucination_call",
                    description=f"Finding references '{ref}()' which is not defined in any changed file",
                    affected_file=finding.file_path,
                    severity="high",
                ))
    return signals


def _detect_dead_abstractions(ctx: ReviewContext) -> list[RiskSignal]:
    """
    Flag helper functions defined in changed files that are never called
    within those same files.
    """
    signals: list[RiskSignal] = []
    all_content = "\n".join(fc.content for fc in ctx.changed_files)

    for fc in ctx.changed_files:
        defined = re.findall(r"def\s+(_[a-z][a-z0-9_]*)\s*\(", fc.content)
        for fn_name in defined:
            call_pattern = rf"\b{re.escape(fn_name)}\s*\("
            call_count = len(re.findall(call_pattern, all_content))
            if call_count <= 1:  # only the definition itself
                signals.append(RiskSignal(
                    signal_type="dead_abstraction",
                    description=f"Private helper '{fn_name}' defined but never called in changed files",
                    affected_file=fc.path,
                    severity="low",
                ))
    return signals


def _detect_defensive_mismatch(ctx: ReviewContext) -> list[RiskSignal]:
    """
    Flag if some changed files use try/except and others with similar
    patterns do not, suggesting inconsistent error handling.
    """
    signals: list[RiskSignal] = []
    if len(ctx.changed_files) < 2:
        return signals

    files_with_try = [fc.path for fc in ctx.changed_files if "try:" in fc.content]
    files_without_try = [fc.path for fc in ctx.changed_files if "try:" not in fc.content]

    if files_with_try and files_without_try:
        signals.append(RiskSignal(
            signal_type="defensive_mismatch",
            description=(
                f"Error handling inconsistency: {len(files_with_try)} file(s) use "
                f"try/except, {len(files_without_try)} do not"
            ),
            affected_file=None,
            severity="medium",
        ))
    return signals


def _detect_cross_file_consistency(ctx: ReviewContext) -> list[RiskSignal]:
    """
    Flag if a type/constant name appears with different casing or value
    across changed files, suggesting a contract mismatch.
    """
    signals: list[RiskSignal] = []
    constant_pattern = re.compile(r"^([A-Z_]{3,})\s*=\s*(.+)$", re.MULTILINE)

    constants_by_file: dict[str, dict[str, str]] = {}
    for fc in ctx.changed_files:
        matches = constant_pattern.findall(fc.content)
        constants_by_file[fc.path] = {name: val.strip() for name, val in matches}

    all_names: set[str] = set()
    for consts in constants_by_file.values():
        all_names.update(consts.keys())

    for name in all_names:
        values_seen: dict[str, str] = {}
        for path, consts in constants_by_file.items():
            if name in consts:
                values_seen[path] = consts[name]
        if len(set(values_seen.values())) > 1:
            signals.append(RiskSignal(
                signal_type="cross_file_consistency",
                description=f"Constant '{name}' defined with different values across files: {values_seen}",
                severity="high",
            ))
    return signals


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class RiskEngine:
    """
    Orchestrates signal detection and scoring for a review context.
    """

    def compute_risk_signals(self, ctx: ReviewContext) -> RiskReport:
        score = score_review(
            findings=ctx.findings,
            churn=ctx.churn,
            jira_labels=ctx.jira_labels,
        )

        signals: list[RiskSignal] = []
        signals.extend(_detect_hallucination_calls(ctx))
        signals.extend(_detect_dead_abstractions(ctx))
        signals.extend(_detect_defensive_mismatch(ctx))
        signals.extend(_detect_cross_file_consistency(ctx))

        has_high_risk = any(s.severity == "high" for s in signals)

        return RiskReport(
            review_id=ctx.review_id,
            score=score,
            signals=signals,
            has_high_risk=has_high_risk,
        )