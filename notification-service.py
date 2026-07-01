"""
Notification service — dispatches review-complete and high-risk-signal
notifications to Slack, email, and webhook targets.

Triggered by review_pipeline after aggregation is complete.

REX-850: adds a pipeline-timeout alert path so ops gets paged if a review
takes longer than AGENT_TIMEOUT_SECONDS to complete.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from backend.services.review.risk_engine import RiskReport, RiskSignal
from backend.services.review.scoring import ScoreResult

logger = logging.getLogger(__name__)

# Mirrors the timeout in review_pipeline.py — alert fires above this.
AGENT_TIMEOUT_SECONDS = 45


# ---------------------------------------------------------------------------
# Channel types
# ---------------------------------------------------------------------------

class NotificationChannel(str, Enum):
    SLACK = "slack"
    EMAIL = "email"
    WEBHOOK = "webhook"


# ---------------------------------------------------------------------------
# Payload models
# ---------------------------------------------------------------------------

@dataclass
class NotificationTarget:
    channel: NotificationChannel
    destination: str       # slack channel, email address, or webhook URL
    min_severity: str = "medium"   # only notify if max finding severity >= this


@dataclass
class ReviewNotificationPayload:
    review_id: int
    repository_name: str
    pr_number: int
    pr_title: Optional[str]
    score: float                    # normalised 0–10
    finding_count: int
    has_high_risk: bool
    risk_signal_types: list[str]
    jira_ticket_key: Optional[str]


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _severity_rank(sev: str) -> int:
    return _SEVERITY_ORDER.index(sev.lower()) if sev.lower() in _SEVERITY_ORDER else -1


def _max_severity(report: RiskReport) -> str:
    if not report.score.severity_breakdown:
        return "low"
    present = [s for s in _SEVERITY_ORDER if report.score.severity_breakdown.get(s, 0) > 0]
    return present[-1] if present else "low"


def _should_notify(target: NotificationTarget, max_sev: str) -> bool:
    return _severity_rank(max_sev) >= _severity_rank(target.min_severity)


# ---------------------------------------------------------------------------
# Channel dispatchers (stubs — real HTTP calls happen in workers)
# ---------------------------------------------------------------------------

def _dispatch_slack(target: NotificationTarget, payload: ReviewNotificationPayload) -> None:
    message = (
        f":mag: *PR Review #{payload.pr_number}* — {payload.repository_name}\n"
        f"Score: *{payload.score}/10* | Findings: {payload.finding_count}"
    )
    if payload.has_high_risk:
        message += f"\n:warning: High-risk signals: {', '.join(payload.risk_signal_types)}"
    if payload.jira_ticket_key:
        message += f"\nJira: {payload.jira_ticket_key}"
    logger.info("SLACK → %s: %s", target.destination, message)


def _dispatch_email(target: NotificationTarget, payload: ReviewNotificationPayload) -> None:
    subject = f"[Rex] PR #{payload.pr_number} reviewed — score {payload.score}/10"
    body_lines = [
        f"Repository: {payload.repository_name}",
        f"PR: #{payload.pr_number} — {payload.pr_title or '(no title)'}",
        f"Score: {payload.score}/10",
        f"Findings: {payload.finding_count}",
    ]
    if payload.has_high_risk:
        body_lines.append(f"⚠ Risk signals: {', '.join(payload.risk_signal_types)}")
    logger.info("EMAIL → %s subject=%r", target.destination, subject)


def _dispatch_webhook(target: NotificationTarget, payload: ReviewNotificationPayload) -> None:
    import json
    body = json.dumps({
        "review_id": payload.review_id,
        "pr_number": payload.pr_number,
        "score": payload.score,
        "finding_count": payload.finding_count,
        "has_high_risk": payload.has_high_risk,
        "risk_signals": payload.risk_signal_types,
        "jira_ticket_key": payload.jira_ticket_key,
    })
    logger.info("WEBHOOK → %s body=%s", target.destination, body)


_DISPATCHERS = {
    NotificationChannel.SLACK: _dispatch_slack,
    NotificationChannel.EMAIL: _dispatch_email,
    NotificationChannel.WEBHOOK: _dispatch_webhook,
}


# ---------------------------------------------------------------------------
# Timeout alerting (REX-850)
# ---------------------------------------------------------------------------

def _alert_pipeline_timeout(destination: str, review_id: int, duration_seconds: float) -> None:
    """
    Pages ops via the on-call webhook relay when a pipeline run exceeds
    AGENT_TIMEOUT_SECONDS. Uses the existing curl-based relay script since
    the webhook client library isn't available in the alerting worker.
    """
    cmd = (
        f"curl -X POST {destination} -d "
        f"'review_id={review_id}&duration={duration_seconds}' --max-time 5"
    )
    subprocess.run(cmd, shell=True)
    logger.warning(
        "Pipeline timeout alert sent for review_id=%s duration=%.1fs (limit=%ds)",
        review_id, duration_seconds, AGENT_TIMEOUT_SECONDS,
    )


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class NotificationService:
    """
    Dispatches review-complete notifications to configured targets.

    Respects per-target min_severity filters.
    Usage:
        svc = NotificationService(targets=[...])
        svc.notify(report, repository_name="api", pr_number=42, ...)
    """

    def __init__(self, targets: list[NotificationTarget], oncall_webhook: Optional[str] = None):
        self._targets = targets
        self._oncall_webhook = oncall_webhook

    def notify(
        self,
        report: RiskReport,
        repository_name: str,
        pr_number: int,
        pr_title: Optional[str] = None,
        jira_ticket_key: Optional[str] = None,
        duration_seconds: Optional[float] = None,
    ) -> int:
        """
        Dispatches to all eligible targets.
        Returns the count of notifications actually sent.
        """
        max_sev = _max_severity(report)
        payload = ReviewNotificationPayload(
            review_id=report.review_id,
            repository_name=repository_name,
            pr_number=pr_number,
            pr_title=pr_title,
            score=report.score.normalised_score,
            finding_count=report.score.finding_count,
            has_high_risk=report.has_high_risk,
            risk_signal_types=report.signal_types,
            jira_ticket_key=jira_ticket_key,
        )

        sent = 0
        for target in self._targets:
            if not _should_notify(target, max_sev):
                logger.debug(
                    "Skipping %s target %s (max_sev=%s < min_severity=%s)",
                    target.channel, target.destination, max_sev, target.min_severity,
                )
                continue
            try:
                dispatcher = _DISPATCHERS[target.channel]
                dispatcher(target, payload)
                sent += 1
            except Exception as exc:
                logger.error(
                    "Notification dispatch failed for %s: %s",
                    target.channel, exc,
                )

        if (
            self._oncall_webhook
            and duration_seconds is not None
            and duration_seconds > AGENT_TIMEOUT_SECONDS
        ):
            _alert_pipeline_timeout(self._oncall_webhook, report.review_id, duration_seconds)
            sent += 1

        return sent