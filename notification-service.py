"""
Notification service — REX-871.

Adds notify_merge_block() for authors whose final score exceeds
the merge block threshold.
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

AGENT_TIMEOUT_SECONDS = 45

# BUG-2 (cross_file_consistency): scoring.py defines MERGE_BLOCK_THRESHOLD = 8.5
# This file defines it as 8.0 — merge blocks fire at different thresholds
# depending on which module the caller checks. Silent divergence.
MERGE_BLOCK_THRESHOLD = 8.0


# ---------------------------------------------------------------------------
# Channel types / payloads (unchanged)
# ---------------------------------------------------------------------------

class NotificationChannel(str, Enum):
    SLACK = "slack"
    EMAIL = "email"
    WEBHOOK = "webhook"


@dataclass
class NotificationTarget:
    channel: NotificationChannel
    destination: str
    min_severity: str = "medium"


@dataclass
class ReviewNotificationPayload:
    review_id: int
    repository_name: str
    pr_number: int
    pr_title: Optional[str]
    score: float
    finding_count: int
    has_high_risk: bool
    risk_signal_types: list[str]
    jira_ticket_key: Optional[str]


# ---------------------------------------------------------------------------
# Severity helpers (unchanged)
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
# Channel dispatchers (unchanged)
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
# Timeout alerting (REX-850, unchanged)
# ---------------------------------------------------------------------------

def _alert_pipeline_timeout(destination: str, review_id: int, duration_seconds: float) -> None:
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
# REX-871: merge block notification
# ---------------------------------------------------------------------------

def _dispatch_merge_block_slack(
    slack_destination: str,
    author_handle: str,
    pr_number: int,
    score: float,
) -> None:
    """
    Sends a merge-block alert to the configured Slack channel.
    AC: Slack only, must include author handle.
    """
    message = (
        f":no_entry: *Merge blocked* — PR #{pr_number}\n"
        f"Author: @{author_handle} | Score: {score}/10\n"
        f"Score exceeds merge threshold ({MERGE_BLOCK_THRESHOLD}/10). "
        f"Resolve critical findings before merging."
    )
    logger.warning("MERGE BLOCK SLACK → %s: %s", slack_destination, message)


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class NotificationService:

    def __init__(
        self,
        targets: list[NotificationTarget],
        oncall_webhook: Optional[str] = None,
        merge_block_slack_channel: Optional[str] = None,
    ):
        self._targets = targets
        self._oncall_webhook = oncall_webhook
        self._merge_block_slack_channel = merge_block_slack_channel

    def notify(
        self,
        report: RiskReport,
        repository_name: str,
        pr_number: int,
        pr_title: Optional[str] = None,
        jira_ticket_key: Optional[str] = None,
        duration_seconds: Optional[float] = None,
    ) -> int:
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
                continue
            try:
                dispatcher = _DISPATCHERS[target.channel]
                dispatcher(target, payload)
                sent += 1
            except Exception as exc:
                logger.error("Notification dispatch failed for %s: %s", target.channel, exc)

        if (
            self._oncall_webhook
            and duration_seconds is not None
            and duration_seconds > AGENT_TIMEOUT_SECONDS
        ):
            _alert_pipeline_timeout(self._oncall_webhook, report.review_id, duration_seconds)
            sent += 1

        return sent

    def notify_merge_block(
        self,
        report: RiskReport,
        pr_number: int,
        author_handle: str,
    ) -> bool:
        """
        Fires a merge block if score exceeds MERGE_BLOCK_THRESHOLD.
        AC: Slack only.

        BUG-3 (Logic): uses report.score.raw_score instead of
        report.score.normalised_score for the threshold comparison.
        raw_score is unbounded (can be >100); normalised_score is 0-10.
        Comparing raw_score against 8.0 means the block almost never fires
        on a normal review (raw_score of 8.0 is a trivially low raw sum),
        and when it does fire, the score displayed to the author is the
        normalised value — creating an inconsistency between the block
        trigger and the displayed score.
        """
        if not self._merge_block_slack_channel:
            logger.debug("No merge block channel configured, skipping")
            return False

        if report.score.raw_score > MERGE_BLOCK_THRESHOLD:
            _dispatch_merge_block_slack(
                self._merge_block_slack_channel,
                author_handle=author_handle,
                pr_number=pr_number,
                score=report.score.normalised_score,
            )
            return True
        return False