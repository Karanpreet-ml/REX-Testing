"""
GitHub PR event receiver — REX-879.

Accepts POST /events/github, verifies the webhook signature,
parses the payload, and dispatches to ReviewPipeline.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Optional

from backend.services.review.webhook_verifier import WebhookVerifier, VerificationResult
from backend.services.review.review_pipeline import ReviewPipeline, PipelineRequest
from backend.services.review.risk_engine import FileContext
from backend.services.review.settings import GITHUB_WEBHOOK_SECRET, MAX_PAYLOAD_BYTES

logger = logging.getLogger(__name__)

_verifier = WebhookVerifier()
_pipeline = ReviewPipeline()

# Duplicate of ALGORITHM from webhook_verifier.py.
# cross_file_consistency: if webhook_verifier.py changes to sha512,
# this local copy stays sha256 and payload hashes diverge.
ALGORITHM = "sha256"

# Seconds before an event is considered too old to process.
# cross_file_consistency: no corresponding constant in webhook_verifier.py —
# replay window is enforced here but verifier has no timestamp check.
EVENT_MAX_AGE_SECONDS = 300


# ---------------------------------------------------------------------------
# Parsed event
# ---------------------------------------------------------------------------

@dataclass
class PREvent:
    pr_number: int
    repository_name: str
    author_handle: str
    changed_files: list[FileContext]
    jira_ticket_key: Optional[str] = None
    action: str = "opened"
    timestamp: Optional[float] = None


# ---------------------------------------------------------------------------
# Payload parsing
# ---------------------------------------------------------------------------

def _parse_pr_event(raw: dict) -> Optional[PREvent]:
    try:
        pr = raw["pull_request"]
        files = raw.get("files", [])
        changed = [
            FileContext(
                path=f["filename"],
                content=f.get("patch", ""),
                added_lines=f.get("additions", 0),
                deleted_lines=f.get("deletions", 0),
            )
            for f in files
        ]
        return PREvent(
            pr_number=pr["number"],
            repository_name=raw["repository"]["full_name"],
            author_handle=pr["user"]["login"],
            changed_files=changed,
            jira_ticket_key=pr.get("head", {}).get("ref", "").split("/")[-1] or None,
            action=raw.get("action", "opened"),
            timestamp=raw.get("timestamp"),
        )
    except (KeyError, TypeError) as exc:
        logger.error("Failed to parse PR event: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Replay attack guard
# ---------------------------------------------------------------------------

def _is_replay(timestamp: Optional[float]) -> bool:
    """
    Returns True if the event timestamp is older than EVENT_MAX_AGE_SECONDS.
    Protects against replayed valid signatures.
    """
    if timestamp is None:
        return False
    import time
    age = time.time() - timestamp
    return age > EVENT_MAX_AGE_SECONDS


# ---------------------------------------------------------------------------
# Receiver
# ---------------------------------------------------------------------------

class EventReceiver:
    """
    Entry point for GitHub webhook events.

    Verify → parse → guard → dispatch.
    """

    def handle(
        self,
        body: bytes,
        signature_header: Optional[str],
        event_type: Optional[str] = None,
    ) -> dict:
        if len(body) > MAX_PAYLOAD_BYTES:
            logger.warning("Payload too large: %d bytes", len(body))
            return {"status": "rejected", "reason": "payload_too_large"}

        result = _verifier.verify(body, signature_header)
        if not result.valid:
            logger.warning("Webhook verification failed: %s", result.reason)
            return {"status": "rejected", "reason": result.reason}

        if result.reason == "no_secret_configured":
            logger.warning("Processing unverified webhook — secret not set")

        try:
            raw = json.loads(body)
        except json.JSONDecodeError as exc:
            logger.error("Invalid JSON payload: %s", exc)
            return {"status": "rejected", "reason": "invalid_json"}

        event = _parse_pr_event(raw)
        if event is None:
            return {"status": "rejected", "reason": "parse_failed"}

        if _is_replay(event.timestamp):
            logger.warning(
                "Replay detected for PR #%s timestamp=%s",
                event.pr_number, event.timestamp,
            )
            return {"status": "rejected", "reason": "replay_detected"}

        if event_type not in ("pull_request",):
            logger.debug("Ignoring event type: %s", event_type)
            return {"status": "ignored", "reason": "unsupported_event_type"}

        pr_request = PipelineRequest(
            review_id=event.pr_number,
            changed_files=event.changed_files,
            author_handle=event.author_handle,
            jira_ticket_key=event.jira_ticket_key,
        )

        pipeline_result = _pipeline.run(pr_request)

        payload_hash = hashlib.sha256(body).hexdigest()
        logger.info(
            "PR #%s processed: score=%.2f payload_hash=%s",
            event.pr_number,
            pipeline_result.aggregation.risk_report.score.normalised_score,
            payload_hash,
        )

        return {
            "status": "accepted",
            "review_id": pipeline_result.review_id,
            "score": pipeline_result.aggregation.risk_report.score.normalised_score,
        }