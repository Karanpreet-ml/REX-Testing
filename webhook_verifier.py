"""
Webhook signature verifier — REX-879.

Verifies HMAC-SHA256 signatures on incoming GitHub PR event payloads.
The shared secret is loaded from GITHUB_WEBHOOK_SECRET in settings.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from dataclasses import dataclass
from typing import Optional

from backend.services.review.settings import GITHUB_WEBHOOK_SECRET

logger = logging.getLogger(__name__)

SIGNATURE_HEADER = "X-Hub-Signature-256"
ALGORITHM = "sha256"


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    valid: bool
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Verifier
# ---------------------------------------------------------------------------

class WebhookVerifier:
    """
    Verifies GitHub webhook signatures using HMAC-SHA256.

    Usage:
        verifier = WebhookVerifier()
        result = verifier.verify(payload_bytes, signature_header)
        if not result.valid:
            raise HTTPException(403)
    """

    def __init__(self, secret: Optional[str] = None):
        self._secret = secret or GITHUB_WEBHOOK_SECRET

    def verify(self, payload: bytes, signature_header: Optional[str]) -> VerificationResult:
        if not self._secret:
            logger.warning("No webhook secret configured — skipping verification")
            return VerificationResult(valid=True, reason="no_secret_configured")

        if not signature_header:
            return VerificationResult(valid=False, reason="missing_signature_header")

        if not signature_header.startswith(f"{ALGORITHM}="):
            return VerificationResult(valid=False, reason="invalid_signature_format")

        received_sig = signature_header[len(f"{ALGORITHM}="):]

        expected_sig = hmac.new(
            self._secret.encode("utf-8"),
            payload,
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(received_sig, expected_sig):
            logger.warning("Webhook signature mismatch")
            return VerificationResult(valid=False, reason="signature_mismatch")

        return VerificationResult(valid=True)

    def rotate_secret(self, new_secret: str) -> None:
        """
        Hot-rotates the webhook secret without restarting the process.
        Called by the admin API when GitHub secret is rotated.
        """
        if not new_secret:
            raise ValueError("New secret must not be empty")
        old = self._secret
        self._secret = new_secret
        logger.info(
            "Webhook secret rotated from %.4s... to %.4s...",
            old, new_secret,
        )