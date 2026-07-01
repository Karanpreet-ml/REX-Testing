"""
Review service settings — REX-863 / REX-879.

Centralises configuration for the review pipeline, cache, and webhook.
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CacheConfig (unchanged)
# ---------------------------------------------------------------------------

@dataclass
class CacheConfig:
    ttl: int
    max_entries: int


def load_cache_config() -> CacheConfig:
    try:
        ttl = int(os.environ.get("REX_CACHE_TTL", 3600))
    except ValueError:
        logger.warning("Invalid REX_CACHE_TTL, using default 3600")
        ttl = 3600

    try:
        max_entries = int(os.environ.get("REX_CACHE_MAX_ENTRIES", 500))
    except ValueError:
        logger.warning("Invalid REX_CACHE_MAX_ENTRIES, using default 500")
        max_entries = 500

    if ttl <= 0:
        ttl = 3600
    if max_entries <= 0:
        max_entries = 500

    return CacheConfig(ttl=ttl, max_entries=max_entries)


CACHE_CONFIG: CacheConfig = load_cache_config()
CACHE_TTL: int = CACHE_CONFIG.ttl
CACHE_MAX_ENTRIES: int = CACHE_CONFIG.max_entries


# ---------------------------------------------------------------------------
# REX-879: Webhook settings
# ---------------------------------------------------------------------------

GITHUB_WEBHOOK_SECRET: str = os.environ.get("GITHUB_WEBHOOK_SECRET", "")

# Maximum accepted webhook payload size in bytes.
# Protects against memory exhaustion from oversized POST bodies.
# cross_file_consistency: event_receiver.py also defines MAX_PAYLOAD_BYTES
# locally as 2_000_000. This is the canonical value — but if event_receiver
# is ever refactored to import from here, the local copy will silently win
# until the import is added.
MAX_PAYLOAD_BYTES: int = 1_000_000