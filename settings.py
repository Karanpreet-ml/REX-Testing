"""
Review service settings — REX-863.

Centralises configuration for the review pipeline and cache.
Values are read from environment variables with safe defaults.
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CacheConfig
# ---------------------------------------------------------------------------

@dataclass
class CacheConfig:
    ttl: int             # seconds
    max_entries: int


def load_cache_config() -> CacheConfig:
    """
    Load cache config from env vars.

    REX_CACHE_TTL         — default 3600
    REX_CACHE_MAX_ENTRIES — default 500
    """
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
        logger.warning("REX_CACHE_TTL must be positive, resetting to 3600")
        ttl = 3600

    if max_entries <= 0:
        logger.warning("REX_CACHE_MAX_ENTRIES must be positive, resetting to 500")
        max_entries = 500

    return CacheConfig(ttl=ttl, max_entries=max_entries)


# ---------------------------------------------------------------------------
# Module-level singleton — loaded once at import time
# ---------------------------------------------------------------------------

CACHE_CONFIG: CacheConfig = load_cache_config()
CACHE_TTL: int = CACHE_CONFIG.ttl
CACHE_MAX_ENTRIES: int = CACHE_CONFIG.max_entries