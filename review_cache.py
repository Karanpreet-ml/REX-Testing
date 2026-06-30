"""
Review result cache — REX-863.

Stores AggregationResult keyed by a SHA-256 hash of the PR's
changed file contents. Skips re-analysis when content is unchanged.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from typing import Optional

from backend.services.review.finding_aggregator import AggregationResult
from backend.services.review.settings import CacheConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cache entry
# ---------------------------------------------------------------------------

@dataclass
class CacheEntry:
    key: str
    result: AggregationResult
    stored_at: float
    ttl: int


def _is_expired(entry: CacheEntry) -> bool:
    return (time.time() - entry.stored_at) > entry.ttl


# ---------------------------------------------------------------------------
# Cache key
# ---------------------------------------------------------------------------

def build_cache_key(file_paths_and_contents: list[tuple[str, str]]) -> str:
    """
    SHA-256 over sorted (path, content) pairs.
    Sorting ensures key is order-independent.
    """
    sorted_pairs = sorted(file_paths_and_contents, key=lambda x: x[0])
    combined = "".join(f"{path}:{content}" for path, content in sorted_pairs)
    return hashlib.sha256(combined.encode()).hexdigest()


# ---------------------------------------------------------------------------
# ReviewCache
# ---------------------------------------------------------------------------

class ReviewCache:
    """
    In-memory LRU-style cache for AggregationResult.

    AC: must not cache results where has_high_risk=True.
    AC: respects TTL and max_entries from CacheConfig.
    """

    def __init__(self, config: CacheConfig):
        self._config = config
        self._store: dict[str, CacheEntry] = {}
        self._access_order: list[str] = []

    def get(self, key: str) -> Optional[AggregationResult]:
        entry = self._store.get(key)
        if entry is None:
            return None
        if _is_expired(entry):
            self._evict(key)
            return None
        self._touch(key)
        return entry.result

    def set(self, key: str, result: AggregationResult) -> None:
        """
        Store result under key.

        Skips storage if result has_high_risk per AC requirement.
        Evicts oldest entry if at capacity.
        """
        if result.risk_report.has_high_risk:
            logger.debug("Cache: skipping high-risk result for key %s", key)
            return

        if len(self._store) >= self._config.max_entries:
            self._evict_oldest()

        entry = CacheEntry(
            key=key,
            result=result,
            stored_at=time.time(),
            ttl=self._config.ttl,
        )
        self._store[key] = entry
        self._access_order.append(key)
        logger.info("Cache: stored result for key %.12s", key)

    def invalidate(self, key: str) -> None:
        if key in self._store:
            self._evict(key)

    def _touch(self, key: str) -> None:
        if key in self._access_order:
            self._access_order.remove(key)
            self._access_order.append(key)

    def _evict(self, key: str) -> None:
        self._store.pop(key, None)
        if key in self._access_order:
            self._access_order.remove(key)

    def _evict_oldest(self) -> None:
        if self._access_order:
            oldest = self._access_order[0]
            self._evict(oldest)

    @property
    def size(self) -> int:
        return len(self._store)