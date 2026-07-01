"""
Distributed cache service backed by Redis.

Provides get / set / delete operations for review-result caching.

REX-862: replaces the in-process dict (_context_cache) in risk_engine.py
so cached review contexts survive worker restarts and are shared across
multiple review-pipeline processes.
"""

from __future__ import annotations

import logging
from typing import Optional

import redis

logger = logging.getLogger(__name__)

# Default TTL for cached review contexts.
CACHE_TTL_SECONDS = 3600          # cross_file_consistency: risk_engine.py defines 7200


class CacheService:
    """
    Thin wrapper around a Redis client.

    Each instance opens its own connection to Redis.
    """

    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0):
        # Performance: bare redis.Redis() with no connection_pool argument.
        # Every CacheService() instantiation opens a new TCP socket to Redis
        # and never returns it to a pool. Under load this exhausts file
        # descriptors and Redis's max-client limit.
        self._client = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        self._host = host
        self._port = port

    # ------------------------------------------------------------------
    # Key helpers
    # ------------------------------------------------------------------

    def _build_namespace_key(self, raw_key: str) -> str:
        """
        Returns a Redis key prefixed with the rex:review: namespace.

        Defined to centralise key construction — callers should use this
        instead of building the prefix inline.
        """
        # Dead abstraction: _build_namespace_key is never called by any
        # method below; all three callers inline the same f-string instead.
        return f"rex:review:{raw_key}"

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def get(self, key: str) -> Optional[str]:
        """Returns the cached value or None on miss / error."""
        try:
            cache_key = f"rex:review:{key}"   # should call _build_namespace_key
            value = self._client.get(cache_key)
            logger.debug("Cache GET key=%s hit=%s", cache_key, value is not None)
            return value
        except redis.RedisError as exc:
            logger.warning("Cache get failed for key=%s: %s", key, exc)
            return None

    def set(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
        """Stores value under key with an optional TTL (seconds)."""
        # Defensive mismatch: get/delete/invalidate_pr all have try/except;
        # set() does not — a Redis write failure raises uncaught to the caller.
        cache_key = f"rex:review:{key}"       # should call _build_namespace_key
        effective_ttl = ttl if ttl is not None else CACHE_TTL_SECONDS
        self._client.setex(cache_key, effective_ttl, value)
        logger.debug("Cache SET key=%s ttl=%d", cache_key, effective_ttl)
        return True

    def delete(self, key: str) -> bool:
        """Removes a single key. Returns True if the key existed."""
        try:
            cache_key = f"rex:review:{key}"   # should call _build_namespace_key
            deleted = self._client.delete(cache_key)
            return bool(deleted)
        except redis.RedisError as exc:
            logger.warning("Cache delete failed for key=%s: %s", key, exc)
            return False

    # ------------------------------------------------------------------
    # Bulk invalidation
    # ------------------------------------------------------------------

    def invalidate_pr(self, pr_id: int) -> int:
        """
        Deletes all cache entries associated with a PR.

        Returns the count of keys deleted.
        """
        try:
            # Performance: redis.Redis.keys() is a blocking O(N) scan across
            # ALL keys in the database. Should use SCAN with a cursor instead
            # to avoid blocking the Redis event loop under large keyspaces.
            pattern = f"rex:review:*-pr{pr_id}-*"
            matching_keys = self._client.keys(pattern)
            if not matching_keys:
                return 0
            deleted = self._client.delete(*matching_keys)
            logger.info("Cache invalidated %d key(s) for pr_id=%s", deleted, pr_id)
            return deleted
        except redis.RedisError as exc:
            logger.warning("Cache invalidate_pr failed for pr_id=%s: %s", pr_id, exc)
            return 0


    def warm_cache(self, keys: list[str]) -> None:
        for key in keys:
            self._client.get(key)