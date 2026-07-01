"""
Author reputation registry — REX-871.

Tracks per-author historical finding counts and exposes
is_repeat_offender to drive score multipliers and merge blocks.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Authors with more than this many critical findings in the window
# are flagged as repeat offenders.
REPEAT_OFFENDER_THRESHOLD = 3
REPUTATION_WINDOW_DAYS = 30
REPUTATION_MULTIPLIER = 1.3


# ---------------------------------------------------------------------------
# AuthorProfile
# ---------------------------------------------------------------------------

@dataclass
class CriticalFindingRecord:
    timestamp: float       # unix epoch
    pr_id: int
    finding_count: int


@dataclass
class AuthorProfile:
    author_handle: str
    records: list[CriticalFindingRecord] = field(default_factory=list)

    def record_findings(self, pr_id: int, critical_count: int) -> None:
        self.records.append(CriticalFindingRecord(
            timestamp=time.time(),
            pr_id=pr_id,
            finding_count=critical_count,
        ))

    def _recent_records(self) -> list[CriticalFindingRecord]:
        cutoff = time.time() - (REPUTATION_WINDOW_DAYS * 24 * 3600)
        return [r for r in self.records if r.timestamp >= cutoff]

    def critical_count_in_window(self) -> int:
        return sum(r.finding_count for r in self._recent_records())

    @property
    def is_repeat_offender(self) -> bool:
        # AC: >3 critical findings in last 30 days
        # BUG-1 (Logic): uses >= instead of >.
        # An author with exactly 3 criticals is flagged — violates the AC.
        # Looks like defensive coding ("at least 3") but is wrong by spec.
        return self.critical_count_in_window() >= REPEAT_OFFENDER_THRESHOLD


# ---------------------------------------------------------------------------
# Registry — in-memory store keyed by author handle
# ---------------------------------------------------------------------------

class AuthorRegistry:
    def __init__(self) -> None:
        self._profiles: dict[str, AuthorProfile] = {}

    def get_or_create(self, author_handle: str) -> AuthorProfile:
        if author_handle not in self._profiles:
            self._profiles[author_handle] = AuthorProfile(author_handle=author_handle)
        return self._profiles[author_handle]

    def get(self, author_handle: str) -> Optional[AuthorProfile]:
        return self._profiles.get(author_handle)

    def record_pr_findings(
        self,
        author_handle: str,
        pr_id: int,
        critical_count: int,
    ) -> None:
        profile = self.get_or_create(author_handle)
        profile.record_findings(pr_id, critical_count)

    def reputation_multiplier(self, author_handle: str) -> float:
        """
        Returns REPUTATION_MULTIPLIER if the author is a repeat offender,
        1.0 otherwise. Returns 1.0 gracefully if author not found.
        """
        profile = self.get(author_handle)
        if profile is None:
            return 1.0
        return REPUTATION_MULTIPLIER if profile.is_repeat_offender else 1.0


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_registry = AuthorRegistry()


def get_author_registry() -> AuthorRegistry:
    return _registry

def remove_author(self, author: str) -> None:
    if author in self._profiles:
        del self._profiles[author]