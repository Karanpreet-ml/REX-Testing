"""
Agent configuration loader — REX-857.

Loads per-agent confidence thresholds from environment variables.
Used by FindingAggregator to suppress low-confidence findings
before deduplication.
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_CONFIDENCE_THRESHOLDS: dict[str, float] = {
    "logic":       0.75,
    "quality":     0.65,
    "performance": 0.70,
    "security":    0.60,
}

_ENV_PREFIX = "REX_AGENT_CONF_THRESHOLD_"


# ---------------------------------------------------------------------------
# AgentConfig dataclass
# ---------------------------------------------------------------------------

@dataclass
class AgentConfig:
    agent_name: str
    confidence_threshold: float

    def should_suppress(self, confidence: float) -> bool:
        return confidence < self.confidence_threshold


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def _load_agent_config(agent_name: str) -> AgentConfig:
    """
    Load threshold for a single agent from env, falling back to default.

    Env var format: REX_AGENT_CONF_THRESHOLD_
    e.g. REX_AGENT_CONF_THRESHOLD_SECURITY=0.55
    """
    env_key = f"{_ENV_PREFIX}{agent_name.upper()}"
    raw = os.environ.get(env_key)

    if raw is not None:
        try:
            threshold = float(raw)
            if not (0.0 <= threshold <= 1.0):
                logger.warning(
                    "Threshold for agent '%s' out of range (%.2f), using default",
                    agent_name, threshold,
                )
                threshold = DEFAULT_CONFIDENCE_THRESHOLDS.get(agent_name, 0.70)
        except ValueError:
            logger.warning(
                "Invalid threshold env var %s=%r, using default", env_key, raw
            )
            threshold = DEFAULT_CONFIDENCE_THRESHOLDS.get(agent_name, 0.70)
    else:
        threshold = DEFAULT_CONFIDENCE_THRESHOLDS.get(agent_name, 0.70)

    return AgentConfig(agent_name=agent_name, confidence_threshold=threshold)


def load_all_agent_configs(agent_names: list[str]) -> dict[str, AgentConfig]:
    """Return a config dict keyed by agent name."""
    return {name: _load_agent_config(name) for name in agent_names}