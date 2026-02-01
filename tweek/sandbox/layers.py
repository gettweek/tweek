"""
Tweek Sandbox Layers

Defines the isolation layer hierarchy and capability matrix.

Layer 0: Bypass        - No isolation, global state only (opt-in escape hatch)
Layer 1: Skills Only   - Skill Isolation Chamber (already built)
Layer 2: Project State - Per-project security DB, overrides, fingerprints, patterns (DEFAULT)
Layer 3+: Deferred     - Filesystem/container isolation via Docker bridge
"""

from enum import IntEnum
from typing import Dict, Set


class IsolationLayer(IntEnum):
    """Isolation layers ordered by increasing security."""

    BYPASS = 0       # No isolation, global state only
    SKILLS = 1       # Skill Isolation Chamber only
    PROJECT = 2      # Per-project security state (default)

    @classmethod
    def from_value(cls, value: int) -> "IsolationLayer":
        """Convert int to IsolationLayer, clamping to valid range."""
        try:
            return cls(value)
        except ValueError:
            if value < 0:
                return cls.BYPASS
            return cls.PROJECT


# Capability matrix: what each layer provides
LAYER_CAPABILITIES: Dict[IsolationLayer, Set[str]] = {
    IsolationLayer.BYPASS: set(),
    IsolationLayer.SKILLS: {
        "skill_scanning",
        "skill_fingerprints",
        "skill_guard",
    },
    IsolationLayer.PROJECT: {
        "skill_scanning",
        "skill_fingerprints",
        "skill_guard",
        "project_security_db",
        "project_overrides",
        "project_fingerprints",
        "project_config",
    },
}


def layer_has_capability(layer: IsolationLayer, capability: str) -> bool:
    """Check if a layer provides a specific capability."""
    return capability in LAYER_CAPABILITIES.get(layer, set())


def get_layer_description(layer: IsolationLayer) -> str:
    """Human-readable description of what a layer provides."""
    descriptions = {
        IsolationLayer.BYPASS: (
            "No isolation. All security state uses global ~/.tweek/. "
            "Skills are not scanned. Use only for trusted projects."
        ),
        IsolationLayer.SKILLS: (
            "Skill Isolation Chamber active. Skills are scanned before install. "
            "Security state uses global ~/.tweek/."
        ),
        IsolationLayer.PROJECT: (
            "Full project isolation. Security events, overrides, skill fingerprints, "
            "and configuration are scoped to this project's .tweek/ directory. "
            "Project overrides are additive-only (cannot weaken global security)."
        ),
    }
    return descriptions.get(layer, "Unknown layer")


# Severity ranking for additive-only merge
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def stricter_severity(a: str, b: str) -> str:
    """Return the stricter (lower threshold) of two severity levels.

    Severity thresholds define the MINIMUM severity to report:
    - "low" = report low+medium+high+critical (screens the most, strictest)
    - "critical" = report only critical (screens the least, most permissive)

    Higher rank number = screens more things = stricter.
    """
    rank_a = SEVERITY_ORDER.get(a, 3)
    rank_b = SEVERITY_ORDER.get(b, 3)
    # Higher rank = stricter = screens more things
    if rank_a >= rank_b:
        return a
    return b
