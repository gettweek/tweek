"""
Tweek Memory Safety Module

Enforces non-negotiable safety invariants for memory-based adjustments.

Rules:
1. CRITICAL+deterministic patterns are immune - memory NEVER adjusts them
2. One-step max relaxation: ask -> log only (never deny -> anything)
3. Additive-only project merge: project can escalate, never relax
4. Minimum threshold: 10+ weighted decisions before any adjustment
"""

from typing import Optional

# Patterns that are immune from any memory-based adjustment.
# These are CRITICAL+deterministic patterns that should always deny.
IMMUNE_SEVERITIES = frozenset({"critical"})
IMMUNE_CONFIDENCES = frozenset({"deterministic"})

# Decision hierarchy: deny > ask > log > allow
DECISION_RANK = {"deny": 3, "ask": 2, "log": 1, "allow": 0}

# Maximum relaxation: current_decision -> max allowed relaxation target
# deny -> NOTHING (immune)
# ask -> log (one step down)
# log -> log (already minimum observable)
MAX_RELAXATION = {
    "deny": "deny",   # Never relax deny
    "ask": "log",      # Can relax to log
    "log": "log",      # Already at minimum
    "allow": "allow",  # Already at minimum
}

# Context-scoped decision thresholds: narrower context = fewer decisions needed.
# The system tries scopes narrowest-first and returns the first match.
# Global (pattern-only) is intentionally absent — too broad to be safe.
SCOPED_THRESHOLDS = {
    "exact": 3,          # pattern + tool + path + project
    "tool_project": 5,   # pattern + tool + project
    "path": 8,           # pattern + path_prefix
}

# Minimum weighted decisions (backward compat — smallest scope threshold)
MIN_DECISION_THRESHOLD = SCOPED_THRESHOLDS["exact"]

# Decisions must span at least this many hours to qualify for adjustment.
# Prevents a rapid burst of approvals from bypassing thresholds.
MIN_DECISION_SPAN_HOURS = 1

# Minimum approval ratio to suggest relaxation
MIN_APPROVAL_RATIO = 0.90  # 90% approval rate

# Minimum confidence score to actually apply an adjustment
MIN_CONFIDENCE_SCORE = 0.80


def is_immune_pattern(severity: str, confidence: str) -> bool:
    """Check if a pattern is immune from memory adjustment.

    CRITICAL+deterministic patterns are NEVER adjusted by memory.
    This is a hard safety invariant enforced at every layer.
    """
    return (
        severity.lower() in IMMUNE_SEVERITIES
        and confidence.lower() in IMMUNE_CONFIDENCES
    )


def get_max_relaxation(current_decision: str) -> str:
    """Get the maximum allowed relaxation target for a decision.

    Returns the most relaxed decision memory is allowed to suggest.
    """
    return MAX_RELAXATION.get(current_decision, current_decision)


def validate_memory_adjustment(
    pattern_name: str,
    original_severity: str,
    original_confidence: str,
    suggested_decision: str,
    current_decision: str,
) -> str:
    """Validate and potentially apply a memory-suggested decision adjustment.

    Returns the final decision after safety validation. This is the last
    gate before a memory adjustment takes effect.

    Args:
        pattern_name: The pattern being evaluated
        original_severity: Pattern's severity level
        original_confidence: Pattern's confidence level
        suggested_decision: What memory suggests
        current_decision: The decision from enforcement policy

    Returns:
        The validated decision (may be same as current if adjustment rejected)
    """
    # Rule 1: CRITICAL+deterministic are immune
    if is_immune_pattern(original_severity, original_confidence):
        return current_decision

    # Rule 2: deny is never relaxed by memory
    if current_decision == "deny":
        return current_decision

    # Rule 3: Can only relax, never escalate via memory
    # Memory is for reducing noise, not adding blocks
    suggested_rank = DECISION_RANK.get(suggested_decision, 2)
    current_rank = DECISION_RANK.get(current_decision, 2)
    if suggested_rank >= current_rank:
        # Suggested is same or stricter - no change needed
        return current_decision

    # Rule 4: Maximum one-step relaxation
    max_relaxation = get_max_relaxation(current_decision)
    max_rank = DECISION_RANK.get(max_relaxation, 2)
    if suggested_rank < max_rank:
        # Suggested goes beyond max relaxation - clamp to max
        return max_relaxation

    return suggested_decision


def compute_suggested_decision(
    current_decision: str,
    approval_ratio: float,
    total_weighted_decisions: float,
    original_severity: str,
    original_confidence: str,
    min_threshold: Optional[float] = None,
) -> Optional[str]:
    """Compute what decision memory would suggest, if any.

    Returns None if memory has no suggestion (insufficient data or
    pattern is immune).

    Args:
        min_threshold: Override the minimum weighted-decision threshold.
            Used by scoped queries where narrower context requires fewer
            decisions. Defaults to SCOPED_THRESHOLDS["path"] (broadest
            allowed scope).
    """
    if min_threshold is None:
        min_threshold = SCOPED_THRESHOLDS["path"]

    # Immune patterns get no suggestions
    if is_immune_pattern(original_severity, original_confidence):
        return None

    # Insufficient data for this scope
    if total_weighted_decisions < min_threshold:
        return None

    # deny is never relaxed
    if current_decision == "deny":
        return None

    # Only suggest relaxation if approval ratio is very high
    if approval_ratio >= MIN_APPROVAL_RATIO and current_decision == "ask":
        return "log"

    return None
