"""
Tweek False-Positive Feedback Loop

Tracks per-pattern false positive rates and automatically demotes
noisy patterns when their FP rate exceeds the threshold.

State file: ~/.tweek/feedback.json

Threshold: 5% FP rate with minimum 20 triggers (Google Tricorder standard).
CRITICAL patterns are never auto-demoted (safety constraint).
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional


FEEDBACK_PATH = Path.home() / ".tweek" / "feedback.json"

# Google Tricorder threshold: 5% max FP rate
FP_THRESHOLD = 0.05
MIN_TRIGGERS_FOR_DEMOTION = 20

# Severity demotion chain: critical is never demoted
DEMOTION_MAP = {
    "high": "medium",
    "medium": "low",
    "low": "low",  # Already at lowest
}

# Severities immune from auto-demotion
IMMUNE_SEVERITIES = {"critical"}


def _load_state() -> Dict:
    """Load feedback state from disk."""
    if not FEEDBACK_PATH.exists():
        return {"patterns": {}}
    try:
        with open(FEEDBACK_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"patterns": {}}


def _save_state(state: Dict) -> None:
    """Save feedback state to disk."""
    FEEDBACK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(FEEDBACK_PATH, "w") as f:
        json.dump(state, f, indent=2)


def record_trigger(pattern_name: str, severity: str) -> None:
    """Record that a pattern triggered (called after USER_APPROVED event).

    This increments the total trigger count for FP rate calculation.
    """
    state = _load_state()
    patterns = state.setdefault("patterns", {})

    if pattern_name not in patterns:
        patterns[pattern_name] = {
            "total_triggers": 0,
            "false_positives": 0,
            "fp_rate": 0.0,
            "last_trigger_at": None,
            "last_fp_at": None,
            "auto_demoted": False,
            "original_severity": severity,
            "current_severity": severity,
        }

    entry = patterns[pattern_name]
    entry["total_triggers"] += 1
    entry["last_trigger_at"] = datetime.now(timezone.utc).isoformat()
    _update_fp_rate(entry)
    _save_state(state)


def report_false_positive(pattern_name: str, context: str = "") -> Dict:
    """Report a false positive for a pattern.

    Returns the updated pattern stats dict.
    """
    state = _load_state()
    patterns = state.setdefault("patterns", {})

    if pattern_name not in patterns:
        patterns[pattern_name] = {
            "total_triggers": 1,  # At least 1 trigger to report FP
            "false_positives": 0,
            "fp_rate": 0.0,
            "last_trigger_at": None,
            "last_fp_at": None,
            "auto_demoted": False,
            "original_severity": "unknown",
            "current_severity": "unknown",
        }

    entry = patterns[pattern_name]
    entry["false_positives"] += 1
    entry["last_fp_at"] = datetime.now(timezone.utc).isoformat()

    if context:
        contexts = entry.setdefault("fp_contexts", [])
        contexts.append({
            "context": context,
            "reported_at": datetime.now(timezone.utc).isoformat(),
        })
        # Keep last 10 contexts
        entry["fp_contexts"] = contexts[-10:]

    _update_fp_rate(entry)
    _check_auto_demotion(entry)
    _save_state(state)

    return dict(entry)


def _update_fp_rate(entry: Dict) -> None:
    """Recalculate FP rate from counts."""
    total = entry.get("total_triggers", 0)
    if total > 0:
        entry["fp_rate"] = entry.get("false_positives", 0) / total
    else:
        entry["fp_rate"] = 0.0


def _check_auto_demotion(entry: Dict) -> None:
    """Check if pattern should be auto-demoted based on FP rate."""
    # Already demoted
    if entry.get("auto_demoted"):
        return

    # Not enough data
    if entry.get("total_triggers", 0) < MIN_TRIGGERS_FOR_DEMOTION:
        return

    # Below threshold
    if entry.get("fp_rate", 0) < FP_THRESHOLD:
        return

    # CRITICAL patterns are never auto-demoted
    original = entry.get("original_severity", "")
    if original in IMMUNE_SEVERITIES:
        return

    # Auto-demote
    demoted_to = DEMOTION_MAP.get(original, original)
    if demoted_to != original:
        entry["auto_demoted"] = True
        entry["current_severity"] = demoted_to
        entry["demoted_at"] = datetime.now(timezone.utc).isoformat()


def get_effective_severity(pattern_name: str, original_severity: str) -> str:
    """Get the effective severity for a pattern, accounting for FP demotions.

    Args:
        pattern_name: The pattern name.
        original_severity: The severity from patterns.yaml.

    Returns:
        The effective severity (may be demoted).
    """
    state = _load_state()
    entry = state.get("patterns", {}).get(pattern_name)
    if entry and entry.get("auto_demoted"):
        return entry.get("current_severity", original_severity)
    return original_severity


def get_stats() -> Dict[str, Dict]:
    """Get all pattern feedback statistics."""
    state = _load_state()
    return state.get("patterns", {})


def reset_pattern(pattern_name: str) -> Optional[Dict]:
    """Reset FP tracking and undo auto-demotion for a pattern.

    Returns info about what was reset, or None if pattern not found.
    """
    state = _load_state()
    patterns = state.get("patterns", {})

    if pattern_name not in patterns:
        return None

    entry = patterns[pattern_name]
    result = {
        "was_demoted": entry.get("auto_demoted", False),
        "original_severity": entry.get("original_severity"),
        "previous_fp_rate": entry.get("fp_rate"),
    }

    del patterns[pattern_name]
    _save_state(state)

    return result
