"""
Tweek Break-Glass Override System

Provides an audited escape path for hard-blocked (deny) patterns.
Break-glass downgrades "deny" to "ask" (never to "allow") — the user
still must explicitly approve after the override.

State file: ~/.tweek/break_glass.json
All uses are logged as BREAK_GLASS events for full audit trail.

The AI agent cannot execute `tweek override` — it requires a
separate CLI invocation by a human operator.
"""

import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional


BREAK_GLASS_PATH = Path.home() / ".tweek" / "break_glass.json"


def _load_state() -> Dict:
    """Load break-glass state from disk."""
    if not BREAK_GLASS_PATH.exists():
        return {"overrides": []}
    try:
        with open(BREAK_GLASS_PATH) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"overrides": []}


def _save_state(state: Dict) -> None:
    """Save break-glass state to disk."""
    BREAK_GLASS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(BREAK_GLASS_PATH, "w") as f:
        json.dump(state, f, indent=2)


def _now_iso() -> str:
    """Current time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def create_override(
    pattern_name: str,
    mode: str = "once",
    duration_minutes: Optional[int] = None,
    reason: str = "",
) -> Dict:
    """Create a new break-glass override.

    Args:
        pattern_name: The pattern to override (e.g., "ssh_key_read").
        mode: "once" (consumed on first use) or "duration" (time-limited).
        duration_minutes: Minutes until expiry (required for mode="duration").
        reason: Human-provided reason for the override.

    Returns:
        The created override dict.
    """
    state = _load_state()
    now = datetime.now(timezone.utc)

    override = {
        "pattern": pattern_name,
        "mode": mode,
        "reason": reason,
        "created_at": now.isoformat(),
        "expires_at": None,
        "used": False,
        "used_at": None,
    }

    if mode == "duration" and duration_minutes:
        expires = now + timedelta(minutes=duration_minutes)
        override["expires_at"] = expires.isoformat()

    state["overrides"].append(override)
    _save_state(state)
    return override


def check_override(pattern_name: str) -> Optional[Dict]:
    """Check if a valid break-glass override exists for a pattern.

    If a valid override is found:
    - For "once" mode: marks it as used (consumed)
    - For "duration" mode: checks expiry

    Returns the override dict if valid, None otherwise.
    """
    state = _load_state()
    now = datetime.now(timezone.utc)
    found = None

    for override in state["overrides"]:
        if override["pattern"] != pattern_name:
            continue

        # Skip already-consumed single-use overrides
        if override["mode"] == "once" and override.get("used"):
            continue

        # Check expiry for duration-based overrides
        if override.get("expires_at"):
            try:
                expires = datetime.fromisoformat(override["expires_at"])
                if now > expires:
                    continue
            except (ValueError, TypeError):
                continue

        found = override
        break

    if found:
        # Consume single-use overrides
        if found["mode"] == "once":
            found["used"] = True
            found["used_at"] = now.isoformat()
            _save_state(state)

    return found


def list_overrides() -> List[Dict]:
    """List all overrides (including expired/consumed for audit)."""
    state = _load_state()
    return state.get("overrides", [])


def list_active_overrides() -> List[Dict]:
    """List only currently active (non-expired, non-consumed) overrides."""
    state = _load_state()
    now = datetime.now(timezone.utc)
    active = []

    for override in state.get("overrides", []):
        if override["mode"] == "once" and override.get("used"):
            continue
        if override.get("expires_at"):
            try:
                expires = datetime.fromisoformat(override["expires_at"])
                if now > expires:
                    continue
            except (ValueError, TypeError):
                continue
        active.append(override)

    return active


def clear_overrides() -> int:
    """Remove all overrides. Returns count of removed overrides."""
    state = _load_state()
    count = len(state.get("overrides", []))
    state["overrides"] = []
    _save_state(state)
    return count
