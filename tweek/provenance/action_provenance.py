"""
Action Provenance Classification — Layer 0.25

Classifies every tool call's provenance before screening to distinguish
user-initiated actions from agent-generated or injection-driven ones.

The ONE unforgeable signal: when a user clicks "Allow" in Claude Code's UI,
an agent cannot fake that interaction. This is the basis for USER_VERIFIED.

Provenance Lattice (lowest → highest trust):
  UNKNOWN(0) → TAINT_INFLUENCED(1) → SKILL_CONTEXT(2) →
  AGENT_GENERATED(3) → USER_INITIATED(4) → USER_VERIFIED(5)

USER_VERIFIED persists for the entire run/turn once a user approves an `ask`
prompt, until taint escalation resets it (invariant #6: taint resets trust).
"""

from __future__ import annotations

from enum import IntEnum
from typing import Optional


class ActionProvenance(IntEnum):
    """Provenance lattice levels ordered by trust (lowest → highest)."""
    UNKNOWN = 0
    TAINT_INFLUENCED = 1
    SKILL_CONTEXT = 2
    AGENT_GENERATED = 3
    USER_INITIATED = 4
    USER_VERIFIED = 5


# String names matching the enum for serialization
PROVENANCE_NAMES = {v: v.name.lower() for v in ActionProvenance}
PROVENANCE_BY_NAME = {v.name.lower(): v for v in ActionProvenance}


def classify_provenance(
    session_id: str,
    tool_name: str,
    taint_level: str,
    active_skill: Optional[str] = None,
) -> str:
    """Classify action provenance from available signals.

    Classification priority (highest priority first):
    1. TAINT_INFLUENCED — session taint >= medium (overrides all trust)
    2. SKILL_CONTEXT — active skill breadcrumb (skills are untrusted)
    3. USER_VERIFIED — user approved an `ask` prompt this run (unforgeable)
    4. USER_INITIATED — first tool call in session (user just typed)
    5. AGENT_GENERATED — default for subsequent tool calls

    Args:
        session_id: Current session identifier.
        tool_name: The tool being invoked.
        taint_level: Current session taint level from provenance store.
        active_skill: Active skill name if any (from skill breadcrumb).

    Returns:
        Provenance level name as lowercase string (e.g. "user_verified").
    """
    # Priority 1: Taint overrides all trust signals
    # If the session has ingested suspicious content, user verification
    # is invalidated (invariant #6: taint resets trust)
    taint_rank = _TAINT_RANK.get(taint_level, 0)
    if taint_rank >= _TAINT_RANK["medium"]:
        return "taint_influenced"

    # Priority 2: Skill context — skills are untrusted by default
    if active_skill:
        return "skill_context"

    # Priority 3: Check for user ask-approval (persists for entire run)
    try:
        from tweek.memory.provenance import get_taint_store
        store = get_taint_store()
        state = store.get_session_taint(session_id)

        # USER_VERIFIED: user approved an ask prompt and taint hasn't reset it
        if state.get("ask_verified", False):
            return "user_verified"

        # USER_INITIATED: first tool call in this session
        if state.get("total_tool_calls", 0) == 0:
            return "user_initiated"

    except Exception:
        pass  # Provenance store unavailable — fall through to default

    # Default: agent-generated tool call
    return "agent_generated"


# Internal taint rank for comparison (mirrors provenance.TAINT_RANK)
_TAINT_RANK = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
