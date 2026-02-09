"""
Tweek Session Provenance & Taint Tracking

Tracks the "trust lineage" of commands within a session.
When external content is ingested (Read, WebFetch, WebSearch)
and that content contains suspicious patterns, the session
becomes "tainted" — subsequent commands receive heightened scrutiny.

When a session is "clean" (no external content or all content
from trusted sources), enforcement thresholds are relaxed to
reduce false positives.

Taint levels: clean → low → medium → high → critical
Taint decays by one level every DECAY_INTERVAL tool calls
without new external content or pattern matches.

Storage: SQLite persistent in memory.db (same DB as pattern decisions).
"""

from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any

# =========================================================================
# Constants
# =========================================================================

# Taint levels in order of severity
TAINT_LEVELS = ("clean", "low", "medium", "high", "critical")
TAINT_RANK = {level: i for i, level in enumerate(TAINT_LEVELS)}

# How many tool calls between taint decay steps
DECAY_INTERVAL = 5

# Tools classified as external content sources (derived from tool registry)
def _tools_for_capabilities(*caps):
    from tweek.tools.registry import get_registry
    r = get_registry()
    return frozenset(r.canonical_for_capability(c) for c in caps if r.canonical_for_capability(c))

EXTERNAL_SOURCE_TOOLS = _tools_for_capabilities("file_read", "web_fetch", "web_search", "content_search")

# Tools classified as action tools (user-context)
ACTION_TOOLS = _tools_for_capabilities("shell_execution", "file_write", "file_edit", "notebook_edit")


# =========================================================================
# Schema
# =========================================================================

PROVENANCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS session_taint (
    session_id TEXT PRIMARY KEY,
    taint_level TEXT NOT NULL DEFAULT 'clean',
    last_taint_source TEXT,
    last_taint_reason TEXT,
    turns_since_taint INTEGER NOT NULL DEFAULT 0,
    total_tool_calls INTEGER NOT NULL DEFAULT 0,
    total_external_ingests INTEGER NOT NULL DEFAULT 0,
    total_taint_escalations INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_st_taint_level
    ON session_taint(taint_level);
"""


# =========================================================================
# Taint Level Operations
# =========================================================================

def escalate_taint(current: str, to_level: str) -> str:
    """Escalate taint level (never downgrade via this function).

    Returns the higher of current and to_level.
    """
    current_rank = TAINT_RANK.get(current, 0)
    target_rank = TAINT_RANK.get(to_level, 0)
    if target_rank > current_rank:
        return to_level
    return current


def decay_taint(current: str) -> str:
    """Decay taint level by one step toward 'clean'.

    Returns the next lower taint level.
    """
    rank = TAINT_RANK.get(current, 0)
    if rank <= 0:
        return "clean"
    return TAINT_LEVELS[rank - 1]


def severity_to_taint(pattern_severity: str) -> str:
    """Map a pattern severity to a taint level.

    critical pattern → critical taint
    high pattern → high taint
    medium pattern → medium taint
    low pattern → low taint
    """
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }
    return mapping.get(pattern_severity, "medium")


# =========================================================================
# Session Taint Store
# =========================================================================

class SessionTaintStore:
    """SQLite-backed session taint tracking.

    Uses the same database as MemoryStore (memory.db) but manages
    its own table (session_taint).
    """

    def __init__(self, db_path: Optional[Path] = None):
        from tweek.memory.store import GLOBAL_MEMORY_PATH
        self.db_path = db_path or GLOBAL_MEMORY_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._ensure_schema()

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(
                str(self.db_path),
                timeout=5.0,
                isolation_level=None,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    def close(self):
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _ensure_schema(self):
        conn = self._get_connection()
        conn.executescript(PROVENANCE_SCHEMA)

    def get_session_taint(self, session_id: str) -> Dict[str, Any]:
        """Get current taint state for a session.

        Returns a dict with taint_level, turns_since_taint, etc.
        Returns a "clean" default if session not found.
        """
        conn = self._get_connection()
        row = conn.execute(
            "SELECT * FROM session_taint WHERE session_id = ?",
            (session_id,),
        ).fetchone()

        if row is None:
            return {
                "taint_level": "clean",
                "turns_since_taint": 0,
                "total_tool_calls": 0,
                "total_external_ingests": 0,
                "total_taint_escalations": 0,
                "last_taint_source": None,
                "last_taint_reason": None,
            }

        return dict(row)

    def record_tool_call(self, session_id: str, tool_name: str) -> Dict[str, Any]:
        """Record a tool call and apply taint decay if applicable.

        Called from pre_tool_use to track tool calls and decay taint.
        Returns the updated taint state.
        """
        conn = self._get_connection()
        state = self.get_session_taint(session_id)

        new_total = state["total_tool_calls"] + 1
        new_turns_since_taint = state["turns_since_taint"] + 1

        # Apply decay if enough clean turns have passed
        current_taint = state["taint_level"]
        if (current_taint != "clean"
                and new_turns_since_taint >= DECAY_INTERVAL):
            current_taint = decay_taint(current_taint)
            new_turns_since_taint = 0  # Reset counter after decay

        # Upsert
        conn.execute("""
            INSERT INTO session_taint
                (session_id, taint_level, turns_since_taint,
                 total_tool_calls, total_external_ingests,
                 total_taint_escalations,
                 last_taint_source, last_taint_reason,
                 updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(session_id) DO UPDATE SET
                taint_level = excluded.taint_level,
                turns_since_taint = excluded.turns_since_taint,
                total_tool_calls = excluded.total_tool_calls,
                updated_at = datetime('now')
        """, (
            session_id, current_taint, new_turns_since_taint,
            new_total, state["total_external_ingests"],
            state["total_taint_escalations"],
            state["last_taint_source"], state["last_taint_reason"],
        ))

        state["taint_level"] = current_taint
        state["turns_since_taint"] = new_turns_since_taint
        state["total_tool_calls"] = new_total
        return state

    def record_taint(
        self,
        session_id: str,
        taint_level: str,
        source: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Escalate session taint after finding suspicious content.

        Called from post_tool_use when patterns are found in ingested content.
        Taint only escalates, never downgrades via this method.
        Returns the updated taint state.
        """
        conn = self._get_connection()
        state = self.get_session_taint(session_id)

        new_taint = escalate_taint(state["taint_level"], taint_level)
        new_escalations = state["total_taint_escalations"]
        if new_taint != state["taint_level"]:
            new_escalations += 1

        new_ingests = state["total_external_ingests"] + 1

        conn.execute("""
            INSERT INTO session_taint
                (session_id, taint_level, turns_since_taint,
                 total_tool_calls, total_external_ingests,
                 total_taint_escalations,
                 last_taint_source, last_taint_reason,
                 updated_at)
            VALUES (?, ?, 0, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(session_id) DO UPDATE SET
                taint_level = excluded.taint_level,
                turns_since_taint = 0,
                total_tool_calls = excluded.total_tool_calls,
                total_external_ingests = excluded.total_external_ingests,
                total_taint_escalations = excluded.total_taint_escalations,
                last_taint_source = excluded.last_taint_source,
                last_taint_reason = excluded.last_taint_reason,
                updated_at = datetime('now')
        """, (
            session_id, new_taint,
            state["total_tool_calls"], new_ingests,
            new_escalations, source, reason,
        ))

        state["taint_level"] = new_taint
        state["turns_since_taint"] = 0
        state["total_external_ingests"] = new_ingests
        state["total_taint_escalations"] = new_escalations
        state["last_taint_source"] = source
        state["last_taint_reason"] = reason
        return state

    def record_external_ingest(self, session_id: str, source: str):
        """Record an external content ingest without escalating taint.

        Called when Read/WebFetch returns content that passes screening.
        Tracks the ingest count but doesn't change taint level.
        """
        conn = self._get_connection()
        state = self.get_session_taint(session_id)

        conn.execute("""
            INSERT INTO session_taint
                (session_id, taint_level, turns_since_taint,
                 total_tool_calls, total_external_ingests,
                 total_taint_escalations,
                 last_taint_source, last_taint_reason,
                 updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            ON CONFLICT(session_id) DO UPDATE SET
                total_external_ingests = excluded.total_external_ingests,
                updated_at = datetime('now')
        """, (
            session_id, state["taint_level"],
            state["turns_since_taint"],
            state["total_tool_calls"],
            state["total_external_ingests"] + 1,
            state["total_taint_escalations"],
            source, state["last_taint_reason"],
        ))

    def clear_session(self, session_id: str):
        """Remove taint tracking for a session."""
        conn = self._get_connection()
        conn.execute(
            "DELETE FROM session_taint WHERE session_id = ?",
            (session_id,),
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get aggregate stats across all tracked sessions."""
        conn = self._get_connection()
        row = conn.execute("""
            SELECT
                COUNT(*) as total_sessions,
                SUM(CASE WHEN taint_level = 'clean' THEN 1 ELSE 0 END) as clean_sessions,
                SUM(CASE WHEN taint_level != 'clean' THEN 1 ELSE 0 END) as tainted_sessions,
                SUM(total_taint_escalations) as total_escalations,
                SUM(total_external_ingests) as total_ingests
            FROM session_taint
        """).fetchone()

        return dict(row) if row else {
            "total_sessions": 0,
            "clean_sessions": 0,
            "tainted_sessions": 0,
            "total_escalations": 0,
            "total_ingests": 0,
        }


# =========================================================================
# Enforcement Adjustment
# =========================================================================

# The "balanced" preset enforcement matrix for CLEAN sessions
# Compared to "cautious" default, this logs instead of asking for
# heuristic/contextual patterns in high severity
BALANCED_CLEAN_OVERRIDES = {
    "critical": {"contextual": "log"},  # Don't prompt on broad contextual
    "high": {"heuristic": "log", "contextual": "log"},  # Don't prompt on heuristic
    "medium": {"deterministic": "log", "heuristic": "log", "contextual": "log"},
}


def adjust_enforcement_for_taint(
    base_decision: str,
    severity: str,
    confidence: str,
    taint_level: str,
) -> str:
    """Adjust an enforcement decision based on session taint level.

    In CLEAN sessions: relax heuristic/contextual patterns to "log"
    In TAINTED sessions: keep base enforcement (or escalate)

    Args:
        base_decision: The decision from EnforcementPolicy.resolve()
        severity: Pattern severity (critical/high/medium/low)
        confidence: Pattern confidence (deterministic/heuristic/contextual)
        taint_level: Current session taint level

    Returns:
        Adjusted decision: "deny", "ask", or "log"
    """
    # Never relax a "deny" decision — deny is hardcoded by policy.
    # This also covers critical+deterministic (always deny from policy).
    # Note: break-glass may downgrade deny→ask before we see it, and
    # we should respect that intentional override.
    if base_decision == "deny":
        return "deny"

    # In clean sessions, apply the balanced overrides
    if taint_level == "clean":
        override = BALANCED_CLEAN_OVERRIDES.get(severity, {}).get(confidence)
        if override is not None:
            return override

    # In tainted sessions (medium+), consider escalation
    if TAINT_RANK.get(taint_level, 0) >= TAINT_RANK["medium"]:
        # Escalate "log" to "ask" for heuristic patterns
        if base_decision == "log" and confidence in ("heuristic", "deterministic"):
            if severity in ("critical", "high"):
                return "ask"

    # In critically tainted sessions, escalate everything
    if taint_level == "critical":
        if base_decision == "log" and severity in ("critical", "high", "medium"):
            return "ask"

    return base_decision


def should_skip_llm_for_clean_session(
    taint_level: str,
    tool_tier: str,
) -> bool:
    """Determine if LLM review can be skipped for clean sessions.

    In clean sessions, default-tier tools don't need LLM review
    since there's no external content that could contain injection.

    Args:
        taint_level: Current session taint level
        tool_tier: The tier of the tool (safe/default/risky/dangerous)

    Returns:
        True if LLM review can be skipped
    """
    if taint_level != "clean":
        return False
    # Only skip for default tier (Read, Edit, NotebookEdit)
    # Risky and dangerous always get LLM review
    return tool_tier == "default"


# =========================================================================
# Singleton
# =========================================================================

_taint_store: Optional[SessionTaintStore] = None


def get_taint_store(db_path: Optional[Path] = None) -> SessionTaintStore:
    """Get the singleton SessionTaintStore instance."""
    global _taint_store
    if _taint_store is None:
        _taint_store = SessionTaintStore(db_path)
    return _taint_store


def reset_taint_store():
    """Reset the singleton (for testing)."""
    global _taint_store
    if _taint_store is not None:
        _taint_store.close()
    _taint_store = None
