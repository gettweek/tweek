"""
Tests for Action Provenance Classification (Layer 0.25)

Tests classify_provenance() under various session states:
- Clean session, no approvals → AGENT_GENERATED
- After ask approval → USER_VERIFIED (persists for entire run)
- First tool call → USER_INITIATED
- Active skill → SKILL_CONTEXT
- Tainted session → TAINT_INFLUENCED
- Taint after verification → resets to TAINT_INFLUENCED
"""
from __future__ import annotations

import pytest
from pathlib import Path

from tweek.memory.provenance import (
    SessionTaintStore,
    reset_taint_store,
    escalate_taint,
)
from tweek.provenance.action_provenance import (
    ActionProvenance,
    PROVENANCE_NAMES,
    PROVENANCE_BY_NAME,
    classify_provenance,
)


@pytest.fixture
def store(tmp_path):
    """Create a fresh SessionTaintStore with isolated DB."""
    reset_taint_store()
    db_path = tmp_path / "test_memory.db"
    s = SessionTaintStore(db_path=db_path)
    yield s
    s.close()
    reset_taint_store()


@pytest.fixture(autouse=True)
def _patch_taint_store(store, monkeypatch):
    """Patch get_taint_store to return our test store."""
    monkeypatch.setattr(
        "tweek.memory.provenance.get_taint_store",
        lambda db_path=None: store,
    )
    # Also patch in the action_provenance module
    monkeypatch.setattr(
        "tweek.provenance.action_provenance.get_taint_store",
        lambda: store,
        raising=False,
    )


class TestActionProvenanceEnum:
    """Test the ActionProvenance enum and ordering."""

    def test_enum_values(self):
        assert ActionProvenance.UNKNOWN == 0
        assert ActionProvenance.TAINT_INFLUENCED == 1
        assert ActionProvenance.SKILL_CONTEXT == 2
        assert ActionProvenance.AGENT_GENERATED == 3
        assert ActionProvenance.USER_INITIATED == 4
        assert ActionProvenance.USER_VERIFIED == 5

    def test_ordering(self):
        assert ActionProvenance.UNKNOWN < ActionProvenance.TAINT_INFLUENCED
        assert ActionProvenance.TAINT_INFLUENCED < ActionProvenance.SKILL_CONTEXT
        assert ActionProvenance.SKILL_CONTEXT < ActionProvenance.AGENT_GENERATED
        assert ActionProvenance.AGENT_GENERATED < ActionProvenance.USER_INITIATED
        assert ActionProvenance.USER_INITIATED < ActionProvenance.USER_VERIFIED

    def test_provenance_names(self):
        assert PROVENANCE_NAMES[ActionProvenance.USER_VERIFIED] == "user_verified"
        assert PROVENANCE_BY_NAME["agent_generated"] == ActionProvenance.AGENT_GENERATED


class TestClassifyProvenance:
    """Test classify_provenance() under various session states."""

    def test_first_tool_call_is_user_initiated(self, store):
        """First tool call in a new session → USER_INITIATED."""
        # New session, no tool calls yet
        result = classify_provenance(
            session_id="sess-new",
            tool_name="Bash",
            taint_level="clean",
        )
        assert result == "user_initiated"

    def test_subsequent_call_is_agent_generated(self, store):
        """Subsequent tool calls → AGENT_GENERATED (default)."""
        store.record_tool_call("sess-1", "Read")
        result = classify_provenance(
            session_id="sess-1",
            tool_name="Bash",
            taint_level="clean",
        )
        assert result == "agent_generated"

    def test_after_ask_approval_is_user_verified(self, store):
        """After user approves an ask → USER_VERIFIED."""
        store.record_tool_call("sess-2", "Read")
        store.record_ask_approval("sess-2")
        result = classify_provenance(
            session_id="sess-2",
            tool_name="Bash",
            taint_level="clean",
        )
        assert result == "user_verified"

    def test_user_verified_persists_across_many_calls(self, store):
        """USER_VERIFIED persists for the entire run (no fixed window)."""
        store.record_tool_call("sess-3", "Read")
        store.record_ask_approval("sess-3")

        # Simulate many subsequent tool calls
        for i in range(20):
            store.record_tool_call("sess-3", "Bash")

        result = classify_provenance(
            session_id="sess-3",
            tool_name="Edit",
            taint_level="clean",
        )
        assert result == "user_verified"

    def test_active_skill_is_skill_context(self, store):
        """Active skill breadcrumb → SKILL_CONTEXT."""
        store.record_tool_call("sess-4", "Read")
        result = classify_provenance(
            session_id="sess-4",
            tool_name="Bash",
            taint_level="clean",
            active_skill="my-skill",
        )
        assert result == "skill_context"

    def test_skill_context_overrides_user_verified(self, store):
        """SKILL_CONTEXT takes priority over USER_VERIFIED."""
        store.record_tool_call("sess-5", "Read")
        store.record_ask_approval("sess-5")
        result = classify_provenance(
            session_id="sess-5",
            tool_name="Bash",
            taint_level="clean",
            active_skill="some-skill",
        )
        assert result == "skill_context"

    def test_medium_taint_is_taint_influenced(self, store):
        """Session taint >= medium → TAINT_INFLUENCED."""
        store.record_tool_call("sess-6", "Read")
        result = classify_provenance(
            session_id="sess-6",
            tool_name="Bash",
            taint_level="medium",
        )
        assert result == "taint_influenced"

    def test_high_taint_is_taint_influenced(self, store):
        store.record_tool_call("sess-7", "Read")
        result = classify_provenance(
            session_id="sess-7",
            tool_name="Bash",
            taint_level="high",
        )
        assert result == "taint_influenced"

    def test_critical_taint_is_taint_influenced(self, store):
        store.record_tool_call("sess-8", "Read")
        result = classify_provenance(
            session_id="sess-8",
            tool_name="Bash",
            taint_level="critical",
        )
        assert result == "taint_influenced"

    def test_low_taint_not_taint_influenced(self, store):
        """Low taint does NOT trigger TAINT_INFLUENCED."""
        store.record_tool_call("sess-9", "Read")
        result = classify_provenance(
            session_id="sess-9",
            tool_name="Bash",
            taint_level="low",
        )
        assert result == "agent_generated"

    def test_taint_overrides_user_verified(self, store):
        """TAINT_INFLUENCED overrides USER_VERIFIED (invariant #6)."""
        store.record_tool_call("sess-10", "Read")
        store.record_ask_approval("sess-10")
        result = classify_provenance(
            session_id="sess-10",
            tool_name="Bash",
            taint_level="medium",
        )
        assert result == "taint_influenced"

    def test_taint_overrides_skill_context(self, store):
        """TAINT_INFLUENCED overrides SKILL_CONTEXT."""
        store.record_tool_call("sess-11", "Read")
        result = classify_provenance(
            session_id="sess-11",
            tool_name="Bash",
            taint_level="high",
            active_skill="some-skill",
        )
        assert result == "taint_influenced"


class TestAskApprovalTracking:
    """Test the ask approval recording mechanism."""

    def test_record_ask_approval(self, store):
        """Recording an ask approval sets ask_verified."""
        store.record_tool_call("sess-a", "Read")
        state = store.record_ask_approval("sess-a")
        assert state["ask_verified"] is True
        assert state["total_ask_approvals"] == 1
        assert state["last_ask_approval_at"] is not None

    def test_multiple_approvals(self, store):
        """Multiple approvals increment the counter."""
        store.record_tool_call("sess-b", "Read")
        store.record_ask_approval("sess-b")
        state = store.record_ask_approval("sess-b")
        assert state["total_ask_approvals"] == 2

    def test_taint_resets_verification(self, store):
        """Taint escalation to medium+ resets ask_verified (invariant #6)."""
        store.record_tool_call("sess-c", "Read")
        store.record_ask_approval("sess-c")
        state = store.get_session_taint("sess-c")
        assert state["ask_verified"] is True

        # Taint to medium → resets verification
        store.record_taint("sess-c", "medium", "WebFetch:evil.com", "suspicious")
        state = store.get_session_taint("sess-c")
        assert state["ask_verified"] is False

    def test_low_taint_preserves_verification(self, store):
        """Low taint does NOT reset ask_verified."""
        store.record_tool_call("sess-d", "Read")
        store.record_ask_approval("sess-d")

        # Low taint should not reset
        store.record_taint("sess-d", "low", "WebFetch:ok.com", "minor")
        state = store.get_session_taint("sess-d")
        assert state["ask_verified"] is True

    def test_pending_ask_flow(self, store):
        """Test the set_pending_ask → check_and_record flow."""
        store.record_tool_call("sess-e", "Read")

        # Pre_tool_use returns "ask"
        store.set_pending_ask("sess-e")
        state = store.get_session_taint("sess-e")
        # pending_ask should be set (stored as int in SQLite)
        assert state.get("pending_ask") in (1, True)

        # Post_tool_use fires (user approved) → records approval
        approved = store.check_and_record_ask_approval("sess-e")
        assert approved is True

        state = store.get_session_taint("sess-e")
        assert state["ask_verified"] is True

    def test_no_pending_ask_no_approval(self, store):
        """check_and_record returns False when no pending ask."""
        store.record_tool_call("sess-f", "Read")
        approved = store.check_and_record_ask_approval("sess-f")
        assert approved is False
