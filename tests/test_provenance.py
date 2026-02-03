"""
Tests for tweek.memory.provenance — Session taint tracking system.

Tests cover:
- Taint level operations (escalation, decay, severity mapping)
- SessionTaintStore CRUD (get, record, clear)
- Taint decay over tool calls
- Enforcement adjustment based on taint level
- Clean session LLM skip logic
"""

import pytest
from pathlib import Path

from tweek.memory.provenance import (
    TAINT_LEVELS,
    TAINT_RANK,
    DECAY_INTERVAL,
    EXTERNAL_SOURCE_TOOLS,
    ACTION_TOOLS,
    escalate_taint,
    decay_taint,
    severity_to_taint,
    SessionTaintStore,
    adjust_enforcement_for_taint,
    should_skip_llm_for_clean_session,
    reset_taint_store,
)

pytestmark = pytest.mark.memory


# =========================================================================
# Fixtures
# =========================================================================

@pytest.fixture(autouse=True)
def clean_singleton():
    """Reset singleton between tests."""
    reset_taint_store()
    yield
    reset_taint_store()


@pytest.fixture
def taint_store(tmp_path):
    """Create a temporary taint store."""
    db_path = tmp_path / "test_memory.db"
    store = SessionTaintStore(db_path=db_path)
    yield store
    store.close()


# =========================================================================
# Taint Level Operations
# =========================================================================

class TestTaintLevelConstants:
    def test_taint_levels_ordered(self):
        assert TAINT_LEVELS == ("clean", "low", "medium", "high", "critical")

    def test_rank_order(self):
        assert TAINT_RANK["clean"] < TAINT_RANK["low"]
        assert TAINT_RANK["low"] < TAINT_RANK["medium"]
        assert TAINT_RANK["medium"] < TAINT_RANK["high"]
        assert TAINT_RANK["high"] < TAINT_RANK["critical"]

    def test_external_source_tools(self):
        assert "Read" in EXTERNAL_SOURCE_TOOLS
        assert "WebFetch" in EXTERNAL_SOURCE_TOOLS
        assert "WebSearch" in EXTERNAL_SOURCE_TOOLS
        assert "Bash" not in EXTERNAL_SOURCE_TOOLS

    def test_action_tools(self):
        assert "Bash" in ACTION_TOOLS
        assert "Write" in ACTION_TOOLS
        assert "Read" not in ACTION_TOOLS


class TestEscalateTaint:
    def test_escalate_clean_to_low(self):
        assert escalate_taint("clean", "low") == "low"

    def test_escalate_low_to_high(self):
        assert escalate_taint("low", "high") == "high"

    def test_escalate_clean_to_critical(self):
        assert escalate_taint("clean", "critical") == "critical"

    def test_no_downgrade(self):
        assert escalate_taint("high", "low") == "high"

    def test_same_level(self):
        assert escalate_taint("medium", "medium") == "medium"

    def test_unknown_level(self):
        assert escalate_taint("clean", "unknown") == "clean"


class TestDecayTaint:
    def test_decay_critical(self):
        assert decay_taint("critical") == "high"

    def test_decay_high(self):
        assert decay_taint("high") == "medium"

    def test_decay_medium(self):
        assert decay_taint("medium") == "low"

    def test_decay_low(self):
        assert decay_taint("low") == "clean"

    def test_decay_clean_stays_clean(self):
        assert decay_taint("clean") == "clean"


class TestSeverityToTaint:
    def test_critical(self):
        assert severity_to_taint("critical") == "critical"

    def test_high(self):
        assert severity_to_taint("high") == "high"

    def test_medium(self):
        assert severity_to_taint("medium") == "medium"

    def test_low(self):
        assert severity_to_taint("low") == "low"

    def test_unknown_defaults_to_medium(self):
        assert severity_to_taint("unknown") == "medium"


# =========================================================================
# SessionTaintStore
# =========================================================================

class TestSessionTaintStore:
    def test_new_session_is_clean(self, taint_store):
        state = taint_store.get_session_taint("sess-1")
        assert state["taint_level"] == "clean"
        assert state["turns_since_taint"] == 0
        assert state["total_tool_calls"] == 0

    def test_record_tool_call_increments(self, taint_store):
        state = taint_store.record_tool_call("sess-1", "Bash")
        assert state["total_tool_calls"] == 1
        assert state["taint_level"] == "clean"

        state = taint_store.record_tool_call("sess-1", "Read")
        assert state["total_tool_calls"] == 2

    def test_record_taint_escalates(self, taint_store):
        state = taint_store.record_taint(
            "sess-1", "high", "WebFetch:evil.com", "Pattern found in response"
        )
        assert state["taint_level"] == "high"
        assert state["turns_since_taint"] == 0
        assert state["total_taint_escalations"] == 1
        assert state["last_taint_source"] == "WebFetch:evil.com"

    def test_taint_only_escalates(self, taint_store):
        taint_store.record_taint("sess-1", "high", "src", "reason")
        state = taint_store.record_taint("sess-1", "low", "src2", "reason2")
        # Should stay at high, not downgrade to low
        assert state["taint_level"] == "high"

    def test_taint_escalates_further(self, taint_store):
        taint_store.record_taint("sess-1", "medium", "src", "reason")
        state = taint_store.record_taint("sess-1", "critical", "src2", "reason2")
        assert state["taint_level"] == "critical"
        assert state["total_taint_escalations"] == 2

    def test_taint_resets_decay_counter(self, taint_store):
        # Record some tool calls to build turns_since_taint
        for _ in range(3):
            taint_store.record_tool_call("sess-1", "Bash")
        state = taint_store.get_session_taint("sess-1")
        assert state["turns_since_taint"] == 3

        # Taint should reset counter
        state = taint_store.record_taint("sess-1", "medium", "src", "reason")
        assert state["turns_since_taint"] == 0

    def test_decay_after_interval(self, taint_store):
        # Set initial taint
        taint_store.record_taint("sess-1", "high", "src", "reason")

        # Record DECAY_INTERVAL tool calls
        for _ in range(DECAY_INTERVAL):
            state = taint_store.record_tool_call("sess-1", "Bash")

        # Should have decayed from high to medium
        assert state["taint_level"] == "medium"

    def test_full_decay_to_clean(self, taint_store):
        taint_store.record_taint("sess-1", "medium", "src", "reason")

        # medium -> low (after 5 calls)
        for _ in range(DECAY_INTERVAL):
            state = taint_store.record_tool_call("sess-1", "Bash")
        assert state["taint_level"] == "low"

        # low -> clean (after 5 more calls)
        for _ in range(DECAY_INTERVAL):
            state = taint_store.record_tool_call("sess-1", "Bash")
        assert state["taint_level"] == "clean"

    def test_no_decay_for_clean(self, taint_store):
        for _ in range(20):
            state = taint_store.record_tool_call("sess-1", "Bash")
        assert state["taint_level"] == "clean"

    def test_record_external_ingest(self, taint_store):
        taint_store.record_external_ingest("sess-1", "Read:/some/file")
        state = taint_store.get_session_taint("sess-1")
        assert state["total_external_ingests"] == 1
        assert state["taint_level"] == "clean"  # No escalation

    def test_clear_session(self, taint_store):
        taint_store.record_taint("sess-1", "high", "src", "reason")
        taint_store.clear_session("sess-1")
        state = taint_store.get_session_taint("sess-1")
        assert state["taint_level"] == "clean"

    def test_independent_sessions(self, taint_store):
        taint_store.record_taint("sess-1", "critical", "src", "reason")
        state2 = taint_store.get_session_taint("sess-2")
        assert state2["taint_level"] == "clean"

    def test_persistence(self, tmp_path):
        db_path = tmp_path / "persist_test.db"

        # Write taint
        store1 = SessionTaintStore(db_path=db_path)
        store1.record_taint("sess-1", "high", "src", "reason")
        store1.close()

        # Read from new connection
        store2 = SessionTaintStore(db_path=db_path)
        state = store2.get_session_taint("sess-1")
        assert state["taint_level"] == "high"
        store2.close()

    def test_get_stats(self, taint_store):
        taint_store.record_taint("sess-1", "high", "src", "reason")
        taint_store.record_tool_call("sess-2", "Bash")  # clean session

        stats = taint_store.get_stats()
        assert stats["total_sessions"] == 2
        assert stats["tainted_sessions"] == 1
        assert stats["clean_sessions"] == 1


# =========================================================================
# Enforcement Adjustment
# =========================================================================

class TestAdjustEnforcementForTaint:
    """Test enforcement decision modification based on session taint."""

    def test_critical_deterministic_always_deny(self):
        # Even in clean session, critical+deterministic stays deny
        result = adjust_enforcement_for_taint("deny", "critical", "deterministic", "clean")
        assert result == "deny"

    def test_clean_session_relaxes_high_heuristic(self):
        # In clean session, high+heuristic "ask" becomes "log"
        result = adjust_enforcement_for_taint("ask", "high", "heuristic", "clean")
        assert result == "log"

    def test_clean_session_relaxes_critical_contextual(self):
        result = adjust_enforcement_for_taint("ask", "critical", "contextual", "clean")
        assert result == "log"

    def test_clean_session_relaxes_medium(self):
        result = adjust_enforcement_for_taint("ask", "medium", "heuristic", "clean")
        assert result == "log"

    def test_clean_session_keeps_critical_heuristic(self):
        # critical+heuristic stays "ask" even in clean session
        result = adjust_enforcement_for_taint("ask", "critical", "heuristic", "clean")
        assert result == "ask"

    def test_clean_session_keeps_high_deterministic(self):
        # high+deterministic stays "ask" even in clean session
        result = adjust_enforcement_for_taint("ask", "high", "deterministic", "clean")
        assert result == "ask"

    def test_tainted_session_escalates_logged_high(self):
        # In medium+ taint, high+heuristic "log" escalates to "ask"
        result = adjust_enforcement_for_taint("log", "high", "heuristic", "medium")
        assert result == "ask"

    def test_low_taint_no_change(self):
        # Low taint doesn't escalate
        result = adjust_enforcement_for_taint("log", "high", "heuristic", "low")
        assert result == "log"

    def test_critical_taint_escalates_medium(self):
        # In critical taint, even medium patterns get "ask"
        result = adjust_enforcement_for_taint("log", "medium", "heuristic", "critical")
        assert result == "ask"

    def test_low_severity_always_log(self):
        # Low severity patterns always stay "log" regardless of taint
        result = adjust_enforcement_for_taint("log", "low", "heuristic", "critical")
        assert result == "log"

    def test_deny_never_relaxed_in_clean_session(self):
        # A "deny" base decision should never be relaxed, even in clean sessions
        result = adjust_enforcement_for_taint("deny", "high", "heuristic", "clean")
        assert result == "deny"

    def test_deny_never_relaxed_for_medium(self):
        result = adjust_enforcement_for_taint("deny", "medium", "contextual", "clean")
        assert result == "deny"


class TestShouldSkipLLM:
    def test_clean_session_skips_default_tier(self):
        assert should_skip_llm_for_clean_session("clean", "default") is True

    def test_clean_session_doesnt_skip_risky(self):
        assert should_skip_llm_for_clean_session("clean", "risky") is False

    def test_clean_session_doesnt_skip_dangerous(self):
        assert should_skip_llm_for_clean_session("clean", "dangerous") is False

    def test_tainted_session_doesnt_skip(self):
        assert should_skip_llm_for_clean_session("low", "default") is False
        assert should_skip_llm_for_clean_session("medium", "default") is False
        assert should_skip_llm_for_clean_session("high", "default") is False

    def test_safe_tier_not_skipped(self):
        # Safe tier doesn't get LLM review anyway, but shouldn't be "skipped"
        assert should_skip_llm_for_clean_session("clean", "safe") is False
