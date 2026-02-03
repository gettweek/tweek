"""
Tests for tweek.memory.safety — CRITICAL immunity, max relaxation, validation.
"""

import pytest

pytestmark = pytest.mark.memory

from tweek.memory.safety import (
    DECISION_RANK,
    MAX_RELAXATION,
    MIN_APPROVAL_RATIO,
    MIN_CONFIDENCE_SCORE,
    MIN_DECISION_THRESHOLD,
    compute_suggested_decision,
    get_max_relaxation,
    is_immune_pattern,
    validate_memory_adjustment,
)


class TestImmunePattern:
    """Test CRITICAL+deterministic immunity."""

    def test_critical_deterministic_immune(self):
        assert is_immune_pattern("critical", "deterministic") is True

    def test_critical_heuristic_not_immune(self):
        assert is_immune_pattern("critical", "heuristic") is False

    def test_critical_contextual_not_immune(self):
        assert is_immune_pattern("critical", "contextual") is False

    def test_high_deterministic_not_immune(self):
        assert is_immune_pattern("high", "deterministic") is False

    def test_medium_heuristic_not_immune(self):
        assert is_immune_pattern("medium", "heuristic") is False

    def test_low_contextual_not_immune(self):
        assert is_immune_pattern("low", "contextual") is False

    def test_case_insensitive(self):
        assert is_immune_pattern("CRITICAL", "DETERMINISTIC") is True
        assert is_immune_pattern("Critical", "Deterministic") is True


class TestMaxRelaxation:
    """Test one-step max relaxation limits."""

    def test_deny_never_relaxed(self):
        assert get_max_relaxation("deny") == "deny"

    def test_ask_relaxes_to_log(self):
        assert get_max_relaxation("ask") == "log"

    def test_log_stays_log(self):
        assert get_max_relaxation("log") == "log"

    def test_allow_stays_allow(self):
        assert get_max_relaxation("allow") == "allow"

    def test_unknown_stays_same(self):
        assert get_max_relaxation("unknown") == "unknown"


class TestValidateMemoryAdjustment:
    """Test the final validation gate for memory adjustments."""

    def test_immune_pattern_returns_current(self):
        """CRITICAL+deterministic should always return current decision."""
        result = validate_memory_adjustment(
            pattern_name="ssh_key_read",
            original_severity="critical",
            original_confidence="deterministic",
            suggested_decision="log",
            current_decision="deny",
        )
        assert result == "deny"

    def test_deny_never_relaxed(self):
        """deny should never be changed by memory."""
        result = validate_memory_adjustment(
            pattern_name="some_pattern",
            original_severity="high",
            original_confidence="heuristic",
            suggested_decision="log",
            current_decision="deny",
        )
        assert result == "deny"

    def test_ask_to_log_allowed(self):
        """ask -> log is a valid one-step relaxation."""
        result = validate_memory_adjustment(
            pattern_name="some_pattern",
            original_severity="high",
            original_confidence="heuristic",
            suggested_decision="log",
            current_decision="ask",
        )
        assert result == "log"

    def test_ask_to_allow_clamped(self):
        """ask -> allow would be two steps, should be clamped to log."""
        result = validate_memory_adjustment(
            pattern_name="some_pattern",
            original_severity="medium",
            original_confidence="heuristic",
            suggested_decision="allow",
            current_decision="ask",
        )
        assert result == "log"

    def test_same_decision_no_change(self):
        """If suggested equals current, no change."""
        result = validate_memory_adjustment(
            pattern_name="some_pattern",
            original_severity="medium",
            original_confidence="heuristic",
            suggested_decision="ask",
            current_decision="ask",
        )
        assert result == "ask"

    def test_escalation_ignored(self):
        """Memory should never escalate (log -> ask would be escalation)."""
        result = validate_memory_adjustment(
            pattern_name="some_pattern",
            original_severity="medium",
            original_confidence="heuristic",
            suggested_decision="ask",
            current_decision="log",
        )
        assert result == "log"

    def test_deny_to_ask_blocked(self):
        """Memory cannot relax deny to ask."""
        result = validate_memory_adjustment(
            pattern_name="some_pattern",
            original_severity="high",
            original_confidence="heuristic",
            suggested_decision="ask",
            current_decision="deny",
        )
        assert result == "deny"

    def test_deny_to_log_blocked(self):
        """Memory cannot relax deny to log."""
        result = validate_memory_adjustment(
            pattern_name="some_pattern",
            original_severity="high",
            original_confidence="heuristic",
            suggested_decision="log",
            current_decision="deny",
        )
        assert result == "deny"


class TestComputeSuggestedDecision:
    """Test memory suggestion computation."""

    def test_immune_pattern_no_suggestion(self):
        result = compute_suggested_decision(
            current_decision="deny",
            approval_ratio=1.0,
            total_weighted_decisions=100,
            original_severity="critical",
            original_confidence="deterministic",
        )
        assert result is None

    def test_insufficient_data_no_suggestion(self):
        result = compute_suggested_decision(
            current_decision="ask",
            approval_ratio=1.0,
            total_weighted_decisions=2,  # Below default threshold (path=5)
            original_severity="high",
            original_confidence="heuristic",
        )
        assert result is None

    def test_deny_never_relaxed(self):
        result = compute_suggested_decision(
            current_decision="deny",
            approval_ratio=1.0,
            total_weighted_decisions=100,
            original_severity="high",
            original_confidence="heuristic",
        )
        assert result is None

    def test_high_approval_ratio_suggests_log(self):
        result = compute_suggested_decision(
            current_decision="ask",
            approval_ratio=0.95,
            total_weighted_decisions=20,
            original_severity="high",
            original_confidence="heuristic",
        )
        assert result == "log"

    def test_low_approval_ratio_no_suggestion(self):
        result = compute_suggested_decision(
            current_decision="ask",
            approval_ratio=0.5,
            total_weighted_decisions=20,
            original_severity="medium",
            original_confidence="heuristic",
        )
        assert result is None

    def test_borderline_ratio_no_suggestion(self):
        result = compute_suggested_decision(
            current_decision="ask",
            approval_ratio=0.89,  # Just below 90% threshold
            total_weighted_decisions=20,
            original_severity="medium",
            original_confidence="heuristic",
        )
        assert result is None

    def test_exact_threshold_suggests(self):
        result = compute_suggested_decision(
            current_decision="ask",
            approval_ratio=0.90,  # Exactly at threshold
            total_weighted_decisions=10,
            original_severity="medium",
            original_confidence="heuristic",
        )
        assert result == "log"

    def test_log_no_further_relaxation(self):
        """Already at log, no further relaxation possible."""
        result = compute_suggested_decision(
            current_decision="log",
            approval_ratio=1.0,
            total_weighted_decisions=100,
            original_severity="low",
            original_confidence="heuristic",
        )
        assert result is None


class TestDecisionRank:
    """Test decision ranking is consistent."""

    def test_rank_order(self):
        assert DECISION_RANK["deny"] > DECISION_RANK["ask"]
        assert DECISION_RANK["ask"] > DECISION_RANK["log"]
        assert DECISION_RANK["log"] > DECISION_RANK["allow"]

    def test_constants(self):
        assert MIN_DECISION_THRESHOLD == 3  # SCOPED_THRESHOLDS["exact"]
        assert MIN_APPROVAL_RATIO == 0.90
        assert MIN_CONFIDENCE_SCORE == 0.80
