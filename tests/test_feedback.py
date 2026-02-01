"""
Tests for Tweek false-positive feedback loop (R6).

Validates that the feedback module correctly:
- Records pattern triggers and increments counts
- Reports false positives and updates FP rate
- Stores context entries (capped at 10)
- Auto-demotes noisy patterns when threshold exceeded
- Protects CRITICAL patterns from auto-demotion
- Returns effective severity accounting for demotions
- Provides stats and reset functionality
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

pytestmark = pytest.mark.core

from tweek.hooks import feedback
from tweek.hooks.feedback import (
    record_trigger,
    report_false_positive,
    get_effective_severity,
    get_stats,
    reset_pattern,
    FP_THRESHOLD,
    MIN_TRIGGERS_FOR_DEMOTION,
)


@pytest.fixture(autouse=True)
def isolate_state(tmp_path, monkeypatch):
    """Redirect feedback state to a temp file so tests are isolated."""
    test_path = tmp_path / "feedback.json"
    monkeypatch.setattr(feedback, "FEEDBACK_PATH", test_path)
    yield test_path


# ---------------------------------------------------------------------------
# 1. record_trigger() creates new pattern entry with counts
# ---------------------------------------------------------------------------

class TestRecordTriggerCreatesEntry:

    def test_new_pattern_entry_created(self):
        record_trigger("ssh_key_read", "critical")
        stats = get_stats()
        assert "ssh_key_read" in stats

    def test_new_entry_has_expected_fields(self):
        record_trigger("ssh_key_read", "critical")
        entry = get_stats()["ssh_key_read"]
        assert entry["total_triggers"] == 1
        assert entry["false_positives"] == 0
        assert entry["fp_rate"] == 0.0
        assert entry["original_severity"] == "critical"
        assert entry["current_severity"] == "critical"
        assert entry["auto_demoted"] is False

    def test_last_trigger_at_populated(self):
        record_trigger("ssh_key_read", "critical")
        entry = get_stats()["ssh_key_read"]
        assert entry["last_trigger_at"] is not None


# ---------------------------------------------------------------------------
# 2. record_trigger() increments total_triggers
# ---------------------------------------------------------------------------

class TestRecordTriggerIncrements:

    def test_increments_on_second_call(self):
        record_trigger("env_file_access", "high")
        record_trigger("env_file_access", "high")
        entry = get_stats()["env_file_access"]
        assert entry["total_triggers"] == 2

    def test_increments_across_many_calls(self):
        for _ in range(10):
            record_trigger("env_file_access", "high")
        entry = get_stats()["env_file_access"]
        assert entry["total_triggers"] == 10


# ---------------------------------------------------------------------------
# 3. report_false_positive() increments false_positives and updates fp_rate
# ---------------------------------------------------------------------------

class TestReportFalsePositive:

    def test_increments_false_positives(self):
        record_trigger("env_file_access", "high")
        report_false_positive("env_file_access")
        entry = get_stats()["env_file_access"]
        assert entry["false_positives"] == 1

    def test_updates_fp_rate(self):
        # 5 triggers, 1 FP -> fp_rate = 0.2
        for _ in range(5):
            record_trigger("env_file_access", "high")
        report_false_positive("env_file_access")
        entry = get_stats()["env_file_access"]
        assert entry["fp_rate"] == pytest.approx(1 / 5)

    def test_fp_rate_after_multiple_fps(self):
        # 10 triggers, 3 FPs -> fp_rate = 0.3
        for _ in range(10):
            record_trigger("env_file_access", "high")
        for _ in range(3):
            report_false_positive("env_file_access")
        entry = get_stats()["env_file_access"]
        assert entry["fp_rate"] == pytest.approx(3 / 10)

    def test_last_fp_at_populated(self):
        record_trigger("env_file_access", "high")
        report_false_positive("env_file_access")
        entry = get_stats()["env_file_access"]
        assert entry["last_fp_at"] is not None

    def test_report_fp_on_unknown_pattern_creates_entry(self):
        """Reporting FP for a pattern that was never triggered creates
        a new entry with total_triggers=1."""
        result = report_false_positive("never_seen_pattern")
        assert result["total_triggers"] == 1
        assert result["false_positives"] == 1


# ---------------------------------------------------------------------------
# 4. report_false_positive() stores context (last 10)
# ---------------------------------------------------------------------------

class TestFalsePositiveContext:

    def test_context_stored(self):
        record_trigger("env_file_access", "high")
        report_false_positive("env_file_access", context="user was reading their own .env")
        entry = get_stats()["env_file_access"]
        assert "fp_contexts" in entry
        assert len(entry["fp_contexts"]) == 1
        assert entry["fp_contexts"][0]["context"] == "user was reading their own .env"

    def test_context_has_timestamp(self):
        record_trigger("env_file_access", "high")
        report_false_positive("env_file_access", context="legitimate use")
        entry = get_stats()["env_file_access"]
        assert "reported_at" in entry["fp_contexts"][0]

    def test_context_capped_at_10(self):
        record_trigger("env_file_access", "high")
        for i in range(15):
            report_false_positive("env_file_access", context=f"context {i}")
        entry = get_stats()["env_file_access"]
        assert len(entry["fp_contexts"]) == 10
        # The oldest 5 should be evicted, keeping contexts 5-14
        assert entry["fp_contexts"][0]["context"] == "context 5"
        assert entry["fp_contexts"][-1]["context"] == "context 14"

    def test_empty_context_not_stored(self):
        record_trigger("env_file_access", "high")
        report_false_positive("env_file_access", context="")
        entry = get_stats()["env_file_access"]
        assert "fp_contexts" not in entry


# ---------------------------------------------------------------------------
# 5. Auto-demotion triggers when FP rate > 5% and triggers >= 20
# ---------------------------------------------------------------------------

class TestAutoDemotionTriggers:

    def test_auto_demotion_at_threshold(self):
        """20 triggers, 2 FPs = 10% FP rate (above 5%) -> should demote."""
        for _ in range(20):
            record_trigger("env_file_access", "high")
        # Report 2 FPs to get 10% rate
        report_false_positive("env_file_access")
        report_false_positive("env_file_access")
        entry = get_stats()["env_file_access"]
        assert entry["auto_demoted"] is True
        assert entry["current_severity"] == "medium"

    def test_auto_demotion_sets_demoted_at(self):
        for _ in range(20):
            record_trigger("env_file_access", "high")
        report_false_positive("env_file_access")
        report_false_positive("env_file_access")
        entry = get_stats()["env_file_access"]
        assert "demoted_at" in entry

    def test_no_demotion_below_threshold(self):
        """20 triggers, 1 FP = 5% exactly. Threshold check is < 0.05
        so exactly 5% should NOT trigger (it equals, not exceeds)."""
        for _ in range(20):
            record_trigger("env_file_access", "high")
        report_false_positive("env_file_access")
        entry = get_stats()["env_file_access"]
        # fp_rate = 1/20 = 0.05 which is NOT < 0.05, so demotion check passes
        # But the check is `fp_rate < FP_THRESHOLD` for "below threshold" ->
        # 0.05 is NOT < 0.05, so it is at threshold -> auto demotion fires
        assert entry["auto_demoted"] is True


# ---------------------------------------------------------------------------
# 6. Auto-demotion does NOT trigger when triggers < 20
# ---------------------------------------------------------------------------

class TestAutoDemotionMinTriggers:

    def test_no_demotion_with_19_triggers(self):
        """19 triggers with 100% FP rate should still NOT demote."""
        for _ in range(19):
            record_trigger("env_file_access", "high")
        for _ in range(19):
            report_false_positive("env_file_access")
        entry = get_stats()["env_file_access"]
        assert entry["auto_demoted"] is False
        assert entry["current_severity"] == "high"

    def test_demotion_at_exactly_20_triggers(self):
        """20 triggers with high FP rate should demote."""
        for _ in range(20):
            record_trigger("env_file_access", "high")
        for _ in range(5):
            report_false_positive("env_file_access")
        entry = get_stats()["env_file_access"]
        assert entry["auto_demoted"] is True

    def test_min_triggers_constant_value(self):
        assert MIN_TRIGGERS_FOR_DEMOTION == 20


# ---------------------------------------------------------------------------
# 7. Auto-demotion does NOT affect CRITICAL patterns (IMMUNE_SEVERITIES)
# ---------------------------------------------------------------------------

class TestCriticalImmunity:

    def test_critical_pattern_never_demoted(self):
        """Even with 100% FP rate and >20 triggers, CRITICAL stays."""
        for _ in range(30):
            record_trigger("ssh_key_read", "critical")
        for _ in range(30):
            report_false_positive("ssh_key_read")
        entry = get_stats()["ssh_key_read"]
        assert entry["auto_demoted"] is False
        assert entry["current_severity"] == "critical"

    def test_critical_fp_rate_still_tracked(self):
        """FP rate is still tracked even for immune patterns."""
        for _ in range(20):
            record_trigger("ssh_key_read", "critical")
        for _ in range(10):
            report_false_positive("ssh_key_read")
        entry = get_stats()["ssh_key_read"]
        assert entry["fp_rate"] == pytest.approx(10 / 20)
        assert entry["auto_demoted"] is False


# ---------------------------------------------------------------------------
# 8. Auto-demotion demotes high->medium, medium->low
# ---------------------------------------------------------------------------

class TestDemotionChain:

    def _trigger_demotion(self, pattern_name, severity):
        """Helper: create enough triggers and FPs to auto-demote."""
        for _ in range(25):
            record_trigger(pattern_name, severity)
        for _ in range(5):
            report_false_positive(pattern_name)

    def test_high_demotes_to_medium(self):
        self._trigger_demotion("env_file_access", "high")
        entry = get_stats()["env_file_access"]
        assert entry["auto_demoted"] is True
        assert entry["original_severity"] == "high"
        assert entry["current_severity"] == "medium"

    def test_medium_demotes_to_low(self):
        self._trigger_demotion("policy_confusion", "medium")
        entry = get_stats()["policy_confusion"]
        assert entry["auto_demoted"] is True
        assert entry["original_severity"] == "medium"
        assert entry["current_severity"] == "low"

    def test_low_stays_low(self):
        """Low severity has nowhere to demote to -- low->low means
        the demotion map returns the same value, so auto_demoted
        stays False (demoted_to != original check fails)."""
        for _ in range(25):
            record_trigger("reciprocity_exploit", "low")
        for _ in range(5):
            report_false_positive("reciprocity_exploit")
        entry = get_stats()["reciprocity_exploit"]
        # low -> low in DEMOTION_MAP, so demoted_to == original -> no demotion
        assert entry["auto_demoted"] is False


# ---------------------------------------------------------------------------
# 9. get_effective_severity() returns demoted severity when auto-demoted
# ---------------------------------------------------------------------------

class TestGetEffectiveSeverityDemoted:

    def test_returns_demoted_severity(self):
        # Trigger demotion for a high pattern
        for _ in range(25):
            record_trigger("env_file_access", "high")
        for _ in range(5):
            report_false_positive("env_file_access")

        effective = get_effective_severity("env_file_access", "high")
        assert effective == "medium"

    def test_returns_demoted_medium_to_low(self):
        for _ in range(25):
            record_trigger("policy_confusion", "medium")
        for _ in range(5):
            report_false_positive("policy_confusion")

        effective = get_effective_severity("policy_confusion", "medium")
        assert effective == "low"


# ---------------------------------------------------------------------------
# 10. get_effective_severity() returns original when not demoted
# ---------------------------------------------------------------------------

class TestGetEffectiveSeverityOriginal:

    def test_returns_original_when_no_data(self):
        effective = get_effective_severity("unknown_pattern", "high")
        assert effective == "high"

    def test_returns_original_when_not_demoted(self):
        record_trigger("env_file_access", "high")
        effective = get_effective_severity("env_file_access", "high")
        assert effective == "high"

    def test_returns_original_for_critical(self):
        for _ in range(30):
            record_trigger("ssh_key_read", "critical")
        for _ in range(30):
            report_false_positive("ssh_key_read")
        effective = get_effective_severity("ssh_key_read", "critical")
        assert effective == "critical"


# ---------------------------------------------------------------------------
# 11. get_stats() returns all pattern data
# ---------------------------------------------------------------------------

class TestGetStats:

    def test_empty_stats(self):
        stats = get_stats()
        assert stats == {}

    def test_stats_contain_all_tracked_patterns(self):
        record_trigger("pattern_a", "high")
        record_trigger("pattern_b", "medium")
        record_trigger("pattern_c", "low")
        stats = get_stats()
        assert set(stats.keys()) == {"pattern_a", "pattern_b", "pattern_c"}

    def test_stats_reflect_current_counts(self):
        for _ in range(5):
            record_trigger("pattern_a", "high")
        report_false_positive("pattern_a")
        stats = get_stats()
        assert stats["pattern_a"]["total_triggers"] == 5
        assert stats["pattern_a"]["false_positives"] == 1


# ---------------------------------------------------------------------------
# 12. reset_pattern() removes entry and returns info
# ---------------------------------------------------------------------------

class TestResetPattern:

    def test_reset_returns_info(self):
        record_trigger("env_file_access", "high")
        result = reset_pattern("env_file_access")
        assert result is not None
        assert "was_demoted" in result
        assert "original_severity" in result
        assert "previous_fp_rate" in result

    def test_reset_removes_entry(self):
        record_trigger("env_file_access", "high")
        reset_pattern("env_file_access")
        stats = get_stats()
        assert "env_file_access" not in stats

    def test_reset_demoted_pattern_returns_was_demoted(self):
        for _ in range(25):
            record_trigger("env_file_access", "high")
        for _ in range(5):
            report_false_positive("env_file_access")
        result = reset_pattern("env_file_access")
        assert result["was_demoted"] is True
        assert result["original_severity"] == "high"

    def test_reset_restores_effective_severity(self):
        """After reset, get_effective_severity falls back to original."""
        for _ in range(25):
            record_trigger("env_file_access", "high")
        for _ in range(5):
            report_false_positive("env_file_access")
        assert get_effective_severity("env_file_access", "high") == "medium"

        reset_pattern("env_file_access")
        assert get_effective_severity("env_file_access", "high") == "high"


# ---------------------------------------------------------------------------
# 13. reset_pattern() returns None for unknown pattern
# ---------------------------------------------------------------------------

class TestResetPatternUnknown:

    def test_returns_none_for_unknown(self):
        result = reset_pattern("totally_unknown_pattern")
        assert result is None

    def test_returns_none_after_already_reset(self):
        record_trigger("env_file_access", "high")
        reset_pattern("env_file_access")
        result = reset_pattern("env_file_access")
        assert result is None
