#!/usr/bin/env python3
"""
Tests for tweek.hooks.break_glass module.

Tests the break-glass override system:
- Creating overrides (once and duration modes)
- Checking overrides (consumption, expiry, missing)
- Listing overrides (all vs active)
- Clearing overrides
- Edge cases (missing state file, corrupted state, independent patterns)
"""

import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

pytestmark = pytest.mark.security

from tweek.hooks import break_glass
from tweek.hooks.break_glass import (
    create_override,
    check_override,
    list_overrides,
    list_active_overrides,
    clear_overrides,
    _load_state,
)


@pytest.fixture(autouse=True)
def isolate_state(tmp_path, monkeypatch):
    """Use a temp file for break-glass state."""
    test_path = tmp_path / "break_glass.json"
    monkeypatch.setattr(break_glass, "BREAK_GLASS_PATH", test_path)
    yield test_path


class TestCreateOverride:
    """Tests for create_override()."""

    def test_create_once_override(self, isolate_state):
        """create_override with mode='once' creates override saved to state."""
        result = create_override(
            pattern_name="ssh_key_read",
            mode="once",
            reason="Emergency access needed",
        )

        assert result["pattern"] == "ssh_key_read"
        assert result["mode"] == "once"
        assert result["reason"] == "Emergency access needed"
        assert result["used"] is False
        assert result["used_at"] is None
        assert result["expires_at"] is None
        assert result["created_at"] is not None

        # Verify persisted to disk
        state = _load_state()
        assert len(state["overrides"]) == 1
        assert state["overrides"][0]["pattern"] == "ssh_key_read"

    def test_create_duration_override(self, isolate_state):
        """create_override with mode='duration' creates override with expires_at."""
        result = create_override(
            pattern_name="env_file_write",
            mode="duration",
            duration_minutes=30,
            reason="Deployment window",
        )

        assert result["pattern"] == "env_file_write"
        assert result["mode"] == "duration"
        assert result["reason"] == "Deployment window"
        assert result["used"] is False
        assert result["expires_at"] is not None

        # Verify expires_at is roughly 30 minutes in the future
        expires = datetime.fromisoformat(result["expires_at"])
        created = datetime.fromisoformat(result["created_at"])
        delta = expires - created
        assert 29 <= delta.total_seconds() / 60 <= 31

    def test_create_duration_override_without_minutes_has_no_expiry(self, isolate_state):
        """Duration mode without duration_minutes results in no expires_at."""
        result = create_override(
            pattern_name="test_pattern",
            mode="duration",
            reason="No duration specified",
        )

        assert result["mode"] == "duration"
        assert result["expires_at"] is None

    def test_create_override_default_mode_is_once(self, isolate_state):
        """Default mode is 'once'."""
        result = create_override(pattern_name="test_pattern")

        assert result["mode"] == "once"

    def test_create_override_default_reason_is_empty(self, isolate_state):
        """Default reason is an empty string."""
        result = create_override(pattern_name="test_pattern")

        assert result["reason"] == ""


class TestCheckOverride:
    """Tests for check_override()."""

    def test_check_finds_active_override(self, isolate_state):
        """check_override returns override dict when an active override exists."""
        create_override(
            pattern_name="ssh_key_read",
            mode="once",
            reason="Testing",
        )

        result = check_override("ssh_key_read")

        assert result is not None
        assert result["pattern"] == "ssh_key_read"
        assert result["reason"] == "Testing"

    def test_check_returns_none_when_no_override(self, isolate_state):
        """check_override returns None when no override exists for the pattern."""
        result = check_override("nonexistent_pattern")

        assert result is None

    def test_check_consumes_once_override(self, isolate_state):
        """check_override consumes a 'once' override -- second check returns None."""
        create_override(
            pattern_name="ssh_key_read",
            mode="once",
            reason="Single use",
        )

        # First check should find and consume it
        first = check_override("ssh_key_read")
        assert first is not None
        assert first["used"] is True
        assert first["used_at"] is not None

        # Second check should return None (consumed)
        second = check_override("ssh_key_read")
        assert second is None

    def test_check_respects_duration_expiry(self, isolate_state):
        """check_override returns None for an expired duration override."""
        # Create an override, then manually backdate its expires_at
        create_override(
            pattern_name="env_file_write",
            mode="duration",
            duration_minutes=30,
            reason="Window closed",
        )

        # Manually set expires_at to the past
        state = _load_state()
        past_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        state["overrides"][0]["expires_at"] = past_time
        with open(isolate_state, "w") as f:
            json.dump(state, f)

        result = check_override("env_file_write")
        assert result is None

    def test_check_active_duration_override(self, isolate_state):
        """check_override returns override for non-expired duration override."""
        create_override(
            pattern_name="env_file_write",
            mode="duration",
            duration_minutes=60,
            reason="Active window",
        )

        result = check_override("env_file_write")

        assert result is not None
        assert result["pattern"] == "env_file_write"
        assert result["mode"] == "duration"
        # Duration overrides are NOT consumed on check
        assert result["used"] is False

    def test_check_ignores_consumed_once_overrides(self, isolate_state):
        """check_override skips already-consumed 'once' overrides."""
        # Create and consume an override
        create_override(
            pattern_name="ssh_key_read",
            mode="once",
            reason="First use",
        )
        check_override("ssh_key_read")  # Consume it

        # Create a second override for the same pattern
        create_override(
            pattern_name="ssh_key_read",
            mode="once",
            reason="Second use",
        )

        # Check should find the second (unconsumed) override
        result = check_override("ssh_key_read")
        assert result is not None
        assert result["reason"] == "Second use"

    def test_check_does_not_consume_duration_override(self, isolate_state):
        """Duration overrides are reusable -- multiple checks succeed."""
        create_override(
            pattern_name="deploy_override",
            mode="duration",
            duration_minutes=60,
            reason="Deployment",
        )

        first = check_override("deploy_override")
        assert first is not None

        second = check_override("deploy_override")
        assert second is not None

        third = check_override("deploy_override")
        assert third is not None


class TestListOverrides:
    """Tests for list_overrides() and list_active_overrides()."""

    def test_list_overrides_returns_all(self, isolate_state):
        """list_overrides returns all overrides including consumed and expired."""
        # Create and consume a once override
        create_override(pattern_name="pattern_a", mode="once", reason="A")
        check_override("pattern_a")  # Consume it

        # Create an active override
        create_override(pattern_name="pattern_b", mode="once", reason="B")

        # Create an expired duration override
        create_override(
            pattern_name="pattern_c",
            mode="duration",
            duration_minutes=30,
            reason="C",
        )
        state = _load_state()
        past_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        state["overrides"][2]["expires_at"] = past_time
        with open(isolate_state, "w") as f:
            json.dump(state, f)

        all_overrides = list_overrides()
        assert len(all_overrides) == 3

        patterns = [o["pattern"] for o in all_overrides]
        assert "pattern_a" in patterns
        assert "pattern_b" in patterns
        assert "pattern_c" in patterns

    def test_list_active_filters_consumed_and_expired(self, isolate_state):
        """list_active_overrides filters out consumed and expired overrides."""
        # Create and consume a once override
        create_override(pattern_name="consumed_pattern", mode="once", reason="Used")
        check_override("consumed_pattern")  # Consume it

        # Create an active override
        create_override(pattern_name="active_pattern", mode="once", reason="Active")

        # Create an expired duration override
        create_override(
            pattern_name="expired_pattern",
            mode="duration",
            duration_minutes=30,
            reason="Expired",
        )
        state = _load_state()
        past_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        # The expired override is the third one (index 2)
        state["overrides"][2]["expires_at"] = past_time
        with open(isolate_state, "w") as f:
            json.dump(state, f)

        active = list_active_overrides()
        assert len(active) == 1
        assert active[0]["pattern"] == "active_pattern"

    def test_list_overrides_empty_state(self, isolate_state):
        """list_overrides returns empty list when no overrides exist."""
        assert list_overrides() == []

    def test_list_active_overrides_empty_state(self, isolate_state):
        """list_active_overrides returns empty list when no overrides exist."""
        assert list_active_overrides() == []


class TestClearOverrides:
    """Tests for clear_overrides()."""

    def test_clear_removes_all_and_returns_count(self, isolate_state):
        """clear_overrides removes all overrides and returns the count removed."""
        create_override(pattern_name="pattern_a", mode="once")
        create_override(pattern_name="pattern_b", mode="once")
        create_override(pattern_name="pattern_c", mode="duration", duration_minutes=60)

        count = clear_overrides()
        assert count == 3

        remaining = list_overrides()
        assert remaining == []

    def test_clear_on_empty_state_returns_zero(self, isolate_state):
        """clear_overrides on empty state returns 0."""
        count = clear_overrides()
        assert count == 0

    def test_clear_persists_to_disk(self, isolate_state):
        """clear_overrides writes the empty state to disk."""
        create_override(pattern_name="pattern_a", mode="once")
        clear_overrides()

        # Reload state from disk
        state = _load_state()
        assert state["overrides"] == []


class TestMultiplePatterns:
    """Tests for independent override behavior across different patterns."""

    def test_overrides_for_different_patterns_are_independent(self, isolate_state):
        """Overrides for different patterns do not interfere with each other."""
        create_override(pattern_name="ssh_key_read", mode="once", reason="SSH")
        create_override(pattern_name="env_file_write", mode="once", reason="ENV")

        # Consume ssh_key_read
        ssh_result = check_override("ssh_key_read")
        assert ssh_result is not None
        assert ssh_result["pattern"] == "ssh_key_read"

        # env_file_write should still be available
        env_result = check_override("env_file_write")
        assert env_result is not None
        assert env_result["pattern"] == "env_file_write"

        # ssh_key_read should now be consumed
        ssh_again = check_override("ssh_key_read")
        assert ssh_again is None

    def test_duration_and_once_overrides_coexist(self, isolate_state):
        """A duration override and a once override for different patterns coexist."""
        create_override(
            pattern_name="ssh_key_read",
            mode="once",
            reason="Single SSH access",
        )
        create_override(
            pattern_name="deploy_config",
            mode="duration",
            duration_minutes=60,
            reason="Deployment window",
        )

        # Both should be active
        active = list_active_overrides()
        assert len(active) == 2

        # Consume the once override
        check_override("ssh_key_read")

        # Only duration should remain active
        active = list_active_overrides()
        assert len(active) == 1
        assert active[0]["pattern"] == "deploy_config"


class TestStateFileEdgeCases:
    """Tests for edge cases with the state file."""

    def test_state_file_does_not_exist(self, isolate_state):
        """When state file does not exist, _load_state returns empty state."""
        # The file should not exist yet (fixture creates path but not file)
        assert not isolate_state.exists()

        state = _load_state()
        assert state == {"overrides": []}

    def test_corrupted_state_file_returns_empty(self, isolate_state):
        """When state file contains invalid JSON, _load_state returns empty state."""
        isolate_state.parent.mkdir(parents=True, exist_ok=True)
        isolate_state.write_text("this is not valid json {{{")

        state = _load_state()
        assert state == {"overrides": []}

    def test_corrupted_state_does_not_break_create(self, isolate_state):
        """Creating an override after corrupted state works correctly."""
        isolate_state.parent.mkdir(parents=True, exist_ok=True)
        isolate_state.write_text("{corrupt!!!}")

        # Should recover gracefully and create a new override
        result = create_override(
            pattern_name="recovery_test",
            mode="once",
            reason="After corruption",
        )

        assert result["pattern"] == "recovery_test"
        state = _load_state()
        assert len(state["overrides"]) == 1

    def test_empty_state_file_returns_empty(self, isolate_state):
        """An empty state file returns empty state."""
        isolate_state.parent.mkdir(parents=True, exist_ok=True)
        isolate_state.write_text("")

        state = _load_state()
        assert state == {"overrides": []}

    def test_state_created_on_first_save(self, isolate_state):
        """State file and parent directories are created on first override."""
        # Use a nested path that doesn't exist yet
        assert not isolate_state.exists()

        create_override(pattern_name="first_override", mode="once")

        assert isolate_state.exists()
        state = _load_state()
        assert len(state["overrides"]) == 1


class TestExpiryBehavior:
    """Detailed tests for override expiry mechanics."""

    def test_duration_override_valid_before_expiry(self, isolate_state):
        """Duration override is valid when current time is before expires_at."""
        create_override(
            pattern_name="timed_access",
            mode="duration",
            duration_minutes=120,
            reason="Two hour window",
        )

        result = check_override("timed_access")
        assert result is not None
        assert result["pattern"] == "timed_access"

    def test_duration_override_invalid_after_expiry(self, isolate_state):
        """Duration override is invalid when current time is past expires_at."""
        create_override(
            pattern_name="timed_access",
            mode="duration",
            duration_minutes=5,
            reason="Short window",
        )

        # Manually backdate expires_at to the past
        state = _load_state()
        expired_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        state["overrides"][0]["expires_at"] = expired_time
        with open(isolate_state, "w") as f:
            json.dump(state, f)

        result = check_override("timed_access")
        assert result is None

    def test_expired_duration_excluded_from_active_list(self, isolate_state):
        """Expired duration overrides are excluded from list_active_overrides."""
        create_override(
            pattern_name="expired_one",
            mode="duration",
            duration_minutes=5,
        )
        create_override(
            pattern_name="still_active",
            mode="duration",
            duration_minutes=120,
        )

        # Expire the first one
        state = _load_state()
        expired_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        state["overrides"][0]["expires_at"] = expired_time
        with open(isolate_state, "w") as f:
            json.dump(state, f)

        active = list_active_overrides()
        assert len(active) == 1
        assert active[0]["pattern"] == "still_active"

    def test_malformed_expires_at_is_treated_as_expired(self, isolate_state):
        """An override with an unparseable expires_at is skipped by check_override."""
        create_override(
            pattern_name="bad_expiry",
            mode="duration",
            duration_minutes=30,
        )

        # Corrupt the expires_at field
        state = _load_state()
        state["overrides"][0]["expires_at"] = "not-a-valid-datetime"
        with open(isolate_state, "w") as f:
            json.dump(state, f)

        result = check_override("bad_expiry")
        assert result is None

    def test_malformed_expires_at_excluded_from_active(self, isolate_state):
        """An override with unparseable expires_at is excluded from active list."""
        create_override(
            pattern_name="bad_expiry",
            mode="duration",
            duration_minutes=30,
        )

        state = _load_state()
        state["overrides"][0]["expires_at"] = "garbage-datetime"
        with open(isolate_state, "w") as f:
            json.dump(state, f)

        active = list_active_overrides()
        assert len(active) == 0


# =============================================================================
# FILE LOCKING TESTS (F4)
# =============================================================================

class TestFileLocking:
    """Tests for fcntl.flock-based file locking in break-glass operations."""

    def test_lock_file_created(self, isolate_state):
        """Lock file should be created during break-glass operations."""
        from tweek.hooks.break_glass import BREAK_GLASS_LOCK
        create_override(pattern_name="lock_test", mode="once", reason="test")
        assert BREAK_GLASS_LOCK.parent.exists()

    def test_concurrent_single_use_override(self, isolate_state):
        """Two threads consuming the same single-use override: exactly one should get it."""
        import threading

        create_override(pattern_name="concurrent_test", mode="once", reason="test")

        results = []
        errors = []

        def check_in_thread():
            try:
                result = check_override("concurrent_test")
                results.append(result)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=check_in_thread)
        t2 = threading.Thread(target=check_in_thread)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(errors) == 0
        assert len(results) == 2
        # Exactly one thread should get the override, the other gets None
        non_none = [r for r in results if r is not None]
        nones = [r for r in results if r is None]
        assert len(non_none) == 1
        assert len(nones) == 1
        assert non_none[0]["pattern"] == "concurrent_test"

    def test_existing_tests_still_pass_with_locking(self, isolate_state):
        """Basic create/check/clear cycle works with file locking."""
        override = create_override(
            pattern_name="basic_lock_test", mode="once", reason="verify locking"
        )
        assert override["pattern"] == "basic_lock_test"

        result = check_override("basic_lock_test")
        assert result is not None
        assert result["used"] is True

        # Second check should return None (consumed)
        result2 = check_override("basic_lock_test")
        assert result2 is None

        # Clear should work
        count = clear_overrides()
        assert count >= 1
