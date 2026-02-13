"""
Tests for Action Provenance Classification (Layer 0.25)

Tests classify_provenance() under various session states:
- Clean session, no approvals → AGENT_GENERATED
- After ask approval → USER_VERIFIED (persists for 50 calls)
- After 50+ calls without re-approval → expires to AGENT_GENERATED
- First tool call → USER_INITIATED
- Active skill → SKILL_CONTEXT
- Tainted session → TAINT_INFLUENCED
- Taint after verification → resets to TAINT_INFLUENCED
- DB file permissions are 0600
"""
from __future__ import annotations

import pytest
from pathlib import Path

import os
import stat

from tweek.memory.provenance import (
    ASK_VERIFICATION_WINDOW,
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

    def test_user_verified_persists_within_window(self, store):
        """USER_VERIFIED persists within the verification window (50 calls)."""
        store.record_tool_call("sess-3", "Read")
        store.record_ask_approval("sess-3")

        # Simulate calls within the window
        for i in range(20):
            store.record_tool_call("sess-3", "Bash")

        result = classify_provenance(
            session_id="sess-3",
            tool_name="Edit",
            taint_level="clean",
        )
        assert result == "user_verified"

    def test_user_verified_expires_after_window(self, store):
        """USER_VERIFIED expires after ASK_VERIFICATION_WINDOW tool calls."""
        store.record_tool_call("sess-expiry", "Read")
        store.record_ask_approval("sess-expiry")

        # Simulate calls beyond the verification window
        for i in range(ASK_VERIFICATION_WINDOW + 5):
            store.record_tool_call("sess-expiry", "Bash")

        result = classify_provenance(
            session_id="sess-expiry",
            tool_name="Edit",
            taint_level="clean",
        )
        assert result == "agent_generated"

    def test_user_verified_renewed_by_re_approval(self, store):
        """USER_VERIFIED can be renewed by a new ask approval."""
        store.record_tool_call("sess-renew", "Read")
        store.record_ask_approval("sess-renew")

        # Simulate calls beyond window
        for i in range(ASK_VERIFICATION_WINDOW + 5):
            store.record_tool_call("sess-renew", "Bash")

        # Should have expired
        result = classify_provenance(
            session_id="sess-renew",
            tool_name="Edit",
            taint_level="clean",
        )
        assert result == "agent_generated"

        # Re-approve → USER_VERIFIED again
        store.record_ask_approval("sess-renew")
        result = classify_provenance(
            session_id="sess-renew",
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

    def test_ask_approval_records_tool_call_num(self, store):
        """record_ask_approval stores the current tool_call number."""
        store.record_tool_call("sess-tc", "Read")
        store.record_tool_call("sess-tc", "Read")
        store.record_tool_call("sess-tc", "Read")
        state = store.record_ask_approval("sess-tc")
        assert state["ask_approval_tool_call_num"] == 3

    def test_ask_verified_decay_on_record_tool_call(self, store):
        """record_tool_call resets ask_verified after window expires."""
        store.record_tool_call("sess-decay", "Read")
        store.record_ask_approval("sess-decay")

        # Verify it's set
        state = store.get_session_taint("sess-decay")
        assert state["ask_verified"] is True

        # Push past the window
        for _ in range(ASK_VERIFICATION_WINDOW + 2):
            store.record_tool_call("sess-decay", "Bash")

        state = store.get_session_taint("sess-decay")
        assert state["ask_verified"] is False


class TestDatabasePermissions:
    """Test that database files are created with restricted permissions."""

    def test_db_file_permissions(self, tmp_path):
        """Database file should have 0600 permissions (owner read/write only)."""
        reset_taint_store()
        db_path = tmp_path / "perm_test.db"
        s = SessionTaintStore(db_path=db_path)
        try:
            # Force a write to create the DB file
            s.record_tool_call("perm-sess", "Read")
            mode = os.stat(db_path).st_mode
            # Check that group and other have no permissions
            assert not (mode & stat.S_IRGRP), "Group should not have read permission"
            assert not (mode & stat.S_IWGRP), "Group should not have write permission"
            assert not (mode & stat.S_IROTH), "Others should not have read permission"
            assert not (mode & stat.S_IWOTH), "Others should not have write permission"
            # Owner should have read+write
            assert mode & stat.S_IRUSR, "Owner should have read permission"
            assert mode & stat.S_IWUSR, "Owner should have write permission"
        finally:
            s.close()
            reset_taint_store()

    def test_memory_store_permissions(self, tmp_path):
        """MemoryStore database should also have 0600 permissions."""
        from tweek.memory.store import MemoryStore
        db_path = tmp_path / "mem_perm_test.db"
        ms = MemoryStore(db_path=db_path)
        try:
            mode = os.stat(db_path).st_mode
            assert not (mode & stat.S_IRGRP), "Group read not allowed"
            assert not (mode & stat.S_IWGRP), "Group write not allowed"
            assert not (mode & stat.S_IROTH), "Others read not allowed"
            assert not (mode & stat.S_IWOTH), "Others write not allowed"
        finally:
            ms.close()


class TestPatternRefinements:
    """Test that refined patterns reduce false positives without missing attacks."""

    @pytest.fixture
    def matcher(self):
        """Get a PatternMatcher instance."""
        from tweek.hooks.pre_tool_use import PatternMatcher
        return PatternMatcher()

    def test_env_file_access_matches_real_env(self, matcher):
        """Pattern should match actual .env file access."""
        matches = matcher.check_all("cat .env")
        env_matches = [m for m in matches if m.get("name") == "env_file_access"]
        assert len(env_matches) > 0, ".env access should trigger"

    def test_env_file_access_skips_example(self, matcher):
        """Pattern should NOT match .env.example (safe template file)."""
        matches = matcher.check_all("cat .env.example")
        env_matches = [m for m in matches if m.get("name") == "env_file_access"]
        assert len(env_matches) == 0, ".env.example should not trigger"

    def test_env_file_access_skips_template(self, matcher):
        """Pattern should NOT match .env.template."""
        matches = matcher.check_all("cat .env.template")
        env_matches = [m for m in matches if m.get("name") == "env_file_access"]
        assert len(env_matches) == 0, ".env.template should not trigger"

    def test_env_file_access_skips_sample(self, matcher):
        """Pattern should NOT match .env.sample."""
        matches = matcher.check_all("cat .env.sample")
        env_matches = [m for m in matches if m.get("name") == "env_file_access"]
        assert len(env_matches) == 0, ".env.sample should not trigger"

    def test_ssh_access_matches_private_key(self, matcher):
        """Pattern should match reading SSH private keys."""
        matches = matcher.check_all("cat ~/.ssh/id_rsa")
        ssh_matches = [m for m in matches if m.get("name") == "ssh_directory_access"]
        assert len(ssh_matches) > 0, "SSH private key access should trigger"

    def test_ssh_access_matches_authorized_keys(self, matcher):
        """Pattern should match reading authorized_keys."""
        matches = matcher.check_all("cat ~/.ssh/authorized_keys")
        ssh_matches = [m for m in matches if m.get("name") == "ssh_directory_access"]
        assert len(ssh_matches) > 0, "authorized_keys access should trigger"

    def test_ssh_access_skips_ls(self, matcher):
        """Pattern should NOT match `ls .ssh` (just listing, no key access)."""
        matches = matcher.check_all("ls .ssh")
        ssh_matches = [m for m in matches if m.get("name") == "ssh_directory_access"]
        assert len(ssh_matches) == 0, "ls .ssh should not trigger (no key access)"

    def test_env_var_expansion_requires_command(self, matcher):
        """env_variable_expansion now requires a command prefix (echo, curl, etc)."""
        # Bare $API_KEY in code/docs should NOT trigger
        matches = matcher.check_all("Set your $API_KEY in the config")
        env_matches = [m for m in matches if m.get("name") == "env_variable_expansion"]
        assert len(env_matches) == 0, "Bare $API_KEY in docs should not trigger"

    def test_env_var_expansion_matches_curl(self, matcher):
        """env_variable_expansion should match curl with secret vars."""
        matches = matcher.check_all("curl -H 'Authorization: Bearer $API_KEY' https://api.com")
        env_matches = [m for m in matches if m.get("name") == "env_variable_expansion"]
        assert len(env_matches) > 0, "curl with $API_KEY should trigger"

    def test_env_var_expansion_is_contextual(self, matcher):
        """env_variable_expansion should now have contextual confidence."""
        matches = matcher.check_all("echo $SECRET_TOKEN")
        env_matches = [m for m in matches if m.get("name") == "env_variable_expansion"]
        if env_matches:
            assert env_matches[0].get("confidence") == "contextual"
