"""Tests for skill context detection via Skill tool breadcrumbs.

Verifies that:
  - Skill tool invocations write a breadcrumb with skill name
  - Subsequent tool calls read the breadcrumb for context
  - Session isolation prevents cross-session leakage
  - Stale breadcrumbs are ignored and cleaned up
  - extract_skill_from_tool_input handles edge cases
  - Tier override works when skill context is active
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from tweek.skills.context import (
    STALENESS_TIMEOUT_SECONDS,
    clear_skill_breadcrumb,
    extract_skill_from_tool_input,
    read_skill_context,
    write_skill_breadcrumb,
)


# ---------------------------------------------------------------------------
# extract_skill_from_tool_input
# ---------------------------------------------------------------------------

class TestExtractSkill:
    """Test skill name extraction from tool_input dicts."""

    def test_basic_skill_name(self):
        assert extract_skill_from_tool_input({"skill": "commit"}) == "commit"

    def test_skill_with_args(self):
        result = extract_skill_from_tool_input({"skill": "review-pr", "args": "123"})
        assert result == "review-pr"

    def test_empty_skill_returns_none(self):
        assert extract_skill_from_tool_input({"skill": ""}) is None

    def test_whitespace_skill_returns_none(self):
        assert extract_skill_from_tool_input({"skill": "  "}) is None

    def test_missing_skill_key_returns_none(self):
        assert extract_skill_from_tool_input({"args": "foo"}) is None

    def test_non_string_skill_returns_none(self):
        assert extract_skill_from_tool_input({"skill": 42}) is None

    def test_none_skill_returns_none(self):
        assert extract_skill_from_tool_input({"skill": None}) is None

    def test_empty_dict(self):
        assert extract_skill_from_tool_input({}) is None

    def test_strips_whitespace(self):
        assert extract_skill_from_tool_input({"skill": " deploy "}) == "deploy"

    def test_fully_qualified_skill_name(self):
        result = extract_skill_from_tool_input({"skill": "ms-office-suite:pdf"})
        assert result == "ms-office-suite:pdf"


# ---------------------------------------------------------------------------
# write / read breadcrumb
# ---------------------------------------------------------------------------

class TestBreadcrumbWriteRead:
    """Test breadcrumb file write and read cycle."""

    def test_write_then_read(self, tmp_path):
        bc = tmp_path / "active_skill.json"
        write_skill_breadcrumb("commit", "session-1", breadcrumb_path=bc)
        result = read_skill_context("session-1", breadcrumb_path=bc)
        assert result == "commit"

    def test_read_nonexistent_returns_none(self, tmp_path):
        bc = tmp_path / "nonexistent.json"
        assert read_skill_context("session-1", breadcrumb_path=bc) is None

    def test_overwrite_updates_skill(self, tmp_path):
        bc = tmp_path / "active_skill.json"
        write_skill_breadcrumb("commit", "session-1", breadcrumb_path=bc)
        write_skill_breadcrumb("deploy", "session-1", breadcrumb_path=bc)
        assert read_skill_context("session-1", breadcrumb_path=bc) == "deploy"

    def test_breadcrumb_content_format(self, tmp_path):
        bc = tmp_path / "active_skill.json"
        write_skill_breadcrumb("review-pr", "sess-42", breadcrumb_path=bc)

        data = json.loads(bc.read_text())
        assert data["skill"] == "review-pr"
        assert data["session_id"] == "sess-42"
        assert "timestamp" in data
        assert isinstance(data["timestamp"], float)

    def test_creates_parent_directories(self, tmp_path):
        bc = tmp_path / "nested" / "deep" / "active_skill.json"
        write_skill_breadcrumb("commit", "s1", breadcrumb_path=bc)
        assert bc.exists()
        assert read_skill_context("s1", breadcrumb_path=bc) == "commit"


# ---------------------------------------------------------------------------
# Session isolation
# ---------------------------------------------------------------------------

class TestSessionIsolation:
    """Breadcrumbs must only match the same session."""

    def test_different_session_returns_none(self, tmp_path):
        bc = tmp_path / "active_skill.json"
        write_skill_breadcrumb("commit", "session-A", breadcrumb_path=bc)
        result = read_skill_context("session-B", breadcrumb_path=bc)
        assert result is None

    def test_same_session_matches(self, tmp_path):
        bc = tmp_path / "active_skill.json"
        write_skill_breadcrumb("deploy", "session-X", breadcrumb_path=bc)
        assert read_skill_context("session-X", breadcrumb_path=bc) == "deploy"

    def test_new_session_overrides_old(self, tmp_path):
        bc = tmp_path / "active_skill.json"
        write_skill_breadcrumb("commit", "session-old", breadcrumb_path=bc)
        write_skill_breadcrumb("deploy", "session-new", breadcrumb_path=bc)

        # Old session no longer matches
        assert read_skill_context("session-old", breadcrumb_path=bc) is None
        # New session matches
        assert read_skill_context("session-new", breadcrumb_path=bc) == "deploy"


# ---------------------------------------------------------------------------
# Staleness timeout
# ---------------------------------------------------------------------------

class TestStaleness:
    """Stale breadcrumbs are ignored and cleaned up."""

    def test_fresh_breadcrumb_is_valid(self, tmp_path):
        bc = tmp_path / "active_skill.json"
        write_skill_breadcrumb("commit", "s1", breadcrumb_path=bc)
        # With generous timeout, should be valid
        result = read_skill_context("s1", breadcrumb_path=bc, staleness_seconds=3600)
        assert result == "commit"

    def test_stale_breadcrumb_returns_none(self, tmp_path):
        bc = tmp_path / "active_skill.json"
        # Write a breadcrumb with a manually backdated timestamp
        data = {
            "skill": "commit",
            "session_id": "s1",
            "timestamp": time.time() - 600,  # 10 minutes ago
        }
        bc.write_text(json.dumps(data))

        result = read_skill_context("s1", breadcrumb_path=bc, staleness_seconds=300)
        assert result is None

    def test_stale_breadcrumb_is_cleaned_up(self, tmp_path):
        bc = tmp_path / "active_skill.json"
        data = {
            "skill": "commit",
            "session_id": "s1",
            "timestamp": time.time() - 600,
        }
        bc.write_text(json.dumps(data))

        read_skill_context("s1", breadcrumb_path=bc, staleness_seconds=300)
        # Breadcrumb file should be removed
        assert not bc.exists()

    def test_just_under_timeout_is_valid(self, tmp_path):
        bc = tmp_path / "active_skill.json"
        data = {
            "skill": "deploy",
            "session_id": "s1",
            "timestamp": time.time() - 290,  # 290s ago, timeout is 300s
        }
        bc.write_text(json.dumps(data))

        result = read_skill_context("s1", breadcrumb_path=bc, staleness_seconds=300)
        assert result == "deploy"

    def test_default_staleness_is_60s(self):
        assert STALENESS_TIMEOUT_SECONDS == 60


# ---------------------------------------------------------------------------
# clear_skill_breadcrumb
# ---------------------------------------------------------------------------

class TestClearBreadcrumb:
    """Test explicit breadcrumb clearing."""

    def test_clear_removes_file(self, tmp_path):
        bc = tmp_path / "active_skill.json"
        write_skill_breadcrumb("commit", "s1", breadcrumb_path=bc)
        assert bc.exists()

        clear_skill_breadcrumb(breadcrumb_path=bc)
        assert not bc.exists()

    def test_clear_nonexistent_is_safe(self, tmp_path):
        bc = tmp_path / "nonexistent.json"
        # Should not raise
        clear_skill_breadcrumb(breadcrumb_path=bc)

    def test_read_after_clear_returns_none(self, tmp_path):
        bc = tmp_path / "active_skill.json"
        write_skill_breadcrumb("commit", "s1", breadcrumb_path=bc)
        clear_skill_breadcrumb(breadcrumb_path=bc)
        assert read_skill_context("s1", breadcrumb_path=bc) is None


# ---------------------------------------------------------------------------
# Error resilience
# ---------------------------------------------------------------------------

class TestErrorResilience:
    """Breadcrumb operations handle corrupt data gracefully."""

    def test_corrupt_json_returns_none(self, tmp_path):
        bc = tmp_path / "active_skill.json"
        bc.write_text("not valid json{{{")
        assert read_skill_context("s1", breadcrumb_path=bc) is None

    def test_missing_fields_returns_none(self, tmp_path):
        bc = tmp_path / "active_skill.json"
        bc.write_text(json.dumps({"skill": "commit"}))  # Missing session_id and timestamp
        # session_id won't match
        assert read_skill_context("s1", breadcrumb_path=bc) is None

    def test_empty_file_returns_none(self, tmp_path):
        bc = tmp_path / "active_skill.json"
        bc.write_text("")
        assert read_skill_context("s1", breadcrumb_path=bc) is None


# ---------------------------------------------------------------------------
# Tier override integration
# ---------------------------------------------------------------------------

class TestTierOverride:
    """Verify TierManager.get_base_tier() uses skill_name when provided."""

    @staticmethod
    def _make_tier_manager(tmp_path, config: dict):
        """Write a YAML config to a temp file and create a TierManager."""
        import yaml
        from tweek.hooks.pre_tool_use import TierManager

        config_file = tmp_path / "tiers.yaml"
        config_file.write_text(yaml.dump(config))
        return TierManager(config_path=config_file)

    def test_skill_can_only_escalate_tool_tier(self, tmp_path):
        """Skills can only escalate a tool's tier, never relax it."""
        mgr = self._make_tier_manager(tmp_path, {
            "tiers": {
                "safe": {"screening": []},
                "default": {"screening": ["regex"]},
                "dangerous": {"screening": ["regex", "llm", "sandbox"]},
            },
            "tools": {"Bash": "dangerous", "Read": "default"},
            "skills": {"deploy": "dangerous", "explore": "safe"},
            "default_tier": "default",
        })

        # Without skill: Bash is dangerous
        assert mgr.get_base_tier("Bash") == "dangerous"

        # Safe skill cannot relax dangerous tool — stays dangerous
        assert mgr.get_base_tier("Bash", skill_name="explore") == "dangerous"

        # Dangerous skill can escalate default tool to dangerous
        assert mgr.get_base_tier("Read", skill_name="deploy") == "dangerous"

        # Safe skill cannot relax default tool — stays default
        assert mgr.get_base_tier("Read", skill_name="explore") == "default"

    def test_unknown_skill_falls_through_to_tool(self, tmp_path):
        """Unknown skill names fall through to tool tier lookup."""
        mgr = self._make_tier_manager(tmp_path, {
            "tiers": {},
            "tools": {"Bash": "dangerous"},
            "skills": {"deploy": "dangerous"},
            "default_tier": "default",
        })

        # Unknown skill falls through to tool tier
        assert mgr.get_base_tier("Bash", skill_name="nonexistent") == "dangerous"

    def test_no_skill_no_override(self, tmp_path):
        """None skill_name means no override."""
        mgr = self._make_tier_manager(tmp_path, {
            "tiers": {},
            "tools": {"Write": "risky"},
            "skills": {"deploy": "dangerous"},
            "default_tier": "default",
        })

        assert mgr.get_base_tier("Write", skill_name=None) == "risky"
        assert mgr.get_base_tier("Write") == "risky"
