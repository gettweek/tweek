#!/usr/bin/env python3
"""Tests for the PluginScope system."""

import pytest
from tweek.plugins.scope import PluginScope
from tweek.screening.context import ScreeningContext


def _make_context(**kwargs) -> ScreeningContext:
    """Helper to create a ScreeningContext with defaults."""
    defaults = {
        "tool_name": "Bash",
        "content": "ls",
        "tier": "default",
        "working_dir": "/tmp",
    }
    defaults.update(kwargs)
    return ScreeningContext(**defaults)


class TestPluginScopeMatches:
    """Test PluginScope.matches() behavior."""

    def test_empty_scope_matches_everything(self):
        """A scope with no restrictions should match any context."""
        scope = PluginScope()
        assert scope.matches(_make_context()) is True
        assert scope.matches(_make_context(tool_name="Read")) is True
        assert scope.matches(_make_context(tier="dangerous")) is True
        assert scope.matches(_make_context(skill_name="deploy")) is True

    def test_tool_filter_matches(self):
        """Scope with tools filter should match only listed tools."""
        scope = PluginScope(tools=["Bash", "WebFetch"])

        assert scope.matches(_make_context(tool_name="Bash")) is True
        assert scope.matches(_make_context(tool_name="WebFetch")) is True
        assert scope.matches(_make_context(tool_name="Read")) is False
        assert scope.matches(_make_context(tool_name="Write")) is False

    def test_skill_filter_matches(self):
        """Scope with skills filter should match only listed skills."""
        scope = PluginScope(skills=["deploy", "email-search"])

        assert scope.matches(_make_context(skill_name="deploy")) is True
        assert scope.matches(_make_context(skill_name="email-search")) is True
        assert scope.matches(_make_context(skill_name="explore")) is False

    def test_skill_filter_allows_none_skill(self):
        """When skill_name is None in context, skill scoping should not block."""
        scope = PluginScope(skills=["deploy"])
        ctx = _make_context(skill_name=None)
        # Should NOT block - we don't have skill info, so don't filter
        assert scope.matches(ctx) is True

    def test_project_filter_matches(self):
        """Scope with projects filter should match working directory prefixes."""
        scope = PluginScope(projects=["/Users/me/healthcare-app"])

        assert scope.matches(
            _make_context(working_dir="/Users/me/healthcare-app")
        ) is True
        assert scope.matches(
            _make_context(working_dir="/Users/me/healthcare-app/src")
        ) is True
        assert scope.matches(
            _make_context(working_dir="/Users/me/other-project")
        ) is False
        assert scope.matches(
            _make_context(working_dir="/tmp")
        ) is False

    def test_tier_filter_matches(self):
        """Scope with tiers filter should match only listed tiers."""
        scope = PluginScope(tiers=["risky", "dangerous"])

        assert scope.matches(_make_context(tier="risky")) is True
        assert scope.matches(_make_context(tier="dangerous")) is True
        assert scope.matches(_make_context(tier="default")) is False
        assert scope.matches(_make_context(tier="safe")) is False

    def test_combined_filters_all_must_match(self):
        """Multiple filters use AND logic - all must match."""
        scope = PluginScope(
            tools=["Bash", "WebFetch"],
            tiers=["dangerous"],
        )

        # Both match
        assert scope.matches(
            _make_context(tool_name="Bash", tier="dangerous")
        ) is True

        # Only tool matches
        assert scope.matches(
            _make_context(tool_name="Bash", tier="default")
        ) is False

        # Only tier matches
        assert scope.matches(
            _make_context(tool_name="Read", tier="dangerous")
        ) is False

    def test_complex_scope(self):
        """Test a scope with tools, skills, and tiers."""
        scope = PluginScope(
            tools=["Bash", "WebFetch", "Write"],
            skills=["email-search", "patient-records"],
            tiers=["risky", "dangerous"],
        )

        # All match
        assert scope.matches(
            _make_context(
                tool_name="Bash",
                skill_name="email-search",
                tier="dangerous",
            )
        ) is True

        # Skill doesn't match
        assert scope.matches(
            _make_context(
                tool_name="Bash",
                skill_name="explore",
                tier="dangerous",
            )
        ) is False

        # No skill info - should still match (don't block without info)
        assert scope.matches(
            _make_context(
                tool_name="Bash",
                skill_name=None,
                tier="dangerous",
            )
        ) is True

    def test_multiple_projects(self):
        """Test scope with multiple project paths."""
        scope = PluginScope(
            projects=["/Users/me/project-a", "/Users/me/project-b"]
        )

        assert scope.matches(
            _make_context(working_dir="/Users/me/project-a/src")
        ) is True
        assert scope.matches(
            _make_context(working_dir="/Users/me/project-b")
        ) is True
        assert scope.matches(
            _make_context(working_dir="/Users/me/project-c")
        ) is False


class TestPluginScopeSerialization:
    """Test PluginScope serialization and deserialization."""

    def test_to_dict_empty(self):
        """Empty scope should serialize to empty dict."""
        scope = PluginScope()
        assert scope.to_dict() == {}

    def test_to_dict_with_values(self):
        """Non-None values should appear in dict."""
        scope = PluginScope(
            tools=["Bash"],
            tiers=["dangerous"],
        )
        d = scope.to_dict()
        assert d == {"tools": ["Bash"], "tiers": ["dangerous"]}
        assert "skills" not in d
        assert "projects" not in d

    def test_from_dict(self):
        """Test creating scope from config dict."""
        data = {
            "tools": ["Bash", "WebFetch"],
            "skills": ["deploy"],
            "tiers": ["risky", "dangerous"],
        }
        scope = PluginScope.from_dict(data)
        assert scope.tools == ["Bash", "WebFetch"]
        assert scope.skills == ["deploy"]
        assert scope.tiers == ["risky", "dangerous"]
        assert scope.projects is None
        assert scope.directions is None

    def test_from_dict_empty(self):
        """Test creating scope from empty dict."""
        scope = PluginScope.from_dict({})
        assert scope.is_global is True

    def test_roundtrip(self):
        """Test serialization roundtrip."""
        original = PluginScope(
            tools=["Bash"],
            skills=["deploy", "email-search"],
            projects=["/Users/me/app"],
            tiers=["dangerous"],
            directions=["input"],
        )
        d = original.to_dict()
        restored = PluginScope.from_dict(d)
        assert restored.tools == original.tools
        assert restored.skills == original.skills
        assert restored.projects == original.projects
        assert restored.tiers == original.tiers
        assert restored.directions == original.directions


class TestPluginScopeProperties:
    """Test PluginScope helper properties."""

    def test_is_global_true(self):
        """Scope with no restrictions is global."""
        assert PluginScope().is_global is True

    def test_is_global_false(self):
        """Scope with any restriction is not global."""
        assert PluginScope(tools=["Bash"]).is_global is False
        assert PluginScope(tiers=["dangerous"]).is_global is False

    def test_describe_global(self):
        """Global scope description."""
        assert "Global" in PluginScope().describe()

    def test_describe_with_filters(self):
        """Filtered scope description includes filter info."""
        scope = PluginScope(
            tools=["Bash", "WebFetch"],
            tiers=["dangerous"],
        )
        desc = scope.describe()
        assert "Bash" in desc
        assert "WebFetch" in desc
        assert "dangerous" in desc
