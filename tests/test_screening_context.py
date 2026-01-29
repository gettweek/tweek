#!/usr/bin/env python3
"""Tests for the ScreeningContext dataclass."""

import pytest
from tweek.screening.context import ScreeningContext


class TestScreeningContext:
    """Tests for ScreeningContext creation and serialization."""

    def test_basic_creation(self):
        """Test creating a context with required fields only."""
        ctx = ScreeningContext(
            tool_name="Bash",
            content="ls -la",
            tier="default",
            working_dir="/tmp",
        )
        assert ctx.tool_name == "Bash"
        assert ctx.content == "ls -la"
        assert ctx.tier == "default"
        assert ctx.working_dir == "/tmp"
        assert ctx.source == "hooks"  # default
        assert ctx.session_id is None
        assert ctx.skill_name is None
        assert ctx.client_name is None

    def test_full_creation(self):
        """Test creating a context with all fields."""
        ctx = ScreeningContext(
            tool_name="WebFetch",
            content="https://example.com",
            tier="risky",
            working_dir="/Users/me/project",
            session_id="sess-123",
            skill_name="email-search",
            source="mcp",
            client_name="claude-desktop",
            mcp_server=None,
            project_config_path="/Users/me/project/.tweek/config.yaml",
            tool_input={"url": "https://example.com"},
            metadata={"custom": "value"},
        )
        assert ctx.source == "mcp"
        assert ctx.client_name == "claude-desktop"
        assert ctx.skill_name == "email-search"
        assert ctx.tool_input == {"url": "https://example.com"}

    def test_to_dict(self):
        """Test serialization to dict."""
        ctx = ScreeningContext(
            tool_name="Bash",
            content="echo hello",
            tier="default",
            working_dir="/tmp",
            source="mcp",
            skill_name="deploy",
        )
        d = ctx.to_dict()
        assert d["tool_name"] == "Bash"
        assert d["content"] == "echo hello"
        assert d["source"] == "mcp"
        assert d["skill_name"] == "deploy"
        assert d["session_id"] is None

    def test_to_legacy_dict(self):
        """Test backward-compatible legacy dict format."""
        ctx = ScreeningContext(
            tool_name="Bash",
            content="echo hello",
            tier="dangerous",
            working_dir="/tmp",
            session_id="sess-456",
            skill_name="deploy",
            source="mcp",
            tool_input={"command": "echo hello"},
        )
        legacy = ctx.to_legacy_dict()
        assert legacy["session_id"] == "sess-456"
        assert legacy["tier"] == "dangerous"
        assert legacy["tool_name"] == "Bash"
        assert legacy["working_dir"] == "/tmp"
        assert legacy["tool_input"] == {"command": "echo hello"}
        # Legacy dict should NOT contain source or skill_name
        assert "source" not in legacy
        assert "skill_name" not in legacy

    def test_to_legacy_dict_without_tool_input(self):
        """Test legacy dict when tool_input is None."""
        ctx = ScreeningContext(
            tool_name="Read",
            content="/tmp/file.txt",
            tier="safe",
            working_dir="/tmp",
        )
        legacy = ctx.to_legacy_dict()
        assert "tool_input" not in legacy

    def test_metadata_default(self):
        """Test that metadata defaults to empty dict."""
        ctx = ScreeningContext(
            tool_name="Bash",
            content="ls",
            tier="default",
            working_dir="/tmp",
        )
        assert ctx.metadata == {}
        # Should be mutable
        ctx.metadata["key"] = "value"
        assert ctx.metadata["key"] == "value"

    def test_mcp_source_context(self):
        """Test context built for MCP gateway use."""
        ctx = ScreeningContext(
            tool_name="Bash",
            content="git status",
            tier="default",
            working_dir="/Users/me/project",
            source="mcp",
            client_name="claude-desktop",
        )
        assert ctx.source == "mcp"
        assert ctx.client_name == "claude-desktop"

    def test_proxy_source_context(self):
        """Test context built for HTTP proxy use."""
        ctx = ScreeningContext(
            tool_name="WebFetch",
            content="https://api.openai.com/v1/chat/completions",
            tier="risky",
            working_dir="/Users/me/project",
            source="proxy",
            client_name="cursor",
        )
        assert ctx.source == "proxy"
        assert ctx.client_name == "cursor"
