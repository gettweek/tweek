#!/usr/bin/env python3
"""Tests for the MCP Security Gateway server (vault + status only)."""

import json
import pytest
from unittest.mock import patch

pytestmark = pytest.mark.mcp

# Check if MCP is available
try:
    from mcp.server import Server
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False


class TestTweekMCPServerCreation:
    """Test MCP server creation and configuration."""

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    def test_create_server(self):
        """Test creating a TweekMCPServer instance."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()
        assert server is not None
        assert server._request_count == 0
        assert server._blocked_count == 0

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    def test_create_server_with_config(self):
        """Test creating server with custom config."""
        from tweek.mcp.server import TweekMCPServer
        config = {
            "mcp": {
                "gateway": {
                    "tools": {
                        "vault": True,
                        "status": True,
                    }
                }
            }
        }
        server = TweekMCPServer(config=config)
        assert server.config == config

    def test_mcp_not_available_error(self):
        """Test error when MCP SDK is not installed."""
        from tweek.mcp.server import _check_mcp_available
        with patch("tweek.mcp.server.MCP_AVAILABLE", False):
            with pytest.raises(RuntimeError, match="MCP SDK not installed"):
                _check_mcp_available()


class TestBuildContext:
    """Test ScreeningContext creation from MCP tool calls."""

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    def test_build_context_defaults(self):
        """Test building a context with defaults."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()
        ctx = server._build_context("Vault", "vault:test/KEY")

        assert ctx.tool_name == "Vault"
        assert ctx.content == "vault:test/KEY"
        assert ctx.source == "mcp"
        assert ctx.tier == "default"

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    def test_build_context_with_client(self):
        """Test building context with client name."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer(config={"client_name": "claude-desktop"})
        ctx = server._build_context("Vault", "vault:test/KEY")

        assert ctx.client_name == "claude-desktop"
        assert ctx.source == "mcp"


class TestGatewayToolHandlers:
    """Test the vault and status tool handlers."""

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    @pytest.mark.asyncio
    async def test_handle_status_summary(self):
        """Test status tool returns valid summary JSON."""
        from tweek.mcp.server import TweekMCPServer, MCP_SERVER_VERSION
        server = TweekMCPServer()

        result_json = await server._handle_status({"detail": "summary"})
        result = json.loads(result_json)

        assert result["version"] == MCP_SERVER_VERSION
        assert result["source"] == "mcp"
        assert result["mode"] == "gateway"
        assert "gateway_requests" in result
        assert "gateway_blocked" in result

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    @pytest.mark.asyncio
    async def test_handle_status_plugins(self):
        """Test status tool with plugins detail."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()

        result_json = await server._handle_status({"detail": "plugins"})
        result = json.loads(result_json)
        assert "plugins" in result

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    @pytest.mark.asyncio
    async def test_handle_vault_not_found(self):
        """Test vault returns error for missing credential."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()

        result_json = await server._handle_vault({
            "skill": "nonexistent",
            "key": "MISSING_KEY",
        })
        result = json.loads(result_json)
        assert "error" in result or "blocked" in result


class TestNoLongerExposedTools:
    """Verify that bash/read/write/web tools are NOT exposed."""

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    def test_no_bash_handler(self):
        """Verify tweek_bash is not registered."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()
        assert not hasattr(server, "_handle_bash")

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    def test_no_read_handler(self):
        """Verify tweek_read is not registered."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()
        assert not hasattr(server, "_handle_read")

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    def test_no_write_handler(self):
        """Verify tweek_write is not registered."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()
        assert not hasattr(server, "_handle_write")

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    def test_no_web_handler(self):
        """Verify tweek_web is not registered."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()
        assert not hasattr(server, "_handle_web")


class TestRequestCounting:
    """Test that request and block counters work."""

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    def test_initial_counts(self):
        """Test initial counters are zero."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()
        assert server._request_count == 0
        assert server._blocked_count == 0
