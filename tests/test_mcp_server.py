#!/usr/bin/env python3
"""Tests for the MCP Security Gateway server."""

import json
import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

# Check if MCP is available
try:
    from mcp.server import Server
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as d:
        yield d


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
                        "bash": True,
                        "read": True,
                        "write": False,
                        "web": False,
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
        ctx = server._build_context("Bash", "ls -la")

        assert ctx.tool_name == "Bash"
        assert ctx.content == "ls -la"
        assert ctx.source == "mcp"
        assert ctx.tier == "default"

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    def test_build_context_with_client(self):
        """Test building context with client name."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer(config={"client_name": "claude-desktop"})
        ctx = server._build_context("Read", "/tmp/file.txt")

        assert ctx.client_name == "claude-desktop"
        assert ctx.source == "mcp"


class TestScreeningIntegration:
    """Test the screening pipeline integration."""

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    def test_screening_safe_command(self):
        """Test that safe commands pass screening."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()
        ctx = server._build_context("Read", "/tmp/test.txt")

        result = server._run_screening(ctx)
        # Safe tier should pass
        assert result["allowed"] is True
        assert result["blocked"] is False

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    def test_output_scan_clean(self):
        """Test output scanning with clean content."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()

        result = server._run_output_scan("Hello, this is clean output")
        assert result["blocked"] is False


class TestMCPToolHandlers:
    """Test individual MCP tool handlers."""

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    @pytest.mark.asyncio
    async def test_handle_bash_simple(self, temp_dir):
        """Test handling a simple bash command."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()

        result_json = await server._handle_bash({
            "command": "echo hello",
            "working_dir": temp_dir,
        })
        result = json.loads(result_json)

        assert "output" in result or "blocked" in result
        if "output" in result:
            assert "hello" in result["output"]
            assert result["return_code"] == 0

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    @pytest.mark.asyncio
    async def test_handle_read_existing_file(self, temp_dir):
        """Test reading an existing file."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()

        # Create a test file
        test_file = Path(temp_dir) / "test.txt"
        test_file.write_text("test content")

        result_json = await server._handle_read({"path": str(test_file)})
        result = json.loads(result_json)

        assert "content" in result or "blocked" in result
        if "content" in result:
            assert result["content"] == "test content"

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    @pytest.mark.asyncio
    async def test_handle_read_nonexistent_file(self):
        """Test reading a nonexistent file."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()

        result_json = await server._handle_read({
            "path": "/tmp/nonexistent_tweek_test_file.txt",
        })
        result = json.loads(result_json)
        assert "error" in result

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    @pytest.mark.asyncio
    async def test_handle_read_blocks_env(self):
        """Test that reading .env files is blocked."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()

        result_json = await server._handle_read({"path": "/Users/me/.env"})
        result = json.loads(result_json)
        assert result.get("blocked") is True

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    @pytest.mark.asyncio
    async def test_handle_read_blocks_ssh(self):
        """Test that reading .ssh files is blocked."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()

        result_json = await server._handle_read({"path": "/Users/me/.ssh/id_rsa"})
        result = json.loads(result_json)
        assert result.get("blocked") is True

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    @pytest.mark.asyncio
    async def test_handle_write_creates_file(self, temp_dir):
        """Test writing a file."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()

        test_path = str(Path(temp_dir) / "output.txt")
        result_json = await server._handle_write({
            "path": test_path,
            "content": "written by tweek",
        })
        result = json.loads(result_json)

        if result.get("success"):
            assert Path(test_path).read_text() == "written by tweek"

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    @pytest.mark.asyncio
    async def test_handle_write_blocks_etc(self):
        """Test that writing to /etc is blocked."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()

        result_json = await server._handle_write({
            "path": "/etc/passwd",
            "content": "malicious",
        })
        result = json.loads(result_json)
        assert result.get("blocked") is True

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    @pytest.mark.asyncio
    async def test_handle_status(self):
        """Test status tool returns valid JSON."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()

        result_json = await server._handle_status({"detail": "summary"})
        result = json.loads(result_json)

        assert "version" in result
        assert "source" in result
        assert result["source"] == "mcp"
        assert "requests" in result

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

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    @pytest.mark.asyncio
    async def test_handle_bash_timeout(self, temp_dir):
        """Test bash command timeout."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()

        result_json = await server._handle_bash({
            "command": "sleep 10",
            "working_dir": temp_dir,
            "timeout": 1,
        })
        result = json.loads(result_json)
        assert "error" in result or "blocked" in result


class TestRequestCounting:
    """Test that request and block counters work."""

    @pytest.mark.skipif(not MCP_AVAILABLE, reason="MCP SDK not installed")
    def test_initial_counts(self):
        """Test initial counters are zero."""
        from tweek.mcp.server import TweekMCPServer
        server = TweekMCPServer()
        assert server._request_count == 0
        assert server._blocked_count == 0
