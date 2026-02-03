#!/usr/bin/env python3
"""Tests for MCP client auto-configuration."""

import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch

pytestmark = pytest.mark.mcp


class TestClaudeDesktopClient:
    """Test Claude Desktop client configuration."""

    def test_install_creates_config(self, tmp_path):
        """Test that install creates a new config file."""
        from tweek.mcp.clients.claude_desktop import ClaudeDesktopClient

        client = ClaudeDesktopClient()
        config_path = tmp_path / "claude_desktop_config.json"

        with patch.object(client, "_get_config_path", return_value=config_path):
            result = client.install()

        assert result["success"] is True
        assert config_path.exists()

        config = json.loads(config_path.read_text())
        assert "mcpServers" in config
        assert "tweek-security" in config["mcpServers"]
        assert "command" in config["mcpServers"]["tweek-security"]
        assert "args" in config["mcpServers"]["tweek-security"]

    def test_install_preserves_existing_servers(self, tmp_path):
        """Test that install preserves other MCP servers."""
        from tweek.mcp.clients.claude_desktop import ClaudeDesktopClient

        client = ClaudeDesktopClient()
        config_path = tmp_path / "claude_desktop_config.json"

        # Create existing config with another server
        existing = {
            "mcpServers": {
                "other-server": {
                    "command": "other",
                    "args": ["serve"],
                }
            }
        }
        config_path.write_text(json.dumps(existing))

        with patch.object(client, "_get_config_path", return_value=config_path):
            result = client.install()

        config = json.loads(config_path.read_text())
        assert "other-server" in config["mcpServers"]
        assert "tweek-security" in config["mcpServers"]

    def test_install_creates_backup(self, tmp_path):
        """Test that install backs up existing config."""
        from tweek.mcp.clients.claude_desktop import ClaudeDesktopClient

        client = ClaudeDesktopClient()
        config_path = tmp_path / "claude_desktop_config.json"
        config_path.write_text(json.dumps({"existing": True}))

        with patch.object(client, "_get_config_path", return_value=config_path):
            result = client.install()

        assert "backup" in result
        assert Path(result["backup"]).exists()

    def test_uninstall_removes_tweek(self, tmp_path):
        """Test that uninstall removes only Tweek server."""
        from tweek.mcp.clients.claude_desktop import ClaudeDesktopClient

        client = ClaudeDesktopClient()
        config_path = tmp_path / "claude_desktop_config.json"

        config = {
            "mcpServers": {
                "tweek-security": {"command": "tweek", "args": ["mcp", "proxy"]},
                "other-server": {"command": "other", "args": ["serve"]},
            }
        }
        config_path.write_text(json.dumps(config))

        with patch.object(client, "_get_config_path", return_value=config_path):
            result = client.uninstall()

        assert result["success"] is True

        updated = json.loads(config_path.read_text())
        assert "tweek-security" not in updated["mcpServers"]
        assert "other-server" in updated["mcpServers"]

    def test_uninstall_no_config(self, tmp_path):
        """Test uninstall when config doesn't exist."""
        from tweek.mcp.clients.claude_desktop import ClaudeDesktopClient

        client = ClaudeDesktopClient()
        config_path = tmp_path / "nonexistent_config.json"

        with patch.object(client, "_get_config_path", return_value=config_path):
            result = client.uninstall()

        assert result["success"] is True

    def test_status_installed(self, tmp_path):
        """Test status when Tweek is installed."""
        from tweek.mcp.clients.claude_desktop import ClaudeDesktopClient

        client = ClaudeDesktopClient()
        config_path = tmp_path / "claude_desktop_config.json"

        config = {
            "mcpServers": {
                "tweek-security": {"command": "tweek", "args": ["mcp", "proxy"]},
            }
        }
        config_path.write_text(json.dumps(config))

        with patch.object(client, "_get_config_path", return_value=config_path):
            result = client.status()

        assert result["installed"] is True

    def test_status_not_installed(self, tmp_path):
        """Test status when Tweek is not installed."""
        from tweek.mcp.clients.claude_desktop import ClaudeDesktopClient

        client = ClaudeDesktopClient()
        config_path = tmp_path / "claude_desktop_config.json"

        config = {"mcpServers": {"other": {"command": "other"}}}
        config_path.write_text(json.dumps(config))

        with patch.object(client, "_get_config_path", return_value=config_path):
            result = client.status()

        assert result["installed"] is False


class TestChatGPTClient:
    """Test ChatGPT Desktop client configuration."""

    def test_install_returns_instructions(self):
        """Test that install provides manual instructions."""
        from tweek.mcp.clients.chatgpt import ChatGPTClient

        client = ChatGPTClient()
        result = client.install()

        assert result["success"] is True
        assert result["manual_setup_required"] is True
        assert "instructions" in result
        assert len(result["instructions"]) > 0
        assert "command" in result
        assert "args" in result

    def test_uninstall_returns_instructions(self):
        """Test that uninstall provides manual removal instructions."""
        from tweek.mcp.clients.chatgpt import ChatGPTClient

        client = ChatGPTClient()
        result = client.uninstall()

        assert result["success"] is True
        assert result["manual_removal_required"] is True

    def test_status_returns_unknown(self):
        """Test that status returns unknown for MCP config."""
        from tweek.mcp.clients.chatgpt import ChatGPTClient

        client = ChatGPTClient()
        result = client.status()

        assert result["installed"] is None
        assert "note" in result


class TestGeminiClient:
    """Test Gemini CLI client configuration."""

    def test_install_creates_config(self, tmp_path):
        """Test that install creates settings.json."""
        from tweek.mcp.clients.gemini import GeminiClient

        client = GeminiClient()
        config_path = tmp_path / "settings.json"

        with patch.object(client, "_get_config_path", return_value=config_path):
            result = client.install()

        assert result["success"] is True
        assert config_path.exists()

        config = json.loads(config_path.read_text())
        assert "mcpServers" in config
        assert "tweek-security" in config["mcpServers"]

    def test_uninstall_removes_tweek(self, tmp_path):
        """Test that uninstall removes Tweek from Gemini settings."""
        from tweek.mcp.clients.gemini import GeminiClient

        client = GeminiClient()
        config_path = tmp_path / "settings.json"

        config = {
            "mcpServers": {
                "tweek-security": {"command": "tweek", "args": ["mcp", "proxy"]},
            }
        }
        config_path.write_text(json.dumps(config))

        with patch.object(client, "_get_config_path", return_value=config_path):
            result = client.uninstall()

        assert result["success"] is True
        updated = json.loads(config_path.read_text())
        assert "tweek-security" not in updated["mcpServers"]


class TestClientDiscovery:
    """Test the client discovery system."""

    def test_supported_clients(self):
        """Test that all expected clients are registered."""
        from tweek.mcp.clients import SUPPORTED_CLIENTS

        assert "claude-desktop" in SUPPORTED_CLIENTS
        assert "chatgpt" in SUPPORTED_CLIENTS
        assert "gemini" in SUPPORTED_CLIENTS

    def test_get_client_valid(self):
        """Test getting a valid client."""
        from tweek.mcp.clients import get_client

        client = get_client("claude-desktop")
        assert client is not None

    def test_get_client_invalid(self):
        """Test getting an invalid client raises error."""
        from tweek.mcp.clients import get_client

        with pytest.raises(ValueError, match="Unknown client"):
            get_client("unknown-client")
