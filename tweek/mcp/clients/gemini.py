#!/usr/bin/env python3
"""
Gemini CLI MCP Client Configuration

Gemini CLI supports MCP servers via ~/.gemini/settings.json.
"""

import json
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional


class GeminiClient:
    """Manage Tweek MCP integration with Gemini CLI."""

    CLIENT_NAME = "gemini"
    DISPLAY_NAME = "Gemini CLI"
    SERVER_KEY = "tweek-security"

    def _get_config_path(self) -> Path:
        """Get Gemini CLI settings path."""
        return Path.home() / ".gemini" / "settings.json"

    def _get_tweek_command(self) -> str:
        """Get the path to the tweek executable."""
        tweek_path = shutil.which("tweek")
        if tweek_path:
            return tweek_path
        return sys.executable

    def _get_tweek_args(self) -> list:
        """Get the arguments for the tweek MCP server."""
        tweek_path = shutil.which("tweek")
        if tweek_path:
            return ["mcp", "serve"]
        return ["-m", "tweek.mcp", "serve"]

    def _build_server_config(self) -> Dict[str, Any]:
        """Build the MCP server configuration entry."""
        return {
            "command": self._get_tweek_command(),
            "args": self._get_tweek_args(),
        }

    def _backup_config(self, config_path: Path) -> Optional[Path]:
        """Create a timestamped backup of the config file."""
        if not config_path.exists():
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = config_path.with_suffix(f".backup_{timestamp}.json")
        shutil.copy2(config_path, backup_path)
        return backup_path

    def install(self) -> Dict[str, Any]:
        """
        Install Tweek MCP server into Gemini CLI settings.

        Merges with existing config, preserving other MCP servers.
        """
        config_path = self._get_config_path()

        # Load existing config
        existing = {}
        if config_path.exists():
            try:
                existing = json.loads(config_path.read_text())
            except json.JSONDecodeError:
                return {
                    "success": False,
                    "error": f"Invalid JSON in {config_path}. Fix manually or delete to reset.",
                }

        # Backup
        backup = self._backup_config(config_path)

        # Merge Tweek into mcpServers
        existing.setdefault("mcpServers", {})
        existing["mcpServers"][self.SERVER_KEY] = self._build_server_config()

        # Write config
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(existing, indent=2))

        result = {
            "success": True,
            "client": self.DISPLAY_NAME,
            "config_path": str(config_path),
            "server_key": self.SERVER_KEY,
            "message": (
                f"Tweek MCP server installed for {self.DISPLAY_NAME}. "
                f"Restart Gemini CLI to activate."
            ),
        }
        if backup:
            result["backup"] = str(backup)

        return result

    def uninstall(self) -> Dict[str, Any]:
        """Remove Tweek MCP server from Gemini CLI settings."""
        config_path = self._get_config_path()

        if not config_path.exists():
            return {
                "success": True,
                "message": f"No config file found at {config_path}. Nothing to remove.",
            }

        try:
            config = json.loads(config_path.read_text())
        except json.JSONDecodeError:
            return {
                "success": False,
                "error": f"Invalid JSON in {config_path}",
            }

        servers = config.get("mcpServers", {})
        if self.SERVER_KEY not in servers:
            return {
                "success": True,
                "message": f"Tweek not found in {self.DISPLAY_NAME} config. Nothing to remove.",
            }

        # Backup and remove
        backup = self._backup_config(config_path)
        del servers[self.SERVER_KEY]

        config_path.write_text(json.dumps(config, indent=2))

        result = {
            "success": True,
            "client": self.DISPLAY_NAME,
            "config_path": str(config_path),
            "message": (
                f"Tweek MCP server removed from {self.DISPLAY_NAME}. "
                f"Restart Gemini CLI to apply."
            ),
        }
        if backup:
            result["backup"] = str(backup)

        return result

    def status(self) -> Dict[str, Any]:
        """Check if Tweek is installed in Gemini CLI."""
        config_path = self._get_config_path()

        if not config_path.exists():
            return {
                "installed": False,
                "client": self.DISPLAY_NAME,
                "config_path": str(config_path),
                "message": "Gemini CLI settings not found",
            }

        try:
            config = json.loads(config_path.read_text())
            servers = config.get("mcpServers", {})
            installed = self.SERVER_KEY in servers

            return {
                "installed": installed,
                "client": self.DISPLAY_NAME,
                "config_path": str(config_path),
                "server_config": servers.get(self.SERVER_KEY) if installed else None,
                "other_servers": [k for k in servers if k != self.SERVER_KEY],
            }

        except json.JSONDecodeError:
            return {
                "installed": False,
                "error": "Invalid JSON in settings file",
                "config_path": str(config_path),
            }
