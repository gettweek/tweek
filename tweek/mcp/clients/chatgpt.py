#!/usr/bin/env python3
"""
ChatGPT Desktop MCP Client Configuration

ChatGPT Desktop supports MCP via Developer Mode.
Unlike Claude Desktop, ChatGPT requires manual Developer Mode activation,
so we provide guided instructions plus the config commands.
"""

import json
import shutil
import sys
from pathlib import Path
from typing import Dict, Any


class ChatGPTClient:
    """Manage Tweek MCP integration with ChatGPT Desktop."""

    CLIENT_NAME = "chatgpt"
    DISPLAY_NAME = "ChatGPT Desktop"

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

    def install(self) -> Dict[str, Any]:
        """
        Provide instructions for ChatGPT Desktop MCP setup.

        ChatGPT requires manual Developer Mode activation.
        """
        command = self._get_tweek_command()
        args = self._get_tweek_args()

        instructions = [
            "ChatGPT Desktop MCP Setup:",
            "",
            "1. Open ChatGPT Desktop",
            "2. Go to Settings -> Developer -> Advanced",
            "3. Enable Developer Mode",
            "4. Go to Connectors settings",
            "5. Click 'Add MCP Server'",
            "6. Configure with:",
            f"   - Name: Tweek Security",
            f"   - Command: {command}",
            f"   - Args: {' '.join(args)}",
            "",
            "After adding, restart ChatGPT Desktop to activate.",
        ]

        return {
            "success": True,
            "client": self.DISPLAY_NAME,
            "manual_setup_required": True,
            "command": command,
            "args": args,
            "instructions": instructions,
            "message": "ChatGPT requires manual Developer Mode activation. See instructions.",
        }

    def uninstall(self) -> Dict[str, Any]:
        """Provide instructions for removing Tweek from ChatGPT Desktop."""
        return {
            "success": True,
            "client": self.DISPLAY_NAME,
            "manual_removal_required": True,
            "instructions": [
                "To remove Tweek from ChatGPT Desktop:",
                "",
                "1. Open ChatGPT Desktop",
                "2. Go to Settings -> Developer -> Connectors",
                "3. Find 'Tweek Security' and remove it",
                "4. Restart ChatGPT Desktop",
            ],
            "message": "Follow instructions to remove Tweek from ChatGPT Desktop.",
        }

    def status(self) -> Dict[str, Any]:
        """
        Check ChatGPT Desktop MCP status.

        Since ChatGPT doesn't use a file-based config, we can only
        check if the app is installed.
        """
        # Check if ChatGPT Desktop is installed
        chatgpt_installed = False

        if sys.platform == "darwin":
            chatgpt_path = Path("/Applications/ChatGPT.app")
            chatgpt_installed = chatgpt_path.exists()
        elif sys.platform == "win32":
            # Windows store app or standard install
            chatgpt_installed = shutil.which("chatgpt") is not None

        return {
            "installed": None,  # Can't determine MCP status
            "client": self.DISPLAY_NAME,
            "app_installed": chatgpt_installed,
            "note": "Cannot detect MCP configuration status for ChatGPT Desktop. "
                    "Check Developer Mode -> Connectors manually.",
        }
