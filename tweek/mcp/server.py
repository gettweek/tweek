#!/usr/bin/env python3
"""
Tweek MCP Gateway Server

Minimal MCP server exposing only tools that add genuinely new capabilities
not available as built-in desktop client tools:
- tweek_vault: Secure keychain credential retrieval
- tweek_status: Security status and activity reporting

Desktop clients' built-in tools (Bash, Read, Write, etc.) cannot be
intercepted via MCP. For upstream MCP server interception, use the
proxy mode: tweek mcp proxy

Usage:
    tweek mcp serve       # stdio mode (desktop clients)
"""

import json
import logging
import os
from typing import Any, Dict, Optional

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import (
        TextContent,
        Tool,
    )
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

from tweek.screening.context import ScreeningContext

logger = logging.getLogger(__name__)

# Version for MCP server identification
MCP_SERVER_VERSION = "0.2.0"


def _check_mcp_available():
    """Raise RuntimeError if MCP SDK is not installed."""
    if not MCP_AVAILABLE:
        raise RuntimeError(
            "MCP SDK not installed. Install with: pip install 'tweek[mcp]' "
            "or pip install mcp"
        )


class TweekMCPServer:
    """
    Tweek MCP Gateway.

    Exposes vault and status tools via MCP. These are genuinely new
    capabilities not available as built-in desktop client tools.

    For intercepting upstream MCP server tool calls, use TweekMCPProxy
    from tweek.mcp.proxy instead.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        _check_mcp_available()
        self.config = config or {}
        self.server = Server("tweek-security")
        self._setup_handlers()
        self._request_count = 0
        self._blocked_count = 0

    def _setup_handlers(self):
        """Register MCP protocol handlers."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """Return the list of tools this server provides."""
            tools = []

            tool_configs = self.config.get("mcp", {}).get("gateway", {}).get("tools", {})

            if tool_configs.get("vault", True):
                tools.append(Tool(
                    name="tweek_vault",
                    description=(
                        "Retrieve a credential from Tweek's secure vault. "
                        "Credentials are stored in the system keychain, not in .env files. "
                        "Use this instead of reading .env files or hardcoding secrets."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "skill": {
                                "type": "string",
                                "description": "Skill namespace for the credential",
                            },
                            "key": {
                                "type": "string",
                                "description": "Credential key name",
                            },
                        },
                        "required": ["skill", "key"],
                    },
                ))

            if tool_configs.get("status", True):
                tools.append(Tool(
                    name="tweek_status",
                    description=(
                        "Show Tweek security status including active plugins, "
                        "recent activity, threat summary, and proxy statistics."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "detail": {
                                "type": "string",
                                "enum": ["summary", "plugins", "activity", "threats"],
                                "description": "Level of detail (default: summary)",
                            },
                        },
                    },
                ))

            return tools

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict) -> list[TextContent]:
            """Handle tool calls."""
            self._request_count += 1

            handler_map = {
                "tweek_vault": self._handle_vault,
                "tweek_status": self._handle_status,
            }

            handler = handler_map.get(name)
            if handler is None:
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "error": f"Unknown tool: {name}",
                        "available_tools": list(handler_map.keys()),
                    }),
                )]

            try:
                result = await handler(arguments)
                return [TextContent(type="text", text=result)]
            except Exception as e:
                logger.error(f"Tool {name} failed: {e}")
                return [TextContent(
                    type="text",
                    text=json.dumps({"error": str(e), "tool": name}),
                )]

    def _build_context(
        self,
        tool_name: str,
        content: str,
        tool_input: Optional[Dict[str, Any]] = None,
    ) -> ScreeningContext:
        """Build a ScreeningContext for MCP tool calls."""
        return ScreeningContext(
            tool_name=tool_name,
            content=content,
            tier="default",
            working_dir=os.getcwd(),
            source="mcp",
            client_name=self.config.get("client_name"),
            tool_input=tool_input,
        )

    def _run_screening(self, context: ScreeningContext) -> Dict[str, Any]:
        """
        Run the shared screening pipeline.

        In gateway mode, should_prompt is converted to blocked
        since there is no interactive user to confirm.
        """
        from tweek.mcp.screening import run_mcp_screening

        result = run_mcp_screening(context)

        if result.get("should_prompt"):
            self._blocked_count += 1
            return {
                "allowed": False,
                "blocked": True,
                "reason": f"Requires user confirmation: {result.get('reason', '')}",
                "findings": result.get("findings", []),
            }

        if result.get("blocked"):
            self._blocked_count += 1

        return {
            "allowed": result.get("allowed", False),
            "blocked": result.get("blocked", False),
            "reason": result.get("reason"),
            "findings": result.get("findings", []),
        }

    async def _handle_vault(self, arguments: Dict[str, Any]) -> str:
        """Handle tweek_vault tool call."""
        skill = arguments.get("skill", "")
        key = arguments.get("key", "")

        # Screen vault access
        context = self._build_context("Vault", f"vault:{skill}/{key}", arguments)
        screening = self._run_screening(context)

        if screening["blocked"]:
            return json.dumps({
                "blocked": True,
                "reason": screening["reason"],
            })

        try:
            from tweek.vault.cross_platform import CrossPlatformVault

            vault = CrossPlatformVault()
            value = vault.get(skill, key)

            if value is None:
                return json.dumps({
                    "error": f"Credential not found: {skill}/{key}",
                    "available": False,
                })

            return json.dumps({
                "value": value,
                "skill": skill,
                "key": key,
            })

        except Exception as e:
            # Don't leak internal details across trust boundary
            logger.error(f"Vault operation failed: {e}")
            return json.dumps({"error": "Vault operation failed"})

    async def _handle_status(self, arguments: Dict[str, Any]) -> str:
        """Handle tweek_status tool call."""
        detail = arguments.get("detail", "summary")

        try:
            status = {
                "version": MCP_SERVER_VERSION,
                "source": "mcp",
                "mode": "gateway",
                "gateway_requests": self._request_count,
                "gateway_blocked": self._blocked_count,
            }

            if detail in ("summary", "plugins"):
                try:
                    from tweek.plugins import get_registry
                    registry = get_registry()
                    stats = registry.get_stats()
                    status["plugins"] = stats
                except ImportError:
                    status["plugins"] = {"error": "Plugin system not available"}

            if detail in ("summary", "activity"):
                try:
                    from tweek.logging.security_log import get_logger as get_sec_logger
                    sec_logger = get_sec_logger()
                    recent = sec_logger.get_recent(limit=10)
                    status["recent_activity"] = [
                        {
                            "timestamp": str(e.timestamp),
                            "event_type": e.event_type.value,
                            "tool": e.tool_name,
                            "decision": e.decision,
                        }
                        for e in recent
                    ] if recent else []
                except (ImportError, Exception):
                    status["recent_activity"] = []

            # Include approval queue stats if available
            try:
                from tweek.mcp.approval import ApprovalQueue
                queue = ApprovalQueue()
                status["approval_queue"] = queue.get_stats()
            except Exception:
                pass

            return json.dumps(status, indent=2)

        except Exception as e:
            return json.dumps({"error": str(e)})


async def run_server(config: Optional[Dict[str, Any]] = None):
    """
    Run the Tweek MCP gateway server on stdio transport.

    Exposes tweek_vault and tweek_status tools. For upstream MCP
    server interception, use run_proxy() instead.
    """
    _check_mcp_available()

    server = TweekMCPServer(config=config)

    logger.info("Starting Tweek MCP Gateway...")
    logger.info(f"Version: {MCP_SERVER_VERSION}")
    logger.info("Tools: tweek_vault, tweek_status")
    logger.info("For upstream MCP interception, use: tweek mcp proxy")

    async with stdio_server() as (read_stream, write_stream):
        await server.server.run(
            read_stream,
            write_stream,
            server.server.create_initialization_options(),
        )


def create_server(config: Optional[Dict[str, Any]] = None) -> "TweekMCPServer":
    """Create a TweekMCPServer instance for programmatic use."""
    return TweekMCPServer(config=config)
