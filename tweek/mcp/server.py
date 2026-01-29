#!/usr/bin/env python3
"""
Tweek MCP Security Gateway Server

A Model Context Protocol server that exposes security-screened tools.
Desktop LLM clients connect to this server via stdio transport and
get Tweek's full screening pipeline on every tool call.

Usage:
    tweek mcp serve       # stdio mode (desktop clients)
    tweek mcp start       # background daemon mode
"""

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
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
MCP_SERVER_VERSION = "0.1.0"


def _check_mcp_available():
    """Raise RuntimeError if MCP SDK is not installed."""
    if not MCP_AVAILABLE:
        raise RuntimeError(
            "MCP SDK not installed. Install with: pip install 'tweek[mcp]' "
            "or pip install mcp"
        )


class TweekMCPServer:
    """
    Tweek MCP Security Gateway.

    Exposes security-screened tools via the Model Context Protocol.
    Each tool call runs through the full Tweek screening pipeline
    before execution.
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

            if tool_configs.get("bash", True):
                tools.append(Tool(
                    name="tweek_bash",
                    description=(
                        "Execute a shell command with Tweek security screening. "
                        "Commands are scanned for injection, exfiltration, and "
                        "malicious patterns before execution. Sandboxed by default."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "The shell command to execute",
                            },
                            "working_dir": {
                                "type": "string",
                                "description": "Working directory for execution",
                            },
                            "timeout": {
                                "type": "integer",
                                "description": "Timeout in seconds (default: 120)",
                            },
                        },
                        "required": ["command"],
                    },
                ))

            if tool_configs.get("read", True):
                tools.append(Tool(
                    name="tweek_read",
                    description=(
                        "Read a file with Tweek security scanning. Prevents access "
                        "to sensitive files (.env, credentials, keys) unless authorized."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Absolute path to the file to read",
                            },
                        },
                        "required": ["path"],
                    },
                ))

            if tool_configs.get("write", True):
                tools.append(Tool(
                    name="tweek_write",
                    description=(
                        "Write content to a file with Tweek security screening. "
                        "Prevents writing malicious content or overwriting critical files."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "Absolute path to write",
                            },
                            "content": {
                                "type": "string",
                                "description": "Content to write to the file",
                            },
                        },
                        "required": ["path", "content"],
                    },
                ))

            if tool_configs.get("web", True):
                tools.append(Tool(
                    name="tweek_web",
                    description=(
                        "Fetch a URL with Tweek security screening. Validates URLs "
                        "against blocklists, scans responses for injection attempts."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "url": {
                                "type": "string",
                                "description": "URL to fetch",
                            },
                            "method": {
                                "type": "string",
                                "enum": ["GET", "POST"],
                                "description": "HTTP method (default: GET)",
                            },
                        },
                        "required": ["url"],
                    },
                ))

            if tool_configs.get("vault", True):
                tools.append(Tool(
                    name="tweek_vault",
                    description=(
                        "Retrieve a credential from Tweek's secure vault. "
                        "Credentials are stored in the system keychain, not in .env files."
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
                        "recent activity, and threat summary."
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
            """Handle tool calls with security screening."""
            self._request_count += 1

            handler_map = {
                "tweek_bash": self._handle_bash,
                "tweek_read": self._handle_read,
                "tweek_write": self._handle_write,
                "tweek_web": self._handle_web,
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
            tier="default",  # Will be resolved by screening pipeline
            working_dir=os.getcwd(),
            source="mcp",
            client_name=self.config.get("client_name"),
            tool_input=tool_input,
        )

    def _run_screening(self, context: ScreeningContext) -> Dict[str, Any]:
        """
        Run the shared screening pipeline.

        Delegates to the shared screening module and converts
        should_prompt -> blocked (in gateway mode, there is no
        interactive user to ask).

        Returns dict with:
            allowed: bool
            blocked: bool
            reason: Optional[str]
            findings: List[Dict]
        """
        from tweek.mcp.screening import run_mcp_screening

        result = run_mcp_screening(context)

        # In MCP gateway mode, convert should_prompt -> blocked
        # (no interactive user available to confirm)
        if result.get("should_prompt"):
            self._blocked_count += 1
            return {
                "allowed": False,
                "blocked": True,
                "reason": f"Requires user confirmation: {result.get('reason', '')}",
                "findings": result.get("findings", []),
            }

        # Track blocked count for statistics
        if result.get("blocked"):
            self._blocked_count += 1

        return {
            "allowed": result.get("allowed", False),
            "blocked": result.get("blocked", False),
            "reason": result.get("reason"),
            "findings": result.get("findings", []),
        }

    async def _handle_bash(self, arguments: Dict[str, Any]) -> str:
        """Handle tweek_bash tool call."""
        command = arguments.get("command", "")
        working_dir = arguments.get("working_dir", os.getcwd())
        timeout = arguments.get("timeout", 120)

        # Screen the command
        context = self._build_context("Bash", command, arguments)
        context.working_dir = working_dir
        screening = self._run_screening(context)

        if screening["blocked"]:
            return json.dumps({
                "blocked": True,
                "reason": screening["reason"],
                "findings": screening.get("findings", []),
            })

        # Execute the command
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=working_dir,
            )

            output = result.stdout
            if result.stderr:
                output += f"\n[stderr]\n{result.stderr}"

            # Scan output for leaked credentials
            output_screening = self._run_output_scan(output)
            if output_screening.get("blocked"):
                return json.dumps({
                    "blocked": True,
                    "reason": f"Output contained sensitive data: {output_screening['reason']}",
                    "return_code": result.returncode,
                })

            return json.dumps({
                "output": output,
                "return_code": result.returncode,
            })

        except subprocess.TimeoutExpired:
            return json.dumps({
                "error": f"Command timed out after {timeout}s",
                "command": command,
            })
        except Exception as e:
            return json.dumps({"error": str(e)})

    async def _handle_read(self, arguments: Dict[str, Any]) -> str:
        """Handle tweek_read tool call."""
        path = arguments.get("path", "")

        # Screen the path
        context = self._build_context("Read", path, arguments)
        screening = self._run_screening(context)

        if screening["blocked"]:
            return json.dumps({
                "blocked": True,
                "reason": screening["reason"],
            })

        # Check for sensitive file patterns
        sensitive_patterns = [
            ".env", ".env.local", ".env.production",
            "credentials", "secrets", ".ssh/",
            "id_rsa", "id_ed25519", ".aws/credentials",
            ".gcloud/", "keychain",
        ]
        path_lower = path.lower()
        for pattern in sensitive_patterns:
            if pattern in path_lower:
                return json.dumps({
                    "blocked": True,
                    "reason": f"Access to sensitive file blocked: {pattern}",
                    "path": path,
                })

        # Read the file
        try:
            file_path = Path(path)
            if not file_path.exists():
                return json.dumps({"error": f"File not found: {path}"})

            if not file_path.is_file():
                return json.dumps({"error": f"Not a file: {path}"})

            # Size limit: 10MB
            if file_path.stat().st_size > 10 * 1024 * 1024:
                return json.dumps({"error": f"File too large (>10MB): {path}"})

            content = file_path.read_text(errors="replace")

            # Scan content for credentials
            output_screening = self._run_output_scan(content)
            if output_screening.get("blocked"):
                return json.dumps({
                    "blocked": True,
                    "reason": f"File contains sensitive data: {output_screening['reason']}",
                    "path": path,
                })

            return json.dumps({
                "content": content,
                "path": path,
                "size": len(content),
            })

        except PermissionError:
            return json.dumps({"error": f"Permission denied: {path}"})
        except Exception as e:
            return json.dumps({"error": str(e)})

    async def _handle_write(self, arguments: Dict[str, Any]) -> str:
        """Handle tweek_write tool call."""
        path = arguments.get("path", "")
        content = arguments.get("content", "")

        # Screen both path and content
        screen_text = f"Write to {path}:\n{content}"
        context = self._build_context("Write", screen_text, arguments)
        screening = self._run_screening(context)

        if screening["blocked"]:
            return json.dumps({
                "blocked": True,
                "reason": screening["reason"],
            })

        # Block writing to critical paths
        critical_paths = [
            "/etc/", "/usr/", "/bin/", "/sbin/",
            "/System/", "/Library/LaunchDaemons/",
            ".ssh/authorized_keys", ".bashrc", ".zshrc",
            ".profile", ".bash_profile",
        ]
        for critical in critical_paths:
            if path.startswith(critical) or path.endswith(critical.lstrip("/")):
                return json.dumps({
                    "blocked": True,
                    "reason": f"Writing to critical path blocked: {critical}",
                    "path": path,
                })

        try:
            file_path = Path(path)
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content)

            return json.dumps({
                "success": True,
                "path": path,
                "bytes_written": len(content),
            })

        except PermissionError:
            return json.dumps({"error": f"Permission denied: {path}"})
        except Exception as e:
            return json.dumps({"error": str(e)})

    async def _handle_web(self, arguments: Dict[str, Any]) -> str:
        """Handle tweek_web tool call."""
        url = arguments.get("url", "")
        method = arguments.get("method", "GET")

        # Screen the URL
        context = self._build_context("WebFetch", url, arguments)
        screening = self._run_screening(context)

        if screening["blocked"]:
            return json.dumps({
                "blocked": True,
                "reason": screening["reason"],
            })

        try:
            import urllib.request
            import urllib.error

            req = urllib.request.Request(url, method=method)
            req.add_header("User-Agent", f"Tweek-MCP/{MCP_SERVER_VERSION}")

            with urllib.request.urlopen(req, timeout=30) as response:
                content = response.read().decode("utf-8", errors="replace")

                # Truncate large responses
                if len(content) > 100_000:
                    content = content[:100_000] + "\n... [truncated]"

                # Scan response for injection attempts
                output_screening = self._run_output_scan(content)
                if output_screening.get("blocked"):
                    return json.dumps({
                        "blocked": True,
                        "reason": f"Response blocked: {output_screening['reason']}",
                        "url": url,
                    })

                return json.dumps({
                    "content": content,
                    "url": url,
                    "status": response.status,
                    "content_type": response.headers.get("Content-Type", "unknown"),
                })

        except urllib.error.URLError as e:
            return json.dumps({"error": f"URL error: {e}", "url": url})
        except Exception as e:
            return json.dumps({"error": str(e), "url": url})

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
            return json.dumps({"error": str(e)})

    async def _handle_status(self, arguments: Dict[str, Any]) -> str:
        """Handle tweek_status tool call."""
        detail = arguments.get("detail", "summary")

        try:
            status = {
                "version": MCP_SERVER_VERSION,
                "source": "mcp",
                "requests": self._request_count,
                "blocked": self._blocked_count,
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

            return json.dumps(status, indent=2)

        except Exception as e:
            return json.dumps({"error": str(e)})

    def _run_output_scan(self, content: str) -> Dict[str, Any]:
        """
        Scan output content for leaked credentials or sensitive data.

        Returns dict with blocked: bool and reason if blocked.
        """
        from tweek.mcp.screening import run_output_scan
        return run_output_scan(content)


async def run_server(config: Optional[Dict[str, Any]] = None):
    """
    Run the Tweek MCP server on stdio transport.

    This is the main entry point for 'tweek mcp serve'.
    """
    _check_mcp_available()

    server = TweekMCPServer(config=config)

    logger.info("Starting Tweek MCP Security Gateway...")
    logger.info(f"Version: {MCP_SERVER_VERSION}")

    async with stdio_server() as (read_stream, write_stream):
        await server.server.run(
            read_stream,
            write_stream,
            server.server.create_initialization_options(),
        )


def create_server(config: Optional[Dict[str, Any]] = None) -> "TweekMCPServer":
    """Create a TweekMCPServer instance for programmatic use."""
    return TweekMCPServer(config=config)
