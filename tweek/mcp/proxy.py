#!/usr/bin/env python3
"""
Tweek MCP Proxy Server

Transparent MCP proxy that sits between LLM clients and upstream MCP servers.
All tool calls are screened through Tweek's defense-in-depth pipeline.
Flagged calls are queued for human approval via a separate CLI daemon.

Architecture:
    LLM Client  <--stdio-->  TweekMCPProxy  <--stdio-->  Upstream MCP Server(s)

Usage:
    tweek mcp proxy       # Start proxy on stdio transport
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import uuid
from contextlib import AsyncExitStack
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Version for MCP server identification
MCP_SERVER_VERSION = "0.2.0"

try:
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import TextContent, Tool
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

from tweek.screening.context import ScreeningContext


# Separator for namespaced tool names: {upstream}__{tool}
NAMESPACE_SEPARATOR = "__"

# Default timeout for upstream tool calls (seconds)
UPSTREAM_CALL_TIMEOUT = 120

# Polling interval for approval decisions (seconds)
APPROVAL_POLL_INTERVAL = 1.0

# Background expiry loop interval (seconds)
EXPIRY_LOOP_INTERVAL = 30


def _check_mcp_available():
    """Raise RuntimeError if MCP SDK is not installed."""
    if not MCP_AVAILABLE:
        raise RuntimeError(
            "MCP SDK not installed. Install with: pip install 'tweek[mcp]' "
            "or pip install mcp"
        )


class UpstreamConnection:
    """
    Manages a single connection to an upstream MCP server.

    Connects via stdio transport, discovers available tools,
    and forwards tool calls.
    """

    def __init__(self, name: str, server_params: StdioServerParameters):
        self.name = name
        self.server_params = server_params
        self.session: Optional[ClientSession] = None
        self.tools: List[Tool] = []
        self.connected: bool = False

    async def connect(self, exit_stack: AsyncExitStack) -> None:
        """
        Connect to the upstream server and discover its tools.

        Uses the provided AsyncExitStack to keep the stdio transport alive
        for the lifetime of the proxy.
        """
        try:
            read_stream, write_stream = await exit_stack.enter_async_context(
                stdio_client(self.server_params)
            )
            self.session = ClientSession(read_stream, write_stream)
            init_result = await self.session.initialize()
            tools_result = await self.session.list_tools()
            self.tools = tools_result.tools
            self.connected = True

            logger.info(
                f"Connected to upstream '{self.name}': "
                f"{len(self.tools)} tool(s) available"
            )
        except Exception as e:
            logger.error(f"Failed to connect to upstream '{self.name}': {e}")
            self.connected = False
            self.tools = []

    async def call_tool(
        self,
        name: str,
        arguments: Optional[Dict[str, Any]] = None,
        timeout: float = UPSTREAM_CALL_TIMEOUT,
    ) -> Dict[str, Any]:
        """
        Forward a tool call to the upstream server.

        Returns dict with:
            content: List of content items (text/image/etc.)
            isError: Whether the call resulted in an error
        """
        if not self.connected or self.session is None:
            return {
                "content": [{"type": "text", "text": json.dumps({
                    "error": f"Upstream server '{self.name}' is not connected",
                })}],
                "isError": True,
            }

        try:
            result = await self.session.call_tool(
                name=name,
                arguments=arguments,
                read_timeout_seconds=timedelta(seconds=timeout),
            )
            # Convert CallToolResult to serializable dict
            content_list = []
            for item in result.content:
                if hasattr(item, "text"):
                    content_list.append({"type": "text", "text": item.text})
                elif hasattr(item, "data"):
                    content_list.append({
                        "type": getattr(item, "type", "unknown"),
                        "data": item.data,
                    })
                else:
                    content_list.append({"type": "text", "text": str(item)})

            return {
                "content": content_list,
                "isError": getattr(result, "isError", False),
            }

        except Exception as e:
            logger.error(f"Tool call to '{self.name}/{name}' failed: {e}")
            return {
                "content": [{"type": "text", "text": json.dumps({
                    "error": f"Upstream call failed: {e}",
                    "server": self.name,
                    "tool": name,
                })}],
                "isError": True,
            }


class TweekMCPProxy:
    """
    MCP Proxy with security screening and human-in-the-loop approval.

    Presents merged tools from upstream MCP servers to the downstream
    LLM client. All tool calls pass through Tweek's screening pipeline.
    Flagged calls are queued for human approval.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        _check_mcp_available()
        self.config = config or {}
        self.server = Server("tweek-proxy")
        self._exit_stack = AsyncExitStack()
        self.upstreams: Dict[str, UpstreamConnection] = {}
        self._tool_registry: Dict[str, str] = {}  # namespaced_name -> upstream_name
        self._request_count = 0
        self._blocked_count = 0
        self._approval_count = 0
        self._approval_queue = None
        self._expiry_task = None
        self._setup_handlers()

    def _get_approval_queue(self):
        """Lazy-initialize the approval queue."""
        if self._approval_queue is None:
            from tweek.mcp.approval import ApprovalQueue
            proxy_config = self.config.get("mcp", {}).get("proxy", {})
            timeout = proxy_config.get("approval_timeout", 300)
            self._approval_queue = ApprovalQueue(default_timeout=timeout)
        return self._approval_queue

    def _get_proxy_config(self) -> Dict[str, Any]:
        """Get proxy-specific config."""
        return self.config.get("mcp", {}).get("proxy", {})

    def _build_upstreams(self) -> Dict[str, UpstreamConnection]:
        """Build upstream connections from config."""
        proxy_config = self._get_proxy_config()
        upstreams_config = proxy_config.get("upstreams", {})
        connections = {}

        for name, server_config in upstreams_config.items():
            command = server_config.get("command", "")
            args = server_config.get("args", [])
            env_config = server_config.get("env") or None
            cwd = server_config.get("cwd")

            # Expand environment variables in env dict
            if env_config:
                expanded_env = {}
                for key, value in env_config.items():
                    if isinstance(value, str):
                        expanded_env[key] = os.path.expandvars(value)
                    else:
                        expanded_env[key] = value
                env_config = expanded_env

            params = StdioServerParameters(
                command=command,
                args=args,
                env=env_config,
                cwd=cwd,
            )
            connections[name] = UpstreamConnection(name=name, server_params=params)

        return connections

    def _namespace_tool(self, upstream_name: str, tool: Tool) -> Tool:
        """Create a namespaced copy of a tool for the merged tool list."""
        namespaced_name = f"{upstream_name}{NAMESPACE_SEPARATOR}{tool.name}"
        description = tool.description or ""
        namespaced_desc = f"[{upstream_name}] {description}"

        return Tool(
            name=namespaced_name,
            description=namespaced_desc,
            inputSchema=tool.inputSchema,
        )

    def _resolve_tool(self, namespaced_name: str) -> Tuple[str, str]:
        """
        Resolve a namespaced tool name to (upstream_name, original_tool_name).

        Raises ValueError if the tool name is not in the registry.
        """
        if NAMESPACE_SEPARATOR not in namespaced_name:
            raise ValueError(f"Tool '{namespaced_name}' is not namespaced")

        upstream_name = self._tool_registry.get(namespaced_name)
        if upstream_name is None:
            raise ValueError(f"Unknown tool: {namespaced_name}")

        # Extract original name by removing the prefix
        prefix = f"{upstream_name}{NAMESPACE_SEPARATOR}"
        original_name = namespaced_name[len(prefix):]
        return upstream_name, original_name

    def _setup_handlers(self):
        """Register MCP protocol handlers for the proxy server."""

        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """Return built-in tools plus merged tools from all connected upstreams."""
            merged = []

            # Built-in tools (vault + status)
            tool_configs = self.config.get("mcp", {}).get("proxy", {}).get("tools", {})

            if tool_configs.get("vault", True):
                merged.append(Tool(
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
                merged.append(Tool(
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

            # Upstream tools
            for upstream_name, upstream in self.upstreams.items():
                if not upstream.connected:
                    continue
                for tool in upstream.tools:
                    namespaced = self._namespace_tool(upstream_name, tool)
                    merged.append(namespaced)
                    self._tool_registry[namespaced.name] = upstream_name
            return merged

        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict) -> list[TextContent]:
            """Handle tool calls with security screening and approval."""
            self._request_count += 1

            # Handle built-in tools (vault, status)
            builtin_handlers = {
                "tweek_vault": self._handle_vault,
                "tweek_status": self._handle_status,
            }
            handler = builtin_handlers.get(name)
            if handler is not None:
                try:
                    result = await handler(arguments)
                    return [TextContent(type="text", text=result)]
                except Exception as e:
                    logger.error(f"Tool {name} failed: {e}")
                    return [TextContent(
                        type="text",
                        text=json.dumps({"error": str(e), "tool": name}),
                    )]

            return await self._handle_call_tool(name, arguments)

    async def _handle_call_tool(
        self, name: str, arguments: dict
    ) -> list[TextContent]:
        """Screen and forward a tool call."""
        # Generate correlation ID for this screening pass
        correlation_id = uuid.uuid4().hex[:12]

        # Resolve upstream and original tool name
        try:
            upstream_name, original_name = self._resolve_tool(name)
        except ValueError as e:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": str(e),
                    "available_tools": list(self._tool_registry.keys()),
                }),
            )]

        upstream = self.upstreams.get(upstream_name)
        if upstream is None or not upstream.connected:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": f"Upstream '{upstream_name}' is not connected",
                }),
            )]

        # Build screening context
        content = self._extract_content_for_screening(original_name, arguments)
        context = self._build_context(
            tool_name=original_name,
            content=content,
            upstream_name=upstream_name,
            tool_input=arguments,
        )

        # Run screening
        result = self._run_screening(context)

        if result.get("blocked"):
            self._blocked_count += 1
            self._log_event("blocked", original_name, upstream_name, content, result,
                            metadata={"correlation_id": correlation_id}, correlation_id=correlation_id)
            return [TextContent(
                type="text",
                text=json.dumps({
                    "blocked": True,
                    "reason": result.get("reason", "Blocked by security screening"),
                    "server": upstream_name,
                    "tool": original_name,
                }),
            )]

        if result.get("should_prompt"):
            # Queue for human approval
            return await self._handle_approval_flow(
                upstream_name, original_name, arguments, content, result, correlation_id
            )

        # Allowed - forward to upstream
        self._log_event("allowed", original_name, upstream_name, content, result,
                        correlation_id=correlation_id)
        return await self._forward_and_return(upstream, original_name, arguments)

    async def _handle_approval_flow(
        self,
        upstream_name: str,
        tool_name: str,
        arguments: Dict[str, Any],
        content: str,
        screening_result: Dict[str, Any],
        correlation_id: Optional[str] = None,
    ) -> list[TextContent]:
        """Queue a tool call for human approval and wait for decision."""
        self._approval_count += 1
        queue = self._get_approval_queue()
        proxy_config = self._get_proxy_config()
        timeout = proxy_config.get("approval_timeout", 300)

        # Log the prompt
        self._log_event(
            "user_prompted", tool_name, upstream_name, content, screening_result,
            correlation_id=correlation_id,
        )

        # Enqueue
        request_id = queue.enqueue(
            upstream_server=upstream_name,
            tool_name=tool_name,
            arguments=arguments,
            screening_reason=screening_result.get("reason", "Needs confirmation"),
            screening_findings=screening_result.get("findings", []),
            risk_level=screening_result.get("tier", "unknown"),
            timeout_seconds=timeout,
        )

        logger.info(
            f"Approval queued [{request_id[:8]}]: "
            f"{upstream_name}/{tool_name} - {screening_result.get('reason', '')}"
        )

        # Wait for decision
        decision = await self._wait_for_approval(request_id, timeout)

        if decision == "approved":
            self._log_event(
                "user_approved", tool_name, upstream_name, content, screening_result,
                metadata={"request_id": request_id},
                correlation_id=correlation_id,
            )
            upstream = self.upstreams[upstream_name]
            return await self._forward_and_return(upstream, tool_name, arguments)
        else:
            reason = "Approval timed out" if decision == "expired" else "Denied by reviewer"
            self._log_event(
                "user_denied", tool_name, upstream_name, content, screening_result,
                metadata={"request_id": request_id, "reason": reason},
                correlation_id=correlation_id,
            )
            return [TextContent(
                type="text",
                text=json.dumps({
                    "blocked": True,
                    "reason": reason,
                    "server": upstream_name,
                    "tool": tool_name,
                    "request_id": request_id[:8],
                }),
            )]

    async def _wait_for_approval(
        self, request_id: str, timeout: float
    ) -> str:
        """
        Poll the approval queue until a decision is made or timeout.

        Returns: "approved", "denied", or "expired"
        """
        queue = self._get_approval_queue()
        elapsed = 0.0

        while elapsed < timeout:
            await asyncio.sleep(APPROVAL_POLL_INTERVAL)
            elapsed += APPROVAL_POLL_INTERVAL

            status = queue.get_decision(request_id)
            if status is None:
                # Request disappeared (shouldn't happen)
                return "denied"

            from tweek.mcp.approval import ApprovalStatus

            if status == ApprovalStatus.APPROVED:
                return "approved"
            elif status == ApprovalStatus.DENIED:
                return "denied"
            elif status == ApprovalStatus.EXPIRED:
                return "expired"
            # Still pending, continue polling

        # Timeout reached - expire the request
        queue.expire_stale()
        return "expired"

    async def _forward_and_return(
        self,
        upstream: UpstreamConnection,
        tool_name: str,
        arguments: Dict[str, Any],
    ) -> list[TextContent]:
        """Forward a tool call to upstream and return the result."""
        result = await upstream.call_tool(tool_name, arguments)
        content_list = result.get("content", [])

        text_contents = []
        for item in content_list:
            if item.get("type") == "text":
                text_contents.append(TextContent(type="text", text=item.get("text", "")))
            else:
                text_contents.append(
                    TextContent(type="text", text=json.dumps(item))
                )

        if not text_contents:
            text_contents = [TextContent(
                type="text",
                text=json.dumps({"result": "empty response from upstream"}),
            )]

        # Screen output for leaked credentials or sensitive data
        try:
            from tweek.mcp.screening import run_output_scan
            combined_text = "\n".join(tc.text for tc in text_contents)
            scan_result = run_output_scan(combined_text)
            if scan_result.get("blocked"):
                reason = scan_result.get("reason", "Output blocked by security screening")
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "error": "Output blocked by Tweek security screening",
                        "reason": reason,
                    }),
                )]
        except Exception:
            pass  # Output scanning errors should not block the response

        return text_contents

    def _build_context(
        self,
        tool_name: str,
        content: str,
        upstream_name: str,
        tool_input: Optional[Dict[str, Any]] = None,
    ) -> ScreeningContext:
        """Build a ScreeningContext for proxy tool calls."""
        proxy_config = self._get_proxy_config()
        overrides = proxy_config.get("screening_overrides", {})
        upstream_override = overrides.get(upstream_name, {})
        default_tier = upstream_override.get("tier", "default")

        return ScreeningContext(
            tool_name=tool_name,
            content=content,
            tier=default_tier,
            working_dir=os.getcwd(),
            source="mcp_proxy",
            client_name=self.config.get("client_name"),
            mcp_server=upstream_name,
            tool_input=tool_input,
        )

    def _run_screening(self, context: ScreeningContext) -> Dict[str, Any]:
        """Run the shared screening pipeline."""
        from tweek.mcp.screening import run_mcp_screening
        return run_mcp_screening(context)

    def _extract_content_for_screening(
        self, tool_name: str, arguments: Dict[str, Any]
    ) -> str:
        """Extract the primary content string from tool arguments for screening."""
        # Try common parameter names that represent the primary action
        for key in ("command", "query", "sql", "code", "content", "path", "url", "body"):
            if key in arguments:
                value = arguments[key]
                if isinstance(value, str):
                    return value

        # Fallback: serialize all arguments
        return json.dumps(arguments, default=str)

    def _log_event(
        self,
        event_type: str,
        tool_name: str,
        upstream_name: str,
        content: str,
        screening_result: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ):
        """Log a screening event to the security logger."""
        try:
            from tweek.logging.security_log import SecurityLogger, SecurityEvent, EventType, get_logger

            event_map = {
                "allowed": EventType.ALLOWED,
                "blocked": EventType.BLOCKED,
                "user_prompted": EventType.USER_PROMPTED,
                "user_approved": EventType.USER_APPROVED,
                "user_denied": EventType.USER_DENIED,
            }
            evt = event_map.get(event_type, EventType.TOOL_INVOKED)

            sec_logger = get_logger()
            event_metadata = {
                "upstream_server": upstream_name,
                "findings_count": len(screening_result.get("findings", [])),
            }
            if metadata:
                event_metadata.update(metadata)

            sec_logger.log(SecurityEvent(
                event_type=evt,
                tool_name=tool_name,
                command=content,
                tier=screening_result.get("tier"),
                decision=event_type,
                decision_reason=screening_result.get("reason"),
                metadata=event_metadata,
                correlation_id=correlation_id,
                source="mcp_proxy",
            ))
        except Exception as e:
            logger.debug(f"Failed to log security event: {e}")

    async def _handle_vault(self, arguments: Dict[str, Any]) -> str:
        """Handle tweek_vault tool call."""
        skill = arguments.get("skill", "")
        key = arguments.get("key", "")

        # Screen vault access
        context = self._build_context(
            tool_name="Vault",
            content=f"vault:{skill}/{key}",
            upstream_name="_builtin",
            tool_input=arguments,
        )
        screening = self._run_screening(context)

        if screening.get("blocked"):
            return json.dumps({
                "blocked": True,
                "reason": screening.get("reason"),
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
                "source": "mcp_proxy",
                "mode": "proxy",
                "proxy_requests": self._request_count,
                "proxy_blocked": self._blocked_count,
                "proxy_approvals": self._approval_count,
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
                queue = self._get_approval_queue()
                status["approval_queue"] = queue.get_stats()
            except Exception:
                pass

            return json.dumps(status, indent=2)

        except Exception as e:
            return json.dumps({"error": str(e)})

    async def start(self) -> None:
        """
        Start the proxy: connect to upstreams and serve on stdio.
        """
        # Build upstream connections from config
        self.upstreams = self._build_upstreams()

        if not self.upstreams:
            logger.warning(
                "No upstream servers configured. "
                "Add 'mcp.proxy.upstreams' to your config."
            )
            print(
                "Warning: No upstream MCP servers configured.\n"
                "Configure upstreams in ~/.tweek/config.yaml under mcp.proxy.upstreams",
                file=sys.stderr,
            )

        async with self._exit_stack:
            # Connect to all upstreams
            for name, upstream in self.upstreams.items():
                await upstream.connect(self._exit_stack)

            connected = sum(1 for u in self.upstreams.values() if u.connected)
            total_tools = sum(
                len(u.tools) for u in self.upstreams.values() if u.connected
            )
            logger.info(
                f"Proxy ready: {connected}/{len(self.upstreams)} upstreams, "
                f"{total_tools} tools available"
            )

            # Check if approval daemon is reachable
            try:
                queue = self._get_approval_queue()
                pending = queue.count_pending()
                if pending > 0:
                    print(
                        f"Note: {pending} pending approval request(s) in queue.",
                        file=sys.stderr,
                    )
            except Exception:
                pass

            print(
                f"Tweek MCP Proxy ready ({connected} upstream(s), {total_tools} tools)",
                file=sys.stderr,
            )

            # Start background expiry loop
            self._expiry_task = asyncio.create_task(self._run_expiry_loop())

            try:
                # Serve on stdio
                async with stdio_server() as (read_stream, write_stream):
                    await self.server.run(
                        read_stream,
                        write_stream,
                        self.server.create_initialization_options(),
                    )
            finally:
                # Clean up
                if self._expiry_task:
                    self._expiry_task.cancel()
                    try:
                        await self._expiry_task
                    except asyncio.CancelledError:
                        pass

                # Expire all pending requests on shutdown
                try:
                    queue = self._get_approval_queue()
                    expired = queue.expire_stale()
                    if expired:
                        logger.info(f"Expired {expired} pending requests on shutdown")
                except Exception:
                    pass

    async def _run_expiry_loop(self):
        """Background task to expire stale approval requests."""
        while True:
            try:
                await asyncio.sleep(EXPIRY_LOOP_INTERVAL)
                queue = self._get_approval_queue()
                queue.expire_stale()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Expiry loop error: {e}")


async def run_proxy(config: Optional[Dict[str, Any]] = None):
    """
    Run the Tweek MCP proxy on stdio transport.

    This is the main entry point for 'tweek mcp proxy'.
    """
    _check_mcp_available()
    proxy = TweekMCPProxy(config=config)
    await proxy.start()


def create_proxy(config: Optional[Dict[str, Any]] = None) -> "TweekMCPProxy":
    """Create a TweekMCPProxy instance for programmatic use."""
    return TweekMCPProxy(config=config)
