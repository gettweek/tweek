"""MCP Gateway CLI commands extracted from tweek.cli.

Provides the ``mcp`` Click group with subcommands: serve, proxy, approve, decide.
"""

import asyncio

import click

from tweek.cli_helpers import console

# =============================================================================
# MCP GATEWAY COMMANDS
# =============================================================================


@click.group()
def mcp():
    """MCP Security Gateway for desktop LLM applications.

    Provides security-screened tools via the Model Context Protocol (MCP).
    Supports Claude Desktop, ChatGPT Desktop, and Gemini CLI.
    """
    pass


@mcp.command(
    epilog="""\b
Examples:
  tweek mcp serve                        Start MCP gateway on stdio transport
"""
)
def serve():
    """Start MCP gateway server (stdio transport).

    This is the command desktop clients call to launch the MCP server.
    Used as the 'command' in client MCP configurations.

    Example Claude Desktop config:
        {"mcpServers": {"tweek-security": {"command": "tweek", "args": ["mcp", "serve"]}}}
    """
    try:
        from tweek.mcp.server import run_server, MCP_AVAILABLE

        if not MCP_AVAILABLE:
            console.print("[red]MCP SDK not installed.[/red]")
            console.print("Install with: pip install 'tweek[mcp]' or pip install mcp")
            return

        # Load config
        try:
            from tweek.config.manager import ConfigManager
            cfg = ConfigManager()
            config = cfg.get_full_config()
        except Exception:
            config = {}

        asyncio.run(run_server(config=config))

    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(f"[red]MCP server error: {e}[/red]")


# =============================================================================
# MCP PROXY COMMANDS
# =============================================================================

@mcp.command("proxy",
    epilog="""\b
Examples:
  tweek mcp proxy                        Start MCP proxy on stdio transport
"""
)
def mcp_proxy():
    """Start MCP proxy server (stdio transport).

    Connects to upstream MCP servers configured in config.yaml,
    screens all tool calls through Tweek's security pipeline,
    and queues flagged operations for human approval.

    Configure upstreams in ~/.tweek/config.yaml:
        mcp:
          proxy:
            upstreams:
              filesystem:
                command: "npx"
                args: ["-y", "@modelcontextprotocol/server-filesystem", "/path"]

    Example Claude Desktop config:
        {"mcpServers": {"tweek-proxy": {"command": "tweek", "args": ["mcp", "proxy"]}}}
    """
    try:
        from tweek.mcp.proxy import run_proxy, MCP_AVAILABLE

        if not MCP_AVAILABLE:
            console.print("[red]MCP SDK not installed.[/red]")
            console.print("Install with: pip install 'tweek[mcp]' or pip install mcp")
            return

        # Load config
        try:
            from tweek.config.manager import ConfigManager
            cfg = ConfigManager()
            config = cfg.get_full_config()
        except Exception:
            config = {}

        asyncio.run(run_proxy(config=config))

    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(f"[red]MCP proxy error: {e}[/red]")


@mcp.command("approve",
    epilog="""\b
Examples:
  tweek mcp approve                      Start approval daemon (interactive)
  tweek mcp approve --list               List pending requests and exit
  tweek mcp approve -p 5                 Poll every 5 seconds
"""
)
@click.option("--poll-interval", "-p", default=2.0, type=float,
              help="Seconds between polls for new requests")
@click.option("--list", "list_pending", is_flag=True, help="List pending requests and exit")
def mcp_approve(poll_interval, list_pending):
    """Start the approval daemon for MCP proxy requests.

    Shows pending requests and allows approve/deny decisions.
    Press Ctrl+C to exit.

    Run this in a separate terminal while 'tweek mcp proxy' is serving.
    Use --list to show pending requests without starting the daemon.
    """
    if list_pending:
        try:
            from tweek.mcp.approval import ApprovalQueue
            from tweek.mcp.approval_cli import display_pending
            queue = ApprovalQueue()
            display_pending(queue)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        return

    try:
        from tweek.mcp.approval import ApprovalQueue
        from tweek.mcp.approval_cli import run_approval_daemon

        queue = ApprovalQueue()
        run_approval_daemon(queue, poll_interval=poll_interval)

    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print(f"[red]Approval daemon error: {e}[/red]")


@mcp.command("decide",
    epilog="""\b
Examples:
  tweek mcp decide abc12345 approve                   Approve a request
  tweek mcp decide abc12345 deny                      Deny a request
  tweek mcp decide abc12345 deny -n "Not authorized"  Deny with notes
"""
)
@click.argument("request_id")
@click.argument("decision", type=click.Choice(["approve", "deny"]))
@click.option("--notes", "-n", help="Decision notes")
def mcp_decide(request_id, decision, notes):
    """Approve or deny a specific approval request.

    REQUEST_ID can be the full UUID or the first 8 characters.
    """
    try:
        from tweek.mcp.approval import ApprovalQueue
        from tweek.mcp.approval_cli import decide_request

        queue = ApprovalQueue()
        success = decide_request(queue, request_id, decision, notes=notes)

        if success:
            verb = "Approved" if decision == "approve" else "Denied"
            style = "green" if decision == "approve" else "red"
            console.print(f"[{style}]{verb} request {request_id}[/{style}]")
        else:
            console.print(f"[yellow]Could not {decision} request {request_id}[/yellow]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
