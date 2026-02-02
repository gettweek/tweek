#!/usr/bin/env python3
"""
Tweek CLI Protect / Unprotect Commands

Per-tool protection lifecycle:
    tweek protect                         Interactive wizard
    tweek protect claude-code             Install Claude Code hooks
    tweek protect openclaw                One-command OpenClaw protection
    tweek protect claude-desktop          Configure Claude Desktop MCP
    tweek protect chatgpt                 Configure ChatGPT Desktop MCP
    tweek protect gemini                  Configure Gemini CLI MCP
    tweek unprotect [tool]                Remove protection from a tool
"""
from __future__ import annotations

import click
import json
import os
import sys
from pathlib import Path

from tweek.cli_helpers import (
    console,
    TWEEK_BANNER,
    _has_tweek_hooks,
    _has_tweek_at,
    _detect_all_tools,
)
from tweek.cli_install import _install_claude_code_hooks


# =============================================================================
# PROTECT GROUP
# =============================================================================

@click.group(
    invoke_without_command=True,
    epilog="""\b
Examples:
  tweek protect                          Interactive wizard — detect & protect all tools
  tweek protect --status                 Show protection status for all tools
  tweek protect claude-code              Install Claude Code hooks
  tweek protect openclaw                 One-command OpenClaw protection
  tweek protect claude-desktop           Configure Claude Desktop integration
  tweek protect chatgpt                  Set up ChatGPT Desktop integration
  tweek protect gemini                   Configure Gemini CLI integration
"""
)
@click.option("--status", is_flag=True, help="Show protection status for all tools")
@click.pass_context
def protect(ctx, status):
    """Set up Tweek protection for AI tools.

    When run without a subcommand, launches an interactive wizard
    that auto-detects installed AI tools and offers to protect them.
    """
    if status:
        _show_protection_status()
        return
    if ctx.invoked_subcommand is None:
        _run_protect_wizard()


@protect.command(
    "openclaw",
    epilog="""\b
Examples:
  tweek protect openclaw                Auto-detect and protect OpenClaw
  tweek protect openclaw --paranoid     Maximum security preset
  tweek protect openclaw --port 9999    Custom gateway port
"""
)
@click.option("--port", default=None, type=int,
              help="OpenClaw gateway port (default: auto-detect)")
@click.option("--paranoid", is_flag=True,
              help="Use paranoid security preset (default: cautious)")
@click.option("--preset", type=click.Choice(["paranoid", "cautious", "trusted"]),
              default=None, help="Security preset to apply")
def protect_openclaw(port, paranoid, preset):
    """One-command OpenClaw protection setup.

    Auto-detects OpenClaw, configures proxy wrapping,
    and starts screening all tool calls through Tweek's
    five-layer defense pipeline.
    """
    from tweek.integrations.openclaw import (
        detect_openclaw_installation,
        setup_openclaw_protection,
    )

    console.print(TWEEK_BANNER, style="cyan")

    # Resolve preset
    if paranoid:
        effective_preset = "paranoid"
    elif preset:
        effective_preset = preset
    else:
        effective_preset = "cautious"

    # Step 1: Detect OpenClaw
    console.print("[cyan]Detecting OpenClaw...[/cyan]")
    openclaw = detect_openclaw_installation()

    if not openclaw["installed"]:
        console.print()
        console.print("[red]OpenClaw not detected on this system.[/red]")
        console.print()
        console.print("[white]Install OpenClaw first:[/white]")
        console.print("  npm install -g openclaw")
        console.print()
        console.print("[white]Or if OpenClaw is installed in a non-standard location,[/white]")
        console.print("[white]specify the gateway port manually:[/white]")
        console.print("  tweek protect openclaw --port 18789")
        return

    # Show detection results
    console.print()
    console.print("  [green]OpenClaw detected[/green]")

    if openclaw["version"]:
        console.print(f"  Version:    {openclaw['version']}")

    console.print(f"  Gateway:    port {openclaw['gateway_port']}", end="")
    if openclaw["gateway_active"]:
        console.print(" [green](running)[/green]")
    elif openclaw["process_running"]:
        console.print(" [yellow](process running, gateway inactive)[/yellow]")
    else:
        console.print(" [white](not running)[/white]")

    if openclaw["config_path"]:
        console.print(f"  Config:     {openclaw['config_path']}")

    console.print()

    # Step 2: Configure protection
    console.print("[cyan]Configuring Tweek protection...[/cyan]")
    result = setup_openclaw_protection(port=port, preset=effective_preset)

    if not result.success:
        console.print(f"\n[red]Setup failed: {result.error}[/red]")
        return

    # Show configuration
    console.print(f"  Scanner:    port {result.scanner_port} -> wrapping OpenClaw gateway")
    console.print(f"  Preset:     {result.preset} (262 patterns + rate limiting)")

    # Check for API key
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        console.print("  LLM Review: [green]active[/green] (ANTHROPIC_API_KEY found)")
    else:
        console.print("  LLM Review: [white]available (set ANTHROPIC_API_KEY for semantic analysis)[/white]")

    # Show warnings
    for warning in result.warnings:
        console.print(f"\n  [yellow]Warning: {warning}[/yellow]")

    console.print()

    if not openclaw["gateway_active"]:
        console.print("[yellow]Note: OpenClaw gateway is not currently running.[/yellow]")
        console.print("[white]Protection will activate when OpenClaw starts.[/white]")
        console.print()

    console.print("[green]Protection configured.[/green] Screening all OpenClaw tool calls.")
    console.print()
    console.print("[white]Verify:     tweek doctor[/white]")
    console.print("[white]Logs:       tweek logs show[/white]")
    console.print("[white]Stop:       tweek proxy stop[/white]")


@protect.command(
    "claude-code",
    epilog="""\b
Examples:
  tweek protect claude-code              Install for current project
  tweek protect claude-code --global     Install globally (all projects)
  tweek protect claude-code --quick      Zero-prompt install with defaults
  tweek protect claude-code --preset paranoid   Apply paranoid security preset
"""
)
@click.option("--global", "install_global", is_flag=True, default=False,
              help="Install globally to ~/.claude/ (protects all projects)")
@click.option("--dev-test", is_flag=True, hidden=True,
              help="Install to test environment (for Tweek development only)")
@click.option("--backup/--no-backup", default=True,
              help="Backup existing hooks before installation")
@click.option("--skip-env-scan", is_flag=True,
              help="Skip scanning for .env files to migrate")
@click.option("--interactive", "-i", is_flag=True,
              help="Interactively configure security settings")
@click.option("--preset", type=click.Choice(["paranoid", "cautious", "trusted"]),
              help="Apply a security preset (skip interactive)")
@click.option("--ai-defaults", is_flag=True,
              help="Let AI suggest default settings based on detected skills")
@click.option("--with-sandbox", is_flag=True,
              help="Prompt to install sandbox tool if not available (Linux only)")
@click.option("--force-proxy", is_flag=True,
              help="Force Tweek proxy to override existing proxy configurations (e.g., openclaw)")
@click.option("--skip-proxy-check", is_flag=True,
              help="Skip checking for existing proxy configurations")
@click.option("--quick", is_flag=True,
              help="Zero-prompt install with cautious defaults (skips env scan and proxy check)")
def protect_claude_code(install_global, dev_test, backup, skip_env_scan, interactive, preset, ai_defaults, with_sandbox, force_proxy, skip_proxy_check, quick):
    """Install Tweek hooks for Claude Code.

    Installs PreToolUse and PostToolUse hooks to screen all
    Claude Code tool calls through Tweek's security pipeline.
    """
    _install_claude_code_hooks(
        install_global=install_global,
        dev_test=dev_test,
        backup=backup,
        skip_env_scan=skip_env_scan,
        interactive=interactive,
        preset=preset,
        ai_defaults=ai_defaults,
        with_sandbox=with_sandbox,
        force_proxy=force_proxy,
        skip_proxy_check=skip_proxy_check,
        quick=quick,
    )


@protect.command("claude-desktop")
def protect_claude_desktop():
    """Configure Tweek as MCP server for Claude Desktop."""
    _protect_mcp_client("claude-desktop")


@protect.command("chatgpt")
def protect_chatgpt():
    """Configure Tweek as MCP server for ChatGPT Desktop."""
    _protect_mcp_client("chatgpt")


@protect.command("gemini")
def protect_gemini():
    """Configure Tweek as MCP server for Gemini CLI."""
    _protect_mcp_client("gemini")


def _protect_mcp_client(client_name: str):
    """Shared logic for MCP client protection commands."""
    try:
        from tweek.mcp.clients import get_client

        handler = get_client(client_name)
        result = handler.install()

        if result.get("success"):
            console.print(f"[green]{result.get('message', 'Installed successfully')}[/green]")
            if result.get("config_path"):
                console.print(f"   Config: {result['config_path']}")
            if result.get("backup"):
                console.print(f"   Backup: {result['backup']}")
            if result.get("instructions"):
                console.print()
                for line in result["instructions"]:
                    console.print(f"   {line}")
        else:
            console.print(f"[red]{result.get('error', 'Installation failed')}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


# =============================================================================
# UNPROTECT COMMAND
# =============================================================================

@click.command(
    epilog="""\b
Examples:
  tweek unprotect                          Interactive — choose what to unprotect
  tweek unprotect claude-code              Remove Claude Code hooks
  tweek unprotect claude-code --global     Remove global Claude Code hooks
  tweek unprotect claude-desktop           Remove from Claude Desktop
  tweek unprotect openclaw                 Remove OpenClaw protection
"""
)
@click.argument("tool", required=False, type=click.Choice(
    ["claude-code", "openclaw", "claude-desktop", "chatgpt", "gemini"]))
@click.option("--global", "unprotect_global", is_flag=True, default=False,
              help="Remove from ~/.claude/ (global installation)")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def unprotect(tool: str, unprotect_global: bool, confirm: bool):
    """Remove Tweek protection from an AI tool.

    This removes hooks and MCP configuration for a specific tool
    but keeps Tweek installed on your system. Use `tweek uninstall`
    to fully remove Tweek.

    When run without arguments, launches an interactive wizard
    that walks through each protected tool asking if you want
    to remove protection.

    This command can only be run from an interactive terminal.
    AI agents are blocked from running it.
    """
    from tweek.cli_uninstall import _uninstall_scope

    # ─────────────────────────────────────────────────────────────
    # HUMAN-ONLY GATE: Block non-interactive execution
    # This is Layer 2 of protection (Layer 1 is the PreToolUse hook)
    # ─────────────────────────────────────────────────────────────
    if not sys.stdin.isatty():
        console.print("[red]ERROR: tweek unprotect must be run from an interactive terminal.[/red]")
        console.print("[white]This command cannot be run by AI agents or automated scripts.[/white]")
        console.print("[white]Open a terminal and run the command directly.[/white]")
        raise SystemExit(1)

    # No tool: run interactive wizard
    if not tool:
        _run_unprotect_wizard()
        return

    console.print(TWEEK_BANNER, style="cyan")

    tweek_dir = Path("~/.tweek").expanduser()
    global_target = Path("~/.claude").expanduser()
    project_target = Path.cwd() / ".claude"

    if tool == "claude-code":
        if unprotect_global:
            _uninstall_scope(global_target, tweek_dir, confirm, scope_label="global")
        else:
            _uninstall_scope(project_target, tweek_dir, confirm, scope_label="project")
        return

    if tool in ("claude-desktop", "chatgpt", "gemini"):
        try:
            from tweek.mcp.clients import get_client
            handler = get_client(tool)
            result = handler.uninstall()
            if result.get("success"):
                console.print(f"[green]{result.get('message', 'Uninstalled successfully')}[/green]")
                if result.get("backup"):
                    console.print(f"   Backup: {result['backup']}")
                if result.get("instructions"):
                    console.print()
                    for line in result["instructions"]:
                        console.print(f"   {line}")
            else:
                console.print(f"[red]{result.get('error', 'Uninstallation failed')}[/red]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
        return

    if tool == "openclaw":
        from tweek.integrations.openclaw import remove_openclaw_protection
        result = remove_openclaw_protection()
        if result.get("success"):
            console.print(f"[green]{result.get('message', 'OpenClaw protection removed')}[/green]")
            for detail in result.get("details", []):
                console.print(f"  [green]\u2713[/green] {detail}")
        else:
            console.print(f"[red]{result.get('error', 'Failed to remove OpenClaw protection')}[/red]")
        return


# =============================================================================
# PROTECT WIZARD & STATUS HELPERS
# =============================================================================

def _run_protect_wizard():
    """Interactive wizard: detect tools and ask Y/n for each one."""
    console.print(TWEEK_BANNER, style="cyan")
    console.print("[bold]Tweek Protection Wizard[/bold]\n")
    console.print("Scanning for AI tools...\n")

    tools = _detect_all_tools()

    # Show detection summary
    detected = [(tid, label, prot) for tid, label, inst, prot, _ in tools if inst]
    not_detected = [label for _, label, inst, _, _ in tools if not inst]

    if not_detected:
        for label in not_detected:
            console.print(f"  [white]{label:<20}[/white] [white]not found[/white]")

    if not detected:
        console.print("\n[yellow]No AI tools detected on this system.[/yellow]")
        return

    # Show already-protected tools
    already_protected = [(tid, label) for tid, label, prot in detected if prot]
    unprotected = [(tid, label) for tid, label, prot in detected if not prot]

    for _, label in already_protected:
        console.print(f"  [green]{label:<20} protected[/green]")

    if not unprotected:
        console.print(f"\n[green]All {len(already_protected)} detected tool(s) already protected.[/green]")
        console.print("Run 'tweek status' to see details.")
        return

    for _, label in unprotected:
        console.print(f"  [yellow]{label:<20} not protected[/yellow]")

    # Ask for preset first (applies to all)
    console.print()
    console.print("[bold]Security preset:[/bold]")
    console.print("  [bold]1.[/bold] cautious [white](recommended)[/white] \u2014 screen risky & dangerous tools")
    console.print("  [bold]2.[/bold] paranoid \u2014 screen everything except safe tools")
    console.print("  [bold]3.[/bold] trusted \u2014 only screen dangerous tools")
    console.print()
    preset_choice = click.prompt("Select preset", type=click.IntRange(1, 3), default=1)
    preset = ["cautious", "paranoid", "trusted"][preset_choice - 1]

    # Walk through each unprotected tool
    console.print()
    protected_count = 0
    skipped_count = 0

    for tool_id, label in unprotected:
        protect_it = click.confirm(f"  Protect {label}?", default=True)

        if not protect_it:
            console.print(f"    [white]skipped[/white]")
            skipped_count += 1
            continue

        try:
            if tool_id == "claude-code":
                _install_claude_code_hooks(
                    install_global=True, dev_test=False, backup=True,
                    skip_env_scan=True, interactive=False, preset=preset,
                    ai_defaults=False, with_sandbox=False, force_proxy=False,
                    skip_proxy_check=True, quick=True,
                )
            elif tool_id == "openclaw":
                from tweek.integrations.openclaw import setup_openclaw_protection
                result = setup_openclaw_protection(preset=preset)
                if result.success:
                    console.print(f"    [green]done[/green]")
                else:
                    console.print(f"    [red]failed: {result.error}[/red]")
                    continue
            elif tool_id in ("claude-desktop", "chatgpt", "gemini"):
                _protect_mcp_client(tool_id)
            protected_count += 1
        except Exception as e:
            console.print(f"    [red]error: {e}[/red]")

    console.print()
    if protected_count:
        console.print(f"[green]Protected {protected_count} tool(s).[/green]", end="")
    if skipped_count:
        console.print(f"  [white]Skipped {skipped_count}.[/white]", end="")
    console.print()
    console.print("Run 'tweek status' to see the full dashboard.")


def _run_unprotect_wizard():
    """Interactive wizard: detect protected tools and ask Y/n to unprotect each."""
    from tweek.cli_uninstall import _uninstall_scope

    console.print(TWEEK_BANNER, style="cyan")
    console.print("[bold]Tweek Unprotect Wizard[/bold]\n")
    console.print("Scanning for protected AI tools...\n")

    tools = _detect_all_tools()
    tweek_dir = Path("~/.tweek").expanduser()
    global_target = Path("~/.claude").expanduser()

    protected = [(tid, label) for tid, label, inst, prot, _ in tools if inst and prot]

    if not protected:
        console.print("[yellow]No protected tools found.[/yellow]")
        return

    for _, label in protected:
        console.print(f"  [green]{label:<20} protected[/green]")

    console.print()
    removed_count = 0
    skipped_count = 0

    for tool_id, label in protected:
        remove_it = click.confirm(f"  Remove protection from {label}?", default=False)

        if not remove_it:
            console.print(f"    [white]kept[/white]")
            skipped_count += 1
            continue

        try:
            if tool_id == "claude-code":
                _uninstall_scope(global_target, tweek_dir, confirm=True, scope_label="global")
            elif tool_id in ("claude-desktop", "chatgpt", "gemini"):
                from tweek.mcp.clients import get_client
                handler = get_client(tool_id)
                result = handler.uninstall()
                if result.get("success"):
                    console.print(f"    [green]{result.get('message', 'removed')}[/green]")
                else:
                    console.print(f"    [red]{result.get('error', 'failed')}[/red]")
                    continue
            elif tool_id == "openclaw":
                from tweek.integrations.openclaw import remove_openclaw_protection
                result = remove_openclaw_protection()
                if result.get("success"):
                    console.print(f"    [green]{result.get('message', 'removed')}[/green]")
                else:
                    console.print(f"    [red]{result.get('error', 'failed')}[/red]")
                    continue
            removed_count += 1
        except Exception as e:
            console.print(f"    [red]error: {e}[/red]")

    console.print()
    if removed_count:
        console.print(f"[green]Removed protection from {removed_count} tool(s).[/green]", end="")
    if skipped_count:
        console.print(f"  [white]Kept {skipped_count}.[/white]", end="")
    console.print()


def _show_protection_status():
    """Show protection status dashboard for all AI tools."""
    from rich.table import Table

    console.print(TWEEK_BANNER, style="cyan")

    tools = _detect_all_tools()

    # Build status table
    table = Table(title="Protection Status", show_lines=False)
    table.add_column("Tool", style="cyan", min_width=18)
    table.add_column("Installed", justify="center", min_width=10)
    table.add_column("Protected", justify="center", min_width=10)
    table.add_column("Details")

    detected_count = 0
    protected_count = 0

    for tool_id, label, installed, prot, detail in tools:
        if installed:
            detected_count += 1
        if prot:
            protected_count += 1

        table.add_row(
            label,
            "[green]yes[/green]" if installed else "[white]no[/white]",
            "[green]yes[/green]" if prot else "[yellow]no[/yellow]" if installed else "[white]\u2014[/white]",
            detail,
        )

    console.print(table)
    console.print()

    # Summary line
    unprotected_count = detected_count - protected_count
    if detected_count == 0:
        console.print("[yellow]No AI tools detected.[/yellow]")
    elif unprotected_count == 0:
        console.print(f"[green]{protected_count}/{detected_count} detected tools protected.[/green]")
    else:
        console.print(f"[yellow]{protected_count}/{detected_count} detected tools protected. {unprotected_count} unprotected.[/yellow]")
        console.print("[white]Run 'tweek protect' to set up protection.[/white]")
    console.print()
