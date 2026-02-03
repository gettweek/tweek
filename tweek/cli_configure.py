#!/usr/bin/env python3
"""
Tweek CLI Configure Command

Post-install configuration for Tweek components that are not required
during the initial quick install. Each subcommand handles one aspect
of configuration independently.

Usage:
    tweek configure              Show available configuration options
    tweek configure llm          Configure LLM review provider
    tweek configure preset       Change security preset
    tweek configure vault        Scan .env files and migrate to vault
    tweek configure proxy        Set up proxy for OpenClaw or other tools
    tweek configure mcp          Protect MCP-capable AI tools
    tweek configure sandbox      Set up Linux sandbox (firejail)
    tweek configure wizard       Run the full interactive setup wizard
"""
from __future__ import annotations

import click

from tweek.cli_helpers import console, print_success, print_warning


@click.group()
def configure():
    """Configure Tweek components after installation.

    Run 'tweek configure' to see available options. Each subcommand
    handles one aspect of configuration independently.
    """
    pass


# ---------------------------------------------------------------------------
# tweek configure llm
# ---------------------------------------------------------------------------

@configure.command()
def llm():
    """Configure the LLM review provider for semantic analysis.

    Sets up the cloud or local LLM used for Layer 3 security screening.
    Supports Anthropic, OpenAI, Google, xAI, or any OpenAI-compatible endpoint.
    """
    from pathlib import Path

    tweek_dir = Path("~/.tweek").expanduser()
    tweek_dir.mkdir(parents=True, exist_ok=True)

    from tweek.cli_install import _configure_llm_provider
    result = _configure_llm_provider(tweek_dir, interactive=True, quick=False)

    if result.get("provider_display"):
        console.print()
        print_success(f"LLM provider: {result['provider_display']}")
        if result.get("model_display"):
            console.print(f"  Model: {result['model_display']}")


# ---------------------------------------------------------------------------
# tweek configure preset
# ---------------------------------------------------------------------------

@configure.command()
@click.argument("name", required=False,
                type=click.Choice(["paranoid", "cautious", "balanced", "trusted"]))
def preset(name):
    """Change the security preset.

    Presets control tool security tiers and enforcement thresholds.

    \b
    Presets:
      paranoid   Maximum security, prompt on everything
      balanced   Smart defaults with provenance tracking (recommended)
      cautious   Prompt on risky operations
      trusted    Minimal prompts, trust AI decisions
    """
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()

    if name is None:
        # Interactive selection
        console.print("[bold]Security Presets[/bold]")
        console.print()
        console.print("  [cyan]1.[/cyan] paranoid  \u2014 Maximum security, prompt on everything")
        console.print("  [cyan]2.[/cyan] balanced  \u2014 Smart defaults with provenance tracking [green](recommended)[/green]")
        console.print("  [cyan]3.[/cyan] cautious  \u2014 Prompt on risky operations")
        console.print("  [cyan]4.[/cyan] trusted   \u2014 Minimal prompts, trust AI decisions")
        console.print()

        choice = click.prompt("Select preset", type=click.IntRange(1, 4), default=2)
        name = {1: "paranoid", 2: "balanced", 3: "cautious", 4: "trusted"}[choice]

    cfg.apply_preset(name)
    print_success(f"Applied {name} preset")
    if name == "balanced":
        console.print("[white]  Clean sessions get fewer prompts; tainted sessions get extra scrutiny[/white]")


# ---------------------------------------------------------------------------
# tweek configure vault
# ---------------------------------------------------------------------------

@configure.command()
@click.option("--dry-run", is_flag=True, help="Show what would be migrated without making changes")
def vault(dry_run):
    """Scan for .env files and migrate credentials to the secure vault.

    Finds .env files in common locations, identifies credential keys,
    and offers to migrate them to the system keychain.
    """
    from tweek.cli_install import scan_for_env_files
    from rich.table import Table

    console.print("[cyan]Scanning for .env files with credentials...[/cyan]\n")

    env_files = scan_for_env_files()

    if not env_files:
        console.print("[white]No .env files with credentials found.[/white]")
        return

    table = Table(title="Found .env Files")
    table.add_column("#", style="white")
    table.add_column("Path")
    table.add_column("Credentials", justify="right")

    for i, (path, keys) in enumerate(env_files, 1):
        from pathlib import Path as P
        try:
            display_path = path.relative_to(P.cwd())
        except ValueError:
            display_path = path
        table.add_row(str(i), str(display_path), str(len(keys)))

    console.print(table)

    if dry_run:
        console.print("\n[white]Dry run \u2014 no changes made.[/white]")
        for path, keys in env_files:
            console.print(f"\n  {path}:")
            for key in keys:
                console.print(f"    \u2022 {key}")
        return

    # Interactive migration
    console.print("\n[yellow]Migrate these credentials to secure storage?[/yellow]")
    if not click.confirm("Proceed?"):
        console.print("[white]Skipped.[/white]")
        return

    try:
        from tweek.vault import get_vault, VAULT_AVAILABLE
        if not VAULT_AVAILABLE:
            print_warning("Vault not available. Install keyring: pip install keyring")
            return
        vault_store = get_vault()
    except ImportError:
        print_warning("Vault module not available.")
        return

    for path, keys in env_files:
        from pathlib import Path as P
        try:
            display_path = path.relative_to(P.cwd())
        except ValueError:
            display_path = path

        console.print(f"\n[cyan]{display_path}[/cyan]")

        suggested_skill = path.parent.name
        if suggested_skill in (".", "", "~"):
            suggested_skill = "default"

        skill = click.prompt("  Skill name", default=suggested_skill)

        console.print(f"  [white]Credentials to migrate:[/white]")
        for key in keys:
            console.print(f"    \u2022 {key}")

        if click.confirm(f"  Migrate {len(keys)} credentials to '{skill}'?"):
            try:
                from tweek.vault import migrate_env_to_vault
                results = migrate_env_to_vault(path, skill, vault_store, dry_run=False)
                successful = sum(1 for _, s in results if s)
                print_success(f"Migrated {successful}/{len(results)} credentials")
            except Exception as e:
                print_warning(f"Migration failed: {e}")
        else:
            console.print("  [white]Skipped[/white]")


# ---------------------------------------------------------------------------
# tweek configure proxy
# ---------------------------------------------------------------------------

@configure.command()
@click.option("--force", is_flag=True, help="Force proxy to override existing configurations")
def proxy(force):
    """Set up Tweek proxy for OpenClaw or other API interceptors.

    Detects OpenClaw and other proxy configurations, then offers to
    set up Tweek as a security layer.
    """
    try:
        from tweek.proxy import detect_proxy_conflicts, get_openclaw_status
    except ImportError:
        print_warning("Proxy module not available.")
        return

    try:
        openclaw_status = get_openclaw_status()
    except Exception as e:
        print_warning(f"Could not check OpenClaw status: {e}")
        return

    if openclaw_status["installed"]:
        console.print("[green]\u2713[/green] OpenClaw detected")
        if openclaw_status["gateway_active"]:
            console.print(f"  Gateway running on port {openclaw_status['port']}")
        elif openclaw_status["running"]:
            console.print(f"  Process running (port {openclaw_status['port']})")
        else:
            console.print("  Installed but not currently running")
        console.print()

        if force or click.confirm("Configure Tweek to protect OpenClaw?", default=True):
            _apply_proxy_config(force=True)
        else:
            console.print("[white]Skipped. Run 'tweek protect openclaw' later.[/white]")
    else:
        console.print("[white]OpenClaw not detected on this system.[/white]")

    # Check for other proxy conflicts
    try:
        conflicts = detect_proxy_conflicts()
        non_openclaw = [c for c in conflicts if c.tool_name != "openclaw"]
        if non_openclaw:
            console.print("\n[yellow]Other proxy conflicts:[/yellow]")
            for conflict in non_openclaw:
                console.print(f"  \u2022 {conflict.description}")
    except Exception:
        pass


def _apply_proxy_config(force: bool = False) -> None:
    """Write proxy configuration to ~/.tweek/config.yaml."""
    import yaml
    from pathlib import Path

    try:
        from tweek.proxy import TWEEK_DEFAULT_PORT
    except ImportError:
        TWEEK_DEFAULT_PORT = 8766

    tweek_dir = Path("~/.tweek").expanduser()
    tweek_dir.mkdir(parents=True, exist_ok=True)
    config_path = tweek_dir / "config.yaml"

    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
    else:
        config = {}

    config["proxy"] = config.get("proxy", {})
    config["proxy"]["enabled"] = True
    config["proxy"]["port"] = TWEEK_DEFAULT_PORT
    config["proxy"]["override_openclaw"] = force
    config["proxy"]["auto_start"] = False

    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    print_success("Proxy configuration saved")
    console.print(f"  [white]Config: {config_path}[/white]")
    console.print("  [white]Run 'tweek proxy start' to begin intercepting API calls[/white]")


# ---------------------------------------------------------------------------
# tweek configure mcp
# ---------------------------------------------------------------------------

@configure.command()
def mcp():
    """Protect MCP-capable AI tools (Claude Desktop, ChatGPT, Gemini CLI).

    Scans for installed MCP clients and offers to add Tweek as an MCP
    security server for each one.
    """
    from tweek.cli_helpers import _detect_all_tools

    try:
        all_tools = _detect_all_tools()
    except Exception as e:
        print_warning(f"Could not detect AI tools: {e}")
        return

    # Filter to MCP-capable tools
    mcp_tool_ids = {"claude-desktop", "chatgpt", "gemini"}
    mcp_tools = [
        (tool_id, label, installed, protected)
        for tool_id, label, installed, protected, _detail in all_tools
        if tool_id in mcp_tool_ids
    ]

    if not mcp_tools:
        console.print("[white]No MCP-capable AI tools detected.[/white]")
        return

    console.print("[bold]MCP-Capable AI Tools[/bold]\n")

    any_unprotected = False
    for tool_id, label, installed, protected in mcp_tools:
        if not installed:
            console.print(f"  [white]\u25cb[/white] {label} \u2014 not installed")
        elif protected:
            console.print(f"  [green]\u2713[/green] {label} \u2014 protected")
        else:
            console.print(f"  [yellow]\u26a0[/yellow] {label} \u2014 not protected")
            any_unprotected = True

    if not any_unprotected:
        console.print("\n[white]All detected MCP tools are already protected.[/white]")
        return

    console.print()
    unprotected = [
        (tool_id, label)
        for tool_id, label, installed, protected in mcp_tools
        if installed and not protected
    ]

    for tool_id, label in unprotected:
        if click.confirm(f"  Protect {label}?", default=True):
            try:
                from tweek.cli_protect import _protect_mcp_client
                _protect_mcp_client(tool_id)
                print_success(f"{label} protected")
            except Exception as e:
                print_warning(f"Could not configure {label}: {e}")
        else:
            console.print(f"  [white]Skipped {label}[/white]")


# ---------------------------------------------------------------------------
# tweek configure sandbox
# ---------------------------------------------------------------------------

@configure.command()
def sandbox():
    """Set up Linux sandbox (firejail) for command isolation.

    Only applicable on Linux systems. Checks if firejail is installed
    and offers to install it if not.
    """
    from tweek.platform import IS_LINUX, get_capabilities

    if not IS_LINUX:
        console.print("[white]Sandbox is only available on Linux.[/white]")
        console.print(f"[white]Your platform: {get_capabilities().platform.value}[/white]")
        return

    caps = get_capabilities()
    if caps.sandbox_available:
        print_success(f"Sandbox already available: {caps.sandbox_tool}")
        return

    console.print("[yellow]Sandbox (firejail) not installed.[/yellow]")
    console.print(f"[white]Install with: {caps.sandbox_install_hint}[/white]")

    try:
        from tweek.sandbox.linux import prompt_install_firejail
        prompt_install_firejail(console)
    except ImportError:
        console.print("[white]Run the install command shown above manually.[/white]")


# ---------------------------------------------------------------------------
# tweek configure wizard
# ---------------------------------------------------------------------------

@configure.command()
@click.pass_context
def wizard(ctx):
    """Run the full interactive setup wizard.

    This is the same interactive experience as 'tweek install' without
    the --quick flag. Use it to reconfigure all Tweek settings at once.
    """
    from tweek.cli_install import install

    console.print("[bold]Starting full configuration wizard...[/bold]")
    console.print("[white]This will walk through all configuration options.[/white]\n")

    # Invoke the install command in interactive mode
    ctx.invoke(
        install,
        scope=None,
        preset=None,
        quick=False,
        backup=True,
        skip_env_scan=False,
        interactive=True,
        ai_defaults=False,
        with_sandbox=False,
        force_proxy=False,
        skip_proxy_check=False,
    )
