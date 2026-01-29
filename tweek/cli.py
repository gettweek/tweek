#!/usr/bin/env python3
"""
Tweek CLI - GAH! Security for your Claude Code skills.

Usage:
    tweek install [--scope global|project]
    tweek uninstall [--scope global|project]
    tweek status
    tweek config [--skill NAME] [--preset paranoid|cautious|trusted]
    tweek vault store SKILL KEY VALUE
    tweek vault get SKILL KEY
    tweek vault migrate-env [--dry-run]
    tweek logs [--limit N] [--type TYPE]
    tweek logs stats [--days N]
    tweek logs export [--days N] [--output FILE]
"""

import click
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Dict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from tweek import __version__

console = Console()


def scan_for_env_files() -> List[Tuple[Path, List[str]]]:
    """
    Scan common locations for .env files.

    Returns:
        List of (path, credential_keys) tuples
    """
    locations = [
        Path.cwd() / ".env",
        Path.home() / ".env",
        Path.cwd() / ".env.local",
        Path.cwd() / ".env.production",
        Path.cwd() / ".env.development",
    ]

    # Also check parent directories up to 3 levels
    parent = Path.cwd().parent
    for _ in range(3):
        if parent != parent.parent:
            locations.append(parent / ".env")
            parent = parent.parent

    found = []
    seen_paths = set()

    for path in locations:
        try:
            resolved = path.resolve()
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)

            if path.exists() and path.is_file():
                keys = parse_env_keys(path)
                if keys:
                    found.append((path, keys))
        except (PermissionError, OSError):
            continue

    return found


def parse_env_keys(env_path: Path) -> List[str]:
    """
    Parse .env file and return list of credential keys.

    Only returns keys that look like credentials (contain KEY, SECRET,
    PASSWORD, TOKEN, API, AUTH, etc.)
    """
    credential_patterns = [
        r'.*KEY.*', r'.*SECRET.*', r'.*PASSWORD.*', r'.*TOKEN.*',
        r'.*API.*', r'.*AUTH.*', r'.*CREDENTIAL.*', r'.*PRIVATE.*',
        r'.*ACCESS.*', r'.*CONN.*STRING.*', r'.*DB_.*', r'.*DATABASE.*',
    ]

    keys = []
    try:
        content = env_path.read_text()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key = line.split("=", 1)[0].strip()

            # Check if it looks like a credential
            key_upper = key.upper()
            is_credential = any(
                re.match(pattern, key_upper, re.IGNORECASE)
                for pattern in credential_patterns
            )

            if is_credential:
                keys.append(key)
    except (PermissionError, OSError):
        pass

    return keys

TWEEK_BANNER = """
 ████████╗██╗    ██╗███████╗███████╗██╗  ██╗
 ╚══██╔══╝██║    ██║██╔════╝██╔════╝██║ ██╔╝
    ██║   ██║ █╗ ██║█████╗  █████╗  █████╔╝
    ██║   ██║███╗██║██╔══╝  ██╔══╝  ██╔═██╗
    ██║   ╚███╔███╔╝███████╗███████╗██║  ██╗
    ╚═╝    ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝

  GAH! Security sandboxing for Claude Code
  "Because paranoia is a feature, not a bug"
"""


@click.group()
@click.version_option(version=__version__, prog_name="tweek")
def main():
    """Tweek - Security sandboxing for Claude Code skills.

    GAH! TOO MUCH PRESSURE on your credentials!
    """
    pass


@main.command(
    epilog="""\b
Examples:
  tweek install                          Install globally with default settings
  tweek install --scope project          Install for current project only
  tweek install --interactive            Walk through configuration prompts
  tweek install --preset paranoid        Apply paranoid security preset
  tweek install --with-sandbox           Install sandbox tool if needed (Linux)
  tweek install --force-proxy            Override existing proxy configurations
"""
)
@click.option("--scope", type=click.Choice(["global", "project"]), default="global",
              help="Installation scope: global (~/.claude) or project (./.claude)")
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
              help="Force Tweek proxy to override existing proxy configurations (e.g., moltbot)")
@click.option("--skip-proxy-check", is_flag=True,
              help="Skip checking for existing proxy configurations")
def install(scope: str, dev_test: bool, backup: bool, skip_env_scan: bool, interactive: bool, preset: str, ai_defaults: bool, with_sandbox: bool, force_proxy: bool, skip_proxy_check: bool):
    """Install Tweek hooks into Claude Code.

    Scope options:
        --scope global  : Install to ~/.claude/ (protects all projects)
        --scope project : Install to ./.claude/ (protects this project only)

    Configuration options:
        --interactive  : Walk through configuration prompts
        --preset       : Apply paranoid/cautious/trusted preset
        --ai-defaults  : Auto-configure based on detected skills
        --with-sandbox : Install sandbox tool if needed (Linux: firejail)
    """
    import json
    import shutil
    from tweek.platform import IS_LINUX, get_capabilities
    from tweek.config.manager import ConfigManager, SecurityTier

    console.print(TWEEK_BANNER, style="cyan")

    # ─────────────────────────────────────────────────────────────
    # Check for existing proxy configurations (moltbot, etc.)
    # ─────────────────────────────────────────────────────────────
    proxy_override_enabled = force_proxy
    if not skip_proxy_check:
        try:
            from tweek.proxy import (
                detect_proxy_conflicts,
                get_moltbot_status,
                MOLTBOT_DEFAULT_PORT,
                TWEEK_DEFAULT_PORT,
            )

            moltbot_status = get_moltbot_status()

            if moltbot_status["installed"]:
                console.print()
                console.print("[yellow]⚠ Moltbot detected on this system[/yellow]")

                if moltbot_status["gateway_active"]:
                    console.print(f"  [red]Gateway is running on port {moltbot_status['port']}[/red]")
                elif moltbot_status["running"]:
                    console.print(f"  [dim]Process is running (gateway may start on port {moltbot_status['port']})[/dim]")
                else:
                    console.print(f"  [dim]Installed but not currently running[/dim]")

                if moltbot_status["config_path"]:
                    console.print(f"  [dim]Config: {moltbot_status['config_path']}[/dim]")

                console.print()

                if not force_proxy:
                    console.print("[cyan]Tweek can work alongside moltbot, or you can configure[/cyan]")
                    console.print("[cyan]Tweek's proxy to intercept API calls instead.[/cyan]")
                    console.print()

                    if click.confirm(
                        "[yellow]Enable Tweek proxy to override moltbot's gateway?[/yellow]",
                        default=False
                    ):
                        proxy_override_enabled = True
                        console.print("[green]✓[/green] Tweek proxy will be configured to intercept API calls")
                        console.print(f"  [dim]Run 'tweek proxy start' after installation[/dim]")
                    else:
                        console.print("[dim]Tweek will work without proxy interception[/dim]")
                        console.print("[dim]You can enable it later with 'tweek proxy enable'[/dim]")
                else:
                    console.print("[green]✓[/green] Force proxy enabled - Tweek will override moltbot")

                console.print()

            # Check for other proxy conflicts
            conflicts = detect_proxy_conflicts()
            non_moltbot_conflicts = [c for c in conflicts if c.tool_name != "moltbot"]

            if non_moltbot_conflicts:
                console.print("[yellow]⚠ Other proxy conflicts detected:[/yellow]")
                for conflict in non_moltbot_conflicts:
                    console.print(f"  • {conflict.description}")
                console.print()

        except ImportError:
            # Proxy module not fully available, skip detection
            pass
        except Exception as e:
            console.print(f"[dim]Warning: Could not check for proxy conflicts: {e}[/dim]")

    # Determine target directory based on scope
    if dev_test:
        console.print("[yellow]Installing in DEV TEST mode (isolated environment)[/yellow]")
        target = Path("~/AI/tweek/test-environment/.claude").expanduser()
    elif scope == "global":
        target = Path("~/.claude").expanduser()
        console.print(f"[cyan]Scope: global[/cyan] - Hooks will protect all projects")
    else:  # project
        target = Path.cwd() / ".claude"
        console.print(f"[cyan]Scope: project[/cyan] - Hooks will protect this project only")

    hook_script = Path(__file__).parent / "hooks" / "pre_tool_use.py"

    # Backup existing hooks if requested
    if backup and target.exists():
        settings_file = target / "settings.json"
        if settings_file.exists():
            backup_path = settings_file.with_suffix(".json.tweek-backup")
            shutil.copy(settings_file, backup_path)
            console.print(f"[dim]Backed up existing settings to {backup_path}[/dim]")

    # Create target directory
    target.mkdir(parents=True, exist_ok=True)

    # Install hooks configuration
    settings_file = target / "settings.json"

    # Load existing settings or create new
    if settings_file.exists():
        with open(settings_file) as f:
            settings = json.load(f)
    else:
        settings = {}

    # Add Tweek hooks
    settings["hooks"] = settings.get("hooks", {})
    settings["hooks"]["PreToolUse"] = [
        {
            "matcher": "Bash",
            "hooks": [
                {
                    "type": "command",
                    "command": f"/usr/bin/env python3 {hook_script.resolve()}"
                }
            ]
        }
    ]

    with open(settings_file, "w") as f:
        json.dump(settings, f, indent=2)

    console.print(f"\n[green]✓[/green] Hooks installed to: {target}")

    # Create Tweek data directory
    tweek_dir = Path("~/.tweek").expanduser()
    tweek_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[green]✓[/green] Tweek data directory: {tweek_dir}")

    # Scan for .env files
    if not skip_env_scan:
        console.print("\n[cyan]Scanning for .env files with credentials...[/cyan]\n")

        env_files = scan_for_env_files()

        if env_files:
            table = Table(title="Found .env Files")
            table.add_column("#", style="dim")
            table.add_column("Path")
            table.add_column("Credentials", justify="right")

            for i, (path, keys) in enumerate(env_files, 1):
                # Show relative path if possible
                try:
                    display_path = path.relative_to(Path.cwd())
                except ValueError:
                    display_path = path

                table.add_row(str(i), str(display_path), str(len(keys)))

            console.print(table)

            if click.confirm("\n[yellow]Migrate these credentials to secure storage?[/yellow]"):
                from tweek.vault import get_vault, VAULT_AVAILABLE
                if not VAULT_AVAILABLE:
                    console.print("[red]✗[/red] Vault not available. Install keyring: pip install keyring")
                else:
                    vault = get_vault()

                for path, keys in env_files:
                    try:
                        display_path = path.relative_to(Path.cwd())
                    except ValueError:
                        display_path = path

                    console.print(f"\n[cyan]{display_path}[/cyan]")

                    # Suggest skill name from directory
                    suggested_skill = path.parent.name
                    if suggested_skill in (".", "", "~"):
                        suggested_skill = "default"

                    skill = click.prompt(
                        "  Skill name",
                        default=suggested_skill
                    )

                    # Show dry-run preview
                    console.print(f"  [dim]Preview - credentials to migrate:[/dim]")
                    for key in keys:
                        console.print(f"    • {key}")

                    if click.confirm(f"  Migrate {len(keys)} credentials to '{skill}'?"):
                        try:
                            from tweek.vault import migrate_env_to_vault
                            results = migrate_env_to_vault(path, skill, vault, dry_run=False)
                            successful = sum(1 for _, s in results if s)
                            console.print(f"  [green]✓[/green] Migrated {successful} credentials")
                        except Exception as e:
                            console.print(f"  [red]✗[/red] Migration failed: {e}")
                    else:
                        console.print(f"  [dim]Skipped[/dim]")
        else:
            console.print("[dim]No .env files with credentials found[/dim]")

    # ─────────────────────────────────────────────────────────────
    # Security Configuration
    # ─────────────────────────────────────────────────────────────
    cfg = ConfigManager()

    if preset:
        # Apply preset directly
        cfg.apply_preset(preset)
        console.print(f"\n[green]✓[/green] Applied [bold]{preset}[/bold] security preset")

    elif ai_defaults:
        # AI-assisted defaults: detect skills and suggest tiers
        console.print("\n[cyan]Detecting installed skills...[/cyan]")

        # Try to detect skills from Claude Code config
        detected_skills = []
        claude_settings = Path("~/.claude/settings.json").expanduser()
        if claude_settings.exists():
            try:
                with open(claude_settings) as f:
                    claude_config = json.load(f)
                # Look for plugins, skills, or custom hooks
                plugins = claude_config.get("enabledPlugins", {})
                detected_skills.extend(plugins.keys())
            except Exception:
                pass

        # Also check for common skill directories
        skill_dirs = [
            Path("~/.claude/skills").expanduser(),
            Path("~/.claude/commands").expanduser(),
        ]
        for skill_dir in skill_dirs:
            if skill_dir.exists():
                for item in skill_dir.iterdir():
                    if item.is_dir() or item.suffix == ".md":
                        detected_skills.append(item.stem)

        # Find unknown skills
        unknown_skills = cfg.get_unknown_skills(detected_skills)

        if unknown_skills:
            console.print(f"\n[yellow]Found {len(unknown_skills)} new skills not in config:[/yellow]")
            for skill in unknown_skills[:10]:  # Limit display
                console.print(f"  • {skill}")
            if len(unknown_skills) > 10:
                console.print(f"  ... and {len(unknown_skills) - 10} more")

            # Suggest defaults based on skill names
            console.print("\n[cyan]Applying AI-suggested defaults:[/cyan]")
            for skill in unknown_skills:
                # Simple heuristics for tier suggestion
                skill_lower = skill.lower()
                if any(x in skill_lower for x in ["deploy", "publish", "release", "prod"]):
                    suggested = SecurityTier.DANGEROUS
                elif any(x in skill_lower for x in ["web", "fetch", "api", "external", "browser"]):
                    suggested = SecurityTier.RISKY
                elif any(x in skill_lower for x in ["review", "read", "explore", "search", "list"]):
                    suggested = SecurityTier.SAFE
                else:
                    suggested = SecurityTier.DEFAULT

                cfg.set_skill_tier(skill, suggested)
                console.print(f"  {skill}: {suggested.value}")

            console.print(f"\n[green]✓[/green] Configured {len(unknown_skills)} skills")
        else:
            console.print("[dim]All detected skills already configured[/dim]")

        # Apply cautious preset as base
        cfg.apply_preset("cautious")
        console.print("[green]✓[/green] Applied [bold]cautious[/bold] base preset")

    elif interactive:
        # Full interactive configuration
        console.print("\n[bold]Security Configuration[/bold]")
        console.print("Choose how to configure security settings:\n")
        console.print("  [cyan]1.[/cyan] Paranoid - Maximum security")
        console.print("  [cyan]2.[/cyan] Cautious - Balanced (recommended)")
        console.print("  [cyan]3.[/cyan] Trusted  - Minimal prompts")
        console.print("  [cyan]4.[/cyan] Custom   - Configure individually")
        console.print()

        choice = click.prompt("Select", type=click.IntRange(1, 4), default=2)

        if choice == 1:
            cfg.apply_preset("paranoid")
            console.print("[green]✓[/green] Applied paranoid preset")
        elif choice == 2:
            cfg.apply_preset("cautious")
            console.print("[green]✓[/green] Applied cautious preset")
        elif choice == 3:
            cfg.apply_preset("trusted")
            console.print("[green]✓[/green] Applied trusted preset")
        else:
            # Custom: ask about key tools
            console.print("\n[bold]Configure key tools:[/bold]")
            console.print("[dim](safe/default/risky/dangerous)[/dim]\n")

            for tool in ["Bash", "WebFetch", "Edit"]:
                current = cfg.get_tool_tier(tool)
                new_tier = click.prompt(
                    f"  {tool}",
                    default=current.value,
                    type=click.Choice(["safe", "default", "risky", "dangerous"])
                )
                cfg.set_tool_tier(tool, SecurityTier.from_string(new_tier))

            console.print("[green]✓[/green] Custom configuration saved")

    else:
        # Default: apply cautious preset silently
        if not cfg.export_config("user"):
            cfg.apply_preset("cautious")
            console.print("\n[green]✓[/green] Applied default [bold]cautious[/bold] security preset")
            console.print("[dim]Run 'tweek config interactive' to customize[/dim]")

    # ─────────────────────────────────────────────────────────────
    # Linux: Prompt for firejail installation
    # ─────────────────────────────────────────────────────────────
    if IS_LINUX:
        caps = get_capabilities()
        if not caps.sandbox_available:
            if with_sandbox or interactive:
                from tweek.sandbox.linux import prompt_install_firejail
                prompt_install_firejail(console)
            else:
                console.print("\n[yellow]Note:[/yellow] Sandbox (firejail) not installed.")
                console.print(f"[dim]Install with: {caps.sandbox_install_hint}[/dim]")
                console.print("[dim]Or run 'tweek install --with-sandbox' to install now[/dim]")

    # ─────────────────────────────────────────────────────────────
    # Configure Tweek proxy if override was enabled
    # ─────────────────────────────────────────────────────────────
    if proxy_override_enabled:
        try:
            import yaml
            from tweek.proxy import TWEEK_DEFAULT_PORT

            proxy_config_path = tweek_dir / "config.yaml"

            # Load existing config or create new
            if proxy_config_path.exists():
                with open(proxy_config_path) as f:
                    tweek_config = yaml.safe_load(f) or {}
            else:
                tweek_config = {}

            # Enable proxy with override settings
            tweek_config["proxy"] = tweek_config.get("proxy", {})
            tweek_config["proxy"]["enabled"] = True
            tweek_config["proxy"]["port"] = TWEEK_DEFAULT_PORT
            tweek_config["proxy"]["override_moltbot"] = True
            tweek_config["proxy"]["auto_start"] = False  # User must explicitly start

            with open(proxy_config_path, "w") as f:
                yaml.dump(tweek_config, f, default_flow_style=False)

            console.print("\n[green]✓[/green] Proxy override configured")
            console.print(f"  [dim]Config saved to: {proxy_config_path}[/dim]")
            console.print("  [yellow]Run 'tweek proxy start' to begin intercepting API calls[/yellow]")
        except Exception as e:
            console.print(f"\n[yellow]Warning: Could not save proxy config: {e}[/yellow]")

    console.print("\n[green]Installation complete![/green]")
    console.print("[dim]Run 'tweek status' to verify installation[/dim]")
    console.print("[dim]Run 'tweek update' to get latest attack patterns[/dim]")
    console.print("[dim]Run 'tweek config list' to see security settings[/dim]")
    if proxy_override_enabled:
        console.print("[dim]Run 'tweek proxy start' to enable API interception[/dim]")


@main.command(
    epilog="""\b
Examples:
  tweek uninstall                        Remove from global installation
  tweek uninstall --scope project        Remove from current project only
  tweek uninstall --confirm              Skip confirmation prompt
"""
)
@click.option("--scope", type=click.Choice(["global", "project"]), default="global",
              help="Uninstall scope: global (~/.claude) or project (./.claude)")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def uninstall(scope: str, confirm: bool):
    """Remove Tweek hooks from Claude Code.

    Scope options:
        --scope global  : Remove from ~/.claude/ (affects all projects)
        --scope project : Remove from ./.claude/ (this project only)
    """
    import json

    console.print(TWEEK_BANNER, style="cyan")

    # Determine target directory based on scope
    if scope == "global":
        target = Path("~/.claude").expanduser()
    else:  # project
        target = Path.cwd() / ".claude"

    # Check if Tweek is installed at target
    settings_file = target / "settings.json"
    tweek_installed = False

    if settings_file.exists():
        try:
            with open(settings_file) as f:
                settings = json.load(f)
            if "hooks" in settings and "PreToolUse" in settings.get("hooks", {}):
                for hook_config in settings["hooks"]["PreToolUse"]:
                    for hook in hook_config.get("hooks", []):
                        if "tweek" in hook.get("command", "").lower():
                            tweek_installed = True
                            break
        except (json.JSONDecodeError, IOError):
            pass

    if not tweek_installed:
        console.print(f"[yellow]No Tweek installation found at {target}[/yellow]")
        return

    console.print(f"[bold]Found Tweek installation at:[/bold] {target}")
    console.print()

    if not confirm:
        if not click.confirm("[yellow]Remove Tweek hooks?[/yellow]"):
            console.print("[dim]Cancelled[/dim]")
            return

    # Remove hooks
    try:
        with open(settings_file) as f:
            settings = json.load(f)

        # Remove Tweek PreToolUse hooks
        if "hooks" in settings and "PreToolUse" in settings["hooks"]:
            # Filter out Tweek hooks
            pre_tool_hooks = settings["hooks"]["PreToolUse"]
            filtered_hooks = []
            for hook_config in pre_tool_hooks:
                filtered_inner = []
                for hook in hook_config.get("hooks", []):
                    if "tweek" not in hook.get("command", "").lower():
                        filtered_inner.append(hook)
                if filtered_inner:
                    hook_config["hooks"] = filtered_inner
                    filtered_hooks.append(hook_config)

            if filtered_hooks:
                settings["hooks"]["PreToolUse"] = filtered_hooks
            else:
                del settings["hooks"]["PreToolUse"]

            # Clean up empty hooks dict
            if not settings["hooks"]:
                del settings["hooks"]

        with open(settings_file, "w") as f:
            json.dump(settings, f, indent=2)

        console.print(f"[green]✓[/green] Removed Tweek hooks from: {target}")

    except Exception as e:
        console.print(f"[red]✗[/red] Failed to update {target}: {e}")

    console.print("\n[green]Uninstall complete![/green]")
    console.print("[dim]Tweek data directory (~/.tweek) was preserved. Remove manually if desired.[/dim]")


@main.command(
    epilog="""\b
Examples:
  tweek update                           Download/update attack patterns
  tweek update --check                   Check for updates without installing
"""
)
@click.option("--check", is_flag=True, help="Check for updates without installing")
def update(check: bool):
    """Update attack patterns from GitHub.

    Patterns are stored in ~/.tweek/patterns/ and can be updated
    independently of the Tweek application.

    All 116 patterns are included free. PRO tier adds LLM review,
    session analysis, and rate limiting.
    """
    import subprocess

    patterns_dir = Path("~/.tweek/patterns").expanduser()
    patterns_repo = "https://github.com/gettweek/tweek-patterns.git"

    console.print(TWEEK_BANNER, style="cyan")

    if not patterns_dir.exists():
        # First time: clone the repo
        if check:
            console.print("[yellow]Patterns not installed.[/yellow]")
            console.print(f"[dim]Run 'tweek update' to install from {patterns_repo}[/dim]")
            return

        console.print(f"[cyan]Installing patterns from {patterns_repo}...[/cyan]")

        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", patterns_repo, str(patterns_dir)],
                capture_output=True,
                text=True,
                check=True
            )
            console.print("[green]✓[/green] Patterns installed successfully")

            # Show pattern count
            patterns_file = patterns_dir / "patterns.yaml"
            if patterns_file.exists():
                import yaml
                with open(patterns_file) as f:
                    data = yaml.safe_load(f)
                count = data.get("pattern_count", len(data.get("patterns", [])))
                free_max = data.get("free_tier_max", 23)
                console.print(f"[dim]Installed {count} patterns ({free_max} free, {count - free_max} pro)[/dim]")

        except subprocess.CalledProcessError as e:
            console.print(f"[red]✗[/red] Failed to clone patterns: {e.stderr}")
            return
        except FileNotFoundError:
            console.print("[red]\u2717[/red] git not found.")
            console.print("  [dim]Hint: Install git from https://git-scm.com/downloads[/dim]")
            console.print("  [dim]On macOS: xcode-select --install[/dim]")
            return

    else:
        # Update existing repo
        if check:
            console.print("[cyan]Checking for pattern updates...[/cyan]")
            try:
                result = subprocess.run(
                    ["git", "-C", str(patterns_dir), "fetch", "--dry-run"],
                    capture_output=True,
                    text=True
                )
                # Check if there are updates
                result2 = subprocess.run(
                    ["git", "-C", str(patterns_dir), "status", "-uno"],
                    capture_output=True,
                    text=True
                )
                if "behind" in result2.stdout:
                    console.print("[yellow]Updates available.[/yellow]")
                    console.print("[dim]Run 'tweek update' to install[/dim]")
                else:
                    console.print("[green]✓[/green] Patterns are up to date")
            except Exception as e:
                console.print(f"[red]✗[/red] Failed to check for updates: {e}")
            return

        console.print("[cyan]Updating patterns...[/cyan]")

        try:
            result = subprocess.run(
                ["git", "-C", str(patterns_dir), "pull", "--ff-only"],
                capture_output=True,
                text=True,
                check=True
            )

            if "Already up to date" in result.stdout:
                console.print("[green]✓[/green] Patterns already up to date")
            else:
                console.print("[green]✓[/green] Patterns updated successfully")

                # Show what changed
                if result.stdout.strip():
                    console.print(f"[dim]{result.stdout.strip()}[/dim]")

        except subprocess.CalledProcessError as e:
            console.print(f"[red]✗[/red] Failed to update patterns: {e.stderr}")
            console.print("[dim]Try: rm -rf ~/.tweek/patterns && tweek update[/dim]")
            return

    # Show current version info
    patterns_file = patterns_dir / "patterns.yaml"
    if patterns_file.exists():
        import yaml
        try:
            with open(patterns_file) as f:
                data = yaml.safe_load(f)
            version = data.get("version", "?")
            count = data.get("pattern_count", len(data.get("patterns", [])))

            console.print()
            console.print(f"[cyan]Pattern version:[/cyan] {version}")
            console.print(f"[cyan]Total patterns:[/cyan] {count} (all included free)")

            # Check license for Pro features
            from tweek.licensing import get_license
            lic = get_license()
            if lic.is_pro:
                console.print(f"[cyan]Pro features:[/cyan] LLM review, session analysis, rate limiting")
            else:
                console.print()
                console.print(f"[dim]Upgrade to Pro for LLM review & session analysis: gettweek.com/pricing[/dim]")

        except Exception:
            pass


@main.command(
    epilog="""\b
Examples:
  tweek doctor                           Run all health checks
  tweek doctor --verbose                 Show detailed check information
  tweek doctor --json                    Output results as JSON for scripting
"""
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed check information")
@click.option("--json-output", "--json", "json_out", is_flag=True, help="Output results as JSON")
def doctor(verbose: bool, json_out: bool):
    """Run health checks on your Tweek installation.

    Checks hooks, configuration, patterns, database, vault, sandbox,
    license, MCP, proxy, and plugin integrity.
    """
    from tweek.diagnostics import run_health_checks
    from tweek.cli_helpers import print_doctor_results, print_doctor_json

    checks = run_health_checks(verbose=verbose)

    if json_out:
        print_doctor_json(checks)
    else:
        print_doctor_results(checks)


@main.command(
    epilog="""\b
Examples:
  tweek quickstart                       Launch interactive setup wizard
"""
)
def quickstart():
    """Interactive first-run setup wizard.

    Walks you through:
      1. Installing hooks (global or project scope)
      2. Choosing a security preset
      3. Verifying credential vault
      4. Optional MCP proxy setup
    """
    from tweek.config.manager import ConfigManager
    from tweek.cli_helpers import print_success, print_warning, spinner

    console.print(TWEEK_BANNER, style="cyan")
    console.print("[bold]Welcome to Tweek![/bold]")
    console.print()
    console.print("This wizard will help you set up Tweek step by step.")
    console.print("  1. Install hooks")
    console.print("  2. Choose a security preset")
    console.print("  3. Verify credential vault")
    console.print("  4. Optional MCP proxy")
    console.print()

    # Step 1: Install hooks
    console.print("[bold cyan]Step 1/4: Hook Installation[/bold cyan]")
    scope_choice = click.prompt(
        "Where should Tweek protect?",
        type=click.Choice(["global", "project", "both"]),
        default="global",
    )

    scopes = ["global", "project"] if scope_choice == "both" else [scope_choice]
    for s in scopes:
        try:
            _quickstart_install_hooks(s)
            print_success(f"Hooks installed ({s})")
        except Exception as e:
            print_warning(f"Could not install hooks ({s}): {e}")
    console.print()

    # Step 2: Security preset
    console.print("[bold cyan]Step 2/4: Security Preset[/bold cyan]")
    console.print("  [cyan]1.[/cyan] paranoid  \u2014 Block everything suspicious, prompt on risky")
    console.print("  [cyan]2.[/cyan] cautious  \u2014 Block dangerous, prompt on risky [dim](recommended)[/dim]")
    console.print("  [cyan]3.[/cyan] trusted   \u2014 Allow most operations, block only dangerous")
    console.print()

    preset_choice = click.prompt(
        "Select preset",
        type=click.Choice(["1", "2", "3"]),
        default="2",
    )
    preset_map = {"1": "paranoid", "2": "cautious", "3": "trusted"}
    preset_name = preset_map[preset_choice]

    try:
        cfg = ConfigManager()
        cfg.apply_preset(preset_name)
        print_success(f"Applied {preset_name} preset")
    except Exception as e:
        print_warning(f"Could not apply preset: {e}")
    console.print()

    # Step 3: Credential vault
    console.print("[bold cyan]Step 3/4: Credential Vault[/bold cyan]")
    try:
        from tweek.platform import get_capabilities
        caps = get_capabilities()
        if caps.vault_available:
            print_success(f"{caps.vault_backend} detected. No configuration needed.")
        else:
            print_warning("No vault backend available. Credentials will use fallback storage.")
    except Exception:
        print_warning("Could not check vault availability.")
    console.print()

    # Step 4: Optional MCP proxy
    console.print("[bold cyan]Step 4/4: MCP Proxy (optional)[/bold cyan]")
    setup_mcp = click.confirm("Set up MCP proxy for Claude Desktop?", default=False)
    if setup_mcp:
        try:
            import mcp  # noqa: F401
            console.print("[dim]MCP package available. Configure upstream servers in ~/.tweek/config.yaml[/dim]")
            console.print("[dim]Then run: tweek mcp proxy[/dim]")
        except ImportError:
            print_warning("MCP package not installed. Install with: pip install tweek[mcp]")
    else:
        console.print("[dim]Skipped.[/dim]")

    console.print()
    console.print("[bold green]Setup complete![/bold green]")
    console.print("  Run [cyan]tweek doctor[/cyan] to verify your installation")
    console.print("  Run [cyan]tweek status[/cyan] to see protection status")


def _quickstart_install_hooks(scope: str) -> None:
    """Install hooks for quickstart wizard (simplified version)."""
    import json

    if scope == "global":
        target_dir = Path("~/.claude").expanduser()
    else:
        target_dir = Path.cwd() / ".claude"

    hooks_dir = target_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    settings_path = target_dir / "settings.json"
    settings = {}
    if settings_path.exists():
        try:
            with open(settings_path) as f:
                settings = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass

    if "hooks" not in settings:
        settings["hooks"] = {}

    hook_entry = {
        "type": "command",
        "command": "tweek hook pre-tool-use $TOOL_NAME",
    }

    for hook_type in ["PreToolUse"]:
        if hook_type not in settings["hooks"]:
            settings["hooks"][hook_type] = []

        # Check if tweek hooks already present
        already_installed = False
        for hook_config in settings["hooks"][hook_type]:
            for h in hook_config.get("hooks", []):
                if "tweek" in h.get("command", "").lower():
                    already_installed = True
                    break

        if not already_installed:
            settings["hooks"][hook_type].append({
                "matcher": "",
                "hooks": [hook_entry],
            })

    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)


@main.group()
def config():
    """Configure Tweek security policies."""
    pass


@config.command("list",
    epilog="""\b
Examples:
  tweek config list                      List all tools and skills
  tweek config list --tools              Show only tool security tiers
  tweek config list --skills             Show only skill security tiers
  tweek config list --summary            Show tier counts and overrides summary
"""
)
@click.option("--tools", "show_tools", is_flag=True, help="Show tools only")
@click.option("--skills", "show_skills", is_flag=True, help="Show skills only")
@click.option("--summary", is_flag=True, help="Show configuration summary instead of full list")
def config_list(show_tools: bool, show_skills: bool, summary: bool):
    """List all tools and skills with their security tiers."""
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()

    # Handle summary mode
    if summary:
        # Count by tier
        tool_tiers = {}
        for tool in cfg.list_tools():
            tier = tool.tier.value
            tool_tiers[tier] = tool_tiers.get(tier, 0) + 1

        skill_tiers = {}
        for skill in cfg.list_skills():
            tier = skill.tier.value
            skill_tiers[tier] = skill_tiers.get(tier, 0) + 1

        # User overrides
        user_config = cfg.export_config("user")
        user_tools = user_config.get("tools", {})
        user_skills = user_config.get("skills", {})

        summary_text = f"[cyan]Default Tier:[/cyan] {cfg.get_default_tier().value}\n\n"

        summary_text += "[cyan]Tools by Tier:[/cyan]\n"
        for tier in ["safe", "default", "risky", "dangerous"]:
            count = tool_tiers.get(tier, 0)
            if count:
                summary_text += f"  {tier}: {count}\n"

        summary_text += "\n[cyan]Skills by Tier:[/cyan]\n"
        for tier in ["safe", "default", "risky", "dangerous"]:
            count = skill_tiers.get(tier, 0)
            if count:
                summary_text += f"  {tier}: {count}\n"

        if user_tools or user_skills:
            summary_text += "\n[cyan]User Overrides:[/cyan]\n"
            for tool_name, tier in user_tools.items():
                summary_text += f"  {tool_name}: {tier}\n"
            for skill_name, tier in user_skills.items():
                summary_text += f"  {skill_name}: {tier}\n"
        else:
            summary_text += "\n[cyan]User Overrides:[/cyan] (none)"

        console.print(Panel.fit(summary_text, title="Tweek Configuration"))
        return

    # Default to showing both if neither specified
    if not show_tools and not show_skills:
        show_tools = show_skills = True

    tier_styles = {
        "safe": "green",
        "default": "blue",
        "risky": "yellow",
        "dangerous": "red",
    }

    source_styles = {
        "default": "dim",
        "user": "cyan",
        "project": "magenta",
    }

    if show_tools:
        table = Table(title="Tool Security Tiers")
        table.add_column("Tool", style="bold")
        table.add_column("Tier")
        table.add_column("Source", style="dim")
        table.add_column("Description")

        for tool in cfg.list_tools():
            tier_style = tier_styles.get(tool.tier.value, "white")
            source_style = source_styles.get(tool.source, "white")
            table.add_row(
                tool.name,
                f"[{tier_style}]{tool.tier.value}[/{tier_style}]",
                f"[{source_style}]{tool.source}[/{source_style}]",
                tool.description or ""
            )

        console.print(table)
        console.print()

    if show_skills:
        table = Table(title="Skill Security Tiers")
        table.add_column("Skill", style="bold")
        table.add_column("Tier")
        table.add_column("Source", style="dim")
        table.add_column("Description")

        for skill in cfg.list_skills():
            tier_style = tier_styles.get(skill.tier.value, "white")
            source_style = source_styles.get(skill.source, "white")
            table.add_row(
                skill.name,
                f"[{tier_style}]{skill.tier.value}[/{tier_style}]",
                f"[{source_style}]{skill.source}[/{source_style}]",
                skill.description or ""
            )

        console.print(table)

    console.print("\n[dim]Tiers: safe (no checks) → default (regex) → risky (+LLM) → dangerous (+sandbox)[/dim]")
    console.print("[dim]Sources: default (built-in), user (~/.tweek/config.yaml), project (.tweek/config.yaml)[/dim]")


@config.command("set",
    epilog="""\b
Examples:
  tweek config set --tool Bash --tier dangerous       Mark Bash as dangerous
  tweek config set --skill web-fetch --tier risky     Set skill to risky tier
  tweek config set --tier cautious                    Set default tier for all
  tweek config set --tool Edit --tier safe --scope project   Project-level override
"""
)
@click.option("--skill", help="Skill name to configure")
@click.option("--tool", help="Tool name to configure")
@click.option("--tier", type=click.Choice(["safe", "default", "risky", "dangerous"]), required=True,
              help="Security tier to set")
@click.option("--scope", type=click.Choice(["user", "project"]), default="user",
              help="Config scope (user=global, project=this directory)")
def config_set(skill: str, tool: str, tier: str, scope: str):
    """Set security tier for a skill or tool."""
    from tweek.config.manager import ConfigManager, SecurityTier

    cfg = ConfigManager()
    tier_enum = SecurityTier.from_string(tier)

    if skill:
        cfg.set_skill_tier(skill, tier_enum, scope=scope)
        console.print(f"[green]✓[/green] Set skill '{skill}' to [bold]{tier}[/bold] tier ({scope} config)")
    elif tool:
        cfg.set_tool_tier(tool, tier_enum, scope=scope)
        console.print(f"[green]✓[/green] Set tool '{tool}' to [bold]{tier}[/bold] tier ({scope} config)")
    else:
        cfg.set_default_tier(tier_enum, scope=scope)
        console.print(f"[green]✓[/green] Set default tier to [bold]{tier}[/bold] ({scope} config)")


@config.command("preset",
    epilog="""\b
Examples:
  tweek config preset paranoid           Maximum security, prompt for everything
  tweek config preset cautious           Balanced security (recommended)
  tweek config preset trusted            Minimal prompts, trust AI decisions
  tweek config preset paranoid --scope project   Apply preset to project only
"""
)
@click.argument("preset_name", type=click.Choice(["paranoid", "cautious", "trusted"]))
@click.option("--scope", type=click.Choice(["user", "project"]), default="user")
def config_preset(preset_name: str, scope: str):
    """Apply a configuration preset.

    Presets:
        paranoid  - Maximum security, prompt for everything
        cautious  - Balanced security (recommended)
        trusted   - Minimal prompts, trust AI decisions
    """
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()
    cfg.apply_preset(preset_name, scope=scope)

    console.print(f"[green]✓[/green] Applied [bold]{preset_name}[/bold] preset ({scope} config)")

    if preset_name == "paranoid":
        console.print("[dim]All tools require screening, Bash commands always sandboxed[/dim]")
    elif preset_name == "cautious":
        console.print("[dim]Balanced: read-only tools safe, Bash dangerous[/dim]")
    elif preset_name == "trusted":
        console.print("[dim]Minimal prompts: only high-risk patterns trigger alerts[/dim]")


@config.command("reset",
    epilog="""\b
Examples:
  tweek config reset --tool Bash         Reset Bash to default tier
  tweek config reset --skill web-fetch   Reset a skill to default tier
  tweek config reset --all               Reset all user configuration
  tweek config reset --all --confirm     Reset all without confirmation prompt
"""
)
@click.option("--skill", help="Reset specific skill to default")
@click.option("--tool", help="Reset specific tool to default")
@click.option("--all", "reset_all", is_flag=True, help="Reset all user configuration")
@click.option("--scope", type=click.Choice(["user", "project"]), default="user")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def config_reset(skill: str, tool: str, reset_all: bool, scope: str, confirm: bool):
    """Reset configuration to defaults."""
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()

    if reset_all:
        if not confirm and not click.confirm(f"Reset ALL {scope} configuration?"):
            console.print("[dim]Cancelled[/dim]")
            return
        cfg.reset_all(scope=scope)
        console.print(f"[green]✓[/green] Reset all {scope} configuration to defaults")
    elif skill:
        if cfg.reset_skill(skill, scope=scope):
            console.print(f"[green]✓[/green] Reset skill '{skill}' to default")
        else:
            console.print(f"[yellow]![/yellow] Skill '{skill}' has no {scope} override")
    elif tool:
        if cfg.reset_tool(tool, scope=scope):
            console.print(f"[green]✓[/green] Reset tool '{tool}' to default")
        else:
            console.print(f"[yellow]![/yellow] Tool '{tool}' has no {scope} override")
    else:
        console.print("[red]Specify --skill, --tool, or --all[/red]")


@config.command("validate",
    epilog="""\b
Examples:
  tweek config validate                  Validate merged configuration
  tweek config validate --scope user     Validate only user-level config
  tweek config validate --scope project  Validate only project-level config
  tweek config validate --json           Output validation results as JSON
"""
)
@click.option("--scope", type=click.Choice(["user", "project", "merged"]), default="merged",
              help="Which config scope to validate")
@click.option("--json-output", "--json", "json_out", is_flag=True, help="Output as JSON")
def config_validate(scope: str, json_out: bool):
    """Validate configuration for errors and typos.

    Checks for unknown keys, invalid tier values, unknown tool/skill names,
    and suggests corrections for typos.
    """
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()
    issues = cfg.validate_config(scope=scope)

    if json_out:
        import json as json_mod
        output = [
            {
                "level": i.level,
                "key": i.key,
                "message": i.message,
                "suggestion": i.suggestion,
            }
            for i in issues
        ]
        console.print_json(json_mod.dumps(output, indent=2))
        return

    console.print()
    console.print("[bold]Configuration Validation[/bold]")
    console.print("\u2500" * 40)
    console.print(f"[dim]Scope: {scope}[/dim]")
    console.print()

    if not issues:
        tools = cfg.list_tools()
        skills = cfg.list_skills()
        console.print(f"  [green]OK[/green]  Configuration valid ({len(tools)} tools, {len(skills)} skills)")
        console.print()
        return

    errors = [i for i in issues if i.level == "error"]
    warnings = [i for i in issues if i.level == "warning"]

    level_styles = {
        "error": "[red]ERROR[/red]",
        "warning": "[yellow]WARN[/yellow] ",
        "info": "[dim]INFO[/dim] ",
    }

    for issue in issues:
        style = level_styles.get(issue.level, "[dim]???[/dim]  ")
        msg = f"  {style}  {issue.key} \u2192 {issue.message}"
        if issue.suggestion:
            msg += f" {issue.suggestion}"
        console.print(msg)

    console.print()
    parts = []
    if errors:
        parts.append(f"{len(errors)} error{'s' if len(errors) != 1 else ''}")
    if warnings:
        parts.append(f"{len(warnings)} warning{'s' if len(warnings) != 1 else ''}")
    console.print(f"  Result: {', '.join(parts)}")
    console.print()


@config.command("diff",
    epilog="""\b
Examples:
  tweek config diff paranoid             Show changes if paranoid preset applied
  tweek config diff cautious             Show changes if cautious preset applied
  tweek config diff trusted              Show changes if trusted preset applied
"""
)
@click.argument("preset_name", type=click.Choice(["paranoid", "cautious", "trusted"]))
def config_diff(preset_name: str):
    """Show what would change if a preset were applied.

    Compare your current configuration against a preset to see
    exactly which settings would be modified.
    """
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()

    try:
        changes = cfg.diff_preset(preset_name)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        return

    console.print()
    console.print(f"[bold]Changes if '{preset_name}' preset is applied:[/bold]")
    console.print("\u2500" * 50)

    if not changes:
        console.print()
        console.print("  [green]No changes[/green] \u2014 your config already matches this preset.")
        console.print()
        return

    table = Table(show_header=True, show_edge=False, pad_edge=False)
    table.add_column("Setting", style="cyan", min_width=25)
    table.add_column("Current", min_width=12)
    table.add_column("", min_width=3)
    table.add_column("New", min_width=12)

    tier_colors = {"safe": "green", "default": "white", "risky": "yellow", "dangerous": "red"}

    for change in changes:
        cur_color = tier_colors.get(str(change.current_value), "white")
        new_color = tier_colors.get(str(change.new_value), "white")
        table.add_row(
            change.key,
            f"[{cur_color}]{change.current_value}[/{cur_color}]",
            "\u2192",
            f"[{new_color}]{change.new_value}[/{new_color}]",
        )

    console.print()
    console.print(table)
    console.print()
    console.print(f"  {len(changes)} change{'s' if len(changes) != 1 else ''} would be made. "
                  f"Apply with: [cyan]tweek config preset {preset_name}[/cyan]")
    console.print()


@main.group()
def vault():
    """Manage credentials in secure storage (Keychain on macOS, Secret Service on Linux)."""
    pass


@vault.command("store",
    epilog="""\b
Examples:
  tweek vault store myskill API_KEY sk-abc123      Store an API key
  tweek vault store deploy AWS_SECRET s3cr3t       Store a deployment secret
"""
)
@click.argument("skill")
@click.argument("key")
@click.argument("value")
def vault_store(skill: str, key: str, value: str):
    """Store a credential securely for a skill."""
    from tweek.vault import get_vault, VAULT_AVAILABLE
    from tweek.platform import get_capabilities

    if not VAULT_AVAILABLE:
        console.print("[red]\u2717[/red] Vault not available.")
        console.print("  [dim]Hint: Install keyring support: pip install keyring[/dim]")
        console.print("  [dim]On macOS, keyring uses Keychain. On Linux, install gnome-keyring or kwallet.[/dim]")
        return

    caps = get_capabilities()

    try:
        vault_instance = get_vault()
        if vault_instance.store(skill, key, value):
            console.print(f"[green]\u2713[/green] Stored {key} for skill '{skill}'")
            console.print(f"[dim]Backend: {caps.vault_backend}[/dim]")
        else:
            console.print(f"[red]\u2717[/red] Failed to store credential")
            console.print("  [dim]Hint: Check your keyring backend is unlocked and accessible[/dim]")
    except Exception as e:
        console.print(f"[red]\u2717[/red] Failed to store credential: {e}")
        console.print("  [dim]Hint: Check your keyring backend is unlocked and accessible[/dim]")


@vault.command("get",
    epilog="""\b
Examples:
  tweek vault get myskill API_KEY        Retrieve a stored credential
  tweek vault get deploy AWS_SECRET      Retrieve a deployment secret
"""
)
@click.argument("skill")
@click.argument("key")
def vault_get(skill: str, key: str):
    """Retrieve a credential from secure storage."""
    from tweek.vault import get_vault, VAULT_AVAILABLE

    if not VAULT_AVAILABLE:
        console.print("[red]\u2717[/red] Vault not available.")
        console.print("  [dim]Hint: Install keyring support: pip install keyring[/dim]")
        return

    vault_instance = get_vault()
    value = vault_instance.get(skill, key)

    if value is not None:
        console.print(f"[yellow]GAH![/yellow] Credential access logged")
        console.print(value)
    else:
        console.print(f"[red]\u2717[/red] Credential not found: {key} for skill '{skill}'")
        console.print("  [dim]Hint: Store it with: tweek vault store {skill} {key} <value>[/dim]".format(skill=skill, key=key))


@vault.command("migrate-env",
    epilog="""\b
Examples:
  tweek vault migrate-env --skill myapp                Migrate .env to vault
  tweek vault migrate-env --skill myapp --dry-run      Preview without changes
  tweek vault migrate-env --skill deploy --env-file .env.production   Migrate specific file
"""
)
@click.option("--dry-run", is_flag=True, help="Show what would be migrated without doing it")
@click.option("--env-file", default=".env", help="Path to .env file")
@click.option("--skill", required=True, help="Skill name to store credentials under")
def vault_migrate_env(dry_run: bool, env_file: str, skill: str):
    """Migrate credentials from .env file to secure storage."""
    from tweek.vault import get_vault, migrate_env_to_vault, VAULT_AVAILABLE

    if not VAULT_AVAILABLE:
        console.print("[red]✗[/red] Vault not available. Install keyring: pip install keyring")
        return

    env_path = Path(env_file)
    console.print(f"[cyan]Scanning {env_path} for credentials...[/cyan]")

    if dry_run:
        console.print("\n[yellow]DRY RUN - No changes will be made[/yellow]\n")

    try:
        vault_instance = get_vault()
        results = migrate_env_to_vault(env_path, skill, vault_instance, dry_run=dry_run)

        if results:
            console.print(f"\n[green]{'Would migrate' if dry_run else 'Migrated'}:[/green]")
            for key, success in results:
                status = "✓" if success else "✗"
                console.print(f"  {status} {key}")
            successful = sum(1 for _, s in results if s)
            console.print(f"\n[green]✓[/green] {'Would migrate' if dry_run else 'Migrated'} {successful} credentials to skill '{skill}'")
        else:
            console.print("[dim]No credentials found to migrate[/dim]")

    except Exception as e:
        console.print(f"[red]✗[/red] Migration failed: {e}")


@vault.command("delete",
    epilog="""\b
Examples:
  tweek vault delete myskill API_KEY     Delete a stored credential
  tweek vault delete deploy AWS_SECRET   Remove a deployment secret
"""
)
@click.argument("skill")
@click.argument("key")
def vault_delete(skill: str, key: str):
    """Delete a credential from secure storage."""
    from tweek.vault import get_vault, VAULT_AVAILABLE

    if not VAULT_AVAILABLE:
        console.print("[red]✗[/red] Vault not available. Install keyring: pip install keyring")
        return

    vault_instance = get_vault()
    deleted = vault_instance.delete(skill, key)

    if deleted:
        console.print(f"[green]✓[/green] Deleted {key} from skill '{skill}'")
    else:
        console.print(f"[yellow]![/yellow] Credential not found: {key} for skill '{skill}'")


# ============================================================
# LICENSE COMMANDS
# ============================================================

@main.group()
def license():
    """Manage Tweek license and features."""
    pass


@license.command("status",
    epilog="""\b
Examples:
  tweek license status                   Show license tier and features
"""
)
def license_status():
    """Show current license status and available features."""
    from tweek.licensing import get_license, TIER_FEATURES, Tier

    console.print(TWEEK_BANNER, style="cyan")

    lic = get_license()
    info = lic.info

    # License info
    tier_colors = {
        Tier.FREE: "white",
        Tier.PRO: "cyan",
    }

    tier_color = tier_colors.get(lic.tier, "white")
    console.print(f"[bold]License Tier:[/bold] [{tier_color}]{lic.tier.value.upper()}[/{tier_color}]")

    if info:
        console.print(f"[dim]Licensed to: {info.email}[/dim]")
        if info.expires_at:
            from datetime import datetime
            exp_date = datetime.fromtimestamp(info.expires_at).strftime("%Y-%m-%d")
            if info.is_expired:
                console.print(f"[red]Expired: {exp_date}[/red]")
            else:
                console.print(f"[dim]Expires: {exp_date}[/dim]")
        else:
            console.print("[dim]Expires: Never[/dim]")
    console.print()

    # Features table
    table = Table(title="Feature Availability")
    table.add_column("Feature", style="cyan")
    table.add_column("Status")
    table.add_column("Tier Required")

    # Collect all features and their required tiers
    feature_tiers = {}
    for tier in [Tier.FREE, Tier.PRO]:
        for feature in TIER_FEATURES.get(tier, []):
            feature_tiers[feature] = tier

    for feature, required_tier in feature_tiers.items():
        has_it = lic.has_feature(feature)
        status = "[green]✓[/green]" if has_it else "[dim]○[/dim]"
        tier_display = required_tier.value.upper()
        if required_tier == Tier.PRO:
            tier_display = f"[cyan]{tier_display}[/cyan]"

        table.add_row(feature, status, tier_display)

    console.print(table)

    if lic.tier == Tier.FREE:
        console.print()
        console.print("[yellow]Upgrade to Pro for advanced features:[/yellow]")
        console.print("[dim]https://gettweek.com/pricing[/dim]")


@license.command("activate",
    epilog="""\b
Examples:
  tweek license activate TWEEK-PRO-XXXX-XXXX   Activate a Pro license key
"""
)
@click.argument("license_key")
def license_activate(license_key: str):
    """Activate a license key."""
    from tweek.licensing import get_license

    lic = get_license()
    success, message = lic.activate(license_key)

    if success:
        console.print(f"[green]✓[/green] {message}")
        console.print()
        console.print("[dim]Run 'tweek license status' to see available features[/dim]")
    else:
        console.print(f"[red]✗[/red] {message}")


@license.command("deactivate",
    epilog="""\b
Examples:
  tweek license deactivate               Deactivate license (with prompt)
  tweek license deactivate --confirm     Deactivate without confirmation
"""
)
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def license_deactivate(confirm: bool):
    """Remove current license and revert to FREE tier."""
    from tweek.licensing import get_license

    if not confirm:
        if not click.confirm("[yellow]Deactivate license and revert to FREE tier?[/yellow]"):
            console.print("[dim]Cancelled[/dim]")
            return

    lic = get_license()
    success, message = lic.deactivate()

    if success:
        console.print(f"[green]✓[/green] {message}")
    else:
        console.print(f"[red]✗[/red] {message}")


# ============================================================
# LOGS COMMANDS
# ============================================================

@main.group()
def logs():
    """View and manage security logs."""
    pass


@logs.command("show",
    epilog="""\b
Examples:
  tweek logs show                        Show last 20 security events
  tweek logs show -n 50                  Show last 50 events
  tweek logs show --type block           Filter by event type
  tweek logs show --blocked              Show only blocked/flagged events
  tweek logs show --stats                Show security statistics summary
  tweek logs show --stats --days 30      Statistics for the last 30 days
"""
)
@click.option("--limit", "-n", default=20, help="Number of events to show")
@click.option("--type", "-t", "event_type", help="Filter by event type")
@click.option("--tool", help="Filter by tool name")
@click.option("--blocked", is_flag=True, help="Show only blocked/flagged events")
@click.option("--stats", is_flag=True, help="Show security statistics instead of events")
@click.option("--days", "-d", default=7, help="Number of days to analyze (with --stats)")
def logs_show(limit: int, event_type: str, tool: str, blocked: bool, stats: bool, days: int):
    """Show recent security events."""
    from tweek.logging.security_log import get_logger

    console.print(TWEEK_BANNER, style="cyan")

    logger = get_logger()

    # Handle stats mode
    if stats:
        stat_data = logger.get_stats(days=days)

        console.print(Panel.fit(
            f"[cyan]Period:[/cyan] Last {days} days\n"
            f"[cyan]Total Events:[/cyan] {stat_data['total_events']}",
            title="Security Statistics"
        ))

        # Decisions breakdown
        if stat_data['by_decision']:
            table = Table(title="Decisions")
            table.add_column("Decision", style="cyan")
            table.add_column("Count", justify="right")

            decision_styles = {"allow": "green", "block": "red", "ask": "yellow", "deny": "red"}
            for decision, count in stat_data['by_decision'].items():
                style = decision_styles.get(decision, "white")
                table.add_row(f"[{style}]{decision}[/{style}]", str(count))

            console.print(table)
            console.print()

        # Top triggered patterns
        if stat_data['top_patterns']:
            table = Table(title="Top Triggered Patterns")
            table.add_column("Pattern", style="cyan")
            table.add_column("Severity")
            table.add_column("Count", justify="right")

            severity_styles = {"critical": "red", "high": "yellow", "medium": "blue", "low": "dim"}
            for pattern in stat_data['top_patterns']:
                sev = pattern['severity'] or "unknown"
                style = severity_styles.get(sev, "white")
                table.add_row(
                    pattern['name'] or "unknown",
                    f"[{style}]{sev}[/{style}]",
                    str(pattern['count'])
                )

            console.print(table)
            console.print()

        # By tool
        if stat_data['by_tool']:
            table = Table(title="Events by Tool")
            table.add_column("Tool", style="green")
            table.add_column("Count", justify="right")

            for tool_name, count in stat_data['by_tool'].items():
                table.add_row(tool_name, str(count))

            console.print(table)
        return

    from tweek.logging.security_log import EventType

    if blocked:
        events = logger.get_blocked_commands(limit=limit)
        title = "Recent Blocked/Flagged Commands"
    else:
        et = None
        if event_type:
            try:
                et = EventType(event_type)
            except ValueError:
                console.print(f"[red]Unknown event type: {event_type}[/red]")
                console.print(f"[dim]Valid types: {', '.join(e.value for e in EventType)}[/dim]")
                return

        events = logger.get_recent_events(limit=limit, event_type=et, tool_name=tool)
        title = "Recent Security Events"

    if not events:
        console.print("[yellow]No events found[/yellow]")
        return

    table = Table(title=title)
    table.add_column("Time", style="dim")
    table.add_column("Type", style="cyan")
    table.add_column("Tool", style="green")
    table.add_column("Tier")
    table.add_column("Decision")
    table.add_column("Pattern/Reason", max_width=30)

    decision_styles = {
        "allow": "green",
        "block": "red",
        "ask": "yellow",
        "deny": "red",
    }

    for event in events:
        timestamp = event.get("timestamp", "")
        if timestamp:
            # Format timestamp nicely
            try:
                dt = datetime.fromisoformat(timestamp)
                timestamp = dt.strftime("%m/%d %H:%M:%S")
            except (ValueError, TypeError):
                pass

        decision = event.get("decision", "")
        decision_style = decision_styles.get(decision, "white")

        reason = event.get("pattern_name") or event.get("decision_reason", "")
        if len(str(reason)) > 30:
            reason = str(reason)[:27] + "..."

        table.add_row(
            timestamp,
            event.get("event_type", ""),
            event.get("tool_name", ""),
            event.get("tier", ""),
            f"[{decision_style}]{decision}[/{decision_style}]" if decision else "",
            str(reason)
        )

    console.print(table)
    console.print(f"\n[dim]Showing {len(events)} events. Use --limit to see more.[/dim]")


@logs.command("export",
    epilog="""\b
Examples:
  tweek logs export                      Export all logs to tweek_security_log.csv
  tweek logs export --days 7             Export only the last 7 days
  tweek logs export -o audit.csv         Export to a custom file path
  tweek logs export --days 30 -o monthly.csv   Last 30 days to custom file
"""
)
@click.option("--days", "-d", type=int, help="Limit to last N days")
@click.option("--output", "-o", default="tweek_security_log.csv", help="Output file path")
def logs_export(days: int, output: str):
    """Export security logs to CSV."""
    from tweek.logging.security_log import get_logger

    logger = get_logger()
    output_path = Path(output)

    count = logger.export_csv(output_path, days=days)

    if count > 0:
        console.print(f"[green]✓[/green] Exported {count} events to {output_path}")
    else:
        console.print("[yellow]No events to export[/yellow]")


@logs.command("clear",
    epilog="""\b
Examples:
  tweek logs clear                       Clear all security logs (with prompt)
  tweek logs clear --days 30             Clear logs older than 30 days
  tweek logs clear --confirm             Clear all logs without confirmation
"""
)
@click.option("--days", "-d", type=int, help="Clear events older than N days")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def logs_clear(days: int, confirm: bool):
    """Clear security logs."""
    from tweek.logging.security_log import get_logger

    if not confirm:
        if days:
            msg = f"Clear all events older than {days} days?"
        else:
            msg = "Clear ALL security logs?"

        if not click.confirm(f"[yellow]{msg}[/yellow]"):
            console.print("[dim]Cancelled[/dim]")
            return

    logger = get_logger()

    # Note: Would need to add a clear method to SecurityLogger
    console.print("[yellow]Log clearing not yet implemented[/yellow]")


# ============================================================
# PROXY COMMANDS (Optional - requires pip install tweek[proxy])
# ============================================================

@main.group()
def proxy():
    """LLM API security proxy for universal protection.

    The proxy intercepts LLM API traffic and screens for dangerous tool calls.
    Works with any application that calls Anthropic, OpenAI, or other LLM APIs.

    \b
    Install dependencies: pip install tweek[proxy]
    Quick start:
        tweek proxy start       # Start the proxy
        tweek proxy trust       # Install CA certificate
        tweek proxy wrap moltbot "npm start"  # Wrap an app
    """
    pass


@proxy.command("start",
    epilog="""\b
Examples:
  tweek proxy start                      Start proxy on default port (9877)
  tweek proxy start --port 8080          Start proxy on custom port
  tweek proxy start --foreground         Run in foreground for debugging
  tweek proxy start --log-only           Log traffic without blocking
"""
)
@click.option("--port", "-p", default=9877, help="Port for proxy to listen on")
@click.option("--web-port", type=int, help="Port for web interface (disabled by default)")
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (for debugging)")
@click.option("--log-only", is_flag=True, help="Log only, don't block dangerous requests")
def proxy_start(port: int, web_port: int, foreground: bool, log_only: bool):
    """Start the Tweek LLM security proxy."""
    from tweek.proxy import PROXY_AVAILABLE, PROXY_MISSING_DEPS

    if not PROXY_AVAILABLE:
        console.print("[red]\u2717[/red] Proxy dependencies not installed.")
        console.print("  [dim]Hint: Install with: pip install tweek[proxy][/dim]")
        console.print("  [dim]This adds mitmproxy for HTTP(S) interception.[/dim]")
        return

    from tweek.proxy.server import start_proxy

    console.print(f"[cyan]Starting Tweek proxy on port {port}...[/cyan]")

    success, message = start_proxy(
        port=port,
        web_port=web_port,
        log_only=log_only,
        foreground=foreground,
    )

    if success:
        console.print(f"[green]✓[/green] {message}")
        console.print()
        console.print("[bold]To use the proxy:[/bold]")
        console.print(f"  export HTTPS_PROXY=http://127.0.0.1:{port}")
        console.print(f"  export HTTP_PROXY=http://127.0.0.1:{port}")
        console.print()
        console.print("[dim]Or use 'tweek proxy wrap' to create a wrapper script[/dim]")
    else:
        console.print(f"[red]✗[/red] {message}")


@proxy.command("stop",
    epilog="""\b
Examples:
  tweek proxy stop                       Stop the running proxy server
"""
)
def proxy_stop():
    """Stop the Tweek LLM security proxy."""
    from tweek.proxy import PROXY_AVAILABLE

    if not PROXY_AVAILABLE:
        console.print("[red]✗[/red] Proxy dependencies not installed.")
        return

    from tweek.proxy.server import stop_proxy

    success, message = stop_proxy()

    if success:
        console.print(f"[green]✓[/green] {message}")
    else:
        console.print(f"[yellow]![/yellow] {message}")


@proxy.command("trust",
    epilog="""\b
Examples:
  tweek proxy trust                      Install CA certificate for HTTPS interception
"""
)
def proxy_trust():
    """Install the proxy CA certificate in system trust store.

    This is required for HTTPS interception to work. The certificate
    is generated locally and only used for local proxy traffic.
    """
    from tweek.proxy import PROXY_AVAILABLE

    if not PROXY_AVAILABLE:
        console.print("[red]✗[/red] Proxy dependencies not installed.")
        console.print("[dim]Run: pip install tweek\\[proxy][/dim]")
        return

    from tweek.proxy.server import install_ca_certificate, get_proxy_info

    info = get_proxy_info()

    console.print("[bold]Tweek Proxy Certificate Installation[/bold]")
    console.print()
    console.print("This will install a local CA certificate to enable HTTPS interception.")
    console.print("The certificate is generated on YOUR machine and never transmitted.")
    console.print()
    console.print(f"[dim]Certificate location: {info['ca_cert']}[/dim]")
    console.print()

    if not click.confirm("Install certificate? (requires admin password)"):
        console.print("[dim]Cancelled[/dim]")
        return

    success, message = install_ca_certificate()

    if success:
        console.print(f"[green]✓[/green] {message}")
    else:
        console.print(f"[red]✗[/red] {message}")


@proxy.command("config",
    epilog="""\b
Examples:
  tweek proxy config --enabled           Enable proxy in configuration
  tweek proxy config --disabled          Disable proxy in configuration
  tweek proxy config --enabled --port 8080   Enable proxy on custom port
"""
)
@click.option("--enabled", "set_enabled", is_flag=True, help="Enable proxy in configuration")
@click.option("--disabled", "set_disabled", is_flag=True, help="Disable proxy in configuration")
@click.option("--port", "-p", default=9877, help="Port for proxy")
def proxy_config(set_enabled, set_disabled, port):
    """Configure proxy settings."""
    if not set_enabled and not set_disabled:
        console.print("[red]Specify --enabled or --disabled[/red]")
        return

    import yaml
    config_path = Path.home() / ".tweek" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)

    config = {}
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
        except Exception:
            pass

    if set_enabled:
        config["proxy"] = {
            "enabled": True,
            "port": port,
            "block_mode": True,
            "log_only": False,
        }

        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)

        console.print(f"[green]✓[/green] Proxy mode enabled (port {port})")
        console.print("[dim]Run 'tweek proxy start' to start the proxy[/dim]")

    elif set_disabled:
        if "proxy" in config:
            config["proxy"]["enabled"] = False

            with open(config_path, "w") as f:
                yaml.dump(config, f, default_flow_style=False)

        console.print("[green]✓[/green] Proxy mode disabled")


@proxy.command("wrap",
    epilog="""\b
Examples:
  tweek proxy wrap moltbot "npm start"                     Wrap a Node.js app
  tweek proxy wrap cursor "/Applications/Cursor.app/Contents/MacOS/Cursor"
  tweek proxy wrap myapp "python serve.py" -o run.sh       Custom output path
  tweek proxy wrap myapp "npm start" --port 8080           Use custom proxy port
"""
)
@click.argument("app_name")
@click.argument("command")
@click.option("--output", "-o", help="Output script path (default: ./run-{app_name}-protected.sh)")
@click.option("--port", "-p", default=9877, help="Proxy port")
def proxy_wrap(app_name: str, command: str, output: str, port: int):
    """Generate a wrapper script to run an app through the proxy."""
    from tweek.proxy.server import generate_wrapper_script

    if output:
        output_path = Path(output)
    else:
        output_path = Path(f"./run-{app_name}-protected.sh")

    script = generate_wrapper_script(command, port=port, output_path=output_path)

    console.print(f"[green]✓[/green] Created wrapper script: {output_path}")
    console.print()
    console.print("[bold]Usage:[/bold]")
    console.print(f"  chmod +x {output_path}")
    console.print(f"  ./{output_path.name}")
    console.print()
    console.print("[dim]The script will:[/dim]")
    console.print("[dim]  1. Start Tweek proxy if not running[/dim]")
    console.print("[dim]  2. Set proxy environment variables[/dim]")
    console.print(f"[dim]  3. Run: {command}[/dim]")


@proxy.command("setup",
    epilog="""\b
Examples:
  tweek proxy setup                      Launch interactive proxy setup wizard
"""
)
def proxy_setup():
    """Interactive setup wizard for the HTTP proxy.

    Walks through:
      1. Detecting LLM tools to protect
      2. Generating and trusting CA certificate
      3. Configuring shell environment variables
    """
    from tweek.cli_helpers import print_success, print_warning, print_error, spinner

    console.print()
    console.print("[bold]HTTP Proxy Setup[/bold]")
    console.print("\u2500" * 30)
    console.print()

    # Check dependencies
    try:
        from tweek.proxy import PROXY_AVAILABLE, PROXY_MISSING_DEPS
    except ImportError:
        print_error(
            "Proxy module not available",
            fix_hint="Install with: pip install tweek[proxy]",
        )
        return

    if not PROXY_AVAILABLE:
        print_error(
            "Proxy dependencies not installed",
            fix_hint="Install with: pip install tweek[proxy]",
        )
        return

    # Step 1: Detect tools
    console.print("[bold cyan]Step 1/3: Detect LLM Tools[/bold cyan]")
    try:
        from tweek.proxy import detect_supported_tools
        with spinner("Scanning for LLM tools"):
            tools = detect_supported_tools()

        detected = [(name, info) for name, info in tools.items() if info]
        if detected:
            for name, info in detected:
                print_success(f"Found {name.capitalize()}")
        else:
            print_warning("No LLM tools detected. You can still set up the proxy manually.")
    except Exception as e:
        print_warning(f"Could not detect tools: {e}")
    console.print()

    # Step 2: CA Certificate
    console.print("[bold cyan]Step 2/3: CA Certificate[/bold cyan]")
    setup_cert = click.confirm("Generate and trust Tweek CA certificate?", default=True)
    if setup_cert:
        try:
            from tweek.proxy.cert import generate_ca, trust_ca
            with spinner("Generating CA certificate"):
                generate_ca()
            print_success("CA certificate generated")

            with spinner("Installing to system trust store"):
                trust_ca()
            print_success("Certificate trusted")
        except ImportError:
            print_warning("Certificate module not available. Run: tweek proxy trust")
        except Exception as e:
            print_warning(f"Could not set up certificate: {e}")
            console.print("  [dim]You can do this later with: tweek proxy trust[/dim]")
    else:
        console.print("  [dim]Skipped. Run 'tweek proxy trust' later.[/dim]")
    console.print()

    # Step 3: Shell environment
    console.print("[bold cyan]Step 3/3: Environment Variables[/bold cyan]")
    port = click.prompt("Proxy port", default=9877, type=int)

    shell_rc = _detect_shell_rc()
    if shell_rc:
        console.print(f"  Detected shell config: {shell_rc}")
        console.print(f"  Will add:")
        console.print(f"    export HTTP_PROXY=http://127.0.0.1:{port}")
        console.print(f"    export HTTPS_PROXY=http://127.0.0.1:{port}")
        console.print()

        apply_env = click.confirm(f"Add to {shell_rc}?", default=True)
        if apply_env:
            try:
                rc_path = Path(shell_rc).expanduser()
                with open(rc_path, "a") as f:
                    f.write(f"\n# Tweek proxy environment\n")
                    f.write(f"export HTTP_PROXY=http://127.0.0.1:{port}\n")
                    f.write(f"export HTTPS_PROXY=http://127.0.0.1:{port}\n")
                print_success(f"Added to {shell_rc}")
                console.print(f"  [dim]Restart your shell or run: source {shell_rc}[/dim]")
            except Exception as e:
                print_warning(f"Could not write to {shell_rc}: {e}")
        else:
            console.print("  [dim]Skipped. Set HTTP_PROXY and HTTPS_PROXY manually.[/dim]")
    else:
        console.print("  [dim]Could not detect shell config file.[/dim]")
        console.print(f"  Add these to your shell profile:")
        console.print(f"    export HTTP_PROXY=http://127.0.0.1:{port}")
        console.print(f"    export HTTPS_PROXY=http://127.0.0.1:{port}")

    console.print()
    console.print("[bold green]Proxy configured![/bold green]")
    console.print("  Start with: [cyan]tweek proxy start[/cyan]")
    console.print()


def _detect_shell_rc() -> str:
    """Detect the user's shell config file."""
    shell = os.environ.get("SHELL", "")
    home = Path.home()

    if "zsh" in shell:
        return "~/.zshrc"
    elif "bash" in shell:
        if (home / ".bash_profile").exists():
            return "~/.bash_profile"
        return "~/.bashrc"
    elif "fish" in shell:
        return "~/.config/fish/config.fish"
    return ""


# ============================================================
# PLUGINS COMMANDS
# ============================================================

@main.group()
def plugins():
    """Manage Tweek plugins (compliance, providers, detectors, screening)."""
    pass


@plugins.command("list",
    epilog="""\b
Examples:
  tweek plugins list                     List all enabled plugins
  tweek plugins list --all               Include disabled plugins
  tweek plugins list -c compliance       Show only compliance plugins
  tweek plugins list -c screening        Show only screening plugins
"""
)
@click.option("--category", "-c", type=click.Choice(["compliance", "providers", "detectors", "screening"]),
              help="Filter by plugin category")
@click.option("--all", "show_all", is_flag=True, help="Show all plugins including disabled")
def plugins_list(category: str, show_all: bool):
    """List installed plugins."""
    try:
        from tweek.plugins import get_registry, init_plugins, PluginCategory, LicenseTier
        from tweek.config.manager import ConfigManager

        init_plugins()
        registry = get_registry()
        cfg = ConfigManager()

        category_map = {
            "compliance": PluginCategory.COMPLIANCE,
            "providers": PluginCategory.LLM_PROVIDER,
            "detectors": PluginCategory.TOOL_DETECTOR,
            "screening": PluginCategory.SCREENING,
        }

        categories = [category_map[category]] if category else list(PluginCategory)

        for cat in categories:
            cat_name = cat.value.split(".")[-1]
            plugins_list = registry.list_plugins(cat)

            if not plugins_list and not show_all:
                continue

            table = Table(title=f"{cat_name.replace('_', ' ').title()} Plugins")
            table.add_column("Name", style="cyan")
            table.add_column("Version")
            table.add_column("Source")
            table.add_column("Enabled")
            table.add_column("License")
            table.add_column("Description", max_width=40)

            for info in plugins_list:
                if not show_all and not info.enabled:
                    continue

                # Get config status
                plugin_cfg = cfg.get_plugin_config(cat_name, info.name)

                license_tier = info.metadata.requires_license
                license_style = "green" if license_tier == LicenseTier.FREE else "cyan"

                source_str = info.source.value if hasattr(info, 'source') else "builtin"
                source_style = "blue" if source_str == "git" else "dim"

                table.add_row(
                    info.name,
                    info.metadata.version,
                    f"[{source_style}]{source_str}[/{source_style}]",
                    "[green]✓[/green]" if info.enabled else "[red]✗[/red]",
                    f"[{license_style}]{license_tier.value}[/{license_style}]",
                    info.metadata.description[:40] + "..." if len(info.metadata.description) > 40 else info.metadata.description,
                )

            console.print(table)
            console.print()

    except ImportError as e:
        console.print(f"[red]Plugin system not available: {e}[/red]")


@plugins.command("info",
    epilog="""\b
Examples:
  tweek plugins info hipaa               Show details for the hipaa plugin
  tweek plugins info pii -c compliance   Specify category explicitly
"""
)
@click.argument("plugin_name")
@click.option("--category", "-c", type=click.Choice(["compliance", "providers", "detectors", "screening"]),
              help="Plugin category (auto-detected if not specified)")
def plugins_info(plugin_name: str, category: str):
    """Show detailed information about a plugin."""
    try:
        from tweek.plugins import get_registry, init_plugins, PluginCategory
        from tweek.config.manager import ConfigManager

        init_plugins()
        registry = get_registry()
        cfg = ConfigManager()

        category_map = {
            "compliance": PluginCategory.COMPLIANCE,
            "providers": PluginCategory.LLM_PROVIDER,
            "detectors": PluginCategory.TOOL_DETECTOR,
            "screening": PluginCategory.SCREENING,
        }

        # Find the plugin
        found_info = None
        found_cat = None

        if category:
            cat_enum = category_map[category]
            found_info = registry.get_info(plugin_name, cat_enum)
            found_cat = category
        else:
            # Search all categories
            for cat_name, cat_enum in category_map.items():
                info = registry.get_info(plugin_name, cat_enum)
                if info:
                    found_info = info
                    found_cat = cat_name
                    break

        if not found_info:
            console.print(f"[red]Plugin not found: {plugin_name}[/red]")
            return

        # Get config
        plugin_cfg = cfg.get_plugin_config(found_cat, plugin_name)

        console.print(f"\n[bold]{found_info.name}[/bold] ({found_cat})")
        console.print(f"[dim]{found_info.metadata.description}[/dim]")
        console.print()

        table = Table(show_header=False)
        table.add_column("Key", style="cyan")
        table.add_column("Value")

        table.add_row("Version", found_info.metadata.version)
        table.add_row("Author", found_info.metadata.author or "Unknown")
        table.add_row("License Required", found_info.metadata.requires_license.value.upper())
        table.add_row("Enabled", "Yes" if found_info.enabled else "No")
        table.add_row("Config Source", plugin_cfg.source)

        if found_info.metadata.tags:
            table.add_row("Tags", ", ".join(found_info.metadata.tags))

        if plugin_cfg.settings:
            table.add_row("Settings", str(plugin_cfg.settings))

        if found_info.load_error:
            table.add_row("[red]Load Error[/red]", found_info.load_error)

        console.print(table)

    except ImportError as e:
        console.print(f"[red]Plugin system not available: {e}[/red]")


@plugins.command("set",
    epilog="""\b
Examples:
  tweek plugins set hipaa --enabled -c compliance          Enable a plugin
  tweek plugins set hipaa --disabled -c compliance         Disable a plugin
  tweek plugins set hipaa threshold 0.8 -c compliance      Set a config value
  tweek plugins set hipaa --scope-tools Bash,Edit -c compliance   Scope to tools
  tweek plugins set hipaa --scope-clear -c compliance      Clear scoping
"""
)
@click.argument("plugin_name")
@click.argument("key", required=False)
@click.argument("value", required=False)
@click.option("--category", "-c", type=click.Choice(["compliance", "providers", "detectors", "screening"]),
              required=True, help="Plugin category")
@click.option("--scope", type=click.Choice(["user", "project"]), default="user")
@click.option("--enabled", "set_enabled", is_flag=True, help="Enable the plugin")
@click.option("--disabled", "set_disabled", is_flag=True, help="Disable the plugin")
@click.option("--scope-tools", help="Comma-separated tool names for scoping")
@click.option("--scope-skills", help="Comma-separated skill names for scoping")
@click.option("--scope-tiers", help="Comma-separated tiers for scoping")
@click.option("--scope-clear", is_flag=True, help="Clear all scoping")
def plugins_set(plugin_name: str, key: str, value: str, category: str, scope: str,
                set_enabled: bool, set_disabled: bool, scope_tools: str,
                scope_skills: str, scope_tiers: str, scope_clear: bool):
    """Set a plugin configuration value, enable/disable, or configure scope."""
    from tweek.config.manager import ConfigManager
    import json

    cfg = ConfigManager()

    # Handle enable/disable
    if set_enabled:
        cfg.set_plugin_enabled(category, plugin_name, True, scope=scope)
        console.print(f"[green]✓[/green] Enabled plugin '{plugin_name}' ({category}) - {scope} config")
        return
    if set_disabled:
        cfg.set_plugin_enabled(category, plugin_name, False, scope=scope)
        console.print(f"[green]✓[/green] Disabled plugin '{plugin_name}' ({category}) - {scope} config")
        return

    # Handle scope configuration
    if scope_clear:
        cfg.set_plugin_scope(plugin_name, None)
        console.print(f"[green]✓[/green] Cleared scope for {plugin_name} (now global)")
        return

    if any([scope_tools, scope_skills, scope_tiers]):
        scope_config = {}
        if scope_tools:
            scope_config["tools"] = [t.strip() for t in scope_tools.split(",")]
        if scope_skills:
            scope_config["skills"] = [s.strip() for s in scope_skills.split(",")]
        if scope_tiers:
            scope_config["tiers"] = [t.strip() for t in scope_tiers.split(",")]
        cfg.set_plugin_scope(plugin_name, scope_config)
        console.print(f"[green]✓[/green] Updated scope for {plugin_name}")
        return

    # Handle key=value setting
    if not key or not value:
        console.print("[red]Specify key and value, or use --enabled/--disabled/--scope-* flags[/red]")
        return

    # Try to parse value as JSON (for booleans, numbers, objects)
    try:
        parsed_value = json.loads(value)
    except json.JSONDecodeError:
        parsed_value = value

    cfg.set_plugin_setting(category, plugin_name, key, parsed_value, scope=scope)
    console.print(f"[green]✓[/green] Set {plugin_name}.{key} = {parsed_value} ({scope} config)")


@plugins.command("reset",
    epilog="""\b
Examples:
  tweek plugins reset hipaa -c compliance          Reset hipaa plugin to defaults
  tweek plugins reset pii -c compliance --scope project   Reset project-level config
"""
)
@click.argument("plugin_name")
@click.option("--category", "-c", type=click.Choice(["compliance", "providers", "detectors", "screening"]),
              required=True, help="Plugin category")
@click.option("--scope", type=click.Choice(["user", "project"]), default="user")
def plugins_reset(plugin_name: str, category: str, scope: str):
    """Reset a plugin to default configuration."""
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()

    if cfg.reset_plugin(category, plugin_name, scope=scope):
        console.print(f"[green]✓[/green] Reset plugin '{plugin_name}' to defaults ({scope} config)")
    else:
        console.print(f"[yellow]![/yellow] Plugin '{plugin_name}' has no {scope} configuration to reset")


@plugins.command("scan",
    epilog="""\b
Examples:
  tweek plugins scan "This is TOP SECRET//NOFORN"         Scan text for compliance
  tweek plugins scan "Patient MRN: 123456" --plugin hipaa  Use specific plugin
  tweek plugins scan @file.txt                             Scan file contents
  tweek plugins scan "SSN: 123-45-6789" -d input           Scan incoming data
"""
)
@click.argument("content")
@click.option("--direction", "-d", type=click.Choice(["input", "output"]), default="output",
              help="Scan direction (input=incoming data, output=LLM response)")
@click.option("--plugin", "-p", help="Specific compliance plugin to use (default: all enabled)")
def plugins_scan(content: str, direction: str, plugin: str):
    """Run compliance scan on content."""
    try:
        from tweek.plugins import get_registry, init_plugins, PluginCategory
        from tweek.plugins.base import ScanDirection

        # Handle file input
        if content.startswith("@"):
            file_path = Path(content[1:])
            if file_path.exists():
                content = file_path.read_text()
            else:
                console.print(f"[red]File not found: {file_path}[/red]")
                return

        init_plugins()
        registry = get_registry()
        direction_enum = ScanDirection(direction)

        total_findings = []

        if plugin:
            # Scan with specific plugin
            plugin_instance = registry.get(plugin, PluginCategory.COMPLIANCE)
            if not plugin_instance:
                console.print(f"[red]Plugin not found: {plugin}[/red]")
                return
            plugins_to_use = [plugin_instance]
        else:
            # Use all enabled compliance plugins
            plugins_to_use = registry.get_all(PluginCategory.COMPLIANCE)

        if not plugins_to_use:
            console.print("[yellow]No compliance plugins enabled.[/yellow]")
            console.print("[dim]Enable plugins with: tweek plugins enable <name> -c compliance[/dim]")
            return

        for p in plugins_to_use:
            result = p.scan(content, direction_enum)

            if result.findings:
                console.print(f"\n[bold]{p.name.upper()}[/bold]: {len(result.findings)} finding(s)")

                for finding in result.findings:
                    severity_styles = {
                        "critical": "red bold",
                        "high": "red",
                        "medium": "yellow",
                        "low": "dim",
                    }
                    style = severity_styles.get(finding.severity.value, "white")

                    console.print(f"  [{style}]{finding.severity.value.upper()}[/{style}] {finding.pattern_name}")
                    console.print(f"    [dim]Matched: {finding.matched_text[:60]}{'...' if len(finding.matched_text) > 60 else ''}[/dim]")
                    if finding.description:
                        console.print(f"    {finding.description}")

                total_findings.extend(result.findings)

        if not total_findings:
            console.print("[green]✓[/green] No compliance issues found")
        else:
            console.print(f"\n[yellow]Total: {len(total_findings)} finding(s)[/yellow]")

    except ImportError as e:
        console.print(f"[red]Plugin system not available: {e}[/red]")


# ============================================================
# GIT PLUGIN MANAGEMENT COMMANDS
# ============================================================

@plugins.command("install",
    epilog="""\b
Examples:
  tweek plugins install hipaa-scanner              Install a plugin by name
  tweek plugins install hipaa-scanner -v 1.2.0     Install a specific version
  tweek plugins install _ --from-lockfile          Install all from lockfile
  tweek plugins install hipaa-scanner --no-verify  Skip verification (not recommended)
"""
)
@click.argument("name")
@click.option("--version", "-v", "version", default=None, help="Specific version to install")
@click.option("--from-lockfile", is_flag=True, help="Install all plugins from lockfile")
@click.option("--no-verify", is_flag=True, help="Skip security verification (not recommended)")
def plugins_install(name: str, version: str, from_lockfile: bool, no_verify: bool):
    """Install a plugin from the Tweek registry."""
    try:
        from tweek.plugins.git_installer import GitPluginInstaller
        from tweek.plugins.git_registry import PluginRegistryClient
        from tweek.plugins.git_lockfile import PluginLockfile

        if from_lockfile:
            lockfile = PluginLockfile()
            if not lockfile.has_lockfile:
                console.print("[red]No lockfile found. Run 'tweek plugins lock' first.[/red]")
                return

            locks = lockfile.load()
            registry = PluginRegistryClient()
            installer = GitPluginInstaller(registry_client=registry)

            for plugin_name, lock in locks.items():
                console.print(f"Installing {plugin_name} v{lock.version}...")
                success, msg = installer.install(
                    plugin_name,
                    version=lock.version,
                    verify=not no_verify,
                )
                if success:
                    console.print(f"  [green]✓[/green] {msg}")
                else:
                    console.print(f"  [red]✗[/red] {msg}")
            return

        registry = PluginRegistryClient()
        installer = GitPluginInstaller(registry_client=registry)

        from tweek.cli_helpers import spinner as cli_spinner

        with cli_spinner(f"Installing {name}"):
            success, msg = installer.install(name, version=version, verify=not no_verify)

        if success:
            console.print(f"[green]\u2713[/green] {msg}")
        else:
            console.print(f"[red]\u2717[/red] {msg}")
            console.print(f"  [dim]Hint: Check network connectivity or try: tweek plugins registry --refresh[/dim]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print(f"  [dim]Hint: Check network connectivity and try again[/dim]")


@plugins.command("update",
    epilog="""\b
Examples:
  tweek plugins update hipaa-scanner     Update a specific plugin
  tweek plugins update --all             Update all installed plugins
  tweek plugins update --check           Check for available updates
  tweek plugins update hipaa-scanner -v 2.0.0   Update to specific version
"""
)
@click.argument("name", required=False)
@click.option("--all", "update_all", is_flag=True, help="Update all installed plugins")
@click.option("--check", "check_only", is_flag=True, help="Check for updates without installing")
@click.option("--version", "-v", "version", default=None, help="Specific version to update to")
@click.option("--no-verify", is_flag=True, help="Skip security verification")
def plugins_update(name: str, update_all: bool, check_only: bool, version: str, no_verify: bool):
    """Update installed plugins."""
    try:
        from tweek.plugins.git_installer import GitPluginInstaller
        from tweek.plugins.git_registry import PluginRegistryClient

        registry = PluginRegistryClient()
        installer = GitPluginInstaller(registry_client=registry)

        if check_only:
            console.print("Checking for updates...")
            updates = installer.check_updates()
            if not updates:
                console.print("[green]All plugins are up to date.[/green]")
            else:
                table = Table(title="Available Updates")
                table.add_column("Plugin", style="cyan")
                table.add_column("Current")
                table.add_column("Latest", style="green")
                for u in updates:
                    table.add_row(u["name"], u["current_version"], u["latest_version"])
                console.print(table)
            return

        if update_all:
            installed = installer.list_installed()
            if not installed:
                console.print("No git plugins installed.")
                return
            for plugin in installed:
                console.print(f"Updating {plugin['name']}...")
                success, msg = installer.update(
                    plugin["name"],
                    verify=not no_verify,
                )
                if success:
                    console.print(f"  [green]✓[/green] {msg}")
                else:
                    console.print(f"  [yellow]![/yellow] {msg}")
            return

        if not name:
            console.print("[red]Specify a plugin name or use --all[/red]")
            return

        success, msg = installer.update(name, version=version, verify=not no_verify)
        if success:
            console.print(f"[green]✓[/green] {msg}")
        else:
            console.print(f"[red]✗[/red] {msg}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@plugins.command("remove",
    epilog="""\b
Examples:
  tweek plugins remove hipaa-scanner     Remove a plugin (with confirmation)
  tweek plugins remove hipaa-scanner -f  Remove without confirmation
"""
)
@click.argument("name")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation")
def plugins_remove(name: str, force: bool):
    """Remove an installed git plugin."""
    try:
        from tweek.plugins.git_installer import GitPluginInstaller
        from tweek.plugins.git_registry import PluginRegistryClient

        installer = GitPluginInstaller(registry_client=PluginRegistryClient())

        if not force:
            if not click.confirm(f"Remove plugin '{name}'?"):
                return

        success, msg = installer.remove(name)
        if success:
            console.print(f"[green]✓[/green] {msg}")
        else:
            console.print(f"[red]✗[/red] {msg}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@plugins.command("search",
    epilog="""\b
Examples:
  tweek plugins search hipaa             Search for plugins by name
  tweek plugins search -c compliance     Browse all compliance plugins
  tweek plugins search -t free           Show only free-tier plugins
  tweek plugins search pii --include-deprecated   Include deprecated results
"""
)
@click.argument("query", required=False)
@click.option("--category", "-c", type=click.Choice(["compliance", "providers", "detectors", "screening"]),
              help="Filter by category")
@click.option("--tier", "-t", type=click.Choice(["free", "pro", "enterprise"]),
              help="Filter by license tier")
@click.option("--include-deprecated", is_flag=True, help="Include deprecated plugins")
def plugins_search(query: str, category: str, tier: str, include_deprecated: bool):
    """Search the Tweek plugin registry."""
    try:
        from tweek.plugins.git_registry import PluginRegistryClient

        registry = PluginRegistryClient()
        console.print("Searching registry...")
        results = registry.search(
            query=query,
            category=category,
            tier=tier,
            include_deprecated=include_deprecated,
        )

        if not results:
            console.print("[yellow]No plugins found matching your criteria.[/yellow]")
            return

        table = Table(title=f"Registry Results ({len(results)} found)")
        table.add_column("Name", style="cyan")
        table.add_column("Version")
        table.add_column("Category")
        table.add_column("Tier")
        table.add_column("Description", max_width=40)

        for entry in results:
            table.add_row(
                entry.name,
                entry.latest_version,
                entry.category,
                entry.requires_license_tier,
                entry.description[:40] + "..." if len(entry.description) > 40 else entry.description,
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@plugins.command("lock",
    epilog="""\b
Examples:
  tweek plugins lock                     Generate lockfile for all plugins
  tweek plugins lock -p hipaa -v 1.2.0   Lock a specific plugin to a version
  tweek plugins lock --project           Create project-level lockfile
"""
)
@click.option("--plugin", "-p", "plugin_name", default=None, help="Lock a specific plugin")
@click.option("--version", "-v", "version", default=None, help="Lock to specific version")
@click.option("--project", is_flag=True, help="Create project-level lockfile (.tweek/plugins.lock.json)")
def plugins_lock(plugin_name: str, version: str, project: bool):
    """Generate or update a plugin version lockfile."""
    try:
        from tweek.plugins.git_lockfile import PluginLockfile

        lockfile = PluginLockfile()
        target = "project" if project else "user"

        specific = None
        if plugin_name:
            specific = {plugin_name: version or "latest"}

        path = lockfile.generate(target=target, specific_plugins=specific)
        console.print(f"[green]✓[/green] Lockfile generated: {path}")

        # Show lock contents
        locks = lockfile.load()
        if locks:
            table = Table(title="Locked Plugins")
            table.add_column("Plugin", style="cyan")
            table.add_column("Version")
            table.add_column("Commit")
            for name, lock in locks.items():
                table.add_row(
                    name,
                    lock.version,
                    lock.commit_sha[:12] if lock.commit_sha else "n/a",
                )
            console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@plugins.command("verify",
    epilog="""\b
Examples:
  tweek plugins verify hipaa-scanner     Verify a specific plugin's integrity
  tweek plugins verify --all             Verify all installed plugins
"""
)
@click.argument("name", required=False)
@click.option("--all", "verify_all", is_flag=True, help="Verify all installed plugins")
def plugins_verify(name: str, verify_all: bool):
    """Verify integrity of installed git plugins."""
    try:
        from tweek.plugins.git_installer import GitPluginInstaller
        from tweek.plugins.git_registry import PluginRegistryClient

        from tweek.cli_helpers import spinner as cli_spinner

        installer = GitPluginInstaller(registry_client=PluginRegistryClient())

        if verify_all:
            with cli_spinner("Verifying plugin integrity"):
                results = installer.verify_all()
            if not results:
                console.print("No git plugins installed.")
                return

            all_valid = True
            for plugin_name, (valid, issues) in results.items():
                if valid:
                    console.print(f"  [green]✓[/green] {plugin_name}: integrity verified")
                else:
                    all_valid = False
                    console.print(f"  [red]✗[/red] {plugin_name}: {len(issues)} issue(s)")
                    for issue in issues:
                        console.print(f"      - {issue}")

            if all_valid:
                console.print(f"\n[green]All {len(results)} plugin(s) verified.[/green]")
            return

        if not name:
            console.print("[red]Specify a plugin name or use --all[/red]")
            return

        valid, issues = installer.verify_plugin(name)
        if valid:
            console.print(f"[green]✓[/green] Plugin '{name}' integrity verified")
        else:
            console.print(f"[red]✗[/red] Plugin '{name}' failed verification:")
            for issue in issues:
                console.print(f"  - {issue}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@plugins.command("registry",
    epilog="""\b
Examples:
  tweek plugins registry                 Show registry summary
  tweek plugins registry --refresh       Force refresh the registry cache
  tweek plugins registry --info          Show detailed registry metadata
"""
)
@click.option("--refresh", is_flag=True, help="Force refresh the registry cache")
@click.option("--info", "show_info", is_flag=True, help="Show registry metadata")
def plugins_registry(refresh: bool, show_info: bool):
    """Manage the plugin registry cache."""
    try:
        from tweek.plugins.git_registry import PluginRegistryClient

        registry = PluginRegistryClient()

        if refresh:
            console.print("Refreshing registry...")
            try:
                entries = registry.fetch(force_refresh=True)
                console.print(f"[green]✓[/green] Registry refreshed: {len(entries)} plugins available")
            except Exception as e:
                console.print(f"[red]✗[/red] Failed to refresh: {e}")
            return

        if show_info:
            info = registry.get_registry_info()
            panel_content = "\n".join([
                f"URL: {info.get('url', 'unknown')}",
                f"Cache: {info.get('cache_path', 'unknown')}",
                f"Cache TTL: {info.get('cache_ttl_seconds', 0)}s",
                f"Cache valid: {info.get('cache_valid', False)}",
                f"Schema version: {info.get('schema_version', 'unknown')}",
                f"Last updated: {info.get('updated_at', 'unknown')}",
                f"Total plugins: {info.get('total_plugins', 'unknown')}",
                f"Cache fetched: {info.get('cache_fetched_at', 'never')}",
            ])
            console.print(Panel(panel_content, title="Registry Info"))
            return

        # Default: show summary
        try:
            entries = registry.fetch()
            verified = [e for e in entries.values() if e.verified and not e.deprecated]
            console.print(f"Registry: {len(verified)} verified plugins available")
            console.print("Use 'tweek plugins search' to browse or 'tweek plugins registry --refresh' to update cache")
        except Exception as e:
            console.print(f"[yellow]Registry unavailable: {e}[/yellow]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


# =============================================================================
# MCP GATEWAY COMMANDS
# =============================================================================

@main.group()
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
    import asyncio

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


@mcp.command(
    epilog="""\b
Examples:
  tweek mcp install claude-desktop       Configure Claude Desktop integration
  tweek mcp install chatgpt              Set up ChatGPT Desktop integration
  tweek mcp install gemini               Configure Gemini CLI integration
"""
)
@click.argument("client", type=click.Choice(["claude-desktop", "chatgpt", "gemini"]))
def install(client):
    """Install Tweek as MCP server for a desktop client.

    Supported clients:
      claude-desktop  - Auto-configures Claude Desktop
      chatgpt         - Provides Developer Mode setup instructions
      gemini          - Auto-configures Gemini CLI settings
    """
    try:
        from tweek.mcp.clients import get_client

        handler = get_client(client)
        result = handler.install()

        if result.get("success"):
            console.print(f"[green]✅ {result.get('message', 'Installed successfully')}[/green]")

            if result.get("config_path"):
                console.print(f"   Config: {result['config_path']}")

            if result.get("backup"):
                console.print(f"   Backup: {result['backup']}")

            # Show instructions for manual setup clients
            if result.get("instructions"):
                console.print()
                for line in result["instructions"]:
                    console.print(f"   {line}")
        else:
            console.print(f"[red]❌ {result.get('error', 'Installation failed')}[/red]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@mcp.command(
    epilog="""\b
Examples:
  tweek mcp uninstall claude-desktop     Remove from Claude Desktop
  tweek mcp uninstall chatgpt            Remove from ChatGPT Desktop
  tweek mcp uninstall gemini             Remove from Gemini CLI
"""
)
@click.argument("client", type=click.Choice(["claude-desktop", "chatgpt", "gemini"]))
def uninstall(client):
    """Remove Tweek MCP server from a desktop client.

    Supported clients: claude-desktop, chatgpt, gemini
    """
    try:
        from tweek.mcp.clients import get_client

        handler = get_client(client)
        result = handler.uninstall()

        if result.get("success"):
            console.print(f"[green]✅ {result.get('message', 'Uninstalled successfully')}[/green]")

            if result.get("backup"):
                console.print(f"   Backup: {result['backup']}")

            if result.get("instructions"):
                console.print()
                for line in result["instructions"]:
                    console.print(f"   {line}")
        else:
            console.print(f"[red]❌ {result.get('error', 'Uninstallation failed')}[/red]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


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
    import asyncio

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

if __name__ == "__main__":
    main()
