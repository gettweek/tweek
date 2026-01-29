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


@main.command()
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


@main.command()
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


@main.command()
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
            console.print("[red]✗[/red] git not found. Please install git.")
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


@main.command()
def status():
    """Show Tweek protection status."""
    from tweek.logging.security_log import get_logger
    from tweek.platform import get_capabilities, PLATFORM, IS_LINUX
    from tweek.sandbox import get_sandbox_status
    import os
    import json

    console.print(TWEEK_BANNER, style="cyan")

    # Get platform capabilities
    caps = get_capabilities()
    sandbox_status = get_sandbox_status()

    # Check hook installations at both global and project level
    global_claude = Path("~/.claude").expanduser()
    project_claude = Path.cwd() / ".claude"

    def check_tweek_hooks(settings_path: Path) -> bool:
        """Check if Tweek hooks are installed in a settings file."""
        if not settings_path.exists():
            return False
        try:
            with open(settings_path) as f:
                settings = json.load(f)
            if "hooks" in settings and "PreToolUse" in settings.get("hooks", {}):
                for hook_config in settings["hooks"]["PreToolUse"]:
                    for hook in hook_config.get("hooks", []):
                        if "tweek" in hook.get("command", "").lower():
                            return True
        except (json.JSONDecodeError, IOError):
            pass
        return False

    global_installed = check_tweek_hooks(global_claude / "settings.json")
    project_installed = check_tweek_hooks(project_claude / "settings.json")
    hook_installed = global_installed or project_installed

    db_path = Path("~/.tweek/security.db").expanduser()

    table = Table(title=f"Tweek Status ({caps.platform.value})")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details")

    # Hook status with scope detail
    if global_installed:
        hook_status = "[green]✓ Installed[/green]"
        hook_detail = "~/.claude (all projects)"
    elif project_installed:
        hook_status = "[green]✓ Installed[/green]"
        hook_detail = "./.claude (this project only)"
    else:
        hook_status = "[yellow]⚠️ Not Installed[/yellow]"
        hook_detail = "Run 'tweek install'"

    table.add_row("Hook Integration", hook_status, hook_detail)

    # Vault status (cross-platform)
    table.add_row(
        "Credential Vault",
        "✓ Available" if caps.vault_available else "✗ Not Available",
        caps.vault_backend
    )

    # Sandbox status (platform-specific)
    if sandbox_status["available"]:
        sandbox_name = f"Sandbox ({sandbox_status['tool']})"
        table.add_row(
            sandbox_name,
            "✓ Available",
            sandbox_status['tool']
        )
    else:
        if IS_LINUX:
            table.add_row(
                "Sandbox (firejail)",
                "[yellow]✗ Not Installed[/yellow]",
                caps.sandbox_install_hint or "Install firejail for sandbox support"
            )
        else:
            table.add_row(
                "Sandbox",
                "✗ Not Available",
                "Not supported on this platform"
            )

    table.add_row(
        "Security Database",
        "✓ Active" if db_path.exists() else "○ Not Created",
        str(db_path) if db_path.exists() else "Will be created on first event"
    )

    # License status
    from tweek.licensing import get_license, Tier
    lic = get_license()
    tier_colors = {Tier.FREE: "white", Tier.PRO: "cyan"}
    tier_color = tier_colors.get(lic.tier, "white")
    tier_display = f"[{tier_color}]{lic.tier.value.upper()}[/{tier_color}]"

    if lic.tier == Tier.FREE:
        license_detail = "Upgrade: gettweek.com/pricing"
    else:
        license_detail = f"Licensed to: {lic.info.email}" if lic.info else ""

    table.add_row("License", tier_display, license_detail)

    # Pattern status
    user_patterns = Path("~/.tweek/patterns/patterns.yaml").expanduser()
    bundled_patterns = Path(__file__).parent / "config" / "patterns.yaml"

    patterns_source = None
    patterns_file = None

    if user_patterns.exists():
        patterns_source = "~/.tweek/patterns"
        patterns_file = user_patterns
    elif bundled_patterns.exists():
        patterns_source = "bundled"
        patterns_file = bundled_patterns

    if patterns_file and patterns_file.exists():
        try:
            import yaml
            with open(patterns_file) as f:
                pdata = yaml.safe_load(f) or {}
            total_patterns = pdata.get("pattern_count", len(pdata.get("patterns", [])))

            pattern_status = f"✓ {total_patterns} patterns"
            pattern_detail = f"all free ({patterns_source})"
        except Exception:
            pattern_status = "✓ Loaded"
            pattern_detail = patterns_source
    else:
        pattern_status = "[yellow]○ Not Found[/yellow]"
        pattern_detail = "Run 'tweek update'"

    table.add_row("Attack Patterns", pattern_status, pattern_detail)

    console.print(table)

    # Show recent stats if database exists
    if db_path.exists():
        try:
            logger = get_logger()
            stats = logger.get_stats(days=1)

            by_decision = stats.get('by_decision', {})
            allowed = by_decision.get('allow', 0)
            blocked = by_decision.get('block', 0) + by_decision.get('deny', 0)
            prompted = by_decision.get('ask', 0)

            console.print(f"\n[dim]Today's stats: {stats['total_events']} events, "
                         f"{allowed} allowed, {blocked} blocked, {prompted} prompted[/dim]")
        except Exception:
            console.print("\n[dim]Unable to load stats[/dim]")
    else:
        console.print("\n[dim]No security events recorded yet[/dim]")


@main.group()
def config():
    """Configure Tweek security policies."""
    pass


@config.command("list")
@click.option("--tools", "show_tools", is_flag=True, help="Show tools only")
@click.option("--skills", "show_skills", is_flag=True, help="Show skills only")
def config_list(show_tools: bool, show_skills: bool):
    """List all tools and skills with their security tiers."""
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()

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


@config.command("show")
def config_show():
    """Show current configuration summary."""
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()

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

    summary = f"[cyan]Default Tier:[/cyan] {cfg.get_default_tier().value}\n\n"

    summary += "[cyan]Tools by Tier:[/cyan]\n"
    for tier in ["safe", "default", "risky", "dangerous"]:
        count = tool_tiers.get(tier, 0)
        if count:
            summary += f"  {tier}: {count}\n"

    summary += "\n[cyan]Skills by Tier:[/cyan]\n"
    for tier in ["safe", "default", "risky", "dangerous"]:
        count = skill_tiers.get(tier, 0)
        if count:
            summary += f"  {tier}: {count}\n"

    if user_tools or user_skills:
        summary += "\n[cyan]User Overrides:[/cyan]\n"
        for tool, tier in user_tools.items():
            summary += f"  {tool}: {tier}\n"
        for skill, tier in user_skills.items():
            summary += f"  {skill}: {tier}\n"
    else:
        summary += "\n[cyan]User Overrides:[/cyan] (none)"

    console.print(Panel.fit(summary, title="Tweek Configuration"))


@config.command("set")
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


@config.command("preset")
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


@config.command("reset")
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


@config.command("interactive")
def config_interactive():
    """Interactively configure security settings."""
    from tweek.config.manager import ConfigManager, SecurityTier

    cfg = ConfigManager()

    console.print(TWEEK_BANNER, style="cyan")
    console.print("[bold]Interactive Security Configuration[/bold]\n")

    # Step 1: Choose preset or custom
    console.print("How would you like to configure Tweek?\n")
    console.print("  [cyan]1.[/cyan] Paranoid - Maximum security, prompt for everything")
    console.print("  [cyan]2.[/cyan] Cautious - Balanced security (recommended)")
    console.print("  [cyan]3.[/cyan] Trusted  - Minimal prompts, trust AI decisions")
    console.print("  [cyan]4.[/cyan] Custom   - Configure each tool/skill individually")
    console.print()

    choice = click.prompt("Select option", type=click.IntRange(1, 4), default=2)

    if choice == 1:
        cfg.apply_preset("paranoid")
        console.print("\n[green]✓[/green] Applied [bold]paranoid[/bold] preset")
    elif choice == 2:
        cfg.apply_preset("cautious")
        console.print("\n[green]✓[/green] Applied [bold]cautious[/bold] preset")
    elif choice == 3:
        cfg.apply_preset("trusted")
        console.print("\n[green]✓[/green] Applied [bold]trusted[/bold] preset")
    else:
        # Custom configuration
        console.print("\n[bold]Custom Configuration[/bold]\n")

        # Configure default tier
        console.print("Default tier for unknown tools/skills:")
        console.print("  [cyan]1.[/cyan] safe     - No screening")
        console.print("  [cyan]2.[/cyan] default  - Regex pattern matching")
        console.print("  [cyan]3.[/cyan] risky    - Regex + LLM rules")
        console.print("  [cyan]4.[/cyan] dangerous - Full screening + sandbox")
        default_choice = click.prompt("Select", type=click.IntRange(1, 4), default=2)
        tiers = ["safe", "default", "risky", "dangerous"]
        cfg.set_default_tier(SecurityTier.from_string(tiers[default_choice - 1]))

        # Configure key tools
        console.print("\n[bold]Tool Configuration[/bold]")
        console.print("[dim]Press Enter to keep default, or enter tier (safe/default/risky/dangerous)[/dim]\n")

        key_tools = ["Bash", "WebFetch", "Edit", "Write"]
        for tool_name in key_tools:
            current = cfg.get_tool_tier(tool_name)
            new_tier = click.prompt(
                f"  {tool_name}",
                default=current.value,
                type=click.Choice(["safe", "default", "risky", "dangerous"]),
                show_default=True
            )
            if new_tier != current.value:
                cfg.set_tool_tier(tool_name, SecurityTier.from_string(new_tier))

        console.print("\n[green]✓[/green] Custom configuration saved")

    # Show summary
    console.print("\n[bold]Configuration Summary[/bold]")
    console.print(f"  Default tier: {cfg.get_default_tier().value}")
    console.print(f"  Bash: {cfg.get_tool_tier('Bash').value}")
    console.print(f"  WebFetch: {cfg.get_tool_tier('WebFetch').value}")
    console.print(f"  Edit: {cfg.get_tool_tier('Edit').value}")

    console.print("\n[dim]Run 'tweek config list' to see all settings[/dim]")


@main.group()
def vault():
    """Manage credentials in secure storage (Keychain on macOS, Secret Service on Linux)."""
    pass


@vault.command("store")
@click.argument("skill")
@click.argument("key")
@click.argument("value")
def vault_store(skill: str, key: str, value: str):
    """Store a credential securely for a skill."""
    from tweek.vault import get_vault, VAULT_AVAILABLE
    from tweek.platform import get_capabilities

    if not VAULT_AVAILABLE:
        console.print("[red]✗[/red] Vault not available. Install keyring: pip install keyring")
        return

    caps = get_capabilities()

    try:
        vault_instance = get_vault()
        if vault_instance.store(skill, key, value):
            console.print(f"[green]✓[/green] Stored {key} for skill '{skill}'")
            console.print(f"[dim]Backend: {caps.vault_backend}[/dim]")
        else:
            console.print(f"[red]✗[/red] Failed to store credential")
    except Exception as e:
        console.print(f"[red]✗[/red] Failed to store credential: {e}")


@vault.command("get")
@click.argument("skill")
@click.argument("key")
def vault_get(skill: str, key: str):
    """Retrieve a credential from secure storage."""
    from tweek.vault import get_vault, VAULT_AVAILABLE

    if not VAULT_AVAILABLE:
        console.print("[red]✗[/red] Vault not available. Install keyring: pip install keyring")
        return

    vault_instance = get_vault()
    value = vault_instance.get(skill, key)

    if value is not None:
        console.print(f"[yellow]GAH![/yellow] Credential access logged")
        console.print(value)
    else:
        console.print(f"[red]✗[/red] Credential not found: {key} for skill '{skill}'")


@vault.command("migrate-env")
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


@vault.command("list")
@click.argument("skill", required=False)
def vault_list(skill: str):
    """List credentials stored in secure storage."""
    from tweek.vault import VAULT_AVAILABLE
    from tweek.platform import get_capabilities

    if not VAULT_AVAILABLE:
        console.print("[red]✗[/red] Vault not available. Install keyring: pip install keyring")
        return

    caps = get_capabilities()
    console.print(f"[cyan]Credential Vault ({caps.vault_backend})[/cyan]")
    console.print("[dim]Note: The keyring library doesn't support listing all credentials.[/dim]")
    console.print("[dim]Use 'tweek vault get <skill> <key>' to retrieve specific credentials.[/dim]")


@vault.command("delete")
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


@license.command("status")
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


@license.command("activate")
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


@license.command("deactivate")
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


@logs.command("show")
@click.option("--limit", "-n", default=20, help="Number of events to show")
@click.option("--type", "-t", "event_type", help="Filter by event type")
@click.option("--tool", help="Filter by tool name")
@click.option("--blocked", is_flag=True, help="Show only blocked/flagged events")
def logs_show(limit: int, event_type: str, tool: str, blocked: bool):
    """Show recent security events."""
    from tweek.logging.security_log import get_logger, EventType

    console.print(TWEEK_BANNER, style="cyan")

    logger = get_logger()

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


@logs.command("stats")
@click.option("--days", "-d", default=7, help="Number of days to analyze")
def logs_stats(days: int):
    """Show security statistics."""
    from tweek.logging.security_log import get_logger

    console.print(TWEEK_BANNER, style="cyan")

    logger = get_logger()
    stats = logger.get_stats(days=days)

    console.print(Panel.fit(
        f"[cyan]Period:[/cyan] Last {days} days\n"
        f"[cyan]Total Events:[/cyan] {stats['total_events']}",
        title="Security Statistics"
    ))

    # Decisions breakdown
    if stats['by_decision']:
        table = Table(title="Decisions")
        table.add_column("Decision", style="cyan")
        table.add_column("Count", justify="right")

        decision_styles = {"allow": "green", "block": "red", "ask": "yellow", "deny": "red"}
        for decision, count in stats['by_decision'].items():
            style = decision_styles.get(decision, "white")
            table.add_row(f"[{style}]{decision}[/{style}]", str(count))

        console.print(table)
        console.print()

    # Top triggered patterns
    if stats['top_patterns']:
        table = Table(title="Top Triggered Patterns")
        table.add_column("Pattern", style="cyan")
        table.add_column("Severity")
        table.add_column("Count", justify="right")

        severity_styles = {"critical": "red", "high": "yellow", "medium": "blue", "low": "dim"}
        for pattern in stats['top_patterns']:
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
    if stats['by_tool']:
        table = Table(title="Events by Tool")
        table.add_column("Tool", style="green")
        table.add_column("Count", justify="right")

        for tool, count in stats['by_tool'].items():
            table.add_row(tool, str(count))

        console.print(table)


@logs.command("export")
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


@logs.command("clear")
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


@proxy.command("status")
def proxy_status():
    """Show proxy status and detected LLM tools."""
    from tweek.proxy import (
        PROXY_AVAILABLE, PROXY_MISSING_DEPS,
        get_proxy_status, detect_supported_tools
    )

    console.print(TWEEK_BANNER, style="cyan")

    status = get_proxy_status()
    tools = status["detected_tools"]

    # Proxy availability
    table = Table(title="Proxy Status")
    table.add_column("Component", style="cyan")
    table.add_column("Status")
    table.add_column("Details")

    if status["available"]:
        table.add_row(
            "Dependencies",
            "[green]✓ Installed[/green]",
            "mitmproxy available"
        )
    else:
        table.add_row(
            "Dependencies",
            "[red]✗ Missing[/red]",
            "Install: pip install tweek\\[proxy]"
        )

    table.add_row(
        "Proxy Enabled",
        "[green]✓ Yes[/green]" if status["enabled"] else "[dim]○ No[/dim]",
        f"Port {status['port']}" if status["enabled"] else "Run 'tweek proxy enable'"
    )

    table.add_row(
        "Proxy Running",
        "[green]✓ Running[/green]" if status["running"] else "[dim]○ Stopped[/dim]",
        f"PID available" if status["running"] else "Run 'tweek proxy start'"
    )

    table.add_row(
        "CA Certificate",
        "[green]✓ Trusted[/green]" if status["ca_trusted"] else "[yellow]○ Not Installed[/yellow]",
        "Run 'tweek proxy trust'" if not status["ca_trusted"] else ""
    )

    console.print(table)
    console.print()

    # Detected tools
    table = Table(title="Detected LLM Tools")
    table.add_column("Tool", style="cyan")
    table.add_column("Detected")
    table.add_column("Details")

    for tool_name, info in tools.items():
        if info:
            table.add_row(
                tool_name.capitalize(),
                "[green]✓ Found[/green]",
                ", ".join(f"{k}={v}" for k, v in info.items() if v)[:50]
            )
        else:
            table.add_row(
                tool_name.capitalize(),
                "[dim]○ Not Found[/dim]",
                ""
            )

    console.print(table)

    # Recommendations
    detected_any = any(info for info in tools.values())
    if detected_any and not status["available"]:
        console.print("\n[yellow]Recommendation:[/yellow] LLM tools detected but proxy not installed.")
        console.print("[dim]Run: pip install tweek\\[proxy][/dim]")
    elif detected_any and not status["running"]:
        console.print("\n[yellow]Recommendation:[/yellow] LLM tools detected. Start proxy for protection.")
        console.print("[dim]Run: tweek proxy start[/dim]")


@proxy.command("start")
@click.option("--port", "-p", default=9877, help="Port for proxy to listen on")
@click.option("--web-port", type=int, help="Port for web interface (disabled by default)")
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (for debugging)")
@click.option("--log-only", is_flag=True, help="Log only, don't block dangerous requests")
def proxy_start(port: int, web_port: int, foreground: bool, log_only: bool):
    """Start the Tweek LLM security proxy."""
    from tweek.proxy import PROXY_AVAILABLE, PROXY_MISSING_DEPS

    if not PROXY_AVAILABLE:
        console.print("[red]✗[/red] Proxy dependencies not installed.")
        console.print("[dim]Run: pip install tweek\\[proxy][/dim]")
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


@proxy.command("stop")
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


@proxy.command("trust")
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


@proxy.command("enable")
@click.option("--port", "-p", default=9877, help="Port for proxy")
def proxy_enable(port: int):
    """Enable proxy mode in Tweek configuration."""
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


@proxy.command("disable")
def proxy_disable():
    """Disable proxy mode in Tweek configuration."""
    import yaml
    config_path = Path.home() / ".tweek" / "config.yaml"

    if not config_path.exists():
        console.print("[dim]Proxy not configured[/dim]")
        return

    try:
        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
    except Exception:
        config = {}

    if "proxy" in config:
        config["proxy"]["enabled"] = False

        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)

    console.print("[green]✓[/green] Proxy mode disabled")


@proxy.command("wrap")
@click.argument("app_name")
@click.argument("command")
@click.option("--output", "-o", help="Output script path (default: ./run-{app_name}-protected.sh)")
@click.option("--port", "-p", default=9877, help="Proxy port")
def proxy_wrap(app_name: str, command: str, output: str, port: int):
    """Generate a wrapper script to run an app through the proxy.

    \b
    Examples:
        tweek proxy wrap moltbot "npm start"
        tweek proxy wrap cursor "/Applications/Cursor.app/Contents/MacOS/Cursor"
    """
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


@proxy.command("detect")
def proxy_detect():
    """Detect installed LLM tools and recommend configuration."""
    from tweek.proxy import detect_supported_tools, PROXY_AVAILABLE

    console.print("[cyan]Scanning for LLM tools...[/cyan]")
    console.print()

    tools = detect_supported_tools()

    detected = [(name, info) for name, info in tools.items() if info]

    if not detected:
        console.print("[dim]No supported LLM tools detected.[/dim]")
        console.print()
        console.print("Supported tools:")
        console.print("  - Moltbot (npm/global or running process)")
        console.print("  - Cursor IDE")
        console.print("  - Continue.dev (VS Code extension)")
        return

    console.print(f"[green]Found {len(detected)} LLM tool(s):[/green]")
    console.print()

    for name, info in detected:
        console.print(f"  [bold]{name.capitalize()}[/bold]")
        for key, value in info.items():
            if value:
                console.print(f"    {key}: {value}")
        console.print()

    if not PROXY_AVAILABLE:
        console.print("[yellow]Recommendation:[/yellow]")
        console.print("  Install proxy dependencies to protect these tools:")
        console.print("  [dim]pip install tweek\\[proxy][/dim]")
    else:
        console.print("[yellow]Recommendation:[/yellow]")
        console.print("  Start the proxy and configure your tools:")
        console.print("  [dim]tweek proxy start[/dim]")
        console.print("  [dim]tweek proxy trust[/dim]")
        for name, _ in detected:
            console.print(f"  [dim]tweek proxy wrap {name} '<start command>'[/dim]")


# ============================================================
# PLUGINS COMMANDS
# ============================================================

@main.group()
def plugins():
    """Manage Tweek plugins (compliance, providers, detectors, screening)."""
    pass


@plugins.command("list")
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


@plugins.command("info")
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


@plugins.command("enable")
@click.argument("plugin_name")
@click.option("--category", "-c", type=click.Choice(["compliance", "providers", "detectors", "screening"]),
              required=True, help="Plugin category")
@click.option("--scope", type=click.Choice(["user", "project"]), default="user")
def plugins_enable(plugin_name: str, category: str, scope: str):
    """Enable a plugin."""
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()
    cfg.set_plugin_enabled(category, plugin_name, True, scope=scope)
    console.print(f"[green]✓[/green] Enabled plugin '{plugin_name}' ({category}) - {scope} config")


@plugins.command("disable")
@click.argument("plugin_name")
@click.option("--category", "-c", type=click.Choice(["compliance", "providers", "detectors", "screening"]),
              required=True, help="Plugin category")
@click.option("--scope", type=click.Choice(["user", "project"]), default="user")
def plugins_disable(plugin_name: str, category: str, scope: str):
    """Disable a plugin."""
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()
    cfg.set_plugin_enabled(category, plugin_name, False, scope=scope)
    console.print(f"[green]✓[/green] Disabled plugin '{plugin_name}' ({category}) - {scope} config")


@plugins.command("set")
@click.argument("plugin_name")
@click.argument("key")
@click.argument("value")
@click.option("--category", "-c", type=click.Choice(["compliance", "providers", "detectors", "screening"]),
              required=True, help="Plugin category")
@click.option("--scope", type=click.Choice(["user", "project"]), default="user")
def plugins_set(plugin_name: str, key: str, value: str, category: str, scope: str):
    """Set a plugin configuration value."""
    from tweek.config.manager import ConfigManager
    import json

    cfg = ConfigManager()

    # Try to parse value as JSON (for booleans, numbers, objects)
    try:
        parsed_value = json.loads(value)
    except json.JSONDecodeError:
        parsed_value = value

    cfg.set_plugin_setting(category, plugin_name, key, parsed_value, scope=scope)
    console.print(f"[green]✓[/green] Set {plugin_name}.{key} = {parsed_value} ({scope} config)")


@plugins.command("reset")
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


@plugins.command("scan")
@click.argument("content")
@click.option("--direction", "-d", type=click.Choice(["input", "output"]), default="output",
              help="Scan direction (input=incoming data, output=LLM response)")
@click.option("--plugin", "-p", help="Specific compliance plugin to use (default: all enabled)")
def plugins_scan(content: str, direction: str, plugin: str):
    """Run compliance scan on content.

    \b
    Examples:
        tweek plugins scan "This document is TOP SECRET//NOFORN"
        tweek plugins scan "Patient MRN: 123456" --plugin hipaa
        tweek plugins scan @file.txt  # Scan file contents
    """
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

@plugins.command("install")
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

        console.print(f"Installing {name}...")
        success, msg = installer.install(name, version=version, verify=not no_verify)

        if success:
            console.print(f"[green]✓[/green] {msg}")
        else:
            console.print(f"[red]✗[/red] {msg}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@plugins.command("update")
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


@plugins.command("remove")
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


@plugins.command("search")
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


@plugins.command("lock")
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


@plugins.command("verify")
@click.argument("name", required=False)
@click.option("--all", "verify_all", is_flag=True, help="Verify all installed plugins")
def plugins_verify(name: str, verify_all: bool):
    """Verify integrity of installed git plugins."""
    try:
        from tweek.plugins.git_installer import GitPluginInstaller
        from tweek.plugins.git_registry import PluginRegistryClient

        installer = GitPluginInstaller(registry_client=PluginRegistryClient())

        if verify_all:
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


@plugins.command("registry")
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


if __name__ == "__main__":
    main()
