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
    tweek skills chamber list|import|scan|approve|reject
    tweek skills jail list|rescan|release|purge
    tweek skills report NAME
    tweek skills status
    tweek skills config [--mode auto|manual]
"""
from __future__ import annotations

import click
import json
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Dict, Optional
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


def _has_tweek_hooks(settings: dict) -> bool:
    """Check if a settings dict contains Tweek hooks."""
    hooks = settings.get("hooks", {})
    for hook_type in ("PreToolUse", "PostToolUse"):
        for hook_config in hooks.get(hook_type, []):
            for hook in hook_config.get("hooks", []):
                if "tweek" in hook.get("command", "").lower():
                    return True
    return False


@main.command(
    epilog="""\b
Examples:
  tweek install                          Install for current project
  tweek install --global                 Install globally (all projects)
  tweek install --interactive            Walk through configuration prompts
  tweek install --preset paranoid        Apply paranoid security preset
  tweek install --quick                  Zero-prompt install with defaults
  tweek install --with-sandbox           Install sandbox tool if needed (Linux)
  tweek install --force-proxy            Override existing proxy configurations
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
              help="Force Tweek proxy to override existing proxy configurations (e.g., moltbot)")
@click.option("--skip-proxy-check", is_flag=True,
              help="Skip checking for existing proxy configurations")
@click.option("--quick", is_flag=True,
              help="Zero-prompt install with cautious defaults (skips env scan and proxy check)")
def install(install_global: bool, dev_test: bool, backup: bool, skip_env_scan: bool, interactive: bool, preset: str, ai_defaults: bool, with_sandbox: bool, force_proxy: bool, skip_proxy_check: bool, quick: bool):
    """Install Tweek hooks into Claude Code.

    By default, installs to the current project (./.claude/).
    Use --global to install system-wide (~/.claude/).

    Configuration options:
        --interactive  : Walk through configuration prompts
        --preset       : Apply paranoid/cautious/trusted preset
        --ai-defaults  : Auto-configure based on detected skills
        --quick        : Zero-prompt install with cautious defaults
        --with-sandbox : Install sandbox tool if needed (Linux: firejail)
    """
    import json
    import shutil
    from tweek.platform import IS_LINUX, get_capabilities
    from tweek.config.manager import ConfigManager, SecurityTier

    # --quick implies non-interactive defaults
    if quick:
        skip_env_scan = True
        skip_proxy_check = True
        if not preset:
            preset = "cautious"

    console.print(TWEEK_BANNER, style="cyan")

    # ─────────────────────────────────────────────────────────────
    # Pre-flight: Python version check
    # ─────────────────────────────────────────────────────────────
    _check_python_version(console, quick)

    # Track install summary for verification output
    install_summary = {
        "scope": "project",
        "preset": None,
        "llm_provider": None,
        "llm_model": None,
        "proxy": False,
    }

    # ─────────────────────────────────────────────────────────────
    # Step 1: Detect Claude Code CLI
    # ─────────────────────────────────────────────────────────────
    claude_path = shutil.which("claude")
    if claude_path:
        console.print(f"[green]✓[/green] Claude Code detected ({claude_path})")
    else:
        console.print()
        console.print("[yellow]⚠ Claude Code not detected on this system[/yellow]")
        console.print("  [dim]Tweek hooks require Claude Code to function.[/dim]")
        console.print("  [dim]https://docs.anthropic.com/en/docs/claude-code[/dim]")
        console.print()
        if quick or not click.confirm("Continue installing hooks anyway?", default=False):
            if not quick:
                console.print()
                console.print("[dim]Run 'tweek install' later after installing Claude Code.[/dim]")
            return
        console.print()

    # ─────────────────────────────────────────────────────────────
    # Step 2: Scope selection (always shown unless --global or --quick)
    # ─────────────────────────────────────────────────────────────
    if not install_global and not dev_test and not quick:
        # Smart default: if in a git repo, default to project; otherwise global
        in_git_repo = (Path.cwd() / ".git").exists()
        default_scope = 1 if in_git_repo else 2

        console.print()
        console.print("[bold]Installation Scope[/bold]")
        console.print()
        console.print("  [cyan]1.[/cyan] This project only (./.claude/)")
        console.print("     [dim]Protects only the current project[/dim]")
        console.print("  [cyan]2.[/cyan] All projects globally (~/.claude/)")
        console.print("     [dim]Protects every project on this machine[/dim]")
        console.print()
        if in_git_repo:
            console.print(f"  [dim]Git repo detected — defaulting to project scope[/dim]")
        else:
            console.print(f"  [dim]No git repo — defaulting to global scope[/dim]")
        console.print()
        scope_choice = click.prompt("Select", type=click.IntRange(1, 2), default=default_scope)
        if scope_choice == 2:
            install_global = True
        console.print()

    # Determine target directory based on scope
    if dev_test:
        console.print("[yellow]Installing in DEV TEST mode (isolated environment)[/yellow]")
        target = Path("~/AI/tweek/test-environment/.claude").expanduser()
        install_summary["scope"] = "dev-test"
    elif install_global:
        target = Path("~/.claude").expanduser()
        console.print(f"[cyan]Scope: global[/cyan] — Hooks will protect all projects")
        install_summary["scope"] = "global"
    else:  # project (default)
        target = Path.cwd() / ".claude"
        console.print(f"[cyan]Scope: project[/cyan] — Hooks will protect this project only")
        install_summary["scope"] = "project"

    # ─────────────────────────────────────────────────────────────
    # Step 3: Scope conflict detection
    # ─────────────────────────────────────────────────────────────
    if not dev_test:
        try:
            if install_global:
                # Installing globally — check if project-level hooks exist here
                project_settings = Path.cwd() / ".claude" / "settings.json"
                if project_settings.exists():
                    with open(project_settings) as f:
                        project_config = json.load(f)
                    if _has_tweek_hooks(project_config):
                        console.print("[dim]Note: Tweek is also installed in this project.[/dim]")
                        console.print("[dim]Project-level settings take precedence over global.[/dim]")
                        console.print()
            else:
                # Installing per-project — check if global hooks exist
                global_settings = Path("~/.claude/settings.json").expanduser()
                if global_settings.exists():
                    with open(global_settings) as f:
                        global_config = json.load(f)
                    if _has_tweek_hooks(global_config):
                        console.print("[dim]Note: Tweek is also installed globally.[/dim]")
                        console.print("[dim]Project-level settings will take precedence in this directory.[/dim]")
                        console.print()
        except (json.JSONDecodeError, IOError):
            pass

    # ─────────────────────────────────────────────────────────────
    # Step 4: Detect Moltbot and offer protection options
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
                console.print("[green]✓[/green] Moltbot detected on this system")

                if moltbot_status["gateway_active"]:
                    console.print(f"  Gateway running on port {moltbot_status['port']}")
                elif moltbot_status["running"]:
                    console.print(f"  [dim]Process running (gateway may start on port {moltbot_status['port']})[/dim]")
                else:
                    console.print(f"  [dim]Installed but not currently running[/dim]")

                if moltbot_status["config_path"]:
                    console.print(f"  [dim]Config: {moltbot_status['config_path']}[/dim]")

                console.print()

                if force_proxy:
                    proxy_override_enabled = True
                    console.print("[green]✓[/green] Force proxy enabled - Tweek will override moltbot")
                    console.print()
                else:
                    console.print("[cyan]Tweek can protect Moltbot tool calls. Choose a method:[/cyan]")
                    console.print()
                    console.print("  [cyan]1.[/cyan] Protect via [bold]tweek-security[/bold] MoltHub skill")
                    console.print("     [dim]Screens tool calls through Tweek as a MoltHub skill[/dim]")
                    console.print("  [cyan]2.[/cyan] Protect via [bold]tweek protect moltbot[/bold]")
                    console.print("     [dim]Wraps the Moltbot gateway with Tweek's proxy[/dim]")
                    console.print("  [cyan]3.[/cyan] Skip for now")
                    console.print("     [dim]You can set up Moltbot protection later[/dim]")
                    console.print()

                    choice = click.prompt(
                        "Select",
                        type=click.IntRange(1, 3),
                        default=3,
                    )

                    if choice == 1:
                        console.print()
                        console.print("[green]✓[/green] To add Moltbot protection via the skill, run:")
                        console.print("  [bold]moltbot protect tweek-security[/bold]")
                        console.print()
                    elif choice == 2:
                        proxy_override_enabled = True
                        console.print()
                        console.print("[green]✓[/green] Moltbot proxy protection will be configured")
                        console.print(f"  [dim]Run 'tweek protect moltbot' after installation to complete setup[/dim]")
                        console.print()
                    else:
                        console.print()
                        console.print("[dim]Skipped. Run 'tweek protect moltbot' or add the[/dim]")
                        console.print("[dim]tweek-security skill later to protect Moltbot.[/dim]")
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

    # ─────────────────────────────────────────────────────────────
    # Step 5: Install hooks into settings.json
    # ─────────────────────────────────────────────────────────────
    hook_script = Path(__file__).parent / "hooks" / "pre_tool_use.py"
    post_hook_script = Path(__file__).parent / "hooks" / "post_tool_use.py"

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

    # Use the exact Python that ran `tweek install` so hooks work even when
    # /usr/bin/env python3 resolves to a different interpreter (e.g., system
    # Python 3.9 while Tweek was installed via pyenv/Homebrew Python 3.12).
    python_exe = sys.executable

    # PreToolUse: screen tool requests before execution
    # Match ALL security-relevant tools, not just Bash — Write/Edit/Read/WebFetch
    # all have screening logic in pre_tool_use.py that must be reachable
    settings["hooks"]["PreToolUse"] = [
        {
            "matcher": "Bash|Write|Edit|Read|WebFetch|NotebookEdit|WebSearch",
            "hooks": [
                {
                    "type": "command",
                    "command": f"{python_exe} {hook_script.resolve()}"
                }
            ]
        }
    ]

    # PostToolUse: screen content returned by tools for injection
    # Include WebSearch and Grep for content injection detection
    settings["hooks"]["PostToolUse"] = [
        {
            "matcher": "Read|WebFetch|Bash|Grep|WebSearch",
            "hooks": [
                {
                    "type": "command",
                    "command": f"{python_exe} {post_hook_script.resolve()}"
                }
            ]
        }
    ]

    with open(settings_file, "w") as f:
        json.dump(settings, f, indent=2)

    console.print(f"\n[green]✓[/green] PreToolUse hooks installed to: {target}")
    console.print(f"[green]✓[/green] PostToolUse content screening installed to: {target}")

    # Create Tweek data directory
    tweek_dir = Path("~/.tweek").expanduser()
    tweek_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[green]✓[/green] Tweek data directory: {tweek_dir}")

    # ─────────────────────────────────────────────────────────────
    # Step 6: Install Tweek skill for Claude Code
    # ─────────────────────────────────────────────────────────────
    skill_source = Path(__file__).resolve().parent / "skill_template"
    skill_target = target / "skills" / "tweek"

    if skill_source.is_dir() and (skill_source / "SKILL.md").exists():
        # Copy skill files to target (overwrite if exists)
        if skill_target.exists():
            shutil.rmtree(skill_target)
        shutil.copytree(skill_source, skill_target)
        console.print(f"[green]✓[/green] Tweek skill installed to: {skill_target}")
        console.print(f"  [dim]Claude now understands Tweek warnings and commands[/dim]")

        # Add whitelist entry for the skill directory in overrides
        try:
            import yaml

            overrides_path = tweek_dir / "overrides.yaml"
            overrides = {}
            if overrides_path.exists():
                with open(overrides_path) as f:
                    overrides = yaml.safe_load(f) or {}

            whitelist = overrides.get("whitelist", [])

            # Check if skill path is already whitelisted
            skill_target_str = str(skill_target)
            already_whitelisted = any(
                entry.get("path", "").rstrip("/") == skill_target_str.rstrip("/")
                for entry in whitelist
                if isinstance(entry, dict)
            )

            if not already_whitelisted:
                whitelist.append({
                    "path": skill_target_str,
                    "tools": ["Read", "Grep"],
                    "reason": "Tweek skill files shipped with package",
                })
                overrides["whitelist"] = whitelist

                with open(overrides_path, "w") as f:
                    yaml.dump(overrides, f, default_flow_style=False, sort_keys=False)

                console.print(f"[green]✓[/green] Skill directory whitelisted in overrides")

        except ImportError:
            console.print(f"[dim]Note: PyYAML not available — skill whitelist not added to overrides[/dim]")
        except Exception as e:
            console.print(f"[dim]Warning: Could not update overrides whitelist: {e}[/dim]")
    else:
        console.print(f"[dim]Tweek skill source not found — skill not installed[/dim]")
        console.print(f"  [dim]Skill can be installed manually from the tweek repository[/dim]")

    # ─────────────────────────────────────────────────────────────
    # Step 7: Security Configuration
    # ─────────────────────────────────────────────────────────────
    cfg = ConfigManager()

    if preset:
        # Apply preset directly
        cfg.apply_preset(preset)
        console.print(f"\n[green]✓[/green] Applied [bold]{preset}[/bold] security preset")
        install_summary["preset"] = preset

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
        install_summary["preset"] = "cautious (ai-defaults)"

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
            install_summary["preset"] = "paranoid"
        elif choice == 2:
            cfg.apply_preset("cautious")
            console.print("[green]✓[/green] Applied cautious preset")
            install_summary["preset"] = "cautious"
        elif choice == 3:
            cfg.apply_preset("trusted")
            console.print("[green]✓[/green] Applied trusted preset")
            install_summary["preset"] = "trusted"
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
            install_summary["preset"] = "custom"

    else:
        # Default: apply cautious preset silently
        if not cfg.export_config("user"):
            cfg.apply_preset("cautious")
            console.print("\n[green]✓[/green] Applied default [bold]cautious[/bold] security preset")
            console.print("[dim]Run 'tweek config interactive' to customize[/dim]")
            install_summary["preset"] = "cautious"
        else:
            install_summary["preset"] = "existing"

    # ─────────────────────────────────────────────────────────────
    # Step 8: LLM Review Provider Selection
    # ─────────────────────────────────────────────────────────────
    llm_config = _configure_llm_provider(tweek_dir, interactive, quick)
    install_summary["llm_provider"] = llm_config.get("provider_display", "auto-detect")
    install_summary["llm_model"] = llm_config.get("model_display")

    # ─────────────────────────────────────────────────────────────
    # Step 9: Scan for .env files (moved after security config)
    # ─────────────────────────────────────────────────────────────
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
    # Step 10: Linux: Prompt for firejail installation
    # ─────────────────────────────────────────────────────────────
    if IS_LINUX:
        caps = get_capabilities()
        if not caps.sandbox_available:
            if with_sandbox or (interactive and not quick):
                from tweek.sandbox.linux import prompt_install_firejail
                prompt_install_firejail(console)
            else:
                console.print("\n[yellow]Note:[/yellow] Sandbox (firejail) not installed.")
                console.print(f"[dim]Install with: {caps.sandbox_install_hint}[/dim]")
                console.print("[dim]Or run 'tweek install --with-sandbox' to install now[/dim]")

    # ─────────────────────────────────────────────────────────────
    # Step 11: Configure Tweek proxy if override was enabled
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
            install_summary["proxy"] = True
        except Exception as e:
            console.print(f"\n[yellow]Warning: Could not save proxy config: {e}[/yellow]")

    # ─────────────────────────────────────────────────────────────
    # Step 12: Post-install verification and summary
    # ─────────────────────────────────────────────────────────────
    _print_install_summary(install_summary, target, tweek_dir, proxy_override_enabled)


def _check_python_version(console: Console, quick: bool) -> None:
    """Check Python version and warn about potential issues.

    Verifies:
    1. Current Python meets minimum version (3.9+)
    2. System `python3` matches the install Python (hook compatibility)
    """
    import platform as plat

    min_version = (3, 9)
    current = sys.version_info[:2]

    # Check 1: Current Python version
    if current < min_version:
        console.print(f"[red]ERROR: Python {min_version[0]}.{min_version[1]}+ required, "
                       f"but running {current[0]}.{current[1]}[/red]")
        console.print()
        console.print("[bold]How to install a supported Python version:[/bold]")
        console.print()

        system = plat.system()
        if system == "Darwin":
            console.print("  [cyan]Option 1: Homebrew (recommended)[/cyan]")
            console.print("    brew install python@3.12")
            console.print("    brew link python@3.12")
            console.print()
            console.print("  [cyan]Option 2: pyenv[/cyan]")
            console.print("    brew install pyenv")
            console.print("    pyenv install 3.12.10")
            console.print("    pyenv global 3.12.10")
            console.print()
            console.print("  [cyan]Option 3: python.org installer[/cyan]")
            console.print("    https://www.python.org/downloads/")
        elif system == "Linux":
            console.print("  [cyan]Option 1: System package manager[/cyan]")
            if shutil.which("apt"):
                console.print("    sudo apt update && sudo apt install python3.12 python3.12-venv")
            elif shutil.which("dnf"):
                console.print("    sudo dnf install python3.12")
            elif shutil.which("pacman"):
                console.print("    sudo pacman -S python")
            else:
                console.print("    Install python3.12 via your package manager")
            console.print()
            console.print("  [cyan]Option 2: pyenv[/cyan]")
            console.print("    curl https://pyenv.run | bash")
            console.print("    pyenv install 3.12.10")
            console.print("    pyenv global 3.12.10")
        elif system == "Windows":
            console.print("  [cyan]Option 1: python.org installer[/cyan]")
            console.print("    https://www.python.org/downloads/")
            console.print()
            console.print("  [cyan]Option 2: winget[/cyan]")
            console.print("    winget install Python.Python.3.12")
        else:
            console.print("  https://www.python.org/downloads/")

        console.print()
        console.print("[dim]After installing, run: pip install tweek && tweek install[/dim]")
        raise SystemExit(1)

    console.print(f"[green]✓[/green] Python {current[0]}.{current[1]} ({sys.executable})")

    # Check 2: Warn if system python3 differs from install Python
    # This matters because hooks run via the Python path stored in settings.json
    system_python3 = shutil.which("python3")
    if system_python3:
        try:
            resolved_install = Path(sys.executable).resolve()
            resolved_system = Path(system_python3).resolve()

            if resolved_install != resolved_system:
                console.print(f"[dim]  Note: system python3 is {resolved_system}[/dim]")
                console.print(f"[dim]  Hooks will use {resolved_install} (the Python running this install)[/dim]")
        except (OSError, ValueError):
            pass
    else:
        if not quick:
            console.print("[yellow]  Note: python3 not found on PATH[/yellow]")
            console.print(f"[dim]  Hooks will use {sys.executable} directly[/dim]")


def _configure_llm_provider(tweek_dir: Path, interactive: bool, quick: bool) -> dict:
    """Configure LLM review provider during installation.

    Returns a dict with provider configuration details for the install summary.
    """
    import os
    import yaml

    result = {
        "provider": "auto",
        "model": "auto",
        "base_url": None,
        "api_key_env": None,
        "provider_display": None,
        "model_display": None,
    }

    # Provider display names and default models
    provider_defaults = {
        "anthropic": ("Anthropic", "claude-3-5-haiku-latest", "ANTHROPIC_API_KEY"),
        "openai": ("OpenAI", "gpt-4o-mini", "OPENAI_API_KEY"),
        "google": ("Google", "gemini-2.0-flash", "GOOGLE_API_KEY"),
    }

    if not quick:
        # Check local model availability for menu display
        local_model_ready = False
        local_model_name = None
        try:
            from tweek.security.local_model import LOCAL_MODEL_AVAILABLE
            from tweek.security.model_registry import is_model_installed, get_default_model_name

            if LOCAL_MODEL_AVAILABLE:
                local_model_name = get_default_model_name()
                local_model_ready = is_model_installed(local_model_name)
        except ImportError:
            pass

        console.print()
        console.print("[bold]Security Screening Provider[/bold] (Layer 3 — semantic analysis)")
        console.print()
        console.print("  Tweek can analyze suspicious commands for deeper security screening.")
        console.print("  A local on-device model is preferred (no API key needed), with")
        console.print("  optional cloud LLM escalation for uncertain cases.")
        console.print()
        console.print("  [cyan]1.[/cyan] Auto-detect (recommended)")
        if local_model_ready:
            console.print(f"     [dim]Local model installed ({local_model_name}) — will use it first[/dim]")
        else:
            console.print("     [dim]Uses first available: Local model > Anthropic > OpenAI > Google[/dim]")
        console.print("  [cyan]2.[/cyan] Anthropic (Claude Haiku)")
        console.print("  [cyan]3.[/cyan] OpenAI (GPT-4o-mini)")
        console.print("  [cyan]4.[/cyan] Google (Gemini 2.0 Flash)")
        console.print("  [cyan]5.[/cyan] Custom endpoint (Ollama, LM Studio, Together, Groq, etc.)")
        console.print("  [cyan]6.[/cyan] Disable screening")
        if not local_model_ready:
            console.print()
            console.print("  [dim]Tip: Run 'tweek model download' to install the local model[/dim]")
            console.print("  [dim]     (on-device, no API key, ~45MB download)[/dim]")
        console.print()

        choice = click.prompt("Select", type=click.IntRange(1, 6), default=1)

        if choice == 1:
            result["provider"] = "auto"
        elif choice == 2:
            result["provider"] = "anthropic"
            result["model"] = "claude-3-5-haiku-latest"
        elif choice == 3:
            result["provider"] = "openai"
            result["model"] = "gpt-4o-mini"
        elif choice == 4:
            result["provider"] = "google"
            result["model"] = "gemini-2.0-flash"
        elif choice == 5:
            # Custom endpoint configuration
            console.print()
            console.print("[bold]Custom Endpoint Configuration[/bold]")
            console.print("[dim]Most local servers (Ollama, LM Studio, vLLM) and cloud providers[/dim]")
            console.print("[dim](Together, Groq, Mistral) expose an OpenAI-compatible API.[/dim]")
            console.print()

            result["provider"] = "openai"
            result["base_url"] = click.prompt(
                "  Base URL",
                default="http://localhost:11434/v1",
            )
            result["model"] = click.prompt(
                "  Model name",
                default="llama3.2",
            )
            api_key_env = click.prompt(
                "  API key env var (blank for local/no auth)",
                default="",
            )
            if api_key_env:
                result["api_key_env"] = api_key_env
            console.print()
        elif choice == 6:
            result["provider"] = "disabled"
            console.print("[dim]Screening disabled. Pattern matching and other layers remain active.[/dim]")
    # else: quick mode — leave as auto

    # Resolve display names for summary
    if result["provider"] == "auto":
        # Run auto-detection to show what was actually selected
        detected = _detect_llm_provider()
        if detected:
            result["provider_display"] = detected["name"]
            result["model_display"] = detected["model"]
        else:
            result["provider_display"] = "disabled (no provider found)"
            result["model_display"] = None
    elif result["provider"] == "disabled":
        result["provider_display"] = "disabled"
        result["model_display"] = None
    elif result["provider"] in provider_defaults:
        display_name, default_model, _ = provider_defaults[result["provider"]]
        result["provider_display"] = display_name
        result["model_display"] = result["model"] if result["model"] != "auto" else default_model
    else:
        result["provider_display"] = result["provider"]
        result["model_display"] = result["model"]

    # If custom endpoint, show base_url in display
    if result.get("base_url"):
        result["provider_display"] = f"OpenAI-compatible ({result['base_url']})"

    # Validate connectivity if provider was explicitly selected (not auto, not disabled)
    if result["provider"] not in ("auto", "disabled") and not quick:
        _validate_llm_provider(result)

    # Save LLM config to ~/.tweek/config.yaml
    if result["provider"] != "auto" or result.get("base_url"):
        try:
            config_path = tweek_dir / "config.yaml"
            if config_path.exists():
                with open(config_path) as f:
                    tweek_config = yaml.safe_load(f) or {}
            else:
                tweek_config = {}

            llm_section = tweek_config.get("llm_review", {})

            if result["provider"] == "disabled":
                llm_section["enabled"] = False
            else:
                llm_section["enabled"] = True
                llm_section["provider"] = result["provider"]
                if result["model"] != "auto":
                    llm_section["model"] = result["model"]
                if result.get("base_url"):
                    llm_section["base_url"] = result["base_url"]
                if result.get("api_key_env"):
                    llm_section["api_key_env"] = result["api_key_env"]

            tweek_config["llm_review"] = llm_section

            with open(config_path, "w") as f:
                yaml.dump(tweek_config, f, default_flow_style=False, sort_keys=False)

            if result["provider"] == "disabled":
                console.print("[green]✓[/green] LLM review disabled in config")
            else:
                console.print(f"[green]✓[/green] LLM provider configured: {result['provider_display']}")
        except Exception as e:
            console.print(f"[dim]Warning: Could not save LLM config: {e}[/dim]")
    else:
        if result["provider_display"] and "disabled" not in (result["provider_display"] or ""):
            console.print(f"[green]✓[/green] LLM provider: {result['provider_display']} ({result.get('model_display', 'auto')})")
        elif result["provider"] == "auto":
            console.print(f"[green]✓[/green] LLM provider: {result['provider_display']}")

    return result


def _detect_llm_provider() -> Optional[dict]:
    """Detect which LLM provider is available based on environment.

    Priority: Local ONNX model > Anthropic > OpenAI > Google.
    Returns dict with 'name' and 'model', or None if none available.
    """
    import os

    # Check local ONNX model first (no API key needed)
    try:
        from tweek.security.local_model import LOCAL_MODEL_AVAILABLE
        from tweek.security.model_registry import is_model_installed, get_default_model_name

        if LOCAL_MODEL_AVAILABLE:
            default_model = get_default_model_name()
            if is_model_installed(default_model):
                return {"name": "Local model", "model": default_model, "env_var": None}
    except ImportError:
        pass

    # Cloud providers
    checks = [
        ("ANTHROPIC_API_KEY", "Anthropic", "claude-3-5-haiku-latest"),
        ("OPENAI_API_KEY", "OpenAI", "gpt-4o-mini"),
        ("GOOGLE_API_KEY", "Google", "gemini-2.0-flash"),
        ("GEMINI_API_KEY", "Google", "gemini-2.0-flash"),
    ]

    for env_var, name, model in checks:
        if os.environ.get(env_var):
            return {"name": name, "model": model, "env_var": env_var}

    return None


def _validate_llm_provider(llm_config: dict) -> None:
    """Validate LLM provider connectivity after selection.

    Checks if the required API key is available and attempts a quick
    availability check. Offers fallback options if validation fails.
    """
    import os

    provider = llm_config.get("provider", "auto")

    # Map provider to expected env vars
    env_var_map = {
        "anthropic": ["ANTHROPIC_API_KEY"],
        "openai": ["OPENAI_API_KEY"],
        "google": ["GOOGLE_API_KEY", "GEMINI_API_KEY"],
    }

    # For custom endpoints with api_key_env, check that env var
    if llm_config.get("api_key_env"):
        expected_vars = [llm_config["api_key_env"]]
    elif llm_config.get("base_url"):
        # Local endpoints (Ollama etc.) don't need an API key
        console.print(f"  [dim]Checking endpoint: {llm_config['base_url']}[/dim]")
        try:
            from tweek.security.llm_reviewer import resolve_provider
            test_provider = resolve_provider(
                provider="openai",
                model=llm_config.get("model", "auto"),
                base_url=llm_config["base_url"],
                timeout=3.0,
            )
            if test_provider and test_provider.is_available():
                console.print(f"  [green]✓[/green] Endpoint reachable")
            else:
                console.print(f"  [yellow]⚠[/yellow] Could not verify endpoint")
                console.print(f"  [dim]Tweek will try this endpoint at runtime[/dim]")
        except Exception:
            console.print(f"  [yellow]⚠[/yellow] Could not verify endpoint")
            console.print(f"  [dim]Tweek will try this endpoint at runtime[/dim]")
        return
    else:
        expected_vars = env_var_map.get(provider, [])

    if not expected_vars:
        return

    # Check if any expected env var is set
    found_key = False
    for var in expected_vars:
        if os.environ.get(var):
            found_key = True
            console.print(f"  [green]✓[/green] {var} found")
            break

    if not found_key:
        var_list = " or ".join(expected_vars)
        console.print(f"  [yellow]⚠[/yellow] {var_list} not set in environment")
        console.print(f"  [dim]LLM review will be disabled until the key is available.[/dim]")
        console.print(f"  [dim]Set it in your shell profile or .env file, then restart Claude Code.[/dim]")

        # Offer fallback
        console.print()
        fallback = click.prompt(
            "  Continue with this provider or switch to auto-detect?",
            type=click.Choice(["continue", "auto"]),
            default="continue",
        )
        if fallback == "auto":
            llm_config["provider"] = "auto"
            detected = _detect_llm_provider()
            if detected:
                llm_config["provider_display"] = detected["name"]
                llm_config["model_display"] = detected["model"]
                console.print(f"  [green]✓[/green] Switched to auto-detect: {detected['name']}")
            else:
                llm_config["provider_display"] = "disabled (no API key found)"
                llm_config["model_display"] = None
                console.print(f"  [dim]No API keys found — LLM review will be disabled[/dim]")


def _print_install_summary(
    summary: dict,
    target: Path,
    tweek_dir: Path,
    proxy_override_enabled: bool,
) -> None:
    """Print post-install verification and summary."""
    from tweek.platform import get_capabilities

    console.print()
    console.print("[green]Installation complete![/green]")
    console.print()

    # Verification checks
    console.print("[bold]Verification[/bold]")

    # Check hooks are installed and Python path is valid
    settings_file = target / "settings.json"
    hook_python = None
    if settings_file.exists():
        try:
            import json
            with open(settings_file) as f:
                settings = json.load(f)
            hooks = settings.get("hooks", {})
            has_pre = "PreToolUse" in hooks
            has_post = "PostToolUse" in hooks
            if has_pre and has_post:
                console.print("  [green]✓[/green] PreToolUse + PostToolUse hooks active")
                # Extract Python path from hook command to verify it exists
                try:
                    cmd = hooks["PreToolUse"][0]["hooks"][0]["command"]
                    hook_python = cmd.split()[0]
                    if Path(hook_python).exists():
                        console.print(f"  [green]✓[/green] Hook Python: {hook_python}")
                    else:
                        console.print(f"  [yellow]⚠[/yellow] Hook Python not found: {hook_python}")
                        console.print(f"    [dim]Run 'tweek install' again if Python was reinstalled[/dim]")
                except (IndexError, KeyError):
                    pass
            elif has_pre:
                console.print("  [green]✓[/green] PreToolUse hook active")
                console.print("  [yellow]⚠[/yellow] PostToolUse hook missing")
            else:
                console.print("  [yellow]⚠[/yellow] Hooks may not be installed correctly")
        except Exception:
            console.print("  [yellow]⚠[/yellow] Could not verify hook installation")
    else:
        console.print("  [yellow]⚠[/yellow] Settings file not found")

    # Check pattern database
    patterns_file = Path(__file__).parent / "config" / "patterns.yaml"
    pattern_count = 0
    if patterns_file.exists():
        try:
            import yaml
            with open(patterns_file) as f:
                pdata = yaml.safe_load(f) or {}
            pattern_count = len(pdata.get("patterns", []))
            console.print(f"  [green]✓[/green] Pattern database loaded ({pattern_count} patterns)")
        except Exception:
            console.print("  [yellow]⚠[/yellow] Could not load pattern database")
    else:
        console.print("  [yellow]⚠[/yellow] Pattern database not found")

    # LLM reviewer status
    llm_display = summary.get("llm_provider", "auto-detect")
    llm_model = summary.get("llm_model")
    if llm_model:
        console.print(f"  [green]✓[/green] LLM reviewer: {llm_display} ({llm_model})")
    elif llm_display and "disabled" not in llm_display:
        console.print(f"  [green]✓[/green] LLM reviewer: {llm_display}")
    else:
        console.print(f"  [dim]○[/dim] LLM reviewer: {llm_display}")

    # Sandbox status
    caps = get_capabilities()
    if caps.sandbox_available:
        console.print(f"  [green]✓[/green] Sandbox: {caps.sandbox_tool}")
    else:
        console.print(f"  [dim]○[/dim] Sandbox: not available ({caps.platform.value})")

    # Summary table
    console.print()
    console.print("[bold]Summary[/bold]")

    scope_display = summary.get("scope", "project")
    if scope_display == "project":
        scope_display = f"project ({target})"
    elif scope_display == "global":
        scope_display = f"global (~/.claude/)"

    py_ver = f"{sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}"
    console.print(f"  Python:   {py_ver} ({sys.executable})")
    console.print(f"  Scope:    {scope_display}")
    console.print(f"  Preset:   {summary.get('preset', 'cautious')}")

    llm_summary = llm_display
    if llm_model:
        llm_summary = f"{llm_display} ({llm_model})"
    console.print(f"  LLM:      {llm_summary}")

    console.print(f"  Patterns: {pattern_count}")
    console.print(f"  Sandbox:  {'available' if caps.sandbox_available else 'not available'}")
    console.print(f"  Proxy:    {'configured' if proxy_override_enabled else 'not configured'}")

    # Next steps
    console.print()
    console.print("[dim]Next steps:[/dim]")
    console.print("[dim]  tweek status       — Verify installation[/dim]")
    console.print("[dim]  tweek update       — Get latest attack patterns[/dim]")
    console.print("[dim]  tweek config list  — See security settings[/dim]")
    if proxy_override_enabled:
        console.print("[dim]  tweek proxy start  — Enable API interception[/dim]")


@main.command(
    epilog="""\b
Examples:
  tweek uninstall                        Remove from current project
  tweek uninstall --global               Remove global installation
  tweek uninstall --everything           Remove ALL Tweek data system-wide
  tweek uninstall --confirm              Skip confirmation prompt
"""
)
@click.option("--global", "uninstall_global", is_flag=True, default=False,
              help="Uninstall from ~/.claude/ (global installation)")
@click.option("--everything", is_flag=True, default=False,
              help="Remove ALL Tweek data: hooks, skills, config, patterns, logs, MCP integrations")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def uninstall(uninstall_global: bool, everything: bool, confirm: bool):
    """Remove Tweek hooks and data from Claude Code.

    By default, removes from the current project (./.claude/).
    Use --global to remove from ~/.claude/.
    Use --everything to remove ALL Tweek data system-wide.

    This command can only be run from an interactive terminal.
    AI agents are blocked from running it.
    """
    import json

    # ─────────────────────────────────────────────────────────────
    # HUMAN-ONLY GATE: Block non-interactive execution
    # This is Layer 2 of protection (Layer 1 is the PreToolUse hook)
    # ─────────────────────────────────────────────────────────────
    if not sys.stdin.isatty():
        console.print("[red]ERROR: tweek uninstall must be run from an interactive terminal.[/red]")
        console.print("[dim]This command cannot be run by AI agents or automated scripts.[/dim]")
        console.print("[dim]Open a terminal and run the command directly.[/dim]")
        raise SystemExit(1)

    console.print(TWEEK_BANNER, style="cyan")

    tweek_dir = Path("~/.tweek").expanduser()
    global_target = Path("~/.claude").expanduser()
    project_target = Path.cwd() / ".claude"

    if everything:
        _uninstall_everything(global_target, project_target, tweek_dir, confirm)
    elif uninstall_global:
        _uninstall_scope(global_target, tweek_dir, confirm, scope_label="global")
    else:
        _uninstall_scope(project_target, tweek_dir, confirm, scope_label="project")


# ─────────────────────────────────────────────────────────────
# Uninstall Helpers
# ─────────────────────────────────────────────────────────────


def _remove_hooks_from_settings(settings_file: Path) -> list:
    """Remove Tweek hooks from a settings.json file.

    Returns list of hook types removed (e.g. ['PreToolUse', 'PostToolUse']).
    """
    import json

    removed = []

    if not settings_file.exists():
        return removed

    try:
        with open(settings_file) as f:
            settings = json.load(f)
    except (json.JSONDecodeError, IOError):
        return removed

    if not _has_tweek_hooks(settings):
        return removed

    for hook_type in ("PreToolUse", "PostToolUse"):
        if "hooks" not in settings or hook_type not in settings["hooks"]:
            continue

        tool_hooks = settings["hooks"][hook_type]
        filtered_hooks = []
        for hook_config in tool_hooks:
            filtered_inner = []
            for hook in hook_config.get("hooks", []):
                if "tweek" not in hook.get("command", "").lower():
                    filtered_inner.append(hook)
            if filtered_inner:
                hook_config["hooks"] = filtered_inner
                filtered_hooks.append(hook_config)

        if filtered_hooks:
            settings["hooks"][hook_type] = filtered_hooks
        else:
            del settings["hooks"][hook_type]
            removed.append(hook_type)

    # Clean up empty hooks dict
    if "hooks" in settings and not settings["hooks"]:
        del settings["hooks"]

    with open(settings_file, "w") as f:
        json.dump(settings, f, indent=2)

    return removed


def _remove_skill_directory(target: Path) -> bool:
    """Remove the Tweek skill directory from a .claude/ target. Returns True if removed."""
    skill_dir = target / "skills" / "tweek"
    if skill_dir.exists() and skill_dir.is_dir():
        shutil.rmtree(skill_dir)
        return True
    return False


def _remove_backup_file(target: Path) -> bool:
    """Remove the settings.json.tweek-backup file. Returns True if removed."""
    backup = target / "settings.json.tweek-backup"
    if backup.exists():
        backup.unlink()
        return True
    return False


def _remove_whitelist_entries(target: Path, tweek_dir: Path) -> int:
    """Remove whitelist entries for target path from overrides.yaml. Returns count removed."""
    import yaml

    overrides_path = tweek_dir / "overrides.yaml"
    if not overrides_path.exists():
        return 0

    try:
        with open(overrides_path) as f:
            data = yaml.safe_load(f) or {}
    except (yaml.YAMLError, IOError):
        return 0

    whitelist = data.get("whitelist", [])
    if not whitelist:
        return 0

    target_str = str(target.resolve())
    original_count = len(whitelist)

    data["whitelist"] = [
        entry for entry in whitelist
        if not (isinstance(entry, dict) and
                str(Path(entry.get("path", "")).resolve()).startswith(target_str))
    ]

    removed_count = original_count - len(data["whitelist"])
    if removed_count > 0:
        with open(overrides_path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    return removed_count


def _remove_tweek_data_dir(tweek_dir: Path) -> list:
    """Remove ~/.tweek/ directory and all contents. Returns list of items removed."""
    removed = []

    if not tweek_dir.exists():
        return removed

    # Remove known items with individual feedback
    items = [
        ("config.yaml", "configuration"),
        ("overrides.yaml", "security overrides"),
        ("security.db", "security log database"),
    ]
    for filename, label in items:
        filepath = tweek_dir / filename
        if filepath.exists():
            filepath.unlink()
            removed.append(label)

    dirs = [
        ("patterns", "pattern repository"),
        ("chamber", "skill isolation chamber"),
        ("jail", "skill jail"),
        ("skills", "managed skills"),
    ]
    for dirname, label in dirs:
        dirpath = tweek_dir / dirname
        if dirpath.exists() and dirpath.is_dir():
            shutil.rmtree(dirpath)
            removed.append(label)

    # Remove any remaining files
    remaining = list(tweek_dir.iterdir()) if tweek_dir.exists() else []
    for item in remaining:
        if item.is_dir():
            shutil.rmtree(item)
        else:
            item.unlink()

    # Remove the directory itself
    if tweek_dir.exists():
        try:
            tweek_dir.rmdir()
            removed.append("data directory (~/.tweek/)")
        except OSError:
            # Not empty for some reason
            shutil.rmtree(tweek_dir, ignore_errors=True)
            removed.append("data directory (~/.tweek/)")

    return removed


def _remove_mcp_integrations() -> list:
    """Remove MCP integrations for all known clients. Returns list of clients removed."""
    removed = []
    clients = {
        "claude-desktop": Path("~/Library/Application Support/Claude/claude_desktop_config.json").expanduser(),
        "chatgpt": Path("~/Library/Application Support/com.openai.chat/config.json").expanduser(),
    }

    for client_name, config_path in clients.items():
        if not config_path.exists():
            continue
        try:
            import json
            with open(config_path) as f:
                config = json.load(f)
            mcp_servers = config.get("mcpServers", {})
            tweek_keys = [k for k in mcp_servers if "tweek" in k.lower()]
            if tweek_keys:
                for key in tweek_keys:
                    del mcp_servers[key]
                with open(config_path, "w") as f:
                    json.dump(config, f, indent=2)
                removed.append(client_name)
        except (json.JSONDecodeError, IOError, KeyError):
            continue

    return removed


def _uninstall_scope(target: Path, tweek_dir: Path, confirm: bool, scope_label: str):
    """Uninstall Tweek from a single scope (project or global)."""
    import json

    settings_file = target / "settings.json"
    has_hooks = False
    has_skills = (target / "skills" / "tweek").exists()
    has_backup = (target / "settings.json.tweek-backup").exists()

    if settings_file.exists():
        try:
            with open(settings_file) as f:
                settings = json.load(f)
            has_hooks = _has_tweek_hooks(settings)
        except (json.JSONDecodeError, IOError):
            pass

    if not has_hooks and not has_skills and not has_backup:
        console.print(f"[yellow]No Tweek installation found at {target}[/yellow]")
        return

    console.print(f"[bold]Found Tweek installation at:[/bold] {target}")
    console.print()
    console.print("[bold]The following will be removed:[/bold]")
    if has_hooks:
        console.print("  [dim]•[/dim] PreToolUse and PostToolUse hooks from settings.json")
    if has_skills:
        console.print("  [dim]•[/dim] Tweek skill directory (skills/tweek/)")
    if has_backup:
        console.print("  [dim]•[/dim] Backup file (settings.json.tweek-backup)")
    console.print("  [dim]•[/dim] Project whitelist entries from overrides")
    console.print()

    if not confirm:
        if not click.confirm(f"[yellow]Remove Tweek from this {scope_label}?[/yellow]"):
            console.print("[dim]Cancelled[/dim]")
            return

    console.print()

    # 1. Remove hooks
    removed_hooks = _remove_hooks_from_settings(settings_file)
    for hook_type in removed_hooks:
        console.print(f"  [green]✓[/green] Removed {hook_type} hook from settings.json")
    if has_hooks and not removed_hooks:
        console.print(f"  [red]✗[/red] Failed to remove hooks from settings.json")

    # 2. Remove skill directory
    if _remove_skill_directory(target):
        console.print(f"  [green]✓[/green] Removed Tweek skill directory (skills/tweek/)")
    else:
        console.print(f"  [dim]-[/dim] Skipped: Tweek skill directory not found")

    # 3. Remove backup file
    if _remove_backup_file(target):
        console.print(f"  [green]✓[/green] Removed backup file (settings.json.tweek-backup)")
    else:
        console.print(f"  [dim]-[/dim] Skipped: no backup file found")

    # 4. Remove whitelist entries
    wl_count = _remove_whitelist_entries(target, tweek_dir)
    if wl_count > 0:
        console.print(f"  [green]✓[/green] Removed {wl_count} whitelist entry(s) from overrides")
    else:
        console.print(f"  [dim]-[/dim] Skipped: no whitelist entries found for this {scope_label}")

    console.print()
    console.print(f"[green]Uninstall complete.[/green] Tweek is no longer active for this {scope_label}.")
    if scope_label == "project":
        console.print("[dim]Global installation (~/.claude/) was not affected.[/dim]")
        console.print("[dim]Tweek data directory (~/.tweek/) was preserved.[/dim]")
    else:
        console.print("[dim]Project installations were not affected.[/dim]")
        console.print("[dim]Tweek data directory (~/.tweek/) was preserved.[/dim]")
    console.print("[dim]Use --everything to remove all Tweek data.[/dim]")


def _uninstall_everything(global_target: Path, project_target: Path, tweek_dir: Path, confirm: bool):
    """Full system removal of all Tweek data."""
    import json

    console.print("[bold yellow]FULL REMOVAL[/bold yellow] — This will remove ALL Tweek data:\n")
    console.print("  [dim]•[/dim] Hooks from current project (.claude/settings.json)")
    console.print("  [dim]•[/dim] Hooks from global installation (~/.claude/settings.json)")
    console.print("  [dim]•[/dim] Tweek skill directories (project + global)")
    console.print("  [dim]•[/dim] All backup files")
    console.print("  [dim]•[/dim] Tweek data directory (~/.tweek/)")

    # Show what exists in ~/.tweek/
    if tweek_dir.exists():
        for item in sorted(tweek_dir.iterdir()):
            if item.is_dir():
                console.print(f"      [dim]├── {item.name}/ [/dim]")
            else:
                console.print(f"      [dim]├── {item.name}[/dim]")

    console.print("  [dim]•[/dim] MCP integrations (Claude Desktop, ChatGPT)")
    console.print()

    if not confirm:
        response = click.prompt(
            "[bold red]Type 'yes' to confirm full removal[/bold red]",
            default="",
            show_default=False,
        )
        if response.strip().lower() != "yes":
            console.print("[dim]Cancelled[/dim]")
            return

    console.print()

    # ── Project scope ──
    console.print("[bold]Project scope (.claude/):[/bold]")
    removed_hooks = _remove_hooks_from_settings(project_target / "settings.json")
    for hook_type in removed_hooks:
        console.print(f"  [green]✓[/green] Removed {hook_type} hook from project settings.json")
    if not removed_hooks:
        console.print(f"  [dim]-[/dim] Skipped: no project hooks found")

    if _remove_skill_directory(project_target):
        console.print(f"  [green]✓[/green] Removed Tweek skill from project")
    else:
        console.print(f"  [dim]-[/dim] Skipped: no project skill directory")

    if _remove_backup_file(project_target):
        console.print(f"  [green]✓[/green] Removed project backup file")
    else:
        console.print(f"  [dim]-[/dim] Skipped: no project backup file")

    console.print()

    # ── Global scope ──
    console.print("[bold]Global scope (~/.claude/):[/bold]")
    removed_hooks = _remove_hooks_from_settings(global_target / "settings.json")
    for hook_type in removed_hooks:
        console.print(f"  [green]✓[/green] Removed {hook_type} hook from global settings.json")
    if not removed_hooks:
        console.print(f"  [dim]-[/dim] Skipped: no global hooks found")

    if _remove_skill_directory(global_target):
        console.print(f"  [green]✓[/green] Removed Tweek skill from global installation")
    else:
        console.print(f"  [dim]-[/dim] Skipped: no global skill directory")

    if _remove_backup_file(global_target):
        console.print(f"  [green]✓[/green] Removed global backup file")
    else:
        console.print(f"  [dim]-[/dim] Skipped: no global backup file")

    console.print()

    # ── Tweek data directory ──
    console.print("[bold]Tweek data (~/.tweek/):[/bold]")
    data_removed = _remove_tweek_data_dir(tweek_dir)
    for item in data_removed:
        console.print(f"  [green]✓[/green] Removed {item}")
    if not data_removed:
        console.print(f"  [dim]-[/dim] Skipped: no data directory found")

    console.print()

    # ── MCP integrations ──
    console.print("[bold]MCP integrations:[/bold]")
    mcp_removed = _remove_mcp_integrations()
    for client in mcp_removed:
        console.print(f"  [green]✓[/green] Removed {client} MCP integration")
    if not mcp_removed:
        console.print(f"  [dim]-[/dim] Skipped: no MCP integrations found")

    console.print()
    console.print("[green]All Tweek data has been removed.[/green]")
    console.print("[dim]To reinstall: pipx install tweek && tweek install[/dim]")
    console.print("[dim]To also remove the Python package: pipx uninstall tweek[/dim]")


def _load_overrides_yaml() -> tuple:
    """Load ~/.tweek/overrides.yaml. Returns (data_dict, file_path)."""
    import yaml

    overrides_path = Path("~/.tweek/overrides.yaml").expanduser()
    if overrides_path.exists():
        with open(overrides_path) as f:
            data = yaml.safe_load(f) or {}
    else:
        data = {}
    return data, overrides_path


def _save_overrides_yaml(data: dict, overrides_path: Path):
    """Write data to ~/.tweek/overrides.yaml."""
    import yaml

    overrides_path.parent.mkdir(parents=True, exist_ok=True)
    with open(overrides_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


@main.command(
    epilog="""\b
Examples:
  tweek trust                            Trust the current project
  tweek trust /path/to/project           Trust a specific directory
  tweek trust --list                     Show all trusted paths
  tweek trust . --reason "My safe repo"  Trust with an explanation
"""
)
@click.argument("path", default=".", type=click.Path(exists=True), required=False)
@click.option("--reason", "-r", default=None, help="Why this path is trusted")
@click.option("--list", "list_trusted", is_flag=True, help="List all trusted paths")
def trust(path: str, reason: str, list_trusted: bool):
    """Trust a project directory — skip all screening for files in this path.

    Adds the directory to the whitelist in ~/.tweek/overrides.yaml.
    All tool calls operating on files within this path will be allowed
    without screening.

    This is useful for temporarily pausing Tweek in a specific project,
    or for permanently trusting a known-safe directory.

    To resume screening, use: tweek untrust
    """
    try:
        overrides, overrides_path = _load_overrides_yaml()
    except ImportError:
        console.print("[red]✗[/red] PyYAML is required. Install with: pip install pyyaml")
        return
    except Exception as e:
        console.print(f"[red]✗[/red] Could not load overrides: {e}")
        return

    whitelist = overrides.get("whitelist", [])

    # --list mode: show all trusted paths
    if list_trusted:
        trusted_entries = [
            entry for entry in whitelist
            if isinstance(entry, dict) and "path" in entry and not entry.get("tools")
        ]
        tool_scoped = [
            entry for entry in whitelist
            if isinstance(entry, dict) and "path" in entry and entry.get("tools")
        ]
        other_entries = [
            entry for entry in whitelist
            if isinstance(entry, dict) and "path" not in entry
        ]

        if not whitelist:
            console.print("[dim]No trusted paths configured.[/dim]")
            console.print("[dim]Use 'tweek trust' to trust the current project.[/dim]")
            return

        if trusted_entries:
            console.print("[bold]Trusted project directories[/bold] (all tools exempt):\n")
            for entry in trusted_entries:
                entry_reason = entry.get("reason", "")
                console.print(f"  [green]✓[/green] {entry['path']}")
                if entry_reason:
                    console.print(f"    [dim]{entry_reason}[/dim]")

        if tool_scoped:
            console.print("\n[bold]Tool-scoped whitelist entries:[/bold]\n")
            for entry in tool_scoped:
                tools = ", ".join(entry.get("tools", []))
                entry_reason = entry.get("reason", "")
                console.print(f"  [cyan]○[/cyan] {entry['path']}  [dim]({tools})[/dim]")
                if entry_reason:
                    console.print(f"    [dim]{entry_reason}[/dim]")

        if other_entries:
            console.print("\n[bold]Other whitelist entries:[/bold]\n")
            for entry in other_entries:
                if entry.get("url_prefix"):
                    console.print(f"  [cyan]○[/cyan] URL: {entry['url_prefix']}")
                elif entry.get("command_prefix"):
                    console.print(f"  [cyan]○[/cyan] Command: {entry['command_prefix']}")
                entry_reason = entry.get("reason", "")
                if entry_reason:
                    console.print(f"    [dim]{entry_reason}[/dim]")

        console.print(f"\n[dim]Config: {overrides_path}[/dim]")
        return

    # Resolve path to absolute
    resolved = Path(path).resolve()
    resolved_str = str(resolved)

    # Check if already whitelisted
    already_trusted = any(
        isinstance(entry, dict)
        and entry.get("path", "").rstrip("/") == resolved_str.rstrip("/")
        and not entry.get("tools")  # full trust, not tool-scoped
        for entry in whitelist
    )

    if already_trusted:
        console.print(f"[green]✓[/green] Already trusted: {resolved}")
        console.print("[dim]Use 'tweek untrust' to remove.[/dim]")
        return

    # Add whitelist entry (no tools restriction = all tools exempt)
    entry = {
        "path": resolved_str,
        "reason": reason or f"Trusted via tweek trust",
    }
    whitelist.append(entry)
    overrides["whitelist"] = whitelist

    try:
        _save_overrides_yaml(overrides, overrides_path)
    except Exception as e:
        console.print(f"[red]✗[/red] Could not save overrides: {e}")
        return

    console.print(f"[green]✓[/green] Trusted: {resolved}")
    console.print(f"  [dim]All screening is now skipped for files in this directory.[/dim]")
    console.print(f"  [dim]To resume screening: tweek untrust {path}[/dim]")


@main.command(
    epilog="""\b
Examples:
  tweek untrust                          Untrust the current project
  tweek untrust /path/to/project         Untrust a specific directory
"""
)
@click.argument("path", default=".", type=click.Path(exists=True), required=False)
def untrust(path: str):
    """Remove trust from a project directory — resume screening.

    Removes the directory from the whitelist in ~/.tweek/overrides.yaml.
    Tweek will resume screening tool calls for files in this path.
    """
    try:
        overrides, overrides_path = _load_overrides_yaml()
    except ImportError:
        console.print("[red]✗[/red] PyYAML is required. Install with: pip install pyyaml")
        return
    except Exception as e:
        console.print(f"[red]✗[/red] Could not load overrides: {e}")
        return

    whitelist = overrides.get("whitelist", [])
    if not whitelist:
        console.print(f"[yellow]This path is not currently trusted.[/yellow]")
        return

    # Resolve path to absolute
    resolved = Path(path).resolve()
    resolved_str = str(resolved)

    # Find and remove matching entry (full trust only, not tool-scoped)
    original_len = len(whitelist)
    whitelist = [
        entry for entry in whitelist
        if not (
            isinstance(entry, dict)
            and entry.get("path", "").rstrip("/") == resolved_str.rstrip("/")
            and not entry.get("tools")  # only remove full trust, not tool-scoped entries
        )
    ]

    if len(whitelist) == original_len:
        console.print(f"[yellow]This path is not currently trusted:[/yellow] {resolved}")
        console.print("[dim]Use 'tweek trust --list' to see all trusted paths.[/dim]")
        return

    overrides["whitelist"] = whitelist

    # Clean up empty whitelist
    if not whitelist:
        del overrides["whitelist"]

    try:
        _save_overrides_yaml(overrides, overrides_path)
    except Exception as e:
        console.print(f"[red]✗[/red] Could not save overrides: {e}")
        return

    console.print(f"[green]✓[/green] Removed trust: {resolved}")
    console.print(f"  [dim]Tweek will now screen tool calls for files in this directory.[/dim]")


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

    All 215 patterns are included free. PRO tier adds LLM review,
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

            console.print(f"[cyan]All features:[/cyan] LLM review, session analysis, rate limiting, sandbox (open source)")
            console.print(f"[dim]Pro (teams) and Enterprise (compliance) coming soon: gettweek.com[/dim]")

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
  tweek audit                            Scan all installed skills
  tweek audit ./skills/my-skill/SKILL.md Audit a specific file
  tweek audit --no-translate             Skip translation of non-English content
  tweek audit --json                     Machine-readable JSON output
"""
)
@click.argument("path", required=False, default=None, type=click.Path())
@click.option("--translate/--no-translate", default=True,
              help="Translate non-English content before pattern analysis (default: auto)")
@click.option("--llm-review/--no-llm-review", default=True,
              help="Run LLM semantic review (requires ANTHROPIC_API_KEY)")
@click.option("--json-output", "--json", "json_out", is_flag=True,
              help="Output results as JSON")
def audit(path, translate, llm_review, json_out):
    """Audit skills and tool files for security risks.

    Scans skill files (SKILL.md, tool descriptions) for prompt injection,
    credential theft, data exfiltration, and other attack patterns.

    Non-English content is detected and translated to English before
    running all 215 regex patterns. LLM semantic review provides
    additional analysis for obfuscated attacks.

    \b
    Without arguments, scans all installed skills in:
      ~/.claude/skills/
      ~/.moltbot/skills/
      ./.claude/skills/
    """
    from tweek.audit import scan_installed_skills, audit_skill, audit_content

    if path:
        # Audit a specific file
        target = Path(path)
        if not target.exists():
            console.print(f"[red]File not found: {target}[/red]")
            return

        console.print(f"[cyan]Auditing {target}...[/cyan]")
        console.print()

        result = audit_skill(target, translate=translate, llm_review=llm_review)

        if json_out:
            _print_audit_json([result])
        else:
            _print_audit_result(result)
    else:
        # Scan all installed skills
        console.print("[cyan]Scanning for installed skills...[/cyan]")
        skills = scan_installed_skills()

        if not skills:
            console.print("[dim]No installed skills found.[/dim]")
            console.print("[dim]Specify a file path to audit: tweek audit <path>[/dim]")
            return

        console.print(f"Found {len(skills)} skill(s)")
        console.print()

        results = []
        for skill_info in skills:
            if skill_info.get("error") or skill_info.get("content") is None:
                console.print(f"[yellow]Skipping {skill_info['name']}: {skill_info.get('error', 'no content')}[/yellow]")
                continue

            console.print(f"[cyan]Auditing {skill_info['name']}...[/cyan]")
            result = audit_content(
                content=skill_info["content"],
                name=skill_info["name"],
                path=skill_info["path"],
                translate=translate,
                llm_review=llm_review,
            )
            results.append(result)

        if json_out:
            _print_audit_json(results)
        else:
            for result in results:
                _print_audit_result(result)
                console.print()

            # Summary
            total = len(results)
            dangerous = sum(1 for r in results if r.risk_level == "dangerous")
            suspicious = sum(1 for r in results if r.risk_level == "suspicious")
            safe = sum(1 for r in results if r.risk_level == "safe")

            console.print("[bold]Summary[/bold]")
            console.print(f"  Skills scanned: {total}")
            if dangerous:
                console.print(f"  [red]Dangerous: {dangerous}[/red]")
            if suspicious:
                console.print(f"  [yellow]Suspicious: {suspicious}[/yellow]")
            console.print(f"  [green]Safe: {safe}[/green]")


def _print_audit_result(result):
    """Print a formatted audit result."""
    risk_icons = {"safe": "[green]SAFE[/green]", "suspicious": "[yellow]SUSPICIOUS[/yellow]", "dangerous": "[red]DANGEROUS[/red]"}

    console.print(f"  [bold]{result.skill_name}[/bold] — {risk_icons.get(result.risk_level, result.risk_level)}")
    console.print(f"  [dim]{result.skill_path}[/dim]")

    if result.error:
        console.print(f"  [red]Error: {result.error}[/red]")
        return

    if result.non_english_detected:
        lang = result.detected_language or "unknown"
        if result.translated:
            console.print(f"  [cyan]Non-English detected ({lang}) — translated for analysis[/cyan]")
        else:
            console.print(f"  [yellow]Non-English detected ({lang}) — translation skipped[/yellow]")

    if result.findings:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Severity", style="dim")
        table.add_column("Pattern")
        table.add_column("Description")
        table.add_column("Match", style="dim")

        severity_styles = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "dim"}

        for finding in result.findings:
            table.add_row(
                f"[{severity_styles.get(finding.severity, '')}]{finding.severity.upper()}[/]",
                finding.pattern_name,
                finding.description,
                finding.matched_text[:40] if finding.matched_text else "",
            )

        console.print(table)
    else:
        console.print("  [green]No patterns matched[/green]")

    if result.llm_review:
        review = result.llm_review
        console.print(f"  LLM Review: {review.get('risk_level', 'N/A')} ({review.get('confidence', 0):.0%}) — {review.get('reason', '')}")


def _print_audit_json(results):
    """Print audit results as JSON."""
    import json
    output = []
    for r in results:
        output.append({
            "skill_name": r.skill_name,
            "skill_path": str(r.skill_path),
            "risk_level": r.risk_level,
            "content_length": r.content_length,
            "non_english_detected": r.non_english_detected,
            "detected_language": r.detected_language,
            "translated": r.translated,
            "finding_count": r.finding_count,
            "critical_count": r.critical_count,
            "high_count": r.high_count,
            "findings": [
                {
                    "pattern_id": f.pattern_id,
                    "pattern_name": f.pattern_name,
                    "severity": f.severity,
                    "description": f.description,
                    "matched_text": f.matched_text,
                }
                for f in r.findings
            ],
            "llm_review": r.llm_review,
            "error": r.error,
        })
    console.print_json(json.dumps(output, indent=2))


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

    pre_hook_entry = {
        "type": "command",
        "command": "tweek hook pre-tool-use $TOOL_NAME",
    }
    post_hook_entry = {
        "type": "command",
        "command": "tweek hook post-tool-use $TOOL_NAME",
    }

    hook_entries = {
        "PreToolUse": pre_hook_entry,
        "PostToolUse": post_hook_entry,
    }

    for hook_type in ["PreToolUse", "PostToolUse"]:
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
                "hooks": [hook_entries[hook_type]],
            })

    with open(settings_path, "w") as f:
        json.dump(settings, f, indent=2)


# =============================================================================
# PROTECT COMMANDS - One-command setup for supported AI agents
# =============================================================================

@main.group(
    epilog="""\b
Examples:
  tweek protect moltbot                One-command Moltbot protection
  tweek protect moltbot --paranoid     Use paranoid security preset
  tweek protect moltbot --port 9999    Override gateway port
  tweek protect claude                 Install Claude Code hooks (alias for tweek install)
"""
)
def protect():
    """Set up Tweek protection for a specific AI agent.

    One-command setup that auto-detects, configures, and starts
    screening all tool calls for your AI assistant.
    """
    pass


@protect.command(
    "moltbot",
    epilog="""\b
Examples:
  tweek protect moltbot                Auto-detect and protect Moltbot
  tweek protect moltbot --paranoid     Maximum security preset
  tweek protect moltbot --port 9999    Custom gateway port
"""
)
@click.option("--port", default=None, type=int,
              help="Moltbot gateway port (default: auto-detect)")
@click.option("--paranoid", is_flag=True,
              help="Use paranoid security preset (default: cautious)")
@click.option("--preset", type=click.Choice(["paranoid", "cautious", "trusted"]),
              default=None, help="Security preset to apply")
def protect_moltbot(port, paranoid, preset):
    """One-command Moltbot protection setup.

    Auto-detects Moltbot, configures proxy wrapping,
    and starts screening all tool calls through Tweek's
    five-layer defense pipeline.
    """
    from tweek.integrations.moltbot import (
        detect_moltbot_installation,
        setup_moltbot_protection,
    )

    console.print(TWEEK_BANNER, style="cyan")

    # Resolve preset
    if paranoid:
        effective_preset = "paranoid"
    elif preset:
        effective_preset = preset
    else:
        effective_preset = "cautious"

    # Step 1: Detect Moltbot
    console.print("[cyan]Detecting Moltbot...[/cyan]")
    moltbot = detect_moltbot_installation()

    if not moltbot["installed"]:
        console.print()
        console.print("[red]Moltbot not detected on this system.[/red]")
        console.print()
        console.print("[dim]Install Moltbot first:[/dim]")
        console.print("  npm install -g moltbot")
        console.print()
        console.print("[dim]Or if Moltbot is installed in a non-standard location,[/dim]")
        console.print("[dim]specify the gateway port manually:[/dim]")
        console.print("  tweek protect moltbot --port 18789")
        return

    # Show detection results
    console.print()
    console.print("  [green]Moltbot detected[/green]")

    if moltbot["version"]:
        console.print(f"  Version:    {moltbot['version']}")

    console.print(f"  Gateway:    port {moltbot['gateway_port']}", end="")
    if moltbot["gateway_active"]:
        console.print(" [green](running)[/green]")
    elif moltbot["process_running"]:
        console.print(" [yellow](process running, gateway inactive)[/yellow]")
    else:
        console.print(" [dim](not running)[/dim]")

    if moltbot["config_path"]:
        console.print(f"  Config:     {moltbot['config_path']}")

    console.print()

    # Step 2: Configure protection
    console.print("[cyan]Configuring Tweek protection...[/cyan]")
    result = setup_moltbot_protection(port=port, preset=effective_preset)

    if not result.success:
        console.print(f"\n[red]Setup failed: {result.error}[/red]")
        return

    # Show configuration
    console.print(f"  Proxy:      port {result.proxy_port} -> wrapping Moltbot gateway")
    console.print(f"  Preset:     {result.preset} (215 patterns + rate limiting)")

    # Check for API key
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
    if anthropic_key:
        console.print("  LLM Review: [green]active[/green] (ANTHROPIC_API_KEY found)")
    else:
        console.print("  LLM Review: [dim]available (set ANTHROPIC_API_KEY for semantic analysis)[/dim]")

    # Show warnings
    for warning in result.warnings:
        console.print(f"\n  [yellow]Warning: {warning}[/yellow]")

    console.print()

    if not moltbot["gateway_active"]:
        console.print("[yellow]Note: Moltbot gateway is not currently running.[/yellow]")
        console.print("[dim]Protection will activate when Moltbot starts.[/dim]")
        console.print()

    console.print("[green]Protection configured.[/green] Screening all Moltbot tool calls.")
    console.print()
    console.print("[dim]Verify:     tweek doctor[/dim]")
    console.print("[dim]Logs:       tweek logs show[/dim]")
    console.print("[dim]Stop:       tweek proxy stop[/dim]")


@protect.command(
    "claude",
    epilog="""\b
Examples:
  tweek protect claude                 Install Claude Code hooks (current project)
  tweek protect claude --global        Install globally (all projects)
"""
)
@click.option("--global", "install_global", is_flag=True, default=False,
              help="Install globally to ~/.claude/ (protects all projects)")
@click.option("--preset", type=click.Choice(["paranoid", "cautious", "trusted"]),
              default=None, help="Security preset to apply")
@click.pass_context
def protect_claude(ctx, install_global, preset):
    """Install Tweek hooks for Claude Code.

    This is equivalent to 'tweek install' -- installs PreToolUse
    and PostToolUse hooks to screen all Claude Code tool calls.
    """
    # Delegate to the main install command
    # (use main.commands lookup to avoid name shadowing by mcp install)
    install_cmd = main.commands['install']
    ctx.invoke(
        install_cmd,
        install_global=install_global,
        dev_test=False,
        backup=True,
        skip_env_scan=False,
        interactive=False,
        preset=preset,
        ai_defaults=False,
        with_sandbox=False,
        force_proxy=False,
        skip_proxy_check=False,
    )


# =============================================================================
# CONFIG COMMANDS
# =============================================================================

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


@config.command("llm",
    epilog="""\b
Examples:
  tweek config llm                        Show current LLM provider status
  tweek config llm --verbose              Show detailed provider information
  tweek config llm --validate             Re-run local model validation suite
"""
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed provider info")
@click.option("--validate", is_flag=True, help="Re-run local model validation suite")
def config_llm(verbose: bool, validate: bool):
    """Show LLM review configuration and provider status.

    Displays the current LLM review provider, model, and availability.
    With --verbose, shows local server detection and fallback chain details.
    With --validate, re-runs the validation suite against local models.
    """
    from tweek.security.llm_reviewer import (
        get_llm_reviewer,
        _detect_local_server,
        _validate_local_model,
        FallbackReviewProvider,
        LOCAL_MODEL_PREFERENCES,
    )

    console.print()
    console.print("[bold]LLM Review Configuration[/bold]")
    console.print("\u2500" * 45)

    reviewer = get_llm_reviewer()

    if not reviewer.enabled:
        console.print()
        console.print("  [yellow]Status:[/yellow] Disabled (no provider available)")
        console.print()
        console.print("  [dim]To enable, set one of:[/dim]")
        console.print("    ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY")
        console.print("    Or install Ollama: [cyan]https://ollama.ai[/cyan]")
        console.print()
        return

    console.print()
    console.print(f"  [green]Status:[/green]   Enabled")
    console.print(f"  [cyan]Provider:[/cyan] {reviewer.provider_name}")
    console.print(f"  [cyan]Model:[/cyan]    {reviewer.model}")

    # Check for fallback chain
    provider = reviewer._provider_instance
    if isinstance(provider, FallbackReviewProvider):
        console.print(f"  [cyan]Chain:[/cyan]    {provider.provider_count} providers in fallback chain")
        if provider.active_provider:
            console.print(f"  [cyan]Active:[/cyan]   {provider.active_provider.name}")

    # Local server detection
    if verbose:
        console.print()
        console.print("[bold]Local LLM Servers[/bold]")
        console.print("\u2500" * 45)

        try:
            server = _detect_local_server()
            if server:
                console.print(f"  [green]Detected:[/green] {server.server_type}")
                console.print(f"  [cyan]URL:[/cyan]      {server.base_url}")
                console.print(f"  [cyan]Model:[/cyan]    {server.model}")
                console.print(f"  [cyan]Available:[/cyan] {len(server.all_models)} model{'s' if len(server.all_models) != 1 else ''}")
                if len(server.all_models) <= 10:
                    for m in server.all_models:
                        console.print(f"    - {m}")
            else:
                console.print("  [dim]No local LLM server detected[/dim]")
                console.print("  [dim]Checked: Ollama (localhost:11434), LM Studio (localhost:1234)[/dim]")
        except Exception as e:
            console.print(f"  [yellow]Detection error: {e}[/yellow]")

        console.print()
        console.print("[bold]Recommended Local Models[/bold]")
        console.print("\u2500" * 45)
        for i, model_name in enumerate(LOCAL_MODEL_PREFERENCES[:5], 1):
            console.print(f"  {i}. {model_name}")

    # Validation mode
    if validate:
        console.print()
        console.print("[bold]Model Validation[/bold]")
        console.print("\u2500" * 45)

        try:
            server = _detect_local_server()
            if not server:
                console.print("  [yellow]No local server detected. Nothing to validate.[/yellow]")
                console.print()
                return

            from tweek.security.llm_reviewer import OpenAIReviewProvider
            local_prov = OpenAIReviewProvider(
                model=server.model,
                api_key="not-needed",
                timeout=10.0,
                base_url=server.base_url,
            )

            console.print(f"  Validating [cyan]{server.model}[/cyan] on {server.server_type}...")
            passed, score = _validate_local_model(local_prov, server.model)

            if passed:
                console.print(f"  [green]PASSED[/green] ({score:.0%})")
            else:
                console.print(f"  [red]FAILED[/red] ({score:.0%}, minimum: 60%)")
                console.print("  [dim]This model may not reliably classify security threats.[/dim]")
                console.print("  [dim]Try a larger model: ollama pull qwen2.5:7b-instruct[/dim]")
        except Exception as e:
            console.print(f"  [red]Validation error: {e}[/red]")

    console.print()


@main.group()
def vault():
    """Manage credentials in secure storage (Keychain on macOS, Secret Service on Linux)."""
    pass


@vault.command("store",
    epilog="""\b
Examples:
  tweek vault store myskill API_KEY                Prompt for value securely
  tweek vault store myskill API_KEY sk-abc123      Store an API key (visible in history!)
"""
)
@click.argument("skill")
@click.argument("key")
@click.argument("value", required=False, default=None)
def vault_store(skill: str, key: str, value: Optional[str]):
    """Store a credential securely for a skill."""
    from tweek.vault import get_vault, VAULT_AVAILABLE
    from tweek.platform import get_capabilities

    if not VAULT_AVAILABLE:
        console.print("[red]\u2717[/red] Vault not available.")
        console.print("  [dim]Hint: Install keyring support: pip install keyring[/dim]")
        console.print("  [dim]On macOS, keyring uses Keychain. On Linux, install gnome-keyring or kwallet.[/dim]")
        return

    caps = get_capabilities()

    # If value not provided as argument, prompt securely (avoids shell history exposure)
    if value is None:
        value = click.prompt(f"Enter value for {key}", hide_input=True)
        if not value:
            console.print("[red]No value provided.[/red]")
            return

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
        import sys as _sys
        if not _sys.stdout.isatty():
            console.print("[yellow]WARNING: stdout is piped — credential may be logged.[/yellow]", err=True)
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
        console.print("[green]All security features are included free and open source.[/green]")
        console.print("[dim]Pro (teams) and Enterprise (compliance) coming soon: gettweek.com[/dim]")


@license.command("activate",
    epilog="""\b
Examples:
  tweek license activate YOUR_KEY               Activate a license key (Pro/Enterprise coming soon)
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
    deleted = logger.delete_events(days=days)

    if deleted > 0:
        if days:
            console.print(f"[green]Cleared {deleted} event(s) older than {days} days[/green]")
        else:
            console.print(f"[green]Cleared {deleted} event(s)[/green]")
    else:
        console.print("[dim]No events to clear[/dim]")


@logs.command("bundle",
    epilog="""\b
Examples:
  tweek logs bundle                        Create diagnostic bundle
  tweek logs bundle -o /tmp/diag.zip       Specify output path
  tweek logs bundle --days 7               Only last 7 days of events
  tweek logs bundle --dry-run              Show what would be collected
"""
)
@click.option("--output", "-o", type=click.Path(), help="Output zip file path")
@click.option("--days", "-d", type=int, help="Only include events from last N days")
@click.option("--no-redact", is_flag=True, help="Skip redaction (for internal debugging)")
@click.option("--dry-run", is_flag=True, help="Show what would be collected")
def logs_bundle(output: str, days: int, no_redact: bool, dry_run: bool):
    """Create a diagnostic bundle for support.

    Collects security logs, configs (redacted), system info, and
    doctor output into a zip file suitable for sending to Tweek support.

    Sensitive data (API keys, passwords, tokens) is automatically
    redacted before inclusion.
    """
    from tweek.logging.bundle import BundleCollector

    collector = BundleCollector(redact=not no_redact, days=days)

    if dry_run:
        report = collector.get_dry_run_report()
        console.print("[bold]Diagnostic Bundle - Dry Run[/bold]\n")
        for item in report:
            status = item.get("status", "unknown")
            name = item.get("file", "?")
            size = item.get("size")
            size_str = f" ({size:,} bytes)" if size else ""
            if "not found" in status:
                console.print(f"  [dim]  SKIP  {name} ({status})[/dim]")
            else:
                console.print(f"  [green]  ADD   {name}{size_str}[/green]")
        console.print()
        console.print("[dim]No files will be collected in dry-run mode.[/dim]")
        return

    # Determine output path
    if not output:
        ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        output = f"tweek_diagnostic_bundle_{ts}.zip"

    from pathlib import Path
    from datetime import datetime
    output_path = Path(output)

    console.print("[bold]Creating diagnostic bundle...[/bold]")

    try:
        result = collector.create_bundle(output_path)
        size = result.stat().st_size
        console.print(f"\n[green]Bundle created: {result}[/green]")
        console.print(f"[dim]Size: {size:,} bytes[/dim]")
        if not no_redact:
            console.print("[dim]Sensitive data has been redacted.[/dim]")
        console.print(f"\n[bold]Send this file to Tweek support for analysis.[/bold]")
    except Exception as e:
        console.print(f"[red]Failed to create bundle: {e}[/red]")


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

# ============================================================
# SKILLS - Isolation Chamber Management
# ============================================================

@main.group()
def skills():
    """Manage skill isolation chamber, jail, and security scanning."""
    pass


@skills.group("chamber")
def skills_chamber():
    """Manage the skill isolation chamber."""
    pass


@skills_chamber.command("list")
def chamber_list():
    """List skills currently in the isolation chamber."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    items = chamber.list_chamber()

    if not items:
        console.print("[dim]Chamber is empty.[/dim]")
        return

    table = Table(title="Isolation Chamber")
    table.add_column("Name", style="cyan")
    table.add_column("Has SKILL.md", style="green")
    table.add_column("Path", style="dim")

    for item in items:
        has_md = "Yes" if item["has_skill_md"] else "[red]No[/red]"
        table.add_row(item["name"], has_md, item["path"])

    console.print(table)


@skills_chamber.command("import")
@click.argument("source")
@click.option("--name", default=None, help="Override skill name")
@click.option("--target", type=click.Choice(["global", "project"]), default="global",
              help="Install target if scan passes")
def chamber_import(source: str, name: Optional[str], target: str):
    """Import a skill into the isolation chamber and scan it.

    SOURCE is a path to a skill directory or SKILL.md file.
    """
    from tweek.skills.isolation import SkillIsolationChamber

    source_path = Path(source).resolve()
    if not source_path.exists():
        console.print(f"[red]Source not found: {source_path}[/red]")
        return

    chamber = SkillIsolationChamber()
    report, msg = chamber.accept_and_scan(source_path, skill_name=name, target=target)

    if report.verdict == "pass":
        console.print(f"[green]PASS[/green] {msg}")
    elif report.verdict == "fail":
        console.print(f"[red]FAIL[/red] {msg}")
    elif report.verdict == "manual_review":
        console.print(f"[yellow]MANUAL REVIEW[/yellow] {msg}")
    else:
        console.print(msg)


@skills_chamber.command("scan")
@click.argument("name")
def chamber_scan(name: str):
    """Manually trigger a scan on a skill in the chamber."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    report, msg = chamber.scan_skill(name)
    console.print(msg)


@skills_chamber.command("approve")
@click.argument("name")
@click.option("--target", type=click.Choice(["global", "project"]), default="global",
              help="Install target directory")
def chamber_approve(name: str, target: str):
    """Approve a skill in the chamber and install it."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    ok, msg = chamber.approve_skill(name, target=target)
    if ok:
        console.print(f"[green]{msg}[/green]")
    else:
        console.print(f"[red]{msg}[/red]")


@skills_chamber.command("reject")
@click.argument("name")
def chamber_reject(name: str):
    """Reject a skill in the chamber and move it to jail."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    ok, msg = chamber.jail_skill(name)
    if ok:
        console.print(f"[yellow]{msg}[/yellow]")
    else:
        console.print(f"[red]{msg}[/red]")


@skills.group("jail")
def skills_jail():
    """Manage quarantined (jailed) skills."""
    pass


@skills_jail.command("list")
def jail_list():
    """List skills currently in the jail."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    items = chamber.list_jail()

    if not items:
        console.print("[dim]Jail is empty.[/dim]")
        return

    table = Table(title="Skill Jail")
    table.add_column("Name", style="cyan")
    table.add_column("Verdict", style="red")
    table.add_column("Risk", style="yellow")
    table.add_column("Critical", style="red")
    table.add_column("High", style="yellow")

    for item in items:
        table.add_row(
            item["name"],
            item.get("verdict", "?"),
            item.get("risk_level", "?"),
            str(item.get("critical", "?")),
            str(item.get("high", "?")),
        )

    console.print(table)


@skills_jail.command("rescan")
@click.argument("name")
def jail_rescan(name: str):
    """Re-scan a jailed skill (useful after pattern updates)."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    ok, msg = chamber.release_from_jail(name, force=False)
    if ok:
        console.print(f"[green]{msg}[/green]")
    else:
        console.print(f"[red]{msg}[/red]")


@skills_jail.command("release")
@click.argument("name")
@click.confirmation_option(prompt="Force-release bypasses security scanning. Are you sure?")
def jail_release(name: str):
    """Force-release a skill from jail (dangerous — bypasses scanning)."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    ok, msg = chamber.release_from_jail(name, force=True)
    if ok:
        console.print(f"[yellow]{msg}[/yellow]")
    else:
        console.print(f"[red]{msg}[/red]")


@skills_jail.command("purge")
@click.confirmation_option(prompt="Delete all jailed skills permanently?")
def jail_purge():
    """Delete all jailed skills permanently."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    count, msg = chamber.purge_jail()
    console.print(msg)


@skills.command("report")
@click.argument("name")
def skills_report(name: str):
    """View the latest scan report for a skill."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    report_data = chamber.get_report(name)

    if not report_data:
        console.print(f"[dim]No report found for '{name}'.[/dim]")
        return

    console.print(Panel(
        json.dumps(report_data, indent=2),
        title=f"Scan Report: {name}",
        border_style="cyan",
    ))


@skills.command("status")
def skills_status():
    """Show overview of chamber, jail, and installed skills."""
    from tweek.skills.isolation import SkillIsolationChamber
    from tweek.skills import CLAUDE_GLOBAL_SKILLS

    chamber = SkillIsolationChamber()
    chamber_items = chamber.list_chamber()
    jail_items = chamber.list_jail()

    # Count installed skills
    installed_count = 0
    if CLAUDE_GLOBAL_SKILLS.exists():
        installed_count = sum(
            1 for d in CLAUDE_GLOBAL_SKILLS.iterdir()
            if d.is_dir() and (d / "SKILL.md").exists()
        )

    table = Table(title="Skill Isolation Status")
    table.add_column("Location", style="cyan")
    table.add_column("Count", style="green")

    table.add_row("Installed (global)", str(installed_count))
    table.add_row("In Chamber", str(len(chamber_items)))
    table.add_row("In Jail", str(len(jail_items)))

    console.print(table)

    if chamber_items:
        console.print(f"\n[yellow]Chamber:[/yellow] {', '.join(i['name'] for i in chamber_items)}")
    if jail_items:
        console.print(f"[red]Jail:[/red] {', '.join(i['name'] for i in jail_items)}")


@skills.command("config")
@click.option("--mode", type=click.Choice(["auto", "manual"]), default=None,
              help="Set isolation mode")
def skills_config(mode: Optional[str]):
    """Show or update isolation chamber configuration."""
    from tweek.skills.config import load_isolation_config, save_isolation_config

    config = load_isolation_config()

    if mode:
        config.mode = mode
        save_isolation_config(config)
        console.print(f"[green]Isolation mode set to: {mode}[/green]")
        return

    table = Table(title="Isolation Chamber Config")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Enabled", str(config.enabled))
    table.add_row("Mode", config.mode)
    table.add_row("Scan Timeout", f"{config.scan_timeout_seconds}s")
    table.add_row("LLM Review", str(config.llm_review_enabled))
    table.add_row("Max Skill Size", f"{config.max_skill_size_bytes:,} bytes")
    table.add_row("Max File Count", str(config.max_file_count))
    table.add_row("Fail on Critical", str(config.fail_on_critical))
    table.add_row("Fail on HIGH Count", str(config.fail_on_high_count))
    table.add_row("Review on HIGH Count", str(config.review_on_high_count))

    console.print(table)


# =========================================================================
# SANDBOX COMMANDS
# =========================================================================

@main.group()
def sandbox():
    """Project-level sandbox isolation management.

    Layer 2 provides per-project security state isolation:
    - Separate security event logs per project
    - Project-scoped pattern overrides (additive-only)
    - Project-scoped skill fingerprints
    - Project-scoped configuration

    Project overrides can ADD security but NEVER weaken global settings.
    """
    pass


@sandbox.command("status")
def sandbox_status():
    """Show current project's sandbox info."""
    from tweek.sandbox.project import get_project_sandbox, _detect_project_dir
    from tweek.sandbox.layers import get_layer_description, IsolationLayer

    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[yellow]Not inside a project directory (no .git/ or .claude/ found).[/yellow]")
        return

    sandbox = get_project_sandbox(os.getcwd())
    if sandbox:
        console.print(f"[bold]Project:[/bold] {sandbox.project_dir}")
        console.print(f"[bold]Layer:[/bold] {sandbox.layer.value} ({sandbox.layer.name})")
        console.print(f"[bold]Description:[/bold] {get_layer_description(sandbox.layer)}")
        console.print(f"[bold]Tweek dir:[/bold] {sandbox.tweek_dir}")
        console.print(f"[bold]Initialized:[/bold] {sandbox.is_initialized}")

        if sandbox.is_initialized:
            db_path = sandbox.tweek_dir / "security.db"
            if db_path.exists():
                size_kb = db_path.stat().st_size / 1024
                console.print(f"[bold]Security DB:[/bold] {size_kb:.1f} KB")
    else:
        console.print(f"[bold]Project:[/bold] {project_dir}")
        console.print(f"[bold]Layer:[/bold] 0-1 (no project isolation)")
        console.print("[dim]Run 'tweek sandbox init' to enable project isolation.[/dim]")


@sandbox.command("init")
@click.option("--layer", type=int, default=2, help="Isolation layer (0=bypass, 1=skills, 2=project)")
def sandbox_init(layer: int):
    """Initialize sandbox for current project."""
    from tweek.sandbox.project import ProjectSandbox, _detect_project_dir
    from tweek.sandbox.layers import IsolationLayer, get_layer_description
    from tweek.logging.security_log import get_logger, EventType

    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[red]Not inside a project directory (no .git/ or .claude/ found).[/red]")
        raise SystemExit(1)

    isolation_layer = IsolationLayer.from_value(layer)
    sandbox = ProjectSandbox(project_dir)
    sandbox.config.layer = isolation_layer.value
    sandbox.layer = isolation_layer

    sandbox.initialize()

    console.print(f"[green]Sandbox initialized for {project_dir}[/green]")
    console.print(f"[bold]Layer:[/bold] {isolation_layer.value} ({isolation_layer.name})")
    console.print(f"[bold]Description:[/bold] {get_layer_description(isolation_layer)}")
    console.print(f"[bold]State directory:[/bold] {sandbox.tweek_dir}")

    try:
        logger = get_logger()
        from tweek.logging.security_log import SecurityEvent
        logger.log(SecurityEvent(
            event_type=EventType.SANDBOX_PROJECT_INIT,
            tool_name="cli",
            decision="allow",
            decision_reason=f"Project sandbox initialized at layer {isolation_layer.value}",
            working_directory=str(project_dir),
        ))
    except Exception:
        pass


@sandbox.command("layer")
@click.argument("level", type=int)
def sandbox_layer(level: int):
    """Set isolation layer for current project (0=bypass, 1=skills, 2=project)."""
    from tweek.sandbox.project import _detect_project_dir
    from tweek.sandbox.layers import IsolationLayer, get_layer_description
    from tweek.sandbox.registry import get_registry

    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[red]Not inside a project directory.[/red]")
        raise SystemExit(1)

    new_layer = IsolationLayer.from_value(level)
    registry = get_registry()
    registry.set_layer(project_dir, new_layer)

    console.print(f"[green]Layer set to {new_layer.value} ({new_layer.name})[/green]")
    console.print(f"[bold]Description:[/bold] {get_layer_description(new_layer)}")


@sandbox.command("list")
def sandbox_list():
    """List all registered projects and their layers."""
    from tweek.sandbox.registry import get_registry
    from tweek.sandbox.layers import IsolationLayer
    from rich.table import Table

    registry = get_registry()
    projects = registry.list_projects()

    if not projects:
        console.print("[dim]No projects registered. Run 'tweek sandbox init' in a project.[/dim]")
        return

    table = Table(title="Registered Projects")
    table.add_column("Project", style="cyan")
    table.add_column("Layer", style="green")
    table.add_column("Last Used")
    table.add_column("Auto-Init")

    for p in projects:
        layer = p["layer"]
        table.add_row(
            p["path"],
            f"{layer.value} ({layer.name})",
            p.get("last_used", "")[:19],
            "Yes" if p.get("auto_initialized") else "No",
        )

    console.print(table)


@sandbox.command("config")
def sandbox_config():
    """Show effective merged config (global + project)."""
    from tweek.sandbox.project import get_project_sandbox, _detect_project_dir

    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[red]Not inside a project directory.[/red]")
        raise SystemExit(1)

    sandbox = get_project_sandbox(os.getcwd())
    if not sandbox:
        console.print("[yellow]Project sandbox not active (layer < 2).[/yellow]")
        return

    console.print("[bold]Effective Configuration (global + project merge):[/bold]")
    console.print(f"  Layer: {sandbox.layer.value} ({sandbox.layer.name})")
    console.print(f"  Additive only: {sandbox.config.additive_only}")
    console.print(f"  Auto gitignore: {sandbox.config.auto_gitignore}")

    overrides = sandbox.get_overrides()
    if overrides:
        console.print(f"  Overrides loaded: Yes")
        if hasattr(overrides, 'global_ovr') and hasattr(overrides, 'project_ovr'):
            console.print(f"  Merge type: Additive-only (global + project)")
        else:
            console.print(f"  Merge type: Global only (no project overrides)")


@sandbox.command("logs")
@click.option("--global", "show_global", is_flag=True, help="Show global security log instead")
@click.option("--limit", default=20, help="Number of events to show")
def sandbox_logs(show_global: bool, limit: int):
    """View project-scoped or global security log."""
    from tweek.logging.security_log import SecurityLogger, get_logger

    if show_global:
        logger = get_logger()
        console.print("[bold]Global Security Log[/bold]")
    else:
        from tweek.sandbox.project import get_project_sandbox
        sandbox = get_project_sandbox(os.getcwd())
        if sandbox:
            logger = sandbox.get_logger()
            console.print(f"[bold]Project Security Log[/bold] ({sandbox.project_dir})")
        else:
            logger = get_logger()
            console.print("[bold]Global Security Log[/bold] (no project sandbox active)")

    events = logger.get_recent_events(limit=limit)
    if not events:
        console.print("[dim]No events found.[/dim]")
        return

    from rich.table import Table
    table = Table()
    table.add_column("Time", style="dim")
    table.add_column("Type")
    table.add_column("Tool")
    table.add_column("Decision", style="green")
    table.add_column("Reason")

    for e in events:
        table.add_row(
            str(e.get("timestamp", ""))[:19],
            e.get("event_type", ""),
            e.get("tool_name", ""),
            e.get("decision", ""),
            (e.get("decision_reason", "") or "")[:60],
        )

    console.print(table)


@sandbox.command("reset")
@click.option("--confirm", is_flag=True, help="Skip confirmation")
def sandbox_reset(confirm: bool):
    """Remove project .tweek/ and deregister."""
    from tweek.sandbox.project import get_project_sandbox, _detect_project_dir

    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[red]Not inside a project directory.[/red]")
        raise SystemExit(1)

    tweek_dir = project_dir / ".tweek"
    if not tweek_dir.exists():
        console.print("[yellow]No .tweek/ directory found in this project.[/yellow]")
        return

    if not confirm:
        console.print(f"[yellow]This will remove {tweek_dir} and all project-scoped security state.[/yellow]")
        if not click.confirm("Continue?"):
            return

    sandbox = get_project_sandbox(os.getcwd())
    if sandbox:
        sandbox.reset()
        console.print(f"[green]Project sandbox removed: {tweek_dir}[/green]")
    else:
        # Manual cleanup
        shutil.rmtree(tweek_dir, ignore_errors=True)
        from tweek.sandbox.registry import get_registry
        get_registry().deregister(project_dir)
        console.print(f"[green]Removed: {tweek_dir}[/green]")


@sandbox.command("verify")
def sandbox_verify():
    """Test that project isolation is working."""
    from tweek.sandbox.project import get_project_sandbox, _detect_project_dir
    from tweek.sandbox.layers import IsolationLayer

    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[red]Not inside a project directory.[/red]")
        raise SystemExit(1)

    sandbox = get_project_sandbox(os.getcwd())
    checks_passed = 0
    checks_total = 0

    # Check 1: Project detected
    checks_total += 1
    console.print(f"  Project detected: {project_dir}", end="")
    console.print(" [green]OK[/green]")
    checks_passed += 1

    # Check 2: Sandbox initialized
    checks_total += 1
    if sandbox and sandbox.is_initialized:
        console.print(f"  Sandbox initialized: {sandbox.tweek_dir}", end="")
        console.print(" [green]OK[/green]")
        checks_passed += 1
    else:
        console.print("  Sandbox initialized: [red]NO[/red]")
        console.print("  [dim]Run 'tweek sandbox init' to enable.[/dim]")

    # Check 3: Layer
    checks_total += 1
    if sandbox and sandbox.layer >= IsolationLayer.PROJECT:
        console.print(f"  Isolation layer: {sandbox.layer.value} ({sandbox.layer.name})", end="")
        console.print(" [green]OK[/green]")
        checks_passed += 1
    else:
        layer_val = sandbox.layer.value if sandbox else 0
        console.print(f"  Isolation layer: {layer_val} [yellow]BELOW PROJECT[/yellow]")

    # Check 4: Security DB exists
    checks_total += 1
    if sandbox and (sandbox.tweek_dir / "security.db").exists():
        console.print("  Project security.db: exists", end="")
        console.print(" [green]OK[/green]")
        checks_passed += 1
    elif sandbox:
        console.print("  Project security.db: [yellow]NOT FOUND[/yellow]")
    else:
        console.print("  Project security.db: [dim]N/A (sandbox inactive)[/dim]")

    # Check 5: .gitignore
    checks_total += 1
    gitignore = project_dir / ".gitignore"
    if gitignore.exists() and ".tweek" in gitignore.read_text():
        console.print("  .gitignore includes .tweek/:", end="")
        console.print(" [green]OK[/green]")
        checks_passed += 1
    else:
        console.print("  .gitignore includes .tweek/: [yellow]NO[/yellow]")

    console.print(f"\n  [bold]{checks_passed}/{checks_total} checks passed[/bold]")


# Docker bridge commands
@sandbox.group("docker")
def sandbox_docker():
    """Docker integration for container-level isolation."""
    pass


@sandbox_docker.command("init")
def docker_init():
    """Generate Docker Sandbox config for this project."""
    from tweek.sandbox.docker_bridge import DockerBridge

    bridge = DockerBridge()
    if not bridge.is_docker_available():
        console.print("[red]Docker is not installed or not running.[/red]")
        console.print("[dim]Install Docker Desktop from https://www.docker.com/products/docker-desktop/[/dim]")
        raise SystemExit(1)

    from tweek.sandbox.project import _detect_project_dir
    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[red]Not inside a project directory.[/red]")
        raise SystemExit(1)

    compose_path = bridge.init(project_dir)
    console.print(f"[green]Docker Sandbox config generated: {compose_path}[/green]")
    console.print("[dim]Run 'tweek sandbox docker run' to start the container.[/dim]")


@sandbox_docker.command("run")
def docker_run():
    """Launch container-isolated session (requires Docker)."""
    from tweek.sandbox.docker_bridge import DockerBridge
    from tweek.sandbox.project import _detect_project_dir

    bridge = DockerBridge()
    if not bridge.is_docker_available():
        console.print("[red]Docker is not available.[/red]")
        raise SystemExit(1)

    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[red]Not inside a project directory.[/red]")
        raise SystemExit(1)

    console.print("[bold]Launching Docker sandbox...[/bold]")
    bridge.run(project_dir)


@sandbox_docker.command("status")
def docker_status():
    """Check Docker integration status."""
    from tweek.sandbox.docker_bridge import DockerBridge

    bridge = DockerBridge()
    console.print(f"[bold]Docker available:[/bold] {bridge.is_docker_available()}")

    from tweek.sandbox.project import _detect_project_dir
    project_dir = _detect_project_dir(os.getcwd())
    if project_dir:
        compose = project_dir / ".tweek" / "docker-compose.yaml"
        console.print(f"[bold]Docker config:[/bold] {'exists' if compose.exists() else 'not generated'}")
    else:
        console.print("[dim]Not in a project directory.[/dim]")


# =========================================================================
# BREAK-GLASS OVERRIDE COMMANDS
# =========================================================================

@main.group("override")
def override_group():
    """Break-glass override for hard-blocked patterns.

    When graduated enforcement blocks a pattern with "deny" (critical +
    deterministic), use these commands to create a temporary override.

    Overrides downgrade "deny" to "ask" — you still see the prompt and
    must explicitly approve. Every use is logged for audit.
    """
    pass


@override_group.command("create")
@click.option("--pattern", required=True, help="Pattern name to override (e.g., ssh_key_read)")
@click.option("--once", "mode", flag_value="once", default=True, help="Single-use override (consumed on first use)")
@click.option("--duration", "duration_minutes", type=int, default=None, help="Duration in minutes (overrides --once)")
@click.option("--reason", default="", help="Reason for the override (logged for audit)")
def override_create(pattern: str, mode: str, duration_minutes: Optional[int], reason: str):
    """Create a break-glass override for a hard-blocked pattern."""
    from tweek.hooks.break_glass import create_override

    if duration_minutes:
        mode = "duration"

    override = create_override(pattern, mode=mode, duration_minutes=duration_minutes, reason=reason)

    # Log the creation
    try:
        from tweek.logging.security_log import get_logger, EventType, SecurityEvent
        logger = get_logger()
        logger.log(SecurityEvent(
            event_type=EventType.BREAK_GLASS,
            tool_name="tweek_cli",
            decision="override_created",
            decision_reason=f"Break-glass override created for '{pattern}'",
            metadata={
                "pattern": pattern,
                "mode": mode,
                "duration_minutes": duration_minutes,
                "reason": reason,
            },
        ))
    except Exception:
        pass

    console.print(f"[bold green]Break-glass override created[/bold green]")
    console.print(f"  Pattern: [bold]{pattern}[/bold]")
    console.print(f"  Mode: {mode}")
    if duration_minutes:
        console.print(f"  Expires: {override.get('expires_at', 'N/A')}")
    if reason:
        console.print(f"  Reason: {reason}")
    console.print()
    console.print("[dim]Next time this pattern triggers, you'll see an 'ask' prompt instead of a hard block.[/dim]")


@override_group.command("list")
def override_list():
    """List all break-glass overrides (active and historical)."""
    from tweek.hooks.break_glass import list_overrides, list_active_overrides

    all_overrides = list_overrides()
    active = list_active_overrides()
    active_patterns = {o["pattern"] for o in active}

    if not all_overrides:
        console.print("[dim]No break-glass overrides found.[/dim]")
        return

    table = Table(title="Break-Glass Overrides")
    table.add_column("Pattern", style="bold")
    table.add_column("Mode")
    table.add_column("Status")
    table.add_column("Reason")
    table.add_column("Created")

    for o in all_overrides:
        if o["pattern"] in active_patterns and not o.get("used"):
            status = "[green]active[/green]"
        elif o.get("used"):
            status = "[dim]consumed[/dim]"
        else:
            status = "[dim]expired[/dim]"

        table.add_row(
            o["pattern"],
            o["mode"],
            status,
            o.get("reason", ""),
            o.get("created_at", "")[:19],
        )

    console.print(table)
    console.print(f"\n[bold]{len(active)}[/bold] active override(s)")


@override_group.command("clear")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def override_clear(confirm: bool):
    """Remove all break-glass overrides."""
    from tweek.hooks.break_glass import clear_overrides

    if not confirm:
        if not sys.stdin.isatty():
            console.print("[red]Use --confirm to clear overrides in non-interactive mode.[/red]")
            return
        if not click.confirm("Clear all break-glass overrides?"):
            return

    count = clear_overrides()
    console.print(f"[bold]Cleared {count} override(s).[/bold]")


# =========================================================================
# FEEDBACK COMMANDS
# =========================================================================

@main.group("feedback")
def feedback_group():
    """False-positive feedback and pattern performance tracking.

    Report false positives, view per-pattern FP rates, and manage
    automatic severity demotions for noisy patterns.
    """
    pass


@feedback_group.command("fp")
@click.argument("pattern_name")
@click.option("--context", default="", help="Description of the false positive context")
def feedback_fp(pattern_name: str, context: str):
    """Report a false positive for a pattern."""
    from tweek.hooks.feedback import report_false_positive

    result = report_false_positive(pattern_name, context=context)

    # Log the report
    try:
        from tweek.logging.security_log import get_logger, EventType, SecurityEvent
        logger = get_logger()
        logger.log(SecurityEvent(
            event_type=EventType.FALSE_POSITIVE_REPORT,
            tool_name="tweek_cli",
            pattern_name=pattern_name,
            decision="fp_reported",
            decision_reason=f"False positive reported for '{pattern_name}'",
            metadata={
                "context": context,
                "fp_rate": result.get("fp_rate"),
                "total_triggers": result.get("total_triggers"),
                "false_positives": result.get("false_positives"),
            },
        ))
    except Exception:
        pass

    console.print(f"[bold green]False positive recorded[/bold green] for [bold]{pattern_name}[/bold]")
    console.print(f"  FP rate: {result.get('fp_rate', 0):.1%} ({result.get('false_positives', 0)}/{result.get('total_triggers', 0)})")

    if result.get("auto_demoted"):
        console.print(f"  [yellow]Auto-demoted:[/yellow] {result.get('original_severity')} -> {result.get('current_severity')}")


@feedback_group.command("stats")
@click.option("--above-threshold", is_flag=True, help="Show only patterns exceeding 5% FP rate")
def feedback_stats(above_threshold: bool):
    """Show false-positive rates per pattern."""
    from tweek.hooks.feedback import get_stats

    stats = get_stats()
    if not stats:
        console.print("[dim]No feedback data recorded yet.[/dim]")
        return

    table = Table(title="Pattern FP Statistics")
    table.add_column("Pattern", style="bold")
    table.add_column("Triggers", justify="right")
    table.add_column("FPs", justify="right")
    table.add_column("FP Rate", justify="right")
    table.add_column("Demoted?")

    for name, data in sorted(stats.items(), key=lambda x: x[1].get("fp_rate", 0), reverse=True):
        fp_rate = data.get("fp_rate", 0)
        if above_threshold and fp_rate < 0.05:
            continue

        rate_style = "red" if fp_rate >= 0.05 else "green"
        demoted = "[yellow]yes[/yellow]" if data.get("auto_demoted") else "no"

        table.add_row(
            name,
            str(data.get("total_triggers", 0)),
            str(data.get("false_positives", 0)),
            f"[{rate_style}]{fp_rate:.1%}[/{rate_style}]",
            demoted,
        )

    console.print(table)


@feedback_group.command("reset")
@click.argument("pattern_name")
def feedback_reset(pattern_name: str):
    """Reset FP tracking and undo auto-demotion for a pattern."""
    from tweek.hooks.feedback import reset_pattern

    result = reset_pattern(pattern_name)
    if result:
        console.print(f"[bold]Reset feedback data for '{pattern_name}'[/bold]")
        if result.get("was_demoted"):
            console.print(f"  Restored severity: {result.get('original_severity')}")
    else:
        console.print(f"[dim]No feedback data found for '{pattern_name}'.[/dim]")


# =========================================================================
# Memory commands
# =========================================================================


@main.group("memory")
def memory_group():
    """Agentic memory management.

    View and manage Tweek's learned security decisions, source trust scores,
    workflow baselines, and whitelist suggestions.
    """
    pass


@memory_group.command("status")
def memory_status():
    """Show overall memory statistics."""
    from tweek.memory.store import get_memory_store

    store = get_memory_store()
    stats = store.get_stats()

    table = Table(title="Tweek Memory Status")
    table.add_column("Table", style="bold")
    table.add_column("Entries", justify="right")

    for table_name in ("pattern_decisions", "source_trust", "workflow_baselines",
                        "learned_whitelists", "memory_audit"):
        table.add_row(table_name, str(stats.get(table_name, 0)))

    console.print(table)
    console.print()

    last_decay = stats.get("last_decay")
    if last_decay:
        console.print(f"  Last decay: {last_decay}")
    else:
        console.print("  Last decay: [dim]never[/dim]")

    db_size = stats.get("db_size_bytes", 0)
    if db_size > 1024 * 1024:
        console.print(f"  DB size: {db_size / (1024*1024):.1f} MB")
    elif db_size > 1024:
        console.print(f"  DB size: {db_size / 1024:.1f} KB")
    else:
        console.print(f"  DB size: {db_size} bytes")


@memory_group.command("patterns")
@click.option("--min-decisions", default=0, type=int, help="Minimum decisions to show")
@click.option("--sort", "sort_by", default="count",
              type=click.Choice(["count", "approval", "name"]),
              help="Sort order")
def memory_patterns(min_decisions: int, sort_by: str):
    """Show per-pattern confidence adjustments."""
    from tweek.memory.store import get_memory_store

    store = get_memory_store()
    patterns = store.get_pattern_stats(min_decisions=min_decisions, sort_by=sort_by)

    if not patterns:
        console.print("[dim]No pattern decision data recorded yet.[/dim]")
        return

    table = Table(title="Pattern Decision History")
    table.add_column("Pattern", style="bold")
    table.add_column("Path Prefix", max_width=30)
    table.add_column("Decisions", justify="right")
    table.add_column("Approvals", justify="right")
    table.add_column("Denials", justify="right")
    table.add_column("Approval %", justify="right")
    table.add_column("Last", max_width=19)

    for p in patterns:
        ratio = p.get("approval_ratio", 0)
        ratio_style = "green" if ratio >= 0.9 else ("yellow" if ratio >= 0.5 else "red")
        table.add_row(
            p.get("pattern_name", "?"),
            p.get("path_prefix") or "[dim]-[/dim]",
            str(p.get("total_decisions", 0)),
            f"{p.get('weighted_approvals', 0):.1f}",
            f"{p.get('weighted_denials', 0):.1f}",
            f"[{ratio_style}]{ratio:.0%}[/{ratio_style}]",
            (p.get("last_decision") or "")[:19],
        )

    console.print(table)


@memory_group.command("sources")
@click.option("--suspicious", is_flag=True, help="Show only sources with trust < 0.5")
def memory_sources(suspicious: bool):
    """Show source trustworthiness scores."""
    from tweek.memory.store import get_memory_store

    store = get_memory_store()
    sources = store.get_all_sources(suspicious_only=suspicious)

    if not sources:
        console.print("[dim]No source trust data recorded yet.[/dim]")
        return

    table = Table(title="Source Trust Scores")
    table.add_column("Type", style="bold")
    table.add_column("Source", max_width=60)
    table.add_column("Scans", justify="right")
    table.add_column("Injections", justify="right")
    table.add_column("Trust", justify="right")
    table.add_column("Last Injection", max_width=19)

    for s in sources:
        trust_style = "green" if s.trust_score >= 0.8 else ("yellow" if s.trust_score >= 0.5 else "red")
        table.add_row(
            s.source_type,
            s.source_key[:60],
            str(s.total_scans),
            str(s.injection_detections),
            f"[{trust_style}]{s.trust_score:.2f}[/{trust_style}]",
            (s.last_injection or "")[:19],
        )

    console.print(table)


@memory_group.command("suggestions")
@click.option("--all", "show_all", is_flag=True, help="Show all suggestions (including reviewed)")
def memory_suggestions(show_all: bool):
    """Show learned whitelist suggestions pending review."""
    from tweek.memory.store import get_memory_store

    store = get_memory_store()
    suggestions = store.get_whitelist_suggestions(pending_only=not show_all)

    if not suggestions:
        console.print("[dim]No whitelist suggestions available.[/dim]")
        return

    table = Table(title="Learned Whitelist Suggestions")
    table.add_column("ID", justify="right")
    table.add_column("Pattern", style="bold")
    table.add_column("Tool")
    table.add_column("Path Prefix", max_width=30)
    table.add_column("Approvals", justify="right")
    table.add_column("Denials", justify="right")
    table.add_column("Confidence", justify="right")
    table.add_column("Status")

    for s in suggestions:
        status = {0: "[yellow]pending[/yellow]", 1: "[green]accepted[/green]", -1: "[red]rejected[/red]"}
        table.add_row(
            str(s.id),
            s.pattern_name,
            s.tool_name or "[dim]-[/dim]",
            s.path_prefix or "[dim]-[/dim]",
            str(s.approval_count),
            str(s.denial_count),
            f"{s.confidence:.0%}",
            status.get(s.human_reviewed, "?"),
        )

    console.print(table)


@memory_group.command("accept")
@click.argument("suggestion_id", type=int)
def memory_accept(suggestion_id: int):
    """Accept a whitelist suggestion."""
    from tweek.memory.store import get_memory_store

    store = get_memory_store()
    if store.review_whitelist_suggestion(suggestion_id, accepted=True):
        console.print(f"[bold green]Accepted[/bold green] suggestion #{suggestion_id}")
        console.print("  [dim]Note: To apply to overrides.yaml, manually add the whitelist rule.[/dim]")
    else:
        console.print(f"[red]Suggestion #{suggestion_id} not found.[/red]")


@memory_group.command("reject")
@click.argument("suggestion_id", type=int)
def memory_reject(suggestion_id: int):
    """Reject a whitelist suggestion."""
    from tweek.memory.store import get_memory_store

    store = get_memory_store()
    if store.review_whitelist_suggestion(suggestion_id, accepted=False):
        console.print(f"[bold]Rejected[/bold] suggestion #{suggestion_id}")
    else:
        console.print(f"[red]Suggestion #{suggestion_id} not found.[/red]")


@memory_group.command("baseline")
@click.option("--project-hash", default=None, help="Override project hash (default: auto-detect from cwd)")
def memory_baseline(project_hash: Optional[str]):
    """Show workflow baseline for current project."""
    from tweek.memory.store import get_memory_store, hash_project

    if not project_hash:
        project_hash = hash_project(str(Path.cwd()))

    store = get_memory_store()
    baselines = store.get_workflow_baseline(project_hash)

    if not baselines:
        console.print("[dim]No workflow baseline data for this project.[/dim]")
        return

    table = Table(title=f"Workflow Baseline (project: {project_hash[:8]}...)")
    table.add_column("Tool", style="bold")
    table.add_column("Hour", justify="right")
    table.add_column("Invocations", justify="right")
    table.add_column("Denied", justify="right")
    table.add_column("Denial %", justify="right")

    for b in baselines:
        total = b.invocation_count or 1
        denial_pct = b.denied_count / total
        pct_style = "green" if denial_pct < 0.1 else ("yellow" if denial_pct < 0.3 else "red")
        table.add_row(
            b.tool_name,
            str(b.hour_of_day) if b.hour_of_day is not None else "[dim]-[/dim]",
            str(b.invocation_count),
            str(b.denied_count),
            f"[{pct_style}]{denial_pct:.0%}[/{pct_style}]",
        )

    console.print(table)


@memory_group.command("audit")
@click.option("--limit", default=50, type=int, help="Number of entries to show")
def memory_audit(limit: int):
    """Show memory operation audit log."""
    from tweek.memory.store import get_memory_store

    store = get_memory_store()
    entries = store.get_audit_log(limit=limit)

    if not entries:
        console.print("[dim]No audit entries.[/dim]")
        return

    table = Table(title=f"Memory Audit Log (last {limit})")
    table.add_column("Timestamp", max_width=19)
    table.add_column("Op", style="bold")
    table.add_column("Table")
    table.add_column("Key", max_width=30)
    table.add_column("Result", max_width=50)

    for e in entries:
        table.add_row(
            (e.get("timestamp") or "")[:19],
            e.get("operation", "?"),
            e.get("table_name", "?"),
            (e.get("key_info") or "")[:30],
            (e.get("result") or "")[:50],
        )

    console.print(table)


@memory_group.command("clear")
@click.option("--table", "table_name", default=None,
              type=click.Choice(["patterns", "sources", "baselines", "whitelists", "audit", "all"]),
              help="Table to clear (default: all)")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def memory_clear(table_name: Optional[str], confirm: bool):
    """Clear memory data."""
    from tweek.memory.store import get_memory_store

    table_map = {
        "patterns": "pattern_decisions",
        "sources": "source_trust",
        "baselines": "workflow_baselines",
        "whitelists": "learned_whitelists",
        "audit": "memory_audit",
    }

    if not confirm:
        target = table_name or "ALL"
        if not click.confirm(f"Clear {target} memory data? This cannot be undone"):
            console.print("[dim]Cancelled.[/dim]")
            return

    store = get_memory_store()

    if table_name and table_name != "all":
        actual_name = table_map.get(table_name, table_name)
        count = store.clear_table(actual_name)
        console.print(f"Cleared {count} entries from {actual_name}")
    else:
        results = store.clear_all()
        for tbl, count in results.items():
            console.print(f"  {tbl}: {count} entries cleared")
        console.print("[bold]All memory data cleared.[/bold]")


@memory_group.command("export")
@click.option("--output", "-o", default=None, help="Output file path (default: stdout)")
def memory_export(output: Optional[str]):
    """Export all memory data to JSON."""
    from tweek.memory.store import get_memory_store

    store = get_memory_store()
    data = store.export_all()

    json_str = json.dumps(data, indent=2, default=str)

    if output:
        Path(output).write_text(json_str)
        console.print(f"Exported memory to {output}")
    else:
        click.echo(json_str)


@memory_group.command("decay")
def memory_decay():
    """Manually trigger time decay on all memory entries."""
    from tweek.memory.store import get_memory_store

    store = get_memory_store()
    results = store.apply_decay()

    console.print("[bold]Decay applied:[/bold]")
    for table, count in results.items():
        console.print(f"  {table}: {count} entries updated")


# Register model management command group
try:
    from tweek.cli_model import model as model_group
    main.add_command(model_group)
except ImportError:
    pass


if __name__ == "__main__":
    main()
