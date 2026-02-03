#!/usr/bin/env python3
"""
Tweek CLI Install Command

The `tweek install` command provides the full Tweek onboarding experience:
    1. Install hooks (global or project scope)
    2. Choose a security preset
    3. Verify credential vault
    4. Optional MCP proxy setup

This is the Tweek *package* lifecycle command. For per-tool protection,
use `tweek protect [tool]` instead.
"""
from __future__ import annotations

import click
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import List, Tuple

from rich.console import Console
from rich.table import Table

from tweek import __version__
from tweek.cli_helpers import (
    console,
    TWEEK_BANNER,
    print_success,
    print_warning,
    _has_tweek_hooks,
    _detect_all_tools,
)


# ---------------------------------------------------------------------------
# Installed scope tracking
# ---------------------------------------------------------------------------

_INSTALLED_SCOPES_FILE = Path("~/.tweek/installed_scopes.json").expanduser()


def _record_installed_scope(target: Path) -> None:
    """Record that hooks were installed at *target* (.claude/ directory).

    Stored in ~/.tweek/installed_scopes.json so ``tweek uninstall --all``
    can find and clean project-level hooks regardless of the user's cwd.
    """
    target_str = str(target.resolve())

    existing: list = []
    if _INSTALLED_SCOPES_FILE.exists():
        try:
            existing = json.loads(_INSTALLED_SCOPES_FILE.read_text()) or []
        except (json.JSONDecodeError, IOError):
            existing = []

    if target_str not in existing:
        existing.append(target_str)

    _INSTALLED_SCOPES_FILE.parent.mkdir(parents=True, exist_ok=True)
    _INSTALLED_SCOPES_FILE.write_text(json.dumps(existing, indent=2))


def _get_installed_scopes() -> list:
    """Return all recorded .claude/ directories where hooks were installed."""
    if not _INSTALLED_SCOPES_FILE.exists():
        return []
    try:
        return json.loads(_INSTALLED_SCOPES_FILE.read_text()) or []
    except (json.JSONDecodeError, IOError):
        return []


# ---------------------------------------------------------------------------
# Utility functions for .env scanning
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Install helpers
# ---------------------------------------------------------------------------


def _download_local_model(quick: bool) -> bool:
    """Download the local classifier model if dependencies are available.

    Called during ``tweek install`` to ensure the on-device prompt-injection
    classifier is ready to use immediately after installation.

    Args:
        quick: If True, skip informational output and just download.

    Returns:
        True if the model is installed (was already present or downloaded
        successfully), False otherwise.
    """
    try:
        from tweek.security.local_model import LOCAL_MODEL_AVAILABLE
        from tweek.security.model_registry import (
            ModelDownloadError,
            download_model,
            get_default_model_name,
            get_model_definition,
            is_model_installed,
        )
    except ImportError:
        if not quick:
            console.print("\n[white]Local model module not available — skipping model download[/white]")
        return False

    if not LOCAL_MODEL_AVAILABLE:
        if not quick:
            console.print("\n[white]Local model dependencies not installed (optional)[/white]")
            console.print("  [white]Install with: pip install tweek[local-models][/white]")
        return False

    default_name = get_default_model_name()

    if is_model_installed(default_name):
        console.print(f"\n[green]\u2713[/green] Local classifier model already installed ({default_name})")
        return True

    definition = get_model_definition(default_name)
    if definition is None:
        return False

    if not quick:
        console.print(f"\n[bold]Downloading local classifier model[/bold]")
        console.print(f"  Model:   {definition.display_name}")
        console.print(f"  Size:    ~{definition.size_mb:.0f} MB")
        console.print(f"  License: {definition.license}")
        console.print(f"  [white]This enables on-device prompt injection detection (no API key needed)[/white]")
        console.print()

    from rich.progress import Progress, BarColumn, DownloadColumn, TransferSpeedColumn

    progress = Progress(
        "[progress.description]{task.description}",
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        console=console,
    )

    tasks = {}

    def progress_callback(filename: str, downloaded: int, total: int):
        if filename not in tasks:
            tasks[filename] = progress.add_task(
                f"  {filename}", total=total or None
            )
        progress.update(tasks[filename], completed=downloaded)

    try:
        with progress:
            download_model(default_name, progress_callback=progress_callback)

        console.print(f"[green]\u2713[/green] Local classifier model downloaded ({default_name})")
        return True

    except ModelDownloadError as e:
        console.print(f"\n[yellow]\u26a0[/yellow] Could not download local model: {e}")
        console.print("  [white]You can download it later with: tweek model download[/white]")
        return False
    except Exception as e:
        console.print(f"\n[yellow]\u26a0[/yellow] Model download failed: {e}")
        console.print("  [white]You can download it later with: tweek model download[/white]")
        return False


def _install_claude_code_hooks(install_global: bool, dev_test: bool, backup: bool, skip_env_scan: bool, interactive: bool, preset: str, ai_defaults: bool, with_sandbox: bool, force_proxy: bool, skip_proxy_check: bool, quick: bool):
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
            preset = "balanced"

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
        console.print(f"[green]\u2713[/green] Claude Code detected ({claude_path})")
    else:
        console.print()
        console.print("[yellow]\u26a0 Claude Code not detected on this system[/yellow]")
        console.print("  [white]Tweek hooks require Claude Code to function.[/white]")
        console.print("  [white]https://docs.anthropic.com/en/docs/claude-code[/white]")
        console.print()
        if quick or not click.confirm("Continue installing hooks anyway?", default=False):
            if not quick:
                console.print()
                console.print("[white]Run 'tweek install' later after installing Claude Code.[/white]")
            return
        console.print()

    # ─────────────────────────────────────────────────────────────
    # Step 2: Scope selection (always shown unless --global or --quick)
    # ─────────────────────────────────────────────────────────────
    if not install_global and not dev_test and not quick:
        console.print()
        console.print("[bold]Installation Scope[/bold]")
        console.print()
        console.print("  [cyan]1.[/cyan] All projects globally (~/.claude/) [green](recommended)[/green]")
        console.print("     [white]Protects every project on this machine[/white]")
        console.print("  [cyan]2.[/cyan] This directory only (./.claude/)")
        console.print("     [white]Protects only the current directory[/white]")
        console.print()
        scope_choice = click.prompt("Select", type=click.IntRange(1, 2), default=1)
        if scope_choice == 1:
            install_global = True
        console.print()

    # Determine target directory based on scope
    if dev_test:
        console.print("[yellow]Installing in DEV TEST mode (isolated environment)[/yellow]")
        target = Path("~/AI/tweek/test-environment/.claude").expanduser()
        install_summary["scope"] = "dev-test"
    elif install_global:
        target = Path("~/.claude").expanduser()
        console.print(f"[cyan]Scope: global[/cyan] \u2014 Hooks will protect all projects")
        install_summary["scope"] = "global"
    else:  # project (default)
        target = Path.cwd() / ".claude"
        console.print(f"[cyan]Scope: project[/cyan] \u2014 Hooks will protect this project only")
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
                        console.print("[white]Note: Tweek is also installed in this project.[/white]")
                        console.print("[white]Project-level settings take precedence over global.[/white]")
                        console.print()
            else:
                # Installing per-project — check if global hooks exist
                global_settings = Path("~/.claude/settings.json").expanduser()
                if global_settings.exists():
                    with open(global_settings) as f:
                        global_config = json.load(f)
                    if _has_tweek_hooks(global_config):
                        console.print("[white]Note: Tweek is also installed globally.[/white]")
                        console.print("[white]Project-level settings will take precedence in this directory.[/white]")
                        console.print()
        except (json.JSONDecodeError, IOError):
            pass

    # ─────────────────────────────────────────────────────────────
    # Step 4: Detect OpenClaw and offer protection options
    # ─────────────────────────────────────────────────────────────
    proxy_override_enabled = force_proxy
    if not skip_proxy_check:
        try:
            from tweek.proxy import (
                detect_proxy_conflicts,
                get_openclaw_status,
                OPENCLAW_DEFAULT_PORT,
                TWEEK_DEFAULT_PORT,
            )

            openclaw_status = get_openclaw_status()

            if openclaw_status["installed"]:
                console.print()
                console.print("[green]\u2713[/green] OpenClaw detected on this system")

                if openclaw_status["gateway_active"]:
                    console.print(f"  Gateway running on port {openclaw_status['port']}")
                elif openclaw_status["running"]:
                    console.print(f"  [white]Process running (gateway may start on port {openclaw_status['port']})[/white]")
                else:
                    console.print(f"  [white]Installed but not currently running[/white]")

                if openclaw_status["config_path"]:
                    console.print(f"  [white]Config: {openclaw_status['config_path']}[/white]")

                console.print()

                if force_proxy:
                    proxy_override_enabled = True
                    console.print("[green]\u2713[/green] Force proxy enabled - Tweek will override openclaw")
                    console.print()
                else:
                    console.print("[cyan]Tweek can protect OpenClaw tool calls. Choose a method:[/cyan]")
                    console.print()
                    console.print("  [cyan]1.[/cyan] Protect via [bold]tweek-security[/bold] ClawHub skill")
                    console.print("     [white]Screens tool calls through Tweek as a ClawHub skill[/white]")
                    console.print("  [cyan]2.[/cyan] Protect via [bold]tweek protect openclaw[/bold]")
                    console.print("     [white]Wraps the OpenClaw gateway with Tweek's proxy[/white]")
                    console.print("  [cyan]3.[/cyan] Skip for now")
                    console.print("     [white]You can set up OpenClaw protection later[/white]")
                    console.print()

                    choice = click.prompt(
                        "Select",
                        type=click.IntRange(1, 3),
                        default=3,
                    )

                    if choice == 1:
                        console.print()
                        console.print("[green]\u2713[/green] To add OpenClaw protection via the skill, run:")
                        console.print("  [bold]openclaw protect tweek-security[/bold]")
                        console.print()
                    elif choice == 2:
                        proxy_override_enabled = True
                        console.print()
                        console.print("[green]\u2713[/green] OpenClaw proxy protection will be configured")
                        console.print(f"  [white]Run 'tweek protect openclaw' after installation to complete setup[/white]")
                        console.print()
                    else:
                        console.print()
                        console.print("[white]Skipped. Run 'tweek protect openclaw' or add the[/white]")
                        console.print("[white]tweek-security skill later to protect OpenClaw.[/white]")
                        console.print()

            # Check for other proxy conflicts
            conflicts = detect_proxy_conflicts()
            non_openclaw_conflicts = [c for c in conflicts if c.tool_name != "openclaw"]

            if non_openclaw_conflicts:
                console.print("[yellow]\u26a0 Other proxy conflicts detected:[/yellow]")
                for conflict in non_openclaw_conflicts:
                    console.print(f"  \u2022 {conflict.description}")
                console.print()

        except ImportError:
            # Proxy module not fully available, skip detection
            pass
        except Exception as e:
            console.print(f"[white]Warning: Could not check for proxy conflicts: {e}[/white]")

    # ─────────────────────────────────────────────────────────────
    # Step 5: Install hooks into settings.json
    # ─────────────────────────────────────────────────────────────
    hook_script = Path(__file__).resolve().parent / "hooks" / "pre_tool_use.py"
    post_hook_script = Path(__file__).resolve().parent / "hooks" / "post_tool_use.py"

    # Backup existing hooks if requested
    if backup and target.exists():
        settings_file = target / "settings.json"
        if settings_file.exists():
            backup_path = settings_file.with_suffix(".json.tweek-backup")
            shutil.copy(settings_file, backup_path)
            console.print(f"[white]Backed up existing settings to {backup_path}[/white]")

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

    console.print(f"\n[green]\u2713[/green] PreToolUse hooks installed to: {target}")
    console.print(f"[green]\u2713[/green] PostToolUse content screening installed to: {target}")

    # Track this installation scope so `tweek uninstall --all` can find it
    _record_installed_scope(target)

    # Create Tweek data directory
    tweek_dir = Path("~/.tweek").expanduser()
    tweek_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[green]\u2713[/green] Tweek data directory: {tweek_dir}")

    # Create .tweek.yaml in the install directory (per-directory hook control)
    _create_tweek_yaml(install_global)

    # Deploy self-documenting config templates (skip .tweek.yaml — handled above)
    try:
        from tweek.config.templates import deploy_all_templates
        for name, path, created in deploy_all_templates(global_scope=install_global):
            if created:
                console.print(f"[green]\u2713[/green] {name}: {path}")
    except Exception:
        pass  # Template deployment is best-effort

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
        console.print(f"[green]\u2713[/green] Tweek skill installed to: {skill_target}")
        console.print(f"  [white]Claude now understands Tweek warnings and commands[/white]")

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

                console.print(f"[green]\u2713[/green] Skill directory whitelisted in overrides")

        except ImportError:
            console.print(f"[white]Note: PyYAML not available \u2014 skill whitelist not added to overrides[/white]")
        except Exception as e:
            console.print(f"[white]Warning: Could not update overrides whitelist: {e}[/white]")
    else:
        console.print(f"[white]Tweek skill source not found \u2014 skill not installed[/white]")
        console.print(f"  [white]Skill can be installed manually from the tweek repository[/white]")

    # ─────────────────────────────────────────────────────────────
    # Step 7: Download local classifier model
    # ─────────────────────────────────────────────────────────────
    _download_local_model(quick)

    # ─────────────────────────────────────────────────────────────
    # Step 8: Security Configuration
    # ─────────────────────────────────────────────────────────────
    cfg = ConfigManager()

    if preset:
        # Apply preset directly
        cfg.apply_preset(preset)
        console.print(f"\n[green]\u2713[/green] Applied [bold]{preset}[/bold] security preset")
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
                console.print(f"  \u2022 {skill}")
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

            console.print(f"\n[green]\u2713[/green] Configured {len(unknown_skills)} skills")
        else:
            console.print("[white]All detected skills already configured[/white]")

        # Apply cautious preset as base
        cfg.apply_preset("cautious")
        console.print("[green]\u2713[/green] Applied [bold]cautious[/bold] base preset")
        install_summary["preset"] = "cautious (ai-defaults)"

    elif interactive:
        # Full interactive configuration
        console.print("\n[bold]Security Configuration[/bold]")
        console.print("Choose how to configure security settings:\n")
        console.print("  [cyan]1.[/cyan] Paranoid  - Maximum security, prompt on everything")
        console.print("  [cyan]2.[/cyan] Balanced  - Smart defaults with provenance tracking [green](recommended)[/green]")
        console.print("  [cyan]3.[/cyan] Cautious  - Prompt on risky operations")
        console.print("  [cyan]4.[/cyan] Trusted   - Minimal prompts")
        console.print("  [cyan]5.[/cyan] Custom    - Configure individually")
        console.print()

        choice = click.prompt("Select", type=click.IntRange(1, 5), default=2)

        if choice == 1:
            cfg.apply_preset("paranoid")
            console.print("[green]\u2713[/green] Applied paranoid preset")
            install_summary["preset"] = "paranoid"
        elif choice == 2:
            cfg.apply_preset("balanced")
            console.print("[green]\u2713[/green] Applied balanced preset")
            console.print("[white]  Clean sessions get fewer prompts; tainted sessions get extra scrutiny[/white]")
            install_summary["preset"] = "balanced"
        elif choice == 3:
            cfg.apply_preset("cautious")
            console.print("[green]\u2713[/green] Applied cautious preset")
            install_summary["preset"] = "cautious"
        elif choice == 4:
            cfg.apply_preset("trusted")
            console.print("[green]\u2713[/green] Applied trusted preset")
            install_summary["preset"] = "trusted"
        else:
            # Custom: ask about key tools
            console.print("\n[bold]Configure key tools:[/bold]")
            console.print("[white](safe/default/risky/dangerous)[/white]\n")

            for tool in ["Bash", "WebFetch", "Edit"]:
                current = cfg.get_tool_tier(tool)
                new_tier = click.prompt(
                    f"  {tool}",
                    default=current.value,
                    type=click.Choice(["safe", "default", "risky", "dangerous"])
                )
                cfg.set_tool_tier(tool, SecurityTier.from_string(new_tier))

            console.print("[green]\u2713[/green] Custom configuration saved")
            install_summary["preset"] = "custom"

    else:
        # Default: apply cautious preset silently
        if not cfg.export_config("user"):
            cfg.apply_preset("cautious")
            console.print("\n[green]\u2713[/green] Applied default [bold]cautious[/bold] security preset")
            console.print("[white]Run 'tweek config interactive' to customize[/white]")
            install_summary["preset"] = "cautious"
        else:
            install_summary["preset"] = "existing"

    # ─────────────────────────────────────────────────────────────
    # Step 9: LLM Review Provider Selection
    # ─────────────────────────────────────────────────────────────
    llm_config = _configure_llm_provider(tweek_dir, interactive, quick)
    install_summary["llm_provider"] = llm_config.get("provider_display", "auto-detect")
    install_summary["llm_model"] = llm_config.get("model_display")

    # ─────────────────────────────────────────────────────────────
    # Step 10: Scan for .env files (moved after security config)
    # ─────────────────────────────────────────────────────────────
    if not skip_env_scan:
        console.print("\n[cyan]Scanning for .env files with credentials...[/cyan]\n")

        env_files = scan_for_env_files()

        if env_files:
            table = Table(title="Found .env Files")
            table.add_column("#", style="white")
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

            console.print("\n[yellow]Migrate these credentials to secure storage?[/yellow] ", end="")
            if click.confirm(""):
                from tweek.vault import get_vault, VAULT_AVAILABLE
                if not VAULT_AVAILABLE:
                    console.print("[red]\u2717[/red] Vault not available. Install keyring: pip install keyring")
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
                    console.print(f"  [white]Preview - credentials to migrate:[/white]")
                    for key in keys:
                        console.print(f"    \u2022 {key}")

                    if click.confirm(f"  Migrate {len(keys)} credentials to '{skill}'?"):
                        try:
                            from tweek.vault import migrate_env_to_vault
                            results = migrate_env_to_vault(path, skill, vault, dry_run=False)
                            successful = sum(1 for _, s in results if s)
                            total = len(results)
                            console.print(f"  [green]\u2713[/green] Migrated {successful} credentials")

                            if successful == total and path.exists():
                                # All credentials migrated — offer to remove the .env file
                                if click.confirm(f"  Remove {display_path}? (credentials are now in the vault)"):
                                    path.unlink()
                                    console.print(f"  [green]\u2713[/green] Removed {display_path}")
                                else:
                                    console.print(f"  [yellow]\u26a0[/yellow] {display_path} still contains plaintext credentials")
                            elif successful < total:
                                failed = total - successful
                                console.print(f"  [yellow]\u26a0[/yellow] {failed} credential(s) failed to migrate \u2014 keeping {display_path}")
                        except Exception as e:
                            console.print(f"  [red]\u2717[/red] Migration failed: {e}")
                    else:
                        console.print(f"  [white]Skipped[/white]")
        else:
            console.print("[white]No .env files with credentials found[/white]")

    # ─────────────────────────────────────────────────────────────
    # Step 11: Linux: Prompt for firejail installation
    # ─────────────────────────────────────────────────────────────
    if IS_LINUX:
        caps = get_capabilities()
        if not caps.sandbox_available:
            if with_sandbox or (interactive and not quick):
                from tweek.sandbox.linux import prompt_install_firejail
                prompt_install_firejail(console)
            else:
                console.print("\n[yellow]Note:[/yellow] Sandbox (firejail) not installed.")
                console.print(f"[white]Install with: {caps.sandbox_install_hint}[/white]")
                console.print("[white]Or run 'tweek install --with-sandbox' to install now[/white]")

    # ─────────────────────────────────────────────────────────────
    # Step 12: Configure Tweek proxy if override was enabled
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
            tweek_config["proxy"]["override_openclaw"] = True
            tweek_config["proxy"]["auto_start"] = False  # User must explicitly start

            with open(proxy_config_path, "w") as f:
                yaml.dump(tweek_config, f, default_flow_style=False)

            console.print("\n[green]\u2713[/green] Proxy override configured")
            console.print(f"  [white]Config saved to: {proxy_config_path}[/white]")
            console.print("  [yellow]Run 'tweek proxy start' to begin intercepting API calls[/yellow]")
            install_summary["proxy"] = True
        except Exception as e:
            console.print(f"\n[yellow]Warning: Could not save proxy config: {e}[/yellow]")

    # ─────────────────────────────────────────────────────────────
    # Step 13: Post-install verification and summary
    # ─────────────────────────────────────────────────────────────
    _print_install_summary(install_summary, target, tweek_dir, proxy_override_enabled)

    # ─────────────────────────────────────────────────────────────
    # Step 14: Scan for other AI tools and offer protection
    # ─────────────────────────────────────────────────────────────
    if not quick:
        _offer_mcp_protection()



def _offer_mcp_protection() -> None:
    """Scan for installed MCP-capable AI tools and offer to protect them.

    Detects Claude Desktop, Gemini CLI, and ChatGPT Desktop. For each tool
    that is installed but not yet protected, prompts the user to add Tweek
    as an MCP server.
    """
    from tweek.cli_protect import _protect_mcp_client

    # MCP client tool IDs to scan for (exclude claude-code and openclaw —
    # those are handled by their own install paths)
    mcp_tool_ids = {"claude-desktop", "chatgpt", "gemini"}

    try:
        all_tools = _detect_all_tools()
    except Exception:
        return

    unprotected = [
        (tool_id, label)
        for tool_id, label, installed, protected, _detail in all_tools
        if tool_id in mcp_tool_ids and installed and not protected
    ]

    if not unprotected:
        return

    console.print("\n[bold]Other AI tools detected[/bold]")
    console.print("Tweek can also protect these tools via MCP server integration:\n")

    for tool_id, label in unprotected:
        if click.confirm(f"  Protect {label}?", default=True):
            try:
                _protect_mcp_client(tool_id)
            except Exception as e:
                console.print(f"  [yellow]Could not configure {label}: {e}[/yellow]")
        else:
            console.print(f"  [dim]Skipped {label}[/dim]")

    console.print()


def _create_tweek_yaml(install_global: bool) -> None:
    """Create .tweek.yaml in the project directory with hooks enabled.

    This file controls whether PreToolUse and PostToolUse hooks run in
    this directory. Created with both enabled by default — the user must
    manually set them to false to disable protection.

    For global installs, creates in the home directory so it applies
    as the fallback when no project-level .tweek.yaml exists.
    """
    import yaml

    if install_global:
        tweek_yaml_path = Path("~/.tweek.yaml").expanduser()
    else:
        tweek_yaml_path = Path.cwd() / ".tweek.yaml"

    # Don't overwrite if it already exists (user may have customized it)
    if tweek_yaml_path.exists():
        return

    config = {
        "hooks": {
            "pre_tool_use": True,
            "post_tool_use": True,
        },
    }

    try:
        with open(tweek_yaml_path, "w") as f:
            f.write("# Tweek per-directory hook configuration\n")
            f.write("# Set to false to disable screening in this directory.\n")
            f.write("# This file is protected — only a human can edit it.\n")
            yaml.dump(config, f, default_flow_style=False)
        console.print(f"[green]\u2713[/green] Hook config: {tweek_yaml_path}")
    except Exception as e:
        console.print(f"[yellow]Warning: Could not create {tweek_yaml_path}: {e}[/yellow]")


def _check_python_version(console: Console, quick: bool) -> None:
    """Show Python version and warn about path mismatches.

    The hard version gate lives in scripts/install.sh. This function only
    reports the running Python and warns if the system python3 differs
    (which affects hook execution).
    """
    current = sys.version_info[:2]
    console.print(f"[green]\u2713[/green] Python {current[0]}.{current[1]} ({sys.executable})")

    # Warn if system python3 differs from install Python
    # This matters because hooks run via the Python path stored in settings.json
    system_python3 = shutil.which("python3")
    if system_python3:
        try:
            resolved_install = Path(sys.executable).resolve()
            resolved_system = Path(system_python3).resolve()

            if resolved_install != resolved_system:
                console.print(f"[white]  Note: system python3 is {resolved_system}[/white]")
                console.print(f"[white]  Hooks will use {resolved_install} (the Python running this install)[/white]")
        except (OSError, ValueError):
            pass
    else:
        if not quick:
            console.print("[yellow]  Note: python3 not found on PATH[/yellow]")
            console.print(f"[white]  Hooks will use {sys.executable} directly[/white]")


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
        console.print("[bold]Security Screening Provider[/bold] (Layer 3 \u2014 semantic analysis)")
        console.print()
        console.print("  Tweek can analyze suspicious commands for deeper security screening.")
        console.print("  A local on-device model is preferred (no API key needed), with")
        console.print("  optional cloud LLM escalation for uncertain cases.")
        console.print()
        console.print("  [cyan]1.[/cyan] Auto-detect (recommended)")
        if local_model_ready:
            console.print(f"     [white]Local model installed ({local_model_name}) \u2014 will use it first[/white]")
        else:
            console.print("     [white]Uses first available: Local model > Google > OpenAI > Anthropic[/white]")
        console.print("  [cyan]2.[/cyan] Anthropic (Claude Haiku) [yellow]— billed separately from Max/Pro plans[/yellow]")
        console.print("  [cyan]3.[/cyan] OpenAI (GPT-4o-mini)")
        console.print("  [cyan]4.[/cyan] Google (Gemini 2.0 Flash) [green]— free tier available[/green]")
        console.print("  [cyan]5.[/cyan] Custom endpoint (Ollama, LM Studio, Together, Groq, etc.)")
        console.print("  [cyan]6.[/cyan] Disable screening")
        if not local_model_ready:
            console.print()
            console.print("  [white]Tip: Run 'tweek model download' to install the local model[/white]")
            console.print("  [white]     (on-device, no API key, ~45MB download)[/white]")
        console.print()

        choice = click.prompt("Select", type=click.IntRange(1, 6), default=1)

        if choice == 1:
            result["provider"] = "auto"
        elif choice == 2:
            console.print()
            console.print("[yellow]  Note: Anthropic API keys are billed per-token, separately from[/yellow]")
            console.print("[yellow]  Claude Pro/Max subscriptions. Consider Google Gemini (option 4)[/yellow]")
            console.print("[yellow]  for a free tier alternative.[/yellow]")
            if not click.confirm("  Continue with Anthropic?", default=True):
                result["provider"] = "google"
                result["model"] = "gemini-2.0-flash"
                console.print("  Switched to Google Gemini 2.0 Flash")
            else:
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
            console.print("[white]Most local servers (Ollama, LM Studio, vLLM) and cloud providers[/white]")
            console.print("[white](Together, Groq, Mistral) expose an OpenAI-compatible API.[/white]")
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
            console.print("[white]Screening disabled. Pattern matching and other layers remain active.[/white]")
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

    # Warn if no LLM provider was found (auto or quick mode)
    if result.get("provider_display") and "disabled" in (result.get("provider_display") or "").lower():
        _warn_no_llm_provider(quick)

    # Save LLM config to ~/.tweek/config.yaml
    # Uses append_active_section to preserve template comments instead of yaml.dump
    if result["provider"] != "auto" or result.get("base_url"):
        try:
            from tweek.config.templates import append_active_section
            config_path = tweek_dir / "config.yaml"

            # Build the active YAML section
            lines = ["llm_review:"]
            if result["provider"] == "disabled":
                lines.append("  enabled: false")
            else:
                lines.append("  enabled: true")
                lines.append(f"  provider: {result['provider']}")
                if result["model"] != "auto":
                    lines.append(f"  model: {result['model']}")
                if result.get("base_url"):
                    lines.append(f"  base_url: {result['base_url']}")
                if result.get("api_key_env"):
                    lines.append(f"  api_key_env: {result['api_key_env']}")

            append_active_section(config_path, "\n".join(lines))

            if result["provider"] == "disabled":
                console.print("[green]\u2713[/green] LLM review disabled in config")
            else:
                console.print(f"[green]\u2713[/green] LLM provider configured: {result['provider_display']}")
        except Exception as e:
            console.print(f"[white]Warning: Could not save LLM config: {e}[/white]")
    else:
        if result["provider_display"] and "disabled" not in (result["provider_display"] or ""):
            console.print(f"[green]\u2713[/green] LLM provider: {result['provider_display']} ({result.get('model_display', 'auto')})")
        elif result["provider"] == "auto":
            console.print(f"[green]\u2713[/green] LLM provider: {result['provider_display']}")

    return result


def _warn_no_llm_provider(quick: bool) -> None:
    """Warn user when no LLM provider is available for semantic analysis.

    This runs in auto and quick modes when auto-detection finds no API key.
    Pattern matching (262 patterns) still works, but the deeper semantic
    analysis layer (Layer 3) will be inactive.
    """
    console.print()
    console.print("[yellow]  LLM review is not available.[/yellow]")
    console.print("  Pattern matching is still active, but LLM semantic analysis requires an API key.")
    console.print()
    console.print("  [bold]Recommended:[/bold] Google Gemini (free tier available)")
    console.print("    1. Get a free key at: https://aistudio.google.com/apikey")
    console.print("    2. Run: [cyan]tweek config edit env[/cyan]")
    console.print("       Uncomment the GOOGLE_API_KEY line and paste your key.")
    console.print()
    console.print("  [yellow]Note:[/yellow] Anthropic API keys are billed separately from Claude Pro/Max plans.")
    console.print("  Google Gemini's free tier is recommended for most users.")
    console.print()
    console.print("  All provider options are documented in ~/.tweek/.env")


def _detect_llm_provider():
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

    # Cloud providers — Google first (free tier), then others (pay-per-token)
    checks = [
        ("GOOGLE_API_KEY", "Google", "gemini-2.0-flash"),
        ("GEMINI_API_KEY", "Google", "gemini-2.0-flash"),
        ("OPENAI_API_KEY", "OpenAI", "gpt-4o-mini"),
        ("XAI_API_KEY", "xAI (Grok)", "grok-2"),
        ("ANTHROPIC_API_KEY", "Anthropic", "claude-3-5-haiku-latest"),
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
        console.print(f"  [white]Checking endpoint: {llm_config['base_url']}[/white]")
        try:
            from tweek.security.llm_reviewer import resolve_provider
            test_provider = resolve_provider(
                provider="openai",
                model=llm_config.get("model", "auto"),
                base_url=llm_config["base_url"],
                timeout=3.0,
            )
            if test_provider and test_provider.is_available():
                console.print(f"  [green]\u2713[/green] Endpoint reachable")
            else:
                console.print(f"  [yellow]\u26a0[/yellow] Could not verify endpoint")
                console.print(f"  [white]Tweek will try this endpoint at runtime[/white]")
        except Exception:
            console.print(f"  [yellow]\u26a0[/yellow] Could not verify endpoint")
            console.print(f"  [white]Tweek will try this endpoint at runtime[/white]")
        return
    else:
        expected_vars = env_var_map.get(provider, [])

    if not expected_vars:
        return

    # Check if any expected env var is set in environment or vault
    found_key = False
    key_source = None

    for var in expected_vars:
        if os.environ.get(var):
            found_key = True
            key_source = "environment"
            console.print(f"  [green]\u2713[/green] {var} found in environment")
            break

    # Check vault if not in environment
    if not found_key:
        try:
            from tweek.vault import get_vault, VAULT_AVAILABLE
            if VAULT_AVAILABLE and get_vault:
                vault = get_vault()
                for var in expected_vars:
                    if vault.get("tweek-security", var):
                        found_key = True
                        key_source = "vault"
                        console.print(f"  [green]\u2713[/green] {var} found in vault")
                        break
        except Exception:
            pass

    if not found_key:
        var_list = " or ".join(expected_vars)
        console.print(f"  [yellow]\u26a0[/yellow] {var_list} not found")
        console.print()

        # Offer to store the key in the vault
        store_key = click.confirm("  Enter your API key now? (stored securely in system vault)", default=True)
        if store_key:
            key_name = expected_vars[0]
            api_key_value = click.prompt(f"  {key_name}", hide_input=True)
            if api_key_value:
                try:
                    from tweek.vault import get_vault, VAULT_AVAILABLE
                    if VAULT_AVAILABLE and get_vault:
                        vault = get_vault()
                        vault.store("tweek-security", key_name, api_key_value)
                        console.print(f"  [green]\u2713[/green] {key_name} stored in vault")
                        found_key = True
                    else:
                        console.print(f"  [yellow]\u26a0[/yellow] Vault not available. Set {key_name} in your shell profile instead.")
                except Exception as e:
                    console.print(f"  [yellow]\u26a0[/yellow] Could not store in vault: {e}")
                    console.print(f"  [white]Set {key_name} in your shell profile instead.[/white]")

    if not found_key:
        console.print(f"  [white]LLM review will be disabled until a key is available.[/white]")

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
                console.print(f"  [green]\u2713[/green] Switched to auto-detect: {detected['name']}")
            else:
                llm_config["provider_display"] = "disabled (no API key found)"
                llm_config["model_display"] = None
                console.print(f"  [white]No API keys found \u2014 LLM review will be disabled[/white]")


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
                console.print("  [green]\u2713[/green] PreToolUse + PostToolUse hooks active")
                # Extract Python path from hook command to verify it exists
                try:
                    cmd = hooks["PreToolUse"][0]["hooks"][0]["command"]
                    hook_python = cmd.split()[0]
                    if Path(hook_python).exists():
                        console.print(f"  [green]\u2713[/green] Hook Python: {hook_python}")
                    else:
                        console.print(f"  [yellow]\u26a0[/yellow] Hook Python not found: {hook_python}")
                        console.print(f"    [white]Run 'tweek install' again if Python was reinstalled[/white]")
                except (IndexError, KeyError):
                    pass
            elif has_pre:
                console.print("  [green]\u2713[/green] PreToolUse hook active")
                console.print("  [yellow]\u26a0[/yellow] PostToolUse hook missing")
            else:
                console.print("  [yellow]\u26a0[/yellow] Hooks may not be installed correctly")
        except Exception:
            console.print("  [yellow]\u26a0[/yellow] Could not verify hook installation")
    else:
        console.print("  [yellow]\u26a0[/yellow] Settings file not found")

    # Check pattern database
    patterns_file = Path(__file__).resolve().parent / "config" / "patterns.yaml"
    pattern_count = 0
    if patterns_file.exists():
        try:
            import yaml
            with open(patterns_file) as f:
                pdata = yaml.safe_load(f) or {}
            pattern_count = len(pdata.get("patterns", []))
            console.print(f"  [green]\u2713[/green] Pattern database loaded ({pattern_count} patterns)")
        except Exception:
            console.print("  [yellow]\u26a0[/yellow] Could not load pattern database")
    else:
        console.print("  [yellow]\u26a0[/yellow] Pattern database not found")

    # LLM reviewer status
    llm_display = summary.get("llm_provider", "auto-detect")
    llm_model = summary.get("llm_model")
    if llm_model:
        console.print(f"  [green]\u2713[/green] LLM reviewer: {llm_display} ({llm_model})")
    elif llm_display and "disabled" not in llm_display:
        console.print(f"  [green]\u2713[/green] LLM reviewer: {llm_display}")
    else:
        console.print(f"  [white]\u25cb[/white] LLM reviewer: {llm_display}")

    # Sandbox status
    caps = get_capabilities()
    if caps.sandbox_available:
        console.print(f"  [green]\u2713[/green] Sandbox: {caps.sandbox_tool}")
    else:
        console.print(f"  [white]\u25cb[/white] Sandbox: not available ({caps.platform.value})")

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

    # Scope-specific guidance
    scope = summary.get("scope", "project")
    if scope == "project":
        console.print()
        console.print("[white]This installation protects only the current project.[/white]")
        console.print("[white]To protect all projects on this machine, run:[/white]")
        console.print("[bold]  tweek protect claude-code --global[/bold]")
    elif scope == "global":
        console.print()
        console.print("[white]This installation protects all projects globally.[/white]")
        console.print("[white]To protect only a specific project instead, run from that directory:[/white]")
        console.print("[bold]  tweek protect claude-code[/bold]")

    # Next steps
    console.print()
    console.print("[white]Next steps:[/white]")
    console.print("[white]  tweek doctor        \u2014 Verify installation[/white]")
    console.print("[white]  tweek update        \u2014 Get latest attack patterns[/white]")
    console.print("[white]  tweek configure     \u2014 Tune LLM, vault, proxy, sandbox[/white]")
    console.print("[white]  tweek config list   \u2014 See security settings[/white]")
    if proxy_override_enabled:
        console.print("[white]  tweek proxy start   \u2014 Enable API interception[/white]")


# ---------------------------------------------------------------------------
# Install command (absorbs quickstart)
# ---------------------------------------------------------------------------

@click.command(
    epilog="""\b
Examples:
  tweek install                          Interactive setup wizard
  tweek install --scope global           Install globally (all projects)
  tweek install --scope project          Install for current project only
  tweek install --preset paranoid        Apply paranoid security preset
  tweek install --quick                  Zero-prompt install with defaults
"""
)
@click.option("--scope", type=click.Choice(["global", "project", "both"]),
              default=None, help="Installation scope (interactive if not specified)")
@click.option("--preset", type=click.Choice(["paranoid", "cautious", "balanced", "trusted"]),
              default=None, help="Security preset (interactive if not specified)")
@click.option("--quick", is_flag=True,
              help="Non-interactive install with cautious defaults")
@click.option("--backup/--no-backup", default=True,
              help="Backup existing hooks before installation")
@click.option("--skip-env-scan", is_flag=True,
              help="Skip scanning for .env files to migrate")
@click.option("--interactive", "-i", is_flag=True,
              help="Interactively configure security settings")
@click.option("--ai-defaults", is_flag=True,
              help="Let AI suggest default settings based on detected skills")
@click.option("--with-sandbox", is_flag=True,
              help="Prompt to install sandbox tool if not available (Linux only)")
@click.option("--force-proxy", is_flag=True,
              help="Force Tweek proxy to override existing proxy configurations")
@click.option("--skip-proxy-check", is_flag=True,
              help="Skip checking for existing proxy configurations")
def install(scope, preset, quick, backup, skip_env_scan, interactive, ai_defaults, with_sandbox, force_proxy, skip_proxy_check):
    """Install Tweek security on your system.

    Sets up hooks, applies a security preset, verifies credential vault,
    and offers optional MCP proxy configuration.

    This is the full onboarding wizard. For tool-specific protection,
    use 'tweek protect [tool]' instead.
    """
    from tweek.cli_helpers import print_success, print_warning, spinner

    if quick:
        # Quick mode: just install hooks with defaults
        install_global = scope == "global" if scope else True
        _install_claude_code_hooks(
            install_global=install_global,
            dev_test=False,
            backup=backup,
            skip_env_scan=True,
            interactive=False,
            preset=preset or "balanced",
            ai_defaults=False,
            with_sandbox=False,
            force_proxy=force_proxy,
            skip_proxy_check=True,
            quick=True,
        )
        return

    # Full wizard mode
    console.print(TWEEK_BANNER, style="cyan")
    console.print("[bold]Welcome to Tweek![/bold]")
    console.print()
    console.print("This wizard will help you set up Tweek step by step.")
    console.print("  1. Install hooks")
    console.print("  2. Choose a security preset")
    console.print("  3. Download classifier model")
    console.print("  4. Verify credential vault")
    console.print("  5. Optional MCP proxy")
    console.print()

    # Step 1: Install hooks
    console.print("[bold cyan]Step 1/5: Hook Installation[/bold cyan]")
    if scope is None:
        scope_choice = click.prompt(
            "Where should Tweek protect?",
            type=click.Choice(["global", "project", "both"]),
            default="global",
        )
    else:
        scope_choice = scope

    scopes = ["global", "project"] if scope_choice == "both" else [scope_choice]
    for s in scopes:
        try:
            _quickstart_install_hooks(s)
            print_success(f"Hooks installed ({s})")
        except Exception as e:
            print_warning(f"Could not install hooks ({s}): {e}")
    console.print()

    # Step 2: Security preset
    console.print("[bold cyan]Step 2/5: Security Preset[/bold cyan]")
    if preset is None:
        console.print("  [cyan]1.[/cyan] paranoid  \u2014 Block everything suspicious, prompt on risky")
        console.print("  [cyan]2.[/cyan] balanced  \u2014 Smart defaults with provenance tracking [white](recommended)[/white]")
        console.print("  [cyan]3.[/cyan] cautious  \u2014 Block dangerous, prompt on risky")
        console.print("  [cyan]4.[/cyan] trusted   \u2014 Allow most operations, block only dangerous")
        console.print()

        preset_choice = click.prompt(
            "Select preset",
            type=click.Choice(["1", "2", "3", "4"]),
            default="2",
        )
        preset_map = {"1": "paranoid", "2": "balanced", "3": "cautious", "4": "trusted"}
        preset_name = preset_map[preset_choice]
    else:
        preset_name = preset

    try:
        from tweek.config.manager import ConfigManager
        cfg = ConfigManager()
        cfg.apply_preset(preset_name)
        print_success(f"Applied {preset_name} preset")
    except Exception as e:
        print_warning(f"Could not apply preset: {e}")
    console.print()

    # Step 3: Download classifier model
    console.print("[bold cyan]Step 3/5: Local Classifier Model[/bold cyan]")
    _download_local_model(quick=False)
    console.print()

    # Step 4: Credential vault
    console.print("[bold cyan]Step 4/5: Credential Vault[/bold cyan]")
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

    # Step 5: Optional MCP proxy
    console.print("[bold cyan]Step 5/5: MCP Proxy (optional)[/bold cyan]")
    setup_mcp = click.confirm("Set up MCP proxy for Claude Desktop?", default=False)
    if setup_mcp:
        try:
            import mcp  # noqa: F401
            console.print("[white]MCP package available. Configure upstream servers in ~/.tweek/config.yaml[/white]")
            console.print("[white]Then run: tweek mcp proxy[/white]")
        except ImportError:
            print_warning("MCP package not installed. Install with: pip install tweek[mcp]")
    else:
        console.print("[white]Skipped.[/white]")

    # Scan for other AI tools
    _offer_mcp_protection()

    console.print()
    console.print("[bold green]Setup complete![/bold green]")
    console.print("  Run [cyan]tweek doctor[/cyan] to verify your installation")


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
