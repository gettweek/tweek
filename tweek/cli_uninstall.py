#!/usr/bin/env python3
"""
Tweek CLI Uninstall Command

Full removal of Tweek from the system:
    tweek uninstall                      Interactive full removal
    tweek uninstall --all                Remove ALL Tweek data system-wide
    tweek uninstall --all --confirm      Remove everything without prompts

Resilience against ``pip uninstall tweek`` running first:
    - Hooks in settings.json point to self-healing wrappers at ~/.tweek/hooks/
      (outside the pip package). If tweek is gone, the wrappers silently remove
      themselves from settings.json and allow the tool call.
    - A standalone cleanup script at ~/.tweek/uninstall.sh can remove all
      Tweek state without requiring the Python package.
"""
from __future__ import annotations

import click
import json
import shutil
import subprocess
import sys
from pathlib import Path

from tweek.cli_helpers import (
    console,
    TWEEK_BANNER,
    _has_tweek_hooks,
    _has_tweek_at,
)


# =============================================================================
# UNINSTALL COMMAND
# =============================================================================

@click.command(
    epilog="""\b
Examples:
  tweek uninstall                          Interactive full removal
  tweek uninstall --all                    Remove ALL Tweek data system-wide
  tweek uninstall --all --confirm          Remove everything without prompts
"""
)
@click.option("--all", "remove_all", is_flag=True, default=False,
              help="Remove ALL Tweek data: hooks, skills, config, patterns, logs, MCP integrations")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompts")
def uninstall(remove_all: bool, confirm: bool):
    """Fully remove Tweek from your system.

    Removes all hooks, skills, configuration, data, and optionally
    the Tweek package itself. For removing protection from a single
    tool without uninstalling, use `tweek unprotect` instead.

    This command can only be run from an interactive terminal.
    AI agents are blocked from running it.
    """
    # ─────────────────────────────────────────────────────────────
    # HUMAN-ONLY GATE: Block non-interactive execution
    # ─────────────────────────────────────────────────────────────
    if not sys.stdin.isatty():
        console.print("[red]ERROR: tweek uninstall must be run from an interactive terminal.[/red]")
        console.print("[white]This command cannot be run by AI agents or automated scripts.[/white]")
        console.print("[white]Open a terminal and run the command directly.[/white]")
        raise SystemExit(1)

    console.print(TWEEK_BANNER, style="cyan")

    tweek_dir = Path("~/.tweek").expanduser()
    global_target = Path("~/.claude").expanduser()
    project_target = Path.cwd() / ".claude"

    if not remove_all:
        # Interactive: ask what to remove
        console.print("[bold]What would you like to remove?[/bold]")
        console.print()
        console.print("  [bold]1.[/bold] Everything (all hooks, data, config, and package)")
        console.print("  [bold]2.[/bold] Cancel")
        console.print()
        choice = click.prompt("Select", type=click.IntRange(1, 2), default=2)
        if choice == 2:
            console.print("[white]Cancelled[/white]")
            return
        console.print()

    _uninstall_everything(global_target, project_target, tweek_dir, confirm)
    _show_package_removal_hint()


# =============================================================================
# UNINSTALL HELPERS
# =============================================================================

def _detect_all_package_managers() -> list:
    """Detect all places tweek is installed. Returns list of uninstall commands."""
    found = []

    # Check pipx
    try:
        result = subprocess.run(
            ["pipx", "list"], capture_output=True, text=True, timeout=5
        )
        if "tweek" in result.stdout:
            found.append("pipx uninstall tweek")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Check uv
    try:
        result = subprocess.run(
            ["uv", "tool", "list"], capture_output=True, text=True, timeout=5
        )
        if "tweek" in result.stdout:
            found.append("uv tool uninstall tweek")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Check pip
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "show", "tweek"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            found.append("pip uninstall tweek -y")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return found


def _show_package_removal_hint():
    """Offer to remove all tweek CLI package installations for the user."""
    pkg_cmds = _detect_all_package_managers()
    if not pkg_cmds:
        return

    console.print()
    console.print("[bold yellow]The tweek CLI binary is still installed on your system.[/bold yellow]")

    if len(pkg_cmds) > 1:
        console.print(f"[white]Found {len(pkg_cmds)} installations:[/white]")
        for cmd in pkg_cmds:
            console.print(f"  [white]\u2022 {cmd}[/white]")

    console.print()
    label = " + ".join(f"[bold]{cmd}[/bold]" for cmd in pkg_cmds)
    console.print(f"  [bold]1.[/bold] Remove all now ({label})")
    console.print(f"  [bold]2.[/bold] Keep (you can remove later)")
    console.print()
    choice = click.prompt("Select", type=click.IntRange(1, 2), default=2)

    if choice == 1:
        for pkg_cmd in pkg_cmds:
            console.print()
            console.print(f"[cyan]Running:[/cyan] {pkg_cmd}")
            try:
                result = subprocess.run(
                    pkg_cmd.split(), capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    console.print(f"[green]\u2713[/green] Removed ({pkg_cmd})")
                else:
                    console.print(f"[red]\u2717[/red] Failed: {result.stderr.strip()}")
                    console.print(f"  [white]Run manually: {pkg_cmd}[/white]")
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
                console.print(f"[red]\u2717[/red] Could not run: {e}")
                console.print(f"  [white]Run manually: {pkg_cmd}[/white]")


def _remove_hooks_from_settings(settings_file: Path) -> list:
    """Remove Tweek hooks from a settings.json file.

    Returns list of hook types removed (e.g. ['PreToolUse', 'PostToolUse']).
    """
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
        ("uninstall.sh", "standalone uninstall script"),
        ("installed_scopes.json", "installation scope tracking"),
    ]
    for filename, label in items:
        filepath = tweek_dir / filename
        if filepath.exists():
            filepath.unlink()
            removed.append(label)

    dirs = [
        ("hooks", "self-healing hook wrappers"),
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


def _remove_tweek_yaml_files(tweek_dir: Path) -> list:
    """Remove .tweek.yaml control files. Returns list of paths removed."""
    removed = []

    # Global .tweek.yaml
    global_yaml = Path("~/.tweek.yaml").expanduser()
    if global_yaml.exists():
        global_yaml.unlink()
        removed.append(str(global_yaml))

    # Project-level .tweek.yaml files from recorded scopes
    scopes_file = tweek_dir / "installed_scopes.json"
    if scopes_file.exists():
        try:
            scopes = json.loads(scopes_file.read_text()) or []
            for scope_str in scopes:
                # .tweek.yaml is in the parent of the .claude/ directory
                scope_parent = Path(scope_str).parent
                project_yaml = scope_parent / ".tweek.yaml"
                if project_yaml.exists():
                    project_yaml.unlink()
                    removed.append(str(project_yaml))
        except (json.JSONDecodeError, IOError):
            pass

    # Current directory .tweek.yaml
    cwd_yaml = Path.cwd() / ".tweek.yaml"
    if cwd_yaml.exists() and str(cwd_yaml) not in removed:
        cwd_yaml.unlink()
        removed.append(str(cwd_yaml))

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
        console.print("  [white]\u2022[/white] PreToolUse and PostToolUse hooks from settings.json")
    if has_skills:
        console.print("  [white]\u2022[/white] Tweek skill directory (skills/tweek/)")
    if has_backup:
        console.print("  [white]\u2022[/white] Backup file (settings.json.tweek-backup)")
    console.print("  [white]\u2022[/white] Project whitelist entries from overrides")
    console.print()

    if not confirm:
        console.print(f"[yellow]Remove Tweek from this {scope_label}?[/yellow] ", end="")
        if not click.confirm(""):
            console.print("[white]Cancelled[/white]")
            return

    console.print()

    # 1. Remove hooks
    removed_hooks = _remove_hooks_from_settings(settings_file)
    for hook_type in removed_hooks:
        console.print(f"  [green]\u2713[/green] Removed {hook_type} hook from settings.json")
    if has_hooks and not removed_hooks:
        console.print(f"  [red]\u2717[/red] Failed to remove hooks from settings.json")

    # 2. Remove skill directory
    if _remove_skill_directory(target):
        console.print(f"  [green]\u2713[/green] Removed Tweek skill directory (skills/tweek/)")
    else:
        console.print(f"  [white]-[/white] Skipped: Tweek skill directory not found")

    # 3. Remove backup file
    if _remove_backup_file(target):
        console.print(f"  [green]\u2713[/green] Removed backup file (settings.json.tweek-backup)")
    else:
        console.print(f"  [white]-[/white] Skipped: no backup file found")

    # 4. Remove whitelist entries
    wl_count = _remove_whitelist_entries(target, tweek_dir)
    if wl_count > 0:
        console.print(f"  [green]\u2713[/green] Removed {wl_count} whitelist entry(s) from overrides")
    else:
        console.print(f"  [white]-[/white] Skipped: no whitelist entries found for this {scope_label}")

    console.print()
    console.print(f"[green]Uninstall complete.[/green] Tweek is no longer active for this {scope_label}.")
    if scope_label == "project":
        console.print("[white]Global installation (~/.claude/) was not affected.[/white]")
    else:
        console.print("[white]Project installations were not affected.[/white]")

    # Offer to remove data directory
    if tweek_dir.exists() and not confirm:
        # Check if the OTHER scope still has tweek installed
        global_target = Path("~/.claude").expanduser()
        project_target = Path.cwd() / ".claude"
        other_target = global_target if scope_label == "project" else project_target
        other_label = "global" if scope_label == "project" else "project"
        other_has_tweek = _has_tweek_at(other_target)

        console.print()
        console.print("[yellow]Also remove Tweek data directory (~/.tweek/)?[/yellow]")
        console.print("[white]This contains config, patterns, security logs, and overrides.[/white]")
        if other_has_tweek:
            console.print(f"[bold red]Warning:[/bold red] Tweek is still installed at {other_label} scope ({other_target}).")
            console.print(f"  Removing ~/.tweek/ will affect that installation (no config, patterns, or logs).")
        console.print()
        console.print(f"  [bold]1.[/bold] Keep data (recommended)" if other_has_tweek else f"  [bold]1.[/bold] Keep data (can reinstall later without re-downloading patterns)")
        console.print(f"  [bold]2.[/bold] Remove data (~/.tweek/)")
        console.print()
        remove_choice = click.prompt("Select", type=click.IntRange(1, 2), default=1)
        if remove_choice == 2:
            console.print()
            data_removed = _remove_tweek_data_dir(tweek_dir)
            for item in data_removed:
                console.print(f"  [green]\u2713[/green] Removed {item}")
            if not data_removed:
                console.print(f"  [white]-[/white] No data to remove")
    elif tweek_dir.exists():
        console.print("[white]Tweek data directory (~/.tweek/) was preserved.[/white]")


def _get_all_project_scopes(project_target: Path) -> list:
    """Get all project-level .claude/ directories that may have tweek hooks.

    Merges: (1) the current project, (2) any recorded install scopes from
    ~/.tweek/installed_scopes.json.  Deduplicates by resolved path.
    """
    seen = set()
    result = []

    # Always include current project
    resolved_cwd = str(project_target.resolve())
    seen.add(resolved_cwd)
    result.append(project_target)

    # Include all recorded scopes from install-time tracking
    try:
        from tweek.cli_install import _get_installed_scopes
        for scope_str in _get_installed_scopes():
            scope = Path(scope_str)
            resolved = str(scope.resolve())
            if resolved not in seen and scope.exists():
                seen.add(resolved)
                result.append(scope)
    except (ImportError, Exception):
        pass

    return result


def _uninstall_everything(global_target: Path, project_target: Path, tweek_dir: Path, confirm: bool):
    """Full system removal of all Tweek data."""
    # Discover all project scopes (current + recorded from install)
    all_project_scopes = _get_all_project_scopes(project_target)

    console.print("[bold yellow]FULL REMOVAL[/bold yellow] \u2014 This will remove ALL Tweek data:\n")
    if len(all_project_scopes) > 1:
        console.print(f"  [white]\u2022[/white] Hooks from {len(all_project_scopes)} project(s):")
        for scope in all_project_scopes:
            console.print(f"      [white]{scope}/settings.json[/white]")
    else:
        console.print("  [white]\u2022[/white] Hooks from current project (.claude/settings.json)")
    console.print("  [white]\u2022[/white] Hooks from global installation (~/.claude/settings.json)")
    console.print("  [white]\u2022[/white] Tweek skill directories (project + global)")
    console.print("  [white]\u2022[/white] All backup files")
    console.print("  [white]\u2022[/white] .tweek.yaml control files")
    console.print("  [white]\u2022[/white] Tweek data directory (~/.tweek/) including hook wrappers")

    # Show what exists in ~/.tweek/
    if tweek_dir.exists():
        for item in sorted(tweek_dir.iterdir()):
            if item.is_dir():
                console.print(f"      [white]\u251c\u2500\u2500 {item.name}/ [/white]")
            else:
                console.print(f"      [white]\u251c\u2500\u2500 {item.name}[/white]")

    console.print("  [white]\u2022[/white] MCP integrations (Claude Desktop, ChatGPT)")
    console.print()

    if not confirm:
        console.print("[bold red]Type 'yes' to confirm full removal[/bold red]: ", end="")
        response = input()
        if response.strip().lower() != "yes":
            console.print("[white]Cancelled[/white]")
            return

    console.print()

    # ── Project scopes (current + recorded from install) ──
    for scope in all_project_scopes:
        scope_label = str(scope)
        console.print(f"[bold]Project scope ({scope_label}):[/bold]")
        removed_hooks = _remove_hooks_from_settings(scope / "settings.json")
        for hook_type in removed_hooks:
            console.print(f"  [green]\u2713[/green] Removed {hook_type} hook from {scope_label}/settings.json")
        if not removed_hooks:
            console.print(f"  [white]-[/white] Skipped: no hooks found")

        if _remove_skill_directory(scope):
            console.print(f"  [green]\u2713[/green] Removed Tweek skill directory")
        else:
            console.print(f"  [white]-[/white] Skipped: no skill directory")

        if _remove_backup_file(scope):
            console.print(f"  [green]\u2713[/green] Removed backup file")
        else:
            console.print(f"  [white]-[/white] Skipped: no backup file")

    console.print()

    # ── Global scope ──
    console.print("[bold]Global scope (~/.claude/):[/bold]")
    removed_hooks = _remove_hooks_from_settings(global_target / "settings.json")
    for hook_type in removed_hooks:
        console.print(f"  [green]\u2713[/green] Removed {hook_type} hook from global settings.json")
    if not removed_hooks:
        console.print(f"  [white]-[/white] Skipped: no global hooks found")

    if _remove_skill_directory(global_target):
        console.print(f"  [green]\u2713[/green] Removed Tweek skill from global installation")
    else:
        console.print(f"  [white]-[/white] Skipped: no global skill directory")

    if _remove_backup_file(global_target):
        console.print(f"  [green]\u2713[/green] Removed global backup file")
    else:
        console.print(f"  [white]-[/white] Skipped: no global backup file")

    console.print()

    # ── .tweek.yaml control files ──
    # Must run before data directory removal (needs installed_scopes.json)
    console.print("[bold]Control files (.tweek.yaml):[/bold]")
    yaml_removed = _remove_tweek_yaml_files(tweek_dir)
    for yaml_path in yaml_removed:
        console.print(f"  [green]\u2713[/green] Removed {yaml_path}")
    if not yaml_removed:
        console.print(f"  [white]-[/white] Skipped: no .tweek.yaml files found")

    console.print()

    # ── MCP integrations ──
    console.print("[bold]MCP integrations:[/bold]")
    mcp_removed = _remove_mcp_integrations()
    for client in mcp_removed:
        console.print(f"  [green]\u2713[/green] Removed {client} MCP integration")
    if not mcp_removed:
        console.print(f"  [white]-[/white] Skipped: no MCP integrations found")

    console.print()

    # ── Tweek data directory (last — other steps need installed_scopes.json) ──
    console.print("[bold]Tweek data (~/.tweek/):[/bold]")
    data_removed = _remove_tweek_data_dir(tweek_dir)
    for item in data_removed:
        console.print(f"  [green]\u2713[/green] Removed {item}")
    if not data_removed:
        console.print(f"  [white]-[/white] Skipped: no data directory found")

    console.print()
    console.print("[green]All Tweek data has been removed.[/green]")
