#!/usr/bin/env python3
"""
Tweek CLI Helpers

Shared formatting utilities for consistent CLI output across all commands.
Provides colored status messages, health banners, command example formatting,
and progress spinners.
"""

import json
import shutil
from contextlib import contextmanager
from pathlib import Path
from typing import List, Tuple

import click

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Single shared Console instance for the entire CLI
console = Console()


def print_success(message: str) -> None:
    """Print a success message with green checkmark."""
    console.print(f"[green]\u2713[/green] {message}")


def print_warning(message: str) -> None:
    """Print a warning message with yellow triangle."""
    console.print(f"[yellow]\u26a0[/yellow]  {message}")


def print_error(message: str, fix_hint: str = "") -> None:
    """Print an error message with red X and optional fix hint."""
    console.print(f"[red]\u2717[/red] {message}")
    if fix_hint:
        console.print(f"  [white]Hint: {fix_hint}[/white]")


def print_health_banner(checks: "List") -> None:
    """
    Print a compact health verdict banner as a Rich Panel.

    Args:
        checks: List of HealthCheck results from run_health_checks().
    """
    from tweek.diagnostics import get_health_verdict, CheckStatus

    verdict_text, color = get_health_verdict(checks)

    ok_count = sum(1 for c in checks if c.status == CheckStatus.OK)
    total_non_skip = sum(1 for c in checks if c.status != CheckStatus.SKIPPED)

    panel = Panel(
        f"[bold {color}]{verdict_text}[/bold {color}]\n"
        f"[white]Run 'tweek doctor' for details[/white]",
        border_style=color,
        padding=(0, 2),
    )
    console.print(panel)


def format_command_example(command: str, description: str) -> str:
    """
    Format a single command example line.

    Args:
        command: The command string, e.g., "tweek protect claude-code --scope global"
        description: Brief explanation of what it does.

    Returns:
        Formatted string like "  tweek protect claude-code --scope global    Install globally"
    """
    return f"  {command:<40s} {description}"


def build_examples_epilog(examples: List[Tuple[str, str]]) -> str:
    """
    Build a formatted epilog string with command examples.

    Args:
        examples: List of (command, description) tuples.

    Returns:
        Multi-line string suitable for Click's epilog parameter.
    """
    lines = ["\nExamples:"]
    for cmd, desc in examples:
        lines.append(format_command_example(cmd, desc))
    return "\n".join(lines) + "\n"


@contextmanager
def spinner(message: str):
    """
    Context manager for showing a Rich spinner during long operations.

    Usage:
        with spinner("Installing hooks"):
            do_slow_work()

    Args:
        message: Text to display next to the spinner.
    """
    with console.status(f"[bold cyan]{message}...", spinner="dots"):
        yield


def format_tier_color(tier_value: str) -> str:
    """
    Return a Rich-markup colored string for a security tier value.

    Args:
        tier_value: One of "safe", "default", "risky", "dangerous".

    Returns:
        Rich-markup string with appropriate color.
    """
    colors = {
        "safe": "green",
        "default": "white",
        "risky": "yellow",
        "dangerous": "red",
    }
    color = colors.get(tier_value.lower(), "white")
    return f"[{color}]{tier_value}[/{color}]"


def print_doctor_results(checks: "List") -> None:
    """
    Print full doctor output with all check results.

    Args:
        checks: List of HealthCheck results from run_health_checks().
    """
    from tweek.diagnostics import get_health_verdict, CheckStatus

    console.print()
    console.print("[bold]Tweek Health Check[/bold]")
    console.print("\u2500" * 50)

    status_styles = {
        CheckStatus.OK: ("[green]OK[/green]    ", "green"),
        CheckStatus.WARNING: ("[yellow]WARN[/yellow]  ", "yellow"),
        CheckStatus.ERROR: ("[red]ERROR[/red] ", "red"),
        CheckStatus.SKIPPED: ("[white]SKIP[/white]  ", "white"),
    }

    for check in checks:
        style_text, _ = status_styles.get(check.status, ("[white]???[/white]   ", "white"))
        console.print(f"  {style_text}  {check.label:<22s} {check.message}")

    # Verdict
    verdict_text, color = get_health_verdict(checks)
    console.print()
    console.print(f"  [bold {color}]Verdict: {verdict_text}[/bold {color}]")

    # Fix hints for non-OK checks
    fixable = [c for c in checks if c.fix_hint and c.status in (CheckStatus.ERROR, CheckStatus.WARNING)]
    if fixable:
        console.print()
        console.print("  [bold]Suggested fixes:[/bold]")
        for check in fixable:
            console.print(f"    {check.label}: {check.fix_hint}")

    console.print()


def print_doctor_json(checks: "List") -> None:
    """
    Print doctor results as JSON for machine consumption.

    Args:
        checks: List of HealthCheck results from run_health_checks().
    """
    import json
    from tweek.diagnostics import get_health_verdict

    verdict_text, _ = get_health_verdict(checks)

    output = {
        "verdict": verdict_text,
        "checks": [
            {
                "name": c.name,
                "label": c.label,
                "status": c.status.value,
                "message": c.message,
                "fix_hint": c.fix_hint or None,
            }
            for c in checks
        ],
    }

    console.print_json(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# Cross-module constants and helpers
# ---------------------------------------------------------------------------

TWEEK_BANNER = """
 ████████╗██╗    ██╗███████╗███████╗██╗  ██╗
 ╚══██╔══╝██║    ██║██╔════╝██╔════╝██║ ██╔╝
    ██║   ██║ █╗ ██║█████╗  █████╗  █████╔╝
    ██║   ██║███╗██║██╔══╝  ██╔══╝  ██╔═██╗
    ██║   ╚███╔███╔╝███████╗███████╗██║  ██╗
    ╚═╝    ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝

  GAH! Security for AI agents
  "Because paranoia is a feature, not a bug"
"""


def _has_tweek_hooks(settings: dict) -> bool:
    """Check if a settings dict contains Tweek hooks."""
    hooks = settings.get("hooks", {})
    for hook_type in ("PreToolUse", "PostToolUse"):
        for hook_config in hooks.get(hook_type, []):
            for hook in hook_config.get("hooks", []):
                if "tweek" in hook.get("command", "").lower():
                    return True
    return False


def _has_tweek_at(target: Path) -> bool:
    """Check if Tweek is installed at a .claude/ target path."""
    import json

    if (target / "skills" / "tweek").exists():
        return True
    if (target / "settings.json.tweek-backup").exists():
        return True
    settings_file = target / "settings.json"
    if settings_file.exists():
        try:
            with open(settings_file) as f:
                settings = json.load(f)
            if _has_tweek_hooks(settings):
                return True
        except (json.JSONDecodeError, IOError):
            pass
    return False


def _detect_all_tools():
    """Detect all supported AI tools and their protection status.

    Returns list of (tool_id, label, installed, protected, detail) tuples.
    """
    import shutil
    import json

    tools = []

    # Claude Code
    claude_installed = shutil.which("claude") is not None
    claude_protected = _has_tweek_at(Path("~/.claude").expanduser()) if claude_installed else False
    tools.append((
        "claude-code", "Claude Code", claude_installed, claude_protected,
        "Hooks in ~/.claude/settings.json" if claude_protected else "",
    ))

    # OpenClaw
    oc_installed = False
    oc_protected = False
    oc_detail = ""
    try:
        from tweek.integrations.openclaw import detect_openclaw_installation
        openclaw = detect_openclaw_installation()
        oc_installed = openclaw.get("installed", False)
        if oc_installed:
            oc_protected = openclaw.get("tweek_configured", False)
            oc_detail = f"Gateway port {openclaw.get('gateway_port', '?')}"
    except Exception:
        pass
    tools.append(("openclaw", "OpenClaw", oc_installed, oc_protected, oc_detail))

    # MCP clients
    mcp_configs = [
        ("claude-desktop", "Claude Desktop",
         Path("~/Library/Application Support/Claude/claude_desktop_config.json").expanduser()),
        ("chatgpt", "ChatGPT Desktop",
         Path("~/Library/Application Support/com.openai.chat/developer_settings.json").expanduser()),
        ("gemini", "Gemini CLI",
         Path("~/.gemini/settings.json").expanduser()),
    ]
    for tool_id, label, config_path in mcp_configs:
        installed = config_path.exists()
        protected = False
        if installed:
            try:
                with open(config_path) as f:
                    data = json.load(f)
                mcp_servers = data.get("mcpServers", {})
                protected = "tweek-security" in mcp_servers or "tweek" in mcp_servers
            except Exception:
                pass
        detail = str(config_path) if protected else ""
        tools.append((tool_id, label, installed, protected, detail))

    return tools


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
