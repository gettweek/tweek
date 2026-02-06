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
    console.print("\u2500" * 70)

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


def _tweek_install_info(target: Path) -> dict:
    """Get detailed Tweek installation info for a .claude/ directory.

    Returns dict with:
        has_hooks: bool  – Actual hooks in settings.json (functional protection).
        has_skill: bool  – Tweek skill directory exists.
        has_backup: bool – settings.json.tweek-backup exists.
        is_protected: bool – has_hooks (actual protection active).
        has_artifacts: bool – has_skill or has_backup (Tweek touched this dir).
    """
    import json

    info = {
        "has_hooks": False,
        "has_skill": (target / "skills" / "tweek").exists(),
        "has_backup": (target / "settings.json.tweek-backup").exists(),
    }

    settings_file = target / "settings.json"
    if settings_file.exists():
        try:
            with open(settings_file) as f:
                settings = json.load(f)
            info["has_hooks"] = _has_tweek_hooks(settings)
        except (json.JSONDecodeError, IOError):
            pass

    info["is_protected"] = info["has_hooks"]
    info["has_artifacts"] = info["has_skill"] or info["has_backup"]
    return info


def _has_tweek_at(target: Path) -> bool:
    """Check if Tweek is installed at a .claude/ target path."""
    info = _tweek_install_info(target)
    return info["is_protected"] or info["has_artifacts"]


def _detect_all_tools():
    """Detect all supported AI tools and their protection status.

    Returns list of (tool_id, label, installed, protected, detail) tuples.
    """
    import shutil
    import json

    tools = []

    # Claude Code — two rows: global (~/.claude) and project (./.claude)
    claude_installed = shutil.which("claude") is not None

    global_info = _tweek_install_info(Path("~/.claude").expanduser()) if claude_installed else {}
    project_info = _tweek_install_info(Path.cwd() / ".claude") if claude_installed else {}

    # Global row
    g_protected = global_info.get("is_protected", False)
    g_detail = ""
    if g_protected:
        g_detail = "Hooks in ~/.claude/settings.json"
    elif global_info.get("has_artifacts"):
        g_detail = "Tweek files in ~/.claude but hooks missing"
    tools.append((
        "claude-code-global", "Claude Code (global)", claude_installed, g_protected,
        g_detail,
    ))

    # Project row — show the actual directory path
    cwd = Path.cwd()
    project_label = f"Claude Code ({cwd})"
    p_protected = project_info.get("is_protected", False)
    p_detail = ""
    if p_protected:
        p_detail = "Hooks in ./.claude/settings.json"
    elif project_info.get("has_artifacts"):
        p_detail = "Tweek files in ./.claude but hooks missing"
    tools.append((
        "claude-code-project", project_label, claude_installed, p_protected,
        p_detail,
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


# ---------------------------------------------------------------------------
# TieredGroup — progressive disclosure for CLI help
# ---------------------------------------------------------------------------

# Command tiers: shown in order in default --help output.
# Commands not listed here go into "All other commands" (compressed).
COMMAND_TIERS = {
    "Getting Started": [
        "protect",
        "status",
        "doctor",
        "update",
        "configure",
    ],
    "Security & Trust": [
        "trust",
        "untrust",
        "config",
        "audit",
    ],
}

# All commands that appear in an explicit tier above
_TIERED_COMMANDS = {cmd for cmds in COMMAND_TIERS.values() for cmd in cmds}


class TieredGroup(click.Group):
    """A Click Group that displays commands in tiered categories.

    Default ``--help`` shows core commands with full descriptions and
    compresses remaining commands into a single line.  Pass ``--help-all``
    to see every command with its description, grouped by category.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.params.append(
            click.Option(
                ["--help-all"],
                is_flag=True,
                expose_value=False,
                is_eager=True,
                callback=self._show_help_all,
                help="Show all commands with full descriptions.",
            )
        )

    def _show_help_all(self, ctx, _param, value):
        if not value:
            return
        # Build the full categorised help text and print it
        formatter = ctx.make_formatter()
        self.format_usage(ctx, formatter)
        self.format_help_text(ctx, formatter)
        self._format_all_commands(ctx, formatter)
        formatter.write("\n")
        click.echo(formatter.getvalue().rstrip("\n"))
        ctx.exit(0)

    # -- default help (tiered) ------------------------------------------------

    def format_commands(self, ctx, formatter):
        """Override: render tiered command list instead of flat alphabetical."""
        commands = self._sorted_commands(ctx)
        if not commands:
            return

        cmd_map = {name: cmd for name, cmd in commands}
        max_len = max(len(name) for name, _ in commands)

        # Tier 1+2: explicit categories with full descriptions
        for tier_name, tier_cmds in COMMAND_TIERS.items():
            rows = []
            for name in tier_cmds:
                cmd = cmd_map.get(name)
                if cmd is None:
                    continue
                help_text = cmd.get_short_help_str(limit=150)
                rows.append((name, help_text))
            if rows:
                with formatter.section(tier_name):
                    formatter.write_dl(rows)

        # Remaining: compressed into a single line
        other_names = [name for name, _ in commands if name not in _TIERED_COMMANDS]
        if other_names:
            with formatter.section("All other commands"):
                # Wrap the names at ~60 chars per line for readability
                lines = _wrap_names(other_names, width=60)
                for line in lines:
                    formatter.write(f"  {line}\n")

            formatter.write(
                "\n  Run 'tweek <command> --help' for details on any command.\n"
                "  Run 'tweek --help-all' for the full command list.\n"
            )

    # -- --help-all output (full categorised) ---------------------------------

    _FULL_TIERS = {
        **COMMAND_TIERS,
        "Diagnostics": [
            "logs",
            "feedback",
            "override",
        ],
        "Infrastructure": [
            "vault",
            "proxy",
            "mcp",
            "plugins",
            "skills",
            "dry-run",
            "memory",
            "model",
        ],
        "Lifecycle": [
            "install",
            "uninstall",
            "unprotect",
            "license",
        ],
    }

    def _format_all_commands(self, ctx, formatter):
        """Render every command grouped into categories."""
        commands = self._sorted_commands(ctx)
        if not commands:
            return
        cmd_map = {name: cmd for name, cmd in commands}
        shown = set()

        for tier_name, tier_cmds in self._FULL_TIERS.items():
            rows = []
            for name in tier_cmds:
                cmd = cmd_map.get(name)
                if cmd is None:
                    continue
                rows.append((name, cmd.get_short_help_str(limit=150)))
                shown.add(name)
            if rows:
                with formatter.section(tier_name):
                    formatter.write_dl(rows)

        # Catch-all for anything not in _FULL_TIERS (future-proofing)
        leftover = [(n, c.get_short_help_str(limit=150))
                     for n, c in commands if n not in shown]
        if leftover:
            with formatter.section("Other"):
                formatter.write_dl(leftover)

    # -- helpers --------------------------------------------------------------

    def _sorted_commands(self, ctx):
        """Return (name, command) pairs sorted alphabetically, skipping hidden."""
        source = self.list_commands(ctx)
        pairs = []
        for name in source:
            cmd = self.get_command(ctx, name)
            if cmd is None or cmd.hidden:
                continue
            pairs.append((name, cmd))
        return pairs


def _wrap_names(names, width=60):
    """Wrap a list of command names into lines of roughly *width* chars."""
    lines = []
    current = ""
    for name in names:
        candidate = f"{current}, {name}" if current else name
        if len(candidate) > width and current:
            lines.append(current)
            current = name
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines


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
