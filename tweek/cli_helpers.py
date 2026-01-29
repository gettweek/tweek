#!/usr/bin/env python3
"""
Tweek CLI Helpers

Shared formatting utilities for consistent CLI output across all commands.
Provides colored status messages, health banners, command example formatting,
and progress spinners.
"""

from contextlib import contextmanager
from typing import List, Tuple

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
        console.print(f"  [dim]Hint: {fix_hint}[/dim]")


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
        f"[dim]Run 'tweek doctor' for details[/dim]",
        border_style=color,
        padding=(0, 2),
    )
    console.print(panel)


def format_command_example(command: str, description: str) -> str:
    """
    Format a single command example line.

    Args:
        command: The command string, e.g., "tweek install --scope global"
        description: Brief explanation of what it does.

    Returns:
        Formatted string like "  tweek install --scope global    Install globally"
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
        CheckStatus.SKIPPED: ("[dim]SKIP[/dim]  ", "dim"),
    }

    for check in checks:
        style_text, _ = status_styles.get(check.status, ("[dim]???[/dim]   ", "dim"))
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
