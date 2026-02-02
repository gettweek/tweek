"""CLI commands for break-glass overrides and false-positive feedback.

Extracted from cli.py to keep the main CLI module manageable.
Groups:
    override_group  -- break-glass override create / list / clear
    feedback_group  -- false-positive reporting, stats, reset
"""

import sys
from typing import Optional

import click
from rich.table import Table

from tweek.cli_helpers import console

# =========================================================================
# BREAK-GLASS OVERRIDE COMMANDS
# =========================================================================


@click.group("override")
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
    console.print("[white]Next time this pattern triggers, you'll see an 'ask' prompt instead of a hard block.[/white]")


@override_group.command("list")
def override_list():
    """List all break-glass overrides (active and historical)."""
    from tweek.hooks.break_glass import list_overrides, list_active_overrides

    all_overrides = list_overrides()
    active = list_active_overrides()
    active_patterns = {o["pattern"] for o in active}

    if not all_overrides:
        console.print("[white]No break-glass overrides found.[/white]")
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
            status = "[white]consumed[/white]"
        else:
            status = "[white]expired[/white]"

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


@click.group("feedback")
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
        console.print("[white]No feedback data recorded yet.[/white]")
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
        console.print(f"[white]No feedback data found for '{pattern_name}'.[/white]")
