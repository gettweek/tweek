#!/usr/bin/env python3
"""
Tweek CLI — Logs command group.

Extracted from cli.py to keep the main CLI module manageable.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import click

from rich.panel import Panel
from rich.table import Table

from tweek.cli_helpers import console, TWEEK_BANNER


# ============================================================
# LOGS COMMANDS
# ============================================================

@click.group()
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

            severity_styles = {"critical": "red", "high": "yellow", "medium": "blue", "low": "white"}
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
                console.print(f"[white]Valid types: {', '.join(e.value for e in EventType)}[/white]")
                return

        events = logger.get_recent_events(limit=limit, event_type=et, tool_name=tool)
        title = "Recent Security Events"

    if not events:
        console.print("[yellow]No events found[/yellow]")
        return

    table = Table(title=title)
    table.add_column("Time", style="white")
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
    console.print(f"\n[white]Showing {len(events)} events. Use --limit to see more.[/white]")


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
        console.print(f"[green]\u2713[/green] Exported {count} events to {output_path}")
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

        console.print(f"[yellow]{msg}[/yellow] ", end="")
        if not click.confirm(""):
            console.print("[white]Cancelled[/white]")
            return

    logger = get_logger()
    deleted = logger.delete_events(days=days)

    if deleted > 0:
        if days:
            console.print(f"[green]Cleared {deleted} event(s) older than {days} days[/green]")
        else:
            console.print(f"[green]Cleared {deleted} event(s)[/green]")
    else:
        console.print("[white]No events to clear[/white]")


@logs.command("verify",
    epilog="""\b
Examples:
  tweek logs verify                      Verify audit log hash chain integrity
  tweek logs verify --json               Output results as JSON
  tweek logs verify --quiet              Only output if chain is broken (for CI)
"""
)
@click.option("--json", "json_out", is_flag=True, help="Output as JSON")
@click.option("--quiet", "-q", is_flag=True, help="Only output if chain is broken")
def logs_verify(json_out: bool, quiet: bool):
    """Verify the integrity of the audit log hash chain.

    Each log entry contains a SHA-256 hash that chains from the previous
    entry. This command walks the entire chain and detects:

    - Tampered entries (hash mismatch)
    - Deleted entries (chain gaps)
    - Legacy entries (pre-chain, no hash)

    Exit code 0 if chain is intact, 1 if tampering detected.
    """
    import sys

    from tweek.logging.security_log import get_logger

    logger = get_logger()
    result = logger.verify_chain()

    if json_out:
        import json as json_mod
        click.echo(json_mod.dumps(result, indent=2))
        if not result["valid"]:
            sys.exit(1)
        return

    if result["total"] == 0:
        if not quiet:
            console.print("[yellow]No log entries to verify[/yellow]")
        return

    if result["valid"]:
        if not quiet:
            console.print(
                f"[green]\u2713[/green] Audit log chain verified: "
                f"{result['verified']} entries intact"
            )
            if result["unchained"] > 0:
                console.print(
                    f"[dim]  {result['unchained']} legacy entries "
                    f"(pre-chain, no hash)[/dim]"
                )
        return

    # Chain is broken — show details
    console.print(
        f"[red]\u2717 Audit log chain BROKEN[/red] at entry #{result['broken_at']}"
    )
    console.print(
        f"  {result['verified']} verified, "
        f"{len(result['errors'])} tampered, "
        f"{result['unchained']} unchained "
        f"out of {result['total']} total"
    )

    if result["errors"]:
        error_table = Table(title="Tampered Entries")
        error_table.add_column("ID", justify="right")
        error_table.add_column("Timestamp")
        error_table.add_column("Event Type")
        error_table.add_column("Expected Hash")
        error_table.add_column("Stored Hash")

        for err in result["errors"][:20]:  # Cap display at 20
            error_table.add_row(
                str(err["id"]),
                err["timestamp"],
                err["event_type"],
                err["expected_hash"],
                err["stored_hash"],
            )

        console.print(error_table)

        if len(result["errors"]) > 20:
            console.print(
                f"[dim]  ... and {len(result['errors']) - 20} more[/dim]"
            )

    sys.exit(1)


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
                console.print(f"  [white]  SKIP  {name} ({status})[/white]")
            else:
                console.print(f"  [green]  ADD   {name}{size_str}[/green]")
        console.print()
        console.print("[white]No files will be collected in dry-run mode.[/white]")
        return

    # Determine output path
    if not output:
        ts = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        output = f"tweek_diagnostic_bundle_{ts}.zip"

    output_path = Path(output)

    console.print("[bold]Creating diagnostic bundle...[/bold]")

    try:
        result = collector.create_bundle(output_path)
        size = result.stat().st_size
        console.print(f"\n[green]Bundle created: {result}[/green]")
        console.print(f"[white]Size: {size:,} bytes[/white]")
        if not no_redact:
            console.print("[white]Sensitive data has been redacted.[/white]")
        console.print(f"\n[bold]Send this file to Tweek support for analysis.[/bold]")
    except Exception as e:
        console.print(f"[red]Failed to create bundle: {e}[/red]")
