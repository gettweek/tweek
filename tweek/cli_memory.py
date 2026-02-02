"""CLI commands for agentic memory management.

Extracted from cli.py to keep the main CLI module manageable.
Groups:
    memory_group  -- status, patterns, sources, suggestions, accept,
                     reject, baseline, audit, clear, export, decay
"""

import json
from pathlib import Path
from typing import Optional

import click
from rich.table import Table

from tweek.cli_helpers import console

# =========================================================================
# Memory commands
# =========================================================================


@click.group("memory")
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
        console.print("  Last decay: [white]never[/white]")

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
        console.print("[white]No pattern decision data recorded yet.[/white]")
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
            p.get("path_prefix") or "[white]-[/white]",
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
        console.print("[white]No source trust data recorded yet.[/white]")
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
        console.print("[white]No whitelist suggestions available.[/white]")
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
            s.tool_name or "[white]-[/white]",
            s.path_prefix or "[white]-[/white]",
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
        console.print("  [white]Note: To apply to overrides.yaml, manually add the whitelist rule.[/white]")
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
        console.print("[white]No workflow baseline data for this project.[/white]")
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
            str(b.hour_of_day) if b.hour_of_day is not None else "[white]-[/white]",
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
        console.print("[white]No audit entries.[/white]")
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
            console.print("[white]Cancelled.[/white]")
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
