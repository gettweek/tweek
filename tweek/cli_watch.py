#!/usr/bin/env python3
"""
Tweek CLI — watch command group

File integrity monitoring for critical Tweek security files.
Detects unauthorized modifications to settings.json, hook scripts,
and configuration files that could disable Tweek protection.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

from tweek.cli_helpers import console


@click.group()
def watch():
    """File integrity monitoring for critical security files.

    Detects unauthorized modifications to settings.json, hook scripts,
    and configuration files that could disable Tweek protection.
    """
    pass


@watch.command("init")
@click.option("--force", is_flag=True, help="Overwrite existing baselines")
@click.option("--no-project", is_flag=True, help="Skip project-level files")
def watch_init(force: bool, no_project: bool):
    """Create baseline hashes for all watched files.

    Run this after `tweek protect` to establish the known-good
    state of your security configuration.
    """
    from tweek.security.file_watch import FileIntegrityMonitor

    monitor = FileIntegrityMonitor()
    existing = monitor.load_baselines()

    if existing and not force:
        console.print(
            f"[yellow]Baselines already exist ({len(existing)} files). "
            f"Use --force to overwrite.[/yellow]"
        )
        return

    created, skipped = monitor.init_baselines(
        include_project=not no_project, force=force,
    )
    console.print(f"[green]\u2713[/green] Baselines created: {created} files monitored")
    if skipped:
        console.print(f"[dim]  {skipped} files skipped (not found or symlink)[/dim]")


@watch.command("check")
@click.option("--json", "json_out", is_flag=True, help="Output as JSON")
@click.option("--quiet", "-q", is_flag=True, help="Only output if drift detected")
def watch_check(json_out: bool, quiet: bool):
    """Verify all watched files against their baselines.

    Exit code 0 if clean, 1 if drift detected.
    """
    from tweek.security.file_watch import DriftStatus, FileIntegrityMonitor

    monitor = FileIntegrityMonitor()
    baselines = monitor.load_baselines()

    if not baselines:
        if not quiet:
            console.print(
                "[yellow]No baselines configured. "
                "Run: tweek watch init[/yellow]"
            )
        return

    report = monitor.check_integrity()

    # Log violations
    for result in report.results:
        if result.status != DriftStatus.OK:
            _log_violation(result)

    if json_out:
        import json as json_mod
        data = {
            "clean": report.is_clean,
            "total": report.total_files,
            "ok": report.ok_count,
            "modified": report.modified_count,
            "missing": report.missing_count,
            "files": [
                {
                    "path": r.path,
                    "status": r.status.value,
                    "policy": r.policy.value,
                    "label": r.label,
                }
                for r in report.results
            ],
        }
        click.echo(json_mod.dumps(data, indent=2))
        if not report.is_clean:
            sys.exit(1)
        return

    if report.is_clean:
        if not quiet:
            console.print(
                f"[green]\u2713[/green] All {report.ok_count} watched files verified"
            )
        return

    # Show drift details
    from rich.table import Table

    table = Table(title="File Integrity Check")
    table.add_column("Status", justify="center", width=10)
    table.add_column("Policy", width=8)
    table.add_column("Label")
    table.add_column("Path")

    for r in report.results:
        if r.status == DriftStatus.OK:
            status_str = "[green]OK[/green]"
        elif r.status == DriftStatus.MODIFIED:
            status_str = "[red]MODIFIED[/red]"
        else:
            status_str = "[red]MISSING[/red]"

        policy_str = (
            "[cyan]restore[/cyan]"
            if r.policy.value == "restore"
            else "[dim]alert[/dim]"
        )
        table.add_row(status_str, policy_str, r.label, r.path)

    console.print(table)
    console.print(
        f"\n[red]{report.modified_count} modified, "
        f"{report.missing_count} missing[/red] out of {report.total_files} files"
    )
    console.print("[dim]Run: tweek watch diff <path>  to see changes[/dim]")
    sys.exit(1)


@watch.command("status")
def watch_status():
    """Show current baseline inventory."""
    from tweek.security.file_watch import FileIntegrityMonitor

    monitor = FileIntegrityMonitor()
    baselines = monitor.load_baselines()

    if not baselines:
        console.print(
            "[yellow]No baselines configured. "
            "Run: tweek watch init[/yellow]"
        )
        return

    from rich.table import Table

    table = Table(title="Watched Files")
    table.add_column("Label")
    table.add_column("Policy", width=8)
    table.add_column("SHA-256", width=16)
    table.add_column("Size")
    table.add_column("Updated")

    for _key, entry in baselines.items():
        size_str = _format_size(entry.size)
        table.add_row(
            entry.label or entry.path,
            entry.policy,
            entry.sha256[:16] + "...",
            size_str,
            entry.updated_at[:19],
        )

    console.print(table)
    console.print(f"[dim]{len(baselines)} file(s) monitored[/dim]")


@watch.command("approve")
@click.argument("file_path", required=False)
@click.option("--all", "approve_all_flag", is_flag=True, help="Approve all drifted files")
def watch_approve(file_path: Optional[str], approve_all_flag: bool):
    """Accept the current state of a drifted file as the new baseline.

    Use when you intentionally changed a watched file.
    """
    from tweek.security.file_watch import FileIntegrityMonitor

    monitor = FileIntegrityMonitor()

    if approve_all_flag:
        count = monitor.approve_all()
        if count:
            console.print(f"[green]\u2713[/green] Approved {count} drifted file(s)")
            _log_approve("all")
        else:
            console.print("[dim]No drifted files to approve[/dim]")
        return

    if not file_path:
        console.print("[red]Specify a file path or use --all[/red]")
        sys.exit(1)

    # Resolve the path for lookup
    resolved = str(Path(file_path).expanduser().resolve())
    if monitor.approve_file(resolved):
        console.print(f"[green]\u2713[/green] Approved: {resolved}")
        _log_approve(resolved)
    else:
        console.print(f"[red]File not in baselines or not found: {file_path}[/red]")
        sys.exit(1)


@watch.command("diff")
@click.argument("file_path")
def watch_diff(file_path: str):
    """Show what changed between baseline and current state."""
    from tweek.security.file_watch import FileIntegrityMonitor

    monitor = FileIntegrityMonitor()
    resolved = str(Path(file_path).expanduser().resolve())
    diff = monitor.diff_file(resolved)

    if diff is None:
        console.print(f"[red]File not in baselines: {file_path}[/red]")
        sys.exit(1)

    from rich.syntax import Syntax

    console.print(Syntax(diff, "diff", theme="monokai"))


@watch.command("restore")
@click.argument("file_path")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation prompt")
def watch_restore(file_path: str, yes: bool):
    """Restore a drifted file from its backup.

    The current file is quarantined to ~/.tweek/quarantine/ before replacement.
    Only works for files with 'restore' policy (settings.json, hook scripts).
    """
    from tweek.security.file_watch import FileIntegrityMonitor

    monitor = FileIntegrityMonitor()
    resolved = str(Path(file_path).expanduser().resolve())

    if not yes:
        if not click.confirm(f"Restore {resolved} from backup?"):
            return

    success, msg = monitor.restore_file(resolved)
    if success:
        console.print(f"[green]\u2713[/green] {msg}")
        _log_restore(resolved)
    else:
        console.print(f"[red]\u2717 {msg}[/red]")
        sys.exit(1)


# --- Helpers ---


def _format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


def _log_violation(result):
    """Log a file integrity violation event."""
    try:
        from tweek.logging.security_log import EventType, SecurityEvent, get_logger

        get_logger().log(SecurityEvent(
            event_type=EventType.FILE_INTEGRITY_VIOLATION,
            tool_name="file_watch",
            decision="alert",
            metadata={
                "file_path": result.path,
                "label": result.label,
                "status": result.status.value,
                "policy": result.policy.value,
                "baseline_sha256": result.baseline_sha256,
                "current_sha256": result.current_sha256,
            },
            source="file_watch",
        ))
    except Exception:
        pass


def _log_approve(file_path: str):
    """Log a file integrity approve event."""
    try:
        from tweek.logging.security_log import EventType, SecurityEvent, get_logger

        get_logger().log(SecurityEvent(
            event_type=EventType.FILE_INTEGRITY_APPROVE,
            tool_name="file_watch",
            decision="allow",
            metadata={"file_path": file_path},
            source="file_watch",
        ))
    except Exception:
        pass


def _log_restore(file_path: str):
    """Log a file integrity restore event."""
    try:
        from tweek.logging.security_log import EventType, SecurityEvent, get_logger

        get_logger().log(SecurityEvent(
            event_type=EventType.FILE_INTEGRITY_RESTORE,
            tool_name="file_watch",
            decision="block",
            metadata={"file_path": file_path},
            source="file_watch",
        ))
    except Exception:
        pass
