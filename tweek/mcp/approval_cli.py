#!/usr/bin/env python3
"""
Tweek MCP Approval CLI Daemon

Interactive terminal interface for reviewing and deciding on
MCP proxy approval requests. Polls the approval queue and
displays pending requests for human review.

Usage:
    tweek mcp approve                    # Start daemon (2s poll)
    tweek mcp approve --poll-interval 5  # Slower polling
    tweek mcp pending                    # One-shot listing
    tweek mcp decide <ID> approve        # One-shot decision
"""

import logging
import sys
import time
from typing import Optional

from tweek.mcp.approval import ApprovalQueue, ApprovalRequest, ApprovalStatus

logger = logging.getLogger(__name__)


def display_pending(queue: ApprovalQueue) -> int:
    """
    Display all pending approval requests as a rich table.

    Returns the number of pending requests displayed.
    """
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        return _display_pending_plain(queue)

    console = Console()
    pending = queue.get_pending()

    if not pending:
        console.print("[dim]No pending approval requests.[/dim]")
        return 0

    table = Table(title="Pending Approval Requests", show_lines=True)
    table.add_column("ID", style="cyan", width=10)
    table.add_column("Server", style="blue")
    table.add_column("Tool", style="yellow")
    table.add_column("Risk", width=10)
    table.add_column("Reason")
    table.add_column("Time Left", width=10)

    for req in pending:
        risk_style = _risk_style(req.risk_level)
        remaining = req.time_remaining
        time_str = f"{int(remaining)}s" if remaining > 0 else "[red]EXPIRED[/red]"

        table.add_row(
            req.short_id,
            req.upstream_server,
            req.tool_name,
            f"[{risk_style}]{req.risk_level}[/{risk_style}]",
            req.screening_reason[:60],
            time_str,
        )

    console.print(table)
    return len(pending)


def display_request_detail(request: ApprovalRequest):
    """Display detailed information about a single request."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text
    except ImportError:
        _display_request_plain(request)
        return

    console = Console()
    risk_style = _risk_style(request.risk_level)

    lines = [
        f"[bold]Request:[/bold]  {request.short_id}",
        f"[bold]Server:[/bold]   {request.upstream_server}",
        f"[bold]Tool:[/bold]     {request.tool_name}",
        f"[bold]Risk:[/bold]     [{risk_style}]{request.risk_level}[/{risk_style}]",
        f"[bold]Reason:[/bold]   {request.screening_reason}",
        "",
        "[bold]Arguments:[/bold]",
    ]

    # Display arguments (already redacted from queue storage)
    args = request.arguments
    for key, value in args.items():
        display_val = str(value)
        if len(display_val) > 120:
            display_val = display_val[:120] + "..."
        lines.append(f"  {key}: {display_val}")

    # Display findings
    findings = request.screening_findings
    if findings:
        lines.append("")
        lines.append("[bold]Findings:[/bold]")
        for f in findings[:5]:
            name = f.get("name", f.get("pattern", "unknown"))
            severity = f.get("severity", "")
            lines.append(f"  - {name} ({severity})")

    remaining = request.time_remaining
    if remaining > 0:
        lines.append("")
        lines.append(f"[dim]Auto-deny in {int(remaining)}s[/dim]")

    panel = Panel(
        "\n".join(lines),
        title=f"Approval Request {request.short_id}",
        border_style=risk_style,
    )
    console.print(panel)


def run_approval_daemon(
    queue: ApprovalQueue,
    poll_interval: float = 2.0,
):
    """
    Run the interactive approval daemon.

    Polls for pending requests, displays them, and prompts for decisions.
    Runs until Ctrl+C.
    """
    try:
        from rich.console import Console
    except ImportError:
        print("Error: rich library required for approval daemon", file=sys.stderr)
        return

    console = Console()
    console.print("[bold]Tweek MCP Approval Daemon[/bold]")
    console.print(f"Polling every {poll_interval}s. Press Ctrl+C to exit.\n")

    seen_ids = set()

    try:
        while True:
            pending = queue.get_pending()

            # Show new requests
            new_requests = [r for r in pending if r.id not in seen_ids]

            for req in new_requests:
                seen_ids.add(req.id)
                console.print()
                display_request_detail(req)
                console.print()

                # Prompt for decision
                decision = _prompt_decision(console, req)
                if decision == "quit":
                    console.print("[dim]Exiting approval daemon.[/dim]")
                    return
                elif decision == "skip":
                    continue
                elif decision == "approve":
                    success = queue.decide(
                        req.id, ApprovalStatus.APPROVED, decided_by="cli"
                    )
                    if success:
                        console.print(f"[green]Approved {req.short_id}[/green]")
                        _log_decision(req, "approved")
                    else:
                        console.print(
                            f"[yellow]Could not approve {req.short_id} "
                            f"(may have expired)[/yellow]"
                        )
                elif decision == "deny":
                    notes = _prompt_notes(console)
                    success = queue.decide(
                        req.id,
                        ApprovalStatus.DENIED,
                        decided_by="cli",
                        notes=notes,
                    )
                    if success:
                        console.print(f"[red]Denied {req.short_id}[/red]")
                        _log_decision(req, "denied")
                    else:
                        console.print(
                            f"[yellow]Could not deny {req.short_id} "
                            f"(may have expired)[/yellow]"
                        )

            if not new_requests and pending:
                # Still have pending but already seen them
                pass

            time.sleep(poll_interval)

    except KeyboardInterrupt:
        console.print("\n[dim]Approval daemon stopped.[/dim]")

    # Print summary
    stats = queue.get_stats()
    console.print("\n[bold]Session Summary:[/bold]")
    for status, count in stats.items():
        console.print(f"  {status}: {count}")


def decide_request(
    queue: ApprovalQueue,
    request_id: str,
    decision: str,
    notes: Optional[str] = None,
) -> bool:
    """
    Make a one-shot decision on a specific request.

    Args:
        queue: The approval queue
        request_id: Full or short ID
        decision: "approve" or "deny"
        notes: Optional decision notes

    Returns:
        True if decision was recorded successfully
    """
    request = queue.get_request(request_id)
    if request is None:
        print(f"Request '{request_id}' not found.", file=sys.stderr)
        return False

    if request.status != ApprovalStatus.PENDING:
        print(
            f"Request '{request_id}' is not pending (status: {request.status.value}).",
            file=sys.stderr,
        )
        return False

    status = ApprovalStatus.APPROVED if decision == "approve" else ApprovalStatus.DENIED
    success = queue.decide(request.id, status, decided_by="cli", notes=notes)

    if success:
        _log_decision(request, decision)

    return success


def _prompt_decision(console, request: ApprovalRequest) -> str:
    """Prompt user for a decision. Returns 'approve', 'deny', 'skip', or 'quit'."""
    while True:
        try:
            console.print(
                "[bold][A][/bold]pprove  "
                "[bold][D][/bold]eny  "
                "[bold][S][/bold]kip  "
                "[bold][Q][/bold]uit"
            )
            choice = input(f"Decision for {request.short_id}: ").strip().lower()
        except EOFError:
            return "quit"

        if choice in ("a", "approve"):
            return "approve"
        elif choice in ("d", "deny"):
            return "deny"
        elif choice in ("s", "skip"):
            return "skip"
        elif choice in ("q", "quit"):
            return "quit"
        else:
            console.print("[yellow]Invalid choice. Use A/D/S/Q.[/yellow]")


def _prompt_notes(console) -> Optional[str]:
    """Prompt for optional denial notes."""
    try:
        notes = input("Notes (optional, press Enter to skip): ").strip()
        return notes if notes else None
    except EOFError:
        return None


def _risk_style(risk_level: str) -> str:
    """Return a rich style string for a risk level."""
    styles = {
        "safe": "green",
        "default": "blue",
        "risky": "yellow",
        "dangerous": "red bold",
    }
    return styles.get(risk_level, "white")


def _log_decision(request: ApprovalRequest, decision: str):
    """Log an approval decision to SecurityLogger."""
    try:
        from tweek.logging.security_log import (
            SecurityLogger,
            SecurityEvent,
            EventType,
            get_logger,
        )

        evt = EventType.USER_APPROVED if decision == "approved" else EventType.USER_DENIED

        sec_logger = get_logger()
        sec_logger.log(SecurityEvent(
            event_type=evt,
            tool_name=request.tool_name,
            decision=decision,
            decision_reason=request.screening_reason,
            user_response=decision,
            metadata={
                "source": "mcp_proxy_approval_cli",
                "upstream_server": request.upstream_server,
                "request_id": request.id,
                "risk_level": request.risk_level,
            },
        ))
    except Exception as e:
        logger.debug(f"Failed to log approval decision: {e}")


def _display_pending_plain(queue: ApprovalQueue) -> int:
    """Fallback plain-text display when rich is unavailable."""
    pending = queue.get_pending()
    if not pending:
        print("No pending approval requests.")
        return 0

    print(f"\nPending Approval Requests ({len(pending)}):")
    print("-" * 70)
    for req in pending:
        remaining = req.time_remaining
        time_str = f"{int(remaining)}s" if remaining > 0 else "EXPIRED"
        print(
            f"  [{req.short_id}] {req.upstream_server}/{req.tool_name} "
            f"({req.risk_level}) - {time_str} remaining"
        )
        print(f"    Reason: {req.screening_reason[:60]}")
    print()
    return len(pending)


def _display_request_plain(request: ApprovalRequest):
    """Fallback plain-text display for a single request."""
    print(f"\nRequest: {request.short_id}")
    print(f"  Server: {request.upstream_server}")
    print(f"  Tool:   {request.tool_name}")
    print(f"  Risk:   {request.risk_level}")
    print(f"  Reason: {request.screening_reason}")
    remaining = request.time_remaining
    print(f"  Time:   {int(remaining)}s remaining")
