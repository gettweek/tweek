#!/usr/bin/env python3
"""
Tweek CLI — pii command group

PII tokenization management: status, cleanup, and testing.
"""
from __future__ import annotations

import sys
from pathlib import Path

import click

from tweek.cli_helpers import console


def _get_store():
    """Get the default TokenStore instance."""
    from tweek.security.token_store import TokenStore

    return TokenStore()


@click.group()
def pii():
    """PII tokenization management.

    Manage the reversible PII token store used to protect
    sensitive data (SSN, credit cards, etc.) during AI sessions.
    """
    pass


@pii.command("status")
@click.option("--json", "json_out", is_flag=True, help="Output as JSON")
def pii_status(json_out: bool):
    """Show PII token store statistics.

    Displays the number of stored tokens, active sessions,
    and database size.
    """
    store = _get_store()
    stats = store.get_stats()
    store.close()

    if json_out:
        import json

        click.echo(json.dumps(stats, indent=2))
        return

    console.print("[bold]PII Token Store[/bold]")
    console.print(f"  Tokens:    {stats['total_tokens']}")
    console.print(f"  Sessions:  {stats['active_sessions']}")

    # Format DB size
    size = stats["db_size_bytes"]
    if size > 1024 * 1024:
        size_str = f"{size / (1024 * 1024):.1f} MB"
    elif size > 1024:
        size_str = f"{size / 1024:.1f} KB"
    else:
        size_str = f"{size} B"
    console.print(f"  DB size:   {size_str}")

    if stats["oldest_token"]:
        console.print(f"  Oldest:    {stats['oldest_token'][:19]}")

    # Check detection backend
    try:
        from tweek.security.pii_tokenizer import _check_presidio

        if _check_presidio():
            console.print("  Backend:   [green]Presidio (NLP)[/green]")
        else:
            console.print("  Backend:   [yellow]Regex fallback[/yellow]")
    except Exception:
        console.print("  Backend:   [dim]unknown[/dim]")


@pii.command("cleanup")
@click.option("--all", "clean_all", is_flag=True, help="Remove ALL tokens (not just expired)")
def pii_cleanup(clean_all: bool):
    """Remove expired PII tokens.

    By default, only removes tokens past their TTL.
    Use --all to wipe the entire token store.
    """
    store = _get_store()

    if clean_all:
        deleted = store.clear_all()
        console.print(f"[green]\u2713[/green] Cleared all {deleted} token(s)")
    else:
        deleted = store.cleanup_expired()
        console.print(f"[green]\u2713[/green] Removed {deleted} expired token(s)")

    store.close()


@pii.command("test")
@click.argument("text")
def pii_test(text: str):
    """Tokenize sample text to preview PII detection.

    Shows what PII would be detected and how it would be
    replaced with tokens. Does not persist any tokens.

    Example:
        tweek pii test "My SSN is 123-45-6789"
    """
    from tweek.security.pii_tokenizer import PIITokenizer, _check_presidio

    store = _get_store()
    tokenizer = PIITokenizer(
        store=store,
        session_id="cli-test-ephemeral",
        use_presidio=_check_presidio(),
        enabled=True,
    )

    tokenized, matches = tokenizer.tokenize(text)

    if not matches:
        console.print("[dim]No PII detected in the provided text.[/dim]")
        # Clean up ephemeral session
        store.clear_session("cli-test-ephemeral")
        store.close()
        return

    console.print(f"[bold]Detected {len(matches)} PII entity(ies):[/bold]\n")

    for m in matches:
        # Show partial masking for display
        masked = m.original_text[:2] + "*" * max(0, len(m.original_text) - 4) + m.original_text[-2:]
        if len(m.original_text) <= 4:
            masked = "*" * len(m.original_text)
        console.print(
            f"  [{m.entity_type}] {masked} \u2192 {m.token}"
            f"  (score: {m.score:.0%}, source: {m.source})"
        )

    console.print(f"\n[bold]Tokenized output:[/bold]")
    console.print(f"  {tokenized}")

    # Verify roundtrip
    restored = tokenizer.detokenize(tokenized)
    if restored == text:
        console.print(f"\n[green]\u2713[/green] Roundtrip verified (de-tokenization recovers original)")
    else:
        console.print(f"\n[yellow]! Roundtrip mismatch[/yellow]")

    # Clean up ephemeral session
    store.clear_session("cli-test-ephemeral")
    store.close()
