#!/usr/bin/env python3
"""
Tweek CLI — Vault and License command groups.

Extracted from cli.py to keep the main CLI module manageable.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import click

from rich.table import Table

from tweek.cli_helpers import console, TWEEK_BANNER


# ============================================================
# VAULT COMMANDS
# ============================================================

@click.group()
def vault():
    """Manage credentials in secure storage (Keychain on macOS, Secret Service on Linux)."""
    pass


@vault.command("store",
    epilog="""\b
Examples:
  tweek vault store myskill API_KEY                Prompt for value securely
  tweek vault store myskill API_KEY sk-abc123      Store an API key (visible in history!)
"""
)
@click.argument("skill")
@click.argument("key")
@click.argument("value", required=False, default=None)
def vault_store(skill: str, key: str, value: Optional[str]):
    """Store a credential securely for a skill."""
    from tweek.vault import get_vault, VAULT_AVAILABLE
    from tweek.platform import get_capabilities

    if not VAULT_AVAILABLE:
        console.print("[red]\u2717[/red] Vault not available.")
        console.print("  [white]Hint: Install keyring support: pip install keyring[/white]")
        console.print("  [white]On macOS, keyring uses Keychain. On Linux, install gnome-keyring or kwallet.[/white]")
        return

    caps = get_capabilities()

    # If value not provided as argument, prompt securely (avoids shell history exposure)
    if value is None:
        value = click.prompt(f"Enter value for {key}", hide_input=True)
        if not value:
            console.print("[red]No value provided.[/red]")
            return

    try:
        vault_instance = get_vault()
        if vault_instance.store(skill, key, value):
            console.print(f"[green]\u2713[/green] Stored {key} for skill '{skill}'")
            console.print(f"[white]Backend: {caps.vault_backend}[/white]")
        else:
            console.print(f"[red]\u2717[/red] Failed to store credential")
            console.print("  [white]Hint: Check your keyring backend is unlocked and accessible[/white]")
    except Exception as e:
        console.print(f"[red]\u2717[/red] Failed to store credential: {e}")
        console.print("  [white]Hint: Check your keyring backend is unlocked and accessible[/white]")


@vault.command("get",
    epilog="""\b
Examples:
  tweek vault get myskill API_KEY        Retrieve a stored credential
  tweek vault get deploy AWS_SECRET      Retrieve a deployment secret
"""
)
@click.argument("skill")
@click.argument("key")
def vault_get(skill: str, key: str):
    """Retrieve a credential from secure storage."""
    from tweek.vault import get_vault, VAULT_AVAILABLE

    if not VAULT_AVAILABLE:
        console.print("[red]\u2717[/red] Vault not available.")
        console.print("  [white]Hint: Install keyring support: pip install keyring[/white]")
        return

    vault_instance = get_vault()
    value = vault_instance.get(skill, key)

    if value is not None:
        console.print(f"[yellow]GAH![/yellow] Credential access logged")
        import sys as _sys
        if not _sys.stdout.isatty():
            console.print("[yellow]WARNING: stdout is piped — credential may be logged.[/yellow]", err=True)
        console.print(value)
    else:
        console.print(f"[red]\u2717[/red] Credential not found: {key} for skill '{skill}'")
        console.print("  [white]Hint: Store it with: tweek vault store {skill} {key} <value>[/white]".format(skill=skill, key=key))


@vault.command("migrate-env",
    epilog="""\b
Examples:
  tweek vault migrate-env --skill myapp                Migrate .env to vault
  tweek vault migrate-env --skill myapp --dry-run      Preview without changes
  tweek vault migrate-env --skill deploy --env-file .env.production   Migrate specific file
"""
)
@click.option("--dry-run", is_flag=True, help="Show what would be migrated without doing it")
@click.option("--env-file", default=".env", help="Path to .env file")
@click.option("--skill", required=True, help="Skill name to store credentials under")
def vault_migrate_env(dry_run: bool, env_file: str, skill: str):
    """Migrate credentials from .env file to secure storage."""
    from tweek.vault import get_vault, migrate_env_to_vault, VAULT_AVAILABLE

    if not VAULT_AVAILABLE:
        console.print("[red]\u2717[/red] Vault not available. Install keyring: pip install keyring")
        return

    env_path = Path(env_file)
    console.print(f"[cyan]Scanning {env_path} for credentials...[/cyan]")

    if dry_run:
        console.print("\n[yellow]DRY RUN - No changes will be made[/yellow]\n")

    try:
        vault_instance = get_vault()
        results = migrate_env_to_vault(env_path, skill, vault_instance, dry_run=dry_run)

        if results:
            console.print(f"\n[green]{'Would migrate' if dry_run else 'Migrated'}:[/green]")
            for key, success in results:
                status = "\u2713" if success else "\u2717"
                console.print(f"  {status} {key}")
            successful = sum(1 for _, s in results if s)
            total = len(results)
            console.print(f"\n[green]\u2713[/green] {'Would migrate' if dry_run else 'Migrated'} {successful} credentials to skill '{skill}'")

            if not dry_run and successful == total and env_path.exists():
                console.print()
                if click.confirm(f"Remove {env_path}? (credentials are now in the vault)"):
                    env_path.unlink()
                    console.print(f"[green]\u2713[/green] Removed {env_path}")
                else:
                    console.print(f"[yellow]\u26a0[/yellow] {env_path} still contains plaintext credentials")
            elif not dry_run and successful < total:
                failed = total - successful
                console.print(f"[yellow]\u26a0[/yellow] {failed} credential(s) failed to migrate \u2014 keeping {env_path}")
        else:
            console.print("[white]No credentials found to migrate[/white]")

    except Exception as e:
        console.print(f"[red]\u2717[/red] Migration failed: {e}")


@vault.command("delete",
    epilog="""\b
Examples:
  tweek vault delete myskill API_KEY     Delete a stored credential
  tweek vault delete deploy AWS_SECRET   Remove a deployment secret
"""
)
@click.argument("skill")
@click.argument("key")
def vault_delete(skill: str, key: str):
    """Delete a credential from secure storage."""
    from tweek.vault import get_vault, VAULT_AVAILABLE

    if not VAULT_AVAILABLE:
        console.print("[red]\u2717[/red] Vault not available. Install keyring: pip install keyring")
        return

    vault_instance = get_vault()
    deleted = vault_instance.delete(skill, key)

    if deleted:
        console.print(f"[green]\u2713[/green] Deleted {key} from skill '{skill}'")
    else:
        console.print(f"[yellow]![/yellow] Credential not found: {key} for skill '{skill}'")


# ============================================================
# LICENSE COMMANDS [experimental]
# ============================================================

@click.group("license")
def license_group():
    """Manage Tweek license and features. [experimental]"""
    pass


@license_group.command("status",
    epilog="""\b
Examples:
  tweek license status                   Show license tier and features
"""
)
def license_status():
    """Show current license status and available features. [experimental]"""
    console.print("[yellow]Note: License management is experimental. Pro/Enterprise tiers coming soon.[/yellow]")

    from tweek.licensing import get_license, TIER_FEATURES, Tier

    console.print(TWEEK_BANNER, style="cyan")

    lic = get_license()
    info = lic.info

    # License info
    tier_colors = {
        Tier.FREE: "white",
        Tier.PRO: "cyan",
    }

    tier_color = tier_colors.get(lic.tier, "white")
    console.print(f"[bold]License Tier:[/bold] [{tier_color}]{lic.tier.value.upper()}[/{tier_color}]")

    if info:
        console.print(f"[white]Licensed to: {info.email}[/white]")
        if info.expires_at:
            from datetime import datetime
            exp_date = datetime.fromtimestamp(info.expires_at).strftime("%Y-%m-%d")
            if info.is_expired:
                console.print(f"[red]Expired: {exp_date}[/red]")
            else:
                console.print(f"[white]Expires: {exp_date}[/white]")
        else:
            console.print("[white]Expires: Never[/white]")
    console.print()

    # Features table
    table = Table(title="Feature Availability")
    table.add_column("Feature", style="cyan")
    table.add_column("Status")
    table.add_column("Tier Required")

    # Collect all features and their required tiers
    feature_tiers = {}
    for tier in [Tier.FREE, Tier.PRO]:
        for feature in TIER_FEATURES.get(tier, []):
            feature_tiers[feature] = tier

    for feature, required_tier in feature_tiers.items():
        has_it = lic.has_feature(feature)
        status = "[green]\u2713[/green]" if has_it else "[white]\u25cb[/white]"
        tier_display = required_tier.value.upper()
        if required_tier == Tier.PRO:
            tier_display = f"[cyan]{tier_display}[/cyan]"

        table.add_row(feature, status, tier_display)

    console.print(table)

    if lic.tier == Tier.FREE:
        console.print()
        console.print("[green]All security features are included free and open source.[/green]")
        console.print("[white]Pro (teams) and Enterprise (compliance) coming soon: gettweek.com[/white]")


@license_group.command("activate",
    epilog="""\b
Examples:
  tweek license activate YOUR_KEY               Activate a license key (Pro/Enterprise coming soon)
"""
)
@click.argument("license_key")
def license_activate(license_key: str):
    """Activate a license key. [experimental]"""
    console.print("[yellow]Note: License management is experimental. Pro/Enterprise tiers coming soon.[/yellow]")

    from tweek.licensing import get_license

    lic = get_license()
    success, message = lic.activate(license_key)

    if success:
        console.print(f"[green]\u2713[/green] {message}")
        console.print()
        console.print("[white]Run 'tweek license status' to see available features[/white]")
    else:
        console.print(f"[red]\u2717[/red] {message}")


@license_group.command("deactivate",
    epilog="""\b
Examples:
  tweek license deactivate               Deactivate license (with prompt)
  tweek license deactivate --confirm     Deactivate without confirmation
"""
)
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def license_deactivate(confirm: bool):
    """Remove current license and revert to FREE tier. [experimental]"""
    console.print("[yellow]Note: License management is experimental. Pro/Enterprise tiers coming soon.[/yellow]")

    from tweek.licensing import get_license

    if not confirm:
        console.print("[yellow]Deactivate license and revert to FREE tier?[/yellow] ", end="")
        if not click.confirm(""):
            console.print("[white]Cancelled[/white]")
            return

    lic = get_license()
    success, message = lic.deactivate()

    if success:
        console.print(f"[green]\u2713[/green] {message}")
    else:
        console.print(f"[red]\u2717[/red] {message}")
