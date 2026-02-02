"""Skills isolation chamber CLI commands extracted from tweek.cli.

Provides the ``skills`` Click group with subgroups: chamber, jail,
and top-level subcommands: report, status, config.
"""

import json
from pathlib import Path
from typing import Optional

import click
from rich.panel import Panel
from rich.table import Table

from tweek.cli_helpers import console

# ============================================================
# SKILLS - Isolation Chamber Management
# ============================================================


@click.group()
def skills():
    """Manage skill isolation chamber, jail, and security scanning."""
    pass


@skills.group("chamber")
def skills_chamber():
    """Manage the skill isolation chamber."""
    pass


@skills_chamber.command("list")
def chamber_list():
    """List skills currently in the isolation chamber."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    items = chamber.list_chamber()

    if not items:
        console.print("[white]Chamber is empty.[/white]")
        return

    table = Table(title="Isolation Chamber")
    table.add_column("Name", style="cyan")
    table.add_column("Has SKILL.md", style="green")
    table.add_column("Path", style="white")

    for item in items:
        has_md = "Yes" if item["has_skill_md"] else "[red]No[/red]"
        table.add_row(item["name"], has_md, item["path"])

    console.print(table)


@skills_chamber.command("import")
@click.argument("source")
@click.option("--name", default=None, help="Override skill name")
@click.option("--target", type=click.Choice(["global", "project"]), default="global",
              help="Install target if scan passes")
def chamber_import(source: str, name: Optional[str], target: str):
    """Import a skill into the isolation chamber and scan it.

    SOURCE is a path to a skill directory or SKILL.md file.
    """
    from tweek.skills.isolation import SkillIsolationChamber

    source_path = Path(source).resolve()
    if not source_path.exists():
        console.print(f"[red]Source not found: {source_path}[/red]")
        return

    chamber = SkillIsolationChamber()
    report, msg = chamber.accept_and_scan(source_path, skill_name=name, target=target)

    if report.verdict == "pass":
        console.print(f"[green]PASS[/green] {msg}")
    elif report.verdict == "fail":
        console.print(f"[red]FAIL[/red] {msg}")
    elif report.verdict == "manual_review":
        console.print(f"[yellow]MANUAL REVIEW[/yellow] {msg}")
    else:
        console.print(msg)


@skills_chamber.command("scan")
@click.argument("name")
def chamber_scan(name: str):
    """Manually trigger a scan on a skill in the chamber."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    report, msg = chamber.scan_skill(name)
    console.print(msg)


@skills_chamber.command("approve")
@click.argument("name")
@click.option("--target", type=click.Choice(["global", "project"]), default="global",
              help="Install target directory")
def chamber_approve(name: str, target: str):
    """Approve a skill in the chamber and install it."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    ok, msg = chamber.approve_skill(name, target=target)
    if ok:
        console.print(f"[green]{msg}[/green]")
    else:
        console.print(f"[red]{msg}[/red]")


@skills_chamber.command("reject")
@click.argument("name")
def chamber_reject(name: str):
    """Reject a skill in the chamber and move it to jail."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    ok, msg = chamber.jail_skill(name)
    if ok:
        console.print(f"[yellow]{msg}[/yellow]")
    else:
        console.print(f"[red]{msg}[/red]")


@skills.group("jail")
def skills_jail():
    """Manage quarantined (jailed) skills."""
    pass


@skills_jail.command("list")
def jail_list():
    """List skills currently in the jail."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    items = chamber.list_jail()

    if not items:
        console.print("[white]Jail is empty.[/white]")
        return

    table = Table(title="Skill Jail")
    table.add_column("Name", style="cyan")
    table.add_column("Verdict", style="red")
    table.add_column("Risk", style="yellow")
    table.add_column("Critical", style="red")
    table.add_column("High", style="yellow")

    for item in items:
        table.add_row(
            item["name"],
            item.get("verdict", "?"),
            item.get("risk_level", "?"),
            str(item.get("critical", "?")),
            str(item.get("high", "?")),
        )

    console.print(table)


@skills_jail.command("rescan")
@click.argument("name")
def jail_rescan(name: str):
    """Re-scan a jailed skill (useful after pattern updates)."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    ok, msg = chamber.release_from_jail(name, force=False)
    if ok:
        console.print(f"[green]{msg}[/green]")
    else:
        console.print(f"[red]{msg}[/red]")


@skills_jail.command("release")
@click.argument("name")
@click.confirmation_option(prompt="Force-release bypasses security scanning. Are you sure?")
def jail_release(name: str):
    """Force-release a skill from jail (dangerous -- bypasses scanning)."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    ok, msg = chamber.release_from_jail(name, force=True)
    if ok:
        console.print(f"[yellow]{msg}[/yellow]")
    else:
        console.print(f"[red]{msg}[/red]")


@skills_jail.command("purge")
@click.confirmation_option(prompt="Delete all jailed skills permanently?")
def jail_purge():
    """Delete all jailed skills permanently."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    count, msg = chamber.purge_jail()
    console.print(msg)


@skills.command("report")
@click.argument("name")
def skills_report(name: str):
    """View the latest scan report for a skill."""
    from tweek.skills.isolation import SkillIsolationChamber

    chamber = SkillIsolationChamber()
    report_data = chamber.get_report(name)

    if not report_data:
        console.print(f"[white]No report found for '{name}'.[/white]")
        return

    console.print(Panel(
        json.dumps(report_data, indent=2),
        title=f"Scan Report: {name}",
        border_style="cyan",
    ))


@skills.command("status")
def skills_status():
    """Show overview of chamber, jail, and installed skills."""
    from tweek.skills.isolation import SkillIsolationChamber
    from tweek.skills import CLAUDE_GLOBAL_SKILLS

    chamber = SkillIsolationChamber()
    chamber_items = chamber.list_chamber()
    jail_items = chamber.list_jail()

    # Count installed skills
    installed_count = 0
    if CLAUDE_GLOBAL_SKILLS.exists():
        installed_count = sum(
            1 for d in CLAUDE_GLOBAL_SKILLS.iterdir()
            if d.is_dir() and (d / "SKILL.md").exists()
        )

    table = Table(title="Skill Isolation Status")
    table.add_column("Location", style="cyan")
    table.add_column("Count", style="green")

    table.add_row("Installed (global)", str(installed_count))
    table.add_row("In Chamber", str(len(chamber_items)))
    table.add_row("In Jail", str(len(jail_items)))

    console.print(table)

    if chamber_items:
        console.print(f"\n[yellow]Chamber:[/yellow] {', '.join(i['name'] for i in chamber_items)}")
    if jail_items:
        console.print(f"[red]Jail:[/red] {', '.join(i['name'] for i in jail_items)}")


@skills.command("config")
@click.option("--mode", type=click.Choice(["auto", "manual"]), default=None,
              help="Set isolation mode")
def skills_config(mode: Optional[str]):
    """Show or update isolation chamber configuration."""
    from tweek.skills.config import load_isolation_config, save_isolation_config

    config = load_isolation_config()

    if mode:
        config.mode = mode
        save_isolation_config(config)
        console.print(f"[green]Isolation mode set to: {mode}[/green]")
        return

    table = Table(title="Isolation Chamber Config")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Enabled", str(config.enabled))
    table.add_row("Mode", config.mode)
    table.add_row("Scan Timeout", f"{config.scan_timeout_seconds}s")
    table.add_row("LLM Review", str(config.llm_review_enabled))
    table.add_row("Max Skill Size", f"{config.max_skill_size_bytes:,} bytes")
    table.add_row("Max File Count", str(config.max_file_count))
    table.add_row("Fail on Critical", str(config.fail_on_critical))
    table.add_row("Fail on HIGH Count", str(config.fail_on_high_count))
    table.add_row("Review on HIGH Count", str(config.review_on_high_count))

    console.print(table)
