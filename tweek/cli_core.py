#!/usr/bin/env python3
"""
Tweek CLI Core Commands

Standalone commands for system management:
    tweek status     Show protection status dashboard
    tweek trust      Trust a project directory
    tweek untrust    Remove trust from a directory
    tweek update     Update attack patterns
    tweek doctor     Run health checks
    tweek upgrade    Upgrade Tweek to latest version
    tweek audit      Audit skills for security risks
"""
from __future__ import annotations

import sys
from pathlib import Path

import click

from tweek.cli_helpers import (
    TWEEK_BANNER,
    _detect_all_tools,
    _has_tweek_at,
    _load_overrides_yaml,
    _save_overrides_yaml,
    console,
)


# =============================================================================
# STATUS
# =============================================================================

@click.command()
def status():
    """Show Tweek protection status dashboard.

    Scans for all supported AI tools and displays which are
    detected, which are protected by Tweek, and configuration details.
    """
    _show_protection_status()


def _show_protection_status():
    """Show protection status dashboard for all AI tools."""
    console.print(TWEEK_BANNER, style="cyan")

    tools = _detect_all_tools()

    from rich.table import Table

    table = Table(title="Protection Status")
    table.add_column("Tool", style="cyan")
    table.add_column("Installed", justify="center")
    table.add_column("Protected", justify="center")
    table.add_column("Details")

    for tool_id, label, installed, protected, detail in tools:
        inst_str = "[green]yes[/green]" if installed else "[white]no[/white]"
        prot_str = "[green]yes[/green]" if protected else ("[yellow]no[/yellow]" if installed else "[white]-[/white]")
        table.add_row(label, inst_str, prot_str, detail)

    console.print(table)
    console.print()
    console.print("[white]Run 'tweek protect' to set up protection for unprotected tools.[/white]")


# =============================================================================
# TRUST / UNTRUST
# =============================================================================

@click.command(
    epilog="""\b
Examples:
  tweek trust                            Trust the current project
  tweek trust /path/to/project           Trust a specific directory
  tweek trust --list                     Show all trusted paths
  tweek trust . --reason "My safe repo"  Trust with an explanation
"""
)
@click.argument("path", default=".", type=click.Path(exists=True), required=False)
@click.option("--reason", "-r", default=None, help="Why this path is trusted")
@click.option("--list", "list_trusted", is_flag=True, help="List all trusted paths")
def trust(path: str, reason: str, list_trusted: bool):
    """Trust a project directory — skip all screening for files in this path.

    Adds the directory to the whitelist in ~/.tweek/overrides.yaml.
    All tool calls operating on files within this path will be allowed
    without screening.

    This is useful for temporarily pausing Tweek in a specific project,
    or for permanently trusting a known-safe directory.

    To resume screening, use: tweek untrust
    """
    try:
        overrides, overrides_path = _load_overrides_yaml()
    except ImportError:
        console.print("[red]✗[/red] PyYAML is required. Install with: pip install pyyaml")
        return
    except Exception as e:
        console.print(f"[red]✗[/red] Could not load overrides: {e}")
        return

    whitelist = overrides.get("whitelist", [])

    # --list mode: show all trusted paths
    if list_trusted:
        trusted_entries = [
            entry for entry in whitelist
            if isinstance(entry, dict) and "path" in entry and not entry.get("tools")
        ]
        tool_scoped = [
            entry for entry in whitelist
            if isinstance(entry, dict) and "path" in entry and entry.get("tools")
        ]
        other_entries = [
            entry for entry in whitelist
            if isinstance(entry, dict) and "path" not in entry
        ]

        if not whitelist:
            console.print("[white]No trusted paths configured.[/white]")
            console.print("[white]Use 'tweek trust' to trust the current project.[/white]")
            return

        if trusted_entries:
            console.print("[bold]Trusted project directories[/bold] (all tools exempt):\n")
            for entry in trusted_entries:
                entry_reason = entry.get("reason", "")
                console.print(f"  [green]✓[/green] {entry['path']}")
                if entry_reason:
                    console.print(f"    [white]{entry_reason}[/white]")

        if tool_scoped:
            console.print("\n[bold]Tool-scoped whitelist entries:[/bold]\n")
            for entry in tool_scoped:
                tools_str = ", ".join(entry.get("tools", []))
                entry_reason = entry.get("reason", "")
                console.print(f"  [cyan]○[/cyan] {entry['path']}  [white]({tools_str})[/white]")
                if entry_reason:
                    console.print(f"    [white]{entry_reason}[/white]")

        if other_entries:
            console.print("\n[bold]Other whitelist entries:[/bold]\n")
            for entry in other_entries:
                if entry.get("url_prefix"):
                    console.print(f"  [cyan]○[/cyan] URL: {entry['url_prefix']}")
                elif entry.get("command_prefix"):
                    console.print(f"  [cyan]○[/cyan] Command: {entry['command_prefix']}")
                entry_reason = entry.get("reason", "")
                if entry_reason:
                    console.print(f"    [white]{entry_reason}[/white]")

        console.print(f"\n[white]Config: {overrides_path}[/white]")
        return

    # Resolve path to absolute
    resolved = Path(path).resolve()
    resolved_str = str(resolved)

    # Check if already whitelisted
    already_trusted = any(
        isinstance(entry, dict)
        and entry.get("path", "").rstrip("/") == resolved_str.rstrip("/")
        and not entry.get("tools")  # full trust, not tool-scoped
        for entry in whitelist
    )

    if already_trusted:
        console.print(f"[green]✓[/green] Already trusted: {resolved}")
        console.print("[white]Use 'tweek untrust' to remove.[/white]")
        return

    # Add whitelist entry (no tools restriction = all tools exempt)
    entry = {
        "path": resolved_str,
        "reason": reason or "Trusted via tweek trust",
    }
    whitelist.append(entry)
    overrides["whitelist"] = whitelist

    try:
        _save_overrides_yaml(overrides, overrides_path)
    except Exception as e:
        console.print(f"[red]✗[/red] Could not save overrides: {e}")
        return

    console.print(f"[green]✓[/green] Trusted: {resolved}")
    console.print(f"  [white]All screening is now skipped for files in this directory.[/white]")
    console.print(f"  [white]To resume screening: tweek untrust {path}[/white]")


@click.command(
    epilog="""\b
Examples:
  tweek untrust                          Untrust the current project
  tweek untrust /path/to/project         Untrust a specific directory
"""
)
@click.argument("path", default=".", type=click.Path(exists=True), required=False)
def untrust(path: str):
    """Remove trust from a project directory — resume screening.

    Removes the directory from the whitelist in ~/.tweek/overrides.yaml.
    Tweek will resume screening tool calls for files in this path.
    """
    try:
        overrides, overrides_path = _load_overrides_yaml()
    except ImportError:
        console.print("[red]✗[/red] PyYAML is required. Install with: pip install pyyaml")
        return
    except Exception as e:
        console.print(f"[red]✗[/red] Could not load overrides: {e}")
        return

    whitelist = overrides.get("whitelist", [])
    if not whitelist:
        console.print("[yellow]This path is not currently trusted.[/yellow]")
        return

    # Resolve path to absolute
    resolved = Path(path).resolve()
    resolved_str = str(resolved)

    # Find and remove matching entry (full trust only, not tool-scoped)
    original_len = len(whitelist)
    whitelist = [
        entry for entry in whitelist
        if not (
            isinstance(entry, dict)
            and entry.get("path", "").rstrip("/") == resolved_str.rstrip("/")
            and not entry.get("tools")  # only remove full trust, not tool-scoped entries
        )
    ]

    if len(whitelist) == original_len:
        console.print(f"[yellow]This path is not currently trusted:[/yellow] {resolved}")
        console.print("[white]Use 'tweek trust --list' to see all trusted paths.[/white]")
        return

    overrides["whitelist"] = whitelist

    # Clean up empty whitelist
    if not whitelist:
        del overrides["whitelist"]

    try:
        _save_overrides_yaml(overrides, overrides_path)
    except Exception as e:
        console.print(f"[red]✗[/red] Could not save overrides: {e}")
        return

    console.print(f"[green]✓[/green] Removed trust: {resolved}")
    console.print(f"  [white]Tweek will now screen tool calls for files in this directory.[/white]")


# =============================================================================
# UPDATE
# =============================================================================

@click.command(
    epilog="""\b
Examples:
  tweek update                           Download/update attack patterns
  tweek update --check                   Check for updates without installing
"""
)
@click.option("--check", is_flag=True, help="Check for updates without installing")
def update(check: bool):
    """Update attack patterns from GitHub.

    Patterns are stored in ~/.tweek/patterns/ and can be updated
    independently of the Tweek application.

    All 262 patterns are included free. PRO tier adds LLM review,
    session analysis, and rate limiting.
    """
    import subprocess

    patterns_dir = Path("~/.tweek/patterns").expanduser()
    patterns_repo = "https://github.com/gettweek/tweek.git"

    console.print(TWEEK_BANNER, style="cyan")

    if not patterns_dir.exists():
        # First time: clone the repo
        if check:
            console.print("[yellow]Patterns not installed.[/yellow]")
            console.print(f"[white]Run 'tweek update' to install from {patterns_repo}[/white]")
            return

        console.print(f"[cyan]Installing patterns from {patterns_repo}...[/cyan]")

        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", patterns_repo, str(patterns_dir)],
                capture_output=True,
                text=True,
                check=True
            )
            console.print("[green]✓[/green] Patterns installed successfully")

            # Show pattern count
            patterns_file = patterns_dir / "patterns.yaml"
            if patterns_file.exists():
                import yaml
                with open(patterns_file) as f:
                    data = yaml.safe_load(f)
                count = data.get("pattern_count", len(data.get("patterns", [])))
                free_max = data.get("free_tier_max", 23)
                console.print(f"[white]Installed {count} patterns ({free_max} free, {count - free_max} pro)[/white]")

        except subprocess.CalledProcessError as e:
            console.print(f"[red]✗[/red] Failed to clone patterns: {e.stderr}")
            return
        except FileNotFoundError:
            console.print("[red]✗[/red] git not found.")
            console.print("  [white]Hint: Install git from https://git-scm.com/downloads[/white]")
            console.print("  [white]On macOS: xcode-select --install[/white]")
            return

    else:
        # Update existing repo
        if check:
            console.print("[cyan]Checking for pattern updates...[/cyan]")
            try:
                result = subprocess.run(
                    ["git", "-C", str(patterns_dir), "fetch", "--dry-run"],
                    capture_output=True,
                    text=True
                )
                # Check if there are updates
                result2 = subprocess.run(
                    ["git", "-C", str(patterns_dir), "status", "-uno"],
                    capture_output=True,
                    text=True
                )
                if "behind" in result2.stdout:
                    console.print("[yellow]Updates available.[/yellow]")
                    console.print("[white]Run 'tweek update' to install[/white]")
                else:
                    console.print("[green]✓[/green] Patterns are up to date")
            except Exception as e:
                console.print(f"[red]✗[/red] Failed to check for updates: {e}")
            return

        console.print("[cyan]Updating patterns...[/cyan]")

        try:
            result = subprocess.run(
                ["git", "-C", str(patterns_dir), "pull", "--ff-only"],
                capture_output=True,
                text=True,
                check=True
            )

            if "Already up to date" in result.stdout:
                console.print("[green]✓[/green] Patterns already up to date")
            else:
                console.print("[green]✓[/green] Patterns updated successfully")

                # Show what changed
                if result.stdout.strip():
                    console.print(f"[white]{result.stdout.strip()}[/white]")

        except subprocess.CalledProcessError as e:
            console.print(f"[red]✗[/red] Failed to update patterns: {e.stderr}")
            console.print("[white]Try: rm -rf ~/.tweek/patterns && tweek update[/white]")
            return

    # Show current version info
    patterns_file = patterns_dir / "patterns.yaml"
    if patterns_file.exists():
        import yaml
        try:
            with open(patterns_file) as f:
                data = yaml.safe_load(f)
            version = data.get("version", "?")
            count = data.get("pattern_count", len(data.get("patterns", [])))

            console.print()
            console.print(f"[cyan]Pattern version:[/cyan] {version}")
            console.print(f"[cyan]Total patterns:[/cyan] {count} (all included free)")

            console.print(f"[cyan]All features:[/cyan] LLM review, session analysis, rate limiting, sandbox (open source)")
            console.print(f"[white]Pro (teams) and Enterprise (compliance) coming soon: gettweek.com[/white]")

        except Exception:
            pass


# =============================================================================
# DOCTOR
# =============================================================================

@click.command(
    epilog="""\b
Examples:
  tweek doctor                           Run all health checks
  tweek doctor --verbose                 Show detailed check information
  tweek doctor --json                    Output results as JSON for scripting
"""
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed check information")
@click.option("--json-output", "--json", "json_out", is_flag=True, help="Output results as JSON")
def doctor(verbose: bool, json_out: bool):
    """Run health checks on your Tweek installation.

    Checks hooks, configuration, patterns, database, vault, sandbox,
    license, MCP, proxy, and plugin integrity.
    """
    from tweek.diagnostics import run_health_checks
    from tweek.cli_helpers import print_doctor_results, print_doctor_json

    checks = run_health_checks(verbose=verbose)

    if json_out:
        print_doctor_json(checks)
    else:
        print_doctor_results(checks)


# =============================================================================
# UPGRADE
# =============================================================================

@click.command("upgrade")
def upgrade():
    """Upgrade Tweek to the latest version from PyPI.

    Detects how Tweek was installed (uv, pipx, or pip) and runs
    the appropriate upgrade command.
    """
    import subprocess

    console.print("[cyan]Checking for updates...[/cyan]")
    console.print()

    current_version = None
    try:
        from tweek import __version__
        current_version = __version__
        console.print(f"  Current version: [bold]{current_version}[/bold]")
    except ImportError:
        pass

    # Detect install method and upgrade
    upgraded = False

    # Try uv first
    try:
        result = subprocess.run(
            ["uv", "tool", "list"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0 and "tweek" in result.stdout:
            console.print("  Install method: [cyan]uv[/cyan]")
            console.print()
            console.print("[white]Upgrading via uv...[/white]")
            proc = subprocess.run(
                ["uv", "tool", "upgrade", "tweek"],
                capture_output=False, timeout=120
            )
            if proc.returncode == 0:
                upgraded = True
            else:
                console.print("[yellow]uv upgrade failed, trying reinstall...[/yellow]")
                subprocess.run(
                    ["uv", "tool", "install", "--force", "tweek"],
                    capture_output=False, timeout=120
                )
                upgraded = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Try pipx
    if not upgraded:
        try:
            result = subprocess.run(
                ["pipx", "list"], capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and "tweek" in result.stdout:
                console.print("  Install method: [cyan]pipx[/cyan]")
                console.print()
                console.print("[white]Upgrading via pipx...[/white]")
                proc = subprocess.run(
                    ["pipx", "upgrade", "tweek"],
                    capture_output=False, timeout=120
                )
                upgraded = proc.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Try pip
    if not upgraded:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "show", "tweek"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                console.print("  Install method: [cyan]pip[/cyan]")
                console.print()
                console.print("[white]Upgrading via pip...[/white]")
                proc = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--upgrade", "tweek"],
                    capture_output=False, timeout=120
                )
                upgraded = proc.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    if not upgraded:
        console.print("[red]Could not determine install method.[/red]")
        console.print("[white]Try manually:[/white]")
        console.print("  uv tool upgrade tweek")
        console.print("  pipx upgrade tweek")
        console.print("  pip install --upgrade tweek")
        return

    # Show new version
    console.print()
    try:
        result = subprocess.run(
            ["tweek", "--version"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            new_version = result.stdout.strip()
            console.print(f"[green]✓[/green] Updated to {new_version}")
        else:
            console.print("[green]✓[/green] Update complete")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        console.print("[green]✓[/green] Update complete")


# =============================================================================
# AUDIT
# =============================================================================

@click.command(
    epilog="""\b
Examples:
  tweek audit                            Scan all installed skills
  tweek audit ./skills/my-skill/SKILL.md Audit a specific file
  tweek audit --no-translate             Skip translation of non-English content
  tweek audit --json                     Machine-readable JSON output
"""
)
@click.argument("path", required=False, default=None, type=click.Path())
@click.option("--translate/--no-translate", default=True,
              help="Translate non-English content before pattern analysis (default: auto)")
@click.option("--llm-review/--no-llm-review", default=True,
              help="Run LLM semantic review (requires ANTHROPIC_API_KEY)")
@click.option("--json-output", "--json", "json_out", is_flag=True,
              help="Output results as JSON")
def audit(path, translate, llm_review, json_out):
    """Audit skills and tool files for security risks.

    Scans skill files (SKILL.md, tool descriptions) for prompt injection,
    credential theft, data exfiltration, and other attack patterns.

    Non-English content is detected and translated to English before
    running all 262 regex patterns. LLM semantic review provides
    additional analysis for obfuscated attacks.

    \b
    Without arguments, scans all installed skills in:
      ~/.claude/skills/
      ~/.openclaw/workspace/skills/
      ./.claude/skills/
    """
    from tweek.audit import scan_installed_skills, audit_skill, audit_content
    from rich.table import Table

    if path:
        # Audit a specific file
        target = Path(path)
        if not target.exists():
            console.print(f"[red]File not found: {target}[/red]")
            return

        console.print(f"[cyan]Auditing {target}...[/cyan]")
        console.print()

        result = audit_skill(target, translate=translate, llm_review=llm_review)

        if json_out:
            _print_audit_json([result])
        else:
            _print_audit_result(result)
    else:
        # Scan all installed skills
        console.print("[cyan]Scanning for installed skills...[/cyan]")
        skills_found = scan_installed_skills()

        if not skills_found:
            console.print("[white]No installed skills found.[/white]")
            console.print("[white]Specify a file path to audit: tweek audit <path>[/white]")
            return

        console.print(f"Found {len(skills_found)} skill(s)")
        console.print()

        results = []
        for skill_info in skills_found:
            if skill_info.get("error") or skill_info.get("content") is None:
                console.print(f"[yellow]Skipping {skill_info['name']}: {skill_info.get('error', 'no content')}[/yellow]")
                continue

            console.print(f"[cyan]Auditing {skill_info['name']}...[/cyan]")
            result = audit_content(
                content=skill_info["content"],
                name=skill_info["name"],
                path=skill_info["path"],
                translate=translate,
                llm_review=llm_review,
            )
            results.append(result)

        if json_out:
            _print_audit_json(results)
        else:
            for result in results:
                _print_audit_result(result)
                console.print()

            # Summary
            total = len(results)
            dangerous = sum(1 for r in results if r.risk_level == "dangerous")
            suspicious = sum(1 for r in results if r.risk_level == "suspicious")
            safe = sum(1 for r in results if r.risk_level == "safe")

            console.print("[bold]Summary[/bold]")
            console.print(f"  Skills scanned: {total}")
            if dangerous:
                console.print(f"  [red]Dangerous: {dangerous}[/red]")
            if suspicious:
                console.print(f"  [yellow]Suspicious: {suspicious}[/yellow]")
            console.print(f"  [green]Safe: {safe}[/green]")


def _print_audit_result(result):
    """Print a formatted audit result."""
    from rich.table import Table

    risk_icons = {"safe": "[green]SAFE[/green]", "suspicious": "[yellow]SUSPICIOUS[/yellow]", "dangerous": "[red]DANGEROUS[/red]"}

    console.print(f"  [bold]{result.skill_name}[/bold] — {risk_icons.get(result.risk_level, result.risk_level)}")
    console.print(f"  [white]{result.skill_path}[/white]")

    if result.error:
        console.print(f"  [red]Error: {result.error}[/red]")
        return

    if result.non_english_detected:
        lang = result.detected_language or "unknown"
        if result.translated:
            console.print(f"  [cyan]Non-English detected ({lang}) — translated for analysis[/cyan]")
        else:
            console.print(f"  [yellow]Non-English detected ({lang}) — translation skipped[/yellow]")

    if result.findings:
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Severity", style="white")
        table.add_column("Pattern")
        table.add_column("Description")
        table.add_column("Match", style="white")

        severity_styles = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "white"}

        for finding in result.findings:
            table.add_row(
                f"[{severity_styles.get(finding.severity, '')}]{finding.severity.upper()}[/]",
                finding.pattern_name,
                finding.description,
                finding.matched_text[:40] if finding.matched_text else "",
            )

        console.print(table)
    else:
        console.print("  [green]No patterns matched[/green]")

    if result.llm_review:
        review = result.llm_review
        console.print(f"  LLM Review: {review.get('risk_level', 'N/A')} ({review.get('confidence', 0):.0%}) — {review.get('reason', '')}")


def _print_audit_json(results):
    """Print audit results as JSON."""
    import json
    output = []
    for r in results:
        output.append({
            "skill_name": r.skill_name,
            "skill_path": str(r.skill_path),
            "risk_level": r.risk_level,
            "content_length": r.content_length,
            "non_english_detected": r.non_english_detected,
            "detected_language": r.detected_language,
            "translated": r.translated,
            "finding_count": r.finding_count,
            "critical_count": r.critical_count,
            "high_count": r.high_count,
            "findings": [
                {
                    "pattern_id": f.pattern_id,
                    "pattern_name": f.pattern_name,
                    "severity": f.severity,
                    "description": f.description,
                    "matched_text": f.matched_text,
                }
                for f in r.findings
            ],
            "llm_review": r.llm_review,
            "error": r.error,
        })
    console.print_json(json.dumps(output, indent=2))
