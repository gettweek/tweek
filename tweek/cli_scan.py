#!/usr/bin/env python3
"""
Tweek CLI — scan command

Pre-scan skill files or URLs for security risks before installation.
Runs the multi-layer security pipeline in read-only mode.
"""
from __future__ import annotations

import json
import sys

import click

from tweek.cli_helpers import console


# =============================================================================
# Display Helpers
# =============================================================================

_SEVERITY_STYLES = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "white",
}

_VERDICT_STYLES = {
    "pass": "[green bold]PASS[/green bold]",
    "fail": "[red bold]FAIL[/red bold]",
    "manual_review": "[yellow bold]MANUAL REVIEW[/yellow bold]",
}

_RISK_STYLES = {
    "safe": "[green]SAFE[/green]",
    "suspicious": "[yellow]SUSPICIOUS[/yellow]",
    "dangerous": "[red]DANGEROUS[/red]",
}


def _source_type_label(target) -> str:
    """Human-readable source type label."""
    if target.source_type == "url":
        meta = target.metadata or {}
        raw_url = meta.get("raw_url", target.source)
        if "githubusercontent.com" in raw_url:
            return "URL (GitHub)"
        elif "gitlab.com" in raw_url:
            return "URL (GitLab)"
        elif "bitbucket.org" in raw_url:
            return "URL (Bitbucket)"
        return "URL"
    elif target.source_type == "directory":
        return "Directory"
    return "File"


def _print_scan_report(report, target, verbose: bool = False) -> None:
    """Print a formatted scan report using Rich."""
    from rich.panel import Panel
    from rich.table import Table

    # Header
    console.print()
    console.print("[bold cyan]Tweek Security Scan[/bold cyan]")
    console.print("[dim]" + "-" * 50 + "[/dim]")
    console.print(f"  Source:  [white]{target.source}[/white]")
    console.print(f"  Type:    {_source_type_label(target)}")
    console.print(
        f"  Files:   {len(target.files)}  |  "
        f"Size: {target.total_bytes:,} bytes"
    )
    console.print()

    # Layer Results
    console.print("[bold]Layer Results[/bold]")

    layer_display = [
        ("structure", "Structure"),
        ("patterns", "Patterns"),
        ("yara", "YARA Rules"),
        ("secrets", "Secrets"),
        ("ast", "AST"),
        ("taint", "Taint Analysis"),
        ("consistency", "Consistency"),
        ("prompt_injection", "Prompt Injection"),
        ("exfiltration", "Exfiltration"),
        ("llm_review", "LLM Review"),
        ("meta_analysis", "Meta-Analysis"),
    ]

    for layer_key, label in layer_display:
        layer = report.layers.get(layer_key, {})

        if layer.get("skipped"):
            icon = "[dim]○[/dim]"
            detail = f"[dim]Skipped ({layer.get('reason', '')})[/dim]"
        elif layer.get("passed", True):
            icon = "[green]✓[/green]"
            findings = layer.get("findings", [])
            issues = layer.get("issues", [])
            count = len(findings) + len(issues)
            if count == 0:
                detail = "[green]No issues[/green]"
            else:
                detail = f"[green]{count} info[/green]"
        else:
            icon = "[red]✗[/red]"
            findings = layer.get("findings", [])
            issues = layer.get("issues", [])
            parts = []
            for sev in ("critical", "high", "medium", "low"):
                c = sum(1 for f in findings if isinstance(f, dict) and f.get("severity") == sev)
                if c > 0:
                    style = _SEVERITY_STYLES.get(sev, "white")
                    parts.append(f"[{style}]{c} {sev}[/{style}]")
            if issues:
                parts.append(f"{len(issues)} issue(s)")
            total = len(findings) + len(issues)
            detail = f"[red]{total} finding(s)[/red]  " + "  ".join(parts)

        console.print(f"  {icon} {label:<20s} {detail}")

        # Show issues in verbose mode
        if verbose and layer.get("issues"):
            for issue in layer["issues"]:
                console.print(f"      [dim]- {issue}[/dim]")

    # Findings Table
    all_findings = []
    for layer_key, _ in layer_display:
        layer = report.layers.get(layer_key, {})
        for f in layer.get("findings", []):
            if isinstance(f, dict) and f.get("severity") in ("critical", "high", "medium"):
                all_findings.append(f)

    if all_findings:
        console.print()
        console.print("[bold]Findings[/bold]")

        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Severity", style="white", width=10)
        table.add_column("Pattern", width=28)
        table.add_column("Description")
        table.add_column("Match", style="dim", width=30)

        for f in sorted(all_findings, key=lambda x: (
            {"critical": 0, "high": 1, "medium": 2}.get(x.get("severity", ""), 3)
        )):
            sev = f.get("severity", "low")
            style = _SEVERITY_STYLES.get(sev, "white")
            name = f.get("name", "unknown")
            desc = f.get("description", "")
            match_text = f.get("matched_text", "")
            if len(match_text) > 28:
                match_text = match_text[:25] + "..."

            table.add_row(
                f"[{style}]{sev.upper()}[/{style}]",
                name,
                desc,
                f'"{match_text}"' if match_text else "",
            )

        console.print(table)

    # Verdict
    console.print()
    verdict_display = _VERDICT_STYLES.get(report.verdict, report.verdict)
    risk_display = _RISK_STYLES.get(report.risk_level, report.risk_level)
    console.print(f"  Verdict: {verdict_display}  |  Risk: {risk_display}")
    console.print(f"  [dim]Scan completed in {report.scan_duration_ms}ms[/dim]")
    console.print()


def _print_scan_json(report) -> None:
    """Print scan report as JSON."""
    console.print_json(json.dumps(report.to_dict(), indent=2))


# =============================================================================
# CLI Command
# =============================================================================

@click.command(
    epilog="""\b
Examples:
  tweek scan ./SKILL.md                                          Scan a local file
  tweek scan ./my-skill/                                         Scan a skill directory
  tweek scan https://github.com/user/repo/blob/main/SKILL.md    Scan from GitHub URL
  tweek scan ./SKILL.md --no-llm-review                         Skip LLM review (faster)
  tweek scan ./SKILL.md --json                                   Machine-readable output
  tweek scan ./SKILL.md --install                                Scan and install if safe
  tweek scan ./SKILL.md --install --target project               Install to project skills
"""
)
@click.argument("source")
@click.option(
    "--llm-review/--no-llm-review", default=True,
    help="Run LLM semantic review (requires API key)"
)
@click.option(
    "--json-output", "--json", "json_out", is_flag=True,
    help="Output results as JSON"
)
@click.option(
    "--install", is_flag=True,
    help="Install skill via isolation chamber if scan passes"
)
@click.option(
    "--target", type=click.Choice(["global", "project"]), default="global",
    help="Install target when using --install (default: global)"
)
@click.option(
    "--verbose", "-v", is_flag=True,
    help="Show detailed per-layer results"
)
def scan(source: str, llm_review: bool, json_out: bool, install: bool,
         target: str, verbose: bool):
    """Pre-scan a skill file or URL for security risks.

    Runs the full 7-layer security analysis pipeline in read-only mode:

    \b
    1. Structure validation   (file types, size, depth)
    2. Pattern matching       (275 regex patterns)
    3. Secret scanning        (hardcoded credentials)
    4. AST analysis           (forbidden Python imports/calls)
    5. Prompt injection       (skill-specific manipulation patterns)
    6. Exfiltration detection (suspicious URLs and network commands)
    7. LLM semantic review    (intent analysis via AI model)

    SOURCE can be a local file path, local directory, or URL to a .md file.
    GitHub, GitLab, and Bitbucket blob URLs are auto-converted to raw URLs.

    This is a read-only operation — nothing is modified on your system.
    """
    from tweek.scan import ContentScanner, ScanTarget, resolve_source
    from tweek.skills.config import IsolationConfig

    config = IsolationConfig(llm_review_enabled=llm_review)

    # Resolve source to in-memory content
    if not json_out:
        console.print(f"[cyan]Scanning {source}...[/cyan]")

    try:
        scan_target = resolve_source(source, config)
    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)

    # Run the 7-layer scan
    scanner = ContentScanner(config=config)
    report = scanner.scan(scan_target)

    # Display results
    if json_out:
        _print_scan_json(report)
    else:
        _print_scan_report(report, scan_target, verbose=verbose)

    # Handle --install
    if install:
        if report.verdict == "pass":
            if scan_target.source_type == "url":
                console.print(
                    "[yellow]URL sources cannot be directly installed. "
                    "Download the skill first, then run:[/yellow]"
                )
                console.print("  tweek scan ./path/to/skill --install")
            else:
                _handle_install(source, target)
        elif report.verdict == "manual_review":
            console.print(
                "[yellow]Scan requires manual review. "
                "Use 'tweek skills chamber import' for manual approval workflow.[/yellow]"
            )
        else:
            console.print(
                "[red]Scan failed — skill will not be installed.[/red]"
            )

    # Exit code: 0 for pass, 1 for fail, 2 for manual_review
    if report.verdict == "fail":
        sys.exit(1)
    elif report.verdict == "manual_review":
        sys.exit(2)


def _handle_install(source: str, target: str) -> None:
    """Install a skill via the isolation chamber after a passing scan."""
    from pathlib import Path

    try:
        from tweek.skills.isolation import SkillIsolationChamber

        chamber = SkillIsolationChamber()
        source_path = Path(source).resolve()

        if source_path.is_file():
            # Single file — wrap in a temp directory for the chamber
            import tempfile
            import shutil

            with tempfile.TemporaryDirectory() as tmp_dir:
                skill_dir = Path(tmp_dir) / source_path.stem
                skill_dir.mkdir()
                shutil.copy2(source_path, skill_dir / source_path.name)

                console.print(f"[cyan]Installing via isolation chamber...[/cyan]")
                chamber.accept_and_scan(
                    source=str(skill_dir),
                    name=source_path.stem,
                    target=target,
                )
        else:
            # Directory — pass directly
            console.print(f"[cyan]Installing via isolation chamber...[/cyan]")
            chamber.accept_and_scan(
                source=str(source_path),
                name=source_path.name,
                target=target,
            )

        console.print("[green]Installation complete.[/green]")

    except ImportError:
        console.print("[red]Isolation chamber not available.[/red]")
    except Exception as e:
        console.print(f"[red]Installation failed: {e}[/red]")
