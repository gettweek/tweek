"""
Tweek CLI — evaluate command

Evaluate a skill for security risks with permission and behavioral analysis.
Runs the 7-layer scan plus permission manifest extraction, cross-validation,
and behavioral signal detection.
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

_SIGNAL_STYLES = {
    "danger": "red bold",
    "warning": "yellow",
    "info": "dim",
}

_RECOMMENDATION_STYLES = {
    "approve": "[green bold]APPROVE[/green bold]",
    "reject": "[red bold]REJECT[/red bold]",
    "review": "[yellow bold]REQUIRES REVIEW[/yellow bold]",
}

_RISK_STYLES = {
    "safe": "[green]SAFE[/green]",
    "suspicious": "[yellow]SUSPICIOUS[/yellow]",
    "dangerous": "[red]DANGEROUS[/red]",
}


def _print_evaluation_report(report, verbose: bool = False) -> None:
    """Print a formatted evaluation report using Rich."""
    from rich.table import Table

    # Header
    console.print()
    console.print("[bold cyan]Tweek Skill Evaluation[/bold cyan]")
    console.print("[dim]" + "-" * 55 + "[/dim]")
    console.print(f"  Skill:   [white]{report.skill_name}[/white]")
    console.print(f"  Path:    [white]{report.skill_path}[/white]")

    scan = report.scan_report
    if scan:
        console.print(
            f"  Files:   {len(scan.files_scanned)}  |  "
            f"Size: {scan.total_content_bytes:,} bytes"
        )
    console.print()

    # ---- Scan Layer Results ----
    if scan:
        console.print("[bold]Scan Layer Results[/bold]")

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
            layer = scan.layers.get(layer_key, {})
            if not layer:
                continue

            if layer.get("skipped"):
                icon = "[dim]o[/dim]"
                detail = f"[dim]Skipped ({layer.get('reason', '')})[/dim]"
            elif layer.get("passed", True):
                icon = "[green]v[/green]"
                findings = layer.get("findings", [])
                issues = layer.get("issues", [])
                count = len(findings) + len(issues)
                detail = "[green]No issues[/green]" if count == 0 else f"[green]{count} info[/green]"
            else:
                icon = "[red]x[/red]"
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

        console.print()

    # ---- Permission Manifest ----
    perms = report.permissions
    if perms:
        console.print("[bold]Permission Manifest[/bold]")
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Property", style="cyan", width=22)
        table.add_column("Value")

        tools_str = ", ".join(perms.tools_requested) if perms.tools_requested else "[dim]none declared[/dim]"
        table.add_row("Tools Requested", tools_str)
        table.add_row("Permission Mode", perms.permission_mode or "[dim]not set[/dim]")
        table.add_row("Network Access", "[yellow]Yes[/yellow]" if perms.network_access else "[green]No[/green]")
        table.add_row("File Write Access", "[yellow]Yes[/yellow]" if perms.file_write_access else "[green]No[/green]")
        table.add_row("Bash Access", "[red]Yes[/red]" if perms.bash_access else "[green]No[/green]")

        console.print(table)
        console.print()

    # ---- Permission Issues ----
    if report.permission_issues:
        console.print("[bold yellow]Permission Issues[/bold yellow]")
        for issue in report.permission_issues:
            console.print(f"  [yellow]![/yellow] {issue}")
        console.print()

    # ---- Behavioral Signals ----
    if report.behavioral_signals:
        console.print("[bold]Behavioral Signals[/bold]")
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("Severity", width=10)
        table.add_column("Signal", width=24)
        table.add_column("Description")
        if verbose:
            table.add_column("Evidence", style="dim", width=30)

        for signal in sorted(
            report.behavioral_signals,
            key=lambda s: {"danger": 0, "warning": 1, "info": 2}.get(s.severity, 3),
        ):
            style = _SIGNAL_STYLES.get(signal.severity, "white")
            row = [
                f"[{style}]{signal.severity.upper()}[/{style}]",
                signal.signal_type,
                signal.description,
            ]
            if verbose:
                evidence = signal.evidence[:28] + "..." if len(signal.evidence) > 28 else signal.evidence
                row.append(evidence)
            table.add_row(*row)

        console.print(table)
        console.print()
    elif verbose:
        console.print("[bold]Behavioral Signals[/bold]")
        console.print("  [green]No behavioral signals detected[/green]")
        console.print()

    # ---- Recommendation ----
    rec_display = _RECOMMENDATION_STYLES.get(report.recommendation, report.recommendation)
    risk_display = "[dim]N/A[/dim]"
    if scan:
        risk_display = _RISK_STYLES.get(scan.risk_level, scan.risk_level)

    console.print(f"  Recommendation: {rec_display}  |  Risk: {risk_display}")

    if report.recommendation_reasons:
        console.print()
        for reason in report.recommendation_reasons:
            icon = "[red]*[/red]" if "Danger" in reason else "[yellow]*[/yellow]" if "Warning" in reason or "Permission" in reason else "[green]*[/green]"
            console.print(f"  {icon} {reason}")

    if report.risk_summary:
        console.print()
        console.print(f"  [dim]{report.risk_summary}[/dim]")

    console.print(f"  [dim]Evaluation completed in {report.evaluation_duration_ms}ms[/dim]")
    console.print()


def _print_evaluation_json(report) -> None:
    """Print evaluation report as JSON."""
    console.print_json(json.dumps(report.to_dict(), indent=2))


# =============================================================================
# CLI Command
# =============================================================================


@click.command(
    epilog="""\b
Examples:
  tweek evaluate ./my-skill/                                       Evaluate a skill directory
  tweek evaluate ./SKILL.md                                        Evaluate a single SKILL.md
  tweek evaluate https://github.com/user/repo/blob/main/SKILL.md  Evaluate from URL
  tweek evaluate ./my-skill/ --no-llm-review                      Skip LLM review (faster)
  tweek evaluate ./my-skill/ --json                                Machine-readable output
  tweek evaluate ./my-skill/ --approve                             Install if evaluation passes
  tweek evaluate ./my-skill/ --approve --target project            Install to project skills
  tweek evaluate ./my-skill/ --save-report /tmp/report.json        Save report to file
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
    "--approve", is_flag=True,
    help="Install skill via isolation chamber if evaluation passes"
)
@click.option(
    "--target", type=click.Choice(["global", "project"]), default="global",
    help="Install target when using --approve (default: global)"
)
@click.option(
    "--verbose", "-v", is_flag=True,
    help="Show detailed behavioral signals and evidence"
)
@click.option(
    "--save-report", type=click.Path(), default=None,
    help="Save the evaluation report JSON to a file path"
)
def evaluate(
    source: str,
    llm_review: bool,
    json_out: bool,
    approve: bool,
    target: str,
    verbose: bool,
    save_report: str,
):
    """Evaluate a skill for security risks with permission and behavioral analysis.

    Runs the full 7-layer security scan plus:

    \b
    - Permission manifest extraction from SKILL.md frontmatter
    - Cross-validation of declared vs. actual capabilities
    - Behavioral signal detection (scope creep, trust escalation)
    - Synthesized approve/reject/review recommendation

    SOURCE can be a local file path or directory.
    """
    from tweek.evaluator import SkillEvaluator
    from tweek.skills.config import IsolationConfig

    config = IsolationConfig(llm_review_enabled=llm_review)

    if not json_out:
        console.print(f"[cyan]Evaluating {source}...[/cyan]")

    try:
        evaluator = SkillEvaluator(config=config)
        report = evaluator.evaluate(source)
    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Evaluation failed: {e}[/red]")
        sys.exit(1)

    # Display results
    if json_out:
        _print_evaluation_json(report)
    else:
        _print_evaluation_report(report, verbose=verbose)

    # Save report if requested
    if save_report:
        try:
            from pathlib import Path
            report_path = Path(save_report)
            report_path.parent.mkdir(parents=True, exist_ok=True)
            report_path.write_text(report.to_json())
            if not json_out:
                console.print(f"  [dim]Report saved to {save_report}[/dim]")
        except (IOError, OSError) as e:
            console.print(f"[red]Failed to save report: {e}[/red]")

    # Handle --approve
    if approve:
        if report.recommendation == "approve":
            _handle_install(source, target, json_out)
        elif report.recommendation == "review":
            if not json_out:
                console.print(
                    "[yellow]Evaluation requires review. "
                    "Use 'tweek skills chamber import' for manual approval.[/yellow]"
                )
        else:
            if not json_out:
                console.print(
                    "[red]Evaluation recommends rejection -- skill will not be installed.[/red]"
                )

    # Exit code: 0 = approve, 1 = reject, 2 = review
    if report.recommendation == "reject":
        sys.exit(1)
    elif report.recommendation == "review":
        sys.exit(2)


def _handle_install(source: str, target: str, quiet: bool = False) -> None:
    """Install a skill via the isolation chamber after a passing evaluation."""
    from pathlib import Path

    try:
        from tweek.skills.isolation import SkillIsolationChamber

        chamber = SkillIsolationChamber()
        source_path = Path(source).resolve()

        if source_path.is_file():
            import shutil
            import tempfile

            with tempfile.TemporaryDirectory() as tmp_dir:
                skill_dir = Path(tmp_dir) / source_path.stem
                skill_dir.mkdir()
                shutil.copy2(source_path, skill_dir / source_path.name)

                if not quiet:
                    console.print("[cyan]Installing via isolation chamber...[/cyan]")
                chamber.accept_and_scan(
                    source_path=skill_dir,
                    skill_name=source_path.stem,
                    target=target,
                )
        else:
            if not quiet:
                console.print("[cyan]Installing via isolation chamber...[/cyan]")
            chamber.accept_and_scan(
                source_path=source_path,
                skill_name=source_path.name,
                target=target,
            )

        if not quiet:
            console.print("[green]Installation complete.[/green]")

    except ImportError:
        console.print("[red]Isolation chamber not available.[/red]")
    except Exception as e:
        console.print(f"[red]Installation failed: {e}[/red]")
