"""Dry-run command group for Tweek CLI (renamed from sandbox).

Provides the ``tweek dry-run`` CLI surface for project-level sandbox
isolation management.  The underlying sandbox subsystem modules
(``tweek.sandbox.*``) are unchanged -- only the user-facing command
hierarchy has been renamed from ``tweek sandbox`` to ``tweek dry-run``.
"""

import os
import shutil
import json
from pathlib import Path

import click
from rich.table import Table

from tweek.cli_helpers import console


@click.group("dry-run")
def dry_run():
    """Project-level dry-run isolation management.

    Layer 2 provides per-project security state isolation:
    - Separate security event logs per project
    - Project-scoped pattern overrides (additive-only)
    - Project-scoped skill fingerprints
    - Project-scoped configuration

    Project overrides can ADD security but NEVER weaken global settings.
    """
    pass


@dry_run.command("status")
def sandbox_status():
    """Show current project's sandbox info."""
    from tweek.sandbox.project import get_project_sandbox, _detect_project_dir
    from tweek.sandbox.layers import get_layer_description, IsolationLayer

    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[yellow]Not inside a project directory (no .git/ or .claude/ found).[/yellow]")
        return

    sandbox = get_project_sandbox(os.getcwd())
    if sandbox:
        console.print(f"[bold]Project:[/bold] {sandbox.project_dir}")
        console.print(f"[bold]Layer:[/bold] {sandbox.layer.value} ({sandbox.layer.name})")
        console.print(f"[bold]Description:[/bold] {get_layer_description(sandbox.layer)}")
        console.print(f"[bold]Tweek dir:[/bold] {sandbox.tweek_dir}")
        console.print(f"[bold]Initialized:[/bold] {sandbox.is_initialized}")

        if sandbox.is_initialized:
            db_path = sandbox.tweek_dir / "security.db"
            if db_path.exists():
                size_kb = db_path.stat().st_size / 1024
                console.print(f"[bold]Security DB:[/bold] {size_kb:.1f} KB")
    else:
        console.print(f"[bold]Project:[/bold] {project_dir}")
        console.print(f"[bold]Layer:[/bold] 0-1 (no project isolation)")
        console.print("[white]Run 'tweek dry-run init' to enable project isolation.[/white]")


@dry_run.command("init")
@click.option("--layer", type=int, default=2, help="Isolation layer (0=bypass, 1=skills, 2=project)")
def sandbox_init(layer: int):
    """Initialize sandbox for current project."""
    from tweek.sandbox.project import ProjectSandbox, _detect_project_dir
    from tweek.sandbox.layers import IsolationLayer, get_layer_description
    from tweek.logging.security_log import get_logger, EventType

    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[red]Not inside a project directory (no .git/ or .claude/ found).[/red]")
        raise SystemExit(1)

    isolation_layer = IsolationLayer.from_value(layer)
    sandbox = ProjectSandbox(project_dir)
    sandbox.config.layer = isolation_layer.value
    sandbox.layer = isolation_layer

    sandbox.initialize()

    console.print(f"[green]Sandbox initialized for {project_dir}[/green]")
    console.print(f"[bold]Layer:[/bold] {isolation_layer.value} ({isolation_layer.name})")
    console.print(f"[bold]Description:[/bold] {get_layer_description(isolation_layer)}")
    console.print(f"[bold]State directory:[/bold] {sandbox.tweek_dir}")

    try:
        logger = get_logger()
        from tweek.logging.security_log import SecurityEvent
        logger.log(SecurityEvent(
            event_type=EventType.SANDBOX_PROJECT_INIT,
            tool_name="cli",
            decision="allow",
            decision_reason=f"Project sandbox initialized at layer {isolation_layer.value}",
            working_directory=str(project_dir),
        ))
    except Exception:
        pass


@dry_run.command("layer")
@click.argument("level", type=int)
def sandbox_layer(level: int):
    """Set isolation layer for current project (0=bypass, 1=skills, 2=project)."""
    from tweek.sandbox.project import _detect_project_dir
    from tweek.sandbox.layers import IsolationLayer, get_layer_description
    from tweek.sandbox.registry import get_registry

    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[red]Not inside a project directory.[/red]")
        raise SystemExit(1)

    new_layer = IsolationLayer.from_value(level)
    registry = get_registry()
    registry.set_layer(project_dir, new_layer)

    console.print(f"[green]Layer set to {new_layer.value} ({new_layer.name})[/green]")
    console.print(f"[bold]Description:[/bold] {get_layer_description(new_layer)}")


@dry_run.command("list")
def sandbox_list():
    """List all registered projects and their layers."""
    from tweek.sandbox.registry import get_registry
    from tweek.sandbox.layers import IsolationLayer

    registry = get_registry()
    projects = registry.list_projects()

    if not projects:
        console.print("[white]No projects registered. Run 'tweek dry-run init' in a project.[/white]")
        return

    table = Table(title="Registered Projects")
    table.add_column("Project", style="cyan")
    table.add_column("Layer", style="green")
    table.add_column("Last Used")
    table.add_column("Auto-Init")

    for p in projects:
        layer = p["layer"]
        table.add_row(
            p["path"],
            f"{layer.value} ({layer.name})",
            p.get("last_used", "")[:19],
            "Yes" if p.get("auto_initialized") else "No",
        )

    console.print(table)


@dry_run.command("config")
def sandbox_config():
    """Show effective merged config (global + project)."""
    from tweek.sandbox.project import get_project_sandbox, _detect_project_dir

    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[red]Not inside a project directory.[/red]")
        raise SystemExit(1)

    sandbox = get_project_sandbox(os.getcwd())
    if not sandbox:
        console.print("[yellow]Project sandbox not active (layer < 2).[/yellow]")
        return

    console.print("[bold]Effective Configuration (global + project merge):[/bold]")
    console.print(f"  Layer: {sandbox.layer.value} ({sandbox.layer.name})")
    console.print(f"  Additive only: {sandbox.config.additive_only}")
    console.print(f"  Auto gitignore: {sandbox.config.auto_gitignore}")

    overrides = sandbox.get_overrides()
    if overrides:
        console.print(f"  Overrides loaded: Yes")
        if hasattr(overrides, 'global_ovr') and hasattr(overrides, 'project_ovr'):
            console.print(f"  Merge type: Additive-only (global + project)")
        else:
            console.print(f"  Merge type: Global only (no project overrides)")


@dry_run.command("logs")
@click.option("--global", "show_global", is_flag=True, help="Show global security log instead")
@click.option("--limit", default=20, help="Number of events to show")
def sandbox_logs(show_global: bool, limit: int):
    """View project-scoped or global security log."""
    from tweek.logging.security_log import SecurityLogger, get_logger

    if show_global:
        logger = get_logger()
        console.print("[bold]Global Security Log[/bold]")
    else:
        from tweek.sandbox.project import get_project_sandbox
        sandbox = get_project_sandbox(os.getcwd())
        if sandbox:
            logger = sandbox.get_logger()
            console.print(f"[bold]Project Security Log[/bold] ({sandbox.project_dir})")
        else:
            logger = get_logger()
            console.print("[bold]Global Security Log[/bold] (no project sandbox active)")

    events = logger.get_recent_events(limit=limit)
    if not events:
        console.print("[white]No events found.[/white]")
        return

    table = Table()
    table.add_column("Time", style="white")
    table.add_column("Type")
    table.add_column("Tool")
    table.add_column("Decision", style="green")
    table.add_column("Reason")

    for e in events:
        table.add_row(
            str(e.get("timestamp", ""))[:19],
            e.get("event_type", ""),
            e.get("tool_name", ""),
            e.get("decision", ""),
            (e.get("decision_reason", "") or "")[:60],
        )

    console.print(table)


@dry_run.command("reset")
@click.option("--confirm", is_flag=True, help="Skip confirmation")
def sandbox_reset(confirm: bool):
    """Remove project .tweek/ and deregister."""
    from tweek.sandbox.project import get_project_sandbox, _detect_project_dir

    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[red]Not inside a project directory.[/red]")
        raise SystemExit(1)

    tweek_dir = project_dir / ".tweek"
    if not tweek_dir.exists():
        console.print("[yellow]No .tweek/ directory found in this project.[/yellow]")
        return

    if not confirm:
        console.print(f"[yellow]This will remove {tweek_dir} and all project-scoped security state.[/yellow]")
        if not click.confirm("Continue?"):
            return

    sandbox = get_project_sandbox(os.getcwd())
    if sandbox:
        sandbox.reset()
        console.print(f"[green]Project sandbox removed: {tweek_dir}[/green]")
    else:
        # Manual cleanup
        shutil.rmtree(tweek_dir, ignore_errors=True)
        from tweek.sandbox.registry import get_registry
        get_registry().deregister(project_dir)
        console.print(f"[green]Removed: {tweek_dir}[/green]")


@dry_run.command("verify")
def sandbox_verify():
    """Test that project isolation is working."""
    from tweek.sandbox.project import get_project_sandbox, _detect_project_dir
    from tweek.sandbox.layers import IsolationLayer

    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[red]Not inside a project directory.[/red]")
        raise SystemExit(1)

    sandbox = get_project_sandbox(os.getcwd())
    checks_passed = 0
    checks_total = 0

    # Check 1: Project detected
    checks_total += 1
    console.print(f"  Project detected: {project_dir}", end="")
    console.print(" [green]OK[/green]")
    checks_passed += 1

    # Check 2: Sandbox initialized
    checks_total += 1
    if sandbox and sandbox.is_initialized:
        console.print(f"  Sandbox initialized: {sandbox.tweek_dir}", end="")
        console.print(" [green]OK[/green]")
        checks_passed += 1
    else:
        console.print("  Sandbox initialized: [red]NO[/red]")
        console.print("  [white]Run 'tweek dry-run init' to enable.[/white]")

    # Check 3: Layer
    checks_total += 1
    if sandbox and sandbox.layer >= IsolationLayer.PROJECT:
        console.print(f"  Isolation layer: {sandbox.layer.value} ({sandbox.layer.name})", end="")
        console.print(" [green]OK[/green]")
        checks_passed += 1
    else:
        layer_val = sandbox.layer.value if sandbox else 0
        console.print(f"  Isolation layer: {layer_val} [yellow]BELOW PROJECT[/yellow]")

    # Check 4: Security DB exists
    checks_total += 1
    if sandbox and (sandbox.tweek_dir / "security.db").exists():
        console.print("  Project security.db: exists", end="")
        console.print(" [green]OK[/green]")
        checks_passed += 1
    elif sandbox:
        console.print("  Project security.db: [yellow]NOT FOUND[/yellow]")
    else:
        console.print("  Project security.db: [white]N/A (sandbox inactive)[/white]")

    # Check 5: .gitignore
    checks_total += 1
    gitignore = project_dir / ".gitignore"
    if gitignore.exists() and ".tweek" in gitignore.read_text():
        console.print("  .gitignore includes .tweek/:", end="")
        console.print(" [green]OK[/green]")
        checks_passed += 1
    else:
        console.print("  .gitignore includes .tweek/: [yellow]NO[/yellow]")

    console.print(f"\n  [bold]{checks_passed}/{checks_total} checks passed[/bold]")


# Docker bridge commands
@dry_run.group("docker")
def sandbox_docker():
    """Docker integration for container-level isolation."""
    pass


@sandbox_docker.command("init")
def docker_init():
    """Generate Docker Sandbox config for this project."""
    from tweek.sandbox.docker_bridge import DockerBridge

    bridge = DockerBridge()
    if not bridge.is_docker_available():
        console.print("[red]Docker is not installed or not running.[/red]")
        console.print("[white]Install Docker Desktop from https://www.docker.com/products/docker-desktop/[/white]")
        raise SystemExit(1)

    from tweek.sandbox.project import _detect_project_dir
    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[red]Not inside a project directory.[/red]")
        raise SystemExit(1)

    compose_path = bridge.init(project_dir)
    console.print(f"[green]Docker Sandbox config generated: {compose_path}[/green]")
    console.print("[white]Run 'tweek dry-run docker run' to start the container.[/white]")


@sandbox_docker.command("run")
def docker_run():
    """Launch container-isolated session (requires Docker)."""
    from tweek.sandbox.docker_bridge import DockerBridge
    from tweek.sandbox.project import _detect_project_dir

    bridge = DockerBridge()
    if not bridge.is_docker_available():
        console.print("[red]Docker is not available.[/red]")
        raise SystemExit(1)

    project_dir = _detect_project_dir(os.getcwd())
    if not project_dir:
        console.print("[red]Not inside a project directory.[/red]")
        raise SystemExit(1)

    console.print("[bold]Launching Docker sandbox...[/bold]")
    bridge.run(project_dir)


@sandbox_docker.command("status")
def docker_status():
    """Check Docker integration status."""
    from tweek.sandbox.docker_bridge import DockerBridge

    bridge = DockerBridge()
    console.print(f"[bold]Docker available:[/bold] {bridge.is_docker_available()}")

    from tweek.sandbox.project import _detect_project_dir
    project_dir = _detect_project_dir(os.getcwd())
    if project_dir:
        compose = project_dir / ".tweek" / "docker-compose.yaml"
        console.print(f"[bold]Docker config:[/bold] {'exists' if compose.exists() else 'not generated'}")
    else:
        console.print("[white]Not in a project directory.[/white]")
