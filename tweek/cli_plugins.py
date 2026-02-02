"""
Tweek CLI Plugins Commands

Plugin management commands for Tweek: list, info, set, reset, scan,
install, update, remove, search, lock, verify, and registry operations.
"""

from pathlib import Path

import click
from rich.panel import Panel
from rich.table import Table

from tweek.cli_helpers import console


@click.group()
def plugins():
    """Manage Tweek plugins (compliance, providers, detectors, screening)."""
    pass


@plugins.command("list",
    epilog="""\b
Examples:
  tweek plugins list                     List all enabled plugins
  tweek plugins list --all               Include disabled plugins
  tweek plugins list -c compliance       Show only compliance plugins
  tweek plugins list -c screening        Show only screening plugins
"""
)
@click.option("--category", "-c", type=click.Choice(["compliance", "providers", "detectors", "screening"]),
              help="Filter by plugin category")
@click.option("--all", "show_all", is_flag=True, help="Show all plugins including disabled")
def plugins_list(category: str, show_all: bool):
    """List installed plugins."""
    try:
        from tweek.plugins import get_registry, init_plugins, PluginCategory, LicenseTier
        from tweek.config.manager import ConfigManager

        init_plugins()
        registry = get_registry()
        cfg = ConfigManager()

        category_map = {
            "compliance": PluginCategory.COMPLIANCE,
            "providers": PluginCategory.LLM_PROVIDER,
            "detectors": PluginCategory.TOOL_DETECTOR,
            "screening": PluginCategory.SCREENING,
        }

        categories = [category_map[category]] if category else list(PluginCategory)

        for cat in categories:
            cat_name = cat.value.split(".")[-1]
            plugins_list = registry.list_plugins(cat)

            if not plugins_list and not show_all:
                continue

            table = Table(title=f"{cat_name.replace('_', ' ').title()} Plugins")
            table.add_column("Name", style="cyan")
            table.add_column("Version")
            table.add_column("Source")
            table.add_column("Enabled")
            table.add_column("License")
            table.add_column("Description", max_width=40)

            for info in plugins_list:
                if not show_all and not info.enabled:
                    continue

                # Get config status
                plugin_cfg = cfg.get_plugin_config(cat_name, info.name)

                license_tier = info.metadata.requires_license
                license_style = "green" if license_tier == LicenseTier.FREE else "cyan"

                source_str = info.source.value if hasattr(info, 'source') else "builtin"
                source_style = "blue" if source_str == "git" else "white"

                table.add_row(
                    info.name,
                    info.metadata.version,
                    f"[{source_style}]{source_str}[/{source_style}]",
                    "[green]\u2713[/green]" if info.enabled else "[red]\u2717[/red]",
                    f"[{license_style}]{license_tier.value}[/{license_style}]",
                    info.metadata.description[:40] + "..." if len(info.metadata.description) > 40 else info.metadata.description,
                )

            console.print(table)
            console.print()

        # Summary line across all categories
        total_count = 0
        enabled_count = 0
        for cat in list(PluginCategory):
            for info in registry.list_plugins(cat):
                total_count += 1
                if info.enabled:
                    enabled_count += 1
        disabled_count = total_count - enabled_count
        console.print(f"Plugins: {total_count} registered, {enabled_count} enabled, {disabled_count} disabled")
        console.print()

    except ImportError as e:
        console.print(f"[red]Plugin system not available: {e}[/red]")


@plugins.command("info",
    epilog="""\b
Examples:
  tweek plugins info hipaa               Show details for the hipaa plugin
  tweek plugins info pii -c compliance   Specify category explicitly
"""
)
@click.argument("plugin_name")
@click.option("--category", "-c", type=click.Choice(["compliance", "providers", "detectors", "screening"]),
              help="Plugin category (auto-detected if not specified)")
def plugins_info(plugin_name: str, category: str):
    """Show detailed information about a plugin."""
    try:
        from tweek.plugins import get_registry, init_plugins, PluginCategory
        from tweek.config.manager import ConfigManager

        init_plugins()
        registry = get_registry()
        cfg = ConfigManager()

        category_map = {
            "compliance": PluginCategory.COMPLIANCE,
            "providers": PluginCategory.LLM_PROVIDER,
            "detectors": PluginCategory.TOOL_DETECTOR,
            "screening": PluginCategory.SCREENING,
        }

        # Find the plugin
        found_info = None
        found_cat = None

        if category:
            cat_enum = category_map[category]
            found_info = registry.get_info(plugin_name, cat_enum)
            found_cat = category
        else:
            # Search all categories
            for cat_name, cat_enum in category_map.items():
                info = registry.get_info(plugin_name, cat_enum)
                if info:
                    found_info = info
                    found_cat = cat_name
                    break

        if not found_info:
            console.print(f"[red]Plugin not found: {plugin_name}[/red]")
            return

        # Get config
        plugin_cfg = cfg.get_plugin_config(found_cat, plugin_name)

        console.print(f"\n[bold]{found_info.name}[/bold] ({found_cat})")
        console.print(f"[white]{found_info.metadata.description}[/white]")
        console.print()

        table = Table(show_header=False)
        table.add_column("Key", style="cyan")
        table.add_column("Value")

        table.add_row("Version", found_info.metadata.version)
        table.add_row("Author", found_info.metadata.author or "Unknown")
        table.add_row("License Required", found_info.metadata.requires_license.value.upper())
        table.add_row("Enabled", "Yes" if found_info.enabled else "No")
        table.add_row("Config Source", plugin_cfg.source)

        if found_info.metadata.tags:
            table.add_row("Tags", ", ".join(found_info.metadata.tags))

        if plugin_cfg.settings:
            table.add_row("Settings", str(plugin_cfg.settings))

        if found_info.load_error:
            table.add_row("[red]Load Error[/red]", found_info.load_error)

        console.print(table)

    except ImportError as e:
        console.print(f"[red]Plugin system not available: {e}[/red]")


@plugins.command("set",
    epilog="""\b
Examples:
  tweek plugins set hipaa --enabled -c compliance          Enable a plugin
  tweek plugins set hipaa --disabled -c compliance         Disable a plugin
  tweek plugins set hipaa threshold 0.8 -c compliance      Set a config value
  tweek plugins set hipaa --scope-tools Bash,Edit -c compliance   Scope to tools
  tweek plugins set hipaa --scope-clear -c compliance      Clear scoping
"""
)
@click.argument("plugin_name")
@click.argument("key", required=False)
@click.argument("value", required=False)
@click.option("--category", "-c", type=click.Choice(["compliance", "providers", "detectors", "screening"]),
              required=True, help="Plugin category")
@click.option("--scope", type=click.Choice(["user", "project"]), default="user")
@click.option("--enabled", "set_enabled", is_flag=True, help="Enable the plugin")
@click.option("--disabled", "set_disabled", is_flag=True, help="Disable the plugin")
@click.option("--scope-tools", help="Comma-separated tool names for scoping")
@click.option("--scope-skills", help="Comma-separated skill names for scoping")
@click.option("--scope-tiers", help="Comma-separated tiers for scoping")
@click.option("--scope-clear", is_flag=True, help="Clear all scoping")
def plugins_set(plugin_name: str, key: str, value: str, category: str, scope: str,
                set_enabled: bool, set_disabled: bool, scope_tools: str,
                scope_skills: str, scope_tiers: str, scope_clear: bool):
    """Set a plugin configuration value, enable/disable, or configure scope."""
    from tweek.config.manager import ConfigManager
    import json

    cfg = ConfigManager()

    # Handle enable/disable
    if set_enabled:
        cfg.set_plugin_enabled(category, plugin_name, True, scope=scope)
        console.print(f"[green]\u2713[/green] Enabled plugin '{plugin_name}' ({category}) - {scope} config")
        return
    if set_disabled:
        cfg.set_plugin_enabled(category, plugin_name, False, scope=scope)
        console.print(f"[green]\u2713[/green] Disabled plugin '{plugin_name}' ({category}) - {scope} config")
        return

    # Handle scope configuration
    if scope_clear:
        cfg.set_plugin_scope(plugin_name, None)
        console.print(f"[green]\u2713[/green] Cleared scope for {plugin_name} (now global)")
        return

    if any([scope_tools, scope_skills, scope_tiers]):
        scope_config = {}
        if scope_tools:
            scope_config["tools"] = [t.strip() for t in scope_tools.split(",")]
        if scope_skills:
            scope_config["skills"] = [s.strip() for s in scope_skills.split(",")]
        if scope_tiers:
            scope_config["tiers"] = [t.strip() for t in scope_tiers.split(",")]
        cfg.set_plugin_scope(plugin_name, scope_config)
        console.print(f"[green]\u2713[/green] Updated scope for {plugin_name}")
        return

    # Handle key=value setting
    if not key or not value:
        console.print("[red]Specify key and value, or use --enabled/--disabled/--scope-* flags[/red]")
        return

    # Try to parse value as JSON (for booleans, numbers, objects)
    try:
        parsed_value = json.loads(value)
    except json.JSONDecodeError:
        parsed_value = value

    cfg.set_plugin_setting(category, plugin_name, key, parsed_value, scope=scope)
    console.print(f"[green]\u2713[/green] Set {plugin_name}.{key} = {parsed_value} ({scope} config)")


@plugins.command("reset",
    epilog="""\b
Examples:
  tweek plugins reset hipaa -c compliance          Reset hipaa plugin to defaults
  tweek plugins reset pii -c compliance --scope project   Reset project-level config
"""
)
@click.argument("plugin_name")
@click.option("--category", "-c", type=click.Choice(["compliance", "providers", "detectors", "screening"]),
              required=True, help="Plugin category")
@click.option("--scope", type=click.Choice(["user", "project"]), default="user")
def plugins_reset(plugin_name: str, category: str, scope: str):
    """Reset a plugin to default configuration."""
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()

    if cfg.reset_plugin(category, plugin_name, scope=scope):
        console.print(f"[green]\u2713[/green] Reset plugin '{plugin_name}' to defaults ({scope} config)")
    else:
        console.print(f"[yellow]![/yellow] Plugin '{plugin_name}' has no {scope} configuration to reset")


@plugins.command("scan",
    epilog="""\b
Examples:
  tweek plugins scan "This is TOP SECRET//NOFORN"         Scan text for compliance
  tweek plugins scan "Patient MRN: 123456" --plugin hipaa  Use specific plugin
  tweek plugins scan @file.txt                             Scan file contents
  tweek plugins scan "SSN: 123-45-6789" -d input           Scan incoming data
"""
)
@click.argument("content")
@click.option("--direction", "-d", type=click.Choice(["input", "output"]), default="output",
              help="Scan direction (input=incoming data, output=LLM response)")
@click.option("--plugin", "-p", help="Specific compliance plugin to use (default: all enabled)")
def plugins_scan(content: str, direction: str, plugin: str):
    """Run compliance scan on content."""
    try:
        from tweek.plugins import get_registry, init_plugins, PluginCategory
        from tweek.plugins.base import ScanDirection

        # Handle file input
        if content.startswith("@"):
            file_path = Path(content[1:])
            if file_path.exists():
                content = file_path.read_text()
            else:
                console.print(f"[red]File not found: {file_path}[/red]")
                return

        init_plugins()
        registry = get_registry()
        direction_enum = ScanDirection(direction)

        total_findings = []

        if plugin:
            # Scan with specific plugin
            plugin_instance = registry.get(plugin, PluginCategory.COMPLIANCE)
            if not plugin_instance:
                console.print(f"[red]Plugin not found: {plugin}[/red]")
                return
            plugins_to_use = [plugin_instance]
        else:
            # Use all enabled compliance plugins
            plugins_to_use = registry.get_all(PluginCategory.COMPLIANCE)

        if not plugins_to_use:
            console.print("[yellow]No compliance plugins enabled.[/yellow]")
            console.print("[white]Enable plugins with: tweek plugins enable <name> -c compliance[/white]")
            return

        for p in plugins_to_use:
            result = p.scan(content, direction_enum)

            if result.findings:
                console.print(f"\n[bold]{p.name.upper()}[/bold]: {len(result.findings)} finding(s)")

                for finding in result.findings:
                    severity_styles = {
                        "critical": "red bold",
                        "high": "red",
                        "medium": "yellow",
                        "low": "white",
                    }
                    style = severity_styles.get(finding.severity.value, "white")

                    console.print(f"  [{style}]{finding.severity.value.upper()}[/{style}] {finding.pattern_name}")
                    console.print(f"    [white]Matched: {finding.matched_text[:60]}{'...' if len(finding.matched_text) > 60 else ''}[/white]")
                    if finding.description:
                        console.print(f"    {finding.description}")

                total_findings.extend(result.findings)

        if not total_findings:
            console.print("[green]\u2713[/green] No compliance issues found")
        else:
            console.print(f"\n[yellow]Total: {len(total_findings)} finding(s)[/yellow]")

    except ImportError as e:
        console.print(f"[red]Plugin system not available: {e}[/red]")


# ============================================================
# GIT PLUGIN MANAGEMENT COMMANDS
# ============================================================

@plugins.command("install",
    epilog="""\b
Examples:
  tweek plugins install hipaa-scanner              Install a plugin by name
  tweek plugins install hipaa-scanner -v 1.2.0     Install a specific version
  tweek plugins install _ --from-lockfile          Install all from lockfile
  tweek plugins install hipaa-scanner --no-verify  Skip verification (not recommended)
"""
)
@click.argument("name")
@click.option("--version", "-v", "version", default=None, help="Specific version to install")
@click.option("--from-lockfile", is_flag=True, help="Install all plugins from lockfile")
@click.option("--no-verify", is_flag=True, help="Skip security verification (not recommended)")
def plugins_install(name: str, version: str, from_lockfile: bool, no_verify: bool):
    """Install a plugin from the Tweek registry."""
    console.print("[yellow]Note: Plugin registry is experimental and may change.[/yellow]")
    try:
        from tweek.plugins.git_installer import GitPluginInstaller
        from tweek.plugins.git_registry import PluginRegistryClient
        from tweek.plugins.git_lockfile import PluginLockfile

        if from_lockfile:
            lockfile = PluginLockfile()
            if not lockfile.has_lockfile:
                console.print("[red]No lockfile found. Run 'tweek plugins lock' first.[/red]")
                return

            locks = lockfile.load()
            registry = PluginRegistryClient()
            installer = GitPluginInstaller(registry_client=registry)

            for plugin_name, lock in locks.items():
                console.print(f"Installing {plugin_name} v{lock.version}...")
                success, msg = installer.install(
                    plugin_name,
                    version=lock.version,
                    verify=not no_verify,
                )
                if success:
                    console.print(f"  [green]\u2713[/green] {msg}")
                else:
                    console.print(f"  [red]\u2717[/red] {msg}")
            return

        registry = PluginRegistryClient()
        installer = GitPluginInstaller(registry_client=registry)

        from tweek.cli_helpers import spinner as cli_spinner

        with cli_spinner(f"Installing {name}"):
            success, msg = installer.install(name, version=version, verify=not no_verify)

        if success:
            console.print(f"[green]\u2713[/green] {msg}")
        else:
            console.print(f"[red]\u2717[/red] {msg}")
            console.print(f"  [white]Hint: Check network connectivity or try: tweek plugins registry --refresh[/white]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print(f"  [white]Hint: Check network connectivity and try again[/white]")


@plugins.command("update",
    epilog="""\b
Examples:
  tweek plugins update hipaa-scanner     Update a specific plugin
  tweek plugins update --all             Update all installed plugins
  tweek plugins update --check           Check for available updates
  tweek plugins update hipaa-scanner -v 2.0.0   Update to specific version
"""
)
@click.argument("name", required=False)
@click.option("--all", "update_all", is_flag=True, help="Update all installed plugins")
@click.option("--check", "check_only", is_flag=True, help="Check for updates without installing")
@click.option("--version", "-v", "version", default=None, help="Specific version to update to")
@click.option("--no-verify", is_flag=True, help="Skip security verification")
def plugins_update(name: str, update_all: bool, check_only: bool, version: str, no_verify: bool):
    """Update installed plugins."""
    console.print("[yellow]Note: Plugin registry is experimental and may change.[/yellow]")
    try:
        from tweek.plugins.git_installer import GitPluginInstaller
        from tweek.plugins.git_registry import PluginRegistryClient

        registry = PluginRegistryClient()
        installer = GitPluginInstaller(registry_client=registry)

        if check_only:
            console.print("Checking for updates...")
            updates = installer.check_updates()
            if not updates:
                console.print("[green]All plugins are up to date.[/green]")
            else:
                table = Table(title="Available Updates")
                table.add_column("Plugin", style="cyan")
                table.add_column("Current")
                table.add_column("Latest", style="green")
                for u in updates:
                    table.add_row(u["name"], u["current_version"], u["latest_version"])
                console.print(table)
            return

        if update_all:
            installed = installer.list_installed()
            if not installed:
                console.print("No git plugins installed.")
                return
            for plugin in installed:
                console.print(f"Updating {plugin['name']}...")
                success, msg = installer.update(
                    plugin["name"],
                    verify=not no_verify,
                )
                if success:
                    console.print(f"  [green]\u2713[/green] {msg}")
                else:
                    console.print(f"  [yellow]![/yellow] {msg}")
            return

        if not name:
            console.print("[red]Specify a plugin name or use --all[/red]")
            return

        success, msg = installer.update(name, version=version, verify=not no_verify)
        if success:
            console.print(f"[green]\u2713[/green] {msg}")
        else:
            console.print(f"[red]\u2717[/red] {msg}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@plugins.command("remove",
    epilog="""\b
Examples:
  tweek plugins remove hipaa-scanner     Remove a plugin (with confirmation)
  tweek plugins remove hipaa-scanner -f  Remove without confirmation
"""
)
@click.argument("name")
@click.option("--force", "-f", is_flag=True, help="Skip confirmation")
def plugins_remove(name: str, force: bool):
    """Remove an installed git plugin."""
    console.print("[yellow]Note: Plugin registry is experimental and may change.[/yellow]")
    try:
        from tweek.plugins.git_installer import GitPluginInstaller
        from tweek.plugins.git_registry import PluginRegistryClient

        installer = GitPluginInstaller(registry_client=PluginRegistryClient())

        if not force:
            if not click.confirm(f"Remove plugin '{name}'?"):
                return

        success, msg = installer.remove(name)
        if success:
            console.print(f"[green]\u2713[/green] {msg}")
        else:
            console.print(f"[red]\u2717[/red] {msg}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@plugins.command("search",
    epilog="""\b
Examples:
  tweek plugins search hipaa             Search for plugins by name
  tweek plugins search -c compliance     Browse all compliance plugins
  tweek plugins search -t free           Show only free-tier plugins
  tweek plugins search pii --include-deprecated   Include deprecated results
"""
)
@click.argument("query", required=False)
@click.option("--category", "-c", type=click.Choice(["compliance", "providers", "detectors", "screening"]),
              help="Filter by category")
@click.option("--tier", "-t", type=click.Choice(["free", "pro", "enterprise"]),
              help="Filter by license tier")
@click.option("--include-deprecated", is_flag=True, help="Include deprecated plugins")
def plugins_search(query: str, category: str, tier: str, include_deprecated: bool):
    """Search the Tweek plugin registry."""
    console.print("[yellow]Note: Plugin registry is experimental and may change.[/yellow]")
    try:
        from tweek.plugins.git_registry import PluginRegistryClient

        registry = PluginRegistryClient()
        console.print("Searching registry...")
        results = registry.search(
            query=query,
            category=category,
            tier=tier,
            include_deprecated=include_deprecated,
        )

        if not results:
            console.print("[yellow]No plugins found matching your criteria.[/yellow]")
            return

        table = Table(title=f"Registry Results ({len(results)} found)")
        table.add_column("Name", style="cyan")
        table.add_column("Version")
        table.add_column("Category")
        table.add_column("Tier")
        table.add_column("Description", max_width=40)

        for entry in results:
            table.add_row(
                entry.name,
                entry.latest_version,
                entry.category,
                entry.requires_license_tier,
                entry.description[:40] + "..." if len(entry.description) > 40 else entry.description,
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@plugins.command("lock",
    epilog="""\b
Examples:
  tweek plugins lock                     Generate lockfile for all plugins
  tweek plugins lock -p hipaa -v 1.2.0   Lock a specific plugin to a version
  tweek plugins lock --project           Create project-level lockfile
"""
)
@click.option("--plugin", "-p", "plugin_name", default=None, help="Lock a specific plugin")
@click.option("--version", "-v", "version", default=None, help="Lock to specific version")
@click.option("--project", is_flag=True, help="Create project-level lockfile (.tweek/plugins.lock.json)")
def plugins_lock(plugin_name: str, version: str, project: bool):
    """Generate or update a plugin version lockfile."""
    console.print("[yellow]Note: Plugin registry is experimental and may change.[/yellow]")
    try:
        from tweek.plugins.git_lockfile import PluginLockfile

        lockfile = PluginLockfile()
        target = "project" if project else "user"

        specific = None
        if plugin_name:
            specific = {plugin_name: version or "latest"}

        path = lockfile.generate(target=target, specific_plugins=specific)
        console.print(f"[green]\u2713[/green] Lockfile generated: {path}")

        # Show lock contents
        locks = lockfile.load()
        if locks:
            table = Table(title="Locked Plugins")
            table.add_column("Plugin", style="cyan")
            table.add_column("Version")
            table.add_column("Commit")
            for name, lock in locks.items():
                table.add_row(
                    name,
                    lock.version,
                    lock.commit_sha[:12] if lock.commit_sha else "n/a",
                )
            console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@plugins.command("verify",
    epilog="""\b
Examples:
  tweek plugins verify hipaa-scanner     Verify a specific plugin's integrity
  tweek plugins verify --all             Verify all installed plugins
"""
)
@click.argument("name", required=False)
@click.option("--all", "verify_all", is_flag=True, help="Verify all installed plugins")
def plugins_verify(name: str, verify_all: bool):
    """Verify integrity of installed git plugins."""
    console.print("[yellow]Note: Plugin registry is experimental and may change.[/yellow]")
    try:
        from tweek.plugins.git_installer import GitPluginInstaller
        from tweek.plugins.git_registry import PluginRegistryClient

        from tweek.cli_helpers import spinner as cli_spinner

        installer = GitPluginInstaller(registry_client=PluginRegistryClient())

        if verify_all:
            with cli_spinner("Verifying plugin integrity"):
                results = installer.verify_all()
            if not results:
                console.print("No git plugins installed.")
                return

            all_valid = True
            for plugin_name, (valid, issues) in results.items():
                if valid:
                    console.print(f"  [green]\u2713[/green] {plugin_name}: integrity verified")
                else:
                    all_valid = False
                    console.print(f"  [red]\u2717[/red] {plugin_name}: {len(issues)} issue(s)")
                    for issue in issues:
                        console.print(f"      - {issue}")

            if all_valid:
                console.print(f"\n[green]All {len(results)} plugin(s) verified.[/green]")
            return

        if not name:
            console.print("[red]Specify a plugin name or use --all[/red]")
            return

        valid, issues = installer.verify_plugin(name)
        if valid:
            console.print(f"[green]\u2713[/green] Plugin '{name}' integrity verified")
        else:
            console.print(f"[red]\u2717[/red] Plugin '{name}' failed verification:")
            for issue in issues:
                console.print(f"  - {issue}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@plugins.command("registry",
    epilog="""\b
Examples:
  tweek plugins registry                 Show registry summary
  tweek plugins registry --refresh       Force refresh the registry cache
  tweek plugins registry --info          Show detailed registry metadata
"""
)
@click.option("--refresh", is_flag=True, help="Force refresh the registry cache")
@click.option("--info", "show_info", is_flag=True, help="Show registry metadata")
def plugins_registry(refresh: bool, show_info: bool):
    """Manage the plugin registry cache."""
    console.print("[yellow]Note: Plugin registry is experimental and may change.[/yellow]")
    try:
        from tweek.plugins.git_registry import PluginRegistryClient

        registry = PluginRegistryClient()

        if refresh:
            console.print("Refreshing registry...")
            try:
                entries = registry.fetch(force_refresh=True)
                console.print(f"[green]\u2713[/green] Registry refreshed: {len(entries)} plugins available")
            except Exception as e:
                console.print(f"[red]\u2717[/red] Failed to refresh: {e}")
            return

        if show_info:
            info = registry.get_registry_info()
            panel_content = "\n".join([
                f"URL: {info.get('url', 'unknown')}",
                f"Cache: {info.get('cache_path', 'unknown')}",
                f"Cache TTL: {info.get('cache_ttl_seconds', 0)}s",
                f"Cache valid: {info.get('cache_valid', False)}",
                f"Schema version: {info.get('schema_version', 'unknown')}",
                f"Last updated: {info.get('updated_at', 'unknown')}",
                f"Total plugins: {info.get('total_plugins', 'unknown')}",
                f"Cache fetched: {info.get('cache_fetched_at', 'never')}",
            ])
            console.print(Panel(panel_content, title="Registry Info"))
            return

        # Default: show summary
        try:
            entries = registry.fetch()
            verified = [e for e in entries.values() if e.verified and not e.deprecated]
            console.print(f"Registry: {len(verified)} verified plugins available")
            console.print("Use 'tweek plugins search' to browse or 'tweek plugins registry --refresh' to update cache")
        except Exception as e:
            console.print(f"[yellow]Registry unavailable: {e}[/yellow]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
