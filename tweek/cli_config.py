#!/usr/bin/env python3
"""
Tweek CLI Config Management

Commands for configuring Tweek security policies:
    tweek config list               List all tools and skills with security tiers
    tweek config set                Set security tier for a skill or tool
    tweek config preset             Apply a configuration preset
    tweek config reset              Reset configuration to defaults
    tweek config validate           Validate configuration for errors
    tweek config diff               Show what would change if a preset were applied
    tweek config llm                Show LLM review configuration and provider status
    tweek config edit               Open config files in your editor
    tweek config show-defaults      View bundled default configuration
"""

import click
from rich.panel import Panel
from rich.table import Table

from tweek.cli_helpers import console, TWEEK_BANNER


@click.group()
def config():
    """Configure Tweek security policies."""
    pass


@config.command("list",
    epilog="""\b
Examples:
  tweek config list                      List all tools and skills
  tweek config list --tools              Show only tool security tiers
  tweek config list --skills             Show only skill security tiers
  tweek config list --summary            Show tier counts and overrides summary
"""
)
@click.option("--tools", "show_tools", is_flag=True, help="Show tools only")
@click.option("--skills", "show_skills", is_flag=True, help="Show skills only")
@click.option("--summary", is_flag=True, help="Show configuration summary instead of full list")
def config_list(show_tools: bool, show_skills: bool, summary: bool):
    """List all tools and skills with their security tiers."""
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()

    # Handle summary mode
    if summary:
        # Count by tier
        tool_tiers = {}
        for tool in cfg.list_tools():
            tier = tool.tier.value
            tool_tiers[tier] = tool_tiers.get(tier, 0) + 1

        skill_tiers = {}
        for skill in cfg.list_skills():
            tier = skill.tier.value
            skill_tiers[tier] = skill_tiers.get(tier, 0) + 1

        # User overrides
        user_config = cfg.export_config("user")
        user_tools = user_config.get("tools", {})
        user_skills = user_config.get("skills", {})

        summary_text = f"[cyan]Default Tier:[/cyan] {cfg.get_default_tier().value}\n\n"

        summary_text += "[cyan]Tools by Tier:[/cyan]\n"
        for tier in ["safe", "default", "risky", "dangerous"]:
            count = tool_tiers.get(tier, 0)
            if count:
                summary_text += f"  {tier}: {count}\n"

        summary_text += "\n[cyan]Skills by Tier:[/cyan]\n"
        for tier in ["safe", "default", "risky", "dangerous"]:
            count = skill_tiers.get(tier, 0)
            if count:
                summary_text += f"  {tier}: {count}\n"

        if user_tools or user_skills:
            summary_text += "\n[cyan]User Overrides:[/cyan]\n"
            for tool_name, tier in user_tools.items():
                summary_text += f"  {tool_name}: {tier}\n"
            for skill_name, tier in user_skills.items():
                summary_text += f"  {skill_name}: {tier}\n"
        else:
            summary_text += "\n[cyan]User Overrides:[/cyan] (none)"

        console.print(Panel.fit(summary_text, title="Tweek Configuration"))
        return

    # Default to showing both if neither specified
    if not show_tools and not show_skills:
        show_tools = show_skills = True

    tier_styles = {
        "safe": "green",
        "default": "blue",
        "risky": "yellow",
        "dangerous": "red",
    }

    source_styles = {
        "default": "white",
        "user": "cyan",
        "project": "magenta",
    }

    if show_tools:
        table = Table(title="Tool Security Tiers")
        table.add_column("Tool", style="bold")
        table.add_column("Tier")
        table.add_column("Source", style="white")
        table.add_column("Description")

        for tool in cfg.list_tools():
            tier_style = tier_styles.get(tool.tier.value, "white")
            source_style = source_styles.get(tool.source, "white")
            table.add_row(
                tool.name,
                f"[{tier_style}]{tool.tier.value}[/{tier_style}]",
                f"[{source_style}]{tool.source}[/{source_style}]",
                tool.description or ""
            )

        console.print(table)
        console.print()

    if show_skills:
        table = Table(title="Skill Security Tiers")
        table.add_column("Skill", style="bold")
        table.add_column("Tier")
        table.add_column("Source", style="white")
        table.add_column("Description")

        for skill in cfg.list_skills():
            tier_style = tier_styles.get(skill.tier.value, "white")
            source_style = source_styles.get(skill.source, "white")
            table.add_row(
                skill.name,
                f"[{tier_style}]{skill.tier.value}[/{tier_style}]",
                f"[{source_style}]{skill.source}[/{source_style}]",
                skill.description or ""
            )

        console.print(table)

    console.print("\n[white]Tiers: safe (no checks) \u2192 default (regex) \u2192 risky (+LLM) \u2192 dangerous (+sandbox)[/white]")
    console.print("[white]Sources: default (built-in), user (~/.tweek/config.yaml), project (.tweek/config.yaml)[/white]")


@config.command("set",
    epilog="""\b
Examples:
  tweek config set --tool Bash --tier dangerous       Mark Bash as dangerous
  tweek config set --skill web-fetch --tier risky     Set skill to risky tier
  tweek config set --tier cautious                    Set default tier for all
  tweek config set --tool Edit --tier safe --scope project   Project-level override
"""
)
@click.option("--skill", help="Skill name to configure")
@click.option("--tool", help="Tool name to configure")
@click.option("--tier", type=click.Choice(["safe", "default", "risky", "dangerous"]), required=True,
              help="Security tier to set")
@click.option("--scope", type=click.Choice(["user", "project"]), default="user",
              help="Config scope (user=global, project=this directory)")
def config_set(skill: str, tool: str, tier: str, scope: str):
    """Set security tier for a skill or tool."""
    from tweek.config.manager import ConfigManager, SecurityTier

    cfg = ConfigManager()
    tier_enum = SecurityTier.from_string(tier)

    if skill:
        cfg.set_skill_tier(skill, tier_enum, scope=scope)
        console.print(f"[green]\u2713[/green] Set skill '{skill}' to [bold]{tier}[/bold] tier ({scope} config)")
    elif tool:
        cfg.set_tool_tier(tool, tier_enum, scope=scope)
        console.print(f"[green]\u2713[/green] Set tool '{tool}' to [bold]{tier}[/bold] tier ({scope} config)")
    else:
        cfg.set_default_tier(tier_enum, scope=scope)
        console.print(f"[green]\u2713[/green] Set default tier to [bold]{tier}[/bold] ({scope} config)")


@config.command("preset",
    epilog="""\b
Examples:
  tweek config preset paranoid           Maximum security, prompt for everything
  tweek config preset cautious           Balanced security (recommended)
  tweek config preset trusted            Minimal prompts, trust AI decisions
  tweek config preset paranoid --scope project   Apply preset to project only
"""
)
@click.argument("preset_name", type=click.Choice(["paranoid", "cautious", "trusted"]))
@click.option("--scope", type=click.Choice(["user", "project"]), default="user")
def config_preset(preset_name: str, scope: str):
    """Apply a configuration preset.

    Presets:
        paranoid  - Maximum security, prompt for everything
        cautious  - Balanced security (recommended)
        trusted   - Minimal prompts, trust AI decisions
    """
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()
    cfg.apply_preset(preset_name, scope=scope)

    console.print(f"[green]\u2713[/green] Applied [bold]{preset_name}[/bold] preset ({scope} config)")

    if preset_name == "paranoid":
        console.print("[white]All tools require screening, Bash commands always sandboxed[/white]")
    elif preset_name == "cautious":
        console.print("[white]Balanced: read-only tools safe, Bash dangerous[/white]")
    elif preset_name == "trusted":
        console.print("[white]Minimal prompts: only high-risk patterns trigger alerts[/white]")


@config.command("reset",
    epilog="""\b
Examples:
  tweek config reset --tool Bash         Reset Bash to default tier
  tweek config reset --skill web-fetch   Reset a skill to default tier
  tweek config reset --all               Reset all user configuration
  tweek config reset --all --confirm     Reset all without confirmation prompt
"""
)
@click.option("--skill", help="Reset specific skill to default")
@click.option("--tool", help="Reset specific tool to default")
@click.option("--all", "reset_all", is_flag=True, help="Reset all user configuration")
@click.option("--scope", type=click.Choice(["user", "project"]), default="user")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def config_reset(skill: str, tool: str, reset_all: bool, scope: str, confirm: bool):
    """Reset configuration to defaults."""
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()

    if reset_all:
        if not confirm and not click.confirm(f"Reset ALL {scope} configuration?"):
            console.print("[white]Cancelled[/white]")
            return
        cfg.reset_all(scope=scope)
        console.print(f"[green]\u2713[/green] Reset all {scope} configuration to defaults")
    elif skill:
        if cfg.reset_skill(skill, scope=scope):
            console.print(f"[green]\u2713[/green] Reset skill '{skill}' to default")
        else:
            console.print(f"[yellow]![/yellow] Skill '{skill}' has no {scope} override")
    elif tool:
        if cfg.reset_tool(tool, scope=scope):
            console.print(f"[green]\u2713[/green] Reset tool '{tool}' to default")
        else:
            console.print(f"[yellow]![/yellow] Tool '{tool}' has no {scope} override")
    else:
        console.print("[red]Specify --skill, --tool, or --all[/red]")


@config.command("validate",
    epilog="""\b
Examples:
  tweek config validate                  Validate merged configuration
  tweek config validate --scope user     Validate only user-level config
  tweek config validate --scope project  Validate only project-level config
  tweek config validate --json           Output validation results as JSON
"""
)
@click.option("--scope", type=click.Choice(["user", "project", "merged"]), default="merged",
              help="Which config scope to validate")
@click.option("--json-output", "--json", "json_out", is_flag=True, help="Output as JSON")
def config_validate(scope: str, json_out: bool):
    """Validate configuration for errors and typos.

    Checks for unknown keys, invalid tier values, unknown tool/skill names,
    and suggests corrections for typos.
    """
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()
    issues = cfg.validate_config(scope=scope)

    if json_out:
        import json as json_mod
        output = [
            {
                "level": i.level,
                "key": i.key,
                "message": i.message,
                "suggestion": i.suggestion,
            }
            for i in issues
        ]
        console.print_json(json_mod.dumps(output, indent=2))
        return

    console.print()
    console.print("[bold]Configuration Validation[/bold]")
    console.print("\u2500" * 40)
    console.print(f"[white]Scope: {scope}[/white]")
    console.print()

    if not issues:
        tools = cfg.list_tools()
        skills = cfg.list_skills()
        console.print(f"  [green]OK[/green]  Configuration valid ({len(tools)} tools, {len(skills)} skills)")
        console.print()
        return

    errors = [i for i in issues if i.level == "error"]
    warnings = [i for i in issues if i.level == "warning"]

    level_styles = {
        "error": "[red]ERROR[/red]",
        "warning": "[yellow]WARN[/yellow] ",
        "info": "[white]INFO[/white] ",
    }

    for issue in issues:
        style = level_styles.get(issue.level, "[white]???[/white]  ")
        msg = f"  {style}  {issue.key} \u2192 {issue.message}"
        if issue.suggestion:
            msg += f" {issue.suggestion}"
        console.print(msg)

    console.print()
    parts = []
    if errors:
        parts.append(f"{len(errors)} error{'s' if len(errors) != 1 else ''}")
    if warnings:
        parts.append(f"{len(warnings)} warning{'s' if len(warnings) != 1 else ''}")
    console.print(f"  Result: {', '.join(parts)}")
    console.print()


@config.command("diff",
    epilog="""\b
Examples:
  tweek config diff paranoid             Show changes if paranoid preset applied
  tweek config diff cautious             Show changes if cautious preset applied
  tweek config diff trusted              Show changes if trusted preset applied
"""
)
@click.argument("preset_name", type=click.Choice(["paranoid", "cautious", "trusted"]))
def config_diff(preset_name: str):
    """Show what would change if a preset were applied.

    Compare your current configuration against a preset to see
    exactly which settings would be modified.
    """
    from tweek.config.manager import ConfigManager

    cfg = ConfigManager()

    try:
        changes = cfg.diff_preset(preset_name)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        return

    console.print()
    console.print(f"[bold]Changes if '{preset_name}' preset is applied:[/bold]")
    console.print("\u2500" * 50)

    if not changes:
        console.print()
        console.print("  [green]No changes[/green] \u2014 your config already matches this preset.")
        console.print()
        return

    table = Table(show_header=True, show_edge=False, pad_edge=False)
    table.add_column("Setting", style="cyan", min_width=25)
    table.add_column("Current", min_width=12)
    table.add_column("", min_width=3)
    table.add_column("New", min_width=12)

    tier_colors = {"safe": "green", "default": "white", "risky": "yellow", "dangerous": "red"}

    for change in changes:
        cur_color = tier_colors.get(str(change.current_value), "white")
        new_color = tier_colors.get(str(change.new_value), "white")
        table.add_row(
            change.key,
            f"[{cur_color}]{change.current_value}[/{cur_color}]",
            "\u2192",
            f"[{new_color}]{change.new_value}[/{new_color}]",
        )

    console.print()
    console.print(table)
    console.print()
    console.print(f"  {len(changes)} change{'s' if len(changes) != 1 else ''} would be made. "
                  f"Apply with: [cyan]tweek config preset {preset_name}[/cyan]")
    console.print()


@config.command("llm",
    epilog="""\b
Examples:
  tweek config llm                        Show current LLM provider status
  tweek config llm --verbose              Show detailed provider information
  tweek config llm --validate             Re-run local model validation suite
"""
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed provider info")
@click.option("--validate", is_flag=True, help="Re-run local model validation suite")
def config_llm(verbose: bool, validate: bool):
    """Show LLM review configuration and provider status.

    Displays the current LLM review provider, model, and availability.
    With --verbose, shows local server detection and fallback chain details.
    With --validate, re-runs the validation suite against local models.
    """
    from tweek.security.llm_reviewer import (
        get_llm_reviewer,
        _detect_local_server,
        _validate_local_model,
        FallbackReviewProvider,
        LOCAL_MODEL_PREFERENCES,
    )

    console.print()
    console.print("[bold]LLM Review Configuration[/bold]")
    console.print("\u2500" * 45)

    reviewer = get_llm_reviewer()

    if not reviewer.enabled:
        console.print()
        console.print("  [yellow]Status:[/yellow] Disabled (no provider available)")
        console.print()
        console.print("  [white]To enable, set one of:[/white]")
        console.print("    ANTHROPIC_API_KEY, OPENAI_API_KEY, or GOOGLE_API_KEY")
        console.print("    Or install Ollama: [cyan]https://ollama.ai[/cyan]")
        console.print()
        return

    console.print()
    console.print(f"  [green]Status:[/green]   Enabled")
    console.print(f"  [cyan]Provider:[/cyan] {reviewer.provider_name}")
    console.print(f"  [cyan]Model:[/cyan]    {reviewer.model}")

    # Check for fallback chain
    provider = reviewer._provider_instance
    if isinstance(provider, FallbackReviewProvider):
        console.print(f"  [cyan]Chain:[/cyan]    {provider.provider_count} providers in fallback chain")
        if provider.active_provider:
            console.print(f"  [cyan]Active:[/cyan]   {provider.active_provider.name}")

    # Local server detection
    if verbose:
        console.print()
        console.print("[bold]Local LLM Servers[/bold]")
        console.print("\u2500" * 45)

        try:
            server = _detect_local_server()
            if server:
                console.print(f"  [green]Detected:[/green] {server.server_type}")
                console.print(f"  [cyan]URL:[/cyan]      {server.base_url}")
                console.print(f"  [cyan]Model:[/cyan]    {server.model}")
                console.print(f"  [cyan]Available:[/cyan] {len(server.all_models)} model{'s' if len(server.all_models) != 1 else ''}")
                if len(server.all_models) <= 10:
                    for m in server.all_models:
                        console.print(f"    - {m}")
            else:
                console.print("  [white]No local LLM server detected[/white]")
                console.print("  [white]Checked: Ollama (localhost:11434), LM Studio (localhost:1234)[/white]")
        except Exception as e:
            console.print(f"  [yellow]Detection error: {e}[/yellow]")

        console.print()
        console.print("[bold]Recommended Local Models[/bold]")
        console.print("\u2500" * 45)
        for i, model_name in enumerate(LOCAL_MODEL_PREFERENCES[:5], 1):
            console.print(f"  {i}. {model_name}")

    # Validation mode
    if validate:
        console.print()
        console.print("[bold]Model Validation[/bold]")
        console.print("\u2500" * 45)

        try:
            server = _detect_local_server()
            if not server:
                console.print("  [yellow]No local server detected. Nothing to validate.[/yellow]")
                console.print()
                return

            from tweek.security.llm_reviewer import OpenAIReviewProvider
            local_prov = OpenAIReviewProvider(
                model=server.model,
                api_key="not-needed",
                timeout=10.0,
                base_url=server.base_url,
            )

            console.print(f"  Validating [cyan]{server.model}[/cyan] on {server.server_type}...")
            passed, score = _validate_local_model(local_prov, server.model)

            if passed:
                console.print(f"  [green]PASSED[/green] ({score:.0%})")
            else:
                console.print(f"  [red]FAILED[/red] ({score:.0%}, minimum: 60%)")
                console.print("  [white]This model may not reliably classify security threats.[/white]")
                console.print("  [white]Try a larger model: ollama pull qwen2.5:7b-instruct[/white]")
        except Exception as e:
            console.print(f"  [red]Validation error: {e}[/red]")

    console.print()


@config.command("edit",
    epilog="""\b
Examples:
  tweek config edit                Open interactive file selector
  tweek config edit config         Open security settings directly
  tweek config edit env            Open API keys file
  tweek config edit overrides      Open security overrides
  tweek config edit hooks          Open hook control file
  tweek config edit --create       Create missing files from templates first
"""
)
@click.argument("file_id", required=False, default=None)
@click.option("--create", "create_missing", is_flag=True,
              help="Create missing config files from templates")
def config_edit(file_id: str, create_missing: bool):
    """Open Tweek configuration files in your editor.

    Lists all config files with descriptions and status, then opens
    the selected file in $VISUAL, $EDITOR, or a platform default.
    """
    import os
    import shutil
    import subprocess
    from pathlib import Path
    from tweek.config.templates import CONFIG_FILES, deploy_template, resolve_target_path

    # Determine editor
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR")
    if not editor:
        for candidate in ["nano", "vim", "vi"]:
            if shutil.which(candidate):
                editor = candidate
                break
    if not editor:
        console.print("[red]No editor found. Set $EDITOR or $VISUAL.[/red]")
        return

    # Build file list with resolved paths and existence status
    entries = []
    for entry in CONFIG_FILES:
        target = resolve_target_path(entry)
        entries.append({**entry, "resolved_path": target, "exists": target.exists()})

    # Direct access by ID
    if file_id:
        valid_ids = [e["id"] for e in entries]
        if file_id not in valid_ids:
            console.print(f"[red]Unknown file: {file_id}[/red]")
            console.print(f"[white]Valid options: {', '.join(valid_ids)}[/white]")
            return
        selected = next(e for e in entries if e["id"] == file_id)
        _open_config_file(selected, editor, create_missing)
        return

    # Interactive: show file list
    console.print()
    console.print("[bold]Tweek Configuration Files[/bold]")
    console.print("\u2500" * 70)

    for i, entry in enumerate(entries, 1):
        if not entry["editable"]:
            status = "[dim](read-only)[/dim]"
        elif entry["exists"]:
            status = "[green]\u2713 exists[/green]"
        else:
            status = "[yellow]\u2717 missing[/yellow]"

        path_display = str(entry["resolved_path"]).replace(str(Path.home()), "~")
        console.print(f"  [cyan]{i}.[/cyan] {entry['name']:<22s} {path_display}")
        console.print(f"     {status}  [dim]{entry['description']}[/dim]")

    console.print()

    choice = click.prompt(
        f"Select file (1-{len(entries)})",
        type=click.IntRange(1, len(entries)),
    )

    selected = entries[choice - 1]
    _open_config_file(selected, editor, create_missing)


def _open_config_file(entry: dict, editor: str, create_missing: bool):
    """Open a single config file in the user's editor."""
    import os
    import subprocess
    from tweek.config.templates import deploy_template

    target = entry["resolved_path"]

    if not entry["editable"]:
        pager = os.environ.get("PAGER", "less")
        console.print(f"[white]Opening read-only reference: {target}[/white]")
        subprocess.run([pager, str(target)])
        return

    if not target.exists():
        if create_missing or click.confirm(
            f"  {entry['name']} does not exist. Create from template?", default=True
        ):
            if entry.get("template"):
                deploy_template(entry["template"], target)
                console.print(f"[green]\u2713[/green] Created {target} from template")
            else:
                console.print(f"[yellow]No template available for {entry['name']}[/yellow]")
                return
        else:
            return

    console.print(f"[white]Opening: {target}[/white]")
    subprocess.run([editor, str(target)])


@config.command("show-defaults")
def config_show_defaults():
    """Display the bundled default configuration.

    Shows all available options with their default values from tiers.yaml.
    This is read-only — to override, edit ~/.tweek/config.yaml.
    """
    import os
    import subprocess
    from pathlib import Path

    defaults_path = Path(__file__).resolve().parent / "config" / "tiers.yaml"
    if not defaults_path.exists():
        console.print("[red]Default configuration not found[/red]")
        return

    pager = os.environ.get("PAGER", "less")
    subprocess.run([pager, str(defaults_path)])
