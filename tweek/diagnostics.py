#!/usr/bin/env python3
"""
Tweek Diagnostics Engine

Health check system for verifying Tweek installation, configuration,
and runtime dependencies. Used by `tweek doctor` and the health banner.
"""

import json
import os
import sqlite3
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple


class CheckStatus(Enum):
    """Health check result status."""
    OK = "ok"
    WARNING = "warning"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class HealthCheck:
    """Result of a single health check."""
    name: str           # Machine name: "hooks_installed"
    label: str          # Human label: "Hook Installation"
    status: CheckStatus
    message: str        # Description: "Global hooks installed at ~/.claude/"
    fix_hint: str = ""  # Recovery: "Run: tweek protect claude-code --global"


def run_health_checks(verbose: bool = False) -> List[HealthCheck]:
    """
    Run all health checks and return results.

    Args:
        verbose: If True, include extra detail in messages.

    Returns:
        List of HealthCheck results in check order.
    """
    checks = [
        _check_hooks_installed,
        _check_config_valid,
        _check_patterns_loaded,
        _check_security_db,
        _check_vault_available,
        _check_sandbox_available,
        _check_license_status,
        _check_mcp_available,
        _check_proxy_config,
        _check_plugin_integrity,
        _check_llm_review,
    ]

    results = []
    for check_fn in checks:
        try:
            result = check_fn(verbose)
            results.append(result)
        except Exception as e:
            results.append(HealthCheck(
                name=check_fn.__name__.replace("_check_", ""),
                label=check_fn.__name__.replace("_check_", "").replace("_", " ").title(),
                status=CheckStatus.ERROR,
                message=f"Check failed: {e}",
                fix_hint="This may indicate a corrupted installation. Try: pip install --force-reinstall tweek",
            ))

    # Log health check results
    try:
        from tweek.logging.security_log import get_logger, SecurityEvent, EventType

        checks_passed = sum(1 for c in results if c.status == CheckStatus.OK)
        checks_failed = sum(1 for c in results if c.status == CheckStatus.ERROR)
        checks_warning = sum(1 for c in results if c.status == CheckStatus.WARNING)

        if checks_failed > 0:
            overall_status = "error"
        elif checks_warning > 0:
            overall_status = "warning"
        else:
            overall_status = "ok"

        get_logger().log(SecurityEvent(
            event_type=EventType.HEALTH_CHECK,
            tool_name="diagnostics",
            decision="allow",
            metadata={
                "overall_status": overall_status,
                "checks_passed": checks_passed,
                "checks_failed": checks_failed,
                "checks_warning": checks_warning,
            },
            source="diagnostics",
        ))
    except Exception:
        pass

    return results


def get_health_verdict(checks: List[HealthCheck]) -> Tuple[str, str]:
    """
    Compute an overall health verdict from check results.

    Returns:
        Tuple of (verdict_text, color) for Rich display.
    """
    ok_count = sum(1 for c in checks if c.status == CheckStatus.OK)
    warn_count = sum(1 for c in checks if c.status == CheckStatus.WARNING)
    error_count = sum(1 for c in checks if c.status == CheckStatus.ERROR)
    skip_count = sum(1 for c in checks if c.status == CheckStatus.SKIPPED)
    total = len(checks)

    if error_count == 0 and warn_count == 0:
        return f"All systems operational ({ok_count}/{total - skip_count} OK)", "green"
    elif error_count == 0:
        return (
            f"Mostly healthy ({ok_count} OK, {warn_count} warning{'s' if warn_count != 1 else ''})",
            "yellow",
        )
    elif error_count <= 2:
        return (
            f"Issues detected ({ok_count} OK, {error_count} error{'s' if error_count != 1 else ''}, "
            f"{warn_count} warning{'s' if warn_count != 1 else ''})",
            "red",
        )
    else:
        return f"Multiple issues ({error_count} errors, {warn_count} warnings)", "red"


# ==================== Individual Health Checks ====================


def _check_hooks_installed(verbose: bool = False) -> HealthCheck:
    """Check if Tweek hooks are installed in Claude Code settings."""
    global_claude = Path("~/.claude").expanduser()
    project_claude = Path.cwd() / ".claude"

    global_installed = _has_tweek_hooks(global_claude / "settings.json")
    project_installed = _has_tweek_hooks(project_claude / "settings.json")

    if global_installed and project_installed:
        return HealthCheck(
            name="hooks_installed",
            label="Hook Installation",
            status=CheckStatus.OK,
            message="Installed globally (~/.claude) and in project (./.claude)",
        )
    elif global_installed:
        msg = "Installed globally (~/.claude)"
        if verbose:
            msg += " — project-level hooks not configured"
        return HealthCheck(
            name="hooks_installed",
            label="Hook Installation",
            status=CheckStatus.OK,
            message=msg,
        )
    elif project_installed:
        return HealthCheck(
            name="hooks_installed",
            label="Hook Installation",
            status=CheckStatus.WARNING,
            message="Installed in project only (./.claude)",
            fix_hint="Run: tweek protect claude-code --global  (to protect all projects)",
        )
    else:
        return HealthCheck(
            name="hooks_installed",
            label="Hook Installation",
            status=CheckStatus.ERROR,
            message="No hooks installed",
            fix_hint="Run: tweek protect claude-code",
        )


def _has_tweek_hooks(settings_path: Path) -> bool:
    """Check if a settings.json file contains Tweek hooks."""
    if not settings_path.exists():
        return False
    try:
        with open(settings_path) as f:
            settings = json.load(f)
        hooks = settings.get("hooks", {})
        for hook_type in ["PreToolUse", "PostToolUse"]:
            for hook_config in hooks.get(hook_type, []):
                for hook in hook_config.get("hooks", []):
                    if "tweek" in hook.get("command", "").lower():
                        return True
    except (json.JSONDecodeError, IOError, KeyError):
        pass
    return False


def _check_config_valid(verbose: bool = False) -> HealthCheck:
    """Check that configuration files parse correctly."""
    from tweek.config import ConfigManager

    try:
        config = ConfigManager()
        tools = config.list_tools()
        skills = config.list_skills()

        # Check for validation issues if the method exists
        issues = []
        if hasattr(config, "validate_config"):
            issues = config.validate_config()
            errors = [i for i in issues if i.level == "error"]
            warnings = [i for i in issues if i.level == "warning"]
            if errors:
                return HealthCheck(
                    name="config_valid",
                    label="Configuration",
                    status=CheckStatus.ERROR,
                    message=f"{len(errors)} config error{'s' if len(errors) != 1 else ''}",
                    fix_hint="Run: tweek config validate  (for details)",
                )
            if warnings:
                return HealthCheck(
                    name="config_valid",
                    label="Configuration",
                    status=CheckStatus.WARNING,
                    message=f"Config valid with {len(warnings)} warning{'s' if len(warnings) != 1 else ''} "
                            f"({len(tools)} tools, {len(skills)} skills)",
                    fix_hint="Run: tweek config validate  (for details)",
                )

        return HealthCheck(
            name="config_valid",
            label="Configuration",
            status=CheckStatus.OK,
            message=f"Config valid ({len(tools)} tools, {len(skills)} skills)",
        )
    except Exception as e:
        return HealthCheck(
            name="config_valid",
            label="Configuration",
            status=CheckStatus.ERROR,
            message=f"Failed to load config: {e}",
            fix_hint="Run: tweek config validate  (to see errors)",
        )


def _check_patterns_loaded(verbose: bool = False) -> HealthCheck:
    """Check that attack patterns are loaded and accessible."""
    user_patterns = Path("~/.tweek/patterns/patterns.yaml").expanduser()
    bundled_patterns = Path(__file__).parent / "config" / "patterns.yaml"

    patterns_file = None
    source = None

    if user_patterns.exists():
        patterns_file = user_patterns
        source = "~/.tweek/patterns"
    elif bundled_patterns.exists():
        patterns_file = bundled_patterns
        source = "bundled"

    if patterns_file is None:
        return HealthCheck(
            name="patterns_loaded",
            label="Attack Patterns",
            status=CheckStatus.ERROR,
            message="No patterns file found",
            fix_hint="Run: tweek update  (to download patterns)",
        )

    try:
        import yaml
        with open(patterns_file) as f:
            pdata = yaml.safe_load(f) or {}

        count = pdata.get("pattern_count", len(pdata.get("patterns", [])))
        if count == 0:
            return HealthCheck(
                name="patterns_loaded",
                label="Attack Patterns",
                status=CheckStatus.WARNING,
                message=f"Patterns file found ({source}) but contains 0 patterns",
                fix_hint="Run: tweek update --force  (to re-download patterns)",
            )

        return HealthCheck(
            name="patterns_loaded",
            label="Attack Patterns",
            status=CheckStatus.OK,
            message=f"{count:,} patterns loaded ({source})",
        )
    except Exception as e:
        return HealthCheck(
            name="patterns_loaded",
            label="Attack Patterns",
            status=CheckStatus.ERROR,
            message=f"Failed to parse patterns: {e}",
            fix_hint="Run: tweek update --force  (to re-download patterns)",
        )


def _check_security_db(verbose: bool = False) -> HealthCheck:
    """Check that the security database exists and is accessible."""
    db_path = Path("~/.tweek/security.db").expanduser()

    if not db_path.exists():
        return HealthCheck(
            name="security_db",
            label="Security Database",
            status=CheckStatus.OK,
            message="Not yet created (will be created on first event)",
        )

    try:
        size_bytes = db_path.stat().st_size
        size_mb = size_bytes / (1024 * 1024)

        # Test that we can open it
        conn = sqlite3.connect(str(db_path))
        conn.execute("SELECT 1")
        conn.close()

        if size_mb > 100:
            return HealthCheck(
                name="security_db",
                label="Security Database",
                status=CheckStatus.WARNING,
                message=f"DB is {size_mb:.0f}MB — consider cleanup",
                fix_hint="Run: tweek logs clear --older-than 30d",
            )
        elif size_mb > 10:
            return HealthCheck(
                name="security_db",
                label="Security Database",
                status=CheckStatus.OK,
                message=f"Active ({size_mb:.1f}MB)",
            )
        else:
            return HealthCheck(
                name="security_db",
                label="Security Database",
                status=CheckStatus.OK,
                message=f"Active ({size_mb:.1f}MB)" if size_mb >= 0.1 else "Active (< 100KB)",
            )
    except sqlite3.Error as e:
        return HealthCheck(
            name="security_db",
            label="Security Database",
            status=CheckStatus.ERROR,
            message=f"Cannot open database: {e}",
            fix_hint="Check file permissions on ~/.tweek/security.db",
        )


def _check_vault_available(verbose: bool = False) -> HealthCheck:
    """Check credential vault availability."""
    try:
        from tweek.platform import get_capabilities
        caps = get_capabilities()

        if caps.vault_available:
            return HealthCheck(
                name="vault_available",
                label="Credential Vault",
                status=CheckStatus.OK,
                message=f"{caps.vault_backend} available",
            )
        else:
            return HealthCheck(
                name="vault_available",
                label="Credential Vault",
                status=CheckStatus.WARNING,
                message="No vault backend available",
                fix_hint="Vault enables secure credential storage. "
                         "Install system keyring support for your platform.",
            )
    except ImportError:
        return HealthCheck(
            name="vault_available",
            label="Credential Vault",
            status=CheckStatus.WARNING,
            message="Platform module not available",
        )


def _check_sandbox_available(verbose: bool = False) -> HealthCheck:
    """Check sandbox availability (platform-dependent)."""
    try:
        from tweek.sandbox import get_sandbox_status
        from tweek.platform import IS_LINUX

        status = get_sandbox_status()

        if status.get("available"):
            return HealthCheck(
                name="sandbox_available",
                label="Sandbox",
                status=CheckStatus.OK,
                message=f"{status.get('tool', 'Available')} available",
            )
        elif IS_LINUX:
            return HealthCheck(
                name="sandbox_available",
                label="Sandbox",
                status=CheckStatus.WARNING,
                message="firejail not installed",
                fix_hint="Install firejail: sudo apt install firejail",
            )
        else:
            return HealthCheck(
                name="sandbox_available",
                label="Sandbox",
                status=CheckStatus.SKIPPED,
                message="Not available on this platform",
            )
    except ImportError:
        return HealthCheck(
            name="sandbox_available",
            label="Sandbox",
            status=CheckStatus.SKIPPED,
            message="Sandbox module not available",
        )


def _check_license_status(verbose: bool = False) -> HealthCheck:
    """Check license status."""
    try:
        from tweek.licensing import get_license, Tier

        lic = get_license()

        if lic.tier == Tier.FREE:
            return HealthCheck(
                name="license_status",
                label="License",
                status=CheckStatus.OK,
                message="Open source (all features included)",
            )
        elif lic.info and lic.info.is_expired:
            return HealthCheck(
                name="license_status",
                label="License",
                status=CheckStatus.WARNING,
                message=f"{lic.tier.value.upper()} license expired",
                fix_hint="Pro and Enterprise tiers coming soon: gettweek.com",
            )
        else:
            email = lic.info.email if lic.info else "unknown"
            return HealthCheck(
                name="license_status",
                label="License",
                status=CheckStatus.OK,
                message=f"{lic.tier.value.upper()} license ({email})",
            )
    except Exception as e:
        return HealthCheck(
            name="license_status",
            label="License",
            status=CheckStatus.WARNING,
            message=f"Cannot check license: {e}",
        )


def _check_mcp_available(verbose: bool = False) -> HealthCheck:
    """Check if MCP dependencies are available."""
    try:
        import mcp  # noqa: F401
        return HealthCheck(
            name="mcp_available",
            label="MCP Server",
            status=CheckStatus.OK,
            message="MCP package installed",
        )
    except ImportError:
        return HealthCheck(
            name="mcp_available",
            label="MCP Server",
            status=CheckStatus.SKIPPED,
            message="MCP package not installed (optional)",
            fix_hint="Install with: pip install tweek[mcp]",
        )


def _check_proxy_config(verbose: bool = False) -> HealthCheck:
    """Check proxy configuration if present."""
    try:
        from tweek.config import ConfigManager
        config = ConfigManager()
        full_config = config.get_full_config()

        proxy_config = full_config.get("proxy", {})
        mcp_config = full_config.get("mcp", {})

        if not proxy_config and not mcp_config:
            return HealthCheck(
                name="proxy_config",
                label="Proxy Config",
                status=CheckStatus.SKIPPED,
                message="No proxy or MCP proxy configured",
            )

        issues = []

        # Check MCP proxy upstreams
        mcp_proxy = mcp_config.get("proxy", {})
        upstreams = mcp_proxy.get("upstreams", {})
        if upstreams:
            for name, upstream in upstreams.items():
                if not upstream.get("command"):
                    issues.append(f"MCP upstream '{name}' missing 'command'")

        if issues:
            return HealthCheck(
                name="proxy_config",
                label="Proxy Config",
                status=CheckStatus.WARNING,
                message="; ".join(issues),
                fix_hint="Check proxy configuration in ~/.tweek/config.yaml",
            )

        parts = []
        if proxy_config:
            parts.append("HTTP proxy configured")
        if upstreams:
            parts.append(f"MCP proxy: {len(upstreams)} upstream{'s' if len(upstreams) != 1 else ''}")

        return HealthCheck(
            name="proxy_config",
            label="Proxy Config",
            status=CheckStatus.OK,
            message=", ".join(parts) if parts else "Configured",
        )
    except Exception as e:
        return HealthCheck(
            name="proxy_config",
            label="Proxy Config",
            status=CheckStatus.WARNING,
            message=f"Cannot check proxy config: {e}",
        )


def _check_plugin_integrity(verbose: bool = False) -> HealthCheck:
    """Check installed plugin integrity."""
    try:
        from tweek.plugins import init_plugins

        registry = init_plugins()
        stats = registry.get_stats()
        total = stats.get("total", 0)
        enabled = stats.get("enabled", 0)

        if total == 0:
            return HealthCheck(
                name="plugin_integrity",
                label="Plugin Integrity",
                status=CheckStatus.OK,
                message="No plugins installed",
            )

        # Check for plugins with load errors
        all_plugins = registry.list_plugins()
        errors = [p for p in all_plugins if p.load_error]

        if errors:
            error_names = ", ".join(p.name for p in errors[:3])
            suffix = f" (+{len(errors) - 3} more)" if len(errors) > 3 else ""
            return HealthCheck(
                name="plugin_integrity",
                label="Plugin Integrity",
                status=CheckStatus.WARNING,
                message=f"{len(errors)} plugin{'s' if len(errors) != 1 else ''} with errors: {error_names}{suffix}",
                fix_hint="Run: tweek plugins verify  (for details)",
            )

        return HealthCheck(
            name="plugin_integrity",
            label="Plugin Integrity",
            status=CheckStatus.OK,
            message=f"{enabled}/{total} plugins verified",
        )
    except Exception as e:
        return HealthCheck(
            name="plugin_integrity",
            label="Plugin Integrity",
            status=CheckStatus.WARNING,
            message=f"Cannot check plugins: {e}",
        )


def _check_llm_review(verbose: bool = False) -> HealthCheck:
    """Check LLM review provider availability and configuration."""
    try:
        from tweek.security.llm_reviewer import (
            get_llm_reviewer,
            _detect_local_server,
            FallbackReviewProvider,
            DEFAULT_API_KEY_ENVS,
        )
        from tweek.security.local_model import LOCAL_MODEL_AVAILABLE

        reviewer = get_llm_reviewer()

        if not reviewer.enabled:
            # Check which env vars are missing to give specific guidance
            missing_keys = []
            for provider, env_names in DEFAULT_API_KEY_ENVS.items():
                if isinstance(env_names, list):
                    if not any(os.environ.get(e) for e in env_names):
                        missing_keys.append(f"{' or '.join(env_names)} ({provider})")
                else:
                    if not os.environ.get(env_names):
                        missing_keys.append(f"{env_names} ({provider})")

            hint_parts = [
                "To enable cloud LLM review for uncertain classifications:",
                "  Set one of: " + ", ".join(
                    k.split(" (")[0] for k in missing_keys
                ),
            ]

            if not LOCAL_MODEL_AVAILABLE:
                hint_parts.append(
                    "  Or install the local model: pip install 'tweek[local]'"
                )
            else:
                hint_parts.append(
                    "  Local ONNX model is available but could not initialize"
                )

            hint_parts.append(
                "  Or install Ollama (https://ollama.ai) for local LLM review"
            )
            hint_parts.append(
                "  See: docs/CONFIGURATION.md or ~/.tweek/config.yaml"
            )

            return HealthCheck(
                name="llm_review",
                label="LLM Review",
                status=CheckStatus.WARNING,
                message="No LLM provider available — review disabled, "
                        "pattern matching and heuristic scoring still active",
                fix_hint="\n".join(hint_parts),
            )

        # Build status message
        provider_name = reviewer.provider_name
        model = reviewer.model
        parts = [f"{model} via {provider_name}"]

        # Check for fallback chain details
        provider = reviewer._provider_instance
        if isinstance(provider, FallbackReviewProvider):
            count = provider.provider_count
            parts.append(f"fallback chain: {count} providers")

        # Check for local LLM server
        try:
            server = _detect_local_server()
            if server:
                if verbose:
                    parts.append(
                        f"local: {server.model} on {server.server_type} "
                        f"({len(server.all_models)} models available)"
                    )
                else:
                    parts.append(f"local: {server.server_type}")
        except Exception:
            pass

        # In verbose mode, report escalation path
        if verbose:
            if provider_name == "local":
                # Check if cloud escalation is available
                cloud_env_found = any(
                    os.environ.get(e) if isinstance(e, str)
                    else any(os.environ.get(v) for v in e)
                    for e in DEFAULT_API_KEY_ENVS.values()
                )
                if cloud_env_found:
                    parts.append("cloud escalation: available")
                else:
                    parts.append("cloud escalation: not configured")

            if LOCAL_MODEL_AVAILABLE:
                parts.append("local ONNX: available")

        return HealthCheck(
            name="llm_review",
            label="LLM Review",
            status=CheckStatus.OK,
            message="; ".join(parts),
        )
    except ImportError:
        return HealthCheck(
            name="llm_review",
            label="LLM Review",
            status=CheckStatus.SKIPPED,
            message="LLM reviewer module not available",
        )
    except Exception as e:
        return HealthCheck(
            name="llm_review",
            label="LLM Review",
            status=CheckStatus.WARNING,
            message=f"Cannot check LLM review: {e}",
        )
