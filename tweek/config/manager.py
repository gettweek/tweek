#!/usr/bin/env python3
"""
Tweek Configuration Manager

Manages user configuration with layered defaults:
1. Built-in defaults (tiers.yaml)
2. User overrides (~/.tweek/config.yaml)
3. Project overrides (.tweek/config.yaml)

Usage:
    config = ConfigManager()
    tier = config.get_tool_tier("Bash")
    config.set_skill_tier("my-skill", "trusted")
"""

import difflib
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

import yaml


class SecurityTier(Enum):
    """Security tier levels."""
    SAFE = "safe"
    DEFAULT = "default"
    RISKY = "risky"
    DANGEROUS = "dangerous"

    @classmethod
    def from_string(cls, value: str) -> "SecurityTier":
        """Convert string to SecurityTier."""
        try:
            return cls(value.lower())
        except ValueError:
            return cls.DEFAULT


@dataclass
class TierConfig:
    """Configuration for a security tier."""
    description: str
    screening: List[str] = field(default_factory=list)


@dataclass
class ToolConfig:
    """Configuration for a tool."""
    name: str
    tier: SecurityTier
    source: str = "default"  # "default", "user", "project"
    description: Optional[str] = None


@dataclass
class SkillConfig:
    """Configuration for a skill."""
    name: str
    tier: SecurityTier
    source: str = "default"
    description: Optional[str] = None
    credentials: List[str] = field(default_factory=list)


@dataclass
class PluginConfig:
    """Configuration for a plugin."""
    name: str
    category: str
    enabled: bool = True
    settings: Dict[str, Any] = field(default_factory=dict)
    source: str = "default"


@dataclass
class ConfigIssue:
    """A configuration validation issue."""
    level: str       # "error", "warning", "info"
    key: str         # "tools.Bahs" (the problematic key path)
    message: str     # "Unknown tool 'Bahs'"
    suggestion: str  # "Did you mean 'Bash'?"


@dataclass
class ConfigChange:
    """A single configuration change from a preset diff."""
    key: str
    current_value: Any
    new_value: Any


class ConfigManager:
    """Manages Tweek configuration with layered overrides."""

    # Default paths
    BUILTIN_CONFIG = Path(__file__).parent / "tiers.yaml"
    USER_CONFIG = Path.home() / ".tweek" / "config.yaml"
    PROJECT_CONFIG = Path(".tweek") / "config.yaml"

    # Well-known tools with sensible defaults
    KNOWN_TOOLS = {
        "Read": ("safe", "Read files - no side effects"),
        "Glob": ("default", "Find files by pattern"),
        "Grep": ("default", "Search file contents"),
        "Edit": ("default", "Modify existing files"),
        "Write": ("default", "Create/overwrite files"),
        "NotebookEdit": ("default", "Edit Jupyter notebooks"),
        "WebFetch": ("risky", "Fetch content from URLs"),
        "WebSearch": ("risky", "Search the web"),
        "Bash": ("dangerous", "Execute shell commands"),
        "Task": ("default", "Spawn subagent tasks"),
    }

    # Well-known skills with sensible defaults
    KNOWN_SKILLS = {
        "commit": ("default", "Git commit operations"),
        "review-pr": ("safe", "Review pull requests (read-only)"),
        "explore": ("safe", "Explore codebase (read-only)"),
        "frontend-design": ("risky", "Generate frontend code"),
        "dev-browser": ("risky", "Browser automation"),
        "deploy": ("dangerous", "Deployment operations"),
    }

    # Configuration presets
    PRESETS = {
        "paranoid": {
            "tools": {
                "Read": "default",
                "Glob": "default",
                "Grep": "default",
                "Edit": "risky",
                "Write": "risky",
                "WebFetch": "dangerous",
                "WebSearch": "dangerous",
                "Bash": "dangerous",
            },
            "default_tier": "risky",
        },
        "cautious": {
            "tools": {
                "Read": "safe",
                "Glob": "safe",
                "Grep": "safe",
                "Edit": "default",
                "Write": "default",
                "WebFetch": "risky",
                "WebSearch": "risky",
                "Bash": "dangerous",
            },
            "default_tier": "default",
        },
        "trusted": {
            "tools": {
                "Read": "safe",
                "Glob": "safe",
                "Grep": "safe",
                "Edit": "safe",
                "Write": "safe",
                "WebFetch": "default",
                "WebSearch": "default",
                "Bash": "risky",
            },
            "default_tier": "safe",
        },
    }

    # Valid top-level config keys
    VALID_TOP_LEVEL_KEYS = {
        "tools", "skills", "default_tier", "escalations",
        "plugins", "mcp", "proxy", "sandbox", "isolation_chamber",
        "llm_review", "local_model", "rate_limiting", "session_analysis",
        "path_boundary", "non_english_handling", "version", "tiers",
        "heuristic_scorer", "openclaw",
    }

    def __init__(
        self,
        user_config_path: Optional[Path] = None,
        project_config_path: Optional[Path] = None,
    ):
        """Initialize the config manager."""
        self.user_config_path = user_config_path or self.USER_CONFIG
        self.project_config_path = project_config_path or self.PROJECT_CONFIG

        # Load configurations
        self._builtin = self._load_yaml(self.BUILTIN_CONFIG)
        self._user = self._load_yaml(self.user_config_path)
        self._project = self._load_yaml(self.project_config_path)

        # Merged configuration cache
        self._merged: Optional[Dict] = None

    def _load_yaml(self, path: Path) -> Dict:
        """Load YAML file, return empty dict if not found."""
        if path.exists():
            try:
                with open(path) as f:
                    return yaml.safe_load(f) or {}
            except Exception:
                return {}
        return {}

    def _save_yaml(self, path: Path, data: Dict) -> None:
        """Save configuration to YAML file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def _get_merged(self) -> Dict:
        """Get merged configuration (cached)."""
        if self._merged is None:
            self._merged = {
                "tools": {},
                "skills": {},
                "escalations": [],
                "default_tier": "default",
            }

            # Layer 1: Built-in defaults
            if self._builtin:
                self._merged["tools"].update(self._builtin.get("tools", {}))
                self._merged["skills"].update(self._builtin.get("skills", {}))
                self._merged["escalations"] = self._builtin.get("escalations", [])
                self._merged["default_tier"] = self._builtin.get("default_tier", "default")

            # Layer 2: User overrides
            if self._user:
                self._merged["tools"].update(self._user.get("tools", {}))
                self._merged["skills"].update(self._user.get("skills", {}))
                if "escalations" in self._user:
                    self._merged["escalations"].extend(self._user["escalations"])
                if "default_tier" in self._user:
                    self._merged["default_tier"] = self._user["default_tier"]

            # Layer 3: Project overrides
            if self._project:
                self._merged["tools"].update(self._project.get("tools", {}))
                self._merged["skills"].update(self._project.get("skills", {}))
                if "escalations" in self._project:
                    self._merged["escalations"].extend(self._project["escalations"])
                if "default_tier" in self._project:
                    self._merged["default_tier"] = self._project["default_tier"]

        return self._merged

    def _invalidate_cache(self) -> None:
        """Invalidate the merged config cache."""
        self._merged = None

    # ==================== GETTERS ====================

    def get_tool_tier(self, tool_name: str) -> SecurityTier:
        """Get the security tier for a tool."""
        merged = self._get_merged()
        tier_str = merged["tools"].get(tool_name, merged["default_tier"])
        return SecurityTier.from_string(tier_str)

    def get_skill_tier(self, skill_name: str) -> SecurityTier:
        """Get the security tier for a skill."""
        merged = self._get_merged()
        tier_str = merged["skills"].get(skill_name, merged["default_tier"])
        return SecurityTier.from_string(tier_str)

    def get_tool_config(self, tool_name: str) -> ToolConfig:
        """Get full configuration for a tool."""
        tier = self.get_tool_tier(tool_name)

        # Determine source
        if tool_name in self._project.get("tools", {}):
            source = "project"
        elif tool_name in self._user.get("tools", {}):
            source = "user"
        else:
            source = "default"

        # Get description
        desc = self.KNOWN_TOOLS.get(tool_name, (None, None))[1]

        return ToolConfig(
            name=tool_name,
            tier=tier,
            source=source,
            description=desc,
        )

    def get_skill_config(self, skill_name: str) -> SkillConfig:
        """Get full configuration for a skill."""
        tier = self.get_skill_tier(skill_name)

        # Determine source
        if skill_name in self._project.get("skills", {}):
            source = "project"
        elif skill_name in self._user.get("skills", {}):
            source = "user"
        else:
            source = "default"

        # Get description
        desc = self.KNOWN_SKILLS.get(skill_name, (None, None))[1]

        return SkillConfig(
            name=skill_name,
            tier=tier,
            source=source,
            description=desc,
        )

    def list_tools(self) -> List[ToolConfig]:
        """List all configured tools."""
        merged = self._get_merged()
        tools = []

        # Add all known tools
        for name in self.KNOWN_TOOLS:
            tools.append(self.get_tool_config(name))

        # Add any custom tools from config
        for name in merged["tools"]:
            if name not in self.KNOWN_TOOLS:
                tools.append(self.get_tool_config(name))

        return sorted(tools, key=lambda t: t.name)

    def list_skills(self) -> List[SkillConfig]:
        """List all configured skills."""
        merged = self._get_merged()
        skills = []

        # Add all known skills
        for name in self.KNOWN_SKILLS:
            skills.append(self.get_skill_config(name))

        # Add any custom skills from config
        for name in merged["skills"]:
            if name not in self.KNOWN_SKILLS:
                skills.append(self.get_skill_config(name))

        return sorted(skills, key=lambda s: s.name)

    def get_unknown_skills(self, skill_names: List[str]) -> List[str]:
        """Get skills that aren't in the known list or user config."""
        merged = self._get_merged()
        known = set(self.KNOWN_SKILLS.keys()) | set(merged["skills"].keys())
        return [s for s in skill_names if s not in known]

    def get_escalations(self) -> List[Dict]:
        """Get all escalation patterns."""
        return self._get_merged()["escalations"]

    def get_default_tier(self) -> SecurityTier:
        """Get the default tier for unknown tools/skills."""
        return SecurityTier.from_string(self._get_merged()["default_tier"])

    # ==================== SETTERS ====================

    def _log_config_change(self, operation: str, **kwargs):
        """Log config change to security logger (never raises)."""
        try:
            from tweek.logging.security_log import get_logger, SecurityEvent, EventType
            metadata = {"operation": operation}
            metadata.update(kwargs)
            get_logger().log(SecurityEvent(
                event_type=EventType.CONFIG_CHANGE,
                tool_name="config",
                decision="allow",
                metadata=metadata,
                source="cli",
            ))
        except Exception:
            pass

    def set_tool_tier(
        self,
        tool_name: str,
        tier: SecurityTier,
        scope: str = "user"
    ) -> None:
        """
        Set the security tier for a tool.

        Args:
            tool_name: Name of the tool
            tier: Security tier to set
            scope: "user" or "project"
        """
        old_tier = self.get_tool_tier(tool_name).value
        if scope == "project":
            if "tools" not in self._project:
                self._project["tools"] = {}
            self._project["tools"][tool_name] = tier.value
            self._save_yaml(self.project_config_path, self._project)
        else:
            if "tools" not in self._user:
                self._user["tools"] = {}
            self._user["tools"][tool_name] = tier.value
            self._save_yaml(self.user_config_path, self._user)

        self._invalidate_cache()
        self._log_config_change("set_tool_tier", tool=tool_name, old_tier=old_tier, new_tier=tier.value, scope=scope)

    def set_skill_tier(
        self,
        skill_name: str,
        tier: SecurityTier,
        scope: str = "user"
    ) -> None:
        """
        Set the security tier for a skill.

        Args:
            skill_name: Name of the skill
            tier: Security tier to set
            scope: "user" or "project"
        """
        old_tier = self.get_skill_tier(skill_name).value
        if scope == "project":
            if "skills" not in self._project:
                self._project["skills"] = {}
            self._project["skills"][skill_name] = tier.value
            self._save_yaml(self.project_config_path, self._project)
        else:
            if "skills" not in self._user:
                self._user["skills"] = {}
            self._user["skills"][skill_name] = tier.value
            self._save_yaml(self.user_config_path, self._user)

        self._invalidate_cache()
        self._log_config_change("set_skill_tier", skill=skill_name, old_tier=old_tier, new_tier=tier.value, scope=scope)

    def set_default_tier(self, tier: SecurityTier, scope: str = "user") -> None:
        """Set the default tier for unknown tools/skills."""
        if scope == "project":
            self._project["default_tier"] = tier.value
            self._save_yaml(self.project_config_path, self._project)
        else:
            self._user["default_tier"] = tier.value
            self._save_yaml(self.user_config_path, self._user)

        self._invalidate_cache()

    def add_escalation(
        self,
        pattern: str,
        description: str,
        escalate_to: SecurityTier,
        scope: str = "user"
    ) -> None:
        """Add a custom escalation pattern."""
        escalation = {
            "pattern": pattern,
            "description": description,
            "escalate_to": escalate_to.value,
        }

        if scope == "project":
            if "escalations" not in self._project:
                self._project["escalations"] = []
            self._project["escalations"].append(escalation)
            self._save_yaml(self.project_config_path, self._project)
        else:
            if "escalations" not in self._user:
                self._user["escalations"] = []
            self._user["escalations"].append(escalation)
            self._save_yaml(self.user_config_path, self._user)

        self._invalidate_cache()

    def reset_tool(self, tool_name: str, scope: str = "user") -> bool:
        """Reset a tool to its default tier."""
        if scope == "project":
            if "tools" in self._project and tool_name in self._project["tools"]:
                del self._project["tools"][tool_name]
                self._save_yaml(self.project_config_path, self._project)
                self._invalidate_cache()
                return True
        else:
            if "tools" in self._user and tool_name in self._user["tools"]:
                del self._user["tools"][tool_name]
                self._save_yaml(self.user_config_path, self._user)
                self._invalidate_cache()
                return True
        return False

    def reset_skill(self, skill_name: str, scope: str = "user") -> bool:
        """Reset a skill to its default tier."""
        if scope == "project":
            if "skills" in self._project and skill_name in self._project["skills"]:
                del self._project["skills"][skill_name]
                self._save_yaml(self.project_config_path, self._project)
                self._invalidate_cache()
                return True
        else:
            if "skills" in self._user and skill_name in self._user["skills"]:
                del self._user["skills"][skill_name]
                self._save_yaml(self.user_config_path, self._user)
                self._invalidate_cache()
                return True
        return False

    def reset_all(self, scope: str = "user") -> None:
        """Reset all configuration to defaults."""
        if scope == "project":
            self._project = {}
            if self.project_config_path.exists():
                self.project_config_path.unlink()
        else:
            self._user = {}
            if self.user_config_path.exists():
                self.user_config_path.unlink()

        self._invalidate_cache()
        self._log_config_change("reset_all", scope=scope)

    # ==================== BULK OPERATIONS ====================

    def apply_preset(self, preset: str, scope: str = "user") -> None:
        """
        Apply a configuration preset.

        Presets:
            paranoid: Maximum security, prompt for everything
            cautious: Balanced security (recommended)
            trusted: Minimal prompts, trust AI decisions
        """
        if preset not in self.PRESETS:
            available = ", ".join(self.PRESETS.keys())
            raise ValueError(f"Unknown preset: {preset}. Available: {available}")

        config = self.PRESETS[preset]

        if scope == "project":
            self._project.update(config)
            self._save_yaml(self.project_config_path, self._project)
        else:
            self._user.update(config)
            self._save_yaml(self.user_config_path, self._user)

        self._invalidate_cache()
        self._log_config_change("apply_preset", preset=preset, scope=scope)

    def import_config(self, config_dict: Dict, scope: str = "user") -> None:
        """Import configuration from a dictionary."""
        if scope == "project":
            self._project.update(config_dict)
            self._save_yaml(self.project_config_path, self._project)
        else:
            self._user.update(config_dict)
            self._save_yaml(self.user_config_path, self._user)

        self._invalidate_cache()

    def export_config(self, scope: str = "user") -> Dict:
        """Export configuration as a dictionary."""
        if scope == "project":
            return dict(self._project)
        elif scope == "user":
            return dict(self._user)
        else:
            return dict(self._get_merged())

    # ==================== VALIDATION ====================

    def validate_config(self, scope: str = "merged") -> List[ConfigIssue]:
        """
        Validate configuration for errors, typos, and warnings.

        Checks:
            - Unknown top-level keys (with typo suggestions)
            - Unknown tool names (with typo suggestions)
            - Invalid tier values
            - Invalid plugin references

        Args:
            scope: "user", "project", or "merged"

        Returns:
            List of ConfigIssue objects.
        """
        issues: List[ConfigIssue] = []

        if scope == "user":
            configs_to_check = [("user", self._user)]
        elif scope == "project":
            configs_to_check = [("project", self._project)]
        else:
            configs_to_check = [("user", self._user), ("project", self._project)]

        valid_tiers = {t.value for t in SecurityTier}
        known_tool_names = set(self.KNOWN_TOOLS.keys())
        known_skill_names = set(self.KNOWN_SKILLS.keys())

        for source_name, config in configs_to_check:
            if not config:
                continue

            # Check top-level keys
            for key in config:
                if key not in self.VALID_TOP_LEVEL_KEYS:
                    matches = difflib.get_close_matches(
                        key, self.VALID_TOP_LEVEL_KEYS, n=1, cutoff=0.6
                    )
                    suggestion = f"Did you mean '{matches[0]}'?" if matches else ""
                    issues.append(ConfigIssue(
                        level="error",
                        key=f"{source_name}.{key}",
                        message=f"Unknown config key '{key}'",
                        suggestion=suggestion,
                    ))

            # Check tool names and tiers
            tools = config.get("tools", {})
            if isinstance(tools, dict):
                for tool_name, tier_value in tools.items():
                    # Check if tool name is known
                    if tool_name not in known_tool_names:
                        # Check merged config tools too (custom tools are fine)
                        merged_tools = self._get_merged().get("tools", {})
                        if tool_name not in merged_tools:
                            matches = difflib.get_close_matches(
                                tool_name, known_tool_names, n=1, cutoff=0.6
                            )
                            suggestion = f"Did you mean '{matches[0]}'?" if matches else ""
                            issues.append(ConfigIssue(
                                level="warning",
                                key=f"tools.{tool_name}",
                                message=f"Unknown tool '{tool_name}'",
                                suggestion=suggestion,
                            ))

                    # Check tier value
                    if isinstance(tier_value, str) and tier_value not in valid_tiers:
                        matches = difflib.get_close_matches(
                            tier_value, valid_tiers, n=1, cutoff=0.5
                        )
                        suggestion = f"Did you mean '{matches[0]}'?" if matches else f"Valid tiers: {', '.join(sorted(valid_tiers))}"
                        issues.append(ConfigIssue(
                            level="error",
                            key=f"tools.{tool_name}",
                            message=f"Invalid tier '{tier_value}' for tool '{tool_name}'",
                            suggestion=suggestion,
                        ))

            # Check skill names and tiers
            skills = config.get("skills", {})
            if isinstance(skills, dict):
                for skill_name, tier_value in skills.items():
                    if skill_name not in known_skill_names:
                        matches = difflib.get_close_matches(
                            skill_name, known_skill_names, n=1, cutoff=0.6
                        )
                        if matches:
                            issues.append(ConfigIssue(
                                level="warning",
                                key=f"skills.{skill_name}",
                                message=f"Unknown skill '{skill_name}'",
                                suggestion=f"Did you mean '{matches[0]}'?",
                            ))

                    if isinstance(tier_value, str) and tier_value not in valid_tiers:
                        matches = difflib.get_close_matches(
                            tier_value, valid_tiers, n=1, cutoff=0.5
                        )
                        suggestion = f"Did you mean '{matches[0]}'?" if matches else f"Valid tiers: {', '.join(sorted(valid_tiers))}"
                        issues.append(ConfigIssue(
                            level="error",
                            key=f"skills.{skill_name}",
                            message=f"Invalid tier '{tier_value}' for skill '{skill_name}'",
                            suggestion=suggestion,
                        ))

            # Check default_tier
            default_tier = config.get("default_tier")
            if default_tier and default_tier not in valid_tiers:
                matches = difflib.get_close_matches(
                    default_tier, valid_tiers, n=1, cutoff=0.5
                )
                suggestion = f"Did you mean '{matches[0]}'?" if matches else f"Valid tiers: {', '.join(sorted(valid_tiers))}"
                issues.append(ConfigIssue(
                    level="error",
                    key="default_tier",
                    message=f"Invalid default tier '{default_tier}'",
                    suggestion=suggestion,
                ))

        # Run Pydantic structural validation on merged config
        try:
            merged = self._get_merged()
            pydantic_issues = self._validate_with_pydantic(merged)
            # Deduplicate: only add Pydantic issues not already caught above
            existing_messages = {i.message for i in issues}
            for pi in pydantic_issues:
                if pi.message not in existing_messages:
                    issues.append(pi)
        except Exception:
            pass  # Pydantic validation is additive, never blocks

        return issues

    def _validate_with_pydantic(self, config: Dict) -> List[ConfigIssue]:
        """Run Pydantic model validation on merged config."""
        from pydantic import ValidationError
        from tweek.config.models import TweekConfig

        try:
            TweekConfig.model_validate(config)
            return []
        except ValidationError as e:
            issues = []
            for err in e.errors():
                loc = ".".join(str(p) for p in err["loc"])
                issues.append(ConfigIssue(
                    level="error",
                    key=loc,
                    message=err["msg"],
                    suggestion="",
                ))
            return issues

    def diff_preset(self, preset_name: str) -> List[ConfigChange]:
        """
        Show what would change if a preset were applied.

        Args:
            preset_name: Name of the preset ("paranoid", "cautious", "trusted").

        Returns:
            List of ConfigChange showing current vs. new values.

        Raises:
            ValueError: If preset_name is unknown.
        """
        if preset_name not in self.PRESETS:
            available = ", ".join(self.PRESETS.keys())
            raise ValueError(f"Unknown preset: {preset_name}. Available: {available}")

        preset = self.PRESETS[preset_name]
        changes: List[ConfigChange] = []

        # Check default_tier change
        current_default = self._get_merged().get("default_tier", "default")
        new_default = preset.get("default_tier", current_default)
        if current_default != new_default:
            changes.append(ConfigChange(
                key="default_tier",
                current_value=current_default,
                new_value=new_default,
            ))

        # Check tool tier changes
        preset_tools = preset.get("tools", {})
        for tool_name, new_tier in preset_tools.items():
            current_tier = self.get_tool_tier(tool_name).value
            if current_tier != new_tier:
                changes.append(ConfigChange(
                    key=f"tools.{tool_name}",
                    current_value=current_tier,
                    new_value=new_tier,
                ))

        return changes

    # ==================== PLUGIN CONFIGURATION ====================

    def get_plugin_config(self, category: str, plugin_name: str) -> PluginConfig:
        """
        Get configuration for a plugin.

        Args:
            category: Plugin category (compliance, providers, detectors, screening)
            plugin_name: Plugin name

        Returns:
            PluginConfig with merged settings
        """
        merged = self._get_merged()
        plugins = merged.get("plugins", {})
        cat_config = plugins.get(category, {})
        modules = cat_config.get("modules", cat_config)

        plugin_settings = modules.get(plugin_name, {})
        if isinstance(plugin_settings, dict):
            enabled = plugin_settings.get("enabled", True)
            settings = {k: v for k, v in plugin_settings.items() if k != "enabled"}
        else:
            enabled = bool(plugin_settings)
            settings = {}

        # Determine source
        source = "default"
        if "plugins" in self._project:
            proj_cat = self._project["plugins"].get(category, {})
            proj_modules = proj_cat.get("modules", proj_cat)
            if plugin_name in proj_modules:
                source = "project"
        if source == "default" and "plugins" in self._user:
            user_cat = self._user["plugins"].get(category, {})
            user_modules = user_cat.get("modules", user_cat)
            if plugin_name in user_modules:
                source = "user"

        return PluginConfig(
            name=plugin_name,
            category=category,
            enabled=enabled,
            settings=settings,
            source=source,
        )

    def set_plugin_enabled(
        self,
        category: str,
        plugin_name: str,
        enabled: bool,
        scope: str = "user"
    ) -> None:
        """
        Enable or disable a plugin.

        Args:
            category: Plugin category
            plugin_name: Plugin name
            enabled: Whether to enable the plugin
            scope: Config scope (user or project)
        """
        target = self._project if scope == "project" else self._user

        if "plugins" not in target:
            target["plugins"] = {}
        if category not in target["plugins"]:
            target["plugins"][category] = {"modules": {}}
        if "modules" not in target["plugins"][category]:
            target["plugins"][category]["modules"] = {}

        if plugin_name not in target["plugins"][category]["modules"]:
            target["plugins"][category]["modules"][plugin_name] = {}

        target["plugins"][category]["modules"][plugin_name]["enabled"] = enabled

        path = self.project_config_path if scope == "project" else self.user_config_path
        self._save_yaml(path, target)
        self._invalidate_cache()

    def set_plugin_setting(
        self,
        category: str,
        plugin_name: str,
        key: str,
        value: Any,
        scope: str = "user"
    ) -> None:
        """
        Set a plugin setting.

        Args:
            category: Plugin category
            plugin_name: Plugin name
            key: Setting key
            value: Setting value
            scope: Config scope
        """
        target = self._project if scope == "project" else self._user

        if "plugins" not in target:
            target["plugins"] = {}
        if category not in target["plugins"]:
            target["plugins"][category] = {"modules": {}}
        if "modules" not in target["plugins"][category]:
            target["plugins"][category]["modules"] = {}
        if plugin_name not in target["plugins"][category]["modules"]:
            target["plugins"][category]["modules"][plugin_name] = {}

        target["plugins"][category]["modules"][plugin_name][key] = value

        path = self.project_config_path if scope == "project" else self.user_config_path
        self._save_yaml(path, target)
        self._invalidate_cache()

    def list_plugin_configs(self, category: Optional[str] = None) -> List[PluginConfig]:
        """
        List all plugin configurations.

        Args:
            category: Optional category filter

        Returns:
            List of PluginConfig objects
        """
        merged = self._get_merged()
        plugins = merged.get("plugins", {})
        configs = []

        categories = [category] if category else list(plugins.keys())

        for cat in categories:
            cat_config = plugins.get(cat, {})
            modules = cat_config.get("modules", cat_config)

            if isinstance(modules, dict):
                for name in modules:
                    configs.append(self.get_plugin_config(cat, name))

        return configs

    def get_plugins_dict(self) -> Dict[str, Any]:
        """
        Get the full plugins configuration dictionary.

        Returns:
            Dictionary with all plugin configurations
        """
        merged = self._get_merged()
        return merged.get("plugins", {})

    def reset_plugin(
        self,
        category: str,
        plugin_name: str,
        scope: str = "user"
    ) -> bool:
        """
        Reset a plugin to default configuration.

        Args:
            category: Plugin category
            plugin_name: Plugin name
            scope: Config scope

        Returns:
            True if reset was performed
        """
        target = self._project if scope == "project" else self._user

        if "plugins" not in target:
            return False
        if category not in target["plugins"]:
            return False

        modules = target["plugins"][category].get("modules", target["plugins"][category])
        if plugin_name in modules:
            del modules[plugin_name]

            path = self.project_config_path if scope == "project" else self.user_config_path
            self._save_yaml(path, target)
            self._invalidate_cache()
            return True

        return False


    # ==================== PLUGIN SCOPING ====================

    def get_plugin_scope(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """
        Get the scope configuration for a plugin.

        Searches across all plugin categories in user config.

        Args:
            plugin_name: Plugin name

        Returns:
            Scope dict if configured, None if no scope (global plugin)
        """
        for source in [self._project, self._user]:
            plugins = source.get("plugins", {})
            for cat_name, cat_config in plugins.items():
                modules = cat_config.get("modules", cat_config)
                if isinstance(modules, dict) and plugin_name in modules:
                    plugin_cfg = modules[plugin_name]
                    if isinstance(plugin_cfg, dict) and "scope" in plugin_cfg:
                        return plugin_cfg["scope"]
        return None

    def set_plugin_scope(
        self,
        plugin_name: str,
        scope: Optional[Dict[str, Any]],
        scope_level: str = "user"
    ) -> None:
        """
        Set or clear the scope for a plugin.

        Finds the plugin across categories and sets its scope.

        Args:
            plugin_name: Plugin name
            scope: Scope dict (None to clear/make global)
            scope_level: "user" or "project"
        """
        target = self._project if scope_level == "project" else self._user

        # Find which category this plugin is in
        category = self._find_plugin_category(plugin_name)

        if "plugins" not in target:
            target["plugins"] = {}
        if category not in target["plugins"]:
            target["plugins"][category] = {"modules": {}}
        if "modules" not in target["plugins"][category]:
            target["plugins"][category]["modules"] = {}
        if plugin_name not in target["plugins"][category]["modules"]:
            target["plugins"][category]["modules"][plugin_name] = {}

        plugin_cfg = target["plugins"][category]["modules"][plugin_name]

        if scope is None:
            # Clear scope
            plugin_cfg.pop("scope", None)
        else:
            plugin_cfg["scope"] = scope

        path = self.project_config_path if scope_level == "project" else self.user_config_path
        self._save_yaml(path, target)
        self._invalidate_cache()

    def _find_plugin_category(self, plugin_name: str) -> str:
        """
        Find which category a plugin belongs to.

        Searches built-in configs and registry.
        """
        # Check known compliance plugins
        compliance_plugins = {"gov", "hipaa", "pci", "legal", "soc2", "gdpr"}
        if plugin_name in compliance_plugins:
            return "compliance"

        # Check known screening plugins
        screening_plugins = {"rate_limiter", "pattern_matcher", "llm_reviewer", "local_model_reviewer", "session_analyzer"}
        if plugin_name in screening_plugins:
            return "screening"

        # Check known provider plugins
        provider_plugins = {"anthropic", "openai", "google", "bedrock", "azure_openai"}
        if plugin_name in provider_plugins:
            return "providers"

        # Check known detector plugins
        detector_plugins = {"openclaw", "cursor", "continue", "copilot", "windsurf"}
        if plugin_name in detector_plugins:
            return "detectors"

        # Search existing config
        for source in [self._project, self._user, self._builtin]:
            plugins = source.get("plugins", {})
            for cat_name, cat_config in plugins.items():
                modules = cat_config.get("modules", cat_config)
                if isinstance(modules, dict) and plugin_name in modules:
                    return cat_name

        # Default to screening
        return "screening"

    # ==================== LOCAL MODEL ====================

    def get_local_model_config(self) -> Dict[str, Any]:
        """Get the merged local model configuration with defaults."""
        defaults = {
            "enabled": True,
            "model": "auto",
            "escalate_to_llm": True,
            "escalate_min_confidence": 0.1,
            "escalate_max_confidence": 0.9,
        }

        # Merge from builtin, user, project
        for source in [self._builtin, self._user, self._project]:
            local_cfg = source.get("local_model", {})
            if isinstance(local_cfg, dict):
                defaults.update(local_cfg)

        return defaults

    def set_active_model(self, name: str) -> None:
        """Set the active local model in user config.

        Args:
            name: Model name from the catalog.
        """
        if "local_model" not in self._user:
            self._user["local_model"] = {}

        self._user["local_model"]["model"] = name
        self._save_yaml(self.user_config_path, self._user)
        self._invalidate_cache()
        self._log_config_change("set_active_model", model=name)

    # ==================== FULL CONFIG ====================

    def get_full_config(self) -> Dict[str, Any]:
        """
        Get the complete merged configuration as a dictionary.

        Returns all configuration including tools, skills, plugins,
        escalations, and any MCP/proxy settings.
        """
        merged = dict(self._get_merged())

        # Include plugin configs
        for source in [self._builtin, self._user, self._project]:
            if "plugins" in source:
                if "plugins" not in merged:
                    merged["plugins"] = {}
                for cat, cat_cfg in source["plugins"].items():
                    if cat not in merged["plugins"]:
                        merged["plugins"][cat] = {}
                    if isinstance(cat_cfg, dict):
                        for k, v in cat_cfg.items():
                            if k == "modules" and isinstance(v, dict):
                                if "modules" not in merged["plugins"][cat]:
                                    merged["plugins"][cat]["modules"] = {}
                                merged["plugins"][cat]["modules"].update(v)
                            else:
                                merged["plugins"][cat][k] = v

        # Include MCP config
        for source in [self._builtin, self._user, self._project]:
            if "mcp" in source:
                merged["mcp"] = source["mcp"]

        # Include proxy config
        for source in [self._builtin, self._user, self._project]:
            if "proxy" in source:
                merged["proxy"] = source["proxy"]

        return merged


def get_config() -> ConfigManager:
    """Get the global configuration manager."""
    return ConfigManager()
