"""
Tweek Project Sandbox

Per-project security state isolation manager. Creates and manages
a .tweek/ directory inside each project with project-scoped:
- security.db (event log)
- overrides.yaml (additive-only pattern overrides)
- fingerprints.json (skill fingerprint cache)
- config.yaml (project Tweek config)
- sandbox.yaml (sandbox layer config)

The additive-only model ensures project-level config can NEVER weaken
global security:
- Project can ADD patterns but not disable global patterns
- Project can RAISE severity thresholds but not lower them
- Project whitelists must be scoped to the project directory
"""

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from .layers import IsolationLayer, stricter_severity
from .registry import get_registry


TWEEK_HOME = Path.home() / ".tweek"


@dataclass
class SandboxConfig:
    """Configuration for a project's sandbox."""

    layer: int = 2
    inherit_global_patterns: bool = True
    additive_only: bool = True
    auto_init: bool = True
    auto_gitignore: bool = True

    @classmethod
    def from_dict(cls, data: dict) -> "SandboxConfig":
        """Create from a dict (loaded from YAML)."""
        return cls(
            layer=data.get("layer", 2),
            inherit_global_patterns=data.get("inherit_global_patterns", True),
            additive_only=data.get("additive_only", True),
            auto_init=data.get("auto_init", True),
            auto_gitignore=data.get("auto_gitignore", True),
        )

    def to_dict(self) -> dict:
        """Serialize to dict for YAML output."""
        return {
            "layer": self.layer,
            "inherit_global_patterns": self.inherit_global_patterns,
            "additive_only": self.additive_only,
            "auto_init": self.auto_init,
            "auto_gitignore": self.auto_gitignore,
        }


def _get_global_sandbox_defaults() -> dict:
    """Load sandbox defaults from global ~/.tweek/config.yaml."""
    global_config = TWEEK_HOME / "config.yaml"
    if not global_config.exists():
        return {}
    try:
        with open(global_config) as f:
            data = yaml.safe_load(f) or {}
        return data.get("sandbox", {})
    except Exception:
        return {}


class ProjectSandbox:
    """Per-project isolation manager.

    Manages the .tweek/ directory inside a project for project-scoped
    security state. Provides scoped logger, overrides, and fingerprints
    that enforce the additive-only security model.
    """

    def __init__(
        self,
        project_dir: Path,
        global_config_path: Optional[Path] = None,
    ):
        self.project_dir = project_dir.resolve()
        self.tweek_dir = self.project_dir / ".tweek"
        self._global_config_path = global_config_path
        self.config = self._load_config()
        self.layer = IsolationLayer.from_value(self.config.layer)

        # Cached service instances
        self._logger = None
        self._overrides = None
        self._fingerprints = None
        self._memory_store = None

    def _load_config(self) -> SandboxConfig:
        """Load sandbox config from project .tweek/sandbox.yaml."""
        sandbox_yaml = self.tweek_dir / "sandbox.yaml"
        if sandbox_yaml.exists():
            try:
                with open(sandbox_yaml) as f:
                    data = yaml.safe_load(f) or {}
                return SandboxConfig.from_dict(data)
            except Exception:
                pass

        # Check registry for layer setting
        registry = get_registry()
        reg_layer = registry.get_layer(self.project_dir)
        if reg_layer is not None:
            return SandboxConfig(layer=reg_layer.value)

        # Fall back to global defaults
        defaults = _get_global_sandbox_defaults()
        return SandboxConfig(
            layer=defaults.get("default_layer", 2),
            auto_init=defaults.get("auto_init", True),
            auto_gitignore=defaults.get("auto_gitignore", True),
        )

    @property
    def is_initialized(self) -> bool:
        """Check if the project .tweek/ directory exists."""
        return self.tweek_dir.is_dir()

    def initialize(self) -> None:
        """Create .tweek/ directory with default state files.

        Creates:
        - .tweek/sandbox.yaml (layer config)
        - .tweek/overrides.yaml (empty, additive-only)
        - .tweek/config.yaml (empty, inherits global)

        Also adds .tweek/ to .gitignore if not present.
        """
        self.tweek_dir.mkdir(parents=True, exist_ok=True)

        # Create sandbox.yaml
        sandbox_yaml = self.tweek_dir / "sandbox.yaml"
        if not sandbox_yaml.exists():
            from datetime import datetime, timezone

            data = self.config.to_dict()
            data["created_at"] = datetime.now(timezone.utc).isoformat()
            with open(sandbox_yaml, "w") as f:
                yaml.safe_dump(data, f, default_flow_style=False)

        # Create empty overrides.yaml
        overrides_yaml = self.tweek_dir / "overrides.yaml"
        if not overrides_yaml.exists():
            with open(overrides_yaml, "w") as f:
                f.write("# Project-scoped security overrides (additive-only)\n")
                f.write("# Project overrides can ADD patterns/whitelists but NEVER disable global ones.\n")
                f.write("# See: tweek sandbox config\n")

        # Create empty config.yaml
        config_yaml = self.tweek_dir / "config.yaml"
        if not config_yaml.exists():
            with open(config_yaml, "w") as f:
                f.write("# Project-scoped Tweek configuration\n")
                f.write("# Values here override global ~/.tweek/config.yaml for this project.\n")

        # Auto-gitignore
        if self.config.auto_gitignore:
            self._ensure_gitignored()

        # Register in the project registry
        registry = get_registry()
        registry.register(
            self.project_dir,
            layer=self.layer,
            auto_initialized=True,
        )

    def _ensure_gitignored(self) -> None:
        """Add .tweek/ to .gitignore if not already present."""
        gitignore = self.project_dir / ".gitignore"
        tweek_entry = ".tweek/"

        if gitignore.exists():
            try:
                content = gitignore.read_text()
                # Check if already gitignored (exact line match)
                lines = content.splitlines()
                for line in lines:
                    stripped = line.strip()
                    if stripped in (".tweek/", ".tweek", "/.tweek/", "/.tweek"):
                        return  # Already present
                # Append
                if not content.endswith("\n"):
                    content += "\n"
                content += f"\n# Tweek project sandbox state\n{tweek_entry}\n"
                gitignore.write_text(content)
            except (IOError, OSError):
                pass
        else:
            # Only create .gitignore if .git/ exists (it's a git repo)
            if (self.project_dir / ".git").exists():
                try:
                    gitignore.write_text(
                        f"# Tweek project sandbox state\n{tweek_entry}\n"
                    )
                except (IOError, OSError):
                    pass

    def get_logger(self):
        """Return project-scoped SecurityLogger.

        Lazy import to avoid circular dependencies since security_log
        is also imported by the hooks.
        """
        if self._logger is not None:
            return self._logger

        if self.layer.value < IsolationLayer.PROJECT.value:
            from tweek.logging.security_log import get_logger
            self._logger = get_logger()
            return self._logger

        from tweek.logging.security_log import SecurityLogger
        self._logger = SecurityLogger(db_path=self.tweek_dir / "security.db")
        return self._logger

    def get_overrides(self):
        """Return merged overrides (global + project, additive-only).

        The merge enforces:
        - Project cannot disable global patterns
        - Project whitelist entries must be scoped to project directory
        - Project severity threshold can only be raised (stricter), not lowered
        - Project can force-enable additional patterns
        """
        if self._overrides is not None:
            return self._overrides

        from tweek.hooks.overrides import (
            get_overrides as get_global_overrides,
            SecurityOverrides,
        )

        global_ovr = get_global_overrides()

        if self.layer.value < IsolationLayer.PROJECT.value:
            self._overrides = global_ovr
            return self._overrides

        project_ovr_path = self.tweek_dir / "overrides.yaml"
        if not project_ovr_path.exists():
            self._overrides = global_ovr
            return self._overrides

        project_ovr = SecurityOverrides(config_path=project_ovr_path)
        if not project_ovr.config:
            self._overrides = global_ovr
            return self._overrides

        # Merge with additive-only enforcement
        self._overrides = MergedOverrides(
            global_ovr=global_ovr,
            project_ovr=project_ovr,
            project_dir=self.project_dir,
        )
        return self._overrides

    def get_memory_store(self):
        """Return project-scoped MemoryStore.

        Uses the project's .tweek/memory.db for project-scoped memory.
        Falls back to global memory for layers below PROJECT.
        """
        if self._memory_store is not None:
            return self._memory_store

        from tweek.memory.store import MemoryStore, get_memory_store

        if self.layer.value < IsolationLayer.PROJECT.value:
            self._memory_store = get_memory_store()
            return self._memory_store

        self._memory_store = MemoryStore(
            db_path=self.tweek_dir / "memory.db"
        )
        return self._memory_store

    def get_fingerprints(self):
        """Return project-scoped fingerprint cache."""
        if self._fingerprints is not None:
            return self._fingerprints

        if self.layer.value < IsolationLayer.PROJECT.value:
            from tweek.skills.fingerprints import get_fingerprints
            self._fingerprints = get_fingerprints()
            return self._fingerprints

        from tweek.skills.fingerprints import SkillFingerprints
        self._fingerprints = SkillFingerprints(
            cache_path=self.tweek_dir / "fingerprints.json"
        )
        return self._fingerprints

    def reset(self) -> None:
        """Remove project .tweek/ directory and deregister."""
        import shutil

        if self.tweek_dir.exists():
            shutil.rmtree(self.tweek_dir)

        registry = get_registry()
        registry.deregister(self.project_dir)

        # Clear cached services
        self._logger = None
        self._overrides = None
        self._fingerprints = None
        if self._memory_store is not None:
            self._memory_store.close()
        self._memory_store = None


class MergedOverrides:
    """Wrapper that merges global and project overrides with additive-only enforcement.

    Implements the same interface as SecurityOverrides so it can be used
    as a drop-in replacement in the hooks.
    """

    def __init__(self, global_ovr, project_ovr, project_dir: Path):
        self.global_ovr = global_ovr
        self.project_ovr = project_ovr
        self.project_dir = project_dir.resolve()

        # Merge the config dicts
        self.config = self._merge_configs()
        self._whitelist_rules = self.config.get("whitelist", [])
        self._pattern_config = self.config.get("patterns", {})
        self._trust_config = self.config.get("trust", {})

    def _merge_configs(self) -> dict:
        """Merge global and project configs with additive-only enforcement."""
        global_cfg = self.global_ovr.config if self.global_ovr else {}
        project_cfg = self.project_ovr.config if self.project_ovr else {}

        merged = {}

        # --- Whitelist: project can add, but only for project-scoped paths ---
        global_whitelist = global_cfg.get("whitelist", [])
        project_whitelist = project_cfg.get("whitelist", [])
        scoped_project_whitelist = [
            rule for rule in project_whitelist
            if self._is_project_scoped_rule(rule)
        ]
        merged["whitelist"] = global_whitelist + scoped_project_whitelist

        # --- Patterns: additive-only ---
        global_patterns = global_cfg.get("patterns", {})
        project_patterns = project_cfg.get("patterns", {})

        merged_patterns = {}

        # Disabled patterns: ONLY from global (project cannot disable)
        merged_patterns["disabled"] = global_patterns.get("disabled", [])

        # Force-enabled: union of global and project
        global_force = set(global_patterns.get("force_enabled", []))
        project_force = set(project_patterns.get("force_enabled", []))
        merged_patterns["force_enabled"] = list(global_force | project_force)

        # Scoped disables: ONLY from global
        merged_patterns["scoped_disables"] = global_patterns.get("scoped_disables", [])

        merged["patterns"] = merged_patterns

        # --- Trust: project can raise threshold (stricter) but not lower ---
        global_trust = global_cfg.get("trust", {})
        project_trust = project_cfg.get("trust", {})
        merged_trust = dict(global_trust)

        for mode in ("interactive", "automated"):
            global_mode = global_trust.get(mode, {})
            project_mode = project_trust.get(mode, {})

            if project_mode.get("min_severity") and global_mode.get("min_severity"):
                # Keep the stricter of the two
                merged_sev = stricter_severity(
                    global_mode["min_severity"],
                    project_mode["min_severity"],
                )
                if mode not in merged_trust:
                    merged_trust[mode] = {}
                merged_trust[mode]["min_severity"] = merged_sev

        merged["trust"] = merged_trust

        return merged

    def _is_project_scoped_rule(self, rule: dict) -> bool:
        """Check if a whitelist rule is scoped to the project directory."""
        rule_path = rule.get("path")
        if not rule_path:
            # Rules without a path (tool-only rules) are allowed from project
            # only if they specify a tool filter
            return bool(rule.get("tool") or rule.get("tools"))

        try:
            resolved = Path(rule_path).expanduser().resolve()
            resolved.relative_to(self.project_dir)
            return True
        except (ValueError, OSError):
            return False

    # === SecurityOverrides-compatible interface ===

    def check_whitelist(self, tool_name, tool_input, content):
        """Check if invocation matches a whitelist rule."""
        if self.global_ovr:
            match = self.global_ovr.check_whitelist(tool_name, tool_input, content)
            if match:
                return match
        if self.project_ovr:
            match = self.project_ovr.check_whitelist(tool_name, tool_input, content)
            if match and self._is_project_scoped_rule(match):
                return match
        return None

    def filter_patterns(self, matches, working_path):
        """Filter patterns using merged config."""
        if self.global_ovr:
            matches = self.global_ovr.filter_patterns(matches, working_path)
        # Project force-enabled patterns are already merged — no additional filtering
        return matches

    def get_min_severity(self, trust_mode):
        """Get minimum severity threshold from merged config."""
        mode_config = self._trust_config.get(trust_mode, {})
        return mode_config.get("min_severity", "low")

    def get_trust_default(self):
        """Get default trust mode from merged config."""
        return self._trust_config.get("default_mode", "interactive")

    def should_skip_llm_for_default_tier(self, trust_mode):
        """Check if LLM review should be skipped for default-tier tools."""
        mode_config = self._trust_config.get(trust_mode, {})
        return mode_config.get("skip_llm_for_default_tier", False)

    def get_enforcement_policy(self):
        """Get merged enforcement policy (additive-only: project can only escalate).

        Uses EnforcementPolicy.merge_additive_only to ensure the project
        can escalate decisions (log→ask, ask→deny) but never downgrade them.
        """
        from tweek.hooks.overrides import EnforcementPolicy

        global_policy = EnforcementPolicy(
            self.global_ovr.config.get("enforcement", {}) if self.global_ovr else {}
        )
        project_policy = EnforcementPolicy(
            self.project_ovr.config.get("enforcement", {}) if self.project_ovr else {}
        )
        return EnforcementPolicy.merge_additive_only(global_policy, project_policy)


# ==========================================================================
# Module-level singleton cache (keyed by resolved project path)
# ==========================================================================

_sandboxes: Dict[str, ProjectSandbox] = {}


def _detect_project_dir(working_dir: str) -> Optional[Path]:
    """Detect a project directory by looking for .git/ or .claude/.

    Walks upward from working_dir to find the project root.
    """
    current = Path(working_dir).resolve()
    # Walk up at most 10 levels
    for _ in range(10):
        if (current / ".git").exists() or (current / ".claude").exists():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def get_project_sandbox(
    working_dir: Optional[str],
) -> Optional[ProjectSandbox]:
    """Get the ProjectSandbox for the given working directory.

    Returns None if:
    - working_dir is None
    - No project root is found (no .git/ or .claude/)
    - The project's layer is < PROJECT (bypass or skills-only)

    Uses a singleton cache keyed by resolved project path for performance.
    """
    if not working_dir:
        return None

    project_dir = _detect_project_dir(working_dir)
    if project_dir is None:
        return None

    key = str(project_dir)
    if key in _sandboxes:
        sandbox = _sandboxes[key]
        # Update last used in registry periodically (not on every call)
        return sandbox

    sandbox = ProjectSandbox(project_dir)

    # Check global config for auto_init
    if sandbox.config.auto_init and sandbox.layer >= IsolationLayer.PROJECT:
        if not sandbox.is_initialized:
            try:
                sandbox.initialize()
            except (IOError, OSError) as e:
                # Fall back to global state if we can't create .tweek/
                print(
                    f"WARNING: Could not initialize project sandbox at "
                    f"{sandbox.tweek_dir}: {e}",
                    file=sys.stderr,
                )
                return None

    # Only return sandbox for Layer 2+
    if sandbox.layer < IsolationLayer.PROJECT:
        _sandboxes[key] = sandbox  # Cache even non-PROJECT layers
        return None

    _sandboxes[key] = sandbox
    return sandbox


def reset_sandboxes() -> None:
    """Reset the singleton cache (for testing)."""
    global _sandboxes
    _sandboxes = {}
