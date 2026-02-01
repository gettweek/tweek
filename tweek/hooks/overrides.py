"""
Tweek Security Overrides

Loads and applies human-only security overrides from ~/.tweek/overrides.yaml.
Used by both PreToolUse and PostToolUse hooks.

Features:
- Whitelist: Exempt specific paths/tools/URLs from screening
- Pattern Toggles: Enable/disable individual detection patterns
- Trust Levels: Different severity thresholds for interactive vs automated sessions

IMPORTANT: The overrides.yaml file is protected from AI modification.
The PreToolUse hook blocks Write/Edit/Bash commands that target this file.
Only a human editing the file directly can change security overrides.
"""

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


# The canonical location of the overrides config file
OVERRIDES_PATH = Path.home() / ".tweek" / "overrides.yaml"

# Files protected from AI modification
PROTECTED_CONFIG_FILES = [
    OVERRIDES_PATH,
    Path.home() / ".tweek" / "skills",  # Entire skills management directory
    Path.home() / ".tweek" / "projects",  # Project registry
]


class SecurityOverrides:
    """Loads and queries the ~/.tweek/overrides.yaml configuration."""

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or OVERRIDES_PATH
        self.config = self._load()
        self._whitelist_rules: List[Dict] = self.config.get("whitelist", [])
        self._pattern_config: Dict = self.config.get("patterns", {})
        self._trust_config: Dict = self.config.get("trust", {})

    def _load(self) -> dict:
        """Load overrides YAML. Returns empty dict if file missing (backward compatible)."""
        if not self.config_path.exists():
            return {}
        self._check_permissions()
        try:
            with open(self.config_path) as f:
                return yaml.safe_load(f) or {}
        except Exception:
            return {}

    def _check_permissions(self):
        """Warn via stderr if overrides file has insecure permissions."""
        try:
            import stat
            mode = self.config_path.stat().st_mode
            if mode & (stat.S_IWGRP | stat.S_IWOTH):
                print(
                    f"WARNING: {self.config_path} has group/other write permissions. "
                    "Run: chmod 600 ~/.tweek/overrides.yaml",
                    file=sys.stderr,
                )
        except OSError:
            pass

    def check_whitelist(
        self, tool_name: str, tool_input: Dict[str, Any], content: str
    ) -> Optional[Dict]:
        """
        Check if this invocation matches a whitelist rule.

        Returns the matching rule dict if whitelisted, None otherwise.
        """
        for rule in self._whitelist_rules:
            if self._matches_rule(rule, tool_name, tool_input, content):
                return rule
        return None

    def _matches_rule(
        self, rule: Dict, tool_name: str, tool_input: Dict[str, Any], content: str
    ) -> bool:
        """Check if a single whitelist rule matches the current invocation."""
        # If rule specifies tools, tool_name must be in that list
        rule_tools = rule.get("tools")
        if rule_tools and tool_name not in rule_tools:
            return False

        # If rule specifies a specific tool (singular), check that
        rule_tool = rule.get("tool")
        if rule_tool and tool_name != rule_tool:
            return False

        # Path matching
        rule_path = rule.get("path")
        if rule_path:
            target_path = tool_input.get("file_path", "")
            if not target_path:
                return False
            if not self._path_matches(rule_path, target_path):
                return False

        # URL prefix matching
        url_prefix = rule.get("url_prefix")
        if url_prefix:
            target_url = tool_input.get("url", "")
            if not target_url or not target_url.startswith(url_prefix):
                return False

        # Command prefix matching (for Bash)
        cmd_prefix = rule.get("command_prefix")
        if cmd_prefix:
            command = tool_input.get("command", "")
            if not command or not command.strip().startswith(cmd_prefix):
                return False

        # If no path/url/command_prefix specified, the rule matches on tool alone
        # (or matches everything if no tool filter either)
        has_filter = rule_path or url_prefix or cmd_prefix
        has_tool_filter = rule_tools or rule_tool
        if not has_filter and not has_tool_filter:
            # Rule with no filters matches nothing (safety)
            return False

        return True

    def _path_matches(self, rule_path: str, target_path: str) -> bool:
        """Check if target_path matches a rule path (prefix match with resolution)."""
        try:
            rule_resolved = Path(rule_path).expanduser().resolve()
            target_resolved = Path(target_path).expanduser().resolve()

            # Exact match
            if target_resolved == rule_resolved:
                return True

            # Prefix match (target is inside the rule directory)
            try:
                target_resolved.relative_to(rule_resolved)
                return True
            except ValueError:
                pass
        except (OSError, ValueError):
            pass
        return False

    def filter_patterns(
        self, matches: List[Dict], working_path: str
    ) -> List[Dict]:
        """
        Remove disabled and scoped-disabled patterns from a match list.

        Args:
            matches: List of pattern match dicts (each has 'name' key)
            working_path: The file path or working directory for scoped checks

        Returns:
            Filtered list with disabled patterns removed
        """
        disabled_names = {
            p["name"] for p in self._pattern_config.get("disabled", [])
            if "name" in p
        }
        scoped_disables = self._pattern_config.get("scoped_disables", [])
        force_enabled = set(self._pattern_config.get("force_enabled", []))

        filtered = []
        for match in matches:
            name = match.get("name", "")

            # Force-enabled patterns are never filtered
            if name in force_enabled:
                filtered.append(match)
                continue

            # Globally disabled
            if name in disabled_names:
                continue

            # Scoped disables
            scoped_disabled = False
            for scope in scoped_disables:
                if scope.get("name") != name:
                    continue
                for scope_path in scope.get("paths", []):
                    if self._path_matches(scope_path, working_path):
                        scoped_disabled = True
                        break
                if scoped_disabled:
                    break

            if not scoped_disabled:
                filtered.append(match)

        return filtered

    def get_min_severity(self, trust_mode: str) -> str:
        """Get minimum severity threshold for the given trust mode."""
        mode_config = self._trust_config.get(trust_mode, {})
        return mode_config.get("min_severity", "low")

    def get_trust_default(self) -> str:
        """Get default trust mode from config."""
        return self._trust_config.get("default_mode", "interactive")

    def should_skip_llm_for_default_tier(self, trust_mode: str) -> bool:
        """Check if LLM review should be skipped for default-tier tools."""
        mode_config = self._trust_config.get(trust_mode, {})
        return mode_config.get("skip_llm_for_default_tier", False)


# =========================================================================
# Module-level singleton
# =========================================================================

_overrides: Optional[SecurityOverrides] = None


def get_overrides(config_path: Optional[Path] = None) -> Optional[SecurityOverrides]:
    """
    Get the singleton SecurityOverrides instance.

    Returns None if no config file exists (backward compatible -- all
    screening runs as before).
    """
    global _overrides
    if _overrides is None:
        _overrides = SecurityOverrides(config_path)
    if not _overrides.config:
        return None
    return _overrides


def reset_overrides():
    """Reset the singleton (for testing)."""
    global _overrides
    _overrides = None


# =========================================================================
# Trust Level Detection
# =========================================================================


def get_trust_mode(overrides: Optional[SecurityOverrides] = None) -> str:
    """
    Determine whether the current session is interactive or automated.

    Detection hierarchy (first match wins):
    1. Explicit env var: TWEEK_TRUST_LEVEL=interactive|automated
    2. Parent process check: launchd/cron/systemd → automated
    3. CI environment variables → automated
    4. Default from overrides.yaml config
    5. Fallback: interactive

    Returns: "interactive" or "automated"
    """
    # 1. Explicit environment variable (highest priority)
    env_trust = os.environ.get("TWEEK_TRUST_LEVEL", "").lower().strip()
    if env_trust in ("interactive", "automated"):
        return env_trust

    # 2. Parent process heuristic (macOS/Linux)
    try:
        ppid = os.getppid()
        result = subprocess.run(
            ["ps", "-p", str(ppid), "-o", "comm="],
            capture_output=True, text=True, timeout=1,
        )
        parent_name = result.stdout.strip().lower()
        automated_parents = {
            "launchd", "cron", "crond", "systemd", "atd",
            "supervisord", "init",
        }
        if parent_name in automated_parents:
            return "automated"
    except Exception:
        pass

    # 3. CI environment variables
    ci_vars = [
        "CI", "CONTINUOUS_INTEGRATION", "GITHUB_ACTIONS",
        "JENKINS_HOME", "GITLAB_CI", "CIRCLECI", "BUILDKITE",
    ]
    for var in ci_vars:
        if os.environ.get(var):
            return "automated"

    # 4. Config default
    if overrides:
        return overrides.get_trust_default()

    # 5. Fallback
    return "interactive"


# =========================================================================
# Self-Protection: prevent AI from modifying the overrides file
# =========================================================================


def is_protected_config_file(file_path: str) -> bool:
    """
    Check if a file path points to a human-only config file.

    Used by PreToolUse to block Write/Edit targeting overrides.yaml,
    project sandbox config, and other protected paths.
    """
    if not file_path:
        return False
    try:
        resolved = Path(file_path).expanduser().resolve()

        # Check explicit protected paths
        for protected in PROTECTED_CONFIG_FILES:
            protected_resolved = protected.resolve()
            if resolved == protected_resolved:
                return True
            # Check if target is inside a protected directory
            try:
                resolved.relative_to(protected_resolved)
                return True
            except ValueError:
                pass

        # Protect project-level .tweek/ directories (sandbox state)
        # Any file inside a .tweek/ directory is protected
        for part in resolved.parts:
            if part == ".tweek":
                return True

    except (OSError, ValueError):
        pass
    return False


def bash_targets_protected_config(command: str) -> bool:
    """
    Check if a bash command would modify the protected config files.

    Catches common shell patterns: redirects, cp, mv, sed -i, rm, tee, etc.
    """
    if not command:
        return False

    # Patterns that indicate writing to the overrides file
    write_patterns = [
        r'(>|>>)\s*.*overrides\.yaml',
        r'(cp|mv|rsync)\s+.*overrides\.yaml',
        r'tee\s+.*overrides\.yaml',
        r'sed\s+-i.*overrides\.yaml',
        r'perl\s+-[pi].*overrides\.yaml',
        r'(echo|cat|printf)\s+.*>\s*.*overrides\.yaml',
        r'rm\s+.*overrides\.yaml',
        r'unlink\s+.*overrides\.yaml',
        r'truncate\s+.*overrides\.yaml',
        r'python[3]?\s+.*overrides\.yaml',
        r'ruby\s+.*overrides\.yaml',
        r'node\s+.*overrides\.yaml',
    ]

    for pattern in write_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return True

    # Also check for the full path
    overrides_str = str(OVERRIDES_PATH)
    full_path_patterns = [
        rf'(>|>>)\s*.*{re.escape(overrides_str)}',
        rf'(cp|mv|rsync)\s+.*{re.escape(overrides_str)}',
        rf'rm\s+.*{re.escape(overrides_str)}',
        rf'tee\s+.*{re.escape(overrides_str)}',
    ]
    for pattern in full_path_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return True

    # Protect project-level .tweek/ directories (sandbox state)
    tweek_dir_patterns = [
        r'(>|>>)\s*.*\.tweek/',
        r'(cp|mv|rsync)\s+.*\.tweek/',
        r'rm\s+(-rf?\s+)?.*\.tweek/',
        r'tee\s+.*\.tweek/',
        r'sed\s+-i.*\.tweek/',
        r'(echo|cat|printf)\s+.*>\s*.*\.tweek/',
    ]
    for pattern in tweek_dir_patterns:
        if re.search(pattern, command, re.IGNORECASE):
            return True

    return False


# =========================================================================
# Severity Filtering
# =========================================================================

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def filter_by_severity(
    matches: List[Dict], min_severity: str
) -> tuple[List[Dict], List[Dict]]:
    """
    Filter pattern matches by severity threshold.

    Returns (kept, suppressed) -- two lists.
    'kept' contains matches at or above the threshold.
    'suppressed' contains matches below the threshold.
    """
    min_rank = SEVERITY_RANK.get(min_severity, 3)
    kept = []
    suppressed = []
    for match in matches:
        match_rank = SEVERITY_RANK.get(match.get("severity", "medium"), 2)
        if match_rank <= min_rank:
            kept.append(match)
        else:
            suppressed.append(match)
    return kept, suppressed
