"""Tests for the security overrides system (whitelist, pattern toggles, trust levels)."""

import os
import stat
import pytest
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

pytestmark = pytest.mark.security

from tweek.hooks.overrides import (
    SecurityOverrides,
    get_overrides,
    reset_overrides,
    get_trust_mode,
    is_protected_config_file,
    bash_targets_protected_config,
    filter_by_severity,
    OVERRIDES_PATH,
    SEVERITY_RANK,
)


# =========================================================================
# Fixtures
# =========================================================================


@pytest.fixture
def overrides_dir(tmp_path):
    """Create a temporary directory for overrides config."""
    return tmp_path


@pytest.fixture
def basic_config(overrides_dir):
    """Create a basic overrides.yaml for testing."""
    config = {
        "version": 1,
        "trust": {
            "default_mode": "interactive",
            "interactive": {
                "min_severity": "high",
                "skip_llm_for_default_tier": True,
            },
            "automated": {
                "min_severity": "low",
                "skip_llm_for_default_tier": False,
            },
        },
        "whitelist": [
            {
                "path": str(overrides_dir / "safe-project"),
                "tools": ["Read", "Grep"],
                "reason": "Trusted project directory",
            },
            {
                "path": str(overrides_dir / "templates.yaml"),
                "tools": ["Read"],
                "reason": "Templates file",
            },
            {
                "url_prefix": "https://api.github.com/",
                "tools": ["WebFetch"],
                "reason": "GitHub API",
            },
            {
                "tool": "Bash",
                "command_prefix": "git status",
                "reason": "git status is safe",
            },
        ],
        "patterns": {
            "disabled": [
                {"name": "env_command", "reason": "Used frequently"},
                {"name": "ssh_directory_access", "reason": "Work with SSH configs"},
            ],
            "scoped_disables": [
                {
                    "name": "hook_bypass",
                    "paths": [str(overrides_dir / "tweek-src")],
                    "reason": "Tweek source code",
                },
            ],
            "force_enabled": ["credential_theft_critical"],
        },
    }
    config_file = overrides_dir / "overrides.yaml"
    with open(config_file, "w") as f:
        yaml.dump(config, f)
    return config_file


@pytest.fixture
def overrides(basic_config):
    """Create a SecurityOverrides instance with basic config."""
    return SecurityOverrides(config_path=basic_config)


@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset the module-level singleton between tests."""
    reset_overrides()
    yield
    reset_overrides()


# =========================================================================
# Config Loading
# =========================================================================


class TestSecurityOverridesLoad:

    def test_missing_file_returns_empty_config(self, tmp_path):
        """No config file → empty config, backward compatible."""
        so = SecurityOverrides(config_path=tmp_path / "nonexistent.yaml")
        assert so.config == {}

    def test_valid_yaml_loads_correctly(self, basic_config):
        """Valid YAML loads all sections."""
        so = SecurityOverrides(config_path=basic_config)
        assert so.config.get("version") == 1
        assert len(so._whitelist_rules) == 4
        assert len(so._pattern_config.get("disabled", [])) == 2
        assert so._trust_config.get("default_mode") == "interactive"

    def test_malformed_yaml_returns_empty(self, overrides_dir):
        """Malformed YAML → empty config (no crash)."""
        bad_file = overrides_dir / "bad.yaml"
        bad_file.write_text("{{invalid yaml::: [")
        so = SecurityOverrides(config_path=bad_file)
        assert so.config == {}

    def test_empty_file_returns_empty(self, overrides_dir):
        """Empty file → empty config."""
        empty_file = overrides_dir / "empty.yaml"
        empty_file.write_text("")
        so = SecurityOverrides(config_path=empty_file)
        assert so.config == {}


# =========================================================================
# Whitelist Matching
# =========================================================================


class TestWhitelist:

    def test_exact_path_match(self, overrides, overrides_dir):
        """Exact file path match works."""
        result = overrides.check_whitelist(
            "Read",
            {"file_path": str(overrides_dir / "templates.yaml")},
            "",
        )
        assert result is not None
        assert result["reason"] == "Templates file"

    def test_path_prefix_match(self, overrides, overrides_dir):
        """Files inside a whitelisted directory match."""
        # Create the directory so Path.resolve() works
        safe_dir = overrides_dir / "safe-project"
        safe_dir.mkdir(exist_ok=True)
        sub_file = safe_dir / "src" / "main.py"
        sub_file.parent.mkdir(parents=True, exist_ok=True)
        sub_file.touch()

        result = overrides.check_whitelist(
            "Read",
            {"file_path": str(sub_file)},
            "",
        )
        assert result is not None
        assert result["reason"] == "Trusted project directory"

    def test_tool_specific_whitelist(self, overrides, overrides_dir):
        """Whitelist only applies to specified tools."""
        result = overrides.check_whitelist(
            "Write",  # Not in the whitelist tools for this path
            {"file_path": str(overrides_dir / "templates.yaml")},
            "",
        )
        assert result is None

    def test_url_prefix_whitelist(self, overrides):
        """URL prefix matching works for WebFetch."""
        result = overrides.check_whitelist(
            "WebFetch",
            {"url": "https://api.github.com/repos/foo/bar"},
            "",
        )
        assert result is not None
        assert result["reason"] == "GitHub API"

    def test_url_prefix_no_match(self, overrides):
        """URLs not matching prefix are not whitelisted."""
        result = overrides.check_whitelist(
            "WebFetch",
            {"url": "https://evil.com/steal"},
            "",
        )
        assert result is None

    def test_command_prefix_whitelist(self, overrides):
        """Command prefix matching works for Bash."""
        result = overrides.check_whitelist(
            "Bash",
            {"command": "git status --short"},
            "",
        )
        assert result is not None
        assert result["reason"] == "git status is safe"

    def test_command_prefix_no_match(self, overrides):
        """Commands not matching prefix are not whitelisted."""
        result = overrides.check_whitelist(
            "Bash",
            {"command": "rm -rf /"},
            "",
        )
        assert result is None

    def test_no_whitelist_match(self, overrides):
        """Non-matching paths return None."""
        result = overrides.check_whitelist(
            "Read",
            {"file_path": "/some/other/path.py"},
            "",
        )
        assert result is None

    def test_empty_whitelist(self, overrides_dir):
        """No whitelist rules → nothing matches."""
        config_file = overrides_dir / "empty_wl.yaml"
        config_file.write_text(yaml.dump({"version": 1, "whitelist": []}))
        so = SecurityOverrides(config_path=config_file)
        result = so.check_whitelist("Read", {"file_path": "/anything"}, "")
        assert result is None

    def test_rule_with_no_filters_matches_nothing(self, overrides_dir):
        """A rule with no path/url/command/tool filters matches nothing (safety)."""
        config_file = overrides_dir / "no_filter.yaml"
        config_file.write_text(yaml.dump({
            "version": 1,
            "whitelist": [{"reason": "bad rule with no filters"}],
        }))
        so = SecurityOverrides(config_path=config_file)
        result = so.check_whitelist("Read", {"file_path": "/anything"}, "")
        assert result is None


# =========================================================================
# Pattern Toggles
# =========================================================================


class TestPatternToggles:

    def test_globally_disabled_pattern_removed(self, overrides):
        """Globally disabled patterns are filtered out."""
        matches = [
            {"name": "env_command", "severity": "medium"},
            {"name": "other_pattern", "severity": "high"},
        ]
        result = overrides.filter_patterns(matches, "/some/path")
        assert len(result) == 1
        assert result[0]["name"] == "other_pattern"

    def test_scoped_disable_for_matching_path(self, overrides, overrides_dir):
        """Scoped-disabled patterns are removed for matching paths."""
        tweek_src = overrides_dir / "tweek-src"
        tweek_src.mkdir(exist_ok=True)
        target = tweek_src / "hooks" / "pre_tool_use.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()

        matches = [
            {"name": "hook_bypass", "severity": "high"},
            {"name": "other_pattern", "severity": "medium"},
        ]
        result = overrides.filter_patterns(matches, str(target))
        assert len(result) == 1
        assert result[0]["name"] == "other_pattern"

    def test_scoped_disable_does_not_apply_outside_path(self, overrides):
        """Scoped-disabled patterns stay active outside their paths."""
        matches = [
            {"name": "hook_bypass", "severity": "high"},
        ]
        result = overrides.filter_patterns(matches, "/completely/different/path")
        assert len(result) == 1
        assert result[0]["name"] == "hook_bypass"

    def test_force_enabled_overrides_disable(self, overrides):
        """Force-enabled patterns survive even if globally disabled."""
        matches = [
            {"name": "credential_theft_critical", "severity": "critical"},
        ]
        # Even if it were in disabled list, force_enabled keeps it
        result = overrides.filter_patterns(matches, "/any/path")
        assert len(result) == 1

    def test_multiple_disabled_patterns(self, overrides):
        """Multiple globally disabled patterns are all removed."""
        matches = [
            {"name": "env_command", "severity": "medium"},
            {"name": "ssh_directory_access", "severity": "high"},
            {"name": "safe_pattern", "severity": "low"},
        ]
        result = overrides.filter_patterns(matches, "/any/path")
        assert len(result) == 1
        assert result[0]["name"] == "safe_pattern"

    def test_empty_toggle_config(self, overrides_dir):
        """No pattern config → all matches pass through."""
        config_file = overrides_dir / "no_patterns.yaml"
        config_file.write_text(yaml.dump({"version": 1}))
        so = SecurityOverrides(config_path=config_file)
        matches = [{"name": "anything", "severity": "high"}]
        result = so.filter_patterns(matches, "/path")
        assert len(result) == 1

    def test_unknown_pattern_name_ignored(self, overrides):
        """Disabled pattern names that don't match any result are harmless."""
        matches = [{"name": "totally_new_pattern", "severity": "medium"}]
        result = overrides.filter_patterns(matches, "/path")
        assert len(result) == 1


# =========================================================================
# Trust Levels
# =========================================================================


class TestTrustLevel:

    def test_env_var_override_interactive(self, monkeypatch):
        """TWEEK_TRUST_LEVEL=interactive takes precedence."""
        monkeypatch.setenv("TWEEK_TRUST_LEVEL", "interactive")
        assert get_trust_mode() == "interactive"

    def test_env_var_override_automated(self, monkeypatch):
        """TWEEK_TRUST_LEVEL=automated takes precedence."""
        monkeypatch.setenv("TWEEK_TRUST_LEVEL", "automated")
        assert get_trust_mode() == "automated"

    def test_env_var_invalid_falls_through(self, monkeypatch):
        """Invalid TWEEK_TRUST_LEVEL is ignored."""
        monkeypatch.setenv("TWEEK_TRUST_LEVEL", "bogus")
        # Should fall through to other detection methods
        mode = get_trust_mode()
        assert mode in ("interactive", "automated")

    def test_ci_env_detected_as_automated(self, monkeypatch):
        """CI environment variable → automated."""
        monkeypatch.delenv("TWEEK_TRUST_LEVEL", raising=False)
        monkeypatch.setenv("CI", "true")
        assert get_trust_mode() == "automated"

    def test_github_actions_detected(self, monkeypatch):
        """GITHUB_ACTIONS env var → automated."""
        monkeypatch.delenv("TWEEK_TRUST_LEVEL", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        assert get_trust_mode() == "automated"

    def test_default_mode_from_config(self, overrides, monkeypatch):
        """Falls back to config default_mode."""
        monkeypatch.delenv("TWEEK_TRUST_LEVEL", raising=False)
        monkeypatch.delenv("CI", raising=False)
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        mode = get_trust_mode(overrides)
        assert mode == "interactive"  # config sets default_mode: interactive

    def test_min_severity_interactive(self, overrides):
        """Interactive mode has high severity threshold."""
        assert overrides.get_min_severity("interactive") == "high"

    def test_min_severity_automated(self, overrides):
        """Automated mode has low severity threshold."""
        assert overrides.get_min_severity("automated") == "low"

    def test_skip_llm_interactive(self, overrides):
        """Interactive mode skips LLM for default tier."""
        assert overrides.should_skip_llm_for_default_tier("interactive") is True

    def test_no_skip_llm_automated(self, overrides):
        """Automated mode does not skip LLM."""
        assert overrides.should_skip_llm_for_default_tier("automated") is False


# =========================================================================
# Severity Filtering
# =========================================================================


class TestSeverityFiltering:

    def test_filter_keeps_high_and_critical(self):
        """With min_severity=high, keeps high and critical."""
        matches = [
            {"name": "a", "severity": "critical"},
            {"name": "b", "severity": "high"},
            {"name": "c", "severity": "medium"},
            {"name": "d", "severity": "low"},
        ]
        kept, suppressed = filter_by_severity(matches, "high")
        assert len(kept) == 2
        assert {m["name"] for m in kept} == {"a", "b"}
        assert len(suppressed) == 2

    def test_filter_keeps_all_with_low(self):
        """With min_severity=low, keeps everything."""
        matches = [
            {"name": "a", "severity": "critical"},
            {"name": "b", "severity": "low"},
        ]
        kept, suppressed = filter_by_severity(matches, "low")
        assert len(kept) == 2
        assert len(suppressed) == 0

    def test_filter_critical_only(self):
        """With min_severity=critical, only keeps critical."""
        matches = [
            {"name": "a", "severity": "critical"},
            {"name": "b", "severity": "high"},
        ]
        kept, suppressed = filter_by_severity(matches, "critical")
        assert len(kept) == 1
        assert kept[0]["name"] == "a"

    def test_filter_empty_matches(self):
        """Empty matches → empty results."""
        kept, suppressed = filter_by_severity([], "high")
        assert kept == []
        assert suppressed == []


# =========================================================================
# Self-Protection
# =========================================================================


class TestSelfProtection:

    def test_overrides_yaml_is_protected(self):
        """The canonical overrides.yaml path is protected."""
        assert is_protected_config_file(str(OVERRIDES_PATH)) is True

    def test_expanded_home_path_is_protected(self):
        """Tilde-expanded path is protected."""
        assert is_protected_config_file("~/.tweek/overrides.yaml") is True

    def test_other_files_not_protected(self):
        """Random files are not protected."""
        assert is_protected_config_file("/tmp/something.yaml") is False
        assert is_protected_config_file("/home/user/project/main.py") is False

    def test_empty_path_not_protected(self):
        """Empty path returns False."""
        assert is_protected_config_file("") is False

    def test_none_path_not_protected(self):
        """None path returns False."""
        assert is_protected_config_file(None) is False

    def test_bash_redirect_blocked(self):
        """Bash redirect to overrides.yaml is caught."""
        assert bash_targets_protected_config('echo "test" > ~/.tweek/overrides.yaml') is True
        assert bash_targets_protected_config('cat foo >> overrides.yaml') is True

    def test_bash_cp_blocked(self):
        """cp to overrides.yaml is caught."""
        assert bash_targets_protected_config("cp /tmp/evil.yaml overrides.yaml") is True

    def test_bash_mv_blocked(self):
        """mv to overrides.yaml is caught."""
        assert bash_targets_protected_config("mv /tmp/evil.yaml overrides.yaml") is True

    def test_bash_rm_blocked(self):
        """rm of overrides.yaml is caught."""
        assert bash_targets_protected_config("rm overrides.yaml") is True
        assert bash_targets_protected_config("rm -f ~/.tweek/overrides.yaml") is True

    def test_bash_sed_inplace_blocked(self):
        """sed -i on overrides.yaml is caught."""
        assert bash_targets_protected_config("sed -i 's/foo/bar/' overrides.yaml") is True

    def test_bash_tee_blocked(self):
        """tee to overrides.yaml is caught."""
        assert bash_targets_protected_config("echo test | tee overrides.yaml") is True

    def test_bash_safe_command_allowed(self):
        """Normal commands not targeting overrides are allowed."""
        assert bash_targets_protected_config("git status") is False
        assert bash_targets_protected_config("ls -la") is False
        assert bash_targets_protected_config("cat overrides.yaml") is False  # read is OK
        assert bash_targets_protected_config("python3 main.py") is False


# =========================================================================
# get_overrides() Singleton
# =========================================================================


class TestGetOverrides:

    def test_returns_none_when_no_file(self, tmp_path):
        """No config file → returns None (backward compatible)."""
        result = get_overrides(config_path=tmp_path / "nonexistent.yaml")
        assert result is None

    def test_returns_instance_with_valid_config(self, basic_config):
        """Valid config → returns SecurityOverrides instance."""
        result = get_overrides(config_path=basic_config)
        assert result is not None
        assert isinstance(result, SecurityOverrides)

    def test_singleton_returns_same_instance(self, basic_config):
        """Repeated calls return same singleton."""
        a = get_overrides(config_path=basic_config)
        b = get_overrides()  # config_path ignored on second call
        assert a is b


# =========================================================================
# Integration: whitelist + pattern toggles + trust level together
# =========================================================================


class TestIntegration:

    def test_whitelisted_read_skips_screening(self, overrides, overrides_dir):
        """A whitelisted Read should return a match (caller uses this to skip)."""
        safe_dir = overrides_dir / "safe-project"
        safe_dir.mkdir(exist_ok=True)
        target = safe_dir / "dangerous_looking_file.py"
        target.touch()

        match = overrides.check_whitelist(
            "Read", {"file_path": str(target)}, ""
        )
        assert match is not None

    def test_disabled_pattern_plus_severity_filter(self, overrides, overrides_dir):
        """Disabled patterns removed, then severity filter applied."""
        tweek_src = overrides_dir / "tweek-src"
        tweek_src.mkdir(exist_ok=True)

        matches = [
            {"name": "env_command", "severity": "medium"},       # globally disabled
            {"name": "hook_bypass", "severity": "high"},         # scoped disabled for tweek-src
            {"name": "real_threat", "severity": "critical"},     # should survive
            {"name": "minor_issue", "severity": "low"},          # below interactive threshold
        ]

        # Step 1: pattern toggle filtering
        filtered = overrides.filter_patterns(matches, str(tweek_src / "file.py"))
        # env_command removed (global), hook_bypass removed (scoped)
        assert len(filtered) == 2
        names = {m["name"] for m in filtered}
        assert names == {"real_threat", "minor_issue"}

        # Step 2: severity filtering for interactive mode (min_severity=high)
        kept, suppressed = filter_by_severity(filtered, "high")
        assert len(kept) == 1
        assert kept[0]["name"] == "real_threat"
        assert len(suppressed) == 1
        assert suppressed[0]["name"] == "minor_issue"

    def test_automated_mode_keeps_low_severity(self, overrides):
        """Automated mode (min_severity=low) keeps everything."""
        matches = [
            {"name": "minor_thing", "severity": "low"},
            {"name": "big_thing", "severity": "critical"},
        ]
        filtered = overrides.filter_patterns(matches, "/non/scoped/path")
        kept, suppressed = filter_by_severity(
            filtered, overrides.get_min_severity("automated")
        )
        assert len(kept) == 2
        assert len(suppressed) == 0
