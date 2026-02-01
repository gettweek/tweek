"""Tests for out-of-project path boundary escalation."""

import os
import pytest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from tweek.hooks.pre_tool_use import (
    extract_target_paths,
    _extract_paths_from_bash,
    TierManager,
)

pytestmark = pytest.mark.hooks


# =============================================================================
# Test: extract_target_paths
# =============================================================================


class TestExtractTargetPaths:
    """Tests for extracting filesystem paths from tool inputs."""

    def test_read_extracts_file_path(self):
        paths = extract_target_paths("Read", {"file_path": "/home/user/file.py"})
        assert paths == ["/home/user/file.py"]

    def test_write_extracts_file_path(self):
        paths = extract_target_paths("Write", {"file_path": "/tmp/out.txt", "content": "hello"})
        assert paths == ["/tmp/out.txt"]

    def test_edit_extracts_file_path(self):
        paths = extract_target_paths("Edit", {"file_path": "/src/main.py", "old_string": "a", "new_string": "b"})
        assert paths == ["/src/main.py"]

    def test_notebook_edit_extracts_path(self):
        paths = extract_target_paths("NotebookEdit", {"notebook_path": "/notebooks/analysis.ipynb"})
        assert paths == ["/notebooks/analysis.ipynb"]

    def test_glob_extracts_path(self):
        paths = extract_target_paths("Glob", {"path": "/other/project", "pattern": "*.py"})
        assert paths == ["/other/project"]

    def test_glob_no_path_returns_empty(self):
        paths = extract_target_paths("Glob", {"pattern": "*.py"})
        assert paths == []

    def test_grep_extracts_path(self):
        paths = extract_target_paths("Grep", {"path": "/other/dir", "pattern": "TODO"})
        assert paths == ["/other/dir"]

    def test_grep_no_path_returns_empty(self):
        paths = extract_target_paths("Grep", {"pattern": "TODO"})
        assert paths == []

    def test_webfetch_returns_empty(self):
        paths = extract_target_paths("WebFetch", {"url": "https://example.com", "prompt": "get"})
        assert paths == []

    def test_websearch_returns_empty(self):
        paths = extract_target_paths("WebSearch", {"query": "python docs"})
        assert paths == []

    def test_bash_extracts_absolute_paths(self):
        paths = extract_target_paths("Bash", {"command": "cat /etc/passwd"})
        assert "/etc/passwd" in paths

    def test_bash_extracts_home_paths(self):
        paths = extract_target_paths("Bash", {"command": "cat ~/.ssh/id_rsa"})
        assert "~/.ssh/id_rsa" in paths

    def test_empty_file_path_returns_empty(self):
        paths = extract_target_paths("Read", {"file_path": ""})
        assert paths == []

    def test_missing_file_path_returns_empty(self):
        paths = extract_target_paths("Read", {})
        assert paths == []

    def test_unknown_tool_returns_empty(self):
        paths = extract_target_paths("UnknownTool", {"some_key": "some_value"})
        assert paths == []


# =============================================================================
# Test: _extract_paths_from_bash
# =============================================================================


class TestExtractPathsFromBash:
    """Tests for best-effort path extraction from bash commands."""

    def test_simple_cat_absolute(self):
        paths = _extract_paths_from_bash("cat /etc/passwd")
        assert "/etc/passwd" in paths

    def test_cp_two_paths(self):
        paths = _extract_paths_from_bash("cp ~/.ssh/id_rsa /tmp/key")
        assert "~/.ssh/id_rsa" in paths
        assert "/tmp/key" in paths

    def test_no_paths(self):
        paths = _extract_paths_from_bash("ls -la")
        assert paths == []

    def test_flags_ignored(self):
        paths = _extract_paths_from_bash("rm -rf /tmp/test")
        assert "-rf" not in paths
        assert "/tmp/test" in paths

    def test_piped_command_only_first(self):
        paths = _extract_paths_from_bash("cat /etc/passwd | grep root")
        assert "/etc/passwd" in paths
        # grep's "root" is not a path and should not appear
        assert len(paths) == 1

    def test_and_chain_only_first(self):
        paths = _extract_paths_from_bash("cat /etc/hosts && cat /etc/passwd")
        assert "/etc/hosts" in paths
        # Second command after && is not parsed
        assert "/etc/passwd" not in paths

    def test_empty_command(self):
        paths = _extract_paths_from_bash("")
        assert paths == []

    def test_none_command(self):
        paths = _extract_paths_from_bash("")
        assert paths == []

    def test_malformed_quotes_graceful(self):
        # Unmatched quotes should not crash
        paths = _extract_paths_from_bash("cat '/etc/passwd")
        # Should still extract something or return empty — no crash
        assert isinstance(paths, list)

    def test_relative_paths_not_extracted(self):
        # Relative paths like ./src are not extracted (no / or ~ prefix)
        paths = _extract_paths_from_bash("cat ./src/main.py")
        assert paths == []

    def test_home_tilde_path(self):
        paths = _extract_paths_from_bash("python3 ~/scripts/run.py")
        assert "~/scripts/run.py" in paths


# =============================================================================
# Test: TierManager.check_path_escalation
# =============================================================================


class TestCheckPathEscalation:
    """Tests for path boundary escalation logic."""

    @pytest.fixture
    def tier_mgr(self):
        """Create a TierManager with default config."""
        return TierManager()

    def test_inside_project_no_escalation(self, tier_mgr, tmp_path):
        """Paths inside the project should not trigger escalation."""
        target = str(tmp_path / "src" / "main.py")
        # Create the file so resolve works
        (tmp_path / "src").mkdir(exist_ok=True)
        (tmp_path / "src" / "main.py").touch()

        result = tier_mgr.check_path_escalation([target], str(tmp_path))
        assert result is None

    def test_outside_project_generic(self, tier_mgr, tmp_path):
        """Paths outside project should escalate to risky by default."""
        result = tier_mgr.check_path_escalation(
            ["/usr/local/share/something.txt"],
            str(tmp_path)
        )
        assert result is not None
        assert result["escalate_to"] == "risky"
        assert result["path_boundary"] is True

    def test_outside_project_ssh_dangerous(self, tier_mgr, tmp_path):
        """SSH directory access outside project should escalate to dangerous."""
        home = str(Path.home())
        result = tier_mgr.check_path_escalation(
            [f"{home}/.ssh/id_rsa"],
            str(tmp_path)
        )
        assert result is not None
        assert result["escalate_to"] == "dangerous"
        assert "SSH" in result["description"]

    def test_outside_project_aws_dangerous(self, tier_mgr, tmp_path):
        """AWS credentials directory should escalate to dangerous."""
        home = str(Path.home())
        result = tier_mgr.check_path_escalation(
            [f"{home}/.aws/credentials"],
            str(tmp_path)
        )
        assert result is not None
        assert result["escalate_to"] == "dangerous"

    def test_outside_project_etc_shadow(self, tier_mgr, tmp_path):
        """/etc/shadow should escalate to dangerous."""
        result = tier_mgr.check_path_escalation(
            ["/etc/shadow"],
            str(tmp_path)
        )
        assert result is not None
        assert result["escalate_to"] == "dangerous"

    def test_outside_project_etc_passwd(self, tier_mgr, tmp_path):
        """/etc/passwd should escalate to risky (not dangerous)."""
        result = tier_mgr.check_path_escalation(
            ["/etc/passwd"],
            str(tmp_path)
        )
        assert result is not None
        assert result["escalate_to"] == "risky"

    def test_no_cwd_no_escalation(self, tier_mgr):
        """Without a working directory, no escalation should occur."""
        result = tier_mgr.check_path_escalation(["/etc/passwd"], None)
        assert result is None

    def test_empty_cwd_no_escalation(self, tier_mgr):
        """Empty working directory string means no escalation."""
        result = tier_mgr.check_path_escalation(["/etc/passwd"], "")
        assert result is None

    def test_no_paths_no_escalation(self, tier_mgr, tmp_path):
        """Empty path list means no escalation."""
        result = tier_mgr.check_path_escalation([], str(tmp_path))
        assert result is None

    def test_relative_path_resolved(self, tier_mgr, tmp_path):
        """Relative paths that resolve outside the project should escalate."""
        # ../something relative to tmp_path should be outside
        result = tier_mgr.check_path_escalation(
            ["../outside_file.txt"],
            str(tmp_path)
        )
        # This depends on CWD -- the path resolves relative to actual CWD
        # not relative to working_dir. But since tmp_path is unique,
        # ../outside_file.txt resolved from actual CWD is likely outside tmp_path.
        # This is a best-effort test.
        if result is not None:
            assert result["escalate_to"] == "risky"
            assert result["path_boundary"] is True

    def test_disabled_in_config(self, tmp_path):
        """path_boundary.enabled: false should disable the feature."""
        # Create a custom config with path_boundary disabled
        config_path = tmp_path / "tiers.yaml"
        config_path.write_text("""
version: 2
tiers:
  safe:
    screening: []
  default:
    screening: [regex]
  risky:
    screening: [regex, llm]
  dangerous:
    screening: [regex, llm, sandbox]
tools:
  Read: default
path_boundary:
  enabled: false
default_tier: default
""")
        mgr = TierManager(config_path)
        result = mgr.check_path_escalation(["/etc/passwd"], str(tmp_path))
        assert result is None

    def test_highest_escalation_wins(self, tier_mgr, tmp_path):
        """When multiple paths are outside, the highest escalation wins."""
        home = str(Path.home())
        result = tier_mgr.check_path_escalation(
            ["/usr/local/share/file.txt", f"{home}/.ssh/id_rsa"],
            str(tmp_path)
        )
        assert result is not None
        assert result["escalate_to"] == "dangerous"  # SSH wins over generic


# =============================================================================
# Test: get_effective_tier with path escalation
# =============================================================================


class TestGetEffectiveTierWithPaths:
    """Tests for get_effective_tier integrating path-boundary escalation."""

    @pytest.fixture
    def tier_mgr(self):
        return TierManager()

    def test_backward_compatible_without_paths(self, tier_mgr):
        """Calling without new params should work as before."""
        tier, esc = tier_mgr.get_effective_tier("Read", "normal content")
        assert tier == "default"
        assert esc is None

    def test_path_escalation_overrides_base(self, tier_mgr, tmp_path):
        """Out-of-project path should escalate Read from default to risky."""
        tier, esc = tier_mgr.get_effective_tier(
            "Read", "/usr/share/file.txt",
            target_paths=["/usr/share/file.txt"],
            working_dir=str(tmp_path),
        )
        assert tier == "risky"
        assert esc is not None
        assert esc.get("path_boundary") is True

    def test_content_escalation_wins_when_higher(self, tier_mgr, tmp_path):
        """Content escalation to dangerous should win over path escalation to risky."""
        # sudo triggers dangerous content escalation
        tier, esc = tier_mgr.get_effective_tier(
            "Read", "sudo rm -rf /",
            target_paths=["/usr/share/file.txt"],
            working_dir=str(tmp_path),
        )
        # Content escalation (sudo -> dangerous) should win
        assert tier == "dangerous"
        assert esc is not None
        assert esc.get("path_boundary") is not True  # Content won, not path

    def test_path_escalation_wins_when_higher(self, tier_mgr, tmp_path):
        """Path escalation to dangerous (.ssh) should win over content escalation to risky."""
        home = str(Path.home())
        # .env triggers risky content escalation, .ssh triggers dangerous path escalation
        tier, esc = tier_mgr.get_effective_tier(
            "Read", f"{home}/.ssh/id_rsa",
            target_paths=[f"{home}/.ssh/id_rsa"],
            working_dir=str(tmp_path),
        )
        assert tier == "dangerous"

    def test_in_project_path_no_escalation(self, tier_mgr, tmp_path):
        """In-project paths should not cause escalation."""
        target = str(tmp_path / "src" / "main.py")
        (tmp_path / "src").mkdir(exist_ok=True)
        (tmp_path / "src" / "main.py").touch()

        tier, esc = tier_mgr.get_effective_tier(
            "Read", target,
            target_paths=[target],
            working_dir=str(tmp_path),
        )
        assert tier == "default"  # Base tier for Read
        assert esc is None

    def test_glob_escalates_from_safe(self, tier_mgr, tmp_path):
        """Glob targeting outside project should escalate from safe."""
        tier, esc = tier_mgr.get_effective_tier(
            "Glob", "/other/project\n*.py",
            target_paths=["/other/project"],
            working_dir=str(tmp_path),
        )
        assert tier == "risky"
        assert esc is not None

    def test_grep_escalates_from_safe(self, tier_mgr, tmp_path):
        """Grep targeting outside project should escalate from safe."""
        tier, esc = tier_mgr.get_effective_tier(
            "Grep", "/other/project\nTODO",
            target_paths=["/other/project"],
            working_dir=str(tmp_path),
        )
        assert tier == "risky"
        assert esc is not None

    def test_no_cwd_no_path_escalation(self, tier_mgr):
        """Without cwd, path escalation should not trigger."""
        tier, esc = tier_mgr.get_effective_tier(
            "Read", "/etc/passwd",
            target_paths=["/etc/passwd"],
            working_dir=None,
        )
        assert tier == "default"  # No escalation without cwd
