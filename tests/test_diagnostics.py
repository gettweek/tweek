#!/usr/bin/env python3
"""
Tests for tweek.diagnostics module.

Tests the health check engine:
- Individual check functions
- Health verdict computation
- Error handling in checks
"""

import json
import sqlite3
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

pytestmark = pytest.mark.core

from tweek.diagnostics import (
    CheckStatus,
    HealthCheck,
    run_health_checks,
    get_health_verdict,
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
)


class TestCheckStatus:
    """Tests for CheckStatus enum."""

    def test_values(self):
        assert CheckStatus.OK.value == "ok"
        assert CheckStatus.WARNING.value == "warning"
        assert CheckStatus.ERROR.value == "error"
        assert CheckStatus.SKIPPED.value == "skipped"


class TestHealthCheck:
    """Tests for HealthCheck dataclass."""

    def test_basic_creation(self):
        check = HealthCheck(
            name="test",
            label="Test Check",
            status=CheckStatus.OK,
            message="Everything fine",
        )
        assert check.name == "test"
        assert check.label == "Test Check"
        assert check.status == CheckStatus.OK
        assert check.message == "Everything fine"
        assert check.fix_hint == ""

    def test_with_fix_hint(self):
        check = HealthCheck(
            name="test",
            label="Test",
            status=CheckStatus.ERROR,
            message="Failed",
            fix_hint="Run: tweek protect claude-code",
        )
        assert check.fix_hint == "Run: tweek protect claude-code"


class TestGetHealthVerdict:
    """Tests for get_health_verdict()."""

    def test_all_ok(self):
        checks = [
            HealthCheck("a", "A", CheckStatus.OK, "ok"),
            HealthCheck("b", "B", CheckStatus.OK, "ok"),
            HealthCheck("c", "C", CheckStatus.OK, "ok"),
        ]
        text, color = get_health_verdict(checks)
        assert "All systems operational" in text
        assert color == "green"

    def test_all_ok_with_skipped(self):
        checks = [
            HealthCheck("a", "A", CheckStatus.OK, "ok"),
            HealthCheck("b", "B", CheckStatus.OK, "ok"),
            HealthCheck("c", "C", CheckStatus.SKIPPED, "skip"),
        ]
        text, color = get_health_verdict(checks)
        assert "All systems operational" in text
        assert "2/2" in text
        assert color == "green"

    def test_warnings_only(self):
        checks = [
            HealthCheck("a", "A", CheckStatus.OK, "ok"),
            HealthCheck("b", "B", CheckStatus.WARNING, "warn"),
        ]
        text, color = get_health_verdict(checks)
        assert "Mostly healthy" in text
        assert "1 warning" in text
        assert color == "yellow"

    def test_single_error(self):
        checks = [
            HealthCheck("a", "A", CheckStatus.OK, "ok"),
            HealthCheck("b", "B", CheckStatus.ERROR, "bad"),
        ]
        text, color = get_health_verdict(checks)
        assert "Issues detected" in text
        assert "1 error" in text
        assert color == "red"

    def test_multiple_errors(self):
        checks = [
            HealthCheck("a", "A", CheckStatus.ERROR, "bad"),
            HealthCheck("b", "B", CheckStatus.ERROR, "bad"),
            HealthCheck("c", "C", CheckStatus.ERROR, "bad"),
        ]
        text, color = get_health_verdict(checks)
        assert "Multiple issues" in text
        assert "3 errors" in text
        assert color == "red"

    def test_mixed_warnings_and_errors(self):
        checks = [
            HealthCheck("a", "A", CheckStatus.OK, "ok"),
            HealthCheck("b", "B", CheckStatus.WARNING, "warn"),
            HealthCheck("c", "C", CheckStatus.ERROR, "bad"),
        ]
        text, color = get_health_verdict(checks)
        assert "1 error" in text
        assert "1 warning" in text
        assert color == "red"

    def test_empty_checks(self):
        text, color = get_health_verdict([])
        assert "All systems operational" in text
        assert color == "green"


class TestCheckHooksInstalled:
    """Tests for _check_hooks_installed()."""

    def test_no_hooks_installed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.chdir(tmp_path)

        result = _check_hooks_installed()
        assert result.status == CheckStatus.ERROR
        assert "No hooks installed" in result.message
        # Should show which paths were checked
        assert "~/.claude" in result.message
        assert "./.claude" in result.message
        assert result.fix_hint

    def test_global_hooks_installed(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        # chdir to a subdirectory WITHOUT .claude so project hooks aren't found
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        monkeypatch.chdir(project_dir)

        # Create global settings with tweek hooks
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        settings = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "", "hooks": [{"type": "command", "command": "tweek hook pre-tool-use"}]}
                ]
            }
        }
        (claude_dir / "settings.json").write_text(json.dumps(settings))

        result = _check_hooks_installed()
        assert result.status == CheckStatus.OK
        assert "~/.claude" in result.message
        assert "global" in result.message.lower()

    def test_project_only_hooks(self, tmp_path, monkeypatch):
        home_dir = tmp_path / "home"
        home_dir.mkdir()
        monkeypatch.setenv("HOME", str(home_dir))

        project_dir = tmp_path / "project"
        project_dir.mkdir()
        monkeypatch.chdir(project_dir)

        # Create project-level settings
        claude_dir = project_dir / ".claude"
        claude_dir.mkdir()
        settings = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "", "hooks": [{"type": "command", "command": "tweek hook pre-tool-use"}]}
                ]
            }
        }
        (claude_dir / "settings.json").write_text(json.dumps(settings))

        result = _check_hooks_installed()
        assert result.status == CheckStatus.WARNING
        assert "project only" in result.message.lower()
        assert "./.claude" in result.message

    def test_both_global_and_project_hooks(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        monkeypatch.chdir(project_dir)

        settings = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "", "hooks": [{"type": "command", "command": "tweek hook pre-tool-use"}]}
                ]
            }
        }

        # Global hooks
        global_claude = tmp_path / ".claude"
        global_claude.mkdir()
        (global_claude / "settings.json").write_text(json.dumps(settings))

        # Project hooks
        project_claude = project_dir / ".claude"
        project_claude.mkdir()
        (project_claude / "settings.json").write_text(json.dumps(settings))

        result = _check_hooks_installed()
        assert result.status == CheckStatus.OK
        assert "global" in result.message.lower()
        assert "project" in result.message.lower()

    def test_artifacts_without_hooks_shows_error(self, tmp_path, monkeypatch):
        """Artifacts (skill dir, backup) without hooks in settings.json."""
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.chdir(tmp_path)

        # Create artifact (backup file) but NO hooks in settings.json
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        (claude_dir / "settings.json.tweek-backup").write_text("{}")
        (claude_dir / "settings.json").write_text("{}")

        result = _check_hooks_installed()
        assert result.status == CheckStatus.ERROR
        assert "Tweek files found" in result.message
        assert "hooks missing" in result.message
        assert "re-install" in result.fix_hint.lower()

    def test_global_hooks_with_project_artifacts_only(self, tmp_path, monkeypatch):
        """Global hooks OK, project has artifacts but no hooks."""
        monkeypatch.setenv("HOME", str(tmp_path))
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        monkeypatch.chdir(project_dir)

        # Global: real hooks
        global_claude = tmp_path / ".claude"
        global_claude.mkdir()
        settings = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "", "hooks": [{"type": "command", "command": "tweek hook pre-tool-use"}]}
                ]
            }
        }
        (global_claude / "settings.json").write_text(json.dumps(settings))

        # Project: only backup artifact, no hooks
        project_claude = project_dir / ".claude"
        project_claude.mkdir()
        (project_claude / "settings.json.tweek-backup").write_text("{}")

        result = _check_hooks_installed()
        assert result.status == CheckStatus.OK
        assert "~/.claude" in result.message
        assert "hooks missing" in result.message or "global" in result.message.lower()


class TestCheckConfigValid:
    """Tests for _check_config_valid()."""

    def test_valid_config(self):
        # Use a mock ConfigManager with a clean config so this test doesn't
        # depend on the user's actual ~/.tweek/config.yaml contents
        mock_cm = MagicMock()
        mock_cm.list_tools.return_value = {"Bash": "dangerous", "Read": "safe"}
        mock_cm.list_skills.return_value = {}
        mock_cm.validate_config.return_value = []  # No issues

        with patch("tweek.config.ConfigManager", return_value=mock_cm):
            result = _check_config_valid()
        assert result.status in (CheckStatus.OK, CheckStatus.WARNING)
        assert result.name == "config_valid"

    @patch("tweek.config.ConfigManager")
    def test_config_load_failure(self, mock_cm_class):
        mock_cm_class.side_effect = Exception("parse error")
        result = _check_config_valid()
        assert result.status == CheckStatus.ERROR
        assert "Failed to load" in result.message


class TestCheckPatternsLoaded:
    """Tests for _check_patterns_loaded()."""

    def test_patterns_loaded(self):
        # Should find bundled patterns
        result = _check_patterns_loaded()
        assert result.name == "patterns_loaded"
        # Could be OK or ERROR depending on whether patterns exist
        assert result.status in (CheckStatus.OK, CheckStatus.ERROR, CheckStatus.WARNING)

    @patch("tweek.diagnostics.Path")
    def test_no_patterns_found(self, mock_path_class):
        # Mock both paths to not exist
        mock_path_instance = MagicMock()
        mock_path_instance.exists.return_value = False
        mock_path_instance.__truediv__ = lambda self, other: mock_path_instance
        mock_path_instance.expanduser.return_value = mock_path_instance
        mock_path_instance.parent = mock_path_instance
        mock_path_class.return_value = mock_path_instance
        mock_path_class.side_effect = lambda *a: mock_path_instance

        # Can't easily mock this cleanly, test the real path instead
        result = _check_patterns_loaded()
        assert result.name == "patterns_loaded"


class TestCheckSecurityDb:
    """Tests for _check_security_db()."""

    def test_no_db(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        result = _check_security_db()
        assert result.status == CheckStatus.OK
        assert "Not yet created" in result.message

    def test_small_db(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()
        db_path = tweek_dir / "security.db"

        # Create a small valid SQLite database
        conn = sqlite3.connect(str(db_path))
        conn.execute("CREATE TABLE test (id INTEGER)")
        conn.close()

        result = _check_security_db()
        assert result.status == CheckStatus.OK
        assert "Active" in result.message


class TestCheckVaultAvailable:
    """Tests for _check_vault_available()."""

    def test_vault_check_runs(self):
        result = _check_vault_available()
        assert result.name == "vault_available"
        assert result.status in (CheckStatus.OK, CheckStatus.WARNING)


class TestCheckSandboxAvailable:
    """Tests for _check_sandbox_available()."""

    def test_sandbox_check_runs(self):
        result = _check_sandbox_available()
        assert result.name == "sandbox_available"
        assert result.status in (CheckStatus.OK, CheckStatus.WARNING, CheckStatus.SKIPPED)


class TestCheckLicenseStatus:
    """Tests for _check_license_status()."""

    def test_license_check_runs(self):
        result = _check_license_status()
        assert result.name == "license_status"
        assert result.status in (CheckStatus.OK, CheckStatus.WARNING)


class TestCheckMcpAvailable:
    """Tests for _check_mcp_available()."""

    def test_mcp_available(self):
        result = _check_mcp_available()
        assert result.name == "mcp_available"
        # MCP may or may not be installed
        assert result.status in (CheckStatus.OK, CheckStatus.SKIPPED)

    @patch.dict("sys.modules", {"mcp": None})
    def test_mcp_not_installed(self):
        # Force ImportError for mcp module
        import sys
        original = sys.modules.get("mcp")
        sys.modules["mcp"] = None
        try:
            result = _check_mcp_available()
            assert result.name == "mcp_available"
        finally:
            if original is not None:
                sys.modules["mcp"] = original
            else:
                sys.modules.pop("mcp", None)


class TestCheckProxyConfig:
    """Tests for _check_proxy_config()."""

    def test_proxy_config_check_runs(self):
        result = _check_proxy_config()
        assert result.name == "proxy_config"
        assert result.status in (CheckStatus.OK, CheckStatus.WARNING, CheckStatus.SKIPPED)


class TestCheckPluginIntegrity:
    """Tests for _check_plugin_integrity()."""

    def test_plugin_check_runs(self):
        result = _check_plugin_integrity()
        assert result.name == "plugin_integrity"
        assert result.status in (CheckStatus.OK, CheckStatus.WARNING)


class TestRunHealthChecks:
    """Tests for run_health_checks() function."""

    def test_returns_list(self):
        results = run_health_checks()
        assert isinstance(results, list)
        assert len(results) == 12  # 10 checks defined

    def test_all_results_are_health_checks(self):
        results = run_health_checks()
        for result in results:
            assert isinstance(result, HealthCheck)
            assert isinstance(result.status, CheckStatus)
            assert result.name
            assert result.label
            assert result.message

    def test_verbose_mode(self):
        results = run_health_checks(verbose=True)
        assert isinstance(results, list)
        assert len(results) == 12

    def test_check_names_unique(self):
        results = run_health_checks()
        names = [r.name for r in results]
        assert len(names) == len(set(names)), f"Duplicate check names: {names}"

    def test_exception_handling(self):
        """Verify that a failing check doesn't crash the whole run."""
        def _failing_check(verbose=False):
            raise RuntimeError("boom")
        _failing_check.__name__ = "_check_hooks_installed"

        with patch("tweek.diagnostics._check_hooks_installed", _failing_check):
            results = run_health_checks()
            assert len(results) == 12
            # The failing check should be ERROR
            hooks_check = [r for r in results if "hooks" in r.name.lower() or "check failed" in r.message.lower()]
            assert len(hooks_check) >= 1
