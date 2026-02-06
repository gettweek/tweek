#!/usr/bin/env python3
"""
Tests for tweek.cli_helpers module.

Tests shared CLI formatting utilities:
- Status message functions
- Health banner
- Command example formatting
- Spinner context manager
- Doctor output formatting
"""

import json
from io import StringIO
from unittest.mock import patch

import pytest
from rich.console import Console

pytestmark = pytest.mark.cli

from tweek.cli_helpers import (
    print_success,
    print_warning,
    print_error,
    print_health_banner,
    format_command_example,
    build_examples_epilog,
    spinner,
    format_tier_color,
    print_doctor_results,
    print_doctor_json,
    _tweek_install_info,
    _has_tweek_hooks,
)
from tweek.diagnostics import CheckStatus, HealthCheck


def _make_test_console():
    """Create a Console that writes to a StringIO buffer for capture."""
    buf = StringIO()
    return Console(file=buf, force_terminal=False, width=120), buf


class TestPrintFunctions:
    """Tests for print_success, print_warning, print_error."""

    def test_print_success(self):
        con, buf = _make_test_console()
        with patch("tweek.cli_helpers.console", con):
            print_success("Test passed")
        text = buf.getvalue()
        assert "Test passed" in text

    def test_print_warning(self):
        con, buf = _make_test_console()
        with patch("tweek.cli_helpers.console", con):
            print_warning("Be careful")
        text = buf.getvalue()
        assert "Be careful" in text

    def test_print_error_without_hint(self):
        con, buf = _make_test_console()
        with patch("tweek.cli_helpers.console", con):
            print_error("Something broke")
        text = buf.getvalue()
        assert "Something broke" in text

    def test_print_error_with_hint(self):
        con, buf = _make_test_console()
        with patch("tweek.cli_helpers.console", con):
            print_error("Something broke", fix_hint="Try restarting")
        text = buf.getvalue()
        assert "Something broke" in text
        assert "Try restarting" in text


class TestFormatCommandExample:
    """Tests for format_command_example()."""

    def test_basic_example(self):
        result = format_command_example("tweek protect claude-code", "Protect Claude Code globally")
        assert "tweek protect claude-code" in result
        assert "Protect Claude Code globally" in result

    def test_long_command(self):
        result = format_command_example(
            "tweek protect claude-code --scope project --force",
            "Force protect for project"
        )
        assert "tweek protect claude-code --scope project --force" in result
        assert "Force protect for project" in result


class TestBuildExamplesEpilog:
    """Tests for build_examples_epilog()."""

    def test_builds_epilog(self):
        examples = [
            ("tweek protect claude-code", "Protect Claude Code globally"),
            ("tweek protect claude-code --scope project", "Protect for project"),
        ]
        result = build_examples_epilog(examples)
        assert "Examples:" in result
        assert "tweek protect claude-code" in result
        assert "tweek protect claude-code --scope project" in result
        assert result.endswith("\n")

    def test_empty_examples(self):
        result = build_examples_epilog([])
        assert "Examples:" in result


class TestSpinner:
    """Tests for spinner context manager."""

    def test_spinner_enters_and_exits(self):
        # Spinner should work as context manager without error
        with spinner("Testing"):
            pass  # Should not raise

    def test_spinner_with_work(self):
        result = 0
        with spinner("Computing"):
            result = 1 + 1
        assert result == 2


class TestFormatTierColor:
    """Tests for format_tier_color()."""

    def test_safe(self):
        result = format_tier_color("safe")
        assert "green" in result
        assert "safe" in result

    def test_default(self):
        result = format_tier_color("default")
        assert "white" in result

    def test_risky(self):
        result = format_tier_color("risky")
        assert "yellow" in result

    def test_dangerous(self):
        result = format_tier_color("dangerous")
        assert "red" in result

    def test_unknown(self):
        result = format_tier_color("unknown_tier")
        assert "white" in result
        assert "unknown_tier" in result


class TestPrintDoctorResults:
    """Tests for print_doctor_results()."""

    def test_prints_results(self):
        checks = [
            HealthCheck("test1", "Test One", CheckStatus.OK, "All good"),
            HealthCheck("test2", "Test Two", CheckStatus.WARNING, "Hmm",
                       fix_hint="Fix it"),
            HealthCheck("test3", "Test Three", CheckStatus.ERROR, "Bad",
                       fix_hint="Run repair"),
        ]
        con, buf = _make_test_console()
        with patch("tweek.cli_helpers.console", con):
            print_doctor_results(checks)
        text = buf.getvalue()
        assert "Test One" in text
        assert "Test Two" in text
        assert "Test Three" in text
        assert "Verdict" in text


class TestPrintDoctorJson:
    """Tests for print_doctor_json()."""

    def test_prints_json(self):
        checks = [
            HealthCheck("test1", "Test One", CheckStatus.OK, "All good"),
            HealthCheck("test2", "Test Two", CheckStatus.ERROR, "Bad",
                       fix_hint="Fix it"),
        ]
        con, buf = _make_test_console()
        with patch("tweek.cli_helpers.console", con):
            print_doctor_json(checks)
        text = buf.getvalue()
        # Should contain valid JSON structure elements
        assert "verdict" in text
        assert "checks" in text
        assert "test1" in text
        assert "test2" in text


class TestTweekInstallInfo:
    """Tests for _tweek_install_info() — granular installation detection."""

    def test_empty_dir(self, tmp_path):
        target = tmp_path / ".claude"
        target.mkdir()
        info = _tweek_install_info(target)
        assert info["has_hooks"] is False
        assert info["has_skill"] is False
        assert info["has_backup"] is False
        assert info["is_protected"] is False
        assert info["has_artifacts"] is False

    def test_nonexistent_dir(self, tmp_path):
        target = tmp_path / ".claude"
        info = _tweek_install_info(target)
        assert info["has_hooks"] is False
        assert info["has_artifacts"] is False
        assert info["is_protected"] is False

    def test_hooks_in_settings(self, tmp_path):
        target = tmp_path / ".claude"
        target.mkdir()
        settings = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "", "hooks": [{"type": "command", "command": "tweek hook pre-tool-use"}]}
                ]
            }
        }
        (target / "settings.json").write_text(json.dumps(settings))
        info = _tweek_install_info(target)
        assert info["has_hooks"] is True
        assert info["is_protected"] is True

    def test_skill_dir_only(self, tmp_path):
        target = tmp_path / ".claude"
        (target / "skills" / "tweek").mkdir(parents=True)
        info = _tweek_install_info(target)
        assert info["has_hooks"] is False
        assert info["has_skill"] is True
        assert info["has_artifacts"] is True
        assert info["is_protected"] is False

    def test_backup_only(self, tmp_path):
        target = tmp_path / ".claude"
        target.mkdir()
        (target / "settings.json.tweek-backup").write_text("{}")
        info = _tweek_install_info(target)
        assert info["has_hooks"] is False
        assert info["has_backup"] is True
        assert info["has_artifacts"] is True
        assert info["is_protected"] is False

    def test_artifacts_plus_hooks(self, tmp_path):
        """Full installation: hooks + skill + backup."""
        target = tmp_path / ".claude"
        (target / "skills" / "tweek").mkdir(parents=True)
        (target / "settings.json.tweek-backup").write_text("{}")
        settings = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "", "hooks": [{"type": "command", "command": "tweek hook pre-tool-use"}]}
                ]
            }
        }
        (target / "settings.json").write_text(json.dumps(settings))
        info = _tweek_install_info(target)
        assert info["has_hooks"] is True
        assert info["has_skill"] is True
        assert info["has_backup"] is True
        assert info["is_protected"] is True
        assert info["has_artifacts"] is True

    def test_corrupt_settings_json(self, tmp_path):
        target = tmp_path / ".claude"
        target.mkdir()
        (target / "settings.json").write_text("NOT VALID JSON!!!")
        (target / "settings.json.tweek-backup").write_text("{}")
        info = _tweek_install_info(target)
        assert info["has_hooks"] is False
        assert info["has_backup"] is True
        assert info["has_artifacts"] is True
        assert info["is_protected"] is False


class TestHasTweekHooks:
    """Tests for _has_tweek_hooks() — dict-level hook detection."""

    def test_empty_settings(self):
        assert _has_tweek_hooks({}) is False

    def test_hooks_present(self):
        settings = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "", "hooks": [{"type": "command", "command": "tweek hook pre-tool-use"}]}
                ]
            }
        }
        assert _has_tweek_hooks(settings) is True

    def test_non_tweek_hooks(self):
        settings = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "", "hooks": [{"type": "command", "command": "other-tool check"}]}
                ]
            }
        }
        assert _has_tweek_hooks(settings) is False


class TestPrintHealthBanner:
    """Tests for print_health_banner()."""

    def test_prints_banner(self):
        checks = [
            HealthCheck("a", "A", CheckStatus.OK, "ok"),
            HealthCheck("b", "B", CheckStatus.OK, "ok"),
        ]
        con, buf = _make_test_console()
        with patch("tweek.cli_helpers.console", con):
            print_health_banner(checks)
        text = buf.getvalue()
        assert "doctor" in text.lower()
