#!/usr/bin/env python3
"""
Tests for Tweek protect command group.

Tests coverage of:
- tweek protect openclaw (detection, setup, error handling)
- tweek protect claude-code (delegation to install)
- OpenClawSetupResult dataclass
- detect_openclaw_installation function
- setup_openclaw_protection function
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

pytestmark = pytest.mark.cli

from tweek.cli import main
from tweek.integrations.openclaw import (
    detect_openclaw_installation,
    setup_openclaw_protection,
    OpenClawSetupResult,
)


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def temp_home(tmp_path):
    """Create temporary home directory structure."""
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    tweek_dir = tmp_path / ".tweek"
    tweek_dir.mkdir()
    return tmp_path


@pytest.fixture
def mock_openclaw_detected():
    """Mock a detected OpenClaw installation."""
    return {
        "installed": True,
        "version": "1.2.3",
        "config_path": Path.home() / ".openclaw" / "config.json",
        "gateway_port": 18789,
        "process_running": True,
        "gateway_active": True,
    }


@pytest.fixture
def mock_openclaw_not_detected():
    """Mock no OpenClaw installation."""
    return {
        "installed": False,
        "version": None,
        "config_path": None,
        "gateway_port": 18789,
        "process_running": False,
        "gateway_active": False,
    }


class TestProtectGroup:
    """Tests for the protect command group."""

    def test_protect_help(self, runner):
        """Test protect group shows help."""
        result = runner.invoke(main, ["protect", "--help"])
        assert result.exit_code == 0
        assert "openclaw" in result.output
        assert "claude-code" in result.output

    def test_protect_no_subcommand(self, runner):
        """Test protect without subcommand shows help."""
        result = runner.invoke(main, ["protect"])
        assert result.exit_code == 0
        assert "openclaw" in result.output


class TestProtectOpenClaw:
    """Tests for tweek protect openclaw."""

    def test_protect_openclaw_detected(self, runner, mock_openclaw_detected, tmp_path):
        """Test protect openclaw when OpenClaw is found and gateway running."""
        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation",
            return_value=mock_openclaw_detected,
        ):
            with patch(
                "tweek.integrations.openclaw.setup_openclaw_protection",
                return_value=OpenClawSetupResult(
                    success=True,
                    openclaw_detected=True,
                    openclaw_version="1.2.3",
                    gateway_port=18789,
                    gateway_running=True,
                    scanner_port=9877,
                    preset="cautious",
                    config_path=str(tmp_path / ".tweek" / "config.yaml"),
                ),
            ):
                result = runner.invoke(main, ["protect", "openclaw"])

        assert result.exit_code == 0
        assert "OpenClaw detected" in result.output
        assert "Protection configured" in result.output

    def test_protect_openclaw_not_found(self, runner, mock_openclaw_not_detected):
        """Test protect openclaw when OpenClaw is not installed."""
        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation",
            return_value=mock_openclaw_not_detected,
        ):
            result = runner.invoke(main, ["protect", "openclaw"])

        assert result.exit_code == 0
        assert "not detected" in result.output
        assert "npm install -g openclaw" in result.output

    def test_protect_openclaw_gateway_not_running(self, runner, tmp_path):
        """Test protect openclaw when gateway is not active."""
        openclaw_info = {
            "installed": True,
            "version": "1.0.0",
            "config_path": None,
            "gateway_port": 18789,
            "process_running": False,
            "gateway_active": False,
        }

        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation",
            return_value=openclaw_info,
        ):
            with patch(
                "tweek.integrations.openclaw.setup_openclaw_protection",
                return_value=OpenClawSetupResult(
                    success=True,
                    openclaw_detected=True,
                    openclaw_version="1.0.0",
                    gateway_port=18789,
                    gateway_running=False,
                    scanner_port=9877,
                    preset="cautious",
                    config_path=str(tmp_path / ".tweek" / "config.yaml"),
                ),
            ):
                result = runner.invoke(main, ["protect", "openclaw"])

        assert result.exit_code == 0
        assert "not currently running" in result.output
        assert "Protection will activate" in result.output

    def test_protect_openclaw_custom_port(self, runner, mock_openclaw_detected, tmp_path):
        """Test protect openclaw with --port override."""
        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation",
            return_value=mock_openclaw_detected,
        ):
            with patch(
                "tweek.integrations.openclaw.setup_openclaw_protection",
                return_value=OpenClawSetupResult(
                    success=True,
                    openclaw_detected=True,
                    gateway_port=9999,
                    gateway_running=True,
                    scanner_port=9877,
                    preset="cautious",
                    config_path=str(tmp_path / ".tweek" / "config.yaml"),
                ),
            ) as mock_setup:
                result = runner.invoke(main, ["protect", "openclaw", "--port", "9999"])
                mock_setup.assert_called_once_with(port=9999, preset="cautious")

        assert result.exit_code == 0

    def test_protect_openclaw_paranoid(self, runner, mock_openclaw_detected, tmp_path):
        """Test protect openclaw with --paranoid flag."""
        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation",
            return_value=mock_openclaw_detected,
        ):
            with patch(
                "tweek.integrations.openclaw.setup_openclaw_protection",
                return_value=OpenClawSetupResult(
                    success=True,
                    openclaw_detected=True,
                    gateway_port=18789,
                    gateway_running=True,
                    scanner_port=9877,
                    preset="paranoid",
                    config_path=str(tmp_path / ".tweek" / "config.yaml"),
                ),
            ) as mock_setup:
                result = runner.invoke(main, ["protect", "openclaw", "--paranoid"])
                mock_setup.assert_called_once_with(port=None, preset="paranoid")

        assert result.exit_code == 0

    def test_protect_openclaw_preset_option(self, runner, mock_openclaw_detected, tmp_path):
        """Test protect openclaw with --preset option."""
        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation",
            return_value=mock_openclaw_detected,
        ):
            with patch(
                "tweek.integrations.openclaw.setup_openclaw_protection",
                return_value=OpenClawSetupResult(
                    success=True,
                    openclaw_detected=True,
                    gateway_port=18789,
                    gateway_running=True,
                    scanner_port=9877,
                    preset="trusted",
                    config_path=str(tmp_path / ".tweek" / "config.yaml"),
                ),
            ) as mock_setup:
                result = runner.invoke(
                    main, ["protect", "openclaw", "--preset", "trusted"]
                )
                mock_setup.assert_called_once_with(port=None, preset="trusted")

        assert result.exit_code == 0

    def test_protect_openclaw_setup_failure(self, runner, mock_openclaw_detected):
        """Test protect openclaw when setup fails."""
        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation",
            return_value=mock_openclaw_detected,
        ):
            with patch(
                "tweek.integrations.openclaw.setup_openclaw_protection",
                return_value=OpenClawSetupResult(
                    success=False,
                    openclaw_detected=True,
                    error="Failed to write config: Permission denied",
                ),
            ):
                result = runner.invoke(main, ["protect", "openclaw"])

        assert result.exit_code == 0
        assert "Setup failed" in result.output

    def test_protect_openclaw_shows_version(self, runner, tmp_path):
        """Test that OpenClaw version is displayed when available."""
        openclaw_info = {
            "installed": True,
            "version": "2.5.1",
            "config_path": None,
            "gateway_port": 18789,
            "process_running": False,
            "gateway_active": False,
        }

        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation",
            return_value=openclaw_info,
        ):
            with patch(
                "tweek.integrations.openclaw.setup_openclaw_protection",
                return_value=OpenClawSetupResult(
                    success=True,
                    openclaw_detected=True,
                    openclaw_version="2.5.1",
                    gateway_port=18789,
                    gateway_running=False,
                    scanner_port=9877,
                    preset="cautious",
                    config_path=str(tmp_path / ".tweek" / "config.yaml"),
                ),
            ):
                result = runner.invoke(main, ["protect", "openclaw"])

        assert "2.5.1" in result.output

    def test_protect_openclaw_help(self, runner):
        """Test protect openclaw --help."""
        result = runner.invoke(main, ["protect", "openclaw", "--help"])
        assert result.exit_code == 0
        assert "--port" in result.output
        assert "--paranoid" in result.output
        assert "--preset" in result.output
        assert "Auto-detect" in result.output


class TestProtectClaudeCode:
    """Tests for tweek protect claude-code."""

    def test_protect_claude_code_invokes_install(self, runner, tmp_path):
        """Test that protect claude-code delegates to install command."""
        with patch.object(Path, "home", return_value=tmp_path):
            with patch("tweek.cli.Path.home", return_value=tmp_path):
                with patch("tweek.cli.scan_for_env_files", return_value=[]):
                    result = runner.invoke(main, ["protect", "claude-code"])

        # Should show the Tweek banner (from install command)
        assert "TWEEK" in result.output or result.exit_code == 0

    def test_protect_claude_code_help(self, runner):
        """Test protect claude-code --help."""
        result = runner.invoke(main, ["protect", "claude-code", "--help"])
        assert result.exit_code == 0
        assert "--global" in result.output
        assert "--preset" in result.output


class TestDetectOpenClawInstallation:
    """Tests for the detect_openclaw_installation function."""

    def test_detect_not_installed(self):
        """Test detection when OpenClaw is not installed."""
        with patch("subprocess.run") as mock_run:
            # npm list returns error
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")

            with patch.object(Path, "exists", return_value=False):
                result = detect_openclaw_installation()

        assert result["installed"] is False
        assert result["version"] is None

    def test_detect_npm_installed(self):
        """Test detection via npm global list."""
        npm_output = json.dumps({
            "dependencies": {
                "openclaw": {"version": "1.5.0"}
            }
        })

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=npm_output, stderr=""
            )

            with patch.object(Path, "exists", return_value=False):
                result = detect_openclaw_installation()

        assert result["installed"] is True
        assert result["version"] == "1.5.0"

    def test_detect_config_exists(self, tmp_path):
        """Test detection via config file."""
        config_dir = tmp_path / ".openclaw"
        config_dir.mkdir()
        config_file = config_dir / "openclaw.json"
        config_file.write_text(json.dumps({
            "gateway": {"port": 19000}
        }))

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")

            with patch("tweek.integrations.openclaw.OPENCLAW_HOME", config_dir.parent / ".openclaw"), \
                 patch("tweek.integrations.openclaw.OPENCLAW_CONFIG", config_file), \
                 patch("tweek.integrations.openclaw.OPENCLAW_SKILLS_DIR", config_dir / "workspace" / "skills"):
                result = detect_openclaw_installation()

        assert result["installed"] is True
        assert result["gateway_port"] == 19000

    def test_detect_default_port(self):
        """Test that default gateway port is 18789."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")

            with patch.object(Path, "exists", return_value=False):
                result = detect_openclaw_installation()

        assert result["gateway_port"] == 18789


class TestSetupOpenClawProtection:
    """Tests for the setup_openclaw_protection function."""

    def test_setup_not_detected(self):
        """Test setup when OpenClaw is not installed."""
        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation",
            return_value={
                "installed": False,
                "version": None,
                "config_path": None,
                "gateway_port": 18789,
                "process_running": False,
                "gateway_active": False,
            },
        ):
            result = setup_openclaw_protection()

        assert result.success is False
        assert result.openclaw_detected is False
        assert "not detected" in result.error

    def test_setup_success(self, tmp_path):
        """Test successful setup writes config."""
        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation",
            return_value={
                "installed": True,
                "version": "1.0.0",
                "config_path": None,
                "gateway_port": 18789,
                "process_running": True,
                "gateway_active": True,
            },
        ):
            with patch.object(Path, "home", return_value=tmp_path):
                with patch(
                    "tweek.config.manager.ConfigManager"
                ) as mock_cfg_cls:
                    mock_cfg = MagicMock()
                    mock_cfg_cls.return_value = mock_cfg

                    result = setup_openclaw_protection()

        assert result.success is True
        assert result.openclaw_detected is True
        assert result.gateway_port == 18789
        assert result.preset == "cautious"
        assert result.config_path is not None

    def test_setup_custom_port(self, tmp_path):
        """Test setup with custom port override."""
        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation",
            return_value={
                "installed": True,
                "version": "1.0.0",
                "config_path": None,
                "gateway_port": 18789,
                "process_running": False,
                "gateway_active": False,
            },
        ):
            with patch.object(Path, "home", return_value=tmp_path):
                with patch(
                    "tweek.config.manager.ConfigManager"
                ) as mock_cfg_cls:
                    mock_cfg = MagicMock()
                    mock_cfg_cls.return_value = mock_cfg

                    result = setup_openclaw_protection(port=9999)

        assert result.success is True
        assert result.gateway_port == 9999

    def test_setup_paranoid_preset(self, tmp_path):
        """Test setup with paranoid preset."""
        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation",
            return_value={
                "installed": True,
                "version": "1.0.0",
                "config_path": None,
                "gateway_port": 18789,
                "process_running": False,
                "gateway_active": False,
            },
        ):
            with patch.object(Path, "home", return_value=tmp_path):
                with patch(
                    "tweek.config.manager.ConfigManager"
                ) as mock_cfg_cls:
                    mock_cfg = MagicMock()
                    mock_cfg_cls.return_value = mock_cfg

                    result = setup_openclaw_protection(preset="paranoid")

        assert result.success is True
        assert result.preset == "paranoid"
        mock_cfg.apply_preset.assert_called_once_with("paranoid")


class TestOpenClawSetupResult:
    """Tests for the OpenClawSetupResult dataclass."""

    def test_default_values(self):
        """Test default values of OpenClawSetupResult."""
        result = OpenClawSetupResult()
        assert result.success is False
        assert result.openclaw_detected is False
        assert result.openclaw_version is None
        assert result.gateway_port is None
        assert result.gateway_running is False
        assert result.preset == "cautious"
        assert result.config_path is None
        assert result.plugin_installed is False
        assert result.error is None
        assert result.warnings == []

    def test_custom_values(self):
        """Test OpenClawSetupResult with custom values."""
        result = OpenClawSetupResult(
            success=True,
            openclaw_detected=True,
            openclaw_version="2.0.0",
            gateway_port=18789,
            gateway_running=True,
            scanner_port=9877,
            preset="paranoid",
            config_path="/home/user/.tweek/config.yaml",
            warnings=["Port conflict detected"],
        )
        assert result.success is True
        assert result.openclaw_version == "2.0.0"
        assert result.gateway_port == 18789
        assert result.preset == "paranoid"
        assert len(result.warnings) == 1
