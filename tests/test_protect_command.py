#!/usr/bin/env python3
"""
Tests for Tweek protect command group.

Tests coverage of:
- tweek protect moltbot (detection, setup, error handling)
- tweek protect claude (delegation to install)
- MoltbotSetupResult dataclass
- detect_moltbot_installation function
- setup_moltbot_protection function
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from tweek.cli import main
from tweek.integrations.moltbot import (
    detect_moltbot_installation,
    setup_moltbot_protection,
    MoltbotSetupResult,
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
def mock_moltbot_detected():
    """Mock a detected Moltbot installation."""
    return {
        "installed": True,
        "version": "1.2.3",
        "config_path": Path.home() / ".moltbot" / "config.json",
        "gateway_port": 18789,
        "process_running": True,
        "gateway_active": True,
    }


@pytest.fixture
def mock_moltbot_not_detected():
    """Mock no Moltbot installation."""
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
        assert "moltbot" in result.output
        assert "claude" in result.output

    def test_protect_no_subcommand(self, runner):
        """Test protect without subcommand shows help."""
        result = runner.invoke(main, ["protect"])
        assert result.exit_code == 0
        assert "moltbot" in result.output


class TestProtectMoltbot:
    """Tests for tweek protect moltbot."""

    def test_protect_moltbot_detected(self, runner, mock_moltbot_detected, tmp_path):
        """Test protect moltbot when Moltbot is found and gateway running."""
        with patch(
            "tweek.integrations.moltbot.detect_moltbot_installation",
            return_value=mock_moltbot_detected,
        ):
            with patch(
                "tweek.integrations.moltbot.setup_moltbot_protection",
                return_value=MoltbotSetupResult(
                    success=True,
                    moltbot_detected=True,
                    moltbot_version="1.2.3",
                    gateway_port=18789,
                    gateway_running=True,
                    proxy_port=9877,
                    preset="cautious",
                    config_path=str(tmp_path / ".tweek" / "config.yaml"),
                ),
            ):
                result = runner.invoke(main, ["protect", "moltbot"])

        assert result.exit_code == 0
        assert "Moltbot detected" in result.output
        assert "Protection configured" in result.output

    def test_protect_moltbot_not_found(self, runner, mock_moltbot_not_detected):
        """Test protect moltbot when Moltbot is not installed."""
        with patch(
            "tweek.integrations.moltbot.detect_moltbot_installation",
            return_value=mock_moltbot_not_detected,
        ):
            result = runner.invoke(main, ["protect", "moltbot"])

        assert result.exit_code == 0
        assert "not detected" in result.output
        assert "npm install -g moltbot" in result.output

    def test_protect_moltbot_gateway_not_running(self, runner, tmp_path):
        """Test protect moltbot when gateway is not active."""
        moltbot_info = {
            "installed": True,
            "version": "1.0.0",
            "config_path": None,
            "gateway_port": 18789,
            "process_running": False,
            "gateway_active": False,
        }

        with patch(
            "tweek.integrations.moltbot.detect_moltbot_installation",
            return_value=moltbot_info,
        ):
            with patch(
                "tweek.integrations.moltbot.setup_moltbot_protection",
                return_value=MoltbotSetupResult(
                    success=True,
                    moltbot_detected=True,
                    moltbot_version="1.0.0",
                    gateway_port=18789,
                    gateway_running=False,
                    proxy_port=9877,
                    preset="cautious",
                    config_path=str(tmp_path / ".tweek" / "config.yaml"),
                ),
            ):
                result = runner.invoke(main, ["protect", "moltbot"])

        assert result.exit_code == 0
        assert "not currently running" in result.output
        assert "Protection will activate" in result.output

    def test_protect_moltbot_custom_port(self, runner, mock_moltbot_detected, tmp_path):
        """Test protect moltbot with --port override."""
        with patch(
            "tweek.integrations.moltbot.detect_moltbot_installation",
            return_value=mock_moltbot_detected,
        ):
            with patch(
                "tweek.integrations.moltbot.setup_moltbot_protection",
                return_value=MoltbotSetupResult(
                    success=True,
                    moltbot_detected=True,
                    gateway_port=9999,
                    gateway_running=True,
                    proxy_port=9877,
                    preset="cautious",
                    config_path=str(tmp_path / ".tweek" / "config.yaml"),
                ),
            ) as mock_setup:
                result = runner.invoke(main, ["protect", "moltbot", "--port", "9999"])
                mock_setup.assert_called_once_with(port=9999, preset="cautious")

        assert result.exit_code == 0

    def test_protect_moltbot_paranoid(self, runner, mock_moltbot_detected, tmp_path):
        """Test protect moltbot with --paranoid flag."""
        with patch(
            "tweek.integrations.moltbot.detect_moltbot_installation",
            return_value=mock_moltbot_detected,
        ):
            with patch(
                "tweek.integrations.moltbot.setup_moltbot_protection",
                return_value=MoltbotSetupResult(
                    success=True,
                    moltbot_detected=True,
                    gateway_port=18789,
                    gateway_running=True,
                    proxy_port=9877,
                    preset="paranoid",
                    config_path=str(tmp_path / ".tweek" / "config.yaml"),
                ),
            ) as mock_setup:
                result = runner.invoke(main, ["protect", "moltbot", "--paranoid"])
                mock_setup.assert_called_once_with(port=None, preset="paranoid")

        assert result.exit_code == 0

    def test_protect_moltbot_preset_option(self, runner, mock_moltbot_detected, tmp_path):
        """Test protect moltbot with --preset option."""
        with patch(
            "tweek.integrations.moltbot.detect_moltbot_installation",
            return_value=mock_moltbot_detected,
        ):
            with patch(
                "tweek.integrations.moltbot.setup_moltbot_protection",
                return_value=MoltbotSetupResult(
                    success=True,
                    moltbot_detected=True,
                    gateway_port=18789,
                    gateway_running=True,
                    proxy_port=9877,
                    preset="trusted",
                    config_path=str(tmp_path / ".tweek" / "config.yaml"),
                ),
            ) as mock_setup:
                result = runner.invoke(
                    main, ["protect", "moltbot", "--preset", "trusted"]
                )
                mock_setup.assert_called_once_with(port=None, preset="trusted")

        assert result.exit_code == 0

    def test_protect_moltbot_setup_failure(self, runner, mock_moltbot_detected):
        """Test protect moltbot when setup fails."""
        with patch(
            "tweek.integrations.moltbot.detect_moltbot_installation",
            return_value=mock_moltbot_detected,
        ):
            with patch(
                "tweek.integrations.moltbot.setup_moltbot_protection",
                return_value=MoltbotSetupResult(
                    success=False,
                    moltbot_detected=True,
                    error="Failed to write config: Permission denied",
                ),
            ):
                result = runner.invoke(main, ["protect", "moltbot"])

        assert result.exit_code == 0
        assert "Setup failed" in result.output

    def test_protect_moltbot_shows_version(self, runner, tmp_path):
        """Test that Moltbot version is displayed when available."""
        moltbot_info = {
            "installed": True,
            "version": "2.5.1",
            "config_path": None,
            "gateway_port": 18789,
            "process_running": False,
            "gateway_active": False,
        }

        with patch(
            "tweek.integrations.moltbot.detect_moltbot_installation",
            return_value=moltbot_info,
        ):
            with patch(
                "tweek.integrations.moltbot.setup_moltbot_protection",
                return_value=MoltbotSetupResult(
                    success=True,
                    moltbot_detected=True,
                    moltbot_version="2.5.1",
                    gateway_port=18789,
                    gateway_running=False,
                    proxy_port=9877,
                    preset="cautious",
                    config_path=str(tmp_path / ".tweek" / "config.yaml"),
                ),
            ):
                result = runner.invoke(main, ["protect", "moltbot"])

        assert "2.5.1" in result.output

    def test_protect_moltbot_help(self, runner):
        """Test protect moltbot --help."""
        result = runner.invoke(main, ["protect", "moltbot", "--help"])
        assert result.exit_code == 0
        assert "--port" in result.output
        assert "--paranoid" in result.output
        assert "--preset" in result.output
        assert "Auto-detect" in result.output


class TestProtectClaude:
    """Tests for tweek protect claude."""

    def test_protect_claude_invokes_install(self, runner, tmp_path):
        """Test that protect claude delegates to install command."""
        with patch.object(Path, "home", return_value=tmp_path):
            with patch("tweek.cli.Path.home", return_value=tmp_path):
                with patch("tweek.cli.scan_for_env_files", return_value=[]):
                    result = runner.invoke(main, ["protect", "claude"])

        # Should show the Tweek banner (from install command)
        assert "TWEEK" in result.output or result.exit_code == 0

    def test_protect_claude_help(self, runner):
        """Test protect claude --help."""
        result = runner.invoke(main, ["protect", "claude", "--help"])
        assert result.exit_code == 0
        assert "--scope" in result.output
        assert "--preset" in result.output


class TestDetectMoltbotInstallation:
    """Tests for the detect_moltbot_installation function."""

    def test_detect_not_installed(self):
        """Test detection when Moltbot is not installed."""
        with patch("subprocess.run") as mock_run:
            # npm list returns error
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")

            with patch.object(Path, "exists", return_value=False):
                result = detect_moltbot_installation()

        assert result["installed"] is False
        assert result["version"] is None

    def test_detect_npm_installed(self):
        """Test detection via npm global list."""
        npm_output = json.dumps({
            "dependencies": {
                "moltbot": {"version": "1.5.0"}
            }
        })

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=npm_output, stderr=""
            )

            with patch.object(Path, "exists", return_value=False):
                result = detect_moltbot_installation()

        assert result["installed"] is True
        assert result["version"] == "1.5.0"

    def test_detect_config_exists(self, tmp_path):
        """Test detection via config file."""
        config_dir = tmp_path / ".moltbot"
        config_dir.mkdir()
        config_file = config_dir / "config.json"
        config_file.write_text(json.dumps({
            "gateway": {"port": 19000}
        }))

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")

            with patch.object(Path, "home", return_value=tmp_path):
                result = detect_moltbot_installation()

        assert result["installed"] is True
        assert result["gateway_port"] == 19000

    def test_detect_default_port(self):
        """Test that default gateway port is 18789."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")

            with patch.object(Path, "exists", return_value=False):
                result = detect_moltbot_installation()

        assert result["gateway_port"] == 18789


class TestSetupMoltbotProtection:
    """Tests for the setup_moltbot_protection function."""

    def test_setup_not_detected(self):
        """Test setup when Moltbot is not installed."""
        with patch(
            "tweek.integrations.moltbot.detect_moltbot_installation",
            return_value={
                "installed": False,
                "version": None,
                "config_path": None,
                "gateway_port": 18789,
                "process_running": False,
                "gateway_active": False,
            },
        ):
            result = setup_moltbot_protection()

        assert result.success is False
        assert result.moltbot_detected is False
        assert "not detected" in result.error

    def test_setup_success(self, tmp_path):
        """Test successful setup writes config."""
        with patch(
            "tweek.integrations.moltbot.detect_moltbot_installation",
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

                    result = setup_moltbot_protection()

        assert result.success is True
        assert result.moltbot_detected is True
        assert result.gateway_port == 18789
        assert result.preset == "cautious"
        assert result.config_path is not None

    def test_setup_custom_port(self, tmp_path):
        """Test setup with custom port override."""
        with patch(
            "tweek.integrations.moltbot.detect_moltbot_installation",
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

                    result = setup_moltbot_protection(port=9999)

        assert result.success is True
        assert result.gateway_port == 9999

    def test_setup_paranoid_preset(self, tmp_path):
        """Test setup with paranoid preset."""
        with patch(
            "tweek.integrations.moltbot.detect_moltbot_installation",
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

                    result = setup_moltbot_protection(preset="paranoid")

        assert result.success is True
        assert result.preset == "paranoid"
        mock_cfg.apply_preset.assert_called_once_with("paranoid")


class TestMoltbotSetupResult:
    """Tests for the MoltbotSetupResult dataclass."""

    def test_default_values(self):
        """Test default values of MoltbotSetupResult."""
        result = MoltbotSetupResult()
        assert result.success is False
        assert result.moltbot_detected is False
        assert result.moltbot_version is None
        assert result.gateway_port is None
        assert result.gateway_running is False
        assert result.proxy_port is None
        assert result.preset == "cautious"
        assert result.config_path is None
        assert result.error is None
        assert result.warnings == []

    def test_custom_values(self):
        """Test MoltbotSetupResult with custom values."""
        result = MoltbotSetupResult(
            success=True,
            moltbot_detected=True,
            moltbot_version="2.0.0",
            gateway_port=18789,
            gateway_running=True,
            proxy_port=9877,
            preset="paranoid",
            config_path="/home/user/.tweek/config.yaml",
            warnings=["Port conflict detected"],
        )
        assert result.success is True
        assert result.moltbot_version == "2.0.0"
        assert result.gateway_port == 18789
        assert result.preset == "paranoid"
        assert len(result.warnings) == 1
