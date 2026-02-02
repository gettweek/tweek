"""Tests for tweek.integrations.openclaw — OpenClaw detection and setup."""

import json
import socket
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from tweek.integrations.openclaw import (
    detect_openclaw_installation,
    setup_openclaw_protection,
    OpenClawSetupResult,
    OPENCLAW_DEFAULT_PORT,
    OPENCLAW_HOME,
    OPENCLAW_CONFIG,
    OPENCLAW_SKILLS_DIR,
    SCANNER_SERVER_PORT,
    _check_plugin_installed,
    _write_openclaw_config,
)


class TestDetectOpenClawInstallation:
    """Tests for detect_openclaw_installation()."""

    def test_returns_dict_with_expected_keys(self):
        """Detection result has all required keys."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
            result = detect_openclaw_installation()

        assert set(result.keys()) == {
            "installed", "version", "config_path", "gateway_port",
            "process_running", "gateway_active", "skills_dir",
        }

    def test_not_installed_when_nothing_found(self):
        """Returns installed=False when OpenClaw is not present."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
            with patch.object(Path, "exists", return_value=False):
                result = detect_openclaw_installation()

        assert result["installed"] is False
        assert result["version"] is None

    def test_detected_via_npm(self):
        """Detects OpenClaw via npm global installation."""
        npm_output = json.dumps({
            "dependencies": {
                "openclaw": {"version": "2026.1.30"}
            }
        })

        def mock_subprocess_run(cmd, **kwargs):
            mock = MagicMock()
            if cmd[0] == "npm":
                mock.returncode = 0
                mock.stdout = npm_output
            else:
                mock.returncode = 1
                mock.stdout = ""
            return mock

        with patch("subprocess.run", side_effect=mock_subprocess_run):
            with patch.object(Path, "exists", return_value=False):
                result = detect_openclaw_installation()

        assert result["installed"] is True
        assert result["version"] == "2026.1.30"

    def test_detected_via_home_dir(self):
        """Detects OpenClaw via ~/.openclaw/ directory existence."""
        original_exists = Path.exists

        def mock_exists(self):
            if str(self).endswith(".openclaw"):
                return True
            return False

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
            with patch.object(Path, "exists", mock_exists):
                result = detect_openclaw_installation()

        assert result["installed"] is True

    def test_default_gateway_port(self):
        """Default gateway port is 18789."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
            with patch.object(Path, "exists", return_value=False):
                result = detect_openclaw_installation()

        assert result["gateway_port"] == OPENCLAW_DEFAULT_PORT
        assert result["gateway_port"] == 18789

    def test_gateway_port_from_config(self, tmp_path):
        """Reads gateway port from openclaw.json config."""
        config = tmp_path / ".openclaw" / "openclaw.json"
        config.parent.mkdir(parents=True)
        config.write_text(json.dumps({"gateway": {"port": 19000}}))

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="")
            with patch(
                "tweek.integrations.openclaw.OPENCLAW_CONFIG", config
            ), patch(
                "tweek.integrations.openclaw.OPENCLAW_HOME", config.parent
            ), patch(
                "tweek.integrations.openclaw.OPENCLAW_SKILLS_DIR",
                config.parent / "workspace" / "skills",
            ):
                result = detect_openclaw_installation()

        assert result["gateway_port"] == 19000

    def test_handles_subprocess_timeout(self):
        """Gracefully handles subprocess timeouts."""
        import subprocess

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("npm", 10)):
            with patch.object(Path, "exists", return_value=False):
                result = detect_openclaw_installation()

        assert result["installed"] is False


class TestSetupOpenClawProtection:
    """Tests for setup_openclaw_protection()."""

    def test_result_type(self):
        """Returns OpenClawSetupResult dataclass."""
        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation"
        ) as mock_detect:
            mock_detect.return_value = {
                "installed": False,
                "version": None,
                "gateway_port": 18789,
                "gateway_active": False,
            }
            result = setup_openclaw_protection()

        assert isinstance(result, OpenClawSetupResult)

    def test_fails_when_not_installed(self):
        """Returns error when OpenClaw is not detected."""
        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation"
        ) as mock_detect:
            mock_detect.return_value = {
                "installed": False,
                "version": None,
                "gateway_port": 18789,
                "gateway_active": False,
            }
            result = setup_openclaw_protection()

        assert result.success is False
        assert result.openclaw_detected is False
        assert "not detected" in result.error

    def test_uses_detected_port(self):
        """Uses auto-detected gateway port."""
        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation"
        ) as mock_detect, patch(
            "tweek.integrations.openclaw._check_plugin_installed",
            return_value=True,
        ), patch(
            "tweek.integrations.openclaw._write_openclaw_config",
            return_value=("/tmp/test.json", None),
        ), patch(
            "tweek.integrations.openclaw.ConfigManager",
            create=True,
        ):
            mock_detect.return_value = {
                "installed": True,
                "version": "2026.1.30",
                "gateway_port": 19999,
                "gateway_active": True,
            }
            result = setup_openclaw_protection()

        assert result.gateway_port == 19999

    def test_override_port(self):
        """Allows explicit port override."""
        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation"
        ) as mock_detect, patch(
            "tweek.integrations.openclaw._check_plugin_installed",
            return_value=True,
        ), patch(
            "tweek.integrations.openclaw._write_openclaw_config",
            return_value=("/tmp/test.json", None),
        ), patch(
            "tweek.integrations.openclaw.ConfigManager",
            create=True,
        ):
            mock_detect.return_value = {
                "installed": True,
                "version": "2026.1.30",
                "gateway_port": 18789,
                "gateway_active": False,
            }
            result = setup_openclaw_protection(port=12345)

        assert result.gateway_port == 12345

    def test_preset_stored(self):
        """Stores the chosen preset in the result."""
        with patch(
            "tweek.integrations.openclaw.detect_openclaw_installation"
        ) as mock_detect:
            mock_detect.return_value = {
                "installed": False,
                "version": None,
                "gateway_port": 18789,
                "gateway_active": False,
            }
            result = setup_openclaw_protection(preset="paranoid")

        assert result.preset == "paranoid"


class TestOpenClawSetupResult:
    """Tests for the OpenClawSetupResult dataclass."""

    def test_defaults(self):
        """Default values are sensible."""
        result = OpenClawSetupResult()
        assert result.success is False
        assert result.openclaw_detected is False
        assert result.openclaw_version is None
        assert result.gateway_port is None
        assert result.gateway_running is False
        assert result.scanner_port == SCANNER_SERVER_PORT
        assert result.preset == "cautious"
        assert result.config_path is None
        assert result.plugin_installed is False
        assert result.error is None
        assert result.warnings == []


class TestWriteOpenClawConfig:
    """Tests for _write_openclaw_config()."""

    def test_writes_config_file(self, tmp_path):
        """Creates openclaw.json with plugin config."""
        config_path = tmp_path / "openclaw.json"

        with patch("tweek.integrations.openclaw.OPENCLAW_HOME", tmp_path), \
             patch("tweek.integrations.openclaw.OPENCLAW_CONFIG", config_path):
            result_path, error = _write_openclaw_config(
                gateway_port=18789,
                scanner_port=9878,
                preset="cautious",
            )

        assert error is None
        assert result_path == str(config_path)
        assert config_path.exists()

        config = json.loads(config_path.read_text())
        assert config["plugins"]["entries"]["tweek"]["enabled"] is True
        assert config["plugins"]["entries"]["tweek"]["config"]["preset"] == "cautious"
        assert config["plugins"]["entries"]["tweek"]["config"]["scannerPort"] == 9878

    def test_preserves_existing_config(self, tmp_path):
        """Preserves existing config entries when adding Tweek plugin."""
        config_path = tmp_path / "openclaw.json"
        config_path.write_text(json.dumps({
            "agent": {"model": "anthropic/claude-opus-4-5"},
            "plugins": {"entries": {"other-plugin": {"enabled": True}}},
        }))

        with patch("tweek.integrations.openclaw.OPENCLAW_HOME", tmp_path), \
             patch("tweek.integrations.openclaw.OPENCLAW_CONFIG", config_path):
            _write_openclaw_config(18789, 9878, "cautious")

        config = json.loads(config_path.read_text())
        assert config["agent"]["model"] == "anthropic/claude-opus-4-5"
        assert "other-plugin" in config["plugins"]["entries"]
        assert "tweek" in config["plugins"]["entries"]

    def test_paranoid_preset(self, tmp_path):
        """Paranoid preset enables manual approval and full screening."""
        config_path = tmp_path / "openclaw.json"

        with patch("tweek.integrations.openclaw.OPENCLAW_HOME", tmp_path), \
             patch("tweek.integrations.openclaw.OPENCLAW_CONFIG", config_path):
            _write_openclaw_config(18789, 9878, "paranoid")

        config = json.loads(config_path.read_text())
        tweek_config = config["plugins"]["entries"]["tweek"]["config"]
        assert tweek_config["skillGuard"]["mode"] == "manual"
        assert tweek_config["outputScanning"]["enabled"] is True

    def test_trusted_preset(self, tmp_path):
        """Trusted preset uses fingerprint-only and disables output scanning."""
        config_path = tmp_path / "openclaw.json"

        with patch("tweek.integrations.openclaw.OPENCLAW_HOME", tmp_path), \
             patch("tweek.integrations.openclaw.OPENCLAW_CONFIG", config_path):
            _write_openclaw_config(18789, 9878, "trusted")

        config = json.loads(config_path.read_text())
        tweek_config = config["plugins"]["entries"]["tweek"]["config"]
        assert tweek_config["skillGuard"]["mode"] == "fingerprint_only"
        assert tweek_config["outputScanning"]["enabled"] is False
        assert tweek_config["toolScreening"]["llmReview"] is False


class TestCheckPluginInstalled:
    """Tests for _check_plugin_installed()."""

    def test_returns_false_when_cli_not_found(self):
        """Returns False when openclaw CLI is not available."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert _check_plugin_installed() is False

    def test_returns_true_when_plugin_found(self):
        """Returns True when tweek plugin is in the plugin list."""
        mock_output = json.dumps({
            "plugins": [
                {"name": "@tweek/openclaw-plugin"},
                {"name": "other-plugin"},
            ]
        })

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=mock_output, stderr=""
            )
            assert _check_plugin_installed() is True

    def test_returns_true_for_clawhub_name(self):
        """Returns True for the ClawHub marketplace name 'tweek-security'."""
        mock_output = json.dumps({
            "plugins": [
                {"name": "tweek-security"},
            ]
        })

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=mock_output, stderr=""
            )
            assert _check_plugin_installed() is True


class TestOpenClawPaths:
    """Tests for OpenClaw path constants."""

    def test_openclaw_home(self):
        """OPENCLAW_HOME is ~/.openclaw."""
        assert OPENCLAW_HOME == Path.home() / ".openclaw"

    def test_openclaw_config(self):
        """OPENCLAW_CONFIG is ~/.openclaw/openclaw.json."""
        assert OPENCLAW_CONFIG == Path.home() / ".openclaw" / "openclaw.json"

    def test_openclaw_skills_dir(self):
        """OPENCLAW_SKILLS_DIR is ~/.openclaw/workspace/skills."""
        assert OPENCLAW_SKILLS_DIR == Path.home() / ".openclaw" / "workspace" / "skills"

    def test_default_port(self):
        """Default gateway port is 18789."""
        assert OPENCLAW_DEFAULT_PORT == 18789

    def test_scanner_port(self):
        """Scanner server port is 9878."""
        assert SCANNER_SERVER_PORT == 9878
