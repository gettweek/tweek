#!/usr/bin/env python3
"""
Tests for Tweek tool detector plugins.

Covers all 5 detector plugins:
- CursorDetector: Cursor AI IDE detection
- CopilotDetector: GitHub Copilot detection (VS Code, JetBrains, Neovim, CLI)
- WindsurfDetector: Windsurf AI IDE detection (by Codeium)
- ContinueDetector: Continue.dev extension detection (VS Code, JetBrains)
- OpenClawDetector: OpenClaw AI personal assistant detection

Each test class covers:
- detect() when installed (paths exist, process running)
- detect() when not installed (nothing found)
- _check_running() / _check_running_process() behavior
- get_conflicts() behavior
- get_proxy_config_instructions() where available
- Platform-specific path logic
- Edge cases (timeouts, missing binaries, corrupt configs)
"""

import json
import os
import subprocess
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

from tweek.plugins.base import ToolDetectorPlugin, DetectionResult
from tweek.plugins.detectors.cursor import CursorDetector
from tweek.plugins.detectors.copilot import CopilotDetector
from tweek.plugins.detectors.windsurf import WindsurfDetector
from tweek.plugins.detectors.continue_dev import ContinueDetector
from tweek.plugins.detectors.openclaw import OpenClawDetector

pytestmark = pytest.mark.plugins


# =============================================================================
# Helper utilities
# =============================================================================

def _make_completed_process(returncode=0, stdout="", stderr=""):
    """Create a mock subprocess.CompletedProcess."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _patch_platform(system_name):
    """Return a patch for platform.system() returning the given OS name."""
    return patch("platform.system", return_value=system_name)


# =============================================================================
# CursorDetector Tests
# =============================================================================

class TestCursorDetector:
    """Tests for the Cursor IDE detector plugin."""

    @pytest.fixture
    def detector(self):
        return CursorDetector()

    # --- Basic properties ---

    def test_name(self, detector):
        """Test that detector name is 'cursor'."""
        assert detector.name == "cursor"

    def test_inherits_tool_detector(self, detector):
        """Test that CursorDetector inherits from ToolDetectorPlugin."""
        assert isinstance(detector, ToolDetectorPlugin)

    def test_class_metadata(self, detector):
        """Test class-level metadata attributes."""
        assert detector.VERSION == "1.0.0"
        assert detector.DESCRIPTION == "Detect Cursor AI IDE"
        assert detector.REQUIRES_LICENSE == "free"
        assert "cursor" in detector.TAGS

    # --- detect() when not installed ---

    def test_detect_not_installed(self, detector, tmp_path):
        """Test detect() returns not detected when nothing is found."""
        with _patch_platform("Darwin"), \
             patch.object(Path, "exists", return_value=False), \
             patch("subprocess.run", return_value=_make_completed_process(returncode=1, stdout="")):
            result = detector.detect()

        assert isinstance(result, DetectionResult)
        assert result.detected is False
        assert result.tool_name == "cursor"
        assert result.install_path is None
        assert result.config_path is None
        assert result.running is False

    # --- detect() when installed (macOS) ---

    def test_detect_installed_macos_app(self, detector, tmp_path):
        """Test detection via macOS application path."""
        app_path = tmp_path / "Applications" / "Cursor.app"
        app_path.mkdir(parents=True)

        def fake_install_paths():
            return [app_path, tmp_path / "nope"]

        def fake_config_paths():
            return [tmp_path / "nonexistent_config"]

        with patch.object(detector, "_get_install_paths", fake_install_paths), \
             patch.object(detector, "_get_config_paths", fake_config_paths), \
             patch.object(detector, "_check_running", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.install_path == str(app_path)

    def test_detect_installed_via_config(self, detector, tmp_path):
        """Test detection via config path existence."""
        config_dir = tmp_path / ".cursor"
        config_dir.mkdir(parents=True)

        def fake_install_paths():
            return [tmp_path / "nope"]

        def fake_config_paths():
            return [config_dir]

        with patch.object(detector, "_get_install_paths", fake_install_paths), \
             patch.object(detector, "_get_config_paths", fake_config_paths), \
             patch.object(detector, "_check_running", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.config_path == str(config_dir)

    def test_detect_reads_version_from_product_json(self, detector, tmp_path):
        """Test that version is extracted from product.json in config dir."""
        config_dir = tmp_path / ".cursor"
        config_dir.mkdir(parents=True)
        product_json = config_dir / "product.json"
        product_json.write_text(json.dumps({"version": "0.42.1"}))

        def fake_install_paths():
            return [tmp_path / "nope"]

        def fake_config_paths():
            return [config_dir]

        with patch.object(detector, "_get_install_paths", fake_install_paths), \
             patch.object(detector, "_get_config_paths", fake_config_paths), \
             patch.object(detector, "_check_running", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.version == "0.42.1"

    def test_detect_corrupt_product_json(self, detector, tmp_path):
        """Test that corrupt product.json does not crash detection."""
        config_dir = tmp_path / ".cursor"
        config_dir.mkdir(parents=True)
        product_json = config_dir / "product.json"
        product_json.write_text("NOT VALID JSON {{{")

        def fake_install_paths():
            return [tmp_path / "nope"]

        def fake_config_paths():
            return [config_dir]

        with patch.object(detector, "_get_install_paths", fake_install_paths), \
             patch.object(detector, "_get_config_paths", fake_config_paths), \
             patch.object(detector, "_check_running", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.version is None

    def test_detect_running_process_sets_detected(self, detector):
        """Test that a running Cursor process sets detected=True."""
        with patch.object(Path, "exists", return_value=False), \
             _patch_platform("Darwin"), \
             patch.object(detector, "_check_running", return_value=True):
            result = detector.detect()

        assert result.detected is True
        assert result.running is True

    # --- _check_running() ---

    def test_check_running_macos_found(self, detector):
        """Test _check_running on macOS when Cursor process is found."""
        with _patch_platform("Darwin"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(returncode=0, stdout="12345\n")):
            assert detector._check_running() is True

    def test_check_running_macos_not_found(self, detector):
        """Test _check_running on macOS when Cursor is not running."""
        with _patch_platform("Darwin"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(returncode=1, stdout="")):
            assert detector._check_running() is False

    def test_check_running_macos_empty_stdout(self, detector):
        """Test _check_running returns False if pgrep returns 0 but empty stdout."""
        with _patch_platform("Darwin"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(returncode=0, stdout="")):
            assert detector._check_running() is False

    def test_check_running_windows(self, detector):
        """Test _check_running on Windows using tasklist."""
        with _patch_platform("Windows"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(
                       returncode=0,
                       stdout='"Cursor.exe","1234","Console","1","50,000 K"\n'
                   )):
            assert detector._check_running() is True

    def test_check_running_windows_not_found(self, detector):
        """Test _check_running on Windows when not running."""
        with _patch_platform("Windows"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(
                       returncode=0,
                       stdout='INFO: No tasks are running which match the specified criteria.'
                   )):
            assert detector._check_running() is False

    def test_check_running_linux(self, detector):
        """Test _check_running on Linux."""
        with _patch_platform("Linux"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(returncode=0, stdout="9876\n")):
            assert detector._check_running() is True

    def test_check_running_timeout(self, detector):
        """Test _check_running handles subprocess timeout gracefully."""
        with _patch_platform("Darwin"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("pgrep", 5)):
            assert detector._check_running() is False

    def test_check_running_file_not_found(self, detector):
        """Test _check_running handles missing pgrep binary."""
        with _patch_platform("Darwin"), \
             patch("subprocess.run", side_effect=FileNotFoundError("pgrep not found")):
            assert detector._check_running() is False

    # --- _get_install_paths() ---

    def test_install_paths_macos(self, detector):
        """Test macOS install paths include /Applications and ~/Applications."""
        with _patch_platform("Darwin"):
            paths = detector._get_install_paths()
        assert any("Cursor.app" in str(p) for p in paths)
        assert len(paths) == 2

    def test_install_paths_windows(self, detector):
        """Test Windows install paths include Programs directory."""
        with _patch_platform("Windows"), \
             patch.dict(os.environ, {"LOCALAPPDATA": "C:\\Users\\test\\AppData\\Local",
                                     "PROGRAMFILES": "C:\\Program Files"}):
            paths = detector._get_install_paths()
        assert any("Cursor.exe" in str(p) for p in paths)
        assert len(paths) == 2

    def test_install_paths_linux(self, detector):
        """Test Linux install paths include standard binary locations."""
        with _patch_platform("Linux"):
            paths = detector._get_install_paths()
        assert any("/usr/bin/cursor" in str(p) for p in paths)
        assert len(paths) >= 3

    # --- get_conflicts() ---

    def test_get_conflicts_running(self, detector):
        """Test that conflicts are reported when Cursor is running."""
        mock_result = DetectionResult(
            detected=True, tool_name="cursor", running=True
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 1
        assert "Cursor IDE is running" in conflicts[0]

    def test_get_conflicts_installed_not_running(self, detector):
        """Test no conflicts when Cursor is installed but not running."""
        mock_result = DetectionResult(
            detected=True, tool_name="cursor", running=False
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 0

    def test_get_conflicts_not_detected(self, detector):
        """Test no conflicts when Cursor is not detected."""
        mock_result = DetectionResult(
            detected=False, tool_name="cursor", running=False
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 0

    # --- get_proxy_config_instructions() ---

    def test_proxy_config_instructions(self, detector):
        """Test that proxy config instructions are returned as a non-empty string."""
        instructions = detector.get_proxy_config_instructions()
        assert isinstance(instructions, str)
        assert "tweek proxy start" in instructions
        assert "127.0.0.1:9877" in instructions
        assert "HTTPS_PROXY" in instructions

    # --- configure() ---

    def test_configure(self, detector):
        """Test that configure() updates internal config."""
        detector.configure({"custom_key": "custom_value"})
        assert detector._config["custom_key"] == "custom_value"


# =============================================================================
# CopilotDetector Tests
# =============================================================================

class TestCopilotDetector:
    """Tests for the GitHub Copilot detector plugin."""

    @pytest.fixture
    def detector(self):
        return CopilotDetector()

    # --- Basic properties ---

    def test_name(self, detector):
        """Test that detector name is 'copilot'."""
        assert detector.name == "copilot"

    def test_inherits_tool_detector(self, detector):
        """Test that CopilotDetector inherits from ToolDetectorPlugin."""
        assert isinstance(detector, ToolDetectorPlugin)

    def test_class_metadata(self, detector):
        """Test class-level metadata attributes."""
        assert detector.VERSION == "1.0.0"
        assert "copilot" in detector.TAGS

    # --- detect() when not installed ---

    def test_detect_not_installed(self, detector):
        """Test detect() returns not detected when nothing exists."""
        with patch.object(Path, "exists", return_value=False), \
             _patch_platform("Darwin"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(returncode=1, stdout="")):
            result = detector.detect()

        assert result.detected is False
        assert result.tool_name == "copilot"
        assert result.metadata["vscode"] is False
        assert result.metadata["jetbrains"] is False
        assert result.metadata["neovim"] is False
        assert result.metadata["cli"] is False

    # --- detect() with VS Code extension ---

    def test_detect_vscode_extension(self, detector, tmp_path):
        """Test detection of VS Code Copilot extension."""
        # Create fake extension directory structure
        ext_dir = tmp_path / ".vscode" / "extensions"
        copilot_ext = ext_dir / "github.copilot-1.200.0"
        copilot_ext.mkdir(parents=True)

        # Write a package.json with version
        package_json = copilot_ext / "package.json"
        package_json.write_text(json.dumps({"version": "1.200.0"}))

        def fake_vscode_paths():
            return [ext_dir]

        def fake_jetbrains_paths():
            return [tmp_path / "nonexistent_jb"]

        def fake_neovim_paths():
            return [tmp_path / "nonexistent_nvim"]

        def fake_cli_paths():
            return [tmp_path / "nonexistent_cli"]

        with patch.object(detector, "_get_vscode_extension_paths", fake_vscode_paths), \
             patch.object(detector, "_get_jetbrains_plugin_paths", fake_jetbrains_paths), \
             patch.object(detector, "_get_neovim_plugin_paths", fake_neovim_paths), \
             patch.object(detector, "_get_cli_paths", fake_cli_paths), \
             patch.object(detector, "_check_running", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.metadata["vscode"] is True
        assert result.version == "1.200.0"
        assert "github.copilot" in result.install_path

    def test_detect_vscode_extension_corrupt_package_json(self, detector, tmp_path):
        """Test detection handles corrupt package.json in VS Code extension."""
        ext_dir = tmp_path / ".vscode" / "extensions"
        copilot_ext = ext_dir / "github.copilot-1.200.0"
        copilot_ext.mkdir(parents=True)

        package_json = copilot_ext / "package.json"
        package_json.write_text("INVALID JSON")

        def fake_vscode_paths():
            return [ext_dir]

        def fake_jetbrains_paths():
            return [tmp_path / "nonexistent_jb"]

        def fake_neovim_paths():
            return [tmp_path / "nonexistent_nvim"]

        def fake_cli_paths():
            return [tmp_path / "nonexistent_cli"]

        with patch.object(detector, "_get_vscode_extension_paths", fake_vscode_paths), \
             patch.object(detector, "_get_jetbrains_plugin_paths", fake_jetbrains_paths), \
             patch.object(detector, "_get_neovim_plugin_paths", fake_neovim_paths), \
             patch.object(detector, "_get_cli_paths", fake_cli_paths), \
             patch.object(detector, "_check_running", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.metadata["vscode"] is True
        assert result.version is None

    # --- detect() with JetBrains plugin ---

    def test_detect_jetbrains_plugin(self, detector, tmp_path):
        """Test detection of JetBrains Copilot plugin."""
        jb_dir = tmp_path / "JetBrains"
        plugin_dir = jb_dir / "IntelliJIdea2024.1" / "plugins" / "github-copilot"
        plugin_dir.mkdir(parents=True)

        def fake_vscode_paths():
            return [tmp_path / "nonexistent_vsc"]

        def fake_jetbrains_paths():
            return [jb_dir]

        def fake_neovim_paths():
            return [tmp_path / "nonexistent_nvim"]

        def fake_cli_paths():
            return [tmp_path / "nonexistent_cli"]

        with patch.object(detector, "_get_vscode_extension_paths", fake_vscode_paths), \
             patch.object(detector, "_get_jetbrains_plugin_paths", fake_jetbrains_paths), \
             patch.object(detector, "_get_neovim_plugin_paths", fake_neovim_paths), \
             patch.object(detector, "_get_cli_paths", fake_cli_paths), \
             patch.object(detector, "_check_running", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.metadata["jetbrains"] is True

    # --- detect() with Neovim plugin ---

    def test_detect_neovim_plugin(self, detector, tmp_path):
        """Test detection of Neovim Copilot plugin."""
        nvim_dir = tmp_path / "nvim" / "site" / "pack"
        nvim_dir.mkdir(parents=True)
        copilot_dir = nvim_dir / "plugins" / "start" / "copilot.vim"
        copilot_dir.mkdir(parents=True)

        def fake_vscode_paths():
            return [tmp_path / "nonexistent_vsc"]

        def fake_jetbrains_paths():
            return [tmp_path / "nonexistent_jb"]

        def fake_neovim_paths():
            return [nvim_dir]

        def fake_cli_paths():
            return [tmp_path / "nonexistent_cli"]

        with patch.object(detector, "_get_vscode_extension_paths", fake_vscode_paths), \
             patch.object(detector, "_get_jetbrains_plugin_paths", fake_jetbrains_paths), \
             patch.object(detector, "_get_neovim_plugin_paths", fake_neovim_paths), \
             patch.object(detector, "_get_cli_paths", fake_cli_paths), \
             patch.object(detector, "_check_running", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.metadata["neovim"] is True

    # --- detect() with CLI ---

    def test_detect_cli(self, detector, tmp_path):
        """Test detection of Copilot CLI (gh-copilot)."""
        cli_path = tmp_path / "gh-copilot"
        cli_path.touch()

        def fake_vscode_paths():
            return [tmp_path / "nonexistent_vsc"]

        def fake_jetbrains_paths():
            return [tmp_path / "nonexistent_jb"]

        def fake_neovim_paths():
            return [tmp_path / "nonexistent_nvim"]

        def fake_cli_paths():
            return [cli_path]

        with patch.object(detector, "_get_vscode_extension_paths", fake_vscode_paths), \
             patch.object(detector, "_get_jetbrains_plugin_paths", fake_jetbrains_paths), \
             patch.object(detector, "_get_neovim_plugin_paths", fake_neovim_paths), \
             patch.object(detector, "_get_cli_paths", fake_cli_paths), \
             patch.object(detector, "_check_running", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.metadata["cli"] is True

    # --- _check_running() ---

    def test_check_running_unix_found(self, detector):
        """Test _check_running on Unix when copilot process is found."""
        with _patch_platform("Darwin"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(returncode=0, stdout="54321\n")):
            assert detector._check_running() is True

    def test_check_running_unix_not_found(self, detector):
        """Test _check_running on Unix when copilot is not running."""
        with _patch_platform("Linux"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(returncode=1, stdout="")):
            assert detector._check_running() is False

    def test_check_running_windows_found(self, detector):
        """Test _check_running on Windows when copilot is found."""
        with _patch_platform("Windows"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(
                       returncode=0,
                       stdout='"copilot-agent.exe","5678","Console","1","25,000 K"\n'
                   )):
            assert detector._check_running() is True

    def test_check_running_windows_not_found(self, detector):
        """Test _check_running on Windows when copilot is not running."""
        with _patch_platform("Windows"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(
                       returncode=0,
                       stdout='INFO: No tasks are running which match the specified criteria.'
                   )):
            assert detector._check_running() is False

    def test_check_running_timeout(self, detector):
        """Test _check_running handles subprocess timeout gracefully."""
        with _patch_platform("Darwin"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("pgrep", 5)):
            assert detector._check_running() is False

    def test_check_running_file_not_found(self, detector):
        """Test _check_running handles missing pgrep binary."""
        with _patch_platform("Linux"), \
             patch("subprocess.run", side_effect=FileNotFoundError):
            assert detector._check_running() is False

    # --- Path methods ---

    def test_vscode_extension_paths_macos(self, detector):
        """Test VS Code extension paths on macOS."""
        with _patch_platform("Darwin"):
            paths = detector._get_vscode_extension_paths()
        assert any(".vscode" in str(p) for p in paths)
        assert any(".vscode-insiders" in str(p) for p in paths)

    def test_vscode_extension_paths_linux(self, detector):
        """Test VS Code extension paths on Linux include vscode-server."""
        with _patch_platform("Linux"):
            paths = detector._get_vscode_extension_paths()
        assert any(".vscode-server" in str(p) for p in paths)

    def test_jetbrains_plugin_paths_macos(self, detector):
        """Test JetBrains plugin paths on macOS."""
        with _patch_platform("Darwin"):
            paths = detector._get_jetbrains_plugin_paths()
        assert any("Library" in str(p) and "JetBrains" in str(p) for p in paths)

    def test_cli_paths_macos(self, detector):
        """Test CLI paths on macOS include homebrew path."""
        with _patch_platform("Darwin"):
            paths = detector._get_cli_paths()
        assert any("homebrew" in str(p) for p in paths)

    def test_neovim_plugin_paths_linux(self, detector):
        """Test Neovim plugin paths on Linux."""
        with _patch_platform("Linux"):
            paths = detector._get_neovim_plugin_paths()
        assert any("nvim" in str(p) for p in paths)

    # --- get_conflicts() ---

    def test_get_conflicts_vscode_detected(self, detector):
        """Test conflicts when VS Code Copilot is detected."""
        mock_result = DetectionResult(
            detected=True, tool_name="copilot",
            metadata={"vscode": True, "jetbrains": False, "neovim": False, "cli": False}
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 1
        assert "VS Code extension" in conflicts[0]

    def test_get_conflicts_jetbrains_detected(self, detector):
        """Test conflicts when JetBrains Copilot is detected."""
        mock_result = DetectionResult(
            detected=True, tool_name="copilot",
            metadata={"vscode": False, "jetbrains": True, "neovim": False, "cli": False}
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 1
        assert "JetBrains" in conflicts[0]

    def test_get_conflicts_both_vscode_and_jetbrains(self, detector):
        """Test conflicts when both VS Code and JetBrains are detected."""
        mock_result = DetectionResult(
            detected=True, tool_name="copilot",
            metadata={"vscode": True, "jetbrains": True, "neovim": False, "cli": False}
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 2

    def test_get_conflicts_not_detected(self, detector):
        """Test no conflicts when Copilot is not detected."""
        mock_result = DetectionResult(
            detected=False, tool_name="copilot",
            metadata={"vscode": False, "jetbrains": False, "neovim": False, "cli": False}
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 0

    def test_get_conflicts_cli_only_no_conflict(self, detector):
        """Test no conflicts when only CLI is detected (no VS Code/JetBrains)."""
        mock_result = DetectionResult(
            detected=True, tool_name="copilot",
            metadata={"vscode": False, "jetbrains": False, "neovim": False, "cli": True}
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 0

    # --- detect() with running process ---

    def test_detect_running_process(self, detector):
        """Test that a running copilot process sets detected=True."""
        with patch.object(Path, "exists", return_value=False), \
             _patch_platform("Darwin"), \
             patch.object(detector, "_check_running", return_value=True):
            result = detector.detect()

        assert result.detected is True
        assert result.running is True


# =============================================================================
# WindsurfDetector Tests
# =============================================================================

class TestWindsurfDetector:
    """Tests for the Windsurf AI IDE detector plugin."""

    @pytest.fixture
    def detector(self):
        return WindsurfDetector()

    # --- Basic properties ---

    def test_name(self, detector):
        """Test that detector name is 'windsurf'."""
        assert detector.name == "windsurf"

    def test_inherits_tool_detector(self, detector):
        """Test that WindsurfDetector inherits from ToolDetectorPlugin."""
        assert isinstance(detector, ToolDetectorPlugin)

    def test_class_metadata(self, detector):
        """Test class-level metadata attributes."""
        assert detector.VERSION == "1.0.0"
        assert "windsurf" in detector.TAGS
        assert "codeium" in detector.TAGS

    # --- detect() when not installed ---

    def test_detect_not_installed(self, detector):
        """Test detect() returns not detected when nothing exists."""
        with patch.object(Path, "exists", return_value=False), \
             _patch_platform("Darwin"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(returncode=1, stdout="")):
            result = detector.detect()

        assert result.detected is False
        assert result.tool_name == "windsurf"
        assert result.install_path is None
        assert result.config_path is None
        assert result.running is False

    # --- detect() when installed ---

    def test_detect_installed_macos_app(self, detector, tmp_path):
        """Test detection via macOS application path."""
        app_path = tmp_path / "Windsurf.app"
        app_path.mkdir(parents=True)

        def fake_install_paths():
            return [app_path]

        def fake_config_paths():
            return [tmp_path / "nonexistent_config"]

        with patch.object(detector, "_get_install_paths", fake_install_paths), \
             patch.object(detector, "_get_config_paths", fake_config_paths), \
             patch.object(detector, "_check_running", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.install_path == str(app_path)

    def test_detect_via_config_with_version(self, detector, tmp_path):
        """Test detection via config path with version from product.json."""
        config_dir = tmp_path / ".windsurf"
        config_dir.mkdir(parents=True)
        product_json = config_dir / "product.json"
        product_json.write_text(json.dumps({"version": "1.5.3"}))

        def fake_install_paths():
            return [tmp_path / "nope"]

        def fake_config_paths():
            return [config_dir]

        with patch.object(detector, "_get_install_paths", fake_install_paths), \
             patch.object(detector, "_get_config_paths", fake_config_paths), \
             patch.object(detector, "_check_running", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.config_path == str(config_dir)
        assert result.version == "1.5.3"

    def test_detect_config_with_codeium_settings(self, detector, tmp_path):
        """Test detection of Codeium configuration in settings.json."""
        config_dir = tmp_path / ".windsurf"
        user_dir = config_dir / "User"
        user_dir.mkdir(parents=True)
        settings_file = user_dir / "settings.json"
        settings_file.write_text(json.dumps({
            "codeium.enableAutoComplete": True,
            "editor.fontSize": 14,
        }))

        def fake_install_paths():
            return [tmp_path / "nope"]

        def fake_config_paths():
            return [config_dir]

        with patch.object(detector, "_get_install_paths", fake_install_paths), \
             patch.object(detector, "_get_config_paths", fake_config_paths), \
             patch.object(detector, "_check_running", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.metadata.get("has_settings") is True
        assert result.metadata.get("codeium_configured") is True

    def test_detect_config_without_codeium_settings(self, detector, tmp_path):
        """Test detection when settings.json exists but has no Codeium keys."""
        config_dir = tmp_path / ".windsurf"
        user_dir = config_dir / "User"
        user_dir.mkdir(parents=True)
        settings_file = user_dir / "settings.json"
        settings_file.write_text(json.dumps({
            "editor.fontSize": 14,
            "workbench.colorTheme": "Default Dark+",
        }))

        def fake_install_paths():
            return [tmp_path / "nope"]

        def fake_config_paths():
            return [config_dir]

        with patch.object(detector, "_get_install_paths", fake_install_paths), \
             patch.object(detector, "_get_config_paths", fake_config_paths), \
             patch.object(detector, "_check_running", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.metadata.get("has_settings") is True
        assert result.metadata.get("codeium_configured") is None  # not set

    def test_detect_corrupt_settings_json(self, detector, tmp_path):
        """Test detection handles corrupt settings.json."""
        config_dir = tmp_path / ".windsurf"
        user_dir = config_dir / "User"
        user_dir.mkdir(parents=True)
        settings_file = user_dir / "settings.json"
        settings_file.write_text("NOT VALID JSON")

        def fake_install_paths():
            return [tmp_path / "nope"]

        def fake_config_paths():
            return [config_dir]

        with patch.object(detector, "_get_install_paths", fake_install_paths), \
             patch.object(detector, "_get_config_paths", fake_config_paths), \
             patch.object(detector, "_check_running", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.metadata.get("has_settings") is None  # not set due to exception

    # --- _check_running() ---

    def test_check_running_macos_found(self, detector):
        """Test _check_running on macOS when Windsurf is found."""
        with _patch_platform("Darwin"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(returncode=0, stdout="12345\n")):
            assert detector._check_running() is True

    def test_check_running_macos_not_found(self, detector):
        """Test _check_running on macOS when Windsurf is not running."""
        with _patch_platform("Darwin"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(returncode=1, stdout="")):
            assert detector._check_running() is False

    def test_check_running_windows_found(self, detector):
        """Test _check_running on Windows."""
        with _patch_platform("Windows"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(
                       returncode=0,
                       stdout='"Windsurf.exe","2222","Console","1","100,000 K"\n'
                   )):
            assert detector._check_running() is True

    def test_check_running_windows_not_found(self, detector):
        """Test _check_running on Windows when not running."""
        with _patch_platform("Windows"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(
                       returncode=0,
                       stdout='INFO: No tasks match the criteria.\n'
                   )):
            assert detector._check_running() is False

    def test_check_running_linux_found(self, detector):
        """Test _check_running on Linux."""
        with _patch_platform("Linux"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(returncode=0, stdout="5555\n")):
            assert detector._check_running() is True

    def test_check_running_timeout(self, detector):
        """Test _check_running handles subprocess timeout."""
        with _patch_platform("Darwin"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("pgrep", 5)):
            assert detector._check_running() is False

    def test_check_running_file_not_found(self, detector):
        """Test _check_running handles missing pgrep binary."""
        with _patch_platform("Linux"), \
             patch("subprocess.run", side_effect=FileNotFoundError):
            assert detector._check_running() is False

    # --- _get_install_paths() ---

    def test_install_paths_macos(self, detector):
        """Test macOS install paths."""
        with _patch_platform("Darwin"):
            paths = detector._get_install_paths()
        assert any("Windsurf.app" in str(p) for p in paths)
        assert len(paths) == 2

    def test_install_paths_windows(self, detector):
        """Test Windows install paths."""
        with _patch_platform("Windows"), \
             patch.dict(os.environ, {"LOCALAPPDATA": "C:\\Users\\test\\AppData\\Local",
                                     "PROGRAMFILES": "C:\\Program Files"}):
            paths = detector._get_install_paths()
        assert any("Windsurf.exe" in str(p) for p in paths)

    def test_install_paths_linux(self, detector):
        """Test Linux install paths."""
        with _patch_platform("Linux"):
            paths = detector._get_install_paths()
        assert any("/usr/bin/windsurf" in str(p) for p in paths)
        assert len(paths) >= 3

    # --- _get_config_paths() ---

    def test_config_paths_macos(self, detector):
        """Test macOS config paths include Library and dotfiles."""
        with _patch_platform("Darwin"):
            paths = detector._get_config_paths()
        assert any("Library" in str(p) and "Windsurf" in str(p) for p in paths)
        assert any(".windsurf" in str(p) for p in paths)

    def test_config_paths_linux(self, detector):
        """Test Linux config paths."""
        with _patch_platform("Linux"):
            paths = detector._get_config_paths()
        assert any(".config" in str(p) and "Windsurf" in str(p) for p in paths)

    # --- get_conflicts() ---

    def test_get_conflicts_running(self, detector):
        """Test conflicts when Windsurf is running."""
        mock_result = DetectionResult(
            detected=True, tool_name="windsurf", running=True
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 1
        assert "Windsurf IDE is running" in conflicts[0]
        assert "Codeium" in conflicts[0]

    def test_get_conflicts_installed_not_running(self, detector):
        """Test no conflicts when installed but not running."""
        mock_result = DetectionResult(
            detected=True, tool_name="windsurf", running=False
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 0

    def test_get_conflicts_not_detected(self, detector):
        """Test no conflicts when not detected."""
        mock_result = DetectionResult(
            detected=False, tool_name="windsurf", running=False
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 0

    # --- get_proxy_config_instructions() ---

    def test_proxy_config_instructions(self, detector):
        """Test proxy config instructions content."""
        instructions = detector.get_proxy_config_instructions()
        assert isinstance(instructions, str)
        assert "tweek proxy start" in instructions
        assert "127.0.0.1:9877" in instructions
        assert "Proxy Support" in instructions
        assert "tweek proxy trust" in instructions


# =============================================================================
# ContinueDetector Tests
# =============================================================================

class TestContinueDetector:
    """Tests for the Continue.dev extension detector plugin."""

    @pytest.fixture
    def detector(self):
        return ContinueDetector()

    # --- Basic properties ---

    def test_name(self, detector):
        """Test that detector name is 'continue'."""
        assert detector.name == "continue"

    def test_inherits_tool_detector(self, detector):
        """Test that ContinueDetector inherits from ToolDetectorPlugin."""
        assert isinstance(detector, ToolDetectorPlugin)

    def test_class_metadata(self, detector):
        """Test class-level metadata attributes."""
        assert detector.VERSION == "1.0.0"
        assert "continue" in detector.TAGS

    def test_extension_id(self, detector):
        """Test the extension ID constant."""
        assert detector.EXTENSION_ID == "continue.continue"

    # --- detect() when not installed ---

    def test_detect_not_installed(self, detector):
        """Test detect() returns not detected when nothing exists."""
        with patch.object(Path, "exists", return_value=False), \
             _patch_platform("Darwin"):
            result = detector.detect()

        assert result.detected is False
        assert result.tool_name == "continue"

    # --- detect() with VS Code extension ---

    def test_detect_vscode_extension(self, detector, tmp_path):
        """Test detection of Continue VS Code extension."""
        ext_dir = tmp_path / ".vscode" / "extensions"
        continue_ext = ext_dir / "continue.continue-0.9.5"
        continue_ext.mkdir(parents=True)

        def fake_vscode_paths():
            return [ext_dir]

        with patch.object(detector, "_get_vscode_extensions_paths", fake_vscode_paths), \
             patch.object(detector, "_get_config_path", return_value=tmp_path / "nonexistent"), \
             patch.object(detector, "_check_jetbrains", return_value=None):
            result = detector.detect()

        assert result.detected is True
        assert result.install_path == str(continue_ext)
        assert result.version == "0.9.5"
        assert result.metadata.get("install_type") == "vscode"

    def test_detect_vscode_extension_multiple_versions(self, detector, tmp_path):
        """Test detection picks up Continue extension when multiple versions exist."""
        ext_dir = tmp_path / ".vscode" / "extensions"
        ext_dir.mkdir(parents=True)
        (ext_dir / "continue.continue-0.9.5").mkdir()
        (ext_dir / "some-other-extension-1.0.0").mkdir()

        def fake_vscode_paths():
            return [ext_dir]

        with patch.object(detector, "_get_vscode_extensions_paths", fake_vscode_paths), \
             patch.object(detector, "_get_config_path", return_value=tmp_path / "nonexistent"), \
             patch.object(detector, "_check_jetbrains", return_value=None):
            result = detector.detect()

        assert result.detected is True
        assert "continue.continue" in result.install_path

    # --- detect() with config directory ---

    def test_detect_config_directory(self, detector, tmp_path):
        """Test detection via ~/.continue config directory."""
        config_dir = tmp_path / ".continue"
        config_dir.mkdir(parents=True)

        def fake_vscode_paths():
            return [tmp_path / "nonexistent"]

        with patch.object(detector, "_get_vscode_extensions_paths", fake_vscode_paths), \
             patch.object(detector, "_get_config_path", return_value=config_dir), \
             patch.object(detector, "_check_jetbrains", return_value=None):
            result = detector.detect()

        assert result.detected is True
        assert result.config_path == str(config_dir)

    def test_detect_config_with_models(self, detector, tmp_path):
        """Test detection reads models from config.json."""
        config_dir = tmp_path / ".continue"
        config_dir.mkdir(parents=True)
        config_file = config_dir / "config.json"
        config_file.write_text(json.dumps({
            "models": [
                {"title": "GPT-4", "model": "gpt-4"},
                {"title": "Claude", "model": "claude-3-opus"},
            ]
        }))

        def fake_vscode_paths():
            return [tmp_path / "nonexistent"]

        with patch.object(detector, "_get_vscode_extensions_paths", fake_vscode_paths), \
             patch.object(detector, "_get_config_path", return_value=config_dir), \
             patch.object(detector, "_check_jetbrains", return_value=None):
            result = detector.detect()

        assert result.detected is True
        assert result.metadata["models"] == ["GPT-4", "Claude"]
        assert result.metadata["has_custom_models"] is True

    def test_detect_config_with_empty_models(self, detector, tmp_path):
        """Test detection with config.json that has no models."""
        config_dir = tmp_path / ".continue"
        config_dir.mkdir(parents=True)
        config_file = config_dir / "config.json"
        config_file.write_text(json.dumps({"models": []}))

        def fake_vscode_paths():
            return [tmp_path / "nonexistent"]

        with patch.object(detector, "_get_vscode_extensions_paths", fake_vscode_paths), \
             patch.object(detector, "_get_config_path", return_value=config_dir), \
             patch.object(detector, "_check_jetbrains", return_value=None):
            result = detector.detect()

        assert result.detected is True
        assert result.metadata["models"] == []
        assert result.metadata["has_custom_models"] is False

    def test_detect_config_corrupt_json(self, detector, tmp_path):
        """Test detection handles corrupt config.json."""
        config_dir = tmp_path / ".continue"
        config_dir.mkdir(parents=True)
        config_file = config_dir / "config.json"
        config_file.write_text("NOT VALID {{{")

        def fake_vscode_paths():
            return [tmp_path / "nonexistent"]

        with patch.object(detector, "_get_vscode_extensions_paths", fake_vscode_paths), \
             patch.object(detector, "_get_config_path", return_value=config_dir), \
             patch.object(detector, "_check_jetbrains", return_value=None):
            result = detector.detect()

        assert result.detected is True
        assert "models" not in result.metadata

    # --- detect() with JetBrains plugin ---

    def test_detect_jetbrains_plugin(self, detector, tmp_path):
        """Test detection of JetBrains Continue plugin."""
        with patch.object(Path, "exists", return_value=False), \
             _patch_platform("Darwin"), \
             patch.object(detector, "_get_vscode_extensions_paths", return_value=[]), \
             patch.object(detector, "_get_config_path", return_value=tmp_path / "nonexistent"), \
             patch.object(detector, "_check_jetbrains",
                          return_value={"path": "/fake/jetbrains/continue"}):
            result = detector.detect()

        assert result.detected is True
        assert result.metadata.get("jetbrains") is True
        assert result.install_path == "/fake/jetbrains/continue"

    # --- _check_jetbrains() ---

    def test_check_jetbrains_found_macos(self, detector, tmp_path):
        """Test JetBrains plugin detection on macOS."""
        jb_dir = tmp_path / "Library" / "Application Support" / "JetBrains"
        ide_dir = jb_dir / "IntelliJIdea2024.1"
        plugins_dir = ide_dir / "plugins" / "continue"
        plugins_dir.mkdir(parents=True)

        with _patch_platform("Darwin"), \
             patch.object(Path, "home", return_value=tmp_path):
            result = detector._check_jetbrains()

        assert result is not None
        assert "continue" in result["path"]

    def test_check_jetbrains_not_found(self, detector, tmp_path):
        """Test JetBrains detection when no Continue plugin exists."""
        # JetBrains directory exists but has no Continue plugin
        jb_dir = tmp_path / "Library" / "Application Support" / "JetBrains"
        ide_dir = jb_dir / "IntelliJIdea2024.1"
        other_plugin = ide_dir / "plugins" / "other-plugin"
        other_plugin.mkdir(parents=True)

        with _patch_platform("Darwin"), \
             patch.object(Path, "home", return_value=tmp_path):
            result = detector._check_jetbrains()

        assert result is None

    def test_check_jetbrains_no_jetbrains_dir(self, detector, tmp_path):
        """Test JetBrains detection when JetBrains dir does not exist."""
        with _patch_platform("Darwin"), \
             patch.object(Path, "home", return_value=tmp_path):
            result = detector._check_jetbrains()

        assert result is None

    # --- _get_vscode_extensions_paths() ---

    def test_vscode_paths_macos(self, detector):
        """Test VS Code extension paths on macOS."""
        with _patch_platform("Darwin"):
            paths = detector._get_vscode_extensions_paths()
        assert any(".vscode" in str(p) for p in paths)
        assert any(".cursor" in str(p) for p in paths)  # Cursor compatibility

    def test_vscode_paths_linux(self, detector):
        """Test VS Code extension paths on Linux include vscode-oss."""
        with _patch_platform("Linux"):
            paths = detector._get_vscode_extensions_paths()
        assert any(".vscode-oss" in str(p) for p in paths)

    # --- get_conflicts() ---

    def test_get_conflicts_detected(self, detector):
        """Test conflicts when Continue is detected."""
        mock_result = DetectionResult(
            detected=True, tool_name="continue"
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 1
        assert "Continue.dev is installed" in conflicts[0]
        assert "config.json" in conflicts[0]

    def test_get_conflicts_not_detected(self, detector):
        """Test no conflicts when Continue is not detected."""
        mock_result = DetectionResult(
            detected=False, tool_name="continue"
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 0

    # --- get_proxy_config_instructions() ---

    def test_proxy_config_instructions(self, detector):
        """Test proxy config instructions content."""
        instructions = detector.get_proxy_config_instructions()
        assert isinstance(instructions, str)
        assert "tweek proxy start" in instructions
        assert "127.0.0.1:9877" in instructions
        assert "config.json" in instructions
        assert "requestOptions" in instructions
        assert "tweek proxy trust" in instructions

    def test_proxy_config_instructions_includes_config_path(self, detector):
        """Test that instructions include the actual config path."""
        instructions = detector.get_proxy_config_instructions()
        assert ".continue" in instructions


# =============================================================================
# OpenClawDetector Tests
# =============================================================================

class TestOpenClawDetector:
    """Tests for the OpenClaw AI personal assistant detector plugin."""

    @pytest.fixture
    def detector(self):
        return OpenClawDetector()

    # --- Basic properties ---

    def test_name(self, detector):
        """Test that detector name is 'openclaw'."""
        assert detector.name == "openclaw"

    def test_inherits_tool_detector(self, detector):
        """Test that OpenClawDetector inherits from ToolDetectorPlugin."""
        assert isinstance(detector, ToolDetectorPlugin)

    def test_class_metadata(self, detector):
        """Test class-level metadata attributes."""
        assert detector.VERSION == "1.0.0"
        assert "openclaw" in detector.TAGS

    def test_default_port(self, detector):
        """Test the default gateway port."""
        assert detector.DEFAULT_PORT == 18789

    # --- detect() when not installed ---

    def test_detect_not_installed(self, detector, tmp_path):
        """Test detect() returns not detected when nothing is found."""
        with patch("subprocess.run",
                   return_value=_make_completed_process(returncode=1, stdout="{}")), \
             patch.object(detector, "_find_config", return_value=None), \
             patch.object(Path, "home", return_value=tmp_path):
            # .openclaw directory does not exist
            result = detector.detect()

        assert result.detected is False
        assert result.tool_name == "openclaw"
        assert result.running is False

    # --- detect() with npm installation ---

    def test_detect_npm_installed(self, detector, tmp_path):
        """Test detection via npm global installation."""
        npm_output = json.dumps({
            "dependencies": {
                "openclaw": {"version": "2.1.0"}
            },
            "path": "/usr/local/lib/node_modules"
        })

        with patch.object(detector, "_check_npm_installation",
                          return_value={"version": "2.1.0", "path": "/usr/local/lib/node_modules"}), \
             patch.object(detector, "_find_config", return_value=None), \
             patch.object(Path, "home", return_value=tmp_path), \
             patch.object(detector, "_check_running_process", return_value=None):
            result = detector.detect()

        assert result.detected is True
        assert result.version == "2.1.0"
        assert result.install_path == "/usr/local/lib/node_modules"

    # --- detect() with config file ---

    def test_detect_config_file(self, detector, tmp_path):
        """Test detection via config file with gateway port."""
        config_path = tmp_path / ".openclaw" / "openclaw.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(json.dumps({
            "gateway": {"port": 19000}
        }))

        openclaw_home = tmp_path / ".openclaw"

        with patch.object(detector, "_check_npm_installation", return_value=None), \
             patch.object(detector, "_find_config", return_value=config_path), \
             patch.object(Path, "home", return_value=tmp_path), \
             patch.object(detector, "_check_running_process", return_value=None), \
             patch.object(detector, "_check_gateway_active", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.config_path == str(config_path)
        assert result.port == 19000

    def test_detect_config_file_corrupt(self, detector, tmp_path):
        """Test detection handles corrupt config file with default port."""
        config_path = tmp_path / ".openclaw" / "openclaw.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text("NOT JSON {{{")

        with patch.object(detector, "_check_npm_installation", return_value=None), \
             patch.object(detector, "_find_config", return_value=config_path), \
             patch.object(Path, "home", return_value=tmp_path), \
             patch.object(detector, "_check_running_process", return_value=None), \
             patch.object(detector, "_check_gateway_active", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.port == 18789  # DEFAULT_PORT

    # --- detect() with .openclaw home directory ---

    def test_detect_openclaw_home_dir_alone_not_detected(self, detector, tmp_path):
        """~/.openclaw/ directory alone should NOT mark as detected.

        The directory may have been created by Tweek's own protect wizard.
        A real installation requires npm/binary or config with non-Tweek content.
        """
        openclaw_home = tmp_path / ".openclaw"
        openclaw_home.mkdir(parents=True)

        with patch.object(detector, "_check_npm_installation", return_value=None), \
             patch.object(detector, "_find_config", return_value=None), \
             patch.object(Path, "home", return_value=tmp_path), \
             patch.object(detector, "_check_running_process", return_value=None):
            result = detector.detect()

        assert result.detected is False

    # --- detect() with running process ---

    def test_detect_running_process(self, detector, tmp_path):
        """Test detection when openclaw process is running."""
        with patch.object(detector, "_check_npm_installation", return_value=None), \
             patch.object(detector, "_find_config", return_value=None), \
             patch.object(Path, "home", return_value=tmp_path), \
             patch.object(detector, "_check_running_process",
                          return_value={"pid": "12345"}), \
             patch.object(detector, "_check_gateway_active", return_value=False):
            result = detector.detect()

        assert result.detected is True
        assert result.running is True
        assert result.metadata["pid"] == "12345"

    def test_detect_running_with_gateway_active(self, detector, tmp_path):
        """Test detection when process is running and gateway is active."""
        config_path = tmp_path / ".openclaw" / "openclaw.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(json.dumps({"gateway": {"port": 18789}}))

        with patch.object(detector, "_check_npm_installation", return_value=None), \
             patch.object(detector, "_find_config", return_value=config_path), \
             patch.object(Path, "home", return_value=tmp_path), \
             patch.object(detector, "_check_running_process",
                          return_value={"pid": "54321"}), \
             patch.object(detector, "_check_gateway_active", return_value=True):
            result = detector.detect()

        assert result.detected is True
        assert result.running is True
        assert result.metadata.get("gateway_active") is True

    # --- _check_npm_installation() ---

    def test_check_npm_installation_found(self, detector):
        """Test npm installation check when openclaw is installed."""
        npm_output = json.dumps({
            "dependencies": {"openclaw": {"version": "2.1.0"}},
            "path": "/usr/local/lib/node_modules"
        })
        with patch("subprocess.run",
                   return_value=_make_completed_process(returncode=0, stdout=npm_output)):
            result = detector._check_npm_installation()

        assert result is not None
        assert result["version"] == "2.1.0"
        assert result["path"] == "/usr/local/lib/node_modules"

    def test_check_npm_installation_not_found(self, detector):
        """Test npm installation check when openclaw is not installed."""
        npm_output = json.dumps({"dependencies": {}})
        with patch("subprocess.run") as mock_run:
            # First call: npm list fails
            mock_run.side_effect = [
                _make_completed_process(returncode=1, stdout=npm_output),
                _make_completed_process(returncode=1, stdout=""),  # which also fails
            ]
            result = detector._check_npm_installation()

        assert result is None

    def test_check_npm_installation_via_which(self, detector):
        """Test npm check falls back to which/where command."""
        npm_output = json.dumps({"dependencies": {}})
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                _make_completed_process(returncode=1, stdout=npm_output),  # npm list fails
                _make_completed_process(returncode=0, stdout="/usr/local/bin/openclaw\n"),  # which succeeds
            ]
            result = detector._check_npm_installation()

        assert result is not None
        assert result["path"] == "/usr/local/bin/openclaw"

    def test_check_npm_installation_timeout(self, detector):
        """Test npm check handles timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("npm", 10)):
            result = detector._check_npm_installation()

        assert result is None

    def test_check_npm_installation_npm_not_found(self, detector):
        """Test npm check handles missing npm binary."""
        with patch("subprocess.run", side_effect=FileNotFoundError):
            result = detector._check_npm_installation()

        assert result is None

    def test_check_npm_installation_invalid_json(self, detector):
        """Test npm check handles invalid JSON from npm list and falls through."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                # npm list returns success but invalid JSON
                _make_completed_process(returncode=0, stdout="NOT JSON"),
                # which/where also fails
                _make_completed_process(returncode=1, stdout=""),
            ]
            result = detector._check_npm_installation()

        assert result is None

    # --- _find_config() ---

    def test_find_config_exists(self, detector, tmp_path):
        """Test finding config when it exists."""
        config_file = tmp_path / ".openclaw" / "openclaw.json"
        config_file.parent.mkdir(parents=True)
        config_file.touch()

        with patch.object(OpenClawDetector, "CONFIG_LOCATIONS", [config_file]):
            result = detector._find_config()

        assert result == config_file

    def test_find_config_not_exists(self, detector, tmp_path):
        """Test finding config when it does not exist."""
        with patch.object(OpenClawDetector, "CONFIG_LOCATIONS",
                          [tmp_path / "nonexistent.json"]):
            result = detector._find_config()

        assert result is None

    # --- _check_running_process() ---

    def test_check_running_process_unix_found(self, detector):
        """Test process check on Unix when openclaw is running."""
        with patch("os.name", "posix"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(returncode=0, stdout="12345\n")):
            result = detector._check_running_process()

        assert result is not None
        assert result["pid"] == "12345"

    def test_check_running_process_unix_not_found(self, detector):
        """Test process check on Unix when openclaw is not running."""
        with patch("os.name", "posix"), \
             patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                _make_completed_process(returncode=1, stdout=""),  # pgrep -f openclaw
                _make_completed_process(returncode=1, stdout=""),  # pgrep -af node.*openclaw
            ]
            result = detector._check_running_process()

        assert result is None

    def test_check_running_process_unix_node_openclaw(self, detector):
        """Test process check finds node.*openclaw pattern."""
        with patch("os.name", "posix"), \
             patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                _make_completed_process(returncode=1, stdout=""),  # pgrep -f openclaw fails
                _make_completed_process(returncode=0, stdout="67890 node /usr/lib/openclaw\n"),  # node pattern matches
            ]
            result = detector._check_running_process()

        assert result is not None
        assert result.get("running") is True

    def test_check_running_process_windows(self, detector):
        """Test process check on Windows."""
        with patch("os.name", "nt"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(
                       returncode=0,
                       stdout='"node.exe","1234","Console","1","50,000 K" openclaw\n'
                   )):
            result = detector._check_running_process()

        assert result is not None
        assert result.get("running") is True

    def test_check_running_process_windows_not_found(self, detector):
        """Test process check on Windows when openclaw is not running."""
        with patch("os.name", "nt"), \
             patch("subprocess.run",
                   return_value=_make_completed_process(
                       returncode=0,
                       stdout='"node.exe","1234","Console","1","50,000 K"\n'
                   )):
            result = detector._check_running_process()

        assert result is None

    def test_check_running_process_timeout(self, detector):
        """Test process check handles timeout."""
        with patch("os.name", "posix"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("pgrep", 10)):
            result = detector._check_running_process()

        assert result is None

    def test_check_running_process_file_not_found(self, detector):
        """Test process check handles missing pgrep/tasklist binary."""
        with patch("os.name", "posix"), \
             patch("subprocess.run", side_effect=FileNotFoundError):
            result = detector._check_running_process()

        assert result is None

    # --- _check_gateway_active() ---

    def test_check_gateway_active_listening(self, detector):
        """Test gateway check when port is listening."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0

        with patch("socket.socket", return_value=mock_sock):
            assert detector._check_gateway_active(18789) is True

        mock_sock.settimeout.assert_called_once_with(1)
        mock_sock.connect_ex.assert_called_once_with(("127.0.0.1", 18789))
        mock_sock.close.assert_called_once()

    def test_check_gateway_active_not_listening(self, detector):
        """Test gateway check when port is not listening."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111  # Connection refused

        with patch("socket.socket", return_value=mock_sock):
            assert detector._check_gateway_active(18789) is False

    def test_check_gateway_active_socket_error(self, detector):
        """Test gateway check handles socket errors."""
        with patch("socket.socket", side_effect=OSError("Network error")):
            assert detector._check_gateway_active(18789) is False

    def test_check_gateway_active_custom_port(self, detector):
        """Test gateway check with custom port number."""
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0

        with patch("socket.socket", return_value=mock_sock):
            detector._check_gateway_active(19999)

        mock_sock.connect_ex.assert_called_once_with(("127.0.0.1", 19999))

    # --- get_conflicts() ---

    def test_get_conflicts_gateway_active(self, detector):
        """Test conflicts when gateway is active."""
        mock_result = DetectionResult(
            detected=True, tool_name="openclaw", running=True, port=18789,
            metadata={"gateway_active": True}
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 1
        assert "gateway is active" in conflicts[0]
        assert "18789" in conflicts[0]

    def test_get_conflicts_running_no_gateway(self, detector):
        """Test conflicts when process is running but gateway is not active."""
        mock_result = DetectionResult(
            detected=True, tool_name="openclaw", running=True,
            metadata={"gateway_active": False}
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 1
        assert "process is running" in conflicts[0]
        assert "Gateway may start" in conflicts[0]

    def test_get_conflicts_not_detected(self, detector):
        """Test no conflicts when OpenClaw is not detected."""
        mock_result = DetectionResult(
            detected=False, tool_name="openclaw", running=False,
            metadata={}
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 0

    def test_get_conflicts_detected_not_running(self, detector):
        """Test no conflicts when detected but not running and no gateway."""
        mock_result = DetectionResult(
            detected=True, tool_name="openclaw", running=False,
            metadata={"gateway_active": False}
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert len(conflicts) == 0


# =============================================================================
# Cross-Detector Tests
# =============================================================================

class TestDetectorCommon:
    """Common tests that apply to all detector plugins."""

    @pytest.fixture(params=[
        CursorDetector,
        CopilotDetector,
        WindsurfDetector,
        ContinueDetector,
        OpenClawDetector,
    ])
    def detector(self, request):
        return request.param()

    def test_all_inherit_from_base(self, detector):
        """Test that all detectors inherit from ToolDetectorPlugin."""
        assert isinstance(detector, ToolDetectorPlugin)

    def test_all_have_name(self, detector):
        """Test that all detectors have a non-empty name."""
        assert detector.name
        assert isinstance(detector.name, str)
        assert len(detector.name) > 0

    def test_detect_returns_detection_result(self, detector):
        """Test that detect() returns a DetectionResult."""
        with patch.object(Path, "exists", return_value=False), \
             patch("subprocess.run",
                   return_value=_make_completed_process(returncode=1, stdout="")), \
             patch.object(Path, "home", return_value=Path("/tmp/test_home_nonexistent")), \
             patch("os.name", "posix"):
            result = detector.detect()

        assert isinstance(result, DetectionResult)
        assert result.tool_name == detector.name

    def test_get_conflicts_returns_list(self, detector):
        """Test that get_conflicts() returns a list."""
        mock_result = DetectionResult(
            detected=False, tool_name=detector.name, running=False,
            metadata={"vscode": False, "jetbrains": False, "neovim": False, "cli": False}
        )
        with patch.object(detector, "detect", return_value=mock_result):
            conflicts = detector.get_conflicts()

        assert isinstance(conflicts, list)

    def test_configure_updates_config(self, detector):
        """Test that configure() updates internal config."""
        detector.configure({"test_key": "test_value"})
        assert detector._config.get("test_key") == "test_value"

    def test_configure_merges_config(self, detector):
        """Test that configure() merges rather than replaces."""
        detector.configure({"key1": "value1"})
        detector.configure({"key2": "value2"})
        assert detector._config.get("key1") == "value1"
        assert detector._config.get("key2") == "value2"

    def test_all_have_version(self, detector):
        """Test that all detectors have a VERSION string."""
        assert hasattr(detector, "VERSION")
        assert isinstance(detector.VERSION, str)

    def test_all_have_tags(self, detector):
        """Test that all detectors have TAGS with 'detector'."""
        assert hasattr(detector, "TAGS")
        assert "detector" in detector.TAGS

    def test_all_have_requires_license(self, detector):
        """Test that all detectors specify a license requirement."""
        assert hasattr(detector, "REQUIRES_LICENSE")
        assert detector.REQUIRES_LICENSE == "free"


# =============================================================================
# DetectionResult Data Class Tests
# =============================================================================

class TestDetectionResult:
    """Tests for the DetectionResult data class."""

    def test_default_values(self):
        """Test default values of DetectionResult."""
        result = DetectionResult(detected=False, tool_name="test")
        assert result.detected is False
        assert result.tool_name == "test"
        assert result.version is None
        assert result.install_path is None
        assert result.config_path is None
        assert result.running is False
        assert result.port is None
        assert result.metadata == {}

    def test_full_initialization(self):
        """Test full initialization of DetectionResult."""
        result = DetectionResult(
            detected=True,
            tool_name="cursor",
            version="1.0.0",
            install_path="/Applications/Cursor.app",
            config_path="/Users/test/.cursor",
            running=True,
            port=8080,
            metadata={"key": "value"},
        )
        assert result.detected is True
        assert result.tool_name == "cursor"
        assert result.version == "1.0.0"
        assert result.install_path == "/Applications/Cursor.app"
        assert result.config_path == "/Users/test/.cursor"
        assert result.running is True
        assert result.port == 8080
        assert result.metadata == {"key": "value"}

    def test_metadata_mutable(self):
        """Test that metadata dict is mutable after creation."""
        result = DetectionResult(detected=False, tool_name="test")
        result.metadata["new_key"] = "new_value"
        assert result.metadata["new_key"] == "new_value"
