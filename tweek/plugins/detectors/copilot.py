#!/usr/bin/env python3
"""
Tweek GitHub Copilot Detector Plugin

Detects GitHub Copilot installation:
- VS Code extension
- JetBrains plugin
- Neovim plugin
- CLI tool
"""

import os
import subprocess
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from tweek.plugins.base import ToolDetectorPlugin, DetectionResult


class CopilotDetector(ToolDetectorPlugin):
    """
    GitHub Copilot detector.

    Detects:
    - VS Code Copilot extension
    - JetBrains Copilot plugin
    - Neovim Copilot plugin
    - Copilot CLI
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Detect GitHub Copilot installations"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["detector", "copilot", "github", "ai"]

    @property
    def name(self) -> str:
        return "copilot"

    def _get_vscode_extension_paths(self) -> List[Path]:
        """Get VS Code extension paths for Copilot."""
        import platform
        system = platform.system()

        if system == "Darwin":
            base_paths = [
                Path.home() / ".vscode" / "extensions",
                Path.home() / ".vscode-insiders" / "extensions",
            ]
        elif system == "Windows":
            base_paths = [
                Path(os.environ.get("USERPROFILE", "")) / ".vscode" / "extensions",
                Path(os.environ.get("USERPROFILE", "")) / ".vscode-insiders" / "extensions",
            ]
        else:  # Linux
            base_paths = [
                Path.home() / ".vscode" / "extensions",
                Path.home() / ".vscode-insiders" / "extensions",
                Path.home() / ".vscode-server" / "extensions",
            ]

        return base_paths

    def _get_jetbrains_plugin_paths(self) -> List[Path]:
        """Get JetBrains plugin paths for Copilot."""
        import platform
        system = platform.system()

        if system == "Darwin":
            base_paths = [
                Path.home() / "Library" / "Application Support" / "JetBrains",
            ]
        elif system == "Windows":
            base_paths = [
                Path(os.environ.get("APPDATA", "")) / "JetBrains",
            ]
        else:  # Linux
            base_paths = [
                Path.home() / ".config" / "JetBrains",
                Path.home() / ".local" / "share" / "JetBrains",
            ]

        return base_paths

    def _get_neovim_plugin_paths(self) -> List[Path]:
        """Get Neovim plugin paths for Copilot."""
        import platform
        system = platform.system()

        if system == "Darwin":
            return [
                Path.home() / ".local" / "share" / "nvim" / "site" / "pack",
                Path.home() / ".config" / "nvim" / "plugged",
                Path.home() / ".vim" / "pack",
            ]
        elif system == "Windows":
            return [
                Path(os.environ.get("LOCALAPPDATA", "")) / "nvim" / "site" / "pack",
                Path(os.environ.get("LOCALAPPDATA", "")) / "nvim-data" / "site" / "pack",
            ]
        else:  # Linux
            return [
                Path.home() / ".local" / "share" / "nvim" / "site" / "pack",
                Path.home() / ".config" / "nvim" / "plugged",
                Path.home() / ".vim" / "pack",
            ]

    def _get_cli_paths(self) -> List[Path]:
        """Get Copilot CLI paths."""
        import platform
        system = platform.system()

        if system == "Darwin":
            return [
                Path("/usr/local/bin/gh-copilot"),
                Path("/opt/homebrew/bin/gh-copilot"),
                Path.home() / ".local" / "bin" / "gh-copilot",
            ]
        elif system == "Windows":
            return [
                Path(os.environ.get("PROGRAMFILES", "")) / "GitHub CLI" / "gh-copilot.exe",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "gh-copilot.exe",
            ]
        else:  # Linux
            return [
                Path("/usr/bin/gh-copilot"),
                Path("/usr/local/bin/gh-copilot"),
                Path.home() / ".local" / "bin" / "gh-copilot",
            ]

    def detect(self) -> DetectionResult:
        """
        Detect Copilot installation and status.
        """
        result = DetectionResult(
            detected=False,
            tool_name=self.name,
            metadata={
                "vscode": False,
                "jetbrains": False,
                "neovim": False,
                "cli": False,
            }
        )

        # Check VS Code extension
        for base_path in self._get_vscode_extension_paths():
            if base_path.exists():
                # Look for Copilot extension directories
                for ext_dir in base_path.glob("github.copilot*"):
                    if ext_dir.is_dir():
                        result.detected = True
                        result.metadata["vscode"] = True
                        result.install_path = str(ext_dir)

                        # Try to get version
                        package_json = ext_dir / "package.json"
                        if package_json.exists():
                            try:
                                with open(package_json) as f:
                                    data = json.load(f)
                                    result.version = data.get("version")
                            except (json.JSONDecodeError, IOError):
                                pass
                        break

        # Check JetBrains plugin
        for base_path in self._get_jetbrains_plugin_paths():
            if base_path.exists():
                for ide_dir in base_path.glob("*"):
                    if ide_dir.is_dir():
                        plugins_dir = ide_dir / "plugins" / "github-copilot"
                        if plugins_dir.exists():
                            result.detected = True
                            result.metadata["jetbrains"] = True
                            if not result.install_path:
                                result.install_path = str(plugins_dir)
                            break

        # Check Neovim plugin
        for base_path in self._get_neovim_plugin_paths():
            if base_path.exists():
                # Look for copilot.vim or copilot.lua
                copilot_dirs = list(base_path.rglob("*copilot*"))
                if copilot_dirs:
                    result.detected = True
                    result.metadata["neovim"] = True
                    if not result.install_path:
                        result.install_path = str(copilot_dirs[0])
                    break

        # Check CLI
        for cli_path in self._get_cli_paths():
            if cli_path.exists():
                result.detected = True
                result.metadata["cli"] = True
                break

        # Also check for Copilot process
        result.running = self._check_running()
        if result.running:
            result.detected = True

        return result

    def _check_running(self) -> bool:
        """Check if Copilot agent is running."""
        import platform
        system = platform.system()

        try:
            if system == "Darwin" or system == "Linux":
                proc = subprocess.run(
                    ["pgrep", "-f", "copilot"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                return proc.returncode == 0 and proc.stdout.strip() != ""

            elif system == "Windows":
                proc = subprocess.run(
                    ["tasklist", "/FI", "IMAGENAME eq copilot*", "/FO", "CSV"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                return "copilot" in proc.stdout.lower()

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return False

    def get_conflicts(self) -> List[str]:
        """Get potential conflicts with Tweek."""
        conflicts = []

        result = self.detect()
        if result.detected:
            if result.metadata.get("vscode"):
                conflicts.append(
                    "GitHub Copilot VS Code extension detected. "
                    "It communicates directly with GitHub servers. "
                    "Consider using Tweek's VS Code extension to add protection."
                )
            if result.metadata.get("jetbrains"):
                conflicts.append(
                    "GitHub Copilot JetBrains plugin detected. "
                    "Configure IDE HTTP proxy settings to route through Tweek."
                )

        return conflicts
