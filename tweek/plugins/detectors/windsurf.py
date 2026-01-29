#!/usr/bin/env python3
"""
Tweek Windsurf Detector Plugin

Detects Windsurf AI-powered IDE (by Codeium):
- Application installation (macOS, Windows, Linux)
- Running process
- Configuration location
"""

import os
import subprocess
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from tweek.plugins.base import ToolDetectorPlugin, DetectionResult


class WindsurfDetector(ToolDetectorPlugin):
    """
    Windsurf IDE detector.

    Windsurf is an AI-powered IDE built by Codeium, featuring:
    - Deep integration with AI assistants
    - Code completion and generation
    - Multi-file editing capabilities

    Detects:
    - Application installation
    - Running Windsurf process
    - Configuration and settings
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Detect Windsurf AI IDE (by Codeium)"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["detector", "windsurf", "codeium", "ide", "ai"]

    @property
    def name(self) -> str:
        return "windsurf"

    def _get_install_paths(self) -> List[Path]:
        """Get platform-specific installation paths."""
        import platform
        system = platform.system()

        if system == "Darwin":
            return [
                Path("/Applications/Windsurf.app"),
                Path.home() / "Applications" / "Windsurf.app",
            ]
        elif system == "Windows":
            return [
                Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Windsurf" / "Windsurf.exe",
                Path(os.environ.get("PROGRAMFILES", "")) / "Windsurf" / "Windsurf.exe",
            ]
        else:  # Linux
            return [
                Path("/usr/bin/windsurf"),
                Path("/usr/local/bin/windsurf"),
                Path.home() / ".local" / "bin" / "windsurf",
                Path("/opt/Windsurf/windsurf"),
                Path.home() / "Applications" / "Windsurf.AppImage",
            ]

    def _get_config_paths(self) -> List[Path]:
        """Get platform-specific config paths."""
        import platform
        system = platform.system()

        if system == "Darwin":
            return [
                Path.home() / "Library" / "Application Support" / "Windsurf",
                Path.home() / ".windsurf",
                Path.home() / ".config" / "Windsurf",
            ]
        elif system == "Windows":
            return [
                Path(os.environ.get("APPDATA", "")) / "Windsurf",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Windsurf",
            ]
        else:  # Linux
            return [
                Path.home() / ".config" / "Windsurf",
                Path.home() / ".windsurf",
            ]

    def detect(self) -> DetectionResult:
        """
        Detect Windsurf installation and status.
        """
        result = DetectionResult(
            detected=False,
            tool_name=self.name,
        )

        # Check installation paths
        for path in self._get_install_paths():
            if path.exists():
                result.detected = True
                result.install_path = str(path)
                break

        # Check config paths
        for path in self._get_config_paths():
            if path.exists():
                result.detected = True
                result.config_path = str(path)

                # Try to get version from package.json or similar
                version_file = path / "product.json"
                if version_file.exists():
                    try:
                        with open(version_file) as f:
                            data = json.load(f)
                            result.version = data.get("version")
                    except (json.JSONDecodeError, IOError):
                        pass

                # Also check settings.json for Codeium configuration
                settings_file = path / "User" / "settings.json"
                if settings_file.exists():
                    try:
                        with open(settings_file) as f:
                            settings = json.load(f)
                            result.metadata["has_settings"] = True
                            # Check if Codeium is configured
                            if any("codeium" in k.lower() for k in settings.keys()):
                                result.metadata["codeium_configured"] = True
                    except (json.JSONDecodeError, IOError):
                        pass
                break

        # Check if running
        result.running = self._check_running()
        if result.running:
            result.detected = True

        return result

    def _check_running(self) -> bool:
        """Check if Windsurf is running."""
        import platform
        system = platform.system()

        try:
            if system == "Darwin":
                proc = subprocess.run(
                    ["pgrep", "-f", "Windsurf"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                return proc.returncode == 0 and proc.stdout.strip() != ""

            elif system == "Windows":
                proc = subprocess.run(
                    ["tasklist", "/FI", "IMAGENAME eq Windsurf.exe", "/FO", "CSV"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                return "Windsurf.exe" in proc.stdout

            else:  # Linux
                proc = subprocess.run(
                    ["pgrep", "-f", "windsurf"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                return proc.returncode == 0 and proc.stdout.strip() != ""

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return False

    def get_conflicts(self) -> List[str]:
        """Get potential conflicts with Tweek."""
        conflicts = []

        result = self.detect()
        if result.detected and result.running:
            conflicts.append(
                "Windsurf IDE is running. It makes direct API calls to Codeium servers. "
                "Configure Windsurf to use Tweek proxy for protection."
            )

        return conflicts

    def get_proxy_config_instructions(self) -> str:
        """Get instructions for configuring Windsurf with Tweek proxy."""
        return """
To protect Windsurf with Tweek proxy:

1. Start Tweek proxy:
   tweek proxy start

2. Configure Windsurf to use proxy:
   - Open Windsurf Settings (Cmd/Ctrl + ,)
   - Search for "proxy"
   - Set HTTP Proxy: http://127.0.0.1:9877
   - Enable "Proxy Support"

3. Or set environment variables before starting Windsurf:
   export HTTPS_PROXY=http://127.0.0.1:9877
   export HTTP_PROXY=http://127.0.0.1:9877

4. Trust the Tweek CA certificate:
   tweek proxy trust
"""
