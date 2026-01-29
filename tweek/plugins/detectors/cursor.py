#!/usr/bin/env python3
"""
Tweek Cursor Detector Plugin

Detects Cursor AI-powered IDE:
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


class CursorDetector(ToolDetectorPlugin):
    """
    Cursor IDE detector.

    Detects:
    - Application installation
    - Running Cursor process
    - Configuration and settings
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Detect Cursor AI IDE"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["detector", "cursor", "ide"]

    @property
    def name(self) -> str:
        return "cursor"

    def _get_install_paths(self) -> List[Path]:
        """Get platform-specific installation paths."""
        import platform
        system = platform.system()

        if system == "Darwin":
            return [
                Path("/Applications/Cursor.app"),
                Path.home() / "Applications" / "Cursor.app",
            ]
        elif system == "Windows":
            return [
                Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "cursor" / "Cursor.exe",
                Path(os.environ.get("PROGRAMFILES", "")) / "Cursor" / "Cursor.exe",
            ]
        else:  # Linux
            return [
                Path("/usr/bin/cursor"),
                Path("/usr/local/bin/cursor"),
                Path.home() / ".local" / "bin" / "cursor",
                Path("/opt/Cursor/cursor"),
                Path.home() / "Applications" / "cursor.AppImage",
            ]

    def _get_config_paths(self) -> List[Path]:
        """Get platform-specific config paths."""
        import platform
        system = platform.system()

        if system == "Darwin":
            return [
                Path.home() / "Library" / "Application Support" / "Cursor",
                Path.home() / ".cursor",
            ]
        elif system == "Windows":
            return [
                Path(os.environ.get("APPDATA", "")) / "Cursor",
                Path(os.environ.get("LOCALAPPDATA", "")) / "Cursor",
            ]
        else:  # Linux
            return [
                Path.home() / ".config" / "Cursor",
                Path.home() / ".cursor",
            ]

    def detect(self) -> DetectionResult:
        """
        Detect Cursor installation and status.
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
                break

        # Check if running
        result.running = self._check_running()
        if result.running:
            result.detected = True

        return result

    def _check_running(self) -> bool:
        """Check if Cursor is running."""
        import platform
        system = platform.system()

        try:
            if system == "Darwin":
                proc = subprocess.run(
                    ["pgrep", "-f", "Cursor"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                return proc.returncode == 0 and proc.stdout.strip() != ""

            elif system == "Windows":
                proc = subprocess.run(
                    ["tasklist", "/FI", "IMAGENAME eq Cursor.exe", "/FO", "CSV"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                return "Cursor.exe" in proc.stdout

            else:  # Linux
                proc = subprocess.run(
                    ["pgrep", "-f", "cursor"],
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
                "Cursor IDE is running. It makes direct API calls to LLM providers. "
                "Configure Cursor to use Tweek proxy for protection."
            )

        return conflicts

    def get_proxy_config_instructions(self) -> str:
        """Get instructions for configuring Cursor with Tweek proxy."""
        return """
To protect Cursor with Tweek proxy:

1. Start Tweek proxy:
   tweek proxy start

2. Set environment variables before starting Cursor:
   export HTTPS_PROXY=http://127.0.0.1:9877
   export HTTP_PROXY=http://127.0.0.1:9877

3. Or create a wrapper script:
   tweek proxy wrap cursor "/Applications/Cursor.app/Contents/MacOS/Cursor"

4. Trust the Tweek CA certificate:
   tweek proxy trust
"""
