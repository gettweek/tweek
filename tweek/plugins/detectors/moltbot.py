#!/usr/bin/env python3
"""
Tweek Moltbot Detector Plugin

Detects Moltbot AI coding assistant:
- Global npm installation
- Running process
- Gateway configuration
- Potential proxy conflicts
"""

import os
import subprocess
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from tweek.plugins.base import ToolDetectorPlugin, DetectionResult


class MoltbotDetector(ToolDetectorPlugin):
    """
    Moltbot AI coding assistant detector.

    Detects:
    - npm global installation
    - Running moltbot process
    - Gateway service on default port
    - Configuration file location
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Detect Moltbot AI coding assistant"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["detector", "moltbot", "ide"]

    DEFAULT_PORT = 8080
    CONFIG_LOCATIONS = [
        Path.home() / ".moltbot" / "config.json",
        Path.home() / ".config" / "moltbot" / "config.json",
    ]

    @property
    def name(self) -> str:
        return "moltbot"

    def detect(self) -> DetectionResult:
        """
        Detect Moltbot installation and status.
        """
        result = DetectionResult(
            detected=False,
            tool_name=self.name,
        )

        # Check npm global installation
        npm_info = self._check_npm_installation()
        if npm_info:
            result.detected = True
            result.version = npm_info.get("version")
            result.install_path = npm_info.get("path")

        # Check for config file
        config_path = self._find_config()
        if config_path:
            result.detected = True
            result.config_path = str(config_path)

            # Read config for port info
            try:
                with open(config_path) as f:
                    config = json.load(f)
                    result.port = config.get("gateway", {}).get("port", self.DEFAULT_PORT)
            except (json.JSONDecodeError, IOError):
                result.port = self.DEFAULT_PORT

        # Check for running process
        process_info = self._check_running_process()
        if process_info:
            result.detected = True
            result.running = True
            result.metadata["pid"] = process_info.get("pid")
            if process_info.get("port"):
                result.port = process_info["port"]

        # Check if gateway is active
        if result.port:
            result.metadata["gateway_active"] = self._check_gateway_active(result.port)

        return result

    def _check_npm_installation(self) -> Optional[Dict[str, str]]:
        """Check if moltbot is installed via npm."""
        try:
            # Try npm list -g
            proc = subprocess.run(
                ["npm", "list", "-g", "moltbot", "--json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                data = json.loads(proc.stdout)
                deps = data.get("dependencies", {})
                if "moltbot" in deps:
                    return {
                        "version": deps["moltbot"].get("version", "unknown"),
                        "path": data.get("path", ""),
                    }
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
            pass

        # Try which/where
        try:
            proc = subprocess.run(
                ["which", "moltbot"] if os.name != "nt" else ["where", "moltbot"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return {"path": proc.stdout.strip().split("\n")[0]}
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return None

    def _find_config(self) -> Optional[Path]:
        """Find moltbot config file."""
        for path in self.CONFIG_LOCATIONS:
            if path.exists():
                return path
        return None

    def _check_running_process(self) -> Optional[Dict[str, Any]]:
        """Check if moltbot process is running."""
        try:
            if os.name == "nt":
                # Windows
                proc = subprocess.run(
                    ["tasklist", "/FI", "IMAGENAME eq node.exe", "/FO", "CSV"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                # This is a rough check - would need more sophisticated detection
                if "moltbot" in proc.stdout.lower():
                    return {"running": True}
            else:
                # Unix-like
                proc = subprocess.run(
                    ["pgrep", "-f", "moltbot"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    pids = proc.stdout.strip().split("\n")
                    return {"pid": pids[0]}

                # Also check for node process with moltbot
                proc = subprocess.run(
                    ["pgrep", "-af", "node.*moltbot"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    return {"running": True}

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return None

    def _check_gateway_active(self, port: int) -> bool:
        """Check if moltbot gateway is listening on port."""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(("127.0.0.1", port))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False

    def get_conflicts(self) -> List[str]:
        """Get potential conflicts with Tweek."""
        conflicts = []

        result = self.detect()
        if result.detected:
            if result.metadata.get("gateway_active"):
                conflicts.append(
                    f"Moltbot gateway is active on port {result.port}. "
                    "This may intercept LLM API calls before Tweek."
                )
            elif result.running:
                conflicts.append(
                    "Moltbot process is running. Gateway may start and "
                    "intercept LLM API calls."
                )

        return conflicts
