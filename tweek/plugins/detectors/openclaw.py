#!/usr/bin/env python3
"""
Tweek OpenClaw Detector Plugin

Detects OpenClaw AI personal assistant:
- Global npm installation
- Running process
- Gateway configuration
- Potential proxy conflicts
"""

import json
from pathlib import Path
from typing import List, Dict, Any

from tweek.integrations.openclaw_detection import (
    OPENCLAW_CONFIG,
    OPENCLAW_DEFAULT_PORT,
    check_gateway_active,
    check_npm_installation,
    check_running_process,
)
from tweek.plugins.base import ToolDetectorPlugin, DetectionResult


class OpenClawDetector(ToolDetectorPlugin):
    """
    OpenClaw AI personal assistant detector.

    Detects:
    - npm global installation
    - Running openclaw process
    - Gateway service on default port
    - Configuration file location
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Detect OpenClaw AI personal assistant"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["detector", "openclaw", "assistant"]

    CONFIG_LOCATIONS = [
        Path.home() / ".openclaw" / "openclaw.json",
    ]

    @property
    def name(self) -> str:
        return "openclaw"

    def detect(self) -> DetectionResult:
        """Detect OpenClaw installation and status."""
        result = DetectionResult(
            detected=False,
            tool_name=self.name,
        )

        # Check npm global installation (shared detection)
        npm_info = check_npm_installation()
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
                    result.port = config.get("gateway", {}).get("port", OPENCLAW_DEFAULT_PORT)
            except (json.JSONDecodeError, IOError):
                result.port = OPENCLAW_DEFAULT_PORT

        # Check for home directory existence
        openclaw_home = Path.home() / ".openclaw"
        if openclaw_home.exists():
            result.detected = True

        # Check for running process (shared detection)
        process_info = check_running_process()
        if process_info:
            result.detected = True
            result.running = True
            result.metadata["pid"] = process_info.get("pid")
            if process_info.get("port"):
                result.port = process_info["port"]

        # Check if gateway is active (shared detection, context-managed socket)
        if result.port:
            result.metadata["gateway_active"] = check_gateway_active(result.port)

        return result

    def _find_config(self):
        """Find OpenClaw config file."""
        for path in self.CONFIG_LOCATIONS:
            if path.exists():
                return path
        return None

    def get_conflicts(self) -> List[str]:
        """Get potential conflicts with Tweek."""
        conflicts = []

        result = self.detect()
        if result.detected:
            if result.metadata.get("gateway_active"):
                conflicts.append(
                    f"OpenClaw gateway is active on port {result.port}. "
                    "Both OpenClaw and Tweek will screen tool calls; "
                    "execution order depends on plugin configuration."
                )
            elif result.running:
                conflicts.append(
                    "OpenClaw process is running. Gateway may start and "
                    "begin screening tool calls alongside Tweek."
                )

        return conflicts
