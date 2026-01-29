#!/usr/bin/env python3
"""
Tweek Continue.dev Detector Plugin

Detects Continue.dev VS Code/JetBrains extension:
- VS Code extension installation
- JetBrains plugin installation
- Configuration file
"""

import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from tweek.plugins.base import ToolDetectorPlugin, DetectionResult


class ContinueDetector(ToolDetectorPlugin):
    """
    Continue.dev AI extension detector.

    Detects:
    - VS Code extension installation
    - JetBrains plugin installation
    - Configuration file (~/.continue)
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Detect Continue.dev AI extension"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["detector", "continue", "vscode", "jetbrains"]

    EXTENSION_ID = "continue.continue"

    @property
    def name(self) -> str:
        return "continue"

    def _get_vscode_extensions_paths(self) -> List[Path]:
        """Get VS Code extensions paths."""
        import platform
        system = platform.system()

        paths = []

        if system == "Darwin":
            paths.extend([
                Path.home() / ".vscode" / "extensions",
                Path.home() / ".vscode-insiders" / "extensions",
                Path.home() / ".cursor" / "extensions",  # Cursor also uses VS Code extensions
            ])
        elif system == "Windows":
            import os
            userprofile = Path(os.environ.get("USERPROFILE", ""))
            paths.extend([
                userprofile / ".vscode" / "extensions",
                userprofile / ".vscode-insiders" / "extensions",
            ])
        else:  # Linux
            paths.extend([
                Path.home() / ".vscode" / "extensions",
                Path.home() / ".vscode-insiders" / "extensions",
                Path.home() / ".vscode-oss" / "extensions",
            ])

        return paths

    def _get_config_path(self) -> Path:
        """Get Continue config path."""
        return Path.home() / ".continue"

    def detect(self) -> DetectionResult:
        """
        Detect Continue.dev installation.
        """
        result = DetectionResult(
            detected=False,
            tool_name=self.name,
        )

        # Check VS Code extensions
        for ext_path in self._get_vscode_extensions_paths():
            if ext_path.exists():
                # Look for continue.continue-* directory
                for item in ext_path.iterdir():
                    if item.is_dir() and item.name.startswith("continue.continue-"):
                        result.detected = True
                        result.install_path = str(item)
                        # Extract version from directory name
                        version_part = item.name.replace("continue.continue-", "")
                        result.version = version_part
                        result.metadata["install_type"] = "vscode"
                        break
                if result.detected:
                    break

        # Check config directory
        config_path = self._get_config_path()
        if config_path.exists():
            result.detected = True
            result.config_path = str(config_path)

            # Try to read config.json for settings
            config_file = config_path / "config.json"
            if config_file.exists():
                try:
                    with open(config_file) as f:
                        config = json.load(f)
                        # Store relevant config info
                        result.metadata["models"] = [
                            m.get("title", m.get("model", "unknown"))
                            for m in config.get("models", [])
                        ]
                        result.metadata["has_custom_models"] = len(config.get("models", [])) > 0
                except (json.JSONDecodeError, IOError):
                    pass

        # Check JetBrains plugins
        jetbrains_result = self._check_jetbrains()
        if jetbrains_result:
            result.detected = True
            if not result.install_path:
                result.install_path = jetbrains_result.get("path")
            result.metadata["jetbrains"] = True

        return result

    def _check_jetbrains(self) -> Optional[Dict[str, Any]]:
        """Check for Continue in JetBrains IDEs."""
        import platform
        system = platform.system()

        # JetBrains plugin paths vary by IDE and version
        jetbrains_paths = []

        if system == "Darwin":
            library = Path.home() / "Library" / "Application Support" / "JetBrains"
            if library.exists():
                for ide_dir in library.iterdir():
                    plugins_dir = ide_dir / "plugins"
                    if plugins_dir.exists():
                        jetbrains_paths.append(plugins_dir)
        elif system == "Windows":
            import os
            appdata = Path(os.environ.get("APPDATA", ""))
            jetbrains_dir = appdata / "JetBrains"
            if jetbrains_dir.exists():
                for ide_dir in jetbrains_dir.iterdir():
                    plugins_dir = ide_dir / "plugins"
                    if plugins_dir.exists():
                        jetbrains_paths.append(plugins_dir)
        else:  # Linux
            config = Path.home() / ".config" / "JetBrains"
            if config.exists():
                for ide_dir in config.iterdir():
                    plugins_dir = ide_dir / "plugins"
                    if plugins_dir.exists():
                        jetbrains_paths.append(plugins_dir)

        # Look for Continue plugin
        for plugins_dir in jetbrains_paths:
            continue_dir = plugins_dir / "continue"
            if continue_dir.exists():
                return {"path": str(continue_dir)}

        return None

    def get_conflicts(self) -> List[str]:
        """Get potential conflicts with Tweek."""
        conflicts = []

        result = self.detect()
        if result.detected:
            conflicts.append(
                "Continue.dev is installed. It makes API calls to configured LLM providers. "
                "Configure proxy settings in Continue's config.json for protection."
            )

        return conflicts

    def get_proxy_config_instructions(self) -> str:
        """Get instructions for configuring Continue with Tweek proxy."""
        config_path = self._get_config_path() / "config.json"

        return f"""
To protect Continue.dev with Tweek proxy:

1. Start Tweek proxy:
   tweek proxy start

2. Edit Continue config at:
   {config_path}

3. Add proxy settings to your config.json:
   {{
     "requestOptions": {{
       "proxy": "http://127.0.0.1:9877"
     }},
     ...
   }}

4. Trust the Tweek CA certificate:
   tweek proxy trust

5. Restart VS Code / JetBrains IDE
"""
