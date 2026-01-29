"""
Tweek Proxy - Optional LLM API security proxy.

This module provides transparent HTTPS interception for LLM API calls,
enabling security screening for any application (not just Claude Code).

Installation:
    pip install tweek[proxy]

Usage:
    tweek proxy start      # Start the proxy server
    tweek proxy stop       # Stop the proxy server
    tweek proxy trust      # Install CA certificate
    tweek proxy status     # Show proxy status

The proxy is DISABLED by default. Enable with:
    tweek proxy enable
"""

import shutil
from typing import Optional

# Check if proxy dependencies are available
PROXY_AVAILABLE = False
PROXY_MISSING_DEPS: list[str] = []

try:
    import mitmproxy
    PROXY_AVAILABLE = True
except ImportError:
    PROXY_MISSING_DEPS.append("mitmproxy")

# Detection functions for supported tools
def detect_moltbot() -> Optional[dict]:
    """Detect if moltbot is installed on the system."""
    import subprocess
    import json
    from pathlib import Path

    indicators = {
        "npm_global": False,
        "process_running": False,
        "config_exists": False,
        "gateway_port": None,
    }

    # Check for npm global installation
    try:
        result = subprocess.run(
            ["npm", "list", "-g", "moltbot", "--json"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if "dependencies" in data and "moltbot" in data.get("dependencies", {}):
                indicators["npm_global"] = True
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        pass

    # Check for running moltbot process
    try:
        result = subprocess.run(
            ["pgrep", "-f", "moltbot"],
            capture_output=True,
            timeout=5
        )
        if result.returncode == 0:
            indicators["process_running"] = True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Check for moltbot config directory
    moltbot_config = Path.home() / ".moltbot"
    if moltbot_config.exists():
        indicators["config_exists"] = True

    # Default gateway port
    indicators["gateway_port"] = 18789

    if any([indicators["npm_global"], indicators["process_running"], indicators["config_exists"]]):
        return indicators

    return None


def detect_cursor() -> Optional[dict]:
    """Detect if Cursor IDE is installed."""
    from pathlib import Path
    import platform

    system = platform.system()

    if system == "Darwin":
        cursor_app = Path("/Applications/Cursor.app")
        cursor_config = Path.home() / "Library/Application Support/Cursor"
    elif system == "Linux":
        cursor_app = Path.home() / ".local/share/applications/cursor.desktop"
        cursor_config = Path.home() / ".config/Cursor"
    else:
        return None

    if cursor_app.exists() or cursor_config.exists():
        return {
            "app_exists": cursor_app.exists(),
            "config_exists": cursor_config.exists(),
        }

    return None


def detect_continue() -> Optional[dict]:
    """Detect if Continue.dev extension is installed."""
    from pathlib import Path

    # Check VS Code extensions
    vscode_ext = Path.home() / ".vscode/extensions"
    continue_pattern = "continue.continue-*"

    if vscode_ext.exists():
        matches = list(vscode_ext.glob(continue_pattern))
        if matches:
            return {
                "extension_path": str(matches[0]),
                "version": matches[0].name.split("-")[-1] if "-" in matches[0].name else "unknown",
            }

    return None


def detect_supported_tools() -> dict:
    """Detect all supported LLM tools on the system."""
    return {
        "moltbot": detect_moltbot(),
        "cursor": detect_cursor(),
        "continue": detect_continue(),
    }


def get_proxy_status() -> dict:
    """Get current proxy status."""
    from pathlib import Path
    import yaml

    config_path = Path.home() / ".tweek" / "config.yaml"

    status = {
        "available": PROXY_AVAILABLE,
        "missing_deps": PROXY_MISSING_DEPS,
        "enabled": False,
        "running": False,
        "port": 9877,
        "ca_trusted": False,
        "detected_tools": detect_supported_tools(),
    }

    if config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            proxy_config = config.get("proxy", {})
            status["enabled"] = proxy_config.get("enabled", False)
            status["port"] = proxy_config.get("port", 9877)
        except Exception:
            pass

    # Check if proxy process is running
    if PROXY_AVAILABLE:
        try:
            import subprocess
            result = subprocess.run(
                ["pgrep", "-f", "tweek.*proxy"],
                capture_output=True,
                timeout=5
            )
            status["running"] = result.returncode == 0
        except Exception:
            pass

    # Check if CA certificate is trusted
    ca_cert = Path.home() / ".tweek" / "proxy" / "tweek-ca.pem"
    status["ca_trusted"] = ca_cert.exists()  # Simplified check

    return status


__all__ = [
    "PROXY_AVAILABLE",
    "PROXY_MISSING_DEPS",
    "detect_moltbot",
    "detect_cursor",
    "detect_continue",
    "detect_supported_tools",
    "get_proxy_status",
]
