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
import socket
from typing import Optional, Tuple
from dataclasses import dataclass

# Check if proxy dependencies are available
PROXY_AVAILABLE = False
PROXY_MISSING_DEPS: list[str] = []

try:
    import mitmproxy
    PROXY_AVAILABLE = True
except ImportError:
    PROXY_MISSING_DEPS.append("mitmproxy")


# Default ports
MOLTBOT_DEFAULT_PORT = 18789
TWEEK_DEFAULT_PORT = 9877


@dataclass
class ProxyConflict:
    """Information about a detected proxy conflict."""
    tool_name: str
    port: int
    is_running: bool
    description: str


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a port is currently in use."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            return result == 0
    except (socket.error, OSError):
        return False


def check_moltbot_gateway_running(port: int = MOLTBOT_DEFAULT_PORT) -> bool:
    """Check if moltbot's gateway is actively listening on its port."""
    return is_port_in_use(port)


def detect_proxy_conflicts() -> list[ProxyConflict]:
    """
    Detect any running proxies that might conflict with Tweek.

    Returns a list of detected conflicts with details about each.
    """
    conflicts = []

    # Check for moltbot
    moltbot_info = detect_moltbot()
    if moltbot_info:
        moltbot_port = moltbot_info.get("gateway_port", MOLTBOT_DEFAULT_PORT)
        is_running = check_moltbot_gateway_running(moltbot_port)

        if moltbot_info.get("process_running") or is_running:
            conflicts.append(ProxyConflict(
                tool_name="moltbot",
                port=moltbot_port,
                is_running=is_running,
                description="Moltbot gateway detected" +
                           (f" on port {moltbot_port}" if is_running else " (process found)")
            ))

    # Check if something else is using Tweek's default port
    if is_port_in_use(TWEEK_DEFAULT_PORT):
        conflicts.append(ProxyConflict(
            tool_name="unknown",
            port=TWEEK_DEFAULT_PORT,
            is_running=True,
            description=f"Port {TWEEK_DEFAULT_PORT} is already in use"
        ))

    return conflicts


def get_moltbot_status() -> dict:
    """
    Get detailed moltbot status including whether its gateway is running.

    Returns:
        Dict with keys: installed, running, gateway_active, port, config_path
    """
    from pathlib import Path

    moltbot_info = detect_moltbot()

    status = {
        "installed": moltbot_info is not None,
        "running": False,
        "gateway_active": False,
        "port": MOLTBOT_DEFAULT_PORT,
        "config_path": None,
    }

    if moltbot_info:
        status["running"] = moltbot_info.get("process_running", False)
        status["port"] = moltbot_info.get("gateway_port", MOLTBOT_DEFAULT_PORT)
        status["gateway_active"] = check_moltbot_gateway_running(status["port"])

        config_path = Path.home() / ".moltbot"
        if config_path.exists():
            status["config_path"] = str(config_path)

    return status


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
    "MOLTBOT_DEFAULT_PORT",
    "TWEEK_DEFAULT_PORT",
    "ProxyConflict",
    "is_port_in_use",
    "check_moltbot_gateway_running",
    "detect_proxy_conflicts",
    "get_moltbot_status",
    "detect_moltbot",
    "detect_cursor",
    "detect_continue",
    "detect_supported_tools",
    "get_proxy_status",
]
