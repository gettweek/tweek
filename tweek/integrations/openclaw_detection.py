"""
Shared OpenClaw detection utilities.

Centralizes OpenClaw detection logic used by both the integrations module
and the detector plugin to eliminate code duplication.
"""

import json
import os
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional


# OpenClaw default paths and ports
OPENCLAW_DEFAULT_PORT = 18789
OPENCLAW_HOME = Path.home() / ".openclaw"
OPENCLAW_CONFIG = OPENCLAW_HOME / "openclaw.json"
OPENCLAW_SKILLS_DIR = OPENCLAW_HOME / "workspace" / "skills"


def check_npm_installation() -> Optional[Dict[str, str]]:
    """Check if openclaw is installed via npm.

    Returns:
        Dict with 'version' and/or 'path' keys if found, None otherwise.
    """
    # Try npm list -g
    try:
        proc = subprocess.run(
            ["npm", "list", "-g", "openclaw", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            deps = data.get("dependencies", {})
            if "openclaw" in deps:
                return {
                    "version": deps["openclaw"].get("version", "unknown"),
                    "path": data.get("path", ""),
                }
    except subprocess.TimeoutExpired:
        pass
    except json.JSONDecodeError:
        pass
    except FileNotFoundError:
        pass

    # Fallback: try which/where
    try:
        cmd = ["which", "openclaw"] if os.name != "nt" else ["where", "openclaw"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if proc.returncode == 0 and proc.stdout.strip():
            return {"path": proc.stdout.strip().split("\n")[0]}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return None


def check_running_process() -> Optional[Dict[str, Any]]:
    """Check if an openclaw process is running.

    Returns:
        Dict with process info if found, None otherwise.
        On Unix: may contain 'pid' key.
        On Windows: contains 'running': True.
    """
    try:
        if os.name == "nt":
            proc = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq node.exe", "/FO", "CSV"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if "openclaw" in proc.stdout.lower():
                return {"running": True}
        else:
            proc = subprocess.run(
                ["pgrep", "-f", "openclaw"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                pids = proc.stdout.strip().split("\n")
                return {"pid": pids[0]}

            # Also check for node process with openclaw
            proc = subprocess.run(
                ["pgrep", "-af", "node.*openclaw"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return {"running": True}

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return None


def check_gateway_active(port: int) -> bool:
    """Check if OpenClaw gateway is listening on port.

    Args:
        port: TCP port number to check.

    Returns:
        True if a service is listening on the port.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex(("127.0.0.1", port))
            return result == 0
    except (socket.error, OSError):
        return False


def read_config_port() -> Optional[int]:
    """Read the gateway port from openclaw.json config.

    Returns:
        The configured port, or None if not found.
    """
    if not OPENCLAW_CONFIG.exists():
        return None
    try:
        with open(OPENCLAW_CONFIG) as f:
            config = json.load(f)
        return config.get("gateway", {}).get("port")
    except (json.JSONDecodeError, IOError):
        return None
