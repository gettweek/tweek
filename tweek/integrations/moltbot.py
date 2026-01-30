"""
Tweek Moltbot Integration - One-command protection setup.

Detects Moltbot, configures proxy wrapping, and starts screening
all tool calls through Tweek's defense pipeline.
"""

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class MoltbotSetupResult:
    """Result of Moltbot protection setup."""
    success: bool = False
    moltbot_detected: bool = False
    moltbot_version: Optional[str] = None
    gateway_port: Optional[int] = None
    gateway_running: bool = False
    proxy_port: Optional[int] = None
    preset: str = "cautious"
    config_path: Optional[str] = None
    error: Optional[str] = None
    warnings: list = field(default_factory=list)


def detect_moltbot_installation() -> dict:
    """
    Detect Moltbot installation details.

    Returns dict with:
        installed: bool
        version: str or None
        config_path: Path or None
        gateway_port: int
        process_running: bool
        gateway_active: bool
    """
    info = {
        "installed": False,
        "version": None,
        "config_path": None,
        "gateway_port": 18789,
        "process_running": False,
        "gateway_active": False,
    }

    # Check npm global installation
    try:
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
                info["installed"] = True
                info["version"] = deps["moltbot"].get("version")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass

    # Check which/where
    if not info["installed"]:
        try:
            import os
            cmd = ["which", "moltbot"] if os.name != "nt" else ["where", "moltbot"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if proc.returncode == 0 and proc.stdout.strip():
                info["installed"] = True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # Check for config file
    config_locations = [
        Path.home() / ".moltbot" / "config.json",
        Path.home() / ".config" / "moltbot" / "config.json",
    ]
    for config_path in config_locations:
        if config_path.exists():
            info["installed"] = True
            info["config_path"] = config_path
            try:
                with open(config_path) as f:
                    config = json.load(f)
                port = config.get("gateway", {}).get("port")
                if port:
                    info["gateway_port"] = port
            except (json.JSONDecodeError, IOError):
                pass
            break

    # Check for running process
    try:
        proc = subprocess.run(
            ["pgrep", "-f", "moltbot"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            info["process_running"] = True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Check if gateway port is active
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex(("127.0.0.1", info["gateway_port"]))
            info["gateway_active"] = result == 0
    except (socket.error, OSError):
        pass

    return info


def setup_moltbot_protection(
    port: Optional[int] = None,
    preset: str = "cautious",
) -> MoltbotSetupResult:
    """
    Configure Tweek to protect Moltbot gateway.

    Args:
        port: Override Moltbot gateway port (default: auto-detect)
        preset: Security preset to apply (paranoid, cautious, trusted)

    Returns:
        MoltbotSetupResult with setup details
    """
    result = MoltbotSetupResult(preset=preset)

    # 1. Detect Moltbot
    moltbot = detect_moltbot_installation()
    result.moltbot_detected = moltbot["installed"]
    result.moltbot_version = moltbot["version"]

    if not moltbot["installed"]:
        result.error = "Moltbot not detected on this system"
        return result

    # 2. Resolve gateway port
    if port is not None:
        result.gateway_port = port
    else:
        result.gateway_port = moltbot["gateway_port"]

    result.gateway_running = moltbot["gateway_active"]

    # 3. Configure Tweek proxy
    from tweek.proxy import TWEEK_DEFAULT_PORT
    result.proxy_port = TWEEK_DEFAULT_PORT

    # Check if Tweek port is already in use by something else
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex(("127.0.0.1", TWEEK_DEFAULT_PORT)) == 0:
                result.warnings.append(
                    f"Port {TWEEK_DEFAULT_PORT} is already in use. "
                    "Tweek proxy may need a different port."
                )
    except (socket.error, OSError):
        pass

    # 4. Write config to ~/.tweek/config.yaml
    tweek_dir = Path.home() / ".tweek"
    tweek_dir.mkdir(parents=True, exist_ok=True)
    config_path = tweek_dir / "config.yaml"

    try:
        import yaml
    except ImportError:
        # Fall back to writing YAML manually if PyYAML not available
        yaml = None

    tweek_config = {}
    if config_path.exists():
        try:
            if yaml:
                with open(config_path) as f:
                    tweek_config = yaml.safe_load(f) or {}
            else:
                tweek_config = {}
        except Exception:
            tweek_config = {}

    # Set proxy configuration
    tweek_config["proxy"] = tweek_config.get("proxy", {})
    tweek_config["proxy"]["enabled"] = True
    tweek_config["proxy"]["port"] = TWEEK_DEFAULT_PORT
    tweek_config["proxy"]["moltbot"] = {
        "enabled": True,
        "gateway_port": result.gateway_port,
        "wrap_gateway": True,
    }

    # Set security preset
    tweek_config["security"] = tweek_config.get("security", {})
    tweek_config["security"]["preset"] = preset

    try:
        if yaml:
            with open(config_path, "w") as f:
                yaml.dump(tweek_config, f, default_flow_style=False)
        else:
            # Manual YAML writing as fallback
            lines = [
                "proxy:",
                f"  enabled: true",
                f"  port: {TWEEK_DEFAULT_PORT}",
                "  moltbot:",
                "    enabled: true",
                f"    gateway_port: {result.gateway_port}",
                "    wrap_gateway: true",
                "security:",
                f"  preset: {preset}",
            ]
            config_path.write_text("\n".join(lines) + "\n")

        result.config_path = str(config_path)
    except Exception as e:
        result.error = f"Failed to write config: {e}"
        return result

    # 5. Apply security preset
    try:
        from tweek.config.manager import ConfigManager
        cfg = ConfigManager()
        cfg.apply_preset(preset)
    except Exception as e:
        result.warnings.append(f"Could not apply preset: {e}")

    result.success = True
    return result
