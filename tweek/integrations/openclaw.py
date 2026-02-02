"""
Tweek OpenClaw Integration - Gateway security plugin setup.

Detects OpenClaw Gateway, installs the Tweek security plugin, and
configures skill scanning, tool screening, and output scanning for
the OpenClaw ecosystem.
"""

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# OpenClaw default paths and ports
OPENCLAW_DEFAULT_PORT = 18789
OPENCLAW_HOME = Path.home() / ".openclaw"
OPENCLAW_CONFIG = OPENCLAW_HOME / "openclaw.json"
OPENCLAW_SKILLS_DIR = OPENCLAW_HOME / "workspace" / "skills"
OPENCLAW_PLUGIN_NAME = "@tweek/openclaw-plugin"

# Scanning server port (separate from Tweek proxy port)
SCANNER_SERVER_PORT = 9878


@dataclass
class OpenClawSetupResult:
    """Result of OpenClaw protection setup."""
    success: bool = False
    openclaw_detected: bool = False
    openclaw_version: Optional[str] = None
    gateway_port: Optional[int] = None
    gateway_running: bool = False
    scanner_port: int = SCANNER_SERVER_PORT
    preset: str = "cautious"
    config_path: Optional[str] = None
    plugin_installed: bool = False
    error: Optional[str] = None
    warnings: list = field(default_factory=list)


def detect_openclaw_installation() -> dict:
    """
    Detect OpenClaw installation details.

    Returns dict with:
        installed: bool
        version: str or None
        config_path: Path or None
        gateway_port: int
        process_running: bool
        gateway_active: bool
        skills_dir: Path or None
    """
    info = {
        "installed": False,
        "version": None,
        "config_path": None,
        "gateway_port": OPENCLAW_DEFAULT_PORT,
        "process_running": False,
        "gateway_active": False,
        "skills_dir": None,
    }

    # Check npm global installation
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
                info["installed"] = True
                info["version"] = deps["openclaw"].get("version")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass

    # Check which/where
    if not info["installed"]:
        try:
            import os
            cmd = ["which", "openclaw"] if os.name != "nt" else ["where", "openclaw"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if proc.returncode == 0 and proc.stdout.strip():
                info["installed"] = True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # Check for OpenClaw home directory
    if OPENCLAW_HOME.exists():
        info["installed"] = True

        # Check for skills directory
        if OPENCLAW_SKILLS_DIR.exists():
            info["skills_dir"] = OPENCLAW_SKILLS_DIR

    # Check for config file and extract port
    if OPENCLAW_CONFIG.exists():
        info["config_path"] = OPENCLAW_CONFIG
        try:
            with open(OPENCLAW_CONFIG) as f:
                config = json.load(f)
            port = config.get("gateway", {}).get("port")
            if port:
                info["gateway_port"] = port
        except (json.JSONDecodeError, IOError):
            pass

    # Check for running process
    try:
        proc = subprocess.run(
            ["pgrep", "-f", "openclaw"],
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


def _check_plugin_installed() -> bool:
    """Check if the Tweek OpenClaw plugin is already installed."""
    try:
        proc = subprocess.run(
            ["openclaw", "plugins", "list", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            plugins = data.get("plugins", [])
            return any(
                p.get("name") == OPENCLAW_PLUGIN_NAME
                or p.get("name") == "tweek-security"
                for p in plugins
            )
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass
    return False


def _install_plugin() -> tuple:
    """
    Install the Tweek plugin into OpenClaw.

    Returns:
        (success: bool, error: str or None)
    """
    try:
        proc = subprocess.run(
            ["openclaw", "plugins", "install", OPENCLAW_PLUGIN_NAME],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if proc.returncode == 0:
            return True, None
        return False, f"Plugin install failed: {proc.stderr.strip()}"
    except subprocess.TimeoutExpired:
        return False, "Plugin install timed out"
    except FileNotFoundError:
        return False, "openclaw CLI not found"


def _write_openclaw_config(
    gateway_port: int,
    scanner_port: int,
    preset: str,
) -> tuple:
    """
    Write or update the Tweek plugin configuration in openclaw.json.

    Returns:
        (config_path: str or None, error: str or None)
    """
    config = {}
    if OPENCLAW_CONFIG.exists():
        try:
            with open(OPENCLAW_CONFIG) as f:
                config = json.load(f)
        except (json.JSONDecodeError, IOError):
            config = {}

    # Build preset-specific settings
    preset_configs = {
        "trusted": {
            "skillGuard": {
                "enabled": True,
                "mode": "fingerprint_only",
                "blockDangerous": False,
                "promptSuspicious": False,
            },
            "toolScreening": {
                "enabled": True,
                "llmReview": False,
            },
            "outputScanning": {
                "enabled": False,
            },
        },
        "cautious": {
            "skillGuard": {
                "enabled": True,
                "mode": "auto",
                "blockDangerous": True,
                "promptSuspicious": True,
            },
            "toolScreening": {
                "enabled": True,
                "llmReview": True,
                "tiers": {
                    "bash": "dangerous",
                    "file_write": "risky",
                    "web_fetch": "risky",
                    "mcp_tool": "default",
                },
            },
            "outputScanning": {
                "enabled": True,
                "secretDetection": True,
                "exfiltrationDetection": True,
            },
        },
        "paranoid": {
            "skillGuard": {
                "enabled": True,
                "mode": "manual",
                "blockDangerous": True,
                "promptSuspicious": True,
            },
            "toolScreening": {
                "enabled": True,
                "llmReview": True,
                "tiers": {
                    "bash": "dangerous",
                    "file_write": "dangerous",
                    "web_fetch": "dangerous",
                    "mcp_tool": "risky",
                },
            },
            "outputScanning": {
                "enabled": True,
                "secretDetection": True,
                "exfiltrationDetection": True,
            },
        },
    }

    preset_config = preset_configs.get(preset, preset_configs["cautious"])

    # Merge into existing config
    plugins = config.setdefault("plugins", {})
    entries = plugins.setdefault("entries", {})
    entries["tweek"] = {
        "enabled": True,
        "config": {
            "preset": preset,
            "scannerPort": scanner_port,
            **preset_config,
        },
    }

    try:
        OPENCLAW_HOME.mkdir(parents=True, exist_ok=True)
        with open(OPENCLAW_CONFIG, "w") as f:
            json.dump(config, f, indent=2)
        return str(OPENCLAW_CONFIG), None
    except IOError as e:
        return None, f"Failed to write config: {e}"


def setup_openclaw_protection(
    port: Optional[int] = None,
    preset: str = "cautious",
    skip_plugin_install: bool = False,
) -> OpenClawSetupResult:
    """
    Configure Tweek to protect OpenClaw Gateway.

    This is the main entry point for the Tweek-first installation path.
    Detects OpenClaw, installs the plugin, writes configuration, and
    prepares the scanning server.

    Args:
        port: Override OpenClaw gateway port (default: auto-detect)
        preset: Security preset to apply (paranoid, cautious, trusted)
        skip_plugin_install: Skip npm plugin install (for ClawHub-first path)

    Returns:
        OpenClawSetupResult with setup details
    """
    result = OpenClawSetupResult(preset=preset)

    # 1. Detect OpenClaw
    openclaw = detect_openclaw_installation()
    result.openclaw_detected = openclaw["installed"]
    result.openclaw_version = openclaw["version"]

    if not openclaw["installed"]:
        result.error = "OpenClaw not detected on this system"
        return result

    # 2. Resolve gateway port
    if port is not None:
        result.gateway_port = port
    else:
        result.gateway_port = openclaw["gateway_port"]

    result.gateway_running = openclaw["gateway_active"]

    # 3. Install plugin (unless skipped for ClawHub-first path)
    if not skip_plugin_install:
        if _check_plugin_installed():
            result.plugin_installed = True
            result.warnings.append("Tweek plugin already installed in OpenClaw")
        else:
            success, error = _install_plugin()
            if success:
                result.plugin_installed = True
            else:
                result.warnings.append(f"Plugin install: {error}")
                result.warnings.append(
                    "You can install manually: "
                    f"openclaw plugins install {OPENCLAW_PLUGIN_NAME}"
                )

    # 4. Check scanner port availability
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex(("127.0.0.1", SCANNER_SERVER_PORT)) == 0:
                result.warnings.append(
                    f"Port {SCANNER_SERVER_PORT} is already in use. "
                    "Scanner server may need a different port."
                )
    except (socket.error, OSError):
        pass

    # 5. Write OpenClaw config
    config_path, error = _write_openclaw_config(
        gateway_port=result.gateway_port,
        scanner_port=result.scanner_port,
        preset=preset,
    )
    if error:
        result.error = error
        return result
    result.config_path = config_path

    # 6. Update Tweek's own config to know about OpenClaw
    tweek_dir = Path.home() / ".tweek"
    tweek_dir.mkdir(parents=True, exist_ok=True)
    tweek_config_path = tweek_dir / "config.yaml"

    try:
        import yaml
    except ImportError:
        yaml = None

    tweek_config = {}
    if tweek_config_path.exists():
        try:
            if yaml:
                with open(tweek_config_path) as f:
                    tweek_config = yaml.safe_load(f) or {}
            else:
                tweek_config = {}
        except Exception:
            tweek_config = {}

    tweek_config["openclaw"] = {
        "enabled": True,
        "gateway_port": result.gateway_port,
        "scanner_port": result.scanner_port,
        "preset": preset,
        "plugin_installed": result.plugin_installed,
    }

    try:
        if yaml:
            with open(tweek_config_path, "w") as f:
                yaml.dump(tweek_config, f, default_flow_style=False)
        else:
            # Manual YAML writing as fallback
            existing_lines = []
            if tweek_config_path.exists():
                existing_content = tweek_config_path.read_text()
                # Remove any existing openclaw section
                in_openclaw = False
                for line in existing_content.splitlines():
                    if line.startswith("openclaw:"):
                        in_openclaw = True
                        continue
                    if in_openclaw and (line.startswith("  ") or not line.strip()):
                        continue
                    in_openclaw = False
                    existing_lines.append(line)

            openclaw_lines = [
                "openclaw:",
                "  enabled: true",
                f"  gateway_port: {result.gateway_port}",
                f"  scanner_port: {result.scanner_port}",
                f"  preset: {preset}",
                f"  plugin_installed: {'true' if result.plugin_installed else 'false'}",
            ]

            all_lines = existing_lines + openclaw_lines
            tweek_config_path.write_text("\n".join(all_lines) + "\n")
    except Exception as e:
        result.warnings.append(f"Could not update Tweek config: {e}")

    # 7. Apply security preset
    try:
        from tweek.config.manager import ConfigManager
        cfg = ConfigManager()
        cfg.apply_preset(preset)
    except Exception as e:
        result.warnings.append(f"Could not apply preset: {e}")

    result.success = True
    return result


def remove_openclaw_protection() -> dict:
    """
    Remove Tweek protection from OpenClaw.

    Reverses setup_openclaw_protection():
    1. Uninstalls the Tweek plugin from OpenClaw
    2. Removes the Tweek plugin entry from openclaw.json
    3. Removes the openclaw section from ~/.tweek/config.yaml

    Returns:
        dict with 'success', 'message', 'details', and optionally 'error'
    """
    details = []

    # 1. Uninstall the npm plugin
    if _check_plugin_installed():
        try:
            proc = subprocess.run(
                ["openclaw", "plugins", "uninstall", OPENCLAW_PLUGIN_NAME],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if proc.returncode == 0:
                details.append(f"Uninstalled {OPENCLAW_PLUGIN_NAME} plugin")
            else:
                details.append(f"Plugin uninstall returned non-zero (may already be removed)")
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Plugin uninstall timed out"}
        except FileNotFoundError:
            details.append("openclaw CLI not found, skipping plugin uninstall")
    else:
        details.append("Tweek plugin not found in OpenClaw (already removed)")

    # 2. Remove Tweek entry from openclaw.json
    if OPENCLAW_CONFIG.exists():
        try:
            with open(OPENCLAW_CONFIG) as f:
                config = json.load(f)

            plugins = config.get("plugins", {})
            entries = plugins.get("entries", {})
            if "tweek" in entries:
                del entries["tweek"]
                with open(OPENCLAW_CONFIG, "w") as f:
                    json.dump(config, f, indent=2)
                details.append(f"Removed tweek entry from {OPENCLAW_CONFIG}")
            else:
                details.append("No tweek entry found in openclaw.json")
        except (json.JSONDecodeError, IOError) as e:
            details.append(f"Could not update openclaw.json: {e}")

    # 3. Remove openclaw section from ~/.tweek/config.yaml
    tweek_config_path = Path.home() / ".tweek" / "config.yaml"
    if tweek_config_path.exists():
        try:
            import yaml
        except ImportError:
            yaml = None

        if yaml:
            try:
                with open(tweek_config_path) as f:
                    tweek_config = yaml.safe_load(f) or {}

                if "openclaw" in tweek_config:
                    del tweek_config["openclaw"]
                    with open(tweek_config_path, "w") as f:
                        yaml.dump(tweek_config, f, default_flow_style=False)
                    details.append("Removed openclaw section from ~/.tweek/config.yaml")
                else:
                    details.append("No openclaw section in ~/.tweek/config.yaml")
            except Exception as e:
                details.append(f"Could not update ~/.tweek/config.yaml: {e}")
        else:
            details.append("PyYAML not available, skipping config.yaml cleanup")

    return {
        "success": True,
        "message": "OpenClaw protection removed",
        "details": details,
    }
