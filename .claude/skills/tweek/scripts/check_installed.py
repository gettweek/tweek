#!/usr/bin/env python3
"""
Tweek Installation Status Checker

Checks whether tweek is installed and operational on this system.
Returns structured JSON for deterministic parsing by AI assistants.

Usage:
    python3 check_installed.py              # Check status (read-only)
    python3 check_installed.py --decline     # Record that user declined install
    python3 check_installed.py --reset       # Clear the decline preference

This script uses ONLY Python stdlib — no tweek imports, no pip imports.
"""

import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


def _preferences_path():
    """Path to the preferences file stored alongside this script."""
    return Path(__file__).resolve().parent.parent / ".preferences.json"


def _load_preferences():
    """Load preferences from disk. Returns empty dict if missing/corrupt."""
    path = _preferences_path()
    if not path.is_file():
        return {}
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def _save_preferences(prefs):
    """Write preferences to disk."""
    path = _preferences_path()
    with open(path, "w") as f:
        json.dump(prefs, f, indent=2)


def decline_install():
    """Record that the user declined tweek installation."""
    prefs = _load_preferences()
    prefs["install_declined"] = True
    prefs["declined_at"] = datetime.now(timezone.utc).isoformat()
    _save_preferences(prefs)
    print(json.dumps({"action": "decline_saved", "path": str(_preferences_path())}))


def reset_preference():
    """Clear the decline preference so the offer can be made again."""
    prefs = _load_preferences()
    prefs.pop("install_declined", None)
    prefs.pop("declined_at", None)
    _save_preferences(prefs)
    print(json.dumps({"action": "preference_reset", "path": str(_preferences_path())}))


def check_installation():
    """Check tweek installation status across multiple signals."""

    result = {
        "tweek_in_path": False,
        "tweek_path": None,
        "tweek_data_dir": False,
        "hooks_registered": False,
        "hooks_detail": {
            "pre_tool_use": False,
            "post_tool_use": False,
        },
        "install_declined": False,
        "declined_at": None,
        "pip_available": False,
        "pipx_available": False,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "status": "not_installed",
        "install_command": None,
    }

    # Check user preferences
    prefs = _load_preferences()
    if prefs.get("install_declined"):
        result["install_declined"] = True
        result["declined_at"] = prefs.get("declined_at")

    # Check 1: Is tweek in PATH?
    tweek_path = shutil.which("tweek")
    if tweek_path:
        result["tweek_in_path"] = True
        result["tweek_path"] = tweek_path

    # Check 2: Does ~/.tweek/ data directory exist?
    tweek_dir = Path.home() / ".tweek"
    if tweek_dir.is_dir():
        result["tweek_data_dir"] = True

    # Check 3: Are hooks registered in ~/.claude/settings.json?
    for settings_path in [
        Path.home() / ".claude" / "settings.json",
        Path.cwd() / ".claude" / "settings.json",
    ]:
        if settings_path.is_file():
            try:
                with open(settings_path) as f:
                    settings = json.load(f)
                hooks = settings.get("hooks", {})

                pre_hooks = hooks.get("PreToolUse", [])
                for hook_group in pre_hooks:
                    for hook in hook_group.get("hooks", []):
                        cmd = hook.get("command", "")
                        if "pre_tool_use.py" in cmd and "tweek" in cmd:
                            result["hooks_detail"]["pre_tool_use"] = True

                post_hooks = hooks.get("PostToolUse", [])
                for hook_group in post_hooks:
                    for hook in hook_group.get("hooks", []):
                        cmd = hook.get("command", "")
                        if "post_tool_use.py" in cmd and "tweek" in cmd:
                            result["hooks_detail"]["post_tool_use"] = True

                if result["hooks_detail"]["pre_tool_use"] or result["hooks_detail"]["post_tool_use"]:
                    result["hooks_registered"] = True
                    break

            except (json.JSONDecodeError, IOError, KeyError):
                pass

    # Check 4: Package manager availability
    if shutil.which("pip") or shutil.which("pip3"):
        result["pip_available"] = True
    if shutil.which("pipx"):
        result["pipx_available"] = True

    # Determine overall status
    if result["tweek_in_path"] and result["hooks_registered"]:
        result["status"] = "fully_operational"
    elif result["tweek_in_path"] and not result["hooks_registered"]:
        result["status"] = "installed_no_hooks"
        result["install_command"] = "tweek install"
    elif not result["tweek_in_path"] and result["hooks_registered"]:
        result["status"] = "hooks_only"
        result["install_command"] = "pip install tweek"
    else:
        result["status"] = "not_installed"
        if result["pipx_available"]:
            result["install_command"] = "pipx install tweek && tweek install"
        elif result["pip_available"]:
            result["install_command"] = "pip install tweek && tweek install"
        else:
            result["install_command"] = "python3 -m pip install tweek && tweek install"

    return result


if __name__ == "__main__":
    if "--decline" in sys.argv:
        decline_install()
    elif "--reset" in sys.argv:
        reset_preference()
    else:
        status = check_installation()
        print(json.dumps(status, indent=2))
