#!/usr/bin/env python3
"""
Tweek Self-Healing Post-Tool-Use Hook Wrapper

Deployed to ~/.tweek/hooks/ at install time. This wrapper script is
referenced by settings.json instead of the package-internal hook scripts.

Behavior:
    1. Tries to import and run the real post_tool_use hook from the
       installed tweek package.
    2. If tweek has been uninstalled (ImportError), silently removes
       all tweek hooks from settings.json and allows the tool response.
    3. If the hook crashes for any other reason, allows the tool response
       (fail-open to avoid blocking the user).

This file survives `pip uninstall tweek` because it lives outside the
Python package directory. It uses ONLY stdlib imports at module level.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Self-healing: remove tweek hooks from settings.json
# ---------------------------------------------------------------------------

def _remove_tweek_hooks_from_file(settings_path: Path) -> None:
    """Remove all tweek hook entries from a single settings.json file."""
    if not settings_path.exists():
        return
    try:
        with open(settings_path) as f:
            settings = json.load(f)
    except (json.JSONDecodeError, IOError, OSError):
        return

    hooks = settings.get("hooks", {})
    if not hooks:
        return

    changed = False
    for hook_type in list(hooks.keys()):
        original = hooks[hook_type]
        filtered = []
        for hook_config in original:
            original_inner = hook_config.get("hooks", [])
            inner = [
                h for h in original_inner
                if "tweek" not in h.get("command", "").lower()
            ]
            if len(inner) != len(original_inner):
                changed = True
            if inner:
                hook_config["hooks"] = inner
                filtered.append(hook_config)
        if len(filtered) != len(original):
            changed = True
        if filtered:
            hooks[hook_type] = filtered
        else:
            del hooks[hook_type]

    if not changed:
        return

    if not hooks:
        settings.pop("hooks", None)

    try:
        with open(settings_path, "w") as f:
            json.dump(settings, f, indent=2)
    except (IOError, OSError):
        pass


def _self_heal() -> None:
    """Remove tweek hooks from all known settings.json locations and allow."""
    # Clean global settings
    _remove_tweek_hooks_from_file(
        Path("~/.claude/settings.json").expanduser()
    )
    # Clean current project settings
    _remove_tweek_hooks_from_file(
        Path.cwd() / ".claude" / "settings.json"
    )
    # Clean any recorded project scopes
    scopes_file = Path("~/.tweek/installed_scopes.json").expanduser()
    if scopes_file.exists():
        try:
            scopes = json.loads(scopes_file.read_text()) or []
            for scope_str in scopes:
                _remove_tweek_hooks_from_file(
                    Path(scope_str) / "settings.json"
                )
        except (json.JSONDecodeError, IOError, OSError):
            pass

    # Output empty JSON to allow the tool response
    print("{}")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    try:
        from tweek.hooks.post_tool_use import main as real_main
        real_main()
    except ImportError:
        _self_heal()
    except Exception:
        # Fail-open: if the hook crashes, allow the tool response
        print("{}")


if __name__ == "__main__":
    main()
