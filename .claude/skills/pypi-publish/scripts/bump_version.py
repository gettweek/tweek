#!/usr/bin/env python3
"""
Compute the next semantic version for Tweek.

Reads the current version from pyproject.toml and computes the next
version based on the bump type (patch, minor, major).

Does NOT modify any files — returns JSON for the caller to act on.

Usage:
    python3 bump_version.py                    # default: patch bump
    python3 bump_version.py --type minor       # minor bump
    python3 bump_version.py --type major       # major bump
    python3 bump_version.py --dry-run          # show without acting
"""

import json
import re
import sys
from pathlib import Path


def find_project_root() -> Path:
    """Walk up from this script to find the repo root (contains pyproject.toml)."""
    current = Path(__file__).resolve().parent
    for _ in range(10):
        if (current / "pyproject.toml").exists():
            return current
        current = current.parent
    raise FileNotFoundError("Could not find pyproject.toml in parent directories")


def read_current_version(root: Path) -> str:
    """Extract version string from pyproject.toml."""
    pyproject = root / "pyproject.toml"
    text = pyproject.read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if not match:
        raise ValueError("Could not find version in pyproject.toml")
    return match.group(1)


def bump(version: str, bump_type: str) -> str:
    """Compute the next version."""
    parts = version.split(".")
    if len(parts) != 3:
        raise ValueError(f"Expected semver x.y.z, got: {version}")

    major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])

    if bump_type == "major":
        return f"{major + 1}.0.0"
    elif bump_type == "minor":
        return f"{major}.{minor + 1}.0"
    else:  # patch
        return f"{major}.{minor}.{patch + 1}"


def main():
    bump_type = "patch"
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--type" and i < len(sys.argv) - 1:
            bump_type = sys.argv[i + 1]

    if bump_type not in ("patch", "minor", "major"):
        print(json.dumps({"error": f"Invalid bump type: {bump_type}"}))
        sys.exit(1)

    try:
        root = find_project_root()
        current = read_current_version(root)
        next_version = bump(current, bump_type)

        result = {
            "current": current,
            "next": next_version,
            "type": bump_type,
            "pyproject_path": str(root / "pyproject.toml"),
            "init_path": str(root / "tweek" / "__init__.py"),
        }
        print(json.dumps(result, indent=2))

    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)


if __name__ == "__main__":
    main()
