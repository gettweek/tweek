#!/usr/bin/env python3
"""
Tweek Source File Integrity — Self-Trust for Own Package Files

Prevents false-positive security warnings when Tweek's hooks screen
Tweek's own source code (which naturally contains patterns like
"prompt injection", ".env", "bypass hooks", etc.).

Security model:
    - Package-relative: only files physically inside the installed
      tweek Python package are trusted.
    - Resolved paths: symlinks and ".." traversal are resolved before
      comparison, so an attacker cannot trick the check with crafted paths.
    - Read-only trust: this only skips *screening* of file content that
      Claude reads.  It does NOT allow execution, writing, or any other
      privileged action.

What IS trusted:
    - Python source (.py), YAML configs (.yaml/.yml), and Markdown (.md)
      files shipped inside the tweek package directory.

What is NOT trusted:
    - User config files (~/.tweek/*)
    - Downloaded model files (~/.tweek/models/*)
    - Any file outside the package directory, even if named similarly
    - Non-allowlisted file extensions (e.g., .onnx, .bin, .pkl)
"""

from pathlib import Path

# Resolve the tweek package root at import time.
# This file lives at tweek/security/integrity.py, so .parent.parent = tweek/
_TWEEK_PACKAGE_ROOT: Path = Path(__file__).resolve().parent.parent

# Only trust files with these extensions — never trust binary/model files
_TRUSTED_EXTENSIONS: frozenset = frozenset({
    ".py", ".yaml", ".yml", ".md", ".txt", ".json",
})


def is_trusted_tweek_file(file_path: str) -> bool:
    """Check whether a file is a verified Tweek package source file.

    A file is trusted if and only if:
    1. Its fully-resolved path is inside the tweek package directory.
    2. It has an allowlisted extension (source/config only, no binaries).
    3. The file actually exists on disk (prevents speculative path trust).

    Args:
        file_path: Absolute or relative path to check.

    Returns:
        True if the file is a Tweek source file that should skip screening.
    """
    if not file_path:
        return False

    try:
        resolved = Path(file_path).resolve()

        # Must exist — don't trust hypothetical paths
        if not resolved.is_file():
            return False

        # Must have a safe extension
        if resolved.suffix.lower() not in _TRUSTED_EXTENSIONS:
            return False

        # Must be inside the tweek package directory
        # Uses is_relative_to (Python 3.9+) for safe containment check
        if not resolved.is_relative_to(_TWEEK_PACKAGE_ROOT):
            return False

        return True

    except (OSError, ValueError, TypeError):
        return False
