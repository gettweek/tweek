#!/usr/bin/env python3
"""
Tweek Git Plugin Security Validation

5-layer security pipeline for validating git-installed plugins before loading:

1. Registry Listing - Plugin must exist in curated registry with verified=true
2. Signature Verification - HMAC of CHECKSUMS.sha256 validated against Tweek key
3. Checksum Verification - SHA-256 of every .py file matches CHECKSUMS.sha256
4. AST Static Analysis - Parse .py files, reject forbidden patterns
5. Base Class Enforcement - Imported class must inherit from approved base class

This module runs BEFORE any plugin code is imported or executed.
"""

import ast
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Type

logger = logging.getLogger(__name__)

# Signing key for plugin verification.
# In production, this would use asymmetric keys (Ed25519).
# The HMAC approach is simpler and sufficient for the curated model
# where Tweek controls both signing and verification.
TWEEK_SIGNING_KEY = os.environ.get(
    "TWEEK_PLUGIN_SIGNING_KEY",
    "tweek-plugin-signing-key-v1"
)

# Modules/functions that are forbidden in plugin code
FORBIDDEN_IMPORTS = frozenset({
    "subprocess",
    "os.system",
    "os.popen",
    "os.exec",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.spawn",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "ctypes",
    "multiprocessing",
})

FORBIDDEN_CALLS = frozenset({
    "eval",
    "exec",
    "compile",
    "__import__",
    "os.system",
    "os.popen",
    "os.remove",
    "os.unlink",
    "os.rmdir",
    "os.removedirs",
    "shutil.rmtree",
    "shutil.move",
})

# Modules that indicate network access
FORBIDDEN_NETWORK_IMPORTS = frozenset({
    "socket",
    "urllib",
    "urllib.request",
    "urllib.parse",
    "http.client",
    "http.server",
    "requests",
    "httpx",
    "aiohttp",
    "websockets",
    "paramiko",
    "ftplib",
    "smtplib",
    "telnetlib",
})

# Required manifest fields
REQUIRED_MANIFEST_FIELDS = {
    "name", "version", "category", "entry_point", "description",
}

VALID_CATEGORIES = {"compliance", "providers", "detectors", "screening"}

VALID_LICENSE_TIERS = {"free", "pro", "enterprise"}


class PluginSecurityError(Exception):
    """Raised when a plugin fails security validation."""
    pass


def validate_manifest(manifest_path: Path) -> Tuple[bool, Optional[dict], List[str]]:
    """
    Load and validate a tweek_plugin.json manifest.

    Args:
        manifest_path: Path to tweek_plugin.json

    Returns:
        (is_valid, manifest_dict_or_None, list_of_issues)
    """
    issues = []

    if not manifest_path.exists():
        return False, None, ["tweek_plugin.json not found"]

    try:
        with open(manifest_path) as f:
            manifest = json.load(f)
    except json.JSONDecodeError as e:
        return False, None, [f"Invalid JSON in manifest: {e}"]

    if not isinstance(manifest, dict):
        return False, None, ["Manifest must be a JSON object"]

    # Check required fields
    for field in REQUIRED_MANIFEST_FIELDS:
        if field not in manifest:
            issues.append(f"Missing required field: {field}")

    # Validate category
    category = manifest.get("category", "")
    if category not in VALID_CATEGORIES:
        issues.append(f"Invalid category '{category}'. Must be one of: {VALID_CATEGORIES}")

    # Validate license tier
    tier = manifest.get("requires_license_tier", "free")
    if tier not in VALID_LICENSE_TIERS:
        issues.append(f"Invalid license tier '{tier}'. Must be one of: {VALID_LICENSE_TIERS}")

    # Validate entry_point format (module:ClassName)
    entry_point = manifest.get("entry_point", "")
    if ":" not in entry_point:
        issues.append(f"Invalid entry_point '{entry_point}'. Must be 'module:ClassName' format")

    # Validate version format
    version = manifest.get("version", "")
    if version and not _is_valid_version(version):
        issues.append(f"Invalid version '{version}'. Must be semver (e.g., 1.2.3)")

    is_valid = len(issues) == 0
    return is_valid, manifest if is_valid else None, issues


def verify_checksums(plugin_dir: Path, expected_checksums: Dict[str, str]) -> Tuple[bool, List[str]]:
    """
    Verify SHA-256 checksums of all Python files in plugin directory.

    Args:
        plugin_dir: Path to the plugin directory
        expected_checksums: Dict mapping filename to "sha256:hexdigest"

    Returns:
        (all_valid, list_of_issues)
    """
    issues = []

    # Check all expected files exist and match
    for filename, expected_hash in expected_checksums.items():
        file_path = plugin_dir / filename
        if not file_path.exists():
            issues.append(f"Expected file missing: {filename}")
            continue

        # Parse hash format
        if expected_hash.startswith("sha256:"):
            expected_hex = expected_hash[7:]
        else:
            expected_hex = expected_hash

        # Compute actual hash
        actual_hex = _compute_file_sha256(file_path)
        if actual_hex != expected_hex:
            issues.append(f"Checksum mismatch for {filename}: expected {expected_hex[:16]}..., got {actual_hex[:16]}...")

    # Check for unexpected .py files not in checksums
    for py_file in plugin_dir.glob("*.py"):
        if py_file.name not in expected_checksums:
            issues.append(f"Unexpected Python file not in checksums: {py_file.name}")

    return len(issues) == 0, issues


def verify_checksum_signature(
    checksums_content: bytes,
    signature: str,
    signing_key: str = None,
) -> bool:
    """
    Verify HMAC signature of checksum file using Tweek's signing key.

    Args:
        checksums_content: Raw bytes of the CHECKSUMS.sha256 file
        signature: Hex-encoded HMAC signature
        signing_key: Override signing key (default: TWEEK_SIGNING_KEY)

    Returns:
        True if signature is valid
    """
    key = (signing_key or TWEEK_SIGNING_KEY).encode()
    expected_sig = hmac.new(key, checksums_content, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, signature)


def static_analyze_python_files(plugin_dir: Path) -> Tuple[bool, List[str]]:
    """
    AST-based static analysis of all Python files in a plugin directory.

    Scans for forbidden patterns:
    - Importing forbidden modules (subprocess, ctypes, etc.)
    - Calling forbidden functions (eval, exec, os.system, etc.)
    - Network access imports (socket, requests, etc.)

    Args:
        plugin_dir: Path to the plugin directory

    Returns:
        (is_safe, list_of_issues)
    """
    issues = []

    for py_file in plugin_dir.glob("**/*.py"):
        # Skip test files
        if "test" in py_file.parts:
            continue

        try:
            source = py_file.read_text()
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError as e:
            issues.append(f"{py_file.name}: Syntax error: {e}")
            continue

        file_issues = _analyze_ast(tree, py_file.name)
        issues.extend(file_issues)

    return len(issues) == 0, issues


def verify_base_class(plugin_class: Type, expected_category: str) -> Tuple[bool, str]:
    """
    Verify that a plugin class inherits from the correct Tweek base class.

    Args:
        plugin_class: The loaded plugin class
        expected_category: Category from manifest (compliance, providers, etc.)

    Returns:
        (is_valid, error_message_or_empty_string)
    """
    from tweek.plugins.base import (
        CompliancePlugin,
        LLMProviderPlugin,
        ToolDetectorPlugin,
        ScreeningPlugin,
    )

    category_base_map = {
        "compliance": CompliancePlugin,
        "providers": LLMProviderPlugin,
        "detectors": ToolDetectorPlugin,
        "screening": ScreeningPlugin,
    }

    expected_base = category_base_map.get(expected_category)
    if expected_base is None:
        return False, f"Unknown category: {expected_category}"

    if not issubclass(plugin_class, expected_base):
        return False, (
            f"Plugin class {plugin_class.__name__} does not inherit from "
            f"{expected_base.__name__} (required for category '{expected_category}')"
        )

    return True, ""


def validate_plugin_full(
    plugin_dir: Path,
    manifest: dict,
    registry_checksums: Optional[Dict[str, str]] = None,
    skip_signature: bool = False,
) -> Tuple[bool, List[str]]:
    """
    Run the full 5-layer security validation pipeline on a plugin.

    Layers:
    1. Manifest validation (format, required fields)
    2. Checksum signature verification (if not skipped)
    3. File checksum verification
    4. AST static analysis
    5. (Base class enforcement happens after import in discovery module)

    Args:
        plugin_dir: Path to the plugin directory
        manifest: Parsed manifest dict
        registry_checksums: Checksums from the registry for this version
        skip_signature: Skip signature verification (for development)

    Returns:
        (is_safe, list_of_all_issues)
    """
    all_issues = []

    # Layer 1: Manifest validation (already done before calling this)
    # Just verify category is valid
    if manifest.get("category") not in VALID_CATEGORIES:
        all_issues.append(f"Invalid category: {manifest.get('category')}")

    # Layer 2: Checksum signature verification
    if not skip_signature:
        checksums_file = plugin_dir / "CHECKSUMS.sha256"
        if checksums_file.exists():
            signature = manifest.get("checksum_signature", "")
            if not signature:
                all_issues.append("Missing checksum_signature in manifest")
            else:
                content = checksums_file.read_bytes()
                if not verify_checksum_signature(content, signature):
                    all_issues.append("Checksum signature verification failed - plugin may be tampered")
        else:
            all_issues.append("CHECKSUMS.sha256 file missing")

    # Layer 3: File checksum verification
    if registry_checksums:
        valid, checksum_issues = verify_checksums(plugin_dir, registry_checksums)
        all_issues.extend(checksum_issues)

    # Layer 4: AST static analysis
    safe, ast_issues = static_analyze_python_files(plugin_dir)
    all_issues.extend(ast_issues)

    is_safe = len(all_issues) == 0

    if not is_safe:
        logger.warning(
            f"Plugin {manifest.get('name', 'unknown')} failed security validation: "
            f"{len(all_issues)} issue(s) found"
        )
        for issue in all_issues:
            logger.warning(f"  - {issue}")

    return is_safe, all_issues


# =============================================================================
# INTERNAL HELPERS
# =============================================================================

def _compute_file_sha256(file_path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _is_valid_version(version: str) -> bool:
    """Check if version string is valid semver-like format."""
    parts = version.split(".")
    if len(parts) < 2 or len(parts) > 3:
        return False
    try:
        for part in parts:
            int(part)
        return True
    except ValueError:
        return False


def _analyze_ast(tree: ast.AST, filename: str) -> List[str]:
    """
    Walk an AST tree and find forbidden patterns.

    Returns list of issues found.
    """
    issues = []

    for node in ast.walk(tree):
        # Check imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                module_name = alias.name
                if module_name in FORBIDDEN_IMPORTS or module_name in FORBIDDEN_NETWORK_IMPORTS:
                    issues.append(
                        f"{filename}:{node.lineno}: Forbidden import '{module_name}'"
                    )

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module in FORBIDDEN_IMPORTS or module in FORBIDDEN_NETWORK_IMPORTS:
                issues.append(
                    f"{filename}:{node.lineno}: Forbidden import from '{module}'"
                )
            # Check for partial matches (e.g., "from os import system")
            for alias in (node.names or []):
                full_name = f"{module}.{alias.name}" if module else alias.name
                if full_name in FORBIDDEN_IMPORTS or full_name in FORBIDDEN_CALLS:
                    issues.append(
                        f"{filename}:{node.lineno}: Forbidden import '{full_name}'"
                    )

        # Check function calls
        elif isinstance(node, ast.Call):
            call_name = _get_call_name(node)
            if call_name in FORBIDDEN_CALLS:
                issues.append(
                    f"{filename}:{node.lineno}: Forbidden call to '{call_name}'"
                )

    return issues


def _get_call_name(node: ast.Call) -> str:
    """Extract the full dotted name of a function call."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def generate_checksums(plugin_dir: Path) -> Dict[str, str]:
    """
    Generate SHA-256 checksums for all Python files in a plugin directory.

    Utility function for plugin developers.

    Args:
        plugin_dir: Path to plugin directory

    Returns:
        Dict mapping filename to "sha256:hexdigest"
    """
    checksums = {}
    for py_file in sorted(plugin_dir.glob("*.py")):
        hex_digest = _compute_file_sha256(py_file)
        checksums[py_file.name] = f"sha256:{hex_digest}"
    return checksums


def sign_checksums(checksums_content: bytes, signing_key: str = None) -> str:
    """
    Sign checksum file content with Tweek's signing key.

    Utility function for registry administrators.

    Args:
        checksums_content: Raw bytes of CHECKSUMS.sha256
        signing_key: Override signing key (default: TWEEK_SIGNING_KEY)

    Returns:
        Hex-encoded HMAC signature
    """
    key = (signing_key or TWEEK_SIGNING_KEY).encode()
    return hmac.new(key, checksums_content, hashlib.sha256).hexdigest()
