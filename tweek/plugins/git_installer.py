#!/usr/bin/env python3
"""
Tweek Git Plugin Installer

Handles git-based plugin installation operations:
- Clone plugin repos from registry
- Update to latest or specific version
- Remove installed plugins
- Verify installation integrity

All git operations use subprocess.run with:
- capture_output=True (no terminal access)
- timeout=30 (prevent hangs)
- No shell=True (no injection risk)
"""

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from tweek.plugins.git_registry import (
    PLUGINS_DIR,
    TWEEK_HOME,
    PluginRegistryClient,
    RegistryEntry,
    RegistryError,
)
from tweek.plugins.git_security import (
    PluginSecurityError,
    generate_checksums,
    validate_manifest,
    validate_plugin_full,
)

logger = logging.getLogger(__name__)

# Git operation timeout in seconds
GIT_TIMEOUT = 30


class InstallError(Exception):
    """Raised when plugin installation fails."""
    pass


class GitPluginInstaller:
    """
    Installs, updates, and removes git-based plugins.

    Each plugin is cloned into ~/.tweek/plugins/{name}/
    Updates are git fetch + checkout to specific tag.
    """

    def __init__(
        self,
        registry_client: Optional[PluginRegistryClient] = None,
        plugins_dir: Optional[Path] = None,
    ):
        self._registry = registry_client or PluginRegistryClient()
        self._plugins_dir = plugins_dir or PLUGINS_DIR

    @property
    def plugins_dir(self) -> Path:
        return self._plugins_dir

    def install(
        self,
        name: str,
        version: Optional[str] = None,
        verify: bool = True,
    ) -> Tuple[bool, str]:
        """
        Install a plugin from the registry.

        Steps:
        1. Look up plugin in registry
        2. Verify it's approved (verified=True)
        3. Git clone --depth 1
        4. Checkout specific version tag
        5. Run security verification pipeline

        Args:
            name: Plugin name (e.g., "tweek-plugin-cursor-detector")
            version: Specific version to install (default: latest)
            verify: Run security verification after install

        Returns:
            (success, message)
        """
        # Look up in registry
        entry = self._registry.get_plugin(name)
        if entry is None:
            return False, f"Plugin '{name}' not found in registry or not verified"

        if entry.deprecated:
            logger.warning(f"Plugin '{name}' is deprecated")

        # Determine version
        target_version = version or entry.latest_version
        if not target_version:
            return False, f"No version available for '{name}'"

        # Check version exists in registry
        version_info = entry.get_version_info(target_version)
        if version_info is None:
            available = ", ".join(entry.versions.keys())
            return False, (
                f"Version '{target_version}' not found for '{name}'. "
                f"Available versions: {available}"
            )

        # Check if already installed
        plugin_dir = self._plugins_dir / name
        if plugin_dir.exists():
            return False, (
                f"Plugin '{name}' is already installed at {plugin_dir}. "
                f"Use 'tweek plugins update {name}' to update."
            )

        # Ensure plugins directory exists
        self._plugins_dir.mkdir(parents=True, exist_ok=True)

        # Git clone
        repo_url = entry.repo_url
        git_ref = entry.get_git_ref(target_version)

        try:
            self._git_clone(repo_url, plugin_dir, git_ref)
        except InstallError as e:
            # Clean up on failure
            if plugin_dir.exists():
                shutil.rmtree(plugin_dir, ignore_errors=True)
            return False, f"Git clone failed: {e}"

        # Verify installation
        if verify:
            try:
                checksums = entry.get_checksums(target_version)
                self._verify_installed_plugin(plugin_dir, checksums)
            except (PluginSecurityError, InstallError) as e:
                # Security check failed - remove the plugin
                shutil.rmtree(plugin_dir, ignore_errors=True)
                return False, f"Security verification failed: {e}"

        logger.info(f"Successfully installed {name} v{target_version}")
        return True, f"Installed {name} v{target_version}"

    def update(
        self,
        name: str,
        version: Optional[str] = None,
        verify: bool = True,
    ) -> Tuple[bool, str]:
        """
        Update an installed plugin.

        Steps:
        1. Verify plugin is installed
        2. Git fetch
        3. Checkout new version tag
        4. Re-run security verification

        Args:
            name: Plugin name
            version: Specific version to update to (default: latest)
            verify: Run security verification after update

        Returns:
            (success, message)
        """
        plugin_dir = self._plugins_dir / name
        if not plugin_dir.exists():
            return False, f"Plugin '{name}' is not installed"

        # Look up in registry
        entry = self._registry.get_plugin(name)
        if entry is None:
            return False, f"Plugin '{name}' not found in registry"

        # Determine target version
        target_version = version or entry.latest_version
        if not target_version:
            return False, f"No version available for '{name}'"

        # Check version exists
        version_info = entry.get_version_info(target_version)
        if version_info is None:
            return False, f"Version '{target_version}' not found for '{name}'"

        git_ref = entry.get_git_ref(target_version)

        # Read current version
        current_version = self._get_installed_version(plugin_dir)
        if current_version == target_version:
            return True, f"Plugin '{name}' is already at version {target_version}"

        try:
            self._git_fetch_checkout(plugin_dir, git_ref)
        except InstallError as e:
            return False, f"Git update failed: {e}"

        # Verify updated plugin
        if verify:
            try:
                checksums = entry.get_checksums(target_version)
                self._verify_installed_plugin(plugin_dir, checksums)
            except (PluginSecurityError, InstallError) as e:
                # Revert to previous version if possible
                if current_version:
                    old_ref = entry.get_git_ref(current_version)
                    try:
                        self._git_fetch_checkout(plugin_dir, old_ref)
                        logger.warning(f"Reverted {name} to v{current_version} after verification failure")
                    except InstallError:
                        pass
                return False, f"Security verification failed after update: {e}"

        logger.info(f"Successfully updated {name} to v{target_version}")
        return True, f"Updated {name} from v{current_version} to v{target_version}"

    def remove(self, name: str) -> Tuple[bool, str]:
        """
        Remove an installed plugin.

        Args:
            name: Plugin name

        Returns:
            (success, message)
        """
        plugin_dir = self._plugins_dir / name
        if not plugin_dir.exists():
            return False, f"Plugin '{name}' is not installed"

        try:
            shutil.rmtree(plugin_dir)
            logger.info(f"Removed plugin '{name}'")
            return True, f"Removed plugin '{name}'"
        except OSError as e:
            return False, f"Failed to remove plugin '{name}': {e}"

    def check_updates(self) -> List[Dict[str, str]]:
        """
        Check all installed plugins for available updates.

        Returns:
            List of dicts with keys: name, current_version, latest_version
        """
        updates = []

        if not self._plugins_dir.exists():
            return updates

        for plugin_dir in self._plugins_dir.iterdir():
            if not plugin_dir.is_dir():
                continue

            name = plugin_dir.name
            current = self._get_installed_version(plugin_dir)
            if not current:
                continue

            latest = self._registry.get_update_available(name, current)
            if latest:
                updates.append({
                    "name": name,
                    "current_version": current,
                    "latest_version": latest,
                })

        return updates

    def list_installed(self) -> List[Dict[str, str]]:
        """
        List all installed git plugins.

        Returns:
            List of dicts with keys: name, version, category, path
        """
        installed = []

        if not self._plugins_dir.exists():
            return installed

        for plugin_dir in self._plugins_dir.iterdir():
            if not plugin_dir.is_dir():
                continue

            manifest_path = plugin_dir / "tweek_plugin.json"
            if not manifest_path.exists():
                continue

            try:
                with open(manifest_path) as f:
                    manifest = json.load(f)

                installed.append({
                    "name": manifest.get("name", plugin_dir.name),
                    "version": manifest.get("version", "unknown"),
                    "category": manifest.get("category", "unknown"),
                    "path": str(plugin_dir),
                })
            except (json.JSONDecodeError, IOError):
                installed.append({
                    "name": plugin_dir.name,
                    "version": "unknown",
                    "category": "unknown",
                    "path": str(plugin_dir),
                })

        return installed

    def verify_plugin(self, name: str) -> Tuple[bool, List[str]]:
        """
        Verify the integrity of an installed plugin.

        Args:
            name: Plugin name

        Returns:
            (is_valid, list_of_issues)
        """
        plugin_dir = self._plugins_dir / name
        if not plugin_dir.exists():
            return False, [f"Plugin '{name}' is not installed"]

        manifest_path = plugin_dir / "tweek_plugin.json"
        valid, manifest, issues = validate_manifest(manifest_path)
        if not valid:
            return False, issues

        # Get checksums from registry
        entry = self._registry.get_plugin(name)
        checksums = {}
        if entry:
            version = manifest.get("version", "")
            checksums = entry.get_checksums(version)

        return validate_plugin_full(
            plugin_dir,
            manifest,
            registry_checksums=checksums,
            skip_signature=False,
        )

    def verify_all(self) -> Dict[str, Tuple[bool, List[str]]]:
        """
        Verify integrity of all installed plugins.

        Returns:
            Dict mapping plugin name to (is_valid, issues)
        """
        results = {}

        if not self._plugins_dir.exists():
            return results

        for plugin_dir in self._plugins_dir.iterdir():
            if not plugin_dir.is_dir():
                continue
            name = plugin_dir.name
            results[name] = self.verify_plugin(name)

        return results

    # =========================================================================
    # INTERNAL HELPERS
    # =========================================================================

    def _git_clone(self, repo_url: str, target_dir: Path, git_ref: str) -> None:
        """
        Clone a git repository.

        Uses --depth 1 for shallow clone and checks out specific ref.
        """
        # Clone with depth 1
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", git_ref, repo_url, str(target_dir)],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
        )

        if result.returncode != 0:
            # Try cloning without --branch (ref might not be a branch/tag)
            result2 = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(target_dir)],
                capture_output=True,
                text=True,
                timeout=GIT_TIMEOUT,
            )

            if result2.returncode != 0:
                raise InstallError(
                    f"git clone failed: {result2.stderr.strip() or result.stderr.strip()}"
                )

            # Fetch and checkout the specific ref
            self._git_fetch_checkout(target_dir, git_ref)

    def _git_fetch_checkout(self, plugin_dir: Path, git_ref: str) -> None:
        """
        Fetch latest changes and checkout a specific ref.
        """
        # Fetch all tags
        result = subprocess.run(
            ["git", "fetch", "--tags", "--depth", "1"],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
            cwd=str(plugin_dir),
        )

        if result.returncode != 0:
            raise InstallError(f"git fetch failed: {result.stderr.strip()}")

        # Checkout the ref
        result = subprocess.run(
            ["git", "checkout", git_ref],
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT,
            cwd=str(plugin_dir),
        )

        if result.returncode != 0:
            raise InstallError(f"git checkout {git_ref} failed: {result.stderr.strip()}")

    def _get_installed_version(self, plugin_dir: Path) -> Optional[str]:
        """Get the version of an installed plugin from its manifest."""
        manifest_path = plugin_dir / "tweek_plugin.json"
        if not manifest_path.exists():
            return None

        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
            return manifest.get("version")
        except (json.JSONDecodeError, IOError):
            return None

    def _verify_installed_plugin(
        self,
        plugin_dir: Path,
        registry_checksums: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Run security verification on an installed plugin.

        Raises:
            PluginSecurityError: If verification fails
            InstallError: If manifest is invalid
        """
        manifest_path = plugin_dir / "tweek_plugin.json"
        valid, manifest, issues = validate_manifest(manifest_path)
        if not valid:
            raise InstallError(
                f"Invalid manifest: {'; '.join(issues)}"
            )

        is_safe, security_issues = validate_plugin_full(
            plugin_dir,
            manifest,
            registry_checksums=registry_checksums,
            skip_signature=False,
        )

        if not is_safe:
            raise PluginSecurityError(
                f"Plugin failed security validation: {'; '.join(security_issues)}"
            )

    def _get_git_commit(self, plugin_dir: Path) -> Optional[str]:
        """Get the current git commit SHA of an installed plugin."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=5,
                cwd=str(plugin_dir),
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return None
