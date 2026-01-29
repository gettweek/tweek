#!/usr/bin/env python3
"""
Tweek Plugin Lockfile Management

Manages version pinning for installed plugins via lockfiles:
- User lockfile: ~/.tweek/plugins.lock.json
- Project lockfile: .tweek/plugins.lock.json (takes precedence)

Lockfiles pin exact versions + commit SHAs + checksums for
reproducible installations across team environments.

Format:
{
    "schema_version": 1,
    "generated_at": "2026-01-29T00:00:00Z",
    "generated_by": "tweek 0.1.0",
    "plugins": {
        "tweek-plugin-cursor-detector": {
            "version": "1.2.0",
            "git_ref": "v1.2.0",
            "commit_sha": "abc123...",
            "checksums": {
                "plugin.py": "sha256:..."
            }
        }
    }
}
"""

import json
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tweek.plugins.git_registry import PLUGINS_DIR, TWEEK_HOME
from tweek.plugins.git_security import generate_checksums

logger = logging.getLogger(__name__)

# Lockfile locations
USER_LOCKFILE = TWEEK_HOME / "plugins.lock.json"
PROJECT_LOCKFILE = Path(".tweek") / "plugins.lock.json"

# Current lockfile schema version
LOCKFILE_SCHEMA_VERSION = 1


class LockfileError(Exception):
    """Raised when lockfile operations fail."""
    pass


class PluginLock:
    """Represents a single plugin's locked state."""

    def __init__(self, data: dict):
        self._data = data

    @property
    def version(self) -> str:
        return self._data.get("version", "")

    @property
    def git_ref(self) -> str:
        return self._data.get("git_ref", "")

    @property
    def commit_sha(self) -> str:
        return self._data.get("commit_sha", "")

    @property
    def checksums(self) -> Dict[str, str]:
        return self._data.get("checksums", {})

    def to_dict(self) -> dict:
        return dict(self._data)


class PluginLockfile:
    """
    Manages plugin version lockfiles.

    Supports two lockfile locations:
    - User lockfile: ~/.tweek/plugins.lock.json
    - Project lockfile: .tweek/plugins.lock.json (takes precedence)

    When a project lockfile exists, it overrides the user lockfile.
    """

    def __init__(
        self,
        user_lockfile: Optional[Path] = None,
        project_lockfile: Optional[Path] = None,
        plugins_dir: Optional[Path] = None,
    ):
        self._user_lockfile = user_lockfile or USER_LOCKFILE
        self._project_lockfile = project_lockfile or PROJECT_LOCKFILE
        self._plugins_dir = plugins_dir or PLUGINS_DIR
        self._locks: Optional[Dict[str, PluginLock]] = None

    @property
    def active_lockfile(self) -> Optional[Path]:
        """Get the active lockfile path (project takes precedence)."""
        if self._project_lockfile.exists():
            return self._project_lockfile
        if self._user_lockfile.exists():
            return self._user_lockfile
        return None

    @property
    def has_lockfile(self) -> bool:
        """Check if any lockfile exists."""
        return self.active_lockfile is not None

    def load(self) -> Dict[str, PluginLock]:
        """
        Load the active lockfile.

        Returns:
            Dict mapping plugin name to PluginLock
        """
        lockfile = self.active_lockfile
        if lockfile is None:
            return {}

        try:
            with open(lockfile) as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            raise LockfileError(f"Failed to read lockfile {lockfile}: {e}")

        schema = data.get("schema_version", 0)
        if schema != LOCKFILE_SCHEMA_VERSION:
            raise LockfileError(
                f"Unsupported lockfile schema version {schema}. "
                f"Expected {LOCKFILE_SCHEMA_VERSION}. "
                f"Regenerate with 'tweek plugins lock'."
            )

        plugins_data = data.get("plugins", {})
        self._locks = {
            name: PluginLock(lock_data)
            for name, lock_data in plugins_data.items()
        }
        return self._locks

    def get_lock(self, name: str) -> Optional[PluginLock]:
        """
        Get the lock for a specific plugin.

        Args:
            name: Plugin name

        Returns:
            PluginLock if locked, None otherwise
        """
        if self._locks is None:
            self.load()
        return self._locks.get(name) if self._locks else None

    def is_locked(self, name: str) -> bool:
        """Check if a plugin version is locked."""
        return self.get_lock(name) is not None

    def generate(
        self,
        target: str = "user",
        specific_plugins: Optional[Dict[str, str]] = None,
    ) -> Path:
        """
        Generate a lockfile from currently installed plugins.

        Args:
            target: "user" for ~/.tweek/ or "project" for .tweek/
            specific_plugins: Optional dict of {name: version} to lock.
                            If None, locks all installed plugins.

        Returns:
            Path to the generated lockfile
        """
        lockfile_path = self._user_lockfile if target == "user" else self._project_lockfile

        # Build plugin locks
        plugins_lock = {}

        if specific_plugins:
            # Lock specific plugins
            for name, version in specific_plugins.items():
                lock_data = self._build_lock_entry(name, version)
                if lock_data:
                    plugins_lock[name] = lock_data
        else:
            # Lock all installed plugins
            if self._plugins_dir.exists():
                for plugin_dir in sorted(self._plugins_dir.iterdir()):
                    if not plugin_dir.is_dir():
                        continue

                    manifest_path = plugin_dir / "tweek_plugin.json"
                    if not manifest_path.exists():
                        continue

                    try:
                        with open(manifest_path) as f:
                            manifest = json.load(f)
                        name = manifest.get("name", plugin_dir.name)
                        version = manifest.get("version", "unknown")
                        lock_data = self._build_lock_entry(name, version)
                        if lock_data:
                            plugins_lock[name] = lock_data
                    except (json.JSONDecodeError, IOError) as e:
                        logger.warning(f"Skipping {plugin_dir.name}: {e}")

        # Build lockfile
        lockfile_data = {
            "schema_version": LOCKFILE_SCHEMA_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "generated_by": self._get_tweek_version(),
            "plugins": plugins_lock,
        }

        # Write lockfile
        lockfile_path.parent.mkdir(parents=True, exist_ok=True)
        with open(lockfile_path, "w") as f:
            json.dump(lockfile_data, f, indent=2, sort_keys=True)

        logger.info(f"Generated lockfile with {len(plugins_lock)} plugin(s): {lockfile_path}")
        return lockfile_path

    def check_compliance(self) -> Tuple[bool, List[str]]:
        """
        Check if installed plugins match the lockfile.

        Returns:
            (all_compliant, list_of_violations)
        """
        if not self.has_lockfile:
            return True, []

        violations = []
        locks = self.load()

        for name, lock in locks.items():
            plugin_dir = self._plugins_dir / name
            if not plugin_dir.exists():
                violations.append(f"Locked plugin '{name}' is not installed")
                continue

            # Check version
            manifest_path = plugin_dir / "tweek_plugin.json"
            if not manifest_path.exists():
                violations.append(f"Plugin '{name}' has no manifest")
                continue

            try:
                with open(manifest_path) as f:
                    manifest = json.load(f)
            except (json.JSONDecodeError, IOError):
                violations.append(f"Plugin '{name}' has invalid manifest")
                continue

            current_version = manifest.get("version", "")
            if current_version != lock.version:
                violations.append(
                    f"Plugin '{name}' version mismatch: "
                    f"installed={current_version}, locked={lock.version}"
                )

            # Check commit SHA if available
            if lock.commit_sha:
                current_sha = self._get_git_commit(plugin_dir)
                if current_sha and current_sha != lock.commit_sha:
                    violations.append(
                        f"Plugin '{name}' commit mismatch: "
                        f"installed={current_sha[:12]}, locked={lock.commit_sha[:12]}"
                    )

            # Check checksums
            if lock.checksums:
                current_checksums = generate_checksums(plugin_dir)
                for filename, expected in lock.checksums.items():
                    actual = current_checksums.get(filename, "")
                    if actual and actual != expected:
                        violations.append(
                            f"Plugin '{name}' file '{filename}' has been modified"
                        )

        return len(violations) == 0, violations

    def _build_lock_entry(self, name: str, version: str) -> Optional[dict]:
        """Build a lock entry for a plugin."""
        plugin_dir = self._plugins_dir / name
        if not plugin_dir.exists():
            return None

        entry = {
            "version": version,
            "git_ref": f"v{version}",
        }

        # Get commit SHA
        commit = self._get_git_commit(plugin_dir)
        if commit:
            entry["commit_sha"] = commit

        # Generate checksums
        checksums = generate_checksums(plugin_dir)
        if checksums:
            entry["checksums"] = checksums

        return entry

    def _get_git_commit(self, plugin_dir: Path) -> Optional[str]:
        """Get the current git commit SHA."""
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

    @staticmethod
    def _get_tweek_version() -> str:
        """Get the current Tweek version string."""
        try:
            from tweek import __version__
            return f"tweek {__version__}"
        except ImportError:
            return "tweek unknown"
