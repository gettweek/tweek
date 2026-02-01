#!/usr/bin/env python3
"""
Tweek Keychain Vault

Secure credential storage using macOS Keychain via the `security` CLI.
Credentials are scoped per-skill using service names like "com.tweek.{skill}".

Usage:
    vault = KeychainVault()
    vault.store("my-skill", "API_KEY", "secret123")
    value = vault.get("my-skill", "API_KEY")
    vault.delete("my-skill", "API_KEY")
    creds = vault.list("my-skill")
"""

import fcntl
import json
import os
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict


class VaultError(Exception):
    """Error from vault operations."""
    pass


@dataclass
class Credential:
    """A stored credential."""
    skill: str
    key: str
    value: str


class KeychainVault:
    """Secure credential storage using macOS Keychain."""

    SERVICE_PREFIX = "com.tweek"
    REGISTRY_PATH = Path.home() / ".tweek" / "credential_registry.json"

    def __init__(self):
        """Initialize the vault."""
        self._ensure_registry_exists()

    def _ensure_registry_exists(self):
        """Create registry file if it doesn't exist, with secure permissions."""
        self.REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not self.REGISTRY_PATH.exists():
            self.REGISTRY_PATH.write_text("{}")
        # Harden permissions - registry reveals which skills store credentials
        try:
            import os
            os.chmod(self.REGISTRY_PATH.parent, 0o700)
            os.chmod(self.REGISTRY_PATH, 0o600)
        except OSError:
            pass

    def _service_name(self, skill: str) -> str:
        """Generate Keychain service name for a skill."""
        return f"{self.SERVICE_PREFIX}.{skill}"

    @contextmanager
    def _registry_lock(self):
        """Acquire exclusive file lock for registry read-modify-write operations."""
        lock_path = self.REGISTRY_PATH.parent / ".credential_registry.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_fd = open(lock_path, "w")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()

    def _load_registry(self) -> Dict[str, List[str]]:
        """Load the credential registry (tracks which keys exist per skill)."""
        try:
            return json.loads(self.REGISTRY_PATH.read_text())
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _save_registry(self, registry: Dict[str, List[str]]):
        """Save the credential registry atomically via temp file + rename."""
        import tempfile
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=str(self.REGISTRY_PATH.parent),
            prefix=".registry_tmp_",
            suffix=".json",
        )
        try:
            with os.fdopen(tmp_fd, "w") as f:
                json.dump(registry, f, indent=2)
            os.replace(tmp_path, str(self.REGISTRY_PATH))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _add_to_registry(self, skill: str, key: str):
        """Add a key to the registry (file-locked for concurrent access)."""
        with self._registry_lock():
            registry = self._load_registry()
            if skill not in registry:
                registry[skill] = []
            if key not in registry[skill]:
                registry[skill].append(key)
            self._save_registry(registry)

    def _remove_from_registry(self, skill: str, key: str):
        """Remove a key from the registry (file-locked for concurrent access)."""
        with self._registry_lock():
            registry = self._load_registry()
            if skill in registry and key in registry[skill]:
                registry[skill].remove(key)
                if not registry[skill]:
                    del registry[skill]
            self._save_registry(registry)

    def _audit_log(self, operation: str, skill: str, key: str, success: bool):
        """Log vault operations to security audit trail."""
        try:
            from tweek.logging.security_log import get_logger, EventType
            get_logger().log_quick(
                EventType.TOOL_INVOKED,
                "vault",
                decision="allow" if success else "block",
                decision_reason=f"Vault {operation}: skill={skill}, key={key}",
                source="vault",
                metadata={"operation": operation, "skill": skill, "key": key, "success": success},
            )
        except Exception:
            pass

    def store(self, skill: str, key: str, value: str) -> bool:
        """
        Store a credential in macOS Keychain.

        Args:
            skill: Skill name (used to scope the credential)
            key: Credential key (e.g., "API_KEY")
            value: Credential value (the secret)

        Returns:
            True if stored successfully

        Raises:
            VaultError: If storage fails
        """
        service = self._service_name(skill)

        # First try to delete existing (ignore if not found)
        subprocess.run(
            ["security", "delete-generic-password", "-s", service, "-a", key],
            capture_output=True
        )

        # Add the new password
        # Note: macOS security CLI requires -w <password> as argument.
        # Using subprocess.run with list (not shell=True) avoids shell expansion.
        result = subprocess.run(
            ["security", "add-generic-password",
             "-s", service,
             "-a", key,
             "-w", value,
             "-U"],  # Update if exists
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            self._audit_log("store", skill, key, success=False)
            raise VaultError(f"Failed to store credential: {result.stderr.strip()}")

        self._add_to_registry(skill, key)
        self._audit_log("store", skill, key, success=True)
        return True

    def get(self, skill: str, key: str) -> Optional[str]:
        """
        Retrieve a credential from macOS Keychain.

        Args:
            skill: Skill name
            key: Credential key

        Returns:
            Credential value, or None if not found
        """
        service = self._service_name(skill)

        result = subprocess.run(
            ["security", "find-generic-password",
             "-s", service,
             "-a", key,
             "-w"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            self._audit_log("get", skill, key, success=False)
            return None

        self._audit_log("get", skill, key, success=True)
        return result.stdout.strip()

    def delete(self, skill: str, key: str) -> bool:
        """
        Delete a credential from macOS Keychain.

        Args:
            skill: Skill name
            key: Credential key

        Returns:
            True if deleted, False if not found
        """
        service = self._service_name(skill)

        result = subprocess.run(
            ["security", "delete-generic-password",
             "-s", service,
             "-a", key],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            self._remove_from_registry(skill, key)
            self._audit_log("delete", skill, key, success=True)
            return True

        self._audit_log("delete", skill, key, success=False)
        return False

    def list_keys(self, skill: str) -> List[str]:
        """
        List all credential keys for a skill.

        Args:
            skill: Skill name

        Returns:
            List of credential keys
        """
        registry = self._load_registry()
        return registry.get(skill, [])

    def list_skills(self) -> List[str]:
        """
        List all skills with stored credentials.

        Returns:
            List of skill names
        """
        registry = self._load_registry()
        return list(registry.keys())

    def get_all(self, skill: str) -> Dict[str, str]:
        """
        Get all credentials for a skill.

        Args:
            skill: Skill name

        Returns:
            Dict of key -> value for all credentials
        """
        result = {}
        for key in self.list_keys(skill):
            value = self.get(skill, key)
            if value is not None:
                result[key] = value
        return result

    def migrate_from_env(self, env_path: Path, skill: str, dry_run: bool = False) -> List[str]:
        """
        Migrate credentials from a .env file to the vault.

        Args:
            env_path: Path to .env file
            skill: Skill to store credentials under
            dry_run: If True, only report what would be migrated

        Returns:
            List of keys that were (or would be) migrated
        """
        if not env_path.exists():
            raise VaultError(f"File not found: {env_path}")

        migrated = []
        content = env_path.read_text()

        for line in content.splitlines():
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Parse KEY=value
            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            # Remove quotes if present
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]

            # Skip empty values
            if not value:
                continue

            if dry_run:
                migrated.append(key)
            else:
                self.store(skill, key, value)
                migrated.append(key)

        return migrated

    def export_for_process(self, skill: str) -> Dict[str, str]:
        """
        Get credentials for a skill as a dict suitable for subprocess env.

        Returns a dict that can be passed directly to subprocess.run(env=...).
        This avoids shell escaping issues entirely by never constructing a
        shell string from credential values.

        Args:
            skill: Skill name

        Returns:
            Dict of KEY -> value for environment injection
        """
        return self.get_all(skill)
