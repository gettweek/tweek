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

import json
import subprocess
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
        """Create registry file if it doesn't exist."""
        self.REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not self.REGISTRY_PATH.exists():
            self.REGISTRY_PATH.write_text("{}")

    def _service_name(self, skill: str) -> str:
        """Generate Keychain service name for a skill."""
        return f"{self.SERVICE_PREFIX}.{skill}"

    def _load_registry(self) -> Dict[str, List[str]]:
        """Load the credential registry (tracks which keys exist per skill)."""
        try:
            return json.loads(self.REGISTRY_PATH.read_text())
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _save_registry(self, registry: Dict[str, List[str]]):
        """Save the credential registry."""
        self.REGISTRY_PATH.write_text(json.dumps(registry, indent=2))

    def _add_to_registry(self, skill: str, key: str):
        """Add a key to the registry."""
        registry = self._load_registry()
        if skill not in registry:
            registry[skill] = []
        if key not in registry[skill]:
            registry[skill].append(key)
        self._save_registry(registry)

    def _remove_from_registry(self, skill: str, key: str):
        """Remove a key from the registry."""
        registry = self._load_registry()
        if skill in registry and key in registry[skill]:
            registry[skill].remove(key)
            if not registry[skill]:
                del registry[skill]
        self._save_registry(registry)

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
            raise VaultError(f"Failed to store credential: {result.stderr.strip()}")

        self._add_to_registry(skill, key)
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
            return None

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
            return True

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

    def export_for_process(self, skill: str) -> str:
        """
        Generate environment variable export string for a skill.

        Returns a string like: KEY1="value1" KEY2="value2"
        Suitable for: env -i $EXPORTS python3 script.py

        Args:
            skill: Skill name

        Returns:
            Space-separated KEY="value" pairs
        """
        creds = self.get_all(skill)
        exports = []
        for key, value in creds.items():
            # Escape special characters in value
            escaped = value.replace('"', '\\"').replace('$', '\\$')
            exports.append(f'{key}="{escaped}"')
        return " ".join(exports)
