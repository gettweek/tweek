"""
Cross-platform vault using the keyring library.

Backends by platform:
- macOS: Keychain
- Linux: Secret Service (GNOME Keyring, KWallet, KeePassXC)
- Windows: Windows Credential Locker

This replaces the macOS-specific keychain.py with a single implementation
that works across all platforms.
"""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    import keyring
    from keyring.errors import PasswordDeleteError
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

from tweek.platform import PLATFORM, Platform, get_vault_backend


# Service name prefix for all Tweek credentials
SERVICE_PREFIX = "tweek"


@dataclass
class StoredCredential:
    """A credential stored in the vault."""
    skill: str
    key: str
    value: str


class CrossPlatformVault:
    """
    Cross-platform credential vault using keyring.

    Credentials are stored with service name format: "tweek.{skill}"
    This groups credentials by skill while keeping them accessible.
    """

    def __init__(self):
        if not KEYRING_AVAILABLE:
            raise RuntimeError(
                "keyring library not installed. "
                "Install with: pip install keyring"
            )
        self.backend_name = get_vault_backend()

    def _service_name(self, skill: str) -> str:
        """Generate service name for a skill."""
        return f"{SERVICE_PREFIX}.{skill}"

    def store(self, skill: str, key: str, value: str) -> bool:
        """
        Store a credential in the vault.

        Args:
            skill: The skill/application this credential belongs to
            key: The credential key (e.g., "API_KEY", "PASSWORD")
            value: The secret value

        Returns:
            True if successful
        """
        try:
            service = self._service_name(skill)
            keyring.set_password(service, key, value)
            return True
        except Exception as e:
            print(f"Failed to store credential: {e}")
            return False

    def get(self, skill: str, key: str) -> Optional[str]:
        """
        Retrieve a credential from the vault.

        Args:
            skill: The skill/application this credential belongs to
            key: The credential key

        Returns:
            The secret value, or None if not found
        """
        try:
            service = self._service_name(skill)
            return keyring.get_password(service, key)
        except Exception:
            return None

    def delete(self, skill: str, key: str) -> bool:
        """
        Delete a credential from the vault.

        Args:
            skill: The skill/application this credential belongs to
            key: The credential key

        Returns:
            True if deleted, False if not found or error
        """
        try:
            service = self._service_name(skill)
            keyring.delete_password(service, key)
            return True
        except PasswordDeleteError:
            return False
        except Exception:
            return False

    def list_keys(self, skill: str) -> list[str]:
        """
        List all credential keys for a skill.

        Note: keyring doesn't have a native list function, so this
        requires platform-specific implementations or tracking keys
        separately. For now, returns empty list.

        Consider storing a metadata key that tracks all keys for a skill.
        """
        # keyring doesn't support listing - would need platform-specific code
        # or maintain a separate index
        return []

    def get_all(self, skill: str) -> dict[str, str]:
        """
        Get all credentials for a skill as a dictionary.

        Note: Limited by keyring's lack of list functionality.
        """
        # Would need to track keys separately
        return {}

    def export_for_process(self, skill: str, keys: list[str]) -> dict[str, str]:
        """
        Export specific credentials as environment variables.

        Args:
            skill: The skill to export credentials from
            keys: List of credential keys to export

        Returns:
            Dictionary of key=value pairs for environment
        """
        env = {}
        for key in keys:
            value = self.get(skill, key)
            if value:
                env[key] = value
        return env


def migrate_env_to_vault(
    env_path: Path,
    skill: str,
    vault: CrossPlatformVault,
    dry_run: bool = False
) -> list[tuple[str, bool]]:
    """
    Migrate credentials from a .env file to the vault.

    Args:
        env_path: Path to the .env file
        skill: Skill name to store credentials under
        vault: Vault instance
        dry_run: If True, don't actually store, just report

    Returns:
        List of (key, success) tuples
    """
    if not env_path.exists():
        return []

    results = []
    env_pattern = re.compile(r'^([A-Z][A-Z0-9_]*)\s*=\s*["\']?(.+?)["\']?\s*$')

    with open(env_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            match = env_pattern.match(line)
            if match:
                key, value = match.groups()
                if dry_run:
                    results.append((key, True))
                else:
                    success = vault.store(skill, key, value)
                    results.append((key, success))

    return results


# Convenience function to get a vault instance
def get_vault() -> CrossPlatformVault:
    """Get a cross-platform vault instance."""
    return CrossPlatformVault()
