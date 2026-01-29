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

    def _log_vault_event(self, operation: str, skill: str, key: str, success: bool = True, error: str = None):
        """Log vault access to security logger (never raises)."""
        try:
            from tweek.logging.security_log import get_logger, SecurityEvent, EventType
            logger = get_logger()
            metadata = {"operation": operation, "skill": skill, "key": key, "success": success}
            if error:
                metadata["error"] = error
            logger.log(SecurityEvent(
                event_type=EventType.VAULT_ACCESS,
                tool_name="vault",
                decision="allow" if success else "error",
                decision_reason=error,
                metadata=metadata,
                source="vault",
            ))
        except Exception:
            pass

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
            self._log_vault_event("store", skill, key, success=True)
            return True
        except Exception as e:
            self._log_vault_event("store", skill, key, success=False, error=str(e))
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
            value = keyring.get_password(service, key)
            self._log_vault_event("get", skill, key, success=value is not None)
            return value
        except Exception as e:
            self._log_vault_event("get", skill, key, success=False, error=str(e))
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
            self._log_vault_event("delete", skill, key, success=True)
            return True
        except PasswordDeleteError:
            self._log_vault_event("delete", skill, key, success=False, error="not found")
            return False
        except Exception as e:
            self._log_vault_event("delete", skill, key, success=False, error=str(e))
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

    # Log migration event
    try:
        from tweek.logging.security_log import get_logger, SecurityEvent, EventType
        migrated_keys = [k for k, s in results if s]
        get_logger().log(SecurityEvent(
            event_type=EventType.VAULT_MIGRATION,
            tool_name="vault",
            decision="allow",
            metadata={
                "source_file": str(env_path),
                "skill": skill,
                "dry_run": dry_run,
                "keys_migrated": len(migrated_keys),
                "keys_failed": len(results) - len(migrated_keys),
            },
            source="vault",
        ))
    except Exception:
        pass

    return results


# Convenience function to get a vault instance
def get_vault() -> CrossPlatformVault:
    """Get a cross-platform vault instance."""
    return CrossPlatformVault()
