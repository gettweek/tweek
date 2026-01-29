"""
Tweek Vault - Cross-platform secure credential storage.

Uses the keyring library which provides:
- macOS: Keychain
- Linux: Secret Service (GNOME Keyring, KWallet)
- Windows: Windows Credential Locker
"""

from tweek.platform import PLATFORM, Platform

# Try to use cross-platform vault first
try:
    from .cross_platform import CrossPlatformVault, get_vault, migrate_env_to_vault
    VAULT_AVAILABLE = True
    VAULT_TYPE = "cross-platform"
except ImportError:
    # Fall back to macOS-only keychain if keyring not installed
    VAULT_AVAILABLE = False
    VAULT_TYPE = None
    CrossPlatformVault = None
    get_vault = None
    migrate_env_to_vault = None

# Keep old imports for backwards compatibility on macOS
try:
    from .keychain import KeychainVault, VaultError
except ImportError:
    KeychainVault = None
    VaultError = Exception

__all__ = [
    "CrossPlatformVault",
    "KeychainVault",
    "VaultError",
    "get_vault",
    "migrate_env_to_vault",
    "VAULT_AVAILABLE",
    "VAULT_TYPE",
]
