"""
Platform detection and cross-platform support for Tweek.

Tweek supports:
- macOS: Full support (Keychain via keyring, sandbox-exec)
- Linux: Full support (Secret Service via keyring, firejail optional)
- Windows: Partial support (Credential Locker via keyring, no sandbox)
"""
from __future__ import annotations

import platform
import shutil
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Platform(Enum):
    """Supported platforms."""
    MACOS = "Darwin"
    LINUX = "Linux"
    WINDOWS = "Windows"
    UNKNOWN = "Unknown"


@dataclass
class PlatformCapabilities:
    """Capabilities available on the current platform."""
    platform: Platform
    vault_available: bool
    vault_backend: str
    sandbox_available: bool
    sandbox_tool: Optional[str]
    sandbox_install_hint: Optional[str]


# Detect current platform
PLATFORM_NAME = platform.system()

if PLATFORM_NAME == "Darwin":
    PLATFORM = Platform.MACOS
elif PLATFORM_NAME == "Linux":
    PLATFORM = Platform.LINUX
elif PLATFORM_NAME == "Windows":
    PLATFORM = Platform.WINDOWS
else:
    PLATFORM = Platform.UNKNOWN

IS_MACOS = PLATFORM == Platform.MACOS
IS_LINUX = PLATFORM == Platform.LINUX
IS_WINDOWS = PLATFORM == Platform.WINDOWS


def get_sandbox_tool() -> Optional[str]:
    """Detect available sandbox tool."""
    if IS_MACOS:
        if shutil.which("sandbox-exec"):
            return "sandbox-exec"
    elif IS_LINUX:
        if shutil.which("firejail"):
            return "firejail"
        elif shutil.which("bwrap"):
            return "bubblewrap"
    return None


def get_sandbox_install_hint() -> Optional[str]:
    """Get installation hint for sandbox tool."""
    if IS_MACOS:
        return None  # sandbox-exec is always available
    elif IS_LINUX:
        # Detect package manager
        if shutil.which("apt"):
            return "sudo apt install firejail"
        elif shutil.which("dnf"):
            return "sudo dnf install firejail"
        elif shutil.which("pacman"):
            return "sudo pacman -S firejail"
        elif shutil.which("zypper"):
            return "sudo zypper install firejail"
        elif shutil.which("apk"):
            return "sudo apk add firejail"
        else:
            return "Install firejail from https://firejail.wordpress.com/download-2/"
    elif IS_WINDOWS:
        return "Sandbox not available on Windows"
    return None


def get_vault_backend() -> str:
    """Get the vault backend name for current platform."""
    if IS_MACOS:
        return "macOS Keychain"
    elif IS_LINUX:
        return "Secret Service (GNOME Keyring/KWallet)"
    elif IS_WINDOWS:
        return "Windows Credential Locker"
    return "Unknown"


def get_capabilities() -> PlatformCapabilities:
    """Get capabilities for the current platform."""
    sandbox_tool = get_sandbox_tool()

    return PlatformCapabilities(
        platform=PLATFORM,
        vault_available=True,  # keyring works everywhere
        vault_backend=get_vault_backend(),
        sandbox_available=sandbox_tool is not None,
        sandbox_tool=sandbox_tool,
        sandbox_install_hint=get_sandbox_install_hint() if not sandbox_tool else None,
    )


def get_linux_package_manager() -> Optional[tuple[str, list[str]]]:
    """Detect Linux package manager and return firejail install command."""
    if not IS_LINUX:
        return None

    managers = {
        "apt": ["sudo", "apt", "install", "-y", "firejail"],
        "dnf": ["sudo", "dnf", "install", "-y", "firejail"],
        "pacman": ["sudo", "pacman", "-S", "--noconfirm", "firejail"],
        "zypper": ["sudo", "zypper", "install", "-y", "firejail"],
        "apk": ["sudo", "apk", "add", "firejail"],
    }

    for manager, command in managers.items():
        if shutil.which(manager):
            return manager, command

    return None
