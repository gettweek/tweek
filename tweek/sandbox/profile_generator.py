#!/usr/bin/env python3
"""
Tweek Sandbox Profile Generator

Generates macOS sandbox-exec profiles (.sb files) from skill manifests.
Profiles restrict filesystem, network, and process access for skills.

Usage:
    generator = ProfileGenerator()
    profile = generator.generate(manifest)
    generator.save(manifest, profile)
    command = generator.wrap_command("python3 script.py", "my-skill")
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

import yaml


@dataclass
class SkillManifest:
    """Parsed skill manifest with permission declarations."""

    name: str
    version: str = "1.0"

    # Filesystem permissions
    read_paths: List[str] = field(default_factory=list)
    write_paths: List[str] = field(default_factory=list)
    deny_paths: List[str] = field(default_factory=list)

    # Network permissions
    network_allow: List[str] = field(default_factory=list)
    network_deny_all: bool = True

    # Process permissions
    allow_subprocess: bool = False
    allow_exec: List[str] = field(default_factory=list)

    # Credentials this skill needs
    credentials: List[str] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: Path) -> "SkillManifest":
        """Load manifest from YAML file."""
        if not path.exists():
            raise FileNotFoundError(f"Manifest not found: {path}")

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        # Extract filesystem permissions
        fs = data.get("permissions", {}).get("filesystem", {})
        net = data.get("permissions", {}).get("network", {})
        proc = data.get("permissions", {}).get("process", {})

        return cls(
            name=data.get("name", path.stem),
            version=data.get("version", "1.0"),
            read_paths=fs.get("read", []),
            write_paths=fs.get("write", []),
            deny_paths=fs.get("deny", []),
            network_allow=net.get("allow", []),
            network_deny_all=net.get("deny_all", True),
            allow_subprocess=proc.get("subprocess", False),
            allow_exec=proc.get("exec", []),
            credentials=data.get("credentials", []),
        )

    @classmethod
    def default(cls, name: str = "default") -> "SkillManifest":
        """Create a restrictive default manifest."""
        return cls(
            name=name,
            read_paths=["./", "/usr/lib", "/usr/local/lib", "/System/Library"],
            write_paths=["./", "/private/tmp"],
            deny_paths=[
                "~/.ssh",
                "~/.aws",
                "~/.config/gcloud",
                "~/.kube",
                "~/.netrc",
                "~/.env",
                "**/.env",
                "~/.bash_history",
                "~/.zsh_history",
            ],
            network_deny_all=True,
            allow_subprocess=False,
        )


class ProfileGenerator:
    """Generates sandbox-exec profiles from skill manifests."""

    PROFILES_DIR = Path.home() / ".tweek" / "profiles"

    # Default paths that are always allowed for basic functionality
    ALWAYS_ALLOW_READ = [
        "/usr/lib",
        "/usr/local/lib",
        "/System/Library",
        "/Library/Frameworks",
        "/private/var/db",
        "/dev/null",
        "/dev/random",
        "/dev/urandom",
    ]

    # Paths that are ALWAYS denied regardless of manifest
    ALWAYS_DENY = [
        "~/.ssh",
        "~/.gnupg",
        "~/.aws/credentials",
        "~/.config/gcloud/credentials.db",
        "~/.netrc",
    ]

    def __init__(self, profiles_dir: Optional[Path] = None):
        """Initialize the generator."""
        self.profiles_dir = profiles_dir or self.PROFILES_DIR
        self.profiles_dir.mkdir(parents=True, exist_ok=True)

    def _expand_path(self, path: str) -> str:
        """Expand ~ and environment variables in path."""
        expanded = os.path.expanduser(path)
        expanded = os.path.expandvars(expanded)
        return expanded

    def _escape_for_scheme(self, s: str) -> str:
        """Escape a string for use in Scheme-like sandbox profile."""
        # Escape backslashes and quotes
        return s.replace("\\", "\\\\").replace('"', '\\"')

    def _generate_path_rule(
        self, action: str, path: str, is_subpath: bool = True
    ) -> str:
        """Generate a single path rule."""
        expanded = self._expand_path(path)
        escaped = self._escape_for_scheme(expanded)

        if "**" in path or "*" in path:
            # Convert glob to regex
            pattern = path.replace("**", ".*").replace("*", "[^/]*")
            pattern = self._expand_path(pattern)
            return f'({action} file-read* (regex #"{pattern}"))'

        if is_subpath:
            return f'({action} file-read* (subpath "{escaped}"))'
        else:
            return f'({action} file-read* (literal "{escaped}"))'

    def generate(self, manifest: SkillManifest) -> str:
        """
        Generate a sandbox profile from a skill manifest.

        Args:
            manifest: Skill manifest with permission declarations

        Returns:
            String containing the .sb profile content
        """
        lines = [
            f";; Tweek Sandbox Profile for: {manifest.name}",
            f";; Generated automatically - do not edit",
            f";; Version: {manifest.version}",
            "",
            "(version 1)",
            "",
            ";; Start with deny-all policy",
            "(deny default)",
            "",
            ";; Allow basic system functionality",
            "(allow process-fork)",
            "(allow signal)",
            "(allow sysctl-read)",
            "",
        ]

        # Always-allow read paths
        lines.append(";; System paths (always allowed)")
        for path in self.ALWAYS_ALLOW_READ:
            lines.append(f'(allow file-read* (subpath "{path}"))')
        lines.append("")

        # Manifest read paths
        if manifest.read_paths:
            lines.append(";; Allowed read paths")
            for path in manifest.read_paths:
                expanded = self._expand_path(path)
                lines.append(f'(allow file-read* (subpath "{expanded}"))')
            lines.append("")

        # Manifest write paths
        if manifest.write_paths:
            lines.append(";; Allowed write paths")
            for path in manifest.write_paths:
                expanded = self._expand_path(path)
                lines.append(f'(allow file-write* (subpath "{expanded}"))')
            lines.append("")

        # Always-deny paths (security critical)
        lines.append(";; SECURITY: Always-denied paths")
        for path in self.ALWAYS_DENY:
            expanded = self._expand_path(path)
            lines.append(f'(deny file-read* (subpath "{expanded}"))')
            lines.append(f'(deny file-write* (subpath "{expanded}"))')
        lines.append("")

        # Manifest deny paths
        if manifest.deny_paths:
            lines.append(";; Additional denied paths")
            for path in manifest.deny_paths:
                if "**" in path or "*" in path:
                    # Glob pattern
                    pattern = path.replace("**", ".*").replace("*", "[^/]*")
                    pattern = self._expand_path(pattern)
                    pattern = self._escape_for_scheme(pattern)
                    lines.append(f'(deny file-read* (regex #"{pattern}"))')
                    lines.append(f'(deny file-write* (regex #"{pattern}"))')
                else:
                    expanded = self._expand_path(path)
                    lines.append(f'(deny file-read* (subpath "{expanded}"))')
                    lines.append(f'(deny file-write* (subpath "{expanded}"))')
            lines.append("")

        # Network rules
        lines.append(";; Network access")
        if manifest.network_deny_all and not manifest.network_allow:
            lines.append("(deny network*)")
        elif manifest.network_allow:
            lines.append(";; Allow specific hosts")
            for host in manifest.network_allow:
                lines.append(f'(allow network-outbound (remote host "{host}"))')
            if manifest.network_deny_all:
                lines.append("(deny network-outbound)")
        lines.append("")

        # Process execution
        lines.append(";; Process execution")
        if manifest.allow_subprocess:
            lines.append("(allow process-exec*)")
        elif manifest.allow_exec:
            for exe in manifest.allow_exec:
                expanded = self._expand_path(exe)
                lines.append(f'(allow process-exec (literal "{expanded}"))')
        else:
            lines.append(";; No subprocess execution allowed")
        lines.append("")

        return "\n".join(lines)

    def save(self, manifest: SkillManifest, profile: Optional[str] = None) -> Path:
        """
        Save a profile to disk.

        Args:
            manifest: Skill manifest
            profile: Profile content (generated if not provided)

        Returns:
            Path to saved profile
        """
        if profile is None:
            profile = self.generate(manifest)

        profile_path = self.profiles_dir / f"{manifest.name}.sb"
        profile_path.write_text(profile)

        return profile_path

    def get_profile_path(self, skill_name: str) -> Optional[Path]:
        """Get path to existing profile for a skill."""
        profile_path = self.profiles_dir / f"{skill_name}.sb"
        if profile_path.exists():
            return profile_path
        return None

    def wrap_command(
        self,
        command: str,
        skill_name: str,
        generate_if_missing: bool = True
    ) -> str:
        """
        Wrap a command with sandbox-exec.

        Args:
            command: The command to wrap
            skill_name: Skill name to use for profile
            generate_if_missing: Generate default profile if none exists

        Returns:
            Command wrapped with sandbox-exec
        """
        profile_path = self.get_profile_path(skill_name)

        if profile_path is None:
            if generate_if_missing:
                # Generate and save default profile
                manifest = SkillManifest.default(skill_name)
                profile_path = self.save(manifest)
            else:
                # No sandboxing - return original command
                return command

        return f'sandbox-exec -f "{profile_path}" {command}'

    def list_profiles(self) -> List[str]:
        """List all generated profiles."""
        return [p.stem for p in self.profiles_dir.glob("*.sb")]

    def delete_profile(self, skill_name: str) -> bool:
        """Delete a profile."""
        profile_path = self.profiles_dir / f"{skill_name}.sb"
        if profile_path.exists():
            profile_path.unlink()
            return True
        return False
