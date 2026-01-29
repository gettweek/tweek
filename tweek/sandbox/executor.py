#!/usr/bin/env python3
"""
Tweek Sandbox Executor

Executes commands in a macOS sandbox for preview/speculative execution.
Captures file accesses, network attempts, and process spawns.

Usage:
    executor = SandboxExecutor()
    result = executor.preview_command("curl http://evil.com", skill="my-skill")

    if result.suspicious:
        print("Blocked:", result.violations)
"""

import os
import subprocess
import tempfile
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any
import re

from .profile_generator import ProfileGenerator, SkillManifest


@dataclass
class ExecutionResult:
    """Result of a sandboxed command execution."""

    # Basic execution info
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    # Security analysis
    suspicious: bool = False
    violations: List[str] = field(default_factory=list)

    # Captured access attempts
    file_reads: List[str] = field(default_factory=list)
    file_writes: List[str] = field(default_factory=list)
    network_attempts: List[str] = field(default_factory=list)
    process_spawns: List[str] = field(default_factory=list)

    # Denied operations (blocked by sandbox)
    denied_operations: List[str] = field(default_factory=list)


class SandboxExecutor:
    """Executes commands in a sandbox and analyzes their behavior."""

    # Sensitive paths that trigger suspicion
    SENSITIVE_PATHS = [
        r"\.ssh",
        r"\.aws",
        r"\.gnupg",
        r"\.netrc",
        r"\.env",
        r"credentials",
        r"\.kube/config",
        r"\.config/gcloud",
        r"keychain",
        r"Cookies",
        r"Login Data",
    ]

    # Suspicious network patterns
    SUSPICIOUS_HOSTS = [
        r"pastebin\.com",
        r"hastebin\.com",
        r"ghostbin\.",
        r"0x0\.st",
        r"transfer\.sh",
        r"file\.io",
        r"webhook\.site",
        r"requestbin\.",
        r"ngrok\.io",
    ]

    def __init__(self, profiles_dir: Optional[Path] = None):
        """Initialize the executor."""
        self.generator = ProfileGenerator(profiles_dir=profiles_dir)
        self._check_sandbox_available()

    def _check_sandbox_available(self) -> bool:
        """Check if sandbox-exec is available."""
        return Path("/usr/bin/sandbox-exec").exists()

    def preview_command(
        self,
        command: str,
        skill: str = "preview",
        timeout: float = 5.0,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[Path] = None,
    ) -> ExecutionResult:
        """
        Execute a command in a restrictive sandbox for preview.

        This runs the command with limited permissions to see what it
        TRIES to do, without actually allowing dangerous operations.

        Args:
            command: Shell command to execute
            skill: Skill name for profile (uses restrictive preview profile)
            timeout: Max execution time in seconds
            env: Additional environment variables
            cwd: Working directory

        Returns:
            ExecutionResult with captured behavior
        """
        # Create a restrictive preview manifest
        # Must allow enough for basic shell operations
        manifest = SkillManifest(
            name=f"preview-{skill}",
            read_paths=[
                "./",
                "/usr/lib",
                "/usr/local/lib",
                "/System",
                "/bin",
                "/usr/bin",
                "/private/var/db",
                "/dev",
                "/Library/Preferences",
                "/var/folders",  # Temp files
            ],
            write_paths=[
                "/dev/null",
                "/dev/stdout",
                "/dev/stderr",
                "/private/var/folders",  # Temp files
            ],
            deny_paths=[
                "~/.ssh", "~/.aws", "~/.gnupg", "~/.netrc",
                "~/.env", "**/.env", "~/.kube", "~/.config/gcloud",
            ],
            network_deny_all=True,
            allow_subprocess=True,  # Needed for basic shell operations
            allow_exec=["/bin/bash", "/bin/sh", "/usr/bin/env", "/bin/echo"],
        )

        # Generate and save the profile
        profile_path = self.generator.save(manifest)

        # Build the sandboxed command
        sandboxed_cmd = f'sandbox-exec -f "{profile_path}" /bin/bash -c {self._shell_quote(command)}'

        # Set up environment
        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        # Execute with timeout
        result = ExecutionResult(exit_code=-1, stdout="", stderr="")

        try:
            proc = subprocess.run(
                sandboxed_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=run_env,
            )

            result.exit_code = proc.returncode
            result.stdout = proc.stdout
            result.stderr = proc.stderr

        except subprocess.TimeoutExpired:
            result.timed_out = True
            result.violations.append(f"Command timed out after {timeout}s")
            result.suspicious = True

        except Exception as e:
            result.stderr = str(e)
            result.exit_code = -1

        # Analyze the output for sandbox violations
        self._analyze_sandbox_output(result, command)

        # Clean up preview profile
        self.generator.delete_profile(f"preview-{skill}")

        return result

    def _shell_quote(self, s: str) -> str:
        """Quote a string for shell use."""
        return "'" + s.replace("'", "'\"'\"'") + "'"

    def _analyze_sandbox_output(self, result: ExecutionResult, command: str) -> None:
        """Analyze execution results for suspicious behavior."""

        # Check stderr for sandbox denials
        denial_pattern = r"sandbox-exec: .* deny"
        denials = re.findall(denial_pattern, result.stderr, re.IGNORECASE)
        result.denied_operations.extend(denials)

        # Check for sensitive path access attempts in command
        for pattern in self.SENSITIVE_PATHS:
            if re.search(pattern, command, re.IGNORECASE):
                result.violations.append(f"Attempts to access sensitive path: {pattern}")
                result.suspicious = True

        # Check for suspicious network destinations in command
        for pattern in self.SUSPICIOUS_HOSTS:
            if re.search(pattern, command, re.IGNORECASE):
                result.violations.append(f"Attempts to contact suspicious host: {pattern}")
                result.suspicious = True

        # Check for data exfiltration patterns
        exfil_patterns = [
            (r"curl.*-d.*\$\(", "Potential data exfiltration via curl POST"),
            (r"wget.*--post-data", "Potential data exfiltration via wget POST"),
            (r"\| *nc ", "Piping data to netcat"),
            (r"\| *curl", "Piping data to curl"),
            (r"base64.*\|.*curl", "Base64 encoding and sending data"),
        ]

        for pattern, description in exfil_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                result.violations.append(description)
                result.suspicious = True

        # Mark as suspicious if sandbox blocked operations
        if result.denied_operations:
            result.suspicious = True
            result.violations.append(f"Sandbox blocked {len(result.denied_operations)} operations")

    def execute_sandboxed(
        self,
        command: str,
        skill: str,
        manifest: Optional[SkillManifest] = None,
        timeout: float = 30.0,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[Path] = None,
    ) -> ExecutionResult:
        """
        Execute a command in a sandbox with skill-specific permissions.

        Unlike preview_command, this uses the skill's actual manifest
        permissions and allows the command to run with appropriate access.

        Args:
            command: Shell command to execute
            skill: Skill name for profile lookup
            manifest: Optional manifest (uses existing or default if not provided)
            timeout: Max execution time in seconds
            env: Additional environment variables
            cwd: Working directory

        Returns:
            ExecutionResult with execution details
        """
        # Get or create profile
        profile_path = self.generator.get_profile_path(skill)

        if profile_path is None:
            if manifest:
                profile_path = self.generator.save(manifest)
            else:
                # Use default restrictive profile
                manifest = SkillManifest.default(skill)
                profile_path = self.generator.save(manifest)

        # Build sandboxed command
        sandboxed_cmd = f'sandbox-exec -f "{profile_path}" /bin/bash -c {self._shell_quote(command)}'

        # Set up environment
        run_env = os.environ.copy()
        if env:
            run_env.update(env)

        # Execute
        result = ExecutionResult(exit_code=-1, stdout="", stderr="")

        try:
            proc = subprocess.run(
                sandboxed_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                env=run_env,
            )

            result.exit_code = proc.returncode
            result.stdout = proc.stdout
            result.stderr = proc.stderr

        except subprocess.TimeoutExpired:
            result.timed_out = True
            result.violations.append(f"Command timed out after {timeout}s")

        except Exception as e:
            result.stderr = str(e)
            result.exit_code = -1

        # Analyze output
        self._analyze_sandbox_output(result, command)

        return result

    def get_sandbox_command(self, command: str, skill: str) -> str:
        """
        Get the sandbox-wrapped version of a command.

        This doesn't execute anything, just returns what the
        sandboxed command would look like.

        Args:
            command: Original command
            skill: Skill name

        Returns:
            Sandbox-wrapped command string
        """
        return self.generator.wrap_command(command, skill)
