"""
Linux sandbox implementation using firejail.

Firejail is a SUID sandbox program that uses Linux namespaces,
seccomp-bpf, and capabilities to restrict process execution.

If firejail is not available, falls back to bubblewrap (bwrap)
which is often installed with Flatpak.
"""

import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

from tweek.platform import IS_LINUX, get_linux_package_manager


@dataclass
class SandboxResult:
    """Result of a sandboxed command execution."""
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    blocked_actions: list[str]


class LinuxSandbox:
    """
    Linux sandbox using firejail or bubblewrap.

    Provides similar functionality to macOS sandbox-exec:
    - Restrict network access
    - Restrict filesystem access
    - Restrict process capabilities
    """

    def __init__(self):
        self.tool = self._detect_tool()

    def _detect_tool(self) -> Optional[str]:
        """Detect available sandbox tool."""
        if shutil.which("firejail"):
            return "firejail"
        elif shutil.which("bwrap"):
            return "bubblewrap"
        return None

    @property
    def available(self) -> bool:
        """Check if sandbox is available."""
        return self.tool is not None

    def get_install_command(self) -> Optional[str]:
        """Get command to install firejail."""
        pkg_info = get_linux_package_manager()
        if pkg_info:
            _, command = pkg_info
            return " ".join(command)
        return None

    def _build_firejail_command(
        self,
        command: str,
        allow_network: bool = False,
        allow_write: bool = False,
        timeout: int = 30
    ) -> list[str]:
        """Build firejail command with restrictions."""
        args = [
            "firejail",
            "--noprofile",          # Don't use app-specific profile
            "--quiet",              # Reduce output noise
            "--caps.drop=all",      # Drop all capabilities
            "--noroot",             # No root privileges
            "--seccomp",            # Enable seccomp filters
            "--private-tmp",        # Isolated /tmp
            "--nogroups",           # No supplementary groups
        ]

        if not allow_network:
            args.append("--net=none")

        if not allow_write:
            args.extend([
                "--read-only=/",
                "--read-write=/tmp",
                "--read-write=/dev/null",
                "--read-write=/dev/zero",
            ])

        args.extend([
            f"--timeout={timeout}",
            "bash", "-c", command
        ])

        return args

    def _build_bubblewrap_command(
        self,
        command: str,
        allow_network: bool = False,
        allow_write: bool = False,
        timeout: int = 30
    ) -> list[str]:
        """Build bubblewrap command with restrictions."""
        args = [
            "bwrap",
            "--ro-bind", "/", "/",          # Read-only root
            "--dev", "/dev",                 # Minimal /dev
            "--proc", "/proc",               # /proc filesystem
            "--tmpfs", "/tmp",               # Isolated /tmp
            "--unshare-all",                 # Unshare all namespaces
            "--die-with-parent",             # Clean up on parent exit
            "--new-session",                 # New session
        ]

        if not allow_network:
            args.append("--unshare-net")

        if allow_write:
            # Re-bind specific paths as read-write
            args.extend(["--bind", "/tmp", "/tmp"])

        args.extend(["bash", "-c", command])

        # Wrap with timeout
        return ["timeout", str(timeout)] + args

    def preview_command(
        self,
        command: str,
        allow_network: bool = False,
        allow_write: bool = False,
        timeout: int = 10
    ) -> SandboxResult:
        """
        Run a command in the sandbox and capture what it tries to do.

        This is used for "preview" mode where we want to see what
        a command would do before allowing it.
        """
        if not self.available:
            return SandboxResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr="Sandbox not available",
                blocked_actions=[]
            )

        if self.tool == "firejail":
            sandbox_cmd = self._build_firejail_command(
                command, allow_network, allow_write, timeout
            )
        else:
            sandbox_cmd = self._build_bubblewrap_command(
                command, allow_network, allow_write, timeout
            )

        try:
            result = subprocess.run(
                sandbox_cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 5  # Extra buffer
            )

            blocked = self._parse_blocked_actions(result.stderr)

            return SandboxResult(
                success=result.returncode == 0,
                exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                blocked_actions=blocked
            )

        except subprocess.TimeoutExpired:
            return SandboxResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr="Command timed out",
                blocked_actions=["timeout"]
            )
        except Exception as e:
            return SandboxResult(
                success=False,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                blocked_actions=[]
            )

    def _parse_blocked_actions(self, stderr: str) -> list[str]:
        """Parse sandbox output to find blocked actions."""
        blocked = []

        # Firejail patterns
        if "Permission denied" in stderr:
            blocked.append("permission_denied")
        if "Network is disabled" in stderr or "No network" in stderr:
            blocked.append("network_blocked")
        if "Read-only file system" in stderr:
            blocked.append("write_blocked")
        if "Operation not permitted" in stderr:
            blocked.append("operation_blocked")

        return blocked


def prompt_install_firejail(console) -> bool:
    """
    Prompt user to install firejail for sandbox support.

    Args:
        console: Rich console for output

    Returns:
        True if firejail is now available, False otherwise
    """
    from rich.prompt import Confirm

    if not IS_LINUX:
        return False

    if shutil.which("firejail"):
        return True  # Already installed

    console.print("\n[yellow]Sandbox not available[/yellow]")
    console.print("Firejail provides sandbox preview for dangerous commands.")
    console.print("Without it, Tweek still provides 4/5 defense layers.\n")

    pkg_info = get_linux_package_manager()

    if not pkg_info:
        console.print("[dim]Could not detect package manager.[/dim]")
        console.print("Install firejail manually: https://firejail.wordpress.com/download-2/")
        return False

    manager, command = pkg_info
    console.print(f"[dim]Detected package manager: {manager}[/dim]")
    console.print(f"[dim]Command: {' '.join(command)}[/dim]\n")

    if Confirm.ask("Install firejail for full sandbox protection?", default=False):
        try:
            console.print("[cyan]Installing firejail...[/cyan]")
            subprocess.run(command, check=True)

            # Verify installation
            if shutil.which("firejail"):
                console.print("[green]Firejail installed successfully![/green]")
                return True
            else:
                console.print("[red]Installation completed but firejail not found in PATH[/red]")
                return False

        except subprocess.CalledProcessError as e:
            console.print(f"[red]Installation failed (exit code {e.returncode})[/red]")
            console.print("[dim]Try running the install command manually with sudo[/dim]")
            return False
        except KeyboardInterrupt:
            console.print("\n[yellow]Installation cancelled.[/yellow]")
            return False
    else:
        console.print("[dim]Skipping firejail. Sandbox layer will be disabled.[/dim]")
        return False


def get_sandbox() -> Optional[LinuxSandbox]:
    """Get a Linux sandbox instance if available."""
    if not IS_LINUX:
        return None

    sandbox = LinuxSandbox()
    return sandbox if sandbox.available else None
