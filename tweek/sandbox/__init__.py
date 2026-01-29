"""
Tweek Sandbox - Cross-platform command sandboxing.

Provides isolated execution environments:
- macOS: sandbox-exec (built-in)
- Linux: firejail (optional, recommended) or bubblewrap
- Windows: Not available
"""

from tweek.platform import PLATFORM, Platform, IS_MACOS, IS_LINUX, get_sandbox_tool

# Import platform-specific implementations
SANDBOX_AVAILABLE = False
SANDBOX_TOOL = None

if IS_MACOS:
    try:
        from .profile_generator import ProfileGenerator, SkillManifest
        from .executor import SandboxExecutor, ExecutionResult
        SANDBOX_AVAILABLE = True
        SANDBOX_TOOL = "sandbox-exec"
    except ImportError:
        ProfileGenerator = None
        SkillManifest = None
        SandboxExecutor = None
        ExecutionResult = None

elif IS_LINUX:
    try:
        from .linux import LinuxSandbox, prompt_install_firejail, get_sandbox
        _sandbox = get_sandbox()
        if _sandbox and _sandbox.available:
            SANDBOX_AVAILABLE = True
            SANDBOX_TOOL = _sandbox.tool
    except ImportError:
        LinuxSandbox = None
        prompt_install_firejail = None
        get_sandbox = None

# Keep macOS imports available for backwards compatibility
try:
    from .profile_generator import ProfileGenerator, SkillManifest
    from .executor import SandboxExecutor, ExecutionResult
except ImportError:
    pass


def get_sandbox_status() -> dict:
    """Get sandbox availability status for current platform."""
    tool = get_sandbox_tool()

    return {
        "available": SANDBOX_AVAILABLE,
        "tool": SANDBOX_TOOL or tool,
        "platform": PLATFORM.value,
    }


__all__ = [
    "ProfileGenerator",
    "SkillManifest",
    "SandboxExecutor",
    "ExecutionResult",
    "SANDBOX_AVAILABLE",
    "SANDBOX_TOOL",
    "get_sandbox_status",
]

# Add Linux-specific exports if available
if IS_LINUX:
    __all__.extend(["LinuxSandbox", "prompt_install_firejail", "get_sandbox"])
