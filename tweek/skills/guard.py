"""
Tweek Skill Isolation Guard — Self-Protection

Prevents the AI agent from bypassing the isolation chamber by:
1. Blocking writes to Claude's skill directories (force use of chamber)
2. Blocking writes to chamber/jail directories
3. Detecting shell commands that manipulate skill directories
4. Detecting autonomous skill downloads

Follows the same pattern as tweek/hooks/overrides.py for protected config files.
"""

import re
from pathlib import Path
from typing import Dict, Optional, Tuple

from tweek.skills import (
    CHAMBER_DIR,
    CLAUDE_GLOBAL_SKILLS,
    JAIL_DIR,
    REPORTS_DIR,
    SKILLS_DIR,
)


# Paths that AI cannot write to directly
PROTECTED_SKILL_PATHS = [
    SKILLS_DIR,          # ~/.tweek/skills/ (chamber, jail, reports)
    CLAUDE_GLOBAL_SKILLS,  # ~/.claude/skills/
]

# Regex patterns for detecting skill-related shell commands
_SKILL_DIR_PATTERNS = [
    # Moving/copying out of jail
    re.compile(
        r"(cp|mv|rsync|ln)\s+.*\.tweek/skills/(jail|chamber)",
        re.IGNORECASE,
    ),
    # Moving/copying into Claude's skill directories
    re.compile(
        r"(cp|mv|rsync|ln)\s+.*\.claude/skills/",
        re.IGNORECASE,
    ),
    # Symlink attacks targeting skill directories
    re.compile(
        r"ln\s+(-sf?\s+)?.*\.claude/skills",
        re.IGNORECASE,
    ),
    re.compile(
        r"ln\s+(-sf?\s+)?.*\.tweek/skills",
        re.IGNORECASE,
    ),
    # Direct creation of SKILL.md via shell
    re.compile(
        r"(echo|cat|tee|printf)\s+.*>\s*.*\.claude/skills/.*SKILL\.md",
        re.IGNORECASE,
    ),
]

# Patterns for detecting skill downloads
_DOWNLOAD_PATTERNS = [
    re.compile(
        r"(curl|wget)\s+[^\n]*https?://[^\s]+.*>\s*.*SKILL",
        re.IGNORECASE,
    ),
    re.compile(
        r"(curl|wget)\s+[^\n]*https?://[^\s]+.*>\s*.*\.claude/skills/",
        re.IGNORECASE,
    ),
    re.compile(
        r"git\s+clone\s+[^\n]*skill",
        re.IGNORECASE,
    ),
    re.compile(
        r"(curl|wget)\s+[^\n]*SKILL\.md",
        re.IGNORECASE,
    ),
]


def is_skill_install_attempt(tool_name: str, tool_input: Dict) -> bool:
    """
    Check if a Write/Edit tool call is attempting to install a skill directly,
    bypassing the isolation chamber.

    Args:
        tool_name: The tool being invoked (Write, Edit)
        tool_input: The tool's input parameters

    Returns:
        True if this appears to be a direct skill installation attempt
    """
    if tool_name not in ("Write", "Edit"):
        return False

    file_path = tool_input.get("file_path", "")
    if not file_path:
        return False

    # Normalize the path
    try:
        resolved = Path(file_path).expanduser().resolve()
    except (ValueError, OSError):
        return False

    # Check if targeting Claude's skill directories
    claude_skills = CLAUDE_GLOBAL_SKILLS.resolve()
    try:
        resolved.relative_to(claude_skills)
        # Writing anything into ~/.claude/skills/ is blocked
        return True
    except ValueError:
        pass

    # Check project-level skills
    # Look for .claude/skills/ pattern anywhere in the path
    path_str = str(resolved)
    if ".claude/skills/" in path_str and "SKILL.md" in path_str:
        return True

    return False


def is_chamber_protected_path(file_path: str) -> bool:
    """
    Check if a file path is within the isolation chamber's protected directories.

    Args:
        file_path: The file path being accessed

    Returns:
        True if the path is protected from AI modification
    """
    if not file_path:
        return False

    try:
        resolved = Path(file_path).expanduser().resolve()
    except (ValueError, OSError):
        return False

    for protected in PROTECTED_SKILL_PATHS:
        try:
            protected_resolved = protected.resolve()
            resolved.relative_to(protected_resolved)
            return True
        except ValueError:
            continue

    return False


def bash_targets_chamber(command: str) -> bool:
    """
    Check if a Bash command targets the isolation chamber or Claude skill directories.

    Args:
        command: The shell command string

    Returns:
        True if the command manipulates skill directories
    """
    if not command:
        return False

    for pattern in _SKILL_DIR_PATTERNS:
        if pattern.search(command):
            return True

    return False


def is_skill_download_attempt(command: str) -> Tuple[bool, str]:
    """
    Check if a Bash command is attempting to download skill content.

    Returns (True, url_or_description) if a download is detected,
    (False, "") otherwise. Downloads are not blocked but trigger an "ask"
    decision so the user can confirm.

    Args:
        command: The shell command string

    Returns:
        (is_download, description)
    """
    if not command:
        return False, ""

    for pattern in _DOWNLOAD_PATTERNS:
        match = pattern.search(command)
        if match:
            return True, match.group(0)[:200]

    return False, ""


def get_skill_guard_reason(tool_name: str, tool_input: Dict) -> Optional[str]:
    """
    Get a human-readable reason if this tool call should be blocked by the guard.

    Returns None if no guard rule applies, or a reason string if blocked.

    Args:
        tool_name: The tool being invoked
        tool_input: The tool's input parameters

    Returns:
        Block reason string, or None if allowed
    """
    if tool_name in ("Write", "Edit"):
        file_path = tool_input.get("file_path", "")

        if is_skill_install_attempt(tool_name, tool_input):
            return (
                "TWEEK SKILL GUARD: Direct skill installation is blocked.\n"
                "Skills must go through the isolation chamber for security scanning.\n"
                "Use: tweek skills chamber import <path>"
            )

        if is_chamber_protected_path(file_path):
            return (
                "TWEEK SKILL GUARD: Isolation chamber directories are protected.\n"
                "The chamber, jail, and reports directories cannot be modified by AI.\n"
                "Use the 'tweek skills' CLI commands to manage skills."
            )

    elif tool_name == "Bash":
        command = tool_input.get("command", "")

        if bash_targets_chamber(command):
            return (
                "TWEEK SKILL GUARD: Shell commands targeting skill directories are blocked.\n"
                "Use the 'tweek skills' CLI commands to manage skills."
            )

    return None


def get_skill_download_prompt(command: str) -> Optional[str]:
    """
    Get an "ask" prompt message if this command appears to download skill content.

    Returns None if no download detected, or a prompt string for the user.

    Args:
        command: The shell command string

    Returns:
        Prompt message string, or None if not a download
    """
    is_download, desc = is_skill_download_attempt(command)
    if not is_download:
        return None

    return (
        f"TWEEK SKILL GUARD: Detected potential skill download.\n"
        f"Command: {desc}\n"
        f"Downloaded skills should go through the isolation chamber.\n"
        f"Allow this download?"
    )
