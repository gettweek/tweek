"""
Tweek Skill Context Tracking

Detects active skill context from Claude Code's Skill tool invocations.
When PreToolUse sees tool_name=="Skill", the skill name is extracted from
tool_input and written to a breadcrumb file. Subsequent tool calls within
the same session read the breadcrumb to get skill context for tier lookup.

This bridges the gap where Claude Code's hook protocol doesn't include
skill_name: the Skill tool IS a regular tool, so PreToolUse sees it.

Security properties:
  - Session-isolated: per-session breadcrumb files (no cross-session leakage)
  - Auto-expiring: 60-second staleness timeout
  - Atomic writes: write-to-temp + os.rename (POSIX atomic)
  - Restricted permissions: 0o600 on breadcrumb files
  - Fail-safe: any error falls to no-context = default tier
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Optional

# Breadcrumb location — per-session files for isolation
TWEEK_STATE_DIR = Path.home() / ".tweek" / "state"

# Breadcrumb expires after 60 seconds of inactivity.
# Skills typically issue tool calls in rapid succession; 60s is generous
# while limiting the window for staleness-based attacks.
STALENESS_TIMEOUT_SECONDS = 60

# Maximum age before a per-session breadcrumb file is considered orphaned
# and eligible for cleanup (1 hour).
ORPHAN_CLEANUP_SECONDS = 3600


def _breadcrumb_path_for_session(session_id: str, state_dir: Optional[Path] = None) -> Path:
    """Get the breadcrumb file path for a specific session.

    Uses first 12 chars of session_id to avoid excessively long filenames
    while maintaining sufficient uniqueness.
    """
    prefix = session_id[:12] if session_id else "unknown"
    base = state_dir or TWEEK_STATE_DIR
    return base / f"active_skill_{prefix}.json"


def write_skill_breadcrumb(
    skill_name: str,
    session_id: str,
    *,
    breadcrumb_path: Optional[Path] = None,
) -> None:
    """Record the active skill for this session.

    Called when PreToolUse detects a Skill tool invocation.
    Uses atomic write (temp file + rename) and restricts permissions to 0o600.

    Args:
        skill_name: The skill being invoked (from tool_input["skill"])
        session_id: Current hook session ID for isolation
        breadcrumb_path: Override for testing (bypasses per-session naming)
    """
    path = breadcrumb_path or _breadcrumb_path_for_session(session_id)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "skill": skill_name,
        "session_id": session_id,
        "timestamp": time.time(),
    }

    # Atomic write: write to temp file, then rename (POSIX atomic)
    fd = None
    tmp_path = None
    try:
        fd, tmp_path = tempfile.mkstemp(
            dir=str(path.parent),
            prefix=".skill_",
            suffix=".tmp",
        )
        os.write(fd, json.dumps(data).encode("utf-8"))
        os.close(fd)
        fd = None  # Mark as closed

        # Restrict permissions before rename (owner read/write only)
        os.chmod(tmp_path, 0o600)

        # Atomic rename
        os.rename(tmp_path, str(path))
        tmp_path = None  # Mark as renamed (don't clean up)
    finally:
        # Clean up on failure
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def read_skill_context(
    session_id: str,
    *,
    breadcrumb_path: Optional[Path] = None,
    staleness_seconds: float = STALENESS_TIMEOUT_SECONDS,
) -> Optional[str]:
    """Read the active skill for the current session, if any.

    Returns the skill name if a fresh, session-matching breadcrumb exists.
    Returns None if no breadcrumb, wrong session, or stale.

    Args:
        session_id: Current hook session ID — must match breadcrumb
        breadcrumb_path: Override for testing (bypasses per-session naming)
        staleness_seconds: Max age in seconds before breadcrumb is stale
    """
    path = breadcrumb_path or _breadcrumb_path_for_session(session_id)

    try:
        if not path.exists():
            return None

        data = json.loads(path.read_text(encoding="utf-8"))

        # Session isolation: only match same session
        if data.get("session_id") != session_id:
            return None

        # Staleness check
        ts = data.get("timestamp", 0)
        if (time.time() - ts) > staleness_seconds:
            # Expired — clean up
            _clear_breadcrumb(path)
            return None

        return data.get("skill")

    except (json.JSONDecodeError, OSError, KeyError):
        return None


def clear_skill_breadcrumb(
    session_id: Optional[str] = None,
    *,
    breadcrumb_path: Optional[Path] = None,
) -> None:
    """Clear the active skill breadcrumb.

    Called on session end or UserPromptSubmit if needed.

    Args:
        session_id: If provided, clears the per-session breadcrumb.
        breadcrumb_path: Override for testing.
    """
    if breadcrumb_path:
        _clear_breadcrumb(breadcrumb_path)
    elif session_id:
        _clear_breadcrumb(_breadcrumb_path_for_session(session_id))


def cleanup_orphaned_breadcrumbs(
    *,
    state_dir: Optional[Path] = None,
    max_age_seconds: float = ORPHAN_CLEANUP_SECONDS,
) -> int:
    """Remove breadcrumb files older than max_age_seconds.

    Called periodically to prevent accumulation of stale session files.
    Returns the number of files cleaned up.
    """
    base = state_dir or TWEEK_STATE_DIR
    cleaned = 0

    try:
        if not base.exists():
            return 0

        now = time.time()
        for f in base.glob("active_skill_*.json"):
            try:
                age = now - f.stat().st_mtime
                if age > max_age_seconds:
                    f.unlink(missing_ok=True)
                    cleaned += 1
            except OSError:
                continue
    except OSError:
        pass

    return cleaned


def _clear_breadcrumb(path: Path) -> None:
    """Remove the breadcrumb file silently."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def extract_skill_from_tool_input(tool_input: dict) -> Optional[str]:
    """Extract the skill name from a Skill tool's tool_input.

    The Skill tool sends: {"skill": "commit", "args": "..."}

    Returns the skill name or None if not a valid Skill invocation.
    """
    skill = tool_input.get("skill")
    if isinstance(skill, str) and skill.strip():
        return skill.strip()
    return None
