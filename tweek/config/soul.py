"""
Load and merge soul.md security policy files.

soul.md lets users express their security philosophy in natural language
(markdown). The LLM reviewer receives the merged policy as trusted operator
context, factoring it into risk decisions.

Config hierarchy:
    ~/.tweek/soul.md       Global baseline policy
    .tweek/soul.md         Project-level overrides/extensions

When both exist, content is merged (global first, project second) so the
LLM sees both and understands project-specific rules take precedence.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

GLOBAL_SOUL_PATH = Path.home() / ".tweek" / "soul.md"
PROJECT_SOUL_DIR = ".tweek"
SOUL_FILENAME = "soul.md"
MAX_SOUL_SIZE = 8192  # 8 KB per file — prevents token bloat in LLM calls

# Session-level cache (soul.md doesn't change mid-session)
_soul_cache: Optional[str] = ...  # sentinel: ... means "not loaded yet"


def load_soul_policy(
    project_dir: Optional[Path] = None,
    *,
    _bypass_cache: bool = False,
) -> Optional[str]:
    """Load merged soul policy from global + project paths.

    Returns combined markdown text, or None if no soul.md exists anywhere.

    Args:
        project_dir: Project root to search for .tweek/soul.md.
                     If None, only the global soul is loaded.
        _bypass_cache: Skip session cache (for testing).
    """
    global _soul_cache

    if not _bypass_cache and _soul_cache is not ...:
        return _soul_cache

    global_text = _read_soul_file(GLOBAL_SOUL_PATH)
    project_text = None

    if project_dir is not None:
        project_soul = Path(project_dir) / PROJECT_SOUL_DIR / SOUL_FILENAME
        project_text = _read_soul_file(project_soul)

    merged = _merge_policies(global_text, project_text)
    _soul_cache = merged
    return merged


def _read_soul_file(path: Path) -> Optional[str]:
    """Read a single soul.md file, enforcing size limit and UTF-8.

    Returns the file content as a string, or None if the file doesn't
    exist or fails validation.
    """
    if not path.is_file():
        return None

    try:
        size = path.stat().st_size
        if size > MAX_SOUL_SIZE:
            logger.warning(
                "soul.md at %s exceeds %d-byte limit (%d bytes) — skipped",
                path, MAX_SOUL_SIZE, size,
            )
            return None

        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        logger.warning("soul.md at %s is not valid UTF-8 — skipped", path)
        return None
    except OSError as exc:
        logger.warning("Could not read soul.md at %s: %s", path, exc)
        return None

    # Strip optional YAML front-matter (---\n...\n---\n)
    text = _strip_frontmatter(text)

    stripped = text.strip()
    if not stripped:
        return None

    return stripped


def _strip_frontmatter(text: str) -> str:
    """Remove optional YAML front-matter delimited by --- lines."""
    if not text.startswith("---"):
        return text
    lines = text.split("\n")
    # Find closing ---
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            return "\n".join(lines[i + 1 :])
    # No closing --- found — return as-is
    return text


def _merge_policies(
    global_text: Optional[str], project_text: Optional[str]
) -> Optional[str]:
    """Merge global and project soul policies.

    When both exist, they are concatenated with a separator so the LLM
    understands project rules take precedence.
    """
    if global_text and project_text:
        return (
            f"{global_text}\n\n"
            f"---\n"
            f"*The following project-level policy takes precedence "
            f"over the global policy above:*\n\n"
            f"{project_text}"
        )
    return global_text or project_text


def reset_soul_cache() -> None:
    """Reset the session cache (for testing)."""
    global _soul_cache
    _soul_cache = ...
