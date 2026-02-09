"""
Tweek Tool Name Registry — Cross-Client Tool Name Normalization

Single source of truth for mapping client-specific tool names to canonical
Tweek tool names. Canonical names use Claude Code's PascalCase convention
since they are the default throughout the existing codebase.

Capabilities group semantically equivalent tools across clients:
  - "shell_execution" covers Bash, exec, run_shell_command
  - "file_read" covers Read, read_file, read, cat
  - etc.

Design:
  - Zero external dependencies (stdlib only)
  - Module-level singleton for hot-path performance
  - Bidirectional lookup: alias → canonical, canonical → aliases
  - Case-insensitive matching with fast path for known canonical names

Supported clients:
  - Claude Code:   PascalCase (Bash, Read, Write, Edit, ...)
  - OpenClaw:      snake_case terse (exec, read, edit, write, ...)
  - Gemini CLI:    snake_case descriptive (run_shell_command, read_file, ...)
  - Anthropic API: lowercase (bash, shell, read_file, cat, ...)
"""

from __future__ import annotations

from typing import Dict, FrozenSet, Optional, Tuple


# =============================================================================
# Capability Definitions
# =============================================================================

class ToolCapability:
    """A semantic tool capability grouping aliases across clients."""

    __slots__ = ("canonical", "capability", "aliases", "description")

    def __init__(
        self,
        canonical: str,
        capability: str,
        aliases: Tuple[str, ...],
        description: str = "",
    ):
        self.canonical = canonical
        self.capability = capability
        self.aliases = aliases
        self.description = description


# =============================================================================
# The Mapping Table — the ONLY place aliases are defined
# =============================================================================

TOOL_CAPABILITIES: Tuple[ToolCapability, ...] = (
    ToolCapability(
        canonical="Bash",
        capability="shell_execution",
        aliases=(
            "bash", "exec", "shell", "execute", "run_command",
            "run_shell_command", "terminal",
        ),
        description="Execute shell commands",
    ),
    ToolCapability(
        canonical="Read",
        capability="file_read",
        aliases=("read", "read_file", "cat", "view_file"),
        description="Read file contents",
    ),
    ToolCapability(
        canonical="Write",
        capability="file_write",
        aliases=("write", "write_file", "create_file", "save_file"),
        description="Create or overwrite files",
    ),
    ToolCapability(
        canonical="Edit",
        capability="file_edit",
        aliases=("edit", "replace", "edit_file", "patch_file", "sed"),
        description="Modify existing files",
    ),
    ToolCapability(
        canonical="Glob",
        capability="file_search",
        aliases=("glob", "find_files", "list_files"),
        description="Find files by pattern",
    ),
    ToolCapability(
        canonical="Grep",
        capability="content_search",
        aliases=("grep", "grep_search", "rg", "ripgrep"),
        description="Search file contents",
    ),
    ToolCapability(
        canonical="WebFetch",
        capability="web_fetch",
        aliases=(
            "web_fetch", "webfetch", "fetch", "curl", "http",
            "url_fetch", "browser",
        ),
        description="Fetch content from URLs",
    ),
    ToolCapability(
        canonical="WebSearch",
        capability="web_search",
        aliases=(
            "web_search", "websearch", "google_web_search", "search_web",
        ),
        description="Search the web",
    ),
    ToolCapability(
        canonical="NotebookEdit",
        capability="notebook_edit",
        aliases=("notebookedit", "notebook_edit", "edit_notebook"),
        description="Edit Jupyter notebooks",
    ),
    ToolCapability(
        canonical="Task",
        capability="subagent",
        aliases=("task", "spawn_task", "subagent", "delegate"),
        description="Spawn subagent tasks",
    ),
    ToolCapability(
        canonical="Skill",
        capability="skill_invoke",
        aliases=("skill", "invoke_skill", "use_skill"),
        description="Invoke a skill",
    ),
)


# =============================================================================
# Registry
# =============================================================================

class ToolRegistry:
    """Bidirectional lookup from client tool name to canonical name.

    Built once at first access. All lookups are O(1) dict operations.

    Usage::

        from tweek.tools.registry import normalize, get_registry

        canonical = normalize("run_shell_command")  # -> "Bash"
        canonical = normalize("Bash")               # -> "Bash" (fast path)

        reg = get_registry()
        cap = reg.get_capability("Bash")            # -> "shell_execution"
    """

    def __init__(
        self,
        capabilities: Tuple[ToolCapability, ...] = TOOL_CAPABILITIES,
    ):
        # Canonical name set — fast-path identity check
        self._canonical_names: FrozenSet[str] = frozenset(
            c.canonical for c in capabilities
        )

        # alias (lowercase) → canonical name
        self._alias_to_canonical: Dict[str, str] = {}

        # canonical name → ToolCapability
        self._canonical_to_cap: Dict[str, ToolCapability] = {}

        # capability string → canonical name
        self._capability_to_canonical: Dict[str, str] = {}

        for cap in capabilities:
            self._canonical_to_cap[cap.canonical] = cap
            self._capability_to_canonical[cap.capability] = cap.canonical

            # Register canonical name as its own alias (lowercase)
            self._alias_to_canonical[cap.canonical.lower()] = cap.canonical

            # Register all aliases (lowercase); first-write wins
            for alias in cap.aliases:
                key = alias.lower()
                if key not in self._alias_to_canonical:
                    self._alias_to_canonical[key] = cap.canonical

    def normalize(self, tool_name: str) -> str:
        """Normalize a tool name to its canonical form.

        Fast path: if tool_name is already canonical (e.g. "Bash"), returns
        immediately without dict lookup. This keeps the hot path (Claude Code
        hooks, where names are already canonical) at near-zero cost.

        For unknown tool names, returns the original name unchanged.
        This ensures forward-compatibility with new tools.

        Args:
            tool_name: Client-specific tool name

        Returns:
            Canonical PascalCase tool name, or original if unknown
        """
        if tool_name in self._canonical_names:
            return tool_name
        return self._alias_to_canonical.get(tool_name.lower(), tool_name)

    def get_capability(self, tool_name: str) -> Optional[str]:
        """Get the capability category for a tool name.

        Args:
            tool_name: Any tool name (canonical or alias)

        Returns:
            Capability string (e.g. "shell_execution") or None
        """
        canonical = self.normalize(tool_name)
        cap = self._canonical_to_cap.get(canonical)
        return cap.capability if cap else None

    def get_aliases(self, canonical_name: str) -> Tuple[str, ...]:
        """Get all known aliases for a canonical tool name.

        Args:
            canonical_name: Canonical PascalCase name

        Returns:
            Tuple of alias strings, empty if unknown
        """
        cap = self._canonical_to_cap.get(canonical_name)
        return cap.aliases if cap else ()

    def is_known(self, tool_name: str) -> bool:
        """Check if a tool name (canonical or alias) is recognized."""
        if tool_name in self._canonical_names:
            return True
        return tool_name.lower() in self._alias_to_canonical

    def canonical_names(self) -> FrozenSet[str]:
        """Return the set of all canonical tool names."""
        return self._canonical_names

    def canonical_for_capability(self, capability: str) -> Optional[str]:
        """Get the canonical tool name for a capability string."""
        return self._capability_to_canonical.get(capability)


# =============================================================================
# Module-level singleton and convenience function
# =============================================================================

_registry: Optional[ToolRegistry] = None


def get_registry() -> ToolRegistry:
    """Get the module-level ToolRegistry singleton."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
    return _registry


def normalize(tool_name: str) -> str:
    """Normalize a tool name to its canonical form.

    This is the primary API for all consumers.

    Examples::

        >>> normalize("run_shell_command")
        'Bash'
        >>> normalize("Bash")
        'Bash'
        >>> normalize("read_file")
        'Read'
        >>> normalize("unknown_tool")
        'unknown_tool'
    """
    return get_registry().normalize(tool_name)
