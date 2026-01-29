#!/usr/bin/env python3
"""
Screening Context - Full context available to the screening engine.

The ScreeningContext carries all information needed by plugins to make
scoping and screening decisions. It is passed through all three
interception layers (hooks, MCP gateway, HTTP proxy).
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class ScreeningContext:
    """
    Full context available to the screening engine.

    Passed to all screening and compliance plugins so they can make
    informed decisions about whether to activate and what to scan.

    Attributes:
        tool_name: The tool being invoked (e.g., "Bash", "Read", "Write")
        content: The content/command to screen
        tier: Effective security tier ("safe", "default", "risky", "dangerous")
        working_dir: Current working directory
        session_id: Optional session identifier for cross-turn analysis
        skill_name: Which Claude skill invoked this (if known)
        source: Which interception layer ("hooks", "mcp", "proxy")
        client_name: Desktop client name ("claude-desktop", "chatgpt", "gemini-cli")
        mcp_server: Name of proxied MCP server (if applicable)
        project_config_path: Path to project-level config (if found)
        tool_input: Raw tool input dict for detailed analysis
        metadata: Additional metadata for plugin-specific use
    """
    tool_name: str
    content: str
    tier: str
    working_dir: str
    session_id: Optional[str] = None
    skill_name: Optional[str] = None
    source: str = "hooks"
    client_name: Optional[str] = None
    mcp_server: Optional[str] = None
    project_config_path: Optional[str] = None
    tool_input: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for legacy plugin compatibility."""
        return {
            "tool_name": self.tool_name,
            "content": self.content,
            "tier": self.tier,
            "working_dir": self.working_dir,
            "session_id": self.session_id,
            "skill_name": self.skill_name,
            "source": self.source,
            "client_name": self.client_name,
            "mcp_server": self.mcp_server,
            "project_config_path": self.project_config_path,
            "tool_input": self.tool_input,
        }

    def to_legacy_dict(self) -> Dict[str, Any]:
        """
        Convert to the legacy context dict format used by existing
        screening plugins.

        This ensures backward compatibility with plugins that expect:
        {"session_id": ..., "tier": ..., "tool_name": ..., "working_dir": ...}
        """
        result = {
            "session_id": self.session_id,
            "tier": self.tier,
            "tool_name": self.tool_name,
            "working_dir": self.working_dir,
        }
        if self.tool_input:
            result["tool_input"] = self.tool_input
        return result
