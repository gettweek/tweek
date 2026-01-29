#!/usr/bin/env python3
"""
Plugin Scoping System

Allows plugins to be scoped to specific tools, skills, projects, tiers,
and scan directions. Plugins without a scope run globally (default behavior).

Example scope config:
    scope:
      tools: [Bash, WebFetch, Write]
      skills: [email-search, patient-records]
      projects: ["/Users/me/healthcare-app"]
      tiers: [risky, dangerous]
      directions: [input, output]
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
import logging

from tweek.screening.context import ScreeningContext

logger = logging.getLogger(__name__)


@dataclass
class PluginScope:
    """
    Defines when a plugin should be active.

    Each field is a filter. None means "match everything" (no restriction).
    When a field is set, the context must match at least one value in the list.

    All non-None fields must match for the scope to match (AND logic).
    Within a field, any value can match (OR logic).
    """
    tools: Optional[List[str]] = None
    skills: Optional[List[str]] = None
    projects: Optional[List[str]] = None
    tiers: Optional[List[str]] = None
    directions: Optional[List[str]] = None

    def matches(self, context: ScreeningContext) -> bool:
        """
        Check if this plugin should run given the context.

        Returns True if all specified scope filters match the context.
        Unset filters (None) always match.

        Args:
            context: The current screening context

        Returns:
            True if the plugin should be active for this context
        """
        # Tools: If specified, tool_name must be in the list
        if self.tools is not None:
            if context.tool_name not in self.tools:
                return False

        # Skills: If specified, context must have a matching skill_name
        # If skill_name is None in context, we don't filter by skill
        # (avoids blocking when skill info isn't available)
        if self.skills is not None:
            if context.skill_name is not None and context.skill_name not in self.skills:
                return False

        # Projects: If specified, working_dir must be under one of the project paths
        if self.projects is not None:
            if not any(
                context.working_dir.startswith(p)
                for p in self.projects
            ):
                return False

        # Tiers: If specified, effective tier must match
        if self.tiers is not None:
            if context.tier not in self.tiers:
                return False

        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {}
        if self.tools is not None:
            result["tools"] = self.tools
        if self.skills is not None:
            result["skills"] = self.skills
        if self.projects is not None:
            result["projects"] = self.projects
        if self.tiers is not None:
            result["tiers"] = self.tiers
        if self.directions is not None:
            result["directions"] = self.directions
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PluginScope":
        """Create a PluginScope from a dictionary (e.g., from config YAML)."""
        return cls(
            tools=data.get("tools"),
            skills=data.get("skills"),
            projects=data.get("projects"),
            tiers=data.get("tiers"),
            directions=data.get("directions"),
        )

    @property
    def is_global(self) -> bool:
        """Returns True if this scope has no restrictions (matches everything)."""
        return all(
            v is None
            for v in [self.tools, self.skills, self.projects, self.tiers, self.directions]
        )

    def describe(self) -> str:
        """Human-readable description of the scope."""
        parts = []
        if self.tools is not None:
            parts.append(f"Tools: {', '.join(self.tools)}")
        if self.skills is not None:
            parts.append(f"Skills: {', '.join(self.skills)}")
        if self.projects is not None:
            parts.append(f"Projects: {', '.join(self.projects)}")
        if self.tiers is not None:
            parts.append(f"Tiers: {', '.join(self.tiers)}")
        if self.directions is not None:
            parts.append(f"Directions: {', '.join(self.directions)}")
        return " | ".join(parts) if parts else "Global (no restrictions)"
