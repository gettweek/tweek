"""
Tweek Project Registry

Tracks known projects and their sandbox configurations.
Persisted at ~/.tweek/projects/registry.json.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .layers import IsolationLayer


TWEEK_HOME = Path.home() / ".tweek"
REGISTRY_DIR = TWEEK_HOME / "projects"
REGISTRY_PATH = REGISTRY_DIR / "registry.json"


class ProjectRegistry:
    """Manages the registry of known projects and their sandbox layers."""

    def __init__(self, registry_path: Optional[Path] = None):
        self.registry_path = registry_path or REGISTRY_PATH
        self._data = self._load()

    def _load(self) -> dict:
        """Load registry from disk."""
        if not self.registry_path.exists():
            return {"schema_version": 1, "projects": {}}
        try:
            data = json.loads(self.registry_path.read_text())
            if not isinstance(data, dict) or "projects" not in data:
                return {"schema_version": 1, "projects": {}}
            return data
        except (json.JSONDecodeError, IOError):
            return {"schema_version": 1, "projects": {}}

    def _save(self) -> None:
        """Persist registry to disk."""
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self.registry_path.write_text(json.dumps(self._data, indent=2))

    def register(
        self,
        project_dir: Path,
        layer: IsolationLayer = IsolationLayer.PROJECT,
        auto_initialized: bool = False,
    ) -> None:
        """Register a project with its sandbox layer."""
        key = str(project_dir.resolve())
        now = datetime.now(timezone.utc).isoformat()

        existing = self._data["projects"].get(key)
        if existing:
            existing["last_used"] = now
            existing["layer"] = layer.value
        else:
            self._data["projects"][key] = {
                "layer": layer.value,
                "created_at": now,
                "last_used": now,
                "auto_initialized": auto_initialized,
            }
        self._save()

    def update_last_used(self, project_dir: Path) -> None:
        """Update the last_used timestamp for a project."""
        key = str(project_dir.resolve())
        entry = self._data["projects"].get(key)
        if entry:
            entry["last_used"] = datetime.now(timezone.utc).isoformat()
            self._save()

    def get_layer(self, project_dir: Path) -> Optional[IsolationLayer]:
        """Get the configured layer for a project. Returns None if not registered."""
        key = str(project_dir.resolve())
        entry = self._data["projects"].get(key)
        if entry is None:
            return None
        return IsolationLayer.from_value(entry.get("layer", 2))

    def set_layer(self, project_dir: Path, layer: IsolationLayer) -> None:
        """Set the isolation layer for a registered project."""
        key = str(project_dir.resolve())
        entry = self._data["projects"].get(key)
        if entry is None:
            self.register(project_dir, layer)
        else:
            entry["layer"] = layer.value
            self._save()

    def deregister(self, project_dir: Path) -> bool:
        """Remove a project from the registry. Returns True if it existed."""
        key = str(project_dir.resolve())
        if key in self._data["projects"]:
            del self._data["projects"][key]
            self._save()
            return True
        return False

    def is_registered(self, project_dir: Path) -> bool:
        """Check if a project is registered."""
        key = str(project_dir.resolve())
        return key in self._data["projects"]

    def list_projects(self) -> List[Dict]:
        """List all registered projects with their info."""
        results = []
        for path_str, info in self._data["projects"].items():
            results.append({
                "path": path_str,
                "layer": IsolationLayer.from_value(info.get("layer", 2)),
                "created_at": info.get("created_at", ""),
                "last_used": info.get("last_used", ""),
                "auto_initialized": info.get("auto_initialized", False),
            })
        return results

    def cleanup_stale(self) -> int:
        """Remove entries for project directories that no longer exist."""
        stale = [
            key for key in self._data["projects"]
            if not Path(key).exists()
        ]
        for key in stale:
            del self._data["projects"][key]
        if stale:
            self._save()
        return len(stale)


# Module-level singleton
_registry: Optional[ProjectRegistry] = None


def get_registry(registry_path: Optional[Path] = None) -> ProjectRegistry:
    """Get the singleton ProjectRegistry instance."""
    global _registry
    if _registry is None:
        _registry = ProjectRegistry(registry_path)
    return _registry


def reset_registry() -> None:
    """Reset the singleton (for testing)."""
    global _registry
    _registry = None
