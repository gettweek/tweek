#!/usr/bin/env python3
"""
Tweek Git Plugin Discovery

Scans ~/.tweek/plugins/ for git-installed plugins, validates them
through the security pipeline, and dynamically imports them into
the plugin registry.

Discovery Flow:
1. Scan ~/.tweek/plugins/*/tweek_plugin.json for manifests
2. Validate each manifest
3. Run security verification (checksums, AST analysis)
4. Dynamic import via importlib
5. Verify base class inheritance
6. Register in the plugin registry

Uses isolated module names (tweek_git_plugins.{name}) to avoid conflicts
with bundled plugins.
"""

import importlib
import importlib.util
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type

from tweek.plugins.git_registry import (
    PLUGINS_DIR,
    PluginRegistryClient,
    RegistryEntry,
)
from tweek.plugins.git_security import (
    PluginSecurityError,
    validate_manifest,
    validate_plugin_full,
    verify_base_class,
)

logger = logging.getLogger(__name__)

# Namespace prefix for dynamically imported git plugins
GIT_PLUGIN_MODULE_PREFIX = "tweek_git_plugins"


class PluginDiscoveryError(Exception):
    """Raised when plugin discovery fails."""
    pass


class DiscoveredPlugin:
    """Information about a discovered git plugin."""

    def __init__(
        self,
        name: str,
        version: str,
        category: str,
        plugin_class: Type,
        plugin_dir: Path,
        manifest: dict,
    ):
        self.name = name
        self.version = version
        self.category = category
        self.plugin_class = plugin_class
        self.plugin_dir = plugin_dir
        self.manifest = manifest

    def __repr__(self) -> str:
        return f"DiscoveredPlugin(name={self.name!r}, version={self.version!r}, category={self.category!r})"


def discover_git_plugins(
    registry_client: Optional[PluginRegistryClient] = None,
    plugins_dir: Optional[Path] = None,
    skip_security: bool = False,
) -> List[DiscoveredPlugin]:
    """
    Scan for and validate git-installed plugins.

    Args:
        registry_client: Registry client for checksum lookups
        plugins_dir: Override plugins directory (default: ~/.tweek/plugins/)
        skip_security: Skip security validation (for development only)

    Returns:
        List of successfully discovered and validated plugins
    """
    plugins_dir = plugins_dir or PLUGINS_DIR
    discovered = []

    if not plugins_dir.exists():
        logger.debug(f"Plugins directory does not exist: {plugins_dir}")
        return discovered

    for plugin_dir in sorted(plugins_dir.iterdir()):
        if not plugin_dir.is_dir():
            continue

        # Skip hidden directories
        if plugin_dir.name.startswith("."):
            continue

        manifest_path = plugin_dir / "tweek_plugin.json"
        if not manifest_path.exists():
            logger.debug(f"No manifest in {plugin_dir.name}, skipping")
            continue

        try:
            plugin = _discover_single_plugin(
                plugin_dir=plugin_dir,
                registry_client=registry_client,
                skip_security=skip_security,
            )
            if plugin:
                discovered.append(plugin)
                logger.info(
                    f"Discovered git plugin: {plugin.name} v{plugin.version} "
                    f"({plugin.category})"
                )
        except (PluginSecurityError, PluginDiscoveryError) as e:
            logger.warning(f"Failed to load plugin from {plugin_dir.name}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error loading {plugin_dir.name}: {e}")

    logger.info(f"Discovered {len(discovered)} git plugin(s)")
    return discovered


def _discover_single_plugin(
    plugin_dir: Path,
    registry_client: Optional[PluginRegistryClient] = None,
    skip_security: bool = False,
) -> Optional[DiscoveredPlugin]:
    """
    Discover and validate a single plugin from a directory.

    Args:
        plugin_dir: Path to the plugin directory
        registry_client: Registry client for checksum lookups
        skip_security: Skip security validation

    Returns:
        DiscoveredPlugin if successful, None otherwise

    Raises:
        PluginSecurityError: If security validation fails
        PluginDiscoveryError: If plugin cannot be loaded
    """
    # Step 1: Validate manifest
    manifest_path = plugin_dir / "tweek_plugin.json"
    valid, manifest, issues = validate_manifest(manifest_path)
    if not valid:
        raise PluginDiscoveryError(
            f"Invalid manifest: {'; '.join(issues)}"
        )

    name = manifest["name"]
    version = manifest["version"]
    category = manifest["category"]
    entry_point = manifest["entry_point"]

    # Step 2: Check version compatibility
    min_tweek = manifest.get("min_tweek_version")
    max_tweek = manifest.get("max_tweek_version")
    if not _check_version_compat(min_tweek, max_tweek):
        raise PluginDiscoveryError(
            f"Plugin {name} v{version} is not compatible with this version of Tweek. "
            f"Requires: {min_tweek or '*'} - {max_tweek or '*'}"
        )

    # Step 3: Security validation
    if not skip_security:
        registry_checksums = None
        if registry_client:
            entry = registry_client.get_plugin(name)
            if entry:
                registry_checksums = entry.get_checksums(version)

        is_safe, security_issues = validate_plugin_full(
            plugin_dir,
            manifest,
            registry_checksums=registry_checksums,
            skip_signature=False,
        )

        if not is_safe:
            raise PluginSecurityError(
                f"Plugin {name} failed security validation: {'; '.join(security_issues)}"
            )

    # Step 4: Dynamic import
    plugin_class = _import_plugin_class(plugin_dir, entry_point, name)

    # Step 5: Verify base class
    valid, error = verify_base_class(plugin_class, category)
    if not valid:
        raise PluginDiscoveryError(f"Base class verification failed: {error}")

    return DiscoveredPlugin(
        name=name,
        version=version,
        category=category,
        plugin_class=plugin_class,
        plugin_dir=plugin_dir,
        manifest=manifest,
    )


def _import_plugin_class(
    plugin_dir: Path,
    entry_point: str,
    plugin_name: str,
) -> Type:
    """
    Dynamically import a plugin class from its entry point.

    Entry point format: "module:ClassName"
    e.g., "plugin:CursorDetector" imports CursorDetector from plugin.py

    Uses isolated module names to avoid conflicts with bundled plugins:
    tweek_git_plugins.{plugin_name}.{module}

    Args:
        plugin_dir: Path to the plugin directory
        entry_point: Entry point string ("module:ClassName")
        plugin_name: Plugin name for module namespace

    Returns:
        The plugin class

    Raises:
        PluginDiscoveryError: If import fails
    """
    if ":" not in entry_point:
        raise PluginDiscoveryError(
            f"Invalid entry_point format '{entry_point}'. "
            f"Must be 'module:ClassName'"
        )

    module_name, class_name = entry_point.split(":", 1)

    # Construct file path and validate against path traversal
    module_file = (plugin_dir / f"{module_name}.py").resolve()
    if not module_file.is_relative_to(plugin_dir.resolve()):
        raise PluginDiscoveryError(
            f"Entry point module '{module_name}' escapes plugin directory (path traversal blocked)"
        )
    if not module_file.exists():
        raise PluginDiscoveryError(
            f"Entry point module '{module_name}.py' not found in {plugin_dir}"
        )

    # Create isolated module name
    full_module_name = f"{GIT_PLUGIN_MODULE_PREFIX}.{plugin_name}.{module_name}"

    try:
        # Load module from file
        spec = importlib.util.spec_from_file_location(
            full_module_name,
            str(module_file),
        )
        if spec is None:
            raise PluginDiscoveryError(
                f"Could not create module spec for {module_file}"
            )

        module = importlib.util.module_from_spec(spec)

        # Add plugin directory to the module's path for relative imports
        # Use try/finally to ensure sys.path is always cleaned up
        path_added = False
        if str(plugin_dir) not in sys.path:
            sys.path.insert(0, str(plugin_dir))
            path_added = True

        # Register the module in sys.modules before executing
        sys.modules[full_module_name] = module

        try:
            spec.loader.exec_module(module)
        finally:
            # Always remove plugin dir from sys.path to prevent pollution
            if path_added and str(plugin_dir) in sys.path:
                sys.path.remove(str(plugin_dir))

        # Get the class
        if not hasattr(module, class_name):
            raise PluginDiscoveryError(
                f"Class '{class_name}' not found in module '{module_name}'. "
                f"Available: {[n for n in dir(module) if not n.startswith('_')]}"
            )

        plugin_class = getattr(module, class_name)

        if not isinstance(plugin_class, type):
            raise PluginDiscoveryError(
                f"'{class_name}' in '{module_name}' is not a class"
            )

        return plugin_class

    except ImportError as e:
        raise PluginDiscoveryError(
            f"Failed to import plugin: {e}"
        ) from e
    except Exception as e:
        if isinstance(e, PluginDiscoveryError):
            raise
        raise PluginDiscoveryError(
            f"Error loading plugin module: {e}"
        ) from e
    finally:
        # Clean up sys.path (only remove if we added it)
        try:
            sys.path.remove(str(plugin_dir))
        except ValueError:
            pass


def _check_version_compat(
    min_version: Optional[str],
    max_version: Optional[str],
) -> bool:
    """
    Check if the current Tweek version is compatible with plugin requirements.

    Args:
        min_version: Minimum Tweek version required (or None for no minimum)
        max_version: Maximum Tweek version allowed (or None for no maximum)

    Returns:
        True if compatible
    """
    # Get current Tweek version
    try:
        from tweek import __version__ as tweek_version
    except ImportError:
        # If we can't determine version, assume compatible
        return True

    if not tweek_version:
        return True

    try:
        current = _parse_version(tweek_version)
    except ValueError:
        return True

    if min_version:
        try:
            minimum = _parse_version(min_version)
            if current < minimum:
                return False
        except ValueError:
            pass

    if max_version:
        try:
            maximum = _parse_version(max_version)
            if current > maximum:
                return False
        except ValueError:
            pass

    return True


def _parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse a version string into a comparable tuple."""
    parts = version_str.strip().split(".")
    return tuple(int(p) for p in parts)


def get_plugin_info(plugin_dir: Path) -> Optional[Dict[str, Any]]:
    """
    Get information about a single git plugin directory.

    Args:
        plugin_dir: Path to the plugin directory

    Returns:
        Dict with plugin info, or None if invalid
    """
    manifest_path = plugin_dir / "tweek_plugin.json"
    if not manifest_path.exists():
        return None

    try:
        with open(manifest_path) as f:
            manifest = json.load(f)

        return {
            "name": manifest.get("name", plugin_dir.name),
            "version": manifest.get("version", "unknown"),
            "category": manifest.get("category", "unknown"),
            "description": manifest.get("description", ""),
            "author": manifest.get("author", ""),
            "requires_license_tier": manifest.get("requires_license_tier", "free"),
            "tags": manifest.get("tags", []),
            "path": str(plugin_dir),
            "source": "git",
        }
    except (json.JSONDecodeError, IOError):
        return None
