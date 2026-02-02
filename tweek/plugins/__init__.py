#!/usr/bin/env python3
"""
Tweek Plugin System

Modular plugin architecture supporting:
- Domain compliance modules (Gov, HIPAA, PCI, Legal)
- LLM provider plugins (Anthropic, OpenAI, Google, Bedrock)
- Tool detector plugins (openclaw, Cursor, Continue)
- Screening method plugins (rate limiting, pattern matching, LLM review)

Plugin Discovery:
- Built-in plugins are registered automatically
- External plugins discovered via Python entry_points
- Plugins can be enabled/disabled via configuration

License Tiers:
- FREE: Core pattern matching, basic screening
- PRO: LLM review, session analysis, rate limiting
- ENTERPRISE: Compliance modules (Gov, HIPAA, PCI, Legal)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, List, Any, Type, Callable
from importlib.metadata import entry_points
import logging
import threading

logger = logging.getLogger(__name__)

# Thread lock for singleton pattern
_registry_lock = threading.Lock()


class PluginSource(Enum):
    """How a plugin was installed/discovered."""
    BUILTIN = "builtin"        # Bundled with Tweek
    GIT = "git"                # Installed from git repository
    ENTRY_POINT = "entry_point"  # Discovered via Python entry_points


class PluginCategory(Enum):
    """Categories of plugins supported by Tweek."""
    COMPLIANCE = "tweek.compliance"          # Gov, HIPAA, PCI, Legal
    LLM_PROVIDER = "tweek.llm_providers"     # Anthropic, OpenAI, etc.
    TOOL_DETECTOR = "tweek.tool_detectors"   # openclaw, Cursor, etc.
    SCREENING = "tweek.screening"            # rate_limiter, pattern_matcher


class LicenseTier(Enum):
    """License tiers for plugin access."""
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


@dataclass
class PluginMetadata:
    """Metadata describing a plugin."""
    name: str
    version: str
    category: PluginCategory
    description: str
    author: Optional[str] = None
    requires_license: LicenseTier = LicenseTier.FREE
    homepage: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        # Ensure tags is a list
        if self.tags is None:
            self.tags = []


@dataclass
class PluginInfo:
    """Runtime information about a loaded plugin."""
    metadata: PluginMetadata
    plugin_class: Type
    instance: Optional[Any] = None
    enabled: bool = True
    load_error: Optional[str] = None
    source: PluginSource = PluginSource.BUILTIN
    install_path: Optional[str] = None
    manifest: Optional[Dict[str, Any]] = None

    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def category(self) -> PluginCategory:
        return self.metadata.category


class PluginRegistry:
    """
    Central registry for all Tweek plugins.

    Handles plugin discovery, registration, and lifecycle management.
    Supports both built-in plugins and external plugins via entry_points.
    """

    def __init__(self):
        self._plugins: Dict[PluginCategory, Dict[str, PluginInfo]] = {
            category: {} for category in PluginCategory
        }
        self._config: Dict[str, Dict[str, Any]] = {}
        self._license_checker: Optional[Callable[[LicenseTier], bool]] = None

    def set_license_checker(self, checker: Callable[[LicenseTier], bool]) -> None:
        """
        Set a function to check if a license tier is available.

        Args:
            checker: Function that takes LicenseTier and returns True if available
        """
        self._license_checker = checker

    def _check_license(self, required: LicenseTier) -> bool:
        """Check if the required license tier is available."""
        if self._license_checker is None:
            # No checker set - allow FREE tier only
            return required == LicenseTier.FREE

        return self._license_checker(required)

    def _log_plugin_event(self, operation: str, **kwargs):
        """Log plugin event to security logger (never raises)."""
        try:
            from tweek.logging.security_log import get_logger as get_sec_logger, SecurityEvent, EventType
            metadata = {"operation": operation, **kwargs}
            get_sec_logger().log(SecurityEvent(
                event_type=EventType.PLUGIN_EVENT,
                tool_name="plugin_registry",
                decision="allow",
                metadata=metadata,
                source="plugins",
            ))
        except Exception:
            pass

    def discover_plugins(self) -> int:
        """
        Discover plugins via Python entry_points.

        Compatible with Python 3.9, 3.10, 3.11, and 3.12.

        Returns:
            Number of plugins discovered
        """
        discovered = 0

        for category in PluginCategory:
            eps = self._get_entry_points(category.value)

            for ep in eps:
                try:
                    plugin_class = ep.load()
                    self.register(ep.name, plugin_class, category)
                    discovered += 1
                    logger.debug(f"Discovered plugin: {ep.name} ({category.value})")
                except Exception as e:
                    logger.warning(f"Failed to load plugin {ep.name}: {e}")
                    self._log_plugin_event(
                        "discover_failed", plugin=ep.name, category=category.value, error=str(e)
                    )

        if discovered > 0:
            self._log_plugin_event("discover_complete", discovered_count=discovered)

        return discovered

    def _get_entry_points(self, group: str) -> List:
        """
        Get entry points for a group, compatible with Python 3.9+.

        Python 3.9: entry_points() returns dict-like SelectableGroups
        Python 3.10+: entry_points(group=...) returns EntryPoints directly

        Args:
            group: The entry point group name

        Returns:
            List of entry points (may be empty)
        """
        import sys

        try:
            if sys.version_info >= (3, 10):
                # Python 3.10+ - use keyword argument
                return list(entry_points(group=group))
            else:
                # Python 3.9 - returns dict-like SelectableGroups
                all_eps = entry_points()

                # In Python 3.9, entry_points() returns SelectableGroups
                # which is dict-like with group names as keys
                if hasattr(all_eps, 'get'):
                    # Standard dict-like access
                    return list(all_eps.get(group, []))
                elif hasattr(all_eps, 'select'):
                    # Some versions support select()
                    return list(all_eps.select(group=group))
                else:
                    # Fallback: iterate and filter
                    return [ep for ep in all_eps if getattr(ep, 'group', None) == group]

        except Exception as e:
            logger.warning(f"Failed to get entry points for {group}: {e}")
            return []

    def register(
        self,
        name: str,
        plugin_class: Type,
        category: PluginCategory,
        metadata: Optional[PluginMetadata] = None,
        source: PluginSource = PluginSource.BUILTIN,
        install_path: Optional[str] = None,
        manifest: Optional[Dict[str, Any]] = None,
        override: bool = False,
    ) -> bool:
        """
        Register a plugin.

        Args:
            name: Plugin name (must be unique within category)
            plugin_class: Plugin class (not instance)
            category: Plugin category
            metadata: Optional metadata (extracted from class if not provided)
            source: How the plugin was installed (builtin, git, entry_point)
            install_path: Filesystem path for git-installed plugins
            manifest: Parsed manifest dict for git-installed plugins
            override: If True, replace existing registration (for git overriding builtin)

        Returns:
            True if registered successfully
        """
        # Extract metadata from class if not provided
        if metadata is None:
            metadata = self._extract_metadata(name, plugin_class, category)

        # Check if already registered
        if name in self._plugins[category]:
            if override:
                logger.info(
                    f"Git plugin {name} overriding builtin in {category.value}"
                )
            else:
                logger.debug(f"Plugin {name} already registered in {category.value}")
                return False

        # Create plugin info
        info = PluginInfo(
            metadata=metadata,
            plugin_class=plugin_class,
            enabled=True,
            source=source,
            install_path=install_path,
            manifest=manifest,
        )

        self._plugins[category][name] = info
        logger.debug(f"Registered plugin: {name} ({category.value}, source={source.value})")
        self._log_plugin_event(
            "register", plugin=name, category=category.value, source=source.value
        )
        return True

    def _extract_metadata(
        self,
        name: str,
        plugin_class: Type,
        category: PluginCategory
    ) -> PluginMetadata:
        """Extract metadata from a plugin class."""
        # Try to get metadata from class attributes
        version = getattr(plugin_class, 'VERSION', '0.0.0')
        description = getattr(plugin_class, 'DESCRIPTION', plugin_class.__doc__ or '')
        author = getattr(plugin_class, 'AUTHOR', None)
        requires_license = getattr(plugin_class, 'REQUIRES_LICENSE', LicenseTier.FREE)
        tags = getattr(plugin_class, 'TAGS', [])

        # Handle string license tier
        if isinstance(requires_license, str):
            try:
                requires_license = LicenseTier(requires_license)
            except ValueError:
                requires_license = LicenseTier.FREE

        return PluginMetadata(
            name=name,
            version=version,
            category=category,
            description=description.strip() if description else '',
            author=author,
            requires_license=requires_license,
            tags=tags
        )

    def unregister(self, name: str, category: PluginCategory) -> bool:
        """
        Unregister a plugin.

        Args:
            name: Plugin name
            category: Plugin category

        Returns:
            True if unregistered successfully
        """
        if name in self._plugins[category]:
            del self._plugins[category][name]
            return True
        return False

    def get(
        self,
        name: str,
        category: PluginCategory,
        instantiate: bool = True
    ) -> Optional[Any]:
        """
        Get a plugin instance.

        Args:
            name: Plugin name
            category: Plugin category
            instantiate: If True, return instance; if False, return class

        Returns:
            Plugin instance/class if found and enabled, None otherwise
        """
        info = self._plugins[category].get(name)
        if info is None:
            return None

        if not info.enabled:
            return None

        # Check license
        if not self._check_license(info.metadata.requires_license):
            logger.debug(
                f"Plugin {name} requires {info.metadata.requires_license.value} license"
            )
            return None

        if not instantiate:
            return info.plugin_class

        # Lazy instantiation
        if info.instance is None:
            try:
                config = self._config.get(name, {})
                info.instance = info.plugin_class(config) if config else info.plugin_class()
            except Exception as e:
                info.load_error = str(e)
                logger.error(f"Failed to instantiate plugin {name}: {e}")
                self._log_plugin_event(
                    "instantiate_failed", plugin=name, category=category.value, error=str(e)
                )
                return None

        return info.instance

    def get_info(self, name: str, category: PluginCategory) -> Optional[PluginInfo]:
        """Get plugin info without instantiating."""
        return self._plugins[category].get(name)

    def get_all(
        self,
        category: PluginCategory,
        enabled_only: bool = True,
        licensed_only: bool = True
    ) -> List[Any]:
        """
        Get all plugins in a category.

        Args:
            category: Plugin category
            enabled_only: Only return enabled plugins
            licensed_only: Only return plugins user has license for

        Returns:
            List of plugin instances
        """
        plugins = []

        for name, info in self._plugins[category].items():
            if enabled_only and not info.enabled:
                continue

            if licensed_only and not self._check_license(info.metadata.requires_license):
                continue

            instance = self.get(name, category)
            if instance is not None:
                plugins.append(instance)

        return plugins

    def list_plugins(
        self,
        category: Optional[PluginCategory] = None
    ) -> List[PluginInfo]:
        """
        List all registered plugins.

        Args:
            category: Optional category filter

        Returns:
            List of PluginInfo objects
        """
        plugins = []

        categories = [category] if category else list(PluginCategory)

        for cat in categories:
            plugins.extend(self._plugins[cat].values())

        return plugins

    def enable(self, name: str, category: PluginCategory) -> bool:
        """Enable a plugin."""
        info = self._plugins[category].get(name)
        if info:
            info.enabled = True
            return True
        return False

    def disable(self, name: str, category: PluginCategory) -> bool:
        """Disable a plugin."""
        info = self._plugins[category].get(name)
        if info:
            info.enabled = False
            return True
        return False

    def is_enabled(self, name: str, category: PluginCategory) -> bool:
        """Check if a plugin is enabled."""
        info = self._plugins[category].get(name)
        return info.enabled if info else False

    def configure(self, name: str, config: Dict[str, Any], invalidate: bool = True) -> None:
        """
        Set configuration for a plugin.

        Args:
            name: Plugin name
            config: Configuration dictionary
            invalidate: If True, invalidate existing instance to force recreation
                       with new config (recommended for config changes)
        """
        self._config[name] = config

        # Handle existing instances
        for category in PluginCategory:
            info = self._plugins[category].get(name)
            if info and info.instance:
                if invalidate:
                    # Invalidate instance so it gets recreated with new config
                    # on next access via get()
                    info.instance = None
                    info.load_error = None
                elif hasattr(info.instance, 'configure'):
                    # Try hot-reconfiguration (for backward compatibility)
                    info.instance.configure(config)

    def get_config(self, name: str) -> Dict[str, Any]:
        """Get configuration for a plugin."""
        return self._config.get(name, {})

    def load_config(self, config: Dict[str, Any]) -> None:
        """
        Load plugin configuration from a dictionary.

        Expected format:
        {
            "plugins": {
                "compliance": {
                    "gov": {"enabled": true, "actions": {...}},
                    "hipaa": {"enabled": false}
                },
                "screening": {
                    "rate_limiter": {"enabled": true, "burst_threshold": 15}
                }
            }
        }
        """
        plugins_config = config.get("plugins", {})

        # Map category names to enums
        category_map = {
            "compliance": PluginCategory.COMPLIANCE,
            "providers": PluginCategory.LLM_PROVIDER,
            "detectors": PluginCategory.TOOL_DETECTOR,
            "screening": PluginCategory.SCREENING,
        }

        for cat_name, cat_config in plugins_config.items():
            category = category_map.get(cat_name)
            if category is None:
                continue

            # Handle "modules" sub-key or direct plugin configs
            modules = cat_config.get("modules", cat_config)
            if not isinstance(modules, dict):
                continue

            for plugin_name, plugin_config in modules.items():
                if not isinstance(plugin_config, dict):
                    continue

                # Enable/disable
                if "enabled" in plugin_config:
                    if plugin_config["enabled"]:
                        self.enable(plugin_name, category)
                    else:
                        self.disable(plugin_name, category)

                # Store config
                self.configure(plugin_name, plugin_config)

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about registered plugins."""
        stats = {
            "total": 0,
            "enabled": 0,
            "by_category": {},
            "by_license": {tier.value: 0 for tier in LicenseTier}
        }

        for category in PluginCategory:
            cat_stats = {"total": 0, "enabled": 0}

            for info in self._plugins[category].values():
                stats["total"] += 1
                cat_stats["total"] += 1
                stats["by_license"][info.metadata.requires_license.value] += 1

                if info.enabled:
                    stats["enabled"] += 1
                    cat_stats["enabled"] += 1

            stats["by_category"][category.value] = cat_stats

        return stats


# Global registry instance
_registry: Optional[PluginRegistry] = None
_initialized: bool = False


def get_registry() -> PluginRegistry:
    """
    Get the global plugin registry.

    Thread-safe singleton pattern using double-checked locking.
    """
    global _registry
    if _registry is None:
        with _registry_lock:
            # Double-check after acquiring lock
            if _registry is None:
                _registry = PluginRegistry()
    return _registry


def init_plugins(config: Optional[Dict[str, Any]] = None) -> PluginRegistry:
    """
    Initialize the plugin system.

    Loads plugins in order:
    1. Built-in plugins (bundled with Tweek)
    2. Git-installed plugins (~/.tweek/plugins/)
    3. Entry point plugins (from installed packages)

    Git plugins with the same name as a builtin will override the builtin.
    Safe to call multiple times — plugin discovery only runs once.

    Args:
        config: Optional configuration dictionary

    Returns:
        The initialized plugin registry
    """
    global _initialized
    registry = get_registry()

    if not _initialized:
        # Log startup
        try:
            from tweek.logging.security_log import get_logger as get_sec_logger, SecurityEvent, EventType
            get_sec_logger().log(SecurityEvent(
                event_type=EventType.STARTUP,
                tool_name="plugin_system",
                decision="allow",
                metadata={"operation": "init_plugins"},
                source="plugins",
            ))
        except Exception:
            pass

        # Register built-in plugins
        _register_builtin_plugins(registry)

        # Discover git-installed plugins
        _discover_git_plugins(registry)

        # Discover external plugins via entry_points
        registry.discover_plugins()

        _initialized = True

    # Load configuration (always applied, even on subsequent calls)
    if config:
        registry.load_config(config)

    # Set up license checker
    try:
        from tweek.licensing import get_license, Tier

        def check_license(required: LicenseTier) -> bool:
            """
            Check if the user's license tier meets the required tier.

            Tier hierarchy: FREE < PRO < ENTERPRISE
            Higher tiers include all lower tier features.
            """
            lic = get_license()
            tier_order = [Tier.FREE, Tier.PRO, Tier.ENTERPRISE]

            # Map plugin LicenseTier to licensing Tier
            tier_map = {
                LicenseTier.FREE: Tier.FREE,
                LicenseTier.PRO: Tier.PRO,
                LicenseTier.ENTERPRISE: Tier.ENTERPRISE,
            }

            required_tier = tier_map.get(required, Tier.FREE)
            user_tier = lic.tier

            # User has access if their tier is >= required tier
            return tier_order.index(user_tier) >= tier_order.index(required_tier)

        registry.set_license_checker(check_license)
    except ImportError:
        pass

    return registry


def _register_builtin_plugins(registry: PluginRegistry) -> None:
    """Register all built-in plugins."""
    # Compliance plugins
    try:
        from tweek.plugins.compliance import (
            GovCompliancePlugin,
            HIPAACompliancePlugin,
            PCICompliancePlugin,
            LegalCompliancePlugin,
            SOC2CompliancePlugin,
            GDPRCompliancePlugin,
        )
        registry.register("gov", GovCompliancePlugin, PluginCategory.COMPLIANCE)
        registry.register("hipaa", HIPAACompliancePlugin, PluginCategory.COMPLIANCE)
        registry.register("pci", PCICompliancePlugin, PluginCategory.COMPLIANCE)
        registry.register("legal", LegalCompliancePlugin, PluginCategory.COMPLIANCE)
        registry.register("soc2", SOC2CompliancePlugin, PluginCategory.COMPLIANCE)
        registry.register("gdpr", GDPRCompliancePlugin, PluginCategory.COMPLIANCE)
    except ImportError as e:
        logger.debug(f"Compliance plugins not available: {e}")

    # Provider plugins
    try:
        from tweek.plugins.providers import (
            AnthropicProvider,
            OpenAIProvider,
            AzureOpenAIProvider,
            GoogleProvider,
            BedrockProvider,
        )
        registry.register("anthropic", AnthropicProvider, PluginCategory.LLM_PROVIDER)
        registry.register("openai", OpenAIProvider, PluginCategory.LLM_PROVIDER)
        registry.register("azure_openai", AzureOpenAIProvider, PluginCategory.LLM_PROVIDER)
        registry.register("google", GoogleProvider, PluginCategory.LLM_PROVIDER)
        registry.register("bedrock", BedrockProvider, PluginCategory.LLM_PROVIDER)
    except ImportError as e:
        logger.debug(f"Provider plugins not available: {e}")

    # Detector plugins
    try:
        from tweek.plugins.detectors import (
            OpenClawDetector,
            CursorDetector,
            ContinueDetector,
            CopilotDetector,
            WindsurfDetector,
        )
        registry.register("openclaw", OpenClawDetector, PluginCategory.TOOL_DETECTOR)
        registry.register("cursor", CursorDetector, PluginCategory.TOOL_DETECTOR)
        registry.register("continue", ContinueDetector, PluginCategory.TOOL_DETECTOR)
        registry.register("copilot", CopilotDetector, PluginCategory.TOOL_DETECTOR)
        registry.register("windsurf", WindsurfDetector, PluginCategory.TOOL_DETECTOR)
    except ImportError as e:
        logger.debug(f"Detector plugins not available: {e}")

    # Screening plugins
    try:
        from tweek.plugins.screening import (
            RateLimiterPlugin,
            PatternMatcherPlugin,
            HeuristicScorerPlugin,
            LLMReviewerPlugin,
            SessionAnalyzerPlugin,
        )
        registry.register("rate_limiter", RateLimiterPlugin, PluginCategory.SCREENING)
        registry.register("pattern_matcher", PatternMatcherPlugin, PluginCategory.SCREENING)
        registry.register("heuristic_scorer", HeuristicScorerPlugin, PluginCategory.SCREENING)
        registry.register("llm_reviewer", LLMReviewerPlugin, PluginCategory.SCREENING)
        registry.register("session_analyzer", SessionAnalyzerPlugin, PluginCategory.SCREENING)
    except ImportError as e:
        logger.debug(f"Screening plugins not available: {e}")

    # Local model reviewer plugin (optional — requires tweek[local-models])
    try:
        from tweek.plugins.screening.local_model_reviewer import LocalModelReviewerPlugin
        if LocalModelReviewerPlugin is not None:
            registry.register("local_model_reviewer", LocalModelReviewerPlugin, PluginCategory.SCREENING)
    except ImportError:
        pass


def _discover_git_plugins(registry: PluginRegistry) -> int:
    """
    Discover and register git-installed plugins from ~/.tweek/plugins/.

    Git plugins override builtins with the same name, allowing users
    to use newer versions of bundled plugins via git.

    Returns:
        Number of git plugins registered
    """
    try:
        from tweek.plugins.git_discovery import discover_git_plugins
        from tweek.plugins.git_registry import PluginRegistryClient
    except ImportError:
        logger.debug("Git plugin discovery modules not available")
        return 0

    # Map manifest categories to PluginCategory enum
    category_map = {
        "compliance": PluginCategory.COMPLIANCE,
        "providers": PluginCategory.LLM_PROVIDER,
        "detectors": PluginCategory.TOOL_DETECTOR,
        "screening": PluginCategory.SCREENING,
    }

    registered = 0
    try:
        registry_client = PluginRegistryClient()
        plugins = discover_git_plugins(registry_client=registry_client)

        for plugin in plugins:
            category = category_map.get(plugin.category)
            if category is None:
                logger.warning(
                    f"Git plugin {plugin.name} has unknown category: {plugin.category}"
                )
                continue

            # Derive a short name from the full plugin name
            # e.g., "tweek-plugin-cursor-detector" -> "cursor"
            short_name = _derive_short_name(plugin.name, plugin.category)

            # Git plugins override builtins
            already_registered = short_name in registry._plugins.get(category, {})

            success = registry.register(
                name=short_name,
                plugin_class=plugin.plugin_class,
                category=category,
                source=PluginSource.GIT,
                install_path=str(plugin.plugin_dir),
                manifest=plugin.manifest,
                override=already_registered,
            )

            if success:
                registered += 1

    except Exception as e:
        logger.warning(f"Git plugin discovery failed: {e}")
        try:
            from tweek.logging.security_log import get_logger as get_sec_logger, SecurityEvent, EventType
            get_sec_logger().log(SecurityEvent(
                event_type=EventType.PLUGIN_EVENT,
                tool_name="plugin_registry",
                decision="error",
                decision_reason=f"Git plugin discovery failed: {e}",
                source="plugins",
            ))
        except Exception:
            pass

    if registered > 0:
        logger.info(f"Registered {registered} git plugin(s)")

    return registered


def _derive_short_name(full_name: str, category: str) -> str:
    """
    Derive a short plugin name from the full registry name.

    Examples:
        "tweek-plugin-cursor-detector" -> "cursor"
        "tweek-plugin-hipaa" -> "hipaa"
        "tweek-plugin-openai-provider" -> "openai"
    """
    # Remove common prefixes
    name = full_name
    for prefix in ("tweek-plugin-", "tweek-"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break

    # Remove common suffixes
    for suffix in ("-detector", "-provider", "-plugin", "-compliance", "-screening"):
        if name.endswith(suffix):
            name = name[:-len(suffix)]
            break

    # Replace hyphens with underscores
    return name.replace("-", "_")


# Public API
__all__ = [
    "PluginCategory",
    "PluginSource",
    "PluginMetadata",
    "PluginInfo",
    "PluginRegistry",
    "LicenseTier",
    "get_registry",
    "init_plugins",
]
