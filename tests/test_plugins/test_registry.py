"""Tests for the plugin registry."""

import pytest

pytestmark = pytest.mark.plugins

from tweek.plugins import (
    PluginRegistry,
    PluginCategory,
    PluginMetadata,
    LicenseTier,
    get_registry,
)
from tweek.plugins.base import (
    CompliancePlugin,
    ScanDirection,
    ScanResult,
    PatternDefinition,
    Severity,
)


class MockCompliancePlugin(CompliancePlugin):
    """Mock compliance plugin for testing."""

    VERSION = "1.0.0"
    DESCRIPTION = "Mock compliance plugin"
    REQUIRES_LICENSE = "free"

    @property
    def name(self) -> str:
        return "mock"

    @property
    def scan_direction(self) -> ScanDirection:
        return ScanDirection.BOTH

    def get_patterns(self):
        return [
            PatternDefinition(
                name="test_pattern",
                regex=r"TEST_SECRET",
                severity=Severity.HIGH,
                description="Test pattern",
            )
        ]


class TestPluginRegistry:
    """Tests for PluginRegistry."""

    def test_registry_creation(self):
        """Test creating a new registry."""
        registry = PluginRegistry()
        assert registry is not None
        assert len(registry.list_plugins()) == 0

    def test_register_plugin(self):
        """Test registering a plugin."""
        registry = PluginRegistry()

        result = registry.register(
            "mock",
            MockCompliancePlugin,
            PluginCategory.COMPLIANCE
        )

        assert result is True
        assert len(registry.list_plugins(PluginCategory.COMPLIANCE)) == 1

    def test_register_duplicate_fails(self):
        """Test that registering duplicate plugin fails."""
        registry = PluginRegistry()

        registry.register("mock", MockCompliancePlugin, PluginCategory.COMPLIANCE)
        result = registry.register("mock", MockCompliancePlugin, PluginCategory.COMPLIANCE)

        assert result is False
        assert len(registry.list_plugins(PluginCategory.COMPLIANCE)) == 1

    def test_get_plugin(self):
        """Test getting a plugin instance."""
        registry = PluginRegistry()
        registry.register("mock", MockCompliancePlugin, PluginCategory.COMPLIANCE)

        plugin = registry.get("mock", PluginCategory.COMPLIANCE)

        assert plugin is not None
        assert isinstance(plugin, MockCompliancePlugin)
        assert plugin.name == "mock"

    def test_get_nonexistent_plugin(self):
        """Test getting a plugin that doesn't exist."""
        registry = PluginRegistry()

        plugin = registry.get("nonexistent", PluginCategory.COMPLIANCE)

        assert plugin is None

    def test_enable_disable_plugin(self):
        """Test enabling and disabling plugins."""
        registry = PluginRegistry()
        registry.register("mock", MockCompliancePlugin, PluginCategory.COMPLIANCE)

        # Should be enabled by default
        assert registry.is_enabled("mock", PluginCategory.COMPLIANCE) is True

        # Disable
        registry.disable("mock", PluginCategory.COMPLIANCE)
        assert registry.is_enabled("mock", PluginCategory.COMPLIANCE) is False

        # Get should return None when disabled
        assert registry.get("mock", PluginCategory.COMPLIANCE) is None

        # Enable
        registry.enable("mock", PluginCategory.COMPLIANCE)
        assert registry.is_enabled("mock", PluginCategory.COMPLIANCE) is True
        assert registry.get("mock", PluginCategory.COMPLIANCE) is not None

    def test_get_all_plugins(self):
        """Test getting all plugins in a category."""
        registry = PluginRegistry()
        registry.register("mock1", MockCompliancePlugin, PluginCategory.COMPLIANCE)
        registry.register("mock2", MockCompliancePlugin, PluginCategory.COMPLIANCE)

        plugins = registry.get_all(PluginCategory.COMPLIANCE)

        assert len(plugins) == 2

    def test_get_all_enabled_only(self):
        """Test get_all with enabled_only filter."""
        registry = PluginRegistry()
        registry.register("mock1", MockCompliancePlugin, PluginCategory.COMPLIANCE)
        registry.register("mock2", MockCompliancePlugin, PluginCategory.COMPLIANCE)
        registry.disable("mock2", PluginCategory.COMPLIANCE)

        plugins = registry.get_all(PluginCategory.COMPLIANCE, enabled_only=True)

        assert len(plugins) == 1

    def test_unregister_plugin(self):
        """Test unregistering a plugin."""
        registry = PluginRegistry()
        registry.register("mock", MockCompliancePlugin, PluginCategory.COMPLIANCE)

        result = registry.unregister("mock", PluginCategory.COMPLIANCE)

        assert result is True
        assert len(registry.list_plugins(PluginCategory.COMPLIANCE)) == 0

    def test_plugin_configuration(self):
        """Test configuring a plugin."""
        registry = PluginRegistry()
        registry.register("mock", MockCompliancePlugin, PluginCategory.COMPLIANCE)

        config = {"enabled": True, "setting1": "value1"}
        registry.configure("mock", config)

        retrieved_config = registry.get_config("mock")
        assert retrieved_config == config

    def test_load_config(self):
        """Test loading configuration from dictionary."""
        registry = PluginRegistry()
        registry.register("mock", MockCompliancePlugin, PluginCategory.COMPLIANCE)

        config = {
            "plugins": {
                "compliance": {
                    "modules": {
                        "mock": {"enabled": False}
                    }
                }
            }
        }

        registry.load_config(config)

        assert registry.is_enabled("mock", PluginCategory.COMPLIANCE) is False

    def test_license_checking(self):
        """Test license tier checking."""
        registry = PluginRegistry()

        # Plugin requiring PRO license
        class ProPlugin(MockCompliancePlugin):
            REQUIRES_LICENSE = "pro"

        registry.register("pro_plugin", ProPlugin, PluginCategory.COMPLIANCE)

        # Without license checker, only FREE is allowed
        plugin = registry.get("pro_plugin", PluginCategory.COMPLIANCE)
        assert plugin is None

        # Set license checker that allows PRO
        registry.set_license_checker(lambda tier: True)
        plugin = registry.get("pro_plugin", PluginCategory.COMPLIANCE)
        assert plugin is not None

    def test_get_stats(self):
        """Test getting registry statistics."""
        registry = PluginRegistry()
        registry.register("mock1", MockCompliancePlugin, PluginCategory.COMPLIANCE)
        registry.register("mock2", MockCompliancePlugin, PluginCategory.COMPLIANCE)
        registry.disable("mock2", PluginCategory.COMPLIANCE)

        stats = registry.get_stats()

        assert stats["total"] == 2
        assert stats["enabled"] == 1
        assert stats["by_license"]["free"] == 2

    def test_metadata_extraction(self):
        """Test automatic metadata extraction from plugin class."""
        registry = PluginRegistry()
        registry.register("mock", MockCompliancePlugin, PluginCategory.COMPLIANCE)

        info = registry.get_info("mock", PluginCategory.COMPLIANCE)

        assert info is not None
        assert info.metadata.version == "1.0.0"
        assert info.metadata.description == "Mock compliance plugin"
        assert info.metadata.requires_license == LicenseTier.FREE


class TestGlobalRegistry:
    """Tests for the global registry singleton."""

    def test_get_registry_returns_same_instance(self):
        """Test that get_registry returns the same instance."""
        registry1 = get_registry()
        registry2 = get_registry()

        assert registry1 is registry2
