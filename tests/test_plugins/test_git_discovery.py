#!/usr/bin/env python3
"""
Tests for tweek.plugins.git_discovery module.

Tests plugin discovery from git-installed directories:
- Manifest scanning
- Security validation
- Dynamic import
- Base class verification
- Version compatibility
"""

import pytest

pytestmark = pytest.mark.plugins

import json
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tweek.plugins.git_discovery import (
    DiscoveredPlugin,
    PluginDiscoveryError,
    _check_version_compat,
    _import_plugin_class,
    _parse_version,
    discover_git_plugins,
    get_plugin_info,
)
from tweek.plugins import _derive_short_name


@pytest.fixture
def plugins_dir(tmp_path):
    """Create a temporary plugins directory."""
    d = tmp_path / "plugins"
    d.mkdir()
    return d


@pytest.fixture
def valid_plugin_dir(plugins_dir):
    """Create a valid plugin directory with all required files."""
    plugin_dir = plugins_dir / "tweek-plugin-test-detector"
    plugin_dir.mkdir()

    # Write manifest
    manifest = {
        "name": "tweek-plugin-test-detector",
        "version": "1.0.0",
        "category": "detectors",
        "entry_point": "plugin:TestDetector",
        "description": "A test detector",
        "author": "Test",
        "requires_license_tier": "free",
    }
    (plugin_dir / "tweek_plugin.json").write_text(json.dumps(manifest))

    # Write safe plugin code
    code = textwrap.dedent("""\
        import json
        from pathlib import Path
        from typing import List

        # Minimal base class stubs for testing without importing tweek.plugins.base
        class DetectionResult:
            def __init__(self, detected=False, tool_name=""):
                self.detected = detected
                self.tool_name = tool_name

        class ToolDetectorPlugin:
            VERSION = "1.0.0"
            DESCRIPTION = "Base"
            @property
            def name(self):
                return ""
            def detect(self):
                return DetectionResult()
            def get_conflicts(self):
                return []

        class TestDetector(ToolDetectorPlugin):
            VERSION = "1.0.0"
            DESCRIPTION = "Test detector"

            @property
            def name(self):
                return "test"

            def detect(self):
                return DetectionResult(detected=True, tool_name="test")

            def get_conflicts(self):
                return []
    """)
    (plugin_dir / "plugin.py").write_text(code)
    (plugin_dir / "__init__.py").write_text("")

    # Write CHECKSUMS.sha256 (empty for skip_signature tests)
    (plugin_dir / "CHECKSUMS.sha256").write_text("{}")

    return plugin_dir


class TestDiscoverGitPlugins:
    """Tests for discover_git_plugins()."""

    def test_empty_directory(self, plugins_dir):
        plugins = discover_git_plugins(
            plugins_dir=plugins_dir,
            skip_security=True,
        )
        assert plugins == []

    def test_nonexistent_directory(self, tmp_path):
        plugins = discover_git_plugins(
            plugins_dir=tmp_path / "nonexistent",
            skip_security=True,
        )
        assert plugins == []

    def test_skips_hidden_directories(self, plugins_dir):
        hidden = plugins_dir / ".hidden"
        hidden.mkdir()
        (hidden / "tweek_plugin.json").write_text("{}")
        plugins = discover_git_plugins(
            plugins_dir=plugins_dir,
            skip_security=True,
        )
        assert plugins == []

    def test_skips_directories_without_manifest(self, plugins_dir):
        no_manifest = plugins_dir / "no-manifest"
        no_manifest.mkdir()
        (no_manifest / "plugin.py").write_text("# no manifest")
        plugins = discover_git_plugins(
            plugins_dir=plugins_dir,
            skip_security=True,
        )
        assert plugins == []

    def test_discover_valid_plugin_skip_security(self, valid_plugin_dir, plugins_dir):
        """Test discovery with security validation skipped."""
        # Patch verify_base_class to always pass (since we have stub classes)
        with patch("tweek.plugins.git_discovery.verify_base_class", return_value=(True, "")):
            plugins = discover_git_plugins(
                plugins_dir=plugins_dir,
                skip_security=True,
            )
        assert len(plugins) == 1
        assert plugins[0].name == "tweek-plugin-test-detector"
        assert plugins[0].version == "1.0.0"
        assert plugins[0].category == "detectors"

    def test_invalid_manifest_skipped(self, plugins_dir):
        """Plugin with invalid manifest is skipped."""
        bad = plugins_dir / "bad-plugin"
        bad.mkdir()
        (bad / "tweek_plugin.json").write_text("{invalid json")
        plugins = discover_git_plugins(
            plugins_dir=plugins_dir,
            skip_security=True,
        )
        assert plugins == []


class TestImportPluginClass:
    """Tests for _import_plugin_class()."""

    def test_import_valid_class(self, valid_plugin_dir):
        cls = _import_plugin_class(
            valid_plugin_dir,
            "plugin:TestDetector",
            "tweek-plugin-test-detector",
        )
        assert cls is not None
        assert cls.__name__ == "TestDetector"

    def test_invalid_entry_point_format(self, valid_plugin_dir):
        with pytest.raises(PluginDiscoveryError, match="entry_point format"):
            _import_plugin_class(
                valid_plugin_dir,
                "no_colon",
                "test",
            )

    def test_missing_module_file(self, valid_plugin_dir):
        with pytest.raises(PluginDiscoveryError, match="not found"):
            _import_plugin_class(
                valid_plugin_dir,
                "nonexistent:SomeClass",
                "test",
            )

    def test_missing_class_in_module(self, valid_plugin_dir):
        with pytest.raises(PluginDiscoveryError, match="not found in module"):
            _import_plugin_class(
                valid_plugin_dir,
                "plugin:NonExistentClass",
                "test",
            )


class TestVersionCompat:
    """Tests for _check_version_compat() and _parse_version()."""

    def test_parse_version(self):
        assert _parse_version("1.2.3") == (1, 2, 3)
        assert _parse_version("0.1") == (0, 1)

    def test_no_constraints(self):
        assert _check_version_compat(None, None) is True

    def test_missing_tweek_version(self):
        """When tweek version can't be determined, assume compatible."""
        # Temporarily remove tweek.__version__ if it exists
        import tweek
        original = getattr(tweek, "__version__", None)
        try:
            tweek.__version__ = None
            assert _check_version_compat("1.0.0", "2.0.0") is True
        finally:
            if original is not None:
                tweek.__version__ = original


class TestGetPluginInfo:
    """Tests for get_plugin_info()."""

    def test_valid_plugin(self, valid_plugin_dir):
        info = get_plugin_info(valid_plugin_dir)
        assert info is not None
        assert info["name"] == "tweek-plugin-test-detector"
        assert info["version"] == "1.0.0"
        assert info["category"] == "detectors"
        assert info["source"] == "git"

    def test_no_manifest(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        assert get_plugin_info(empty) is None

    def test_invalid_manifest(self, tmp_path):
        bad = tmp_path / "bad"
        bad.mkdir()
        (bad / "tweek_plugin.json").write_text("{invalid")
        assert get_plugin_info(bad) is None


class TestDeriveShortName:
    """Tests for _derive_short_name()."""

    def test_cursor_detector(self):
        assert _derive_short_name("tweek-plugin-cursor-detector", "detectors") == "cursor"

    def test_hipaa_compliance(self):
        assert _derive_short_name("tweek-plugin-hipaa", "compliance") == "hipaa"

    def test_openai_provider(self):
        assert _derive_short_name("tweek-plugin-openai-provider", "providers") == "openai"

    def test_no_prefix(self):
        assert _derive_short_name("custom-detector", "detectors") == "custom"

    def test_plain_name(self):
        assert _derive_short_name("mydetector", "detectors") == "mydetector"
