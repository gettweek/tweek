#!/usr/bin/env python3
"""
Tests for tweek.plugins.git_registry module.

Tests the plugin registry client:
- Registry parsing and entry access
- Cache management
- Search functionality
- Signature verification
- Version comparison
"""

import pytest

pytestmark = pytest.mark.plugins

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tweek.plugins.git_registry import (
    DEFAULT_CACHE_TTL_SECONDS,
    PluginRegistryClient,
    RegistryEntry,
    RegistryError,
)


@pytest.fixture
def sample_registry_data():
    """Sample registry JSON data."""
    return {
        "schema_version": 1,
        "updated_at": "2026-01-29T00:00:00Z",
        "registry_signature": "",
        "plugins": [
            {
                "name": "tweek-plugin-cursor-detector",
                "category": "detectors",
                "repo_url": "https://github.com/gettweek/tweek-plugin-cursor-detector.git",
                "latest_version": "1.2.0",
                "requires_license_tier": "free",
                "verified": True,
                "deprecated": False,
                "description": "Detect Cursor AI IDE",
                "author": "Tweek",
                "tags": ["detector", "cursor", "ide"],
                "versions": {
                    "1.0.0": {
                        "git_ref": "v1.0.0",
                        "checksums": {"plugin.py": "sha256:abc123"},
                    },
                    "1.2.0": {
                        "git_ref": "v1.2.0",
                        "checksums": {"plugin.py": "sha256:def456"},
                    },
                },
            },
            {
                "name": "tweek-plugin-hipaa",
                "category": "compliance",
                "repo_url": "https://github.com/gettweek/tweek-plugin-hipaa.git",
                "latest_version": "2.0.0",
                "requires_license_tier": "enterprise",
                "verified": True,
                "deprecated": False,
                "description": "HIPAA compliance scanning",
                "tags": ["compliance", "hipaa", "healthcare"],
                "versions": {
                    "2.0.0": {
                        "git_ref": "v2.0.0",
                        "checksums": {"plugin.py": "sha256:ghi789"},
                    },
                },
            },
            {
                "name": "tweek-plugin-deprecated",
                "category": "detectors",
                "repo_url": "https://github.com/gettweek/tweek-plugin-deprecated.git",
                "latest_version": "0.1.0",
                "requires_license_tier": "free",
                "verified": True,
                "deprecated": True,
                "description": "An old plugin",
                "tags": [],
                "versions": {},
            },
            {
                "name": "tweek-plugin-unverified",
                "category": "detectors",
                "repo_url": "https://github.com/example/unverified.git",
                "latest_version": "1.0.0",
                "verified": False,
                "deprecated": False,
                "description": "Not verified",
                "tags": [],
                "versions": {},
            },
        ],
    }


@pytest.fixture
def registry_cache_dir(tmp_path):
    """Temporary directory for registry cache."""
    cache_dir = tmp_path / ".tweek"
    cache_dir.mkdir()
    return cache_dir


@pytest.fixture
def cached_registry(registry_cache_dir, sample_registry_data):
    """Write sample registry to cache."""
    cache_path = registry_cache_dir / "registry.json"
    cache_path.write_text(json.dumps(sample_registry_data))

    meta_path = registry_cache_dir / "registry_meta.json"
    meta_path.write_text(json.dumps({
        "fetched_at": time.time(),
        "fetched_from": "https://registry.gettweek.com/v1/plugins.json",
    }))

    return cache_path


class TestRegistryEntry:
    """Tests for RegistryEntry data class."""

    def test_basic_properties(self, sample_registry_data):
        data = sample_registry_data["plugins"][0]
        entry = RegistryEntry(data)
        assert entry.name == "tweek-plugin-cursor-detector"
        assert entry.category == "detectors"
        assert entry.latest_version == "1.2.0"
        assert entry.verified is True
        assert entry.deprecated is False
        assert entry.requires_license_tier == "free"

    def test_version_info(self, sample_registry_data):
        entry = RegistryEntry(sample_registry_data["plugins"][0])
        info = entry.get_version_info("1.2.0")
        assert info is not None
        assert info["git_ref"] == "v1.2.0"

    def test_get_git_ref(self, sample_registry_data):
        entry = RegistryEntry(sample_registry_data["plugins"][0])
        assert entry.get_git_ref("1.2.0") == "v1.2.0"
        assert entry.get_git_ref() == "v1.2.0"  # Default to latest

    def test_get_checksums(self, sample_registry_data):
        entry = RegistryEntry(sample_registry_data["plugins"][0])
        checksums = entry.get_checksums("1.2.0")
        assert "plugin.py" in checksums

    def test_missing_version(self, sample_registry_data):
        entry = RegistryEntry(sample_registry_data["plugins"][0])
        assert entry.get_version_info("99.0.0") is None

    def test_to_dict(self, sample_registry_data):
        data = sample_registry_data["plugins"][0]
        entry = RegistryEntry(data)
        assert entry.to_dict() == data


class TestPluginRegistryClient:
    """Tests for PluginRegistryClient."""

    def test_init_defaults(self):
        client = PluginRegistryClient()
        assert "registry.gettweek.com" in client.registry_url

    def test_custom_url(self):
        client = PluginRegistryClient(registry_url="https://custom.example.com/plugins.json")
        assert client.registry_url == "https://custom.example.com/plugins.json"

    def test_fetch_from_cache(self, cached_registry, registry_cache_dir):
        client = PluginRegistryClient(
            cache_path=cached_registry,
        )
        entries = client.fetch()
        assert len(entries) == 4
        assert "tweek-plugin-cursor-detector" in entries

    def test_search_by_query(self, cached_registry):
        client = PluginRegistryClient(cache_path=cached_registry)
        client.fetch()
        results = client.search(query="cursor")
        assert len(results) == 1
        assert results[0].name == "tweek-plugin-cursor-detector"

    def test_search_by_category(self, cached_registry):
        client = PluginRegistryClient(cache_path=cached_registry)
        client.fetch()
        results = client.search(category="compliance")
        assert len(results) == 1
        assert results[0].name == "tweek-plugin-hipaa"

    def test_search_by_tier(self, cached_registry):
        client = PluginRegistryClient(cache_path=cached_registry)
        client.fetch()
        results = client.search(tier="enterprise")
        assert len(results) == 1

    def test_search_excludes_deprecated(self, cached_registry):
        client = PluginRegistryClient(cache_path=cached_registry)
        client.fetch()
        results = client.search()
        names = [r.name for r in results]
        assert "tweek-plugin-deprecated" not in names

    def test_search_includes_deprecated(self, cached_registry):
        client = PluginRegistryClient(cache_path=cached_registry)
        client.fetch()
        results = client.search(include_deprecated=True)
        names = [r.name for r in results]
        assert "tweek-plugin-deprecated" in names

    def test_search_excludes_unverified(self, cached_registry):
        client = PluginRegistryClient(cache_path=cached_registry)
        client.fetch()
        results = client.search()
        names = [r.name for r in results]
        assert "tweek-plugin-unverified" not in names

    def test_get_plugin(self, cached_registry):
        client = PluginRegistryClient(cache_path=cached_registry)
        entry = client.get_plugin("tweek-plugin-cursor-detector")
        assert entry is not None
        assert entry.latest_version == "1.2.0"

    def test_get_unverified_plugin_returns_none(self, cached_registry):
        client = PluginRegistryClient(cache_path=cached_registry)
        entry = client.get_plugin("tweek-plugin-unverified")
        assert entry is None

    def test_get_nonexistent_plugin(self, cached_registry):
        client = PluginRegistryClient(cache_path=cached_registry)
        entry = client.get_plugin("nonexistent-plugin")
        assert entry is None

    def test_is_plugin_available(self, cached_registry):
        client = PluginRegistryClient(cache_path=cached_registry)
        assert client.is_plugin_available("tweek-plugin-cursor-detector") is True
        assert client.is_plugin_available("tweek-plugin-unverified") is False
        assert client.is_plugin_available("nonexistent") is False

    def test_get_update_available(self, cached_registry):
        client = PluginRegistryClient(cache_path=cached_registry)
        update = client.get_update_available("tweek-plugin-cursor-detector", "1.0.0")
        assert update == "1.2.0"

    def test_no_update_available(self, cached_registry):
        client = PluginRegistryClient(cache_path=cached_registry)
        update = client.get_update_available("tweek-plugin-cursor-detector", "1.2.0")
        assert update is None

    def test_cache_ttl(self, cached_registry, registry_cache_dir):
        # Cache with TTL=0 should be expired
        client = PluginRegistryClient(
            cache_path=cached_registry,
            cache_ttl=0,
        )
        assert client._is_cache_valid() is False

    def test_clear_cache(self, cached_registry, registry_cache_dir):
        client = PluginRegistryClient(cache_path=cached_registry)
        client.fetch()
        client.clear_cache()
        assert client._entries is None
        assert client._last_fetch_time is None

    def test_get_registry_info(self, cached_registry):
        client = PluginRegistryClient(cache_path=cached_registry)
        client.fetch()
        info = client.get_registry_info()
        assert "url" in info
        assert "cache_path" in info
        assert info["total_plugins"] == 4

    def test_no_cache_no_network_raises(self, tmp_path):
        """Test that missing cache + no network raises RegistryError."""
        client = PluginRegistryClient(
            registry_url="https://unreachable.invalid/plugins.json",
            cache_path=tmp_path / "nonexistent" / "registry.json",
            cache_ttl=0,
        )
        with pytest.raises(RegistryError, match="No registry data"):
            client.fetch()


class TestVersionComparison:
    """Tests for version comparison logic."""

    def test_greater_major(self):
        assert PluginRegistryClient._version_gt("2.0.0", "1.0.0") is True

    def test_greater_minor(self):
        assert PluginRegistryClient._version_gt("1.2.0", "1.1.0") is True

    def test_greater_patch(self):
        assert PluginRegistryClient._version_gt("1.0.2", "1.0.1") is True

    def test_equal(self):
        assert PluginRegistryClient._version_gt("1.0.0", "1.0.0") is False

    def test_lesser(self):
        assert PluginRegistryClient._version_gt("1.0.0", "2.0.0") is False

    def test_two_part_version(self):
        assert PluginRegistryClient._version_gt("1.1", "1.0") is True

    def test_invalid_version(self):
        assert PluginRegistryClient._version_gt("abc", "1.0.0") is False
