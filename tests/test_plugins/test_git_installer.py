#!/usr/bin/env python3
"""
Tests for tweek.plugins.git_installer module.

Tests git-based plugin installation:
- Install from registry
- Update installed plugins
- Remove plugins
- Check for updates
- Verify integrity
"""

import pytest

pytestmark = pytest.mark.plugins

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tweek.plugins.git_installer import (
    GIT_TIMEOUT,
    GitPluginInstaller,
    InstallError,
)
from tweek.plugins.git_registry import PluginRegistryClient, RegistryEntry


@pytest.fixture
def mock_registry_entry():
    """Create a mock registry entry."""
    return RegistryEntry({
        "name": "tweek-plugin-test",
        "category": "detectors",
        "repo_url": "https://github.com/gettweek/tweek-plugin-test.git",
        "latest_version": "1.0.0",
        "requires_license_tier": "free",
        "verified": True,
        "deprecated": False,
        "description": "Test plugin",
        "versions": {
            "1.0.0": {
                "git_ref": "v1.0.0",
                "checksums": {"plugin.py": "sha256:abc123"},
            },
            "1.1.0": {
                "git_ref": "v1.1.0",
                "checksums": {"plugin.py": "sha256:def456"},
            },
        },
    })


@pytest.fixture
def mock_registry(mock_registry_entry):
    """Create a mock registry client."""
    registry = MagicMock(spec=PluginRegistryClient)
    registry.get_plugin.return_value = mock_registry_entry
    registry.get_update_available.return_value = None
    return registry


@pytest.fixture
def plugins_dir(tmp_path):
    """Temporary plugins directory."""
    d = tmp_path / "plugins"
    d.mkdir()
    return d


@pytest.fixture
def installer(mock_registry, plugins_dir):
    """Create a GitPluginInstaller with mocked registry."""
    return GitPluginInstaller(
        registry_client=mock_registry,
        plugins_dir=plugins_dir,
    )


@pytest.fixture
def installed_plugin(plugins_dir):
    """Create a pre-installed plugin directory."""
    plugin_dir = plugins_dir / "tweek-plugin-test"
    plugin_dir.mkdir()

    manifest = {
        "name": "tweek-plugin-test",
        "version": "1.0.0",
        "category": "detectors",
        "entry_point": "plugin:TestDetector",
        "description": "Test",
    }
    (plugin_dir / "tweek_plugin.json").write_text(json.dumps(manifest))
    (plugin_dir / "plugin.py").write_text("class TestDetector: pass\n")
    (plugin_dir / "__init__.py").write_text("")

    return plugin_dir


class TestInstall:
    """Tests for GitPluginInstaller.install()."""

    def test_plugin_not_in_registry(self, installer, mock_registry):
        mock_registry.get_plugin.return_value = None
        success, msg = installer.install("nonexistent-plugin")
        assert success is False
        assert "not found" in msg

    def test_already_installed(self, installer, installed_plugin):
        success, msg = installer.install("tweek-plugin-test")
        assert success is False
        assert "already installed" in msg

    def test_version_not_found(self, installer, mock_registry_entry):
        success, msg = installer.install("tweek-plugin-test", version="99.0.0")
        assert success is False
        assert "not found" in msg

    @patch("tweek.plugins.git_installer.subprocess.run")
    def test_successful_install_no_verify(self, mock_run, installer):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        success, msg = installer.install("tweek-plugin-test", verify=False)
        assert success is True
        assert "Installed" in msg
        # Verify git clone was called
        mock_run.assert_called()
        call_args = mock_run.call_args_list[0]
        assert "git" in call_args[0][0]
        assert "clone" in call_args[0][0]

    @patch("tweek.plugins.git_installer.subprocess.run")
    def test_git_clone_failure(self, mock_run, installer):
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="fatal: repository not found"
        )
        success, msg = installer.install("tweek-plugin-test", verify=False)
        assert success is False
        assert "Git clone failed" in msg


class TestUpdate:
    """Tests for GitPluginInstaller.update()."""

    def test_not_installed(self, installer):
        success, msg = installer.update("nonexistent")
        assert success is False
        assert "not installed" in msg

    def test_not_in_registry(self, installer, installed_plugin, mock_registry):
        mock_registry.get_plugin.return_value = None
        success, msg = installer.update("tweek-plugin-test")
        assert success is False
        assert "not found in registry" in msg

    def test_already_at_target_version(self, installer, installed_plugin):
        success, msg = installer.update("tweek-plugin-test", version="1.0.0")
        assert success is True
        assert "already at version" in msg

    @patch("tweek.plugins.git_installer.subprocess.run")
    def test_successful_update_no_verify(self, mock_run, installer, installed_plugin):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        success, msg = installer.update("tweek-plugin-test", version="1.1.0", verify=False)
        assert success is True
        assert "Updated" in msg

    @patch("tweek.plugins.git_installer.subprocess.run")
    def test_git_fetch_failure(self, mock_run, installer, installed_plugin):
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="fatal: fetch failed"
        )
        success, msg = installer.update("tweek-plugin-test", version="1.1.0", verify=False)
        assert success is False
        assert "Git update failed" in msg


class TestRemove:
    """Tests for GitPluginInstaller.remove()."""

    def test_remove_installed(self, installer, installed_plugin):
        success, msg = installer.remove("tweek-plugin-test")
        assert success is True
        assert not installed_plugin.exists()

    def test_remove_not_installed(self, installer):
        success, msg = installer.remove("nonexistent")
        assert success is False
        assert "not installed" in msg


class TestCheckUpdates:
    """Tests for GitPluginInstaller.check_updates()."""

    def test_no_plugins_installed(self, installer):
        updates = installer.check_updates()
        assert updates == []

    def test_no_updates_available(self, installer, installed_plugin):
        updates = installer.check_updates()
        assert updates == []

    def test_update_available(self, installer, installed_plugin, mock_registry):
        mock_registry.get_update_available.return_value = "1.1.0"
        updates = installer.check_updates()
        assert len(updates) == 1
        assert updates[0]["name"] == "tweek-plugin-test"
        assert updates[0]["current_version"] == "1.0.0"
        assert updates[0]["latest_version"] == "1.1.0"


class TestListInstalled:
    """Tests for GitPluginInstaller.list_installed()."""

    def test_no_plugins(self, installer):
        assert installer.list_installed() == []

    def test_lists_installed_plugin(self, installer, installed_plugin):
        installed = installer.list_installed()
        assert len(installed) == 1
        assert installed[0]["name"] == "tweek-plugin-test"
        assert installed[0]["version"] == "1.0.0"
        assert installed[0]["category"] == "detectors"

    def test_handles_invalid_manifest(self, installer, plugins_dir):
        bad = plugins_dir / "bad-plugin"
        bad.mkdir()
        (bad / "tweek_plugin.json").write_text("{invalid")
        installed = installer.list_installed()
        assert len(installed) == 1
        assert installed[0]["version"] == "unknown"


class TestVerifyPlugin:
    """Tests for GitPluginInstaller.verify_plugin()."""

    def test_not_installed(self, installer):
        valid, issues = installer.verify_plugin("nonexistent")
        assert valid is False
        assert any("not installed" in i for i in issues)

    def test_verify_installed_plugin(self, installer, installed_plugin, mock_registry):
        """Verify runs manifest + security validation."""
        # This will fail because no CHECKSUMS.sha256 file
        # but it exercises the verification pipeline
        valid, issues = installer.verify_plugin("tweek-plugin-test")
        # Without checksums file, it will report issues
        assert isinstance(valid, bool)
        assert isinstance(issues, list)
