#!/usr/bin/env python3
"""
Tests for tweek.plugins.git_lockfile module.

Tests version pinning lockfile management:
- Lockfile generation
- Lockfile loading
- Compliance checking
- User vs project lockfile precedence
"""

import pytest

pytestmark = pytest.mark.plugins

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from tweek.plugins.git_lockfile import (
    LOCKFILE_SCHEMA_VERSION,
    LockfileError,
    PluginLock,
    PluginLockfile,
)
from tweek.plugins.git_security import generate_checksums


@pytest.fixture
def plugins_dir(tmp_path):
    """Create a plugins directory with an installed plugin."""
    plugins = tmp_path / "plugins"
    plugins.mkdir()

    plugin = plugins / "tweek-plugin-test"
    plugin.mkdir()

    # Manifest
    manifest = {
        "name": "tweek-plugin-test",
        "version": "1.0.0",
        "category": "detectors",
        "entry_point": "plugin:TestDetector",
        "description": "Test plugin",
    }
    (plugin / "tweek_plugin.json").write_text(json.dumps(manifest))
    (plugin / "plugin.py").write_text("class TestDetector: pass\n")
    (plugin / "__init__.py").write_text("")

    return plugins


@pytest.fixture
def lockfile_manager(tmp_path, plugins_dir):
    """Create a PluginLockfile instance."""
    return PluginLockfile(
        user_lockfile=tmp_path / "user.lock.json",
        project_lockfile=tmp_path / "project.lock.json",
        plugins_dir=plugins_dir,
    )


class TestPluginLock:
    """Tests for PluginLock data class."""

    def test_basic_properties(self):
        lock = PluginLock({
            "version": "1.0.0",
            "git_ref": "v1.0.0",
            "commit_sha": "abc123",
            "checksums": {"plugin.py": "sha256:def456"},
        })
        assert lock.version == "1.0.0"
        assert lock.git_ref == "v1.0.0"
        assert lock.commit_sha == "abc123"
        assert "plugin.py" in lock.checksums

    def test_missing_fields(self):
        lock = PluginLock({})
        assert lock.version == ""
        assert lock.git_ref == ""
        assert lock.commit_sha == ""
        assert lock.checksums == {}

    def test_to_dict(self):
        data = {"version": "1.0.0", "git_ref": "v1.0.0"}
        lock = PluginLock(data)
        assert lock.to_dict() == data


class TestPluginLockfile:
    """Tests for PluginLockfile."""

    def test_no_lockfile(self, lockfile_manager):
        assert lockfile_manager.has_lockfile is False
        assert lockfile_manager.active_lockfile is None

    def test_user_lockfile_active(self, lockfile_manager, tmp_path):
        # Create user lockfile
        user_lock = tmp_path / "user.lock.json"
        user_lock.write_text(json.dumps({
            "schema_version": LOCKFILE_SCHEMA_VERSION,
            "plugins": {},
        }))
        assert lockfile_manager.has_lockfile is True
        assert lockfile_manager.active_lockfile == user_lock

    def test_project_lockfile_takes_precedence(self, lockfile_manager, tmp_path):
        # Create both
        user_lock = tmp_path / "user.lock.json"
        project_lock = tmp_path / "project.lock.json"
        user_lock.write_text(json.dumps({
            "schema_version": LOCKFILE_SCHEMA_VERSION,
            "plugins": {},
        }))
        project_lock.write_text(json.dumps({
            "schema_version": LOCKFILE_SCHEMA_VERSION,
            "plugins": {},
        }))
        assert lockfile_manager.active_lockfile == project_lock

    def test_generate_lockfile(self, lockfile_manager):
        path = lockfile_manager.generate(target="user")
        assert path.exists()

        with open(path) as f:
            data = json.load(f)

        assert data["schema_version"] == LOCKFILE_SCHEMA_VERSION
        assert "generated_at" in data
        assert "tweek-plugin-test" in data["plugins"]
        assert data["plugins"]["tweek-plugin-test"]["version"] == "1.0.0"

    def test_generate_with_checksums(self, lockfile_manager):
        path = lockfile_manager.generate(target="user")
        with open(path) as f:
            data = json.load(f)

        plugin_lock = data["plugins"]["tweek-plugin-test"]
        assert "checksums" in plugin_lock
        assert "plugin.py" in plugin_lock["checksums"]

    def test_generate_specific_plugins(self, lockfile_manager):
        path = lockfile_manager.generate(
            target="user",
            specific_plugins={"tweek-plugin-test": "1.0.0"},
        )
        with open(path) as f:
            data = json.load(f)
        assert "tweek-plugin-test" in data["plugins"]

    def test_load_lockfile(self, lockfile_manager, tmp_path):
        # Generate first
        lockfile_manager.generate(target="user")

        # Load
        locks = lockfile_manager.load()
        assert "tweek-plugin-test" in locks
        assert locks["tweek-plugin-test"].version == "1.0.0"

    def test_load_invalid_schema(self, lockfile_manager, tmp_path):
        user_lock = tmp_path / "user.lock.json"
        user_lock.write_text(json.dumps({
            "schema_version": 999,
            "plugins": {},
        }))
        with pytest.raises(LockfileError, match="schema version"):
            lockfile_manager.load()

    def test_load_invalid_json(self, tmp_path):
        user_lock = tmp_path / "bad.lock.json"
        user_lock.write_text("{invalid")
        manager = PluginLockfile(
            user_lockfile=user_lock,
            project_lockfile=tmp_path / "project.lock.json",
            plugins_dir=tmp_path / "plugins",
        )
        with pytest.raises(LockfileError, match="Failed to read"):
            manager.load()

    def test_get_lock(self, lockfile_manager):
        lockfile_manager.generate(target="user")
        lock = lockfile_manager.get_lock("tweek-plugin-test")
        assert lock is not None
        assert lock.version == "1.0.0"

    def test_get_lock_nonexistent(self, lockfile_manager):
        lockfile_manager.generate(target="user")
        lock = lockfile_manager.get_lock("nonexistent-plugin")
        assert lock is None

    def test_is_locked(self, lockfile_manager):
        lockfile_manager.generate(target="user")
        assert lockfile_manager.is_locked("tweek-plugin-test") is True
        assert lockfile_manager.is_locked("nonexistent") is False


class TestComplianceChecking:
    """Tests for lockfile compliance checking."""

    def test_compliant_installation(self, lockfile_manager):
        lockfile_manager.generate(target="user")
        compliant, violations = lockfile_manager.check_compliance()
        assert compliant is True
        assert len(violations) == 0

    def test_no_lockfile_is_compliant(self, lockfile_manager):
        compliant, violations = lockfile_manager.check_compliance()
        assert compliant is True

    def test_missing_plugin_is_violation(self, lockfile_manager, tmp_path):
        # Create lockfile with a plugin that doesn't exist
        user_lock = tmp_path / "user.lock.json"
        user_lock.write_text(json.dumps({
            "schema_version": LOCKFILE_SCHEMA_VERSION,
            "plugins": {
                "nonexistent-plugin": {
                    "version": "1.0.0",
                    "git_ref": "v1.0.0",
                },
            },
        }))
        compliant, violations = lockfile_manager.check_compliance()
        assert compliant is False
        assert any("not installed" in v for v in violations)

    def test_version_mismatch_is_violation(self, lockfile_manager, tmp_path):
        # Create lockfile with wrong version
        user_lock = tmp_path / "user.lock.json"
        user_lock.write_text(json.dumps({
            "schema_version": LOCKFILE_SCHEMA_VERSION,
            "plugins": {
                "tweek-plugin-test": {
                    "version": "2.0.0",
                    "git_ref": "v2.0.0",
                },
            },
        }))
        compliant, violations = lockfile_manager.check_compliance()
        assert compliant is False
        assert any("version mismatch" in v for v in violations)

    def test_modified_file_is_violation(self, lockfile_manager, plugins_dir, tmp_path):
        # Generate lockfile, then modify a file
        lockfile_manager.generate(target="user")

        # Modify a plugin file
        plugin_file = plugins_dir / "tweek-plugin-test" / "plugin.py"
        plugin_file.write_text("class TestDetector:\n    MODIFIED = True\n")

        compliant, violations = lockfile_manager.check_compliance()
        assert compliant is False
        assert any("modified" in v for v in violations)
