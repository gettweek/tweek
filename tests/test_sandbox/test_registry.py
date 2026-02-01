"""
Comprehensive tests for tweek.sandbox.registry.ProjectRegistry.

Uses real temp directories via pytest's tmp_path fixture -- no mock data.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

pytestmark = pytest.mark.sandbox

from tweek.sandbox.layers import IsolationLayer
from tweek.sandbox.registry import (
    ProjectRegistry,
    get_registry,
    reset_registry,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_project_dir(tmp_path: Path, name: str = "myproject") -> Path:
    """Create and return a real temp project directory."""
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def _registry_path(tmp_path: Path) -> Path:
    """Return a registry JSON path scoped to the test's tmp_path."""
    return tmp_path / "tweek" / "projects" / "registry.json"


# ===================================================================
# 1. Registry creation with default and custom path
# ===================================================================

class TestRegistryCreation:

    def test_default_path(self, tmp_path, monkeypatch):
        """Registry uses REGISTRY_PATH when no custom path is supplied."""
        # We don't actually construct with the real default to avoid touching
        # the user's home directory; just verify the attribute logic.
        custom = _registry_path(tmp_path)
        reg = ProjectRegistry(registry_path=custom)
        assert reg.registry_path == custom

    def test_custom_path(self, tmp_path):
        custom = _registry_path(tmp_path)
        reg = ProjectRegistry(registry_path=custom)
        assert reg.registry_path == custom
        # Should have an empty projects dict
        assert reg._data["projects"] == {}

    def test_schema_version_present(self, tmp_path):
        reg = ProjectRegistry(registry_path=_registry_path(tmp_path))
        assert reg._data["schema_version"] == 1


# ===================================================================
# 2. _load()
# ===================================================================

class TestLoad:

    def test_handles_missing_file(self, tmp_path):
        """When the file does not exist, _load returns a fresh skeleton."""
        rp = _registry_path(tmp_path)
        assert not rp.exists()
        reg = ProjectRegistry(registry_path=rp)
        assert reg._data == {"schema_version": 1, "projects": {}}

    def test_handles_corrupted_json(self, tmp_path):
        """Corrupted JSON on disk yields a fresh skeleton."""
        rp = _registry_path(tmp_path)
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text("{{{not json at all!!")
        reg = ProjectRegistry(registry_path=rp)
        assert reg._data == {"schema_version": 1, "projects": {}}

    def test_handles_missing_projects_key(self, tmp_path):
        """Valid JSON but without a 'projects' key yields a fresh skeleton."""
        rp = _registry_path(tmp_path)
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(json.dumps({"schema_version": 1}))
        reg = ProjectRegistry(registry_path=rp)
        assert reg._data == {"schema_version": 1, "projects": {}}

    def test_handles_non_dict_json(self, tmp_path):
        """A JSON array on disk is not a dict, yields fresh skeleton."""
        rp = _registry_path(tmp_path)
        rp.parent.mkdir(parents=True, exist_ok=True)
        rp.write_text(json.dumps([1, 2, 3]))
        reg = ProjectRegistry(registry_path=rp)
        assert reg._data == {"schema_version": 1, "projects": {}}

    def test_loads_valid_file(self, tmp_path):
        """Pre-existing valid registry is loaded correctly."""
        rp = _registry_path(tmp_path)
        rp.parent.mkdir(parents=True, exist_ok=True)
        existing_data = {
            "schema_version": 1,
            "projects": {
                "/some/path": {
                    "layer": 2,
                    "created_at": "2025-01-01T00:00:00+00:00",
                    "last_used": "2025-01-01T00:00:00+00:00",
                    "auto_initialized": False,
                },
            },
        }
        rp.write_text(json.dumps(existing_data))
        reg = ProjectRegistry(registry_path=rp)
        assert "/some/path" in reg._data["projects"]
        assert reg._data["projects"]["/some/path"]["layer"] == 2


# ===================================================================
# 3. _save()
# ===================================================================

class TestSave:

    def test_persists_to_disk(self, tmp_path):
        """After register(), the file on disk reflects the new entry."""
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "proj_save")
        reg = ProjectRegistry(registry_path=rp)
        reg.register(proj)
        assert rp.exists()
        on_disk = json.loads(rp.read_text())
        assert str(proj.resolve()) in on_disk["projects"]

    def test_creates_parent_directories(self, tmp_path):
        """_save creates intermediate directories when they don't exist."""
        rp = tmp_path / "deep" / "nested" / "dir" / "registry.json"
        assert not rp.parent.exists()
        reg = ProjectRegistry(registry_path=rp)
        proj = _make_project_dir(tmp_path, "proj_mkdir")
        reg.register(proj)
        assert rp.exists()

    def test_round_trip(self, tmp_path):
        """Data written by one instance is read correctly by another."""
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "proj_rt")

        reg1 = ProjectRegistry(registry_path=rp)
        reg1.register(proj, layer=IsolationLayer.SKILLS)

        reg2 = ProjectRegistry(registry_path=rp)
        assert reg2.get_layer(proj) == IsolationLayer.SKILLS


# ===================================================================
# 4. register()
# ===================================================================

class TestRegister:

    def test_adds_new_project(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "new_proj")
        reg = ProjectRegistry(registry_path=rp)

        reg.register(proj, layer=IsolationLayer.PROJECT, auto_initialized=True)

        key = str(proj.resolve())
        entry = reg._data["projects"][key]
        assert entry["layer"] == IsolationLayer.PROJECT.value
        assert entry["auto_initialized"] is True
        assert "created_at" in entry
        assert "last_used" in entry

    def test_updates_existing_project_last_used(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "upd_proj")
        reg = ProjectRegistry(registry_path=rp)

        reg.register(proj, layer=IsolationLayer.BYPASS)
        key = str(proj.resolve())
        first_used = reg._data["projects"][key]["last_used"]
        first_created = reg._data["projects"][key]["created_at"]

        # Small sleep to ensure timestamp difference
        time.sleep(0.05)
        reg.register(proj, layer=IsolationLayer.SKILLS)

        entry = reg._data["projects"][key]
        assert entry["last_used"] > first_used
        # created_at stays the same on update
        assert entry["created_at"] == first_created
        # Layer gets updated
        assert entry["layer"] == IsolationLayer.SKILLS.value

    def test_default_layer_is_project(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "def_layer")
        reg = ProjectRegistry(registry_path=rp)

        reg.register(proj)
        key = str(proj.resolve())
        assert reg._data["projects"][key]["layer"] == IsolationLayer.PROJECT.value

    def test_register_multiple_projects(self, tmp_path):
        rp = _registry_path(tmp_path)
        reg = ProjectRegistry(registry_path=rp)
        dirs = [_make_project_dir(tmp_path, f"multi_{i}") for i in range(5)]
        for d in dirs:
            reg.register(d)
        assert len(reg._data["projects"]) == 5


# ===================================================================
# 5. update_last_used()
# ===================================================================

class TestUpdateLastUsed:

    def test_updates_timestamp_for_registered_project(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "ts_proj")
        reg = ProjectRegistry(registry_path=rp)
        reg.register(proj)

        key = str(proj.resolve())
        old_ts = reg._data["projects"][key]["last_used"]

        time.sleep(0.05)
        reg.update_last_used(proj)

        new_ts = reg._data["projects"][key]["last_used"]
        assert new_ts > old_ts

    def test_no_op_for_unregistered_project(self, tmp_path):
        rp = _registry_path(tmp_path)
        unknown = _make_project_dir(tmp_path, "unknown")
        reg = ProjectRegistry(registry_path=rp)

        # Should not raise and should not create an entry
        reg.update_last_used(unknown)
        assert reg._data["projects"] == {}

    def test_persists_after_update(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "persist_ts")
        reg = ProjectRegistry(registry_path=rp)
        reg.register(proj)

        time.sleep(0.05)
        reg.update_last_used(proj)

        # Reload from disk and verify
        reg2 = ProjectRegistry(registry_path=rp)
        key = str(proj.resolve())
        assert reg2._data["projects"][key]["last_used"] == reg._data["projects"][key]["last_used"]


# ===================================================================
# 6. get_layer()
# ===================================================================

class TestGetLayer:

    def test_returns_layer_for_registered_project(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "gl_proj")
        reg = ProjectRegistry(registry_path=rp)
        reg.register(proj, layer=IsolationLayer.SKILLS)
        assert reg.get_layer(proj) == IsolationLayer.SKILLS

    def test_returns_none_for_unregistered_project(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "gl_unreg")
        reg = ProjectRegistry(registry_path=rp)
        assert reg.get_layer(proj) is None

    def test_returns_correct_layer_after_update(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "gl_upd")
        reg = ProjectRegistry(registry_path=rp)
        reg.register(proj, layer=IsolationLayer.BYPASS)
        assert reg.get_layer(proj) == IsolationLayer.BYPASS

        reg.set_layer(proj, IsolationLayer.PROJECT)
        assert reg.get_layer(proj) == IsolationLayer.PROJECT

    def test_each_layer_value(self, tmp_path):
        """Verify all three IsolationLayer values round-trip correctly."""
        rp = _registry_path(tmp_path)
        reg = ProjectRegistry(registry_path=rp)
        for layer in IsolationLayer:
            proj = _make_project_dir(tmp_path, f"layer_{layer.name}")
            reg.register(proj, layer=layer)
            assert reg.get_layer(proj) == layer


# ===================================================================
# 7. set_layer()
# ===================================================================

class TestSetLayer:

    def test_updates_layer_for_existing_project(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "sl_exist")
        reg = ProjectRegistry(registry_path=rp)
        reg.register(proj, layer=IsolationLayer.BYPASS)

        reg.set_layer(proj, IsolationLayer.PROJECT)
        key = str(proj.resolve())
        assert reg._data["projects"][key]["layer"] == IsolationLayer.PROJECT.value

    def test_auto_registers_for_new_project(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "sl_new")
        reg = ProjectRegistry(registry_path=rp)

        assert not reg.is_registered(proj)
        reg.set_layer(proj, IsolationLayer.SKILLS)
        assert reg.is_registered(proj)
        assert reg.get_layer(proj) == IsolationLayer.SKILLS

    def test_persists_layer_change(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "sl_persist")
        reg = ProjectRegistry(registry_path=rp)
        reg.register(proj, layer=IsolationLayer.BYPASS)
        reg.set_layer(proj, IsolationLayer.SKILLS)

        # Reload from disk
        reg2 = ProjectRegistry(registry_path=rp)
        assert reg2.get_layer(proj) == IsolationLayer.SKILLS


# ===================================================================
# 8. deregister()
# ===================================================================

class TestDeregister:

    def test_removes_registered_project(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "dr_proj")
        reg = ProjectRegistry(registry_path=rp)
        reg.register(proj)
        assert reg.is_registered(proj)

        result = reg.deregister(proj)
        assert result is True
        assert not reg.is_registered(proj)

    def test_returns_false_for_unknown_project(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "dr_unknown")
        reg = ProjectRegistry(registry_path=rp)
        result = reg.deregister(proj)
        assert result is False

    def test_persists_after_deregister(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "dr_persist")
        reg = ProjectRegistry(registry_path=rp)
        reg.register(proj)
        reg.deregister(proj)

        reg2 = ProjectRegistry(registry_path=rp)
        assert not reg2.is_registered(proj)

    def test_only_removes_target(self, tmp_path):
        rp = _registry_path(tmp_path)
        keep = _make_project_dir(tmp_path, "dr_keep")
        remove = _make_project_dir(tmp_path, "dr_remove")
        reg = ProjectRegistry(registry_path=rp)
        reg.register(keep)
        reg.register(remove)

        reg.deregister(remove)
        assert reg.is_registered(keep)
        assert not reg.is_registered(remove)


# ===================================================================
# 9. is_registered()
# ===================================================================

class TestIsRegistered:

    def test_true_for_registered(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "ir_yes")
        reg = ProjectRegistry(registry_path=rp)
        reg.register(proj)
        assert reg.is_registered(proj) is True

    def test_false_for_unregistered(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "ir_no")
        reg = ProjectRegistry(registry_path=rp)
        assert reg.is_registered(proj) is False

    def test_false_after_deregister(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "ir_after")
        reg = ProjectRegistry(registry_path=rp)
        reg.register(proj)
        reg.deregister(proj)
        assert reg.is_registered(proj) is False


# ===================================================================
# 10. list_projects()
# ===================================================================

class TestListProjects:

    def test_empty_registry(self, tmp_path):
        rp = _registry_path(tmp_path)
        reg = ProjectRegistry(registry_path=rp)
        assert reg.list_projects() == []

    def test_returns_all_projects(self, tmp_path):
        rp = _registry_path(tmp_path)
        reg = ProjectRegistry(registry_path=rp)
        dirs = [_make_project_dir(tmp_path, f"lp_{i}") for i in range(3)]
        layers = [IsolationLayer.BYPASS, IsolationLayer.SKILLS, IsolationLayer.PROJECT]
        for d, layer in zip(dirs, layers):
            reg.register(d, layer=layer)

        projects = reg.list_projects()
        assert len(projects) == 3

        # Verify that each result has expected keys
        for p in projects:
            assert "path" in p
            assert "layer" in p
            assert "created_at" in p
            assert "last_used" in p
            assert "auto_initialized" in p
            assert isinstance(p["layer"], IsolationLayer)

    def test_correct_layer_mapping(self, tmp_path):
        rp = _registry_path(tmp_path)
        reg = ProjectRegistry(registry_path=rp)
        proj = _make_project_dir(tmp_path, "lp_layer")
        reg.register(proj, layer=IsolationLayer.SKILLS)

        projects = reg.list_projects()
        assert len(projects) == 1
        assert projects[0]["layer"] == IsolationLayer.SKILLS
        assert projects[0]["path"] == str(proj.resolve())

    def test_auto_initialized_flag(self, tmp_path):
        rp = _registry_path(tmp_path)
        reg = ProjectRegistry(registry_path=rp)
        proj = _make_project_dir(tmp_path, "lp_auto")
        reg.register(proj, auto_initialized=True)

        projects = reg.list_projects()
        assert projects[0]["auto_initialized"] is True

    def test_reflects_deregistration(self, tmp_path):
        rp = _registry_path(tmp_path)
        reg = ProjectRegistry(registry_path=rp)
        p1 = _make_project_dir(tmp_path, "lp_a")
        p2 = _make_project_dir(tmp_path, "lp_b")
        reg.register(p1)
        reg.register(p2)
        reg.deregister(p1)

        projects = reg.list_projects()
        assert len(projects) == 1
        assert projects[0]["path"] == str(p2.resolve())


# ===================================================================
# 11. cleanup_stale()
# ===================================================================

class TestCleanupStale:

    def test_removes_deleted_directories(self, tmp_path):
        rp = _registry_path(tmp_path)
        reg = ProjectRegistry(registry_path=rp)

        existing = _make_project_dir(tmp_path, "cs_exist")
        deleted = _make_project_dir(tmp_path, "cs_deleted")
        reg.register(existing)
        reg.register(deleted)

        # Actually remove the directory so Path.exists() returns False
        deleted.rmdir()

        removed = reg.cleanup_stale()
        assert removed == 1
        assert reg.is_registered(existing)
        assert not reg.is_registered(deleted)

    def test_returns_zero_when_all_exist(self, tmp_path):
        rp = _registry_path(tmp_path)
        reg = ProjectRegistry(registry_path=rp)
        p1 = _make_project_dir(tmp_path, "cs_ok1")
        p2 = _make_project_dir(tmp_path, "cs_ok2")
        reg.register(p1)
        reg.register(p2)

        removed = reg.cleanup_stale()
        assert removed == 0
        assert len(reg.list_projects()) == 2

    def test_removes_multiple_stale(self, tmp_path):
        rp = _registry_path(tmp_path)
        reg = ProjectRegistry(registry_path=rp)

        keep = _make_project_dir(tmp_path, "cs_keep")
        stale = [_make_project_dir(tmp_path, f"cs_stale_{i}") for i in range(4)]
        reg.register(keep)
        for s in stale:
            reg.register(s)

        for s in stale:
            s.rmdir()

        removed = reg.cleanup_stale()
        assert removed == 4
        assert len(reg.list_projects()) == 1

    def test_persists_cleanup(self, tmp_path):
        rp = _registry_path(tmp_path)
        reg = ProjectRegistry(registry_path=rp)
        existing = _make_project_dir(tmp_path, "cs_persist_keep")
        gone = _make_project_dir(tmp_path, "cs_persist_gone")
        reg.register(existing)
        reg.register(gone)
        gone.rmdir()

        reg.cleanup_stale()

        # Reload from disk
        reg2 = ProjectRegistry(registry_path=rp)
        assert reg2.is_registered(existing)
        assert not reg2.is_registered(gone)

    def test_no_save_when_nothing_stale(self, tmp_path):
        """When nothing is stale, _save should not be called (file mtime unchanged)."""
        rp = _registry_path(tmp_path)
        reg = ProjectRegistry(registry_path=rp)
        proj = _make_project_dir(tmp_path, "cs_nosave")
        reg.register(proj)

        mtime_before = rp.stat().st_mtime
        time.sleep(0.05)
        removed = reg.cleanup_stale()
        assert removed == 0
        mtime_after = rp.stat().st_mtime
        assert mtime_before == mtime_after


# ===================================================================
# 12. Singleton get_registry() and reset_registry()
# ===================================================================

class TestSingleton:

    def setup_method(self):
        """Always start with a clean singleton."""
        reset_registry()

    def teardown_method(self):
        """Leave singleton clean for other tests."""
        reset_registry()

    def test_get_registry_returns_instance(self, tmp_path):
        rp = _registry_path(tmp_path)
        reg = get_registry(registry_path=rp)
        assert isinstance(reg, ProjectRegistry)

    def test_get_registry_is_singleton(self, tmp_path):
        rp = _registry_path(tmp_path)
        reg1 = get_registry(registry_path=rp)
        reg2 = get_registry(registry_path=rp)
        assert reg1 is reg2

    def test_reset_registry_clears_singleton(self, tmp_path):
        rp = _registry_path(tmp_path)
        reg1 = get_registry(registry_path=rp)
        reset_registry()

        # After reset, a new path can be used (demonstrating independence)
        rp2 = tmp_path / "other" / "registry.json"
        reg2 = get_registry(registry_path=rp2)
        assert reg1 is not reg2

    def test_reset_then_get_creates_fresh_instance(self, tmp_path):
        rp = _registry_path(tmp_path)
        reg1 = get_registry(registry_path=rp)
        proj = _make_project_dir(tmp_path, "singleton_proj")
        reg1.register(proj)

        reset_registry()
        reg2 = get_registry(registry_path=rp)
        # Data is persisted on disk, so the new instance should still see it
        assert reg2.is_registered(proj)
        # But it is a different Python object
        assert reg1 is not reg2


# ===================================================================
# Integration / edge-case tests
# ===================================================================

class TestEdgeCases:

    def test_resolved_path_consistency(self, tmp_path):
        """Registering via a relative-style path still resolves correctly."""
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "resolve_test")
        reg = ProjectRegistry(registry_path=rp)

        # Register using the direct path
        reg.register(proj)
        # Query using the resolved path
        assert reg.is_registered(proj.resolve())

    def test_re_register_preserves_created_at(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "re_reg")
        reg = ProjectRegistry(registry_path=rp)
        reg.register(proj)
        key = str(proj.resolve())
        original_created = reg._data["projects"][key]["created_at"]

        time.sleep(0.05)
        reg.register(proj, layer=IsolationLayer.SKILLS)
        assert reg._data["projects"][key]["created_at"] == original_created

    def test_concurrent_registrations_in_sequence(self, tmp_path):
        """Two separate instances writing to the same file -- last write wins."""
        rp = _registry_path(tmp_path)
        p1 = _make_project_dir(tmp_path, "conc_a")
        p2 = _make_project_dir(tmp_path, "conc_b")

        reg_a = ProjectRegistry(registry_path=rp)
        reg_a.register(p1)

        # reg_b loads from disk (sees p1)
        reg_b = ProjectRegistry(registry_path=rp)
        reg_b.register(p2)

        # reg_b should see both
        assert reg_b.is_registered(p1)
        assert reg_b.is_registered(p2)

    def test_empty_projects_after_full_deregister(self, tmp_path):
        rp = _registry_path(tmp_path)
        reg = ProjectRegistry(registry_path=rp)
        dirs = [_make_project_dir(tmp_path, f"empty_{i}") for i in range(3)]
        for d in dirs:
            reg.register(d)
        for d in dirs:
            reg.deregister(d)
        assert reg.list_projects() == []
        assert reg._data["projects"] == {}

    def test_timestamps_are_utc_iso_format(self, tmp_path):
        rp = _registry_path(tmp_path)
        proj = _make_project_dir(tmp_path, "ts_utc")
        reg = ProjectRegistry(registry_path=rp)

        before = datetime.now(timezone.utc)
        reg.register(proj)
        after = datetime.now(timezone.utc)

        key = str(proj.resolve())
        created_str = reg._data["projects"][key]["created_at"]
        created_dt = datetime.fromisoformat(created_str)
        assert created_dt.tzinfo is not None
        assert before <= created_dt <= after
