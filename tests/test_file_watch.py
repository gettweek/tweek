#!/usr/bin/env python3
"""
Tests for tweek.security.file_watch module.

File integrity monitoring: baseline creation, drift detection,
diff generation, approval, and restore with quarantine.
"""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.security

from tweek.security.file_watch import (
    BaselineEntry,
    DriftResult,
    DriftStatus,
    FileIntegrityMonitor,
    FilePolicy,
    IntegrityReport,
)


@pytest.fixture(autouse=True)
def _isolate_watched_files():
    """Prevent tests from picking up real system files."""
    with patch("tweek.security.file_watch.DEFAULT_WATCHED_FILES", []), \
         patch("tweek.security.file_watch.PROJECT_WATCHED_FILES", []):
        yield


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def watch_env(tmp_path):
    """Create an isolated file watch environment with fake watched files."""
    baselines_path = tmp_path / "baselines.json"
    quarantine_dir = tmp_path / "quarantine"

    # Create fake global .claude/ settings
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    settings = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "",
                    "hooks": [
                        {"type": "command", "command": "tweek hook pre-tool-use"}
                    ],
                }
            ]
        }
    }
    settings_text = json.dumps(settings, indent=2)
    (claude_dir / "settings.json").write_text(settings_text)
    (claude_dir / "settings.json.tweek-backup").write_text(settings_text)

    # Create fake hook wrappers
    hooks_dir = tmp_path / ".tweek" / "hooks"
    hooks_dir.mkdir(parents=True)
    (hooks_dir / "pre_tool_use.py").write_text("# pre hook\nprint('hello')\n")
    (hooks_dir / "post_tool_use.py").write_text("# post hook\nprint('world')\n")

    # Create overrides file
    tweek_dir = tmp_path / ".tweek"
    overrides = tweek_dir / "overrides.yaml"
    overrides.write_text("whitelist: []\n")

    return {
        "tmp_path": tmp_path,
        "baselines_path": baselines_path,
        "quarantine_dir": quarantine_dir,
        "claude_dir": claude_dir,
        "hooks_dir": hooks_dir,
        "overrides": overrides,
    }


@pytest.fixture
def monitor(watch_env):
    """Create a FileIntegrityMonitor pointing at the test environment."""
    return FileIntegrityMonitor(
        baselines_path=watch_env["baselines_path"],
        quarantine_dir=watch_env["quarantine_dir"],
    )


def _custom_watched_files(env):
    """Build watched file definitions pointing at the test environment."""
    return [
        {
            "path_expr": str(env["claude_dir"] / "settings.json"),
            "policy": "restore",
            "label": "Global Claude settings",
        },
        {
            "path_expr": str(env["hooks_dir"] / "pre_tool_use.py"),
            "policy": "restore",
            "label": "Pre-tool-use hook",
        },
        {
            "path_expr": str(env["hooks_dir"] / "post_tool_use.py"),
            "policy": "restore",
            "label": "Post-tool-use hook",
        },
        {
            "path_expr": str(env["overrides"]),
            "policy": "alert",
            "label": "Security overrides",
        },
    ]


# ---------------------------------------------------------------------------
# TestHashFile
# ---------------------------------------------------------------------------


class TestHashFile:
    """Tests for SHA-256 hashing."""

    def test_consistent_hash(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world")
        h1 = FileIntegrityMonitor.hash_file(f)
        h2 = FileIntegrityMonitor.hash_file(f)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest length

    def test_different_content_different_hash(self, tmp_path):
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_text("hello")
        f2.write_text("world")
        assert FileIntegrityMonitor.hash_file(f1) != FileIntegrityMonitor.hash_file(f2)

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        h = FileIntegrityMonitor.hash_file(f)
        assert len(h) == 64
        # SHA-256 of empty string is well-known
        assert h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ---------------------------------------------------------------------------
# TestResolveSafe
# ---------------------------------------------------------------------------


class TestResolveSafe:
    """Tests for symlink refusal."""

    def test_regular_file(self, tmp_path):
        f = tmp_path / "real.txt"
        f.write_text("content")
        resolved = FileIntegrityMonitor._resolve_safe(f)
        assert resolved == f.resolve()

    def test_symlink_refused(self, tmp_path):
        target = tmp_path / "real.txt"
        target.write_text("content")
        link = tmp_path / "link.txt"
        link.symlink_to(target)
        with pytest.raises(ValueError, match="symlink"):
            FileIntegrityMonitor._resolve_safe(link)

    def test_directory_resolves(self, tmp_path):
        d = tmp_path / "subdir"
        d.mkdir()
        resolved = FileIntegrityMonitor._resolve_safe(d)
        assert resolved == d.resolve()


# ---------------------------------------------------------------------------
# TestBaselineCRUD
# ---------------------------------------------------------------------------


class TestBaselineCRUD:
    """Tests for baseline persistence."""

    def test_save_and_load_roundtrip(self, monitor, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("data")

        baselines = {
            str(f): BaselineEntry(
                path=str(f),
                sha256="abc123",
                size=4,
                mtime=1000.0,
                policy="alert",
                created_at="2026-01-01T00:00:00",
                updated_at="2026-01-01T00:00:00",
                label="Test file",
            )
        }
        monitor.save_baselines(baselines)
        loaded = monitor.load_baselines()

        assert str(f) in loaded
        entry = loaded[str(f)]
        assert entry.sha256 == "abc123"
        assert entry.policy == "alert"
        assert entry.label == "Test file"

    def test_load_missing_file(self, monitor):
        loaded = monitor.load_baselines()
        assert loaded == {}

    def test_load_corrupt_json(self, monitor):
        monitor.baselines_path.parent.mkdir(parents=True, exist_ok=True)
        monitor.baselines_path.write_text("{invalid json")
        loaded = monitor.load_baselines()
        assert loaded == {}

    def test_atomic_write(self, monitor, tmp_path):
        """Save should use atomic write (no partial files on crash)."""
        f = tmp_path / "x.txt"
        f.write_text("x")
        baselines = {
            str(f): BaselineEntry(
                path=str(f), sha256="a", size=1, mtime=1.0,
                policy="alert", created_at="t", updated_at="t",
            )
        }
        monitor.save_baselines(baselines)
        assert monitor.baselines_path.exists()
        data = json.loads(monitor.baselines_path.read_text())
        assert data["version"] == 1
        assert str(f) in data["files"]


# ---------------------------------------------------------------------------
# TestInitBaselines
# ---------------------------------------------------------------------------


class TestInitBaselines:
    """Tests for baseline initialization."""

    def test_creates_baselines_for_existing_files(self, monitor, watch_env):
        custom = _custom_watched_files(watch_env)
        created, skipped = monitor.init_baselines(
            include_project=False, extra_paths=custom
        )
        assert created == 4
        baselines = monitor.load_baselines()
        assert len(baselines) == 4

    def test_skips_missing_files(self, monitor, watch_env):
        custom = [
            {
                "path_expr": str(watch_env["tmp_path"] / "nonexistent.txt"),
                "policy": "alert",
                "label": "Missing",
            }
        ]
        created, skipped = monitor.init_baselines(
            include_project=False, extra_paths=custom
        )
        assert created == 0
        assert skipped >= 1

    def test_force_overwrites_existing(self, monitor, watch_env):
        custom = _custom_watched_files(watch_env)
        monitor.init_baselines(include_project=False, extra_paths=custom)

        # Modify a file
        settings = watch_env["claude_dir"] / "settings.json"
        original_hash = monitor.load_baselines()[str(settings.resolve())].sha256
        settings.write_text('{"modified": true}')

        # Re-init without force — should skip
        created, _ = monitor.init_baselines(
            include_project=False, extra_paths=custom
        )
        assert created == 0

        # Re-init with force — should overwrite
        created, _ = monitor.init_baselines(
            include_project=False, extra_paths=custom, force=True
        )
        assert created == 4
        new_hash = monitor.load_baselines()[str(settings.resolve())].sha256
        assert new_hash != original_hash

    def test_skips_symlinks(self, monitor, watch_env):
        real = watch_env["tmp_path"] / "real.txt"
        real.write_text("real content")
        link = watch_env["tmp_path"] / "link.txt"
        link.symlink_to(real)

        custom = [
            {
                "path_expr": str(link),
                "policy": "alert",
                "label": "Symlink",
            }
        ]
        created, skipped = monitor.init_baselines(
            include_project=False, extra_paths=custom
        )
        assert created == 0
        assert skipped >= 1


# ---------------------------------------------------------------------------
# TestCheckIntegrity
# ---------------------------------------------------------------------------


class TestCheckIntegrity:
    """Tests for integrity verification."""

    def test_clean_report(self, monitor, watch_env):
        custom = _custom_watched_files(watch_env)
        monitor.init_baselines(include_project=False, extra_paths=custom)

        report = monitor.check_integrity()
        assert report.is_clean
        assert report.ok_count == 4
        assert report.modified_count == 0
        assert report.missing_count == 0

    def test_detects_modification(self, monitor, watch_env):
        custom = _custom_watched_files(watch_env)
        monitor.init_baselines(include_project=False, extra_paths=custom)

        # Modify settings.json
        settings = watch_env["claude_dir"] / "settings.json"
        settings.write_text('{"tampered": true}')

        report = monitor.check_integrity()
        assert not report.is_clean
        assert report.modified_count == 1

        modified = [r for r in report.results if r.status == DriftStatus.MODIFIED]
        assert len(modified) == 1
        assert modified[0].current_sha256 != modified[0].baseline_sha256

    def test_detects_deletion(self, monitor, watch_env):
        custom = _custom_watched_files(watch_env)
        monitor.init_baselines(include_project=False, extra_paths=custom)

        # Delete a watched file
        (watch_env["hooks_dir"] / "pre_tool_use.py").unlink()

        report = monitor.check_integrity()
        assert not report.is_clean
        assert report.missing_count == 1

    def test_empty_baselines_returns_clean(self, monitor):
        report = monitor.check_integrity()
        assert report.is_clean
        assert report.total_files == 0

    def test_detects_symlink_replacement(self, monitor, watch_env):
        custom = _custom_watched_files(watch_env)
        monitor.init_baselines(include_project=False, extra_paths=custom)

        # Replace a real file with a symlink
        hook = watch_env["hooks_dir"] / "pre_tool_use.py"
        evil = watch_env["tmp_path"] / "evil.py"
        evil.write_text("# malicious code")
        hook.unlink()
        hook.symlink_to(evil)

        report = monitor.check_integrity()
        assert not report.is_clean
        # Should be flagged as modified (symlink = suspicious)
        drifted = [r for r in report.results if r.status != DriftStatus.OK]
        assert len(drifted) >= 1


# ---------------------------------------------------------------------------
# TestDiffFile
# ---------------------------------------------------------------------------


class TestDiffFile:
    """Tests for diff generation."""

    def test_diff_shows_changes(self, monitor, watch_env):
        settings = watch_env["claude_dir"] / "settings.json"
        custom = _custom_watched_files(watch_env)
        monitor.init_baselines(include_project=False, extra_paths=custom)

        # Modify the file
        settings.write_text('{"tampered": true}')

        diff = monitor.diff_file(str(settings.resolve()))
        assert diff is not None
        assert "---" in diff or "baseline" in diff.lower()

    def test_diff_deleted_file(self, monitor, watch_env):
        settings = watch_env["claude_dir"] / "settings.json"
        custom = _custom_watched_files(watch_env)
        monitor.init_baselines(include_project=False, extra_paths=custom)

        settings.unlink()
        diff = monitor.diff_file(str(settings.resolve()))
        assert diff is not None
        assert "deleted" in diff.lower()

    def test_diff_no_backup(self, monitor, watch_env):
        overrides = watch_env["overrides"]
        custom = _custom_watched_files(watch_env)
        monitor.init_baselines(include_project=False, extra_paths=custom)

        overrides.write_text("whitelist: [hacked]")

        diff = monitor.diff_file(str(overrides.resolve()))
        assert diff is not None
        assert "no backup" in diff.lower() or "SHA-256" in diff

    def test_diff_not_in_baselines(self, monitor):
        result = monitor.diff_file("/nonexistent/path")
        assert result is None

    def test_diff_identical_files(self, monitor, watch_env):
        settings = watch_env["claude_dir"] / "settings.json"
        custom = _custom_watched_files(watch_env)
        monitor.init_baselines(include_project=False, extra_paths=custom)

        # File unchanged
        diff = monitor.diff_file(str(settings.resolve()))
        assert diff is not None
        assert "no differences" in diff.lower()


# ---------------------------------------------------------------------------
# TestApproveFile
# ---------------------------------------------------------------------------


class TestApproveFile:
    """Tests for baseline approval."""

    def test_approve_updates_hash(self, monitor, watch_env):
        settings = watch_env["claude_dir"] / "settings.json"
        custom = _custom_watched_files(watch_env)
        monitor.init_baselines(include_project=False, extra_paths=custom)

        key = str(settings.resolve())
        old_hash = monitor.load_baselines()[key].sha256

        settings.write_text('{"approved_change": true}')
        assert monitor.approve_file(key)

        new_hash = monitor.load_baselines()[key].sha256
        assert new_hash != old_hash

    def test_approve_nonexistent_file(self, monitor):
        assert not monitor.approve_file("/nonexistent/path")

    def test_approve_file_not_in_baselines(self, monitor, watch_env):
        f = watch_env["tmp_path"] / "random.txt"
        f.write_text("data")
        assert not monitor.approve_file(str(f))

    def test_approve_all_drifted(self, monitor, watch_env):
        custom = _custom_watched_files(watch_env)
        monitor.init_baselines(include_project=False, extra_paths=custom)

        # Modify two files
        (watch_env["claude_dir"] / "settings.json").write_text('{"a": 1}')
        (watch_env["overrides"]).write_text("whitelist: [new]")

        count = monitor.approve_all()
        assert count == 2

        # Should be clean now
        report = monitor.check_integrity()
        assert report.is_clean

    def test_approve_all_no_drift(self, monitor, watch_env):
        custom = _custom_watched_files(watch_env)
        monitor.init_baselines(include_project=False, extra_paths=custom)

        count = monitor.approve_all()
        assert count == 0


# ---------------------------------------------------------------------------
# TestRestoreFile
# ---------------------------------------------------------------------------


class TestRestoreFile:
    """Tests for quarantine and restore."""

    def test_restore_quarantines_and_replaces(self, monitor, watch_env):
        settings = watch_env["claude_dir"] / "settings.json"
        backup = watch_env["claude_dir"] / "settings.json.tweek-backup"
        custom = _custom_watched_files(watch_env)
        monitor.init_baselines(include_project=False, extra_paths=custom)

        # Tamper with the file
        original_content = backup.read_text()
        settings.write_text('{"tampered": true}')

        key = str(settings.resolve())
        success, msg = monitor.restore_file(key)
        assert success
        assert "quarantine" in msg.lower()

        # File should be restored
        assert settings.read_text() == original_content

        # Quarantine dir should have the tampered version
        assert monitor.quarantine_dir.exists()
        quarantined = list(monitor.quarantine_dir.iterdir())
        assert len(quarantined) == 1
        assert '{"tampered": true}' in quarantined[0].read_text()

    def test_restore_alert_policy_refused(self, monitor, watch_env):
        custom = _custom_watched_files(watch_env)
        monitor.init_baselines(include_project=False, extra_paths=custom)

        key = str(watch_env["overrides"].resolve())
        success, msg = monitor.restore_file(key)
        assert not success
        assert "alert" in msg.lower()

    def test_restore_no_backup(self, monitor, watch_env):
        # Create a restore-policy file with no backup
        orphan = watch_env["tmp_path"] / "orphan.json"
        orphan.write_text("{}")
        custom = [
            {"path_expr": str(orphan), "policy": "restore", "label": "Orphan"},
        ]
        monitor.init_baselines(include_project=False, extra_paths=custom)

        key = str(orphan.resolve())
        success, msg = monitor.restore_file(key)
        assert not success
        assert "No backup" in msg

    def test_restore_not_in_baselines(self, monitor):
        success, msg = monitor.restore_file("/nonexistent")
        assert not success
        assert "Not in baselines" in msg

    def test_quarantine_dir_created(self, monitor, watch_env):
        settings = watch_env["claude_dir"] / "settings.json"
        custom = _custom_watched_files(watch_env)
        monitor.init_baselines(include_project=False, extra_paths=custom)

        settings.write_text('{"tampered": true}')
        assert not monitor.quarantine_dir.exists()

        key = str(settings.resolve())
        monitor.restore_file(key)
        assert monitor.quarantine_dir.exists()


# ---------------------------------------------------------------------------
# TestIntegrityReport
# ---------------------------------------------------------------------------


class TestIntegrityReport:
    """Tests for IntegrityReport properties."""

    def test_is_clean_with_all_ok(self):
        report = IntegrityReport(
            timestamp="t", total_files=2, ok_count=2,
            modified_count=0, missing_count=0, results=[],
        )
        assert report.is_clean

    def test_not_clean_with_modified(self):
        report = IntegrityReport(
            timestamp="t", total_files=2, ok_count=1,
            modified_count=1, missing_count=0, results=[],
        )
        assert not report.is_clean

    def test_not_clean_with_missing(self):
        report = IntegrityReport(
            timestamp="t", total_files=2, ok_count=1,
            modified_count=0, missing_count=1, results=[],
        )
        assert not report.is_clean

    def test_empty_report_is_clean(self):
        report = IntegrityReport(
            timestamp="t", total_files=0, ok_count=0,
            modified_count=0, missing_count=0, results=[],
        )
        assert report.is_clean


# ---------------------------------------------------------------------------
# TestFindBackup
# ---------------------------------------------------------------------------


class TestFindBackup:
    """Tests for backup file discovery."""

    def test_finds_settings_backup(self, watch_env):
        settings = watch_env["claude_dir"] / "settings.json"
        backup = FileIntegrityMonitor._find_backup(settings)
        assert backup is not None
        assert backup.name == "settings.json.tweek-backup"

    def test_no_backup_for_random_file(self, tmp_path):
        f = tmp_path / "random.txt"
        f.write_text("data")
        backup = FileIntegrityMonitor._find_backup(f)
        assert backup is None

    def test_no_backup_when_missing(self, tmp_path):
        settings = tmp_path / "settings.json"
        settings.write_text("{}")
        # No .tweek-backup file exists
        backup = FileIntegrityMonitor._find_backup(settings)
        assert backup is None


# ---------------------------------------------------------------------------
# TestEventTypeIntegration
# ---------------------------------------------------------------------------


class TestEventTypeIntegration:
    """Tests for new EventType members."""

    def test_file_integrity_event_types_exist(self):
        from tweek.logging.security_log import EventType

        assert hasattr(EventType, "FILE_INTEGRITY_VIOLATION")
        assert hasattr(EventType, "FILE_INTEGRITY_RESTORE")
        assert hasattr(EventType, "FILE_INTEGRITY_APPROVE")
        assert EventType.FILE_INTEGRITY_VIOLATION.value == "file_integrity_violation"
