"""
Comprehensive tests for the tweek.skills.fingerprints module.

Tests cover:
- SkillFingerprints.__init__ and _load (empty, missing, invalid, valid JSON)
- _hash_file (SHA-256 hashing)
- is_known (matching, unknown, modified, missing files)
- register (new, update, custom verdict/report_path)
- remove (existing and non-existing entries)
- check_project_skills (new, modified, known skills)
- cleanup_stale (stale entry removal)
- get_fingerprints (module-level singleton)
"""

import pytest

pytestmark = pytest.mark.skills

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from tweek.skills.fingerprints import SkillFingerprints, get_fingerprints


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(content: bytes) -> str:
    """Compute SHA-256 hex digest for given bytes."""
    return hashlib.sha256(content).hexdigest()


def _make_skill_file(directory: Path, name: str = "SKILL.md", content: str = "# My Skill\n") -> Path:
    """Create a skill file inside a directory and return its path."""
    directory.mkdir(parents=True, exist_ok=True)
    fp = directory / name
    fp.write_text(content)
    return fp


def _make_cache(cache_path: Path, data: dict) -> None:
    """Write a JSON cache file."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# __init__ and _load
# ---------------------------------------------------------------------------

class TestInitAndLoad:
    """Tests for SkillFingerprints.__init__ and _load."""

    def test_load_missing_file(self, tmp_path):
        """Loading from a non-existent cache file returns the empty skeleton."""
        cache_path = tmp_path / "nonexistent" / "fingerprints.json"
        fp = SkillFingerprints(cache_path=cache_path)
        assert fp._data == {"schema_version": 1, "skills": {}}

    def test_load_empty_file(self, tmp_path):
        """An empty file is invalid JSON; _load returns the default skeleton."""
        cache_path = tmp_path / "fingerprints.json"
        cache_path.write_text("")
        fp = SkillFingerprints(cache_path=cache_path)
        assert fp._data == {"schema_version": 1, "skills": {}}

    def test_load_invalid_json(self, tmp_path):
        """Corrupted JSON falls back to the default skeleton."""
        cache_path = tmp_path / "fingerprints.json"
        cache_path.write_text("{not valid json!!!")
        fp = SkillFingerprints(cache_path=cache_path)
        assert fp._data == {"schema_version": 1, "skills": {}}

    def test_load_json_without_skills_key(self, tmp_path):
        """Valid JSON missing the 'skills' key falls back to default."""
        cache_path = tmp_path / "fingerprints.json"
        cache_path.write_text(json.dumps({"schema_version": 1}))
        fp = SkillFingerprints(cache_path=cache_path)
        assert fp._data == {"schema_version": 1, "skills": {}}

    def test_load_json_not_a_dict(self, tmp_path):
        """JSON that is an array (not a dict) falls back to default."""
        cache_path = tmp_path / "fingerprints.json"
        cache_path.write_text(json.dumps([1, 2, 3]))
        fp = SkillFingerprints(cache_path=cache_path)
        assert fp._data == {"schema_version": 1, "skills": {}}

    def test_load_valid_json(self, tmp_path):
        """Valid JSON with correct structure is loaded as-is."""
        cache_path = tmp_path / "fingerprints.json"
        valid_data = {
            "schema_version": 1,
            "skills": {
                "/some/path/SKILL.md": {
                    "sha256": "abc123",
                    "scanned_at": "2026-01-01T00:00:00Z",
                    "verdict": "pass",
                    "report_path": "",
                }
            },
        }
        _make_cache(cache_path, valid_data)
        fp = SkillFingerprints(cache_path=cache_path)
        assert fp._data == valid_data

    def test_default_cache_path(self):
        """Without an explicit cache_path the class uses the module default."""
        from tweek.skills.fingerprints import FINGERPRINT_PATH

        fp = SkillFingerprints()
        assert fp.cache_path == FINGERPRINT_PATH


# ---------------------------------------------------------------------------
# _hash_file
# ---------------------------------------------------------------------------

class TestHashFile:
    """Tests for the static _hash_file method."""

    def test_hash_known_content(self, tmp_path):
        """Hash of a known string matches the expected SHA-256 digest."""
        content = b"Hello, World!"
        f = tmp_path / "hello.txt"
        f.write_bytes(content)
        assert SkillFingerprints._hash_file(f) == _sha256(content)

    def test_hash_empty_file(self, tmp_path):
        """Hash of an empty file matches SHA-256 of empty bytes."""
        f = tmp_path / "empty.txt"
        f.write_bytes(b"")
        assert SkillFingerprints._hash_file(f) == _sha256(b"")

    def test_hash_large_file(self, tmp_path):
        """Hash of a file larger than the 8192-byte chunk boundary is correct."""
        content = b"A" * 20_000
        f = tmp_path / "large.bin"
        f.write_bytes(content)
        assert SkillFingerprints._hash_file(f) == _sha256(content)

    def test_hash_binary_content(self, tmp_path):
        """Binary (non-UTF-8) content hashes correctly."""
        content = bytes(range(256)) * 10
        f = tmp_path / "binary.bin"
        f.write_bytes(content)
        assert SkillFingerprints._hash_file(f) == _sha256(content)

    def test_hash_missing_file_raises(self, tmp_path):
        """Hashing a nonexistent file raises an appropriate error."""
        missing = tmp_path / "does_not_exist.md"
        with pytest.raises((IOError, OSError, FileNotFoundError)):
            SkillFingerprints._hash_file(missing)


# ---------------------------------------------------------------------------
# is_known
# ---------------------------------------------------------------------------

class TestIsKnown:
    """Tests for is_known."""

    def test_known_file_matching_hash(self, tmp_path):
        """A registered file whose content has not changed is recognized."""
        cache_path = tmp_path / "fp.json"
        skill = _make_skill_file(tmp_path / "skills" / "my-skill")
        fp = SkillFingerprints(cache_path=cache_path)
        fp.register(skill)
        assert fp.is_known(skill) is True

    def test_unknown_file_no_entry(self, tmp_path):
        """A file with no cache entry is unknown."""
        cache_path = tmp_path / "fp.json"
        skill = _make_skill_file(tmp_path / "skills" / "my-skill")
        fp = SkillFingerprints(cache_path=cache_path)
        assert fp.is_known(skill) is False

    def test_modified_file_different_hash(self, tmp_path):
        """A file whose content changed after registration is not known."""
        cache_path = tmp_path / "fp.json"
        skill = _make_skill_file(tmp_path / "skills" / "my-skill", content="original")
        fp = SkillFingerprints(cache_path=cache_path)
        fp.register(skill)
        # Modify the file
        skill.write_text("modified content")
        assert fp.is_known(skill) is False

    def test_missing_file_returns_false(self, tmp_path):
        """A file that was registered but then deleted returns False."""
        cache_path = tmp_path / "fp.json"
        skill = _make_skill_file(tmp_path / "skills" / "my-skill")
        fp = SkillFingerprints(cache_path=cache_path)
        fp.register(skill)
        skill.unlink()
        assert fp.is_known(skill) is False


# ---------------------------------------------------------------------------
# register
# ---------------------------------------------------------------------------

class TestRegister:
    """Tests for register."""

    def test_register_new_file(self, tmp_path):
        """Registering a new file adds its hash to the cache and persists."""
        cache_path = tmp_path / "fp.json"
        skill = _make_skill_file(tmp_path / "skills" / "a-skill", content="content A")
        fp = SkillFingerprints(cache_path=cache_path)
        fp.register(skill)

        key = str(skill.resolve())
        assert key in fp._data["skills"]
        entry = fp._data["skills"][key]
        assert entry["sha256"] == _sha256(b"content A")
        assert entry["verdict"] == "pass"
        assert entry["report_path"] == ""
        # Verify it was persisted to disk
        assert cache_path.exists()
        on_disk = json.loads(cache_path.read_text())
        assert key in on_disk["skills"]

    def test_register_updates_existing(self, tmp_path):
        """Re-registering a modified file updates the stored hash."""
        cache_path = tmp_path / "fp.json"
        skill = _make_skill_file(tmp_path / "skills" / "b-skill", content="v1")
        fp = SkillFingerprints(cache_path=cache_path)
        fp.register(skill)
        old_hash = fp._data["skills"][str(skill.resolve())]["sha256"]

        skill.write_text("v2")
        fp.register(skill)
        new_hash = fp._data["skills"][str(skill.resolve())]["sha256"]

        assert old_hash != new_hash
        assert new_hash == _sha256(b"v2")

    def test_register_custom_verdict_and_report(self, tmp_path):
        """Custom verdict and report_path are stored correctly."""
        cache_path = tmp_path / "fp.json"
        skill = _make_skill_file(tmp_path / "skills" / "c-skill")
        fp = SkillFingerprints(cache_path=cache_path)
        fp.register(skill, verdict="quarantine", report_path="/tmp/report.json")

        entry = fp._data["skills"][str(skill.resolve())]
        assert entry["verdict"] == "quarantine"
        assert entry["report_path"] == "/tmp/report.json"

    def test_register_missing_file_is_noop(self, tmp_path):
        """Registering a file that does not exist does nothing."""
        cache_path = tmp_path / "fp.json"
        missing = tmp_path / "nope" / "SKILL.md"
        fp = SkillFingerprints(cache_path=cache_path)
        fp.register(missing)
        assert fp._data["skills"] == {}

    def test_register_includes_scanned_at(self, tmp_path):
        """Registered entries contain an ISO-format scanned_at timestamp."""
        cache_path = tmp_path / "fp.json"
        skill = _make_skill_file(tmp_path / "skills" / "d-skill")
        fp = SkillFingerprints(cache_path=cache_path)
        fp.register(skill)

        entry = fp._data["skills"][str(skill.resolve())]
        # Should be parseable ISO timestamp ending with +00:00 or Z
        assert "scanned_at" in entry
        assert len(entry["scanned_at"]) > 0


# ---------------------------------------------------------------------------
# remove
# ---------------------------------------------------------------------------

class TestRemove:
    """Tests for remove."""

    def test_remove_existing_entry(self, tmp_path):
        """Removing a registered skill deletes it from the cache."""
        cache_path = tmp_path / "fp.json"
        skill = _make_skill_file(tmp_path / "skills" / "e-skill")
        fp = SkillFingerprints(cache_path=cache_path)
        fp.register(skill)
        assert str(skill.resolve()) in fp._data["skills"]

        fp.remove(skill)
        assert str(skill.resolve()) not in fp._data["skills"]
        # Verify persistence
        on_disk = json.loads(cache_path.read_text())
        assert str(skill.resolve()) not in on_disk["skills"]

    def test_remove_nonexistent_entry(self, tmp_path):
        """Removing a path that was never registered is a silent no-op."""
        cache_path = tmp_path / "fp.json"
        fp = SkillFingerprints(cache_path=cache_path)
        unknown_skill = tmp_path / "unknown" / "SKILL.md"
        # Should not raise
        fp.remove(unknown_skill)
        assert fp._data["skills"] == {}


# ---------------------------------------------------------------------------
# check_project_skills
# ---------------------------------------------------------------------------

class TestCheckProjectSkills:
    """Tests for check_project_skills."""

    def test_empty_skills_dir(self, tmp_path):
        """A project with no .claude/skills/ returns an empty list."""
        fp = SkillFingerprints(cache_path=tmp_path / "fp.json")
        results = fp.check_project_skills(working_dir=tmp_path)
        assert results == []

    def test_new_skill_detected(self, tmp_path):
        """An unregistered SKILL.md is detected as 'new'."""
        skills_dir = tmp_path / ".claude" / "skills" / "new-skill"
        _make_skill_file(skills_dir, content="brand new")
        fp = SkillFingerprints(cache_path=tmp_path / "fp.json")

        results = fp.check_project_skills(working_dir=tmp_path)
        assert len(results) == 1
        path, status = results[0]
        assert status == "new"
        assert path.name == "SKILL.md"

    def test_modified_skill_detected(self, tmp_path):
        """A SKILL.md whose content changed since registration is 'modified'."""
        skills_dir = tmp_path / ".claude" / "skills" / "mod-skill"
        skill = _make_skill_file(skills_dir, content="original")

        fp = SkillFingerprints(cache_path=tmp_path / "fp.json")
        fp.register(skill)

        # Now modify
        skill.write_text("modified!")
        results = fp.check_project_skills(working_dir=tmp_path)
        assert len(results) == 1
        _, status = results[0]
        assert status == "modified"

    def test_known_skill_omitted(self, tmp_path):
        """A known, unchanged SKILL.md does not appear in results."""
        skills_dir = tmp_path / ".claude" / "skills" / "ok-skill"
        skill = _make_skill_file(skills_dir, content="known good")

        fp = SkillFingerprints(cache_path=tmp_path / "fp.json")
        fp.register(skill)

        results = fp.check_project_skills(working_dir=tmp_path)
        assert results == []

    def test_mixed_skills(self, tmp_path):
        """Multiple skills with mixed states are categorized correctly."""
        base = tmp_path / ".claude" / "skills"

        known_skill = _make_skill_file(base / "known-skill", content="known")
        new_skill = _make_skill_file(base / "new-skill", content="new")
        modified_skill = _make_skill_file(base / "mod-skill", content="orig")

        fp = SkillFingerprints(cache_path=tmp_path / "fp.json")
        fp.register(known_skill)
        fp.register(modified_skill)

        modified_skill.write_text("changed")

        results = fp.check_project_skills(working_dir=tmp_path)
        statuses = {status for _, status in results}
        assert "new" in statuses
        assert "modified" in statuses
        # known should not appear
        paths = {str(p.resolve()) for p, _ in results}
        assert str(known_skill.resolve()) not in paths


# ---------------------------------------------------------------------------
# cleanup_stale
# ---------------------------------------------------------------------------

class TestCleanupStale:
    """Tests for cleanup_stale."""

    def test_removes_stale_entries(self, tmp_path):
        """Entries for deleted files are removed and the count is returned."""
        cache_path = tmp_path / "fp.json"
        skill = _make_skill_file(tmp_path / "skills" / "stale-skill")
        fp = SkillFingerprints(cache_path=cache_path)
        fp.register(skill)
        assert len(fp._data["skills"]) == 1

        # Delete the file
        skill.unlink()
        removed = fp.cleanup_stale()
        assert removed == 1
        assert len(fp._data["skills"]) == 0

    def test_preserves_existing_files(self, tmp_path):
        """Entries for files that still exist are kept."""
        cache_path = tmp_path / "fp.json"
        skill = _make_skill_file(tmp_path / "skills" / "live-skill")
        fp = SkillFingerprints(cache_path=cache_path)
        fp.register(skill)

        removed = fp.cleanup_stale()
        assert removed == 0
        assert len(fp._data["skills"]) == 1

    def test_cleanup_mixed(self, tmp_path):
        """Only stale entries are removed; live ones survive."""
        cache_path = tmp_path / "fp.json"
        live_skill = _make_skill_file(tmp_path / "skills" / "live")
        stale_skill = _make_skill_file(tmp_path / "skills" / "stale")

        fp = SkillFingerprints(cache_path=cache_path)
        fp.register(live_skill)
        fp.register(stale_skill)
        assert len(fp._data["skills"]) == 2

        stale_skill.unlink()
        removed = fp.cleanup_stale()
        assert removed == 1
        assert len(fp._data["skills"]) == 1
        assert str(live_skill.resolve()) in fp._data["skills"]

    def test_cleanup_no_entries(self, tmp_path):
        """Cleanup on an empty cache returns 0."""
        cache_path = tmp_path / "fp.json"
        fp = SkillFingerprints(cache_path=cache_path)
        removed = fp.cleanup_stale()
        assert removed == 0


# ---------------------------------------------------------------------------
# get_fingerprints (module-level singleton)
# ---------------------------------------------------------------------------

class TestGetFingerprints:
    """Tests for the module-level get_fingerprints() accessor."""

    def test_returns_skill_fingerprints_instance(self):
        """get_fingerprints() returns a SkillFingerprints object."""
        with patch("tweek.skills.fingerprints._fingerprints", None):
            instance = get_fingerprints()
            assert isinstance(instance, SkillFingerprints)

    def test_singleton_returns_same_instance(self):
        """Repeated calls return the same object."""
        with patch("tweek.skills.fingerprints._fingerprints", None):
            first = get_fingerprints()
            second = get_fingerprints()
            assert first is second


# ---------------------------------------------------------------------------
# _save (persistence round-trip)
# ---------------------------------------------------------------------------

class TestSave:
    """Tests for _save and persistence round-trips."""

    def test_save_creates_parent_dirs(self, tmp_path):
        """_save creates intermediate directories if they do not exist."""
        cache_path = tmp_path / "a" / "b" / "c" / "fingerprints.json"
        skill = _make_skill_file(tmp_path / "skills" / "s1")
        fp = SkillFingerprints(cache_path=cache_path)
        fp.register(skill)
        assert cache_path.exists()

    def test_round_trip_persistence(self, tmp_path):
        """Data registered in one instance is visible in a fresh instance."""
        cache_path = tmp_path / "fp.json"
        skill = _make_skill_file(tmp_path / "skills" / "round-trip")

        fp1 = SkillFingerprints(cache_path=cache_path)
        fp1.register(skill)

        # New instance reading from the same cache
        fp2 = SkillFingerprints(cache_path=cache_path)
        assert fp2.is_known(skill) is True
