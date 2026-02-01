"""
Tweek Skill Fingerprint Cache

Tracks SHA-256 hashes of known-approved SKILL.md files to detect
new or modified skills that arrive via git pull, clone, or branch switch.

When the PreToolUse hook encounters a SKILL.md with no fingerprint or a
changed hash, it routes the skill through the isolation chamber.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from tweek.skills import SKILLS_DIR, get_claude_project_skills


FINGERPRINT_PATH = SKILLS_DIR / "fingerprints.json"


class SkillFingerprints:
    """
    SHA-256 fingerprint cache for known-approved skills.

    Format:
    {
        "schema_version": 1,
        "skills": {
            "/abs/path/.claude/skills/my-skill/SKILL.md": {
                "sha256": "abc123...",
                "scanned_at": "2026-02-01T15:30:00Z",
                "verdict": "pass",
                "report_path": "..."
            }
        }
    }
    """

    def __init__(self, cache_path: Optional[Path] = None):
        self.cache_path = cache_path or FINGERPRINT_PATH
        self._data = self._load()

    def _load(self) -> Dict:
        """Load fingerprints from disk."""
        if not self.cache_path.exists():
            return {"schema_version": 1, "skills": {}}
        try:
            data = json.loads(self.cache_path.read_text())
            if not isinstance(data, dict) or "skills" not in data:
                return {"schema_version": 1, "skills": {}}
            return data
        except (json.JSONDecodeError, IOError):
            return {"schema_version": 1, "skills": {}}

    def _save(self) -> None:
        """Persist fingerprints to disk."""
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.cache_path.write_text(json.dumps(self._data, indent=2))

    @staticmethod
    def _hash_file(file_path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def is_known(self, skill_md_path: Path) -> bool:
        """
        Check if a SKILL.md file is known and unchanged.

        Args:
            skill_md_path: Absolute path to a SKILL.md file

        Returns:
            True if the file hash matches the stored fingerprint
        """
        key = str(skill_md_path.resolve())
        entry = self._data["skills"].get(key)
        if not entry:
            return False

        try:
            current_hash = self._hash_file(skill_md_path)
        except (IOError, OSError):
            return False

        return entry.get("sha256") == current_hash

    def register(
        self,
        skill_md_path: Path,
        verdict: str = "pass",
        report_path: Optional[str] = None,
    ) -> None:
        """
        Register a SKILL.md file as known-approved.

        Args:
            skill_md_path: Absolute path to the SKILL.md
            verdict: The scan verdict that approved it
            report_path: Path to the scan report
        """
        key = str(skill_md_path.resolve())
        try:
            current_hash = self._hash_file(skill_md_path)
        except (IOError, OSError):
            return

        self._data["skills"][key] = {
            "sha256": current_hash,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict,
            "report_path": report_path or "",
        }
        self._save()

    def remove(self, skill_md_path: Path) -> None:
        """Remove a fingerprint entry."""
        key = str(skill_md_path.resolve())
        if key in self._data["skills"]:
            del self._data["skills"][key]
            self._save()

    def check_project_skills(
        self, working_dir: Optional[Path] = None
    ) -> List[Tuple[Path, str]]:
        """
        Check all SKILL.md files in a project's .claude/skills/ directory.

        Returns a list of (path, status) tuples where status is:
        - "known": file hash matches fingerprint
        - "new": file has no fingerprint
        - "modified": file hash differs from fingerprint

        Args:
            working_dir: Project working directory (defaults to cwd)

        Returns:
            List of (skill_md_path, status) tuples for unknown/modified skills
        """
        skills_dir = get_claude_project_skills(working_dir)
        if not skills_dir.exists():
            return []

        results = []
        for skill_md in skills_dir.rglob("SKILL.md"):
            resolved = skill_md.resolve()
            key = str(resolved)
            entry = self._data["skills"].get(key)

            if not entry:
                results.append((skill_md, "new"))
            else:
                try:
                    current_hash = self._hash_file(skill_md)
                    if current_hash != entry.get("sha256"):
                        results.append((skill_md, "modified"))
                    # "known" skills are not returned (nothing to do)
                except (IOError, OSError):
                    results.append((skill_md, "new"))

        return results

    def cleanup_stale(self) -> int:
        """
        Remove fingerprints for files that no longer exist.

        Returns:
            Number of stale entries removed
        """
        stale_keys = []
        for key in self._data["skills"]:
            if not Path(key).exists():
                stale_keys.append(key)

        for key in stale_keys:
            del self._data["skills"][key]

        if stale_keys:
            self._save()

        return len(stale_keys)


# Module-level singleton
_fingerprints: Optional[SkillFingerprints] = None


def get_fingerprints() -> SkillFingerprints:
    """Get the singleton SkillFingerprints instance."""
    global _fingerprints
    if _fingerprints is None:
        _fingerprints = SkillFingerprints()
    return _fingerprints
