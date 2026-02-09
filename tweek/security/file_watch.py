#!/usr/bin/env python3
"""
Tweek File Integrity Monitoring

On-demand SHA-256 drift detection for critical security files:
- ~/.claude/settings.json (global hooks)
- .claude/settings.json (project hooks)
- ~/.tweek/hooks/pre_tool_use.py (wrapper scripts)
- ~/.tweek/hooks/post_tool_use.py
- ~/.tweek/overrides.yaml

Uses baselines stored in ~/.tweek/baselines.json.
Supports quarantine-before-restore for critical files.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class FilePolicy(Enum):
    """What to do when a file drifts from baseline."""
    RESTORE = "restore"   # Critical files: quarantine + restore from backup
    ALERT = "alert"       # Advisory files: warn only, user must approve


class DriftStatus(Enum):
    """Result of checking a single file against its baseline."""
    OK = "ok"             # Hash matches baseline
    MODIFIED = "modified" # Hash changed
    MISSING = "missing"   # File was deleted


@dataclass
class BaselineEntry:
    """Single file's baseline record."""
    path: str                     # Resolved absolute path
    sha256: str                   # Hex digest
    size: int                     # File size in bytes
    mtime: float                  # Last modification time (epoch)
    policy: str                   # "restore" or "alert"
    created_at: str               # ISO timestamp when baseline was taken
    updated_at: str               # ISO timestamp when last approved/refreshed
    label: str = ""               # Human label: "Global settings.json"


@dataclass
class DriftResult:
    """Result of checking one file against its baseline."""
    path: str
    status: DriftStatus
    policy: FilePolicy
    label: str
    current_sha256: Optional[str] = None
    baseline_sha256: Optional[str] = None
    diff_text: Optional[str] = None


@dataclass
class IntegrityReport:
    """Summary of a full integrity check run."""
    timestamp: str
    total_files: int
    ok_count: int
    modified_count: int
    missing_count: int
    results: List[DriftResult]

    @property
    def is_clean(self) -> bool:
        return self.modified_count == 0 and self.missing_count == 0


# --- Default watched files ---

DEFAULT_WATCHED_FILES: List[dict] = [
    {
        "path_expr": "~/.claude/settings.json",
        "policy": "restore",
        "label": "Global Claude settings",
    },
    {
        "path_expr": "~/.tweek/hooks/pre_tool_use.py",
        "policy": "restore",
        "label": "Pre-tool-use hook wrapper",
    },
    {
        "path_expr": "~/.tweek/hooks/post_tool_use.py",
        "policy": "restore",
        "label": "Post-tool-use hook wrapper",
    },
    {
        "path_expr": "~/.tweek/overrides.yaml",
        "policy": "alert",
        "label": "Security overrides config",
    },
]

PROJECT_WATCHED_FILES: List[dict] = [
    {
        "path_expr": ".claude/settings.json",
        "policy": "restore",
        "label": "Project Claude settings",
    },
]


BASELINES_PATH = Path("~/.tweek/baselines.json").expanduser()
QUARANTINE_DIR = Path("~/.tweek/quarantine").expanduser()


class FileIntegrityMonitor:
    """Core engine for baseline creation, verification, and restore."""

    def __init__(
        self,
        baselines_path: Path = BASELINES_PATH,
        quarantine_dir: Path = QUARANTINE_DIR,
    ):
        self.baselines_path = baselines_path
        self.quarantine_dir = quarantine_dir

    # --- Hashing ---

    @staticmethod
    def hash_file(path: Path) -> str:
        """Compute SHA-256 of a file. Path must be resolved (no symlinks)."""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _resolve_safe(path: Path) -> Path:
        """Resolve path and refuse if it is a symlink."""
        resolved = path.resolve()
        if path.is_symlink():
            raise ValueError(
                f"Refusing to monitor symlink: {path} -> {resolved}"
            )
        return resolved

    # --- Baseline CRUD ---

    def load_baselines(self) -> Dict[str, BaselineEntry]:
        """Load baselines from JSON. Returns {resolved_path_str: BaselineEntry}."""
        if not self.baselines_path.exists():
            return {}
        try:
            data = json.loads(self.baselines_path.read_text())
            return {
                k: BaselineEntry(**v) for k, v in data.get("files", {}).items()
            }
        except (json.JSONDecodeError, TypeError, KeyError):
            return {}

    def save_baselines(self, baselines: Dict[str, BaselineEntry]) -> None:
        """Atomically write baselines to JSON."""
        self.baselines_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "files": {k: asdict(v) for k, v in baselines.items()},
        }
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self.baselines_path.parent),
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp_path, str(self.baselines_path))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # --- Init: Create initial baselines ---

    def init_baselines(
        self,
        include_project: bool = True,
        extra_paths: Optional[List[dict]] = None,
        force: bool = False,
    ) -> Tuple[int, int]:
        """
        Create baselines for all default watched files.

        Args:
            include_project: Include .claude/settings.json from CWD.
            extra_paths: Additional path definitions to monitor.
            force: If True, overwrite existing baseline entries.

        Returns:
            (created_count, skipped_count) tuple
        """
        watched = list(DEFAULT_WATCHED_FILES)
        if include_project:
            watched.extend(PROJECT_WATCHED_FILES)
        if extra_paths:
            watched.extend(extra_paths)

        baselines = {} if force else self.load_baselines()
        now = datetime.now(timezone.utc).isoformat()
        created = 0
        skipped = 0

        for entry_def in watched:
            raw_path = entry_def["path_expr"]
            policy = entry_def["policy"]
            label = entry_def.get("label", "")

            try:
                path = self._resolve_safe(Path(raw_path).expanduser())
            except ValueError:
                skipped += 1
                continue

            if not path.is_file():
                skipped += 1
                continue

            key = str(path)

            if key in baselines and not force:
                skipped += 1
                continue

            sha = self.hash_file(path)
            stat = path.stat()

            baselines[key] = BaselineEntry(
                path=key,
                sha256=sha,
                size=stat.st_size,
                mtime=stat.st_mtime,
                policy=policy,
                created_at=now,
                updated_at=now,
                label=label,
            )
            created += 1

        self.save_baselines(baselines)
        return created, skipped

    # --- Check: Verify all baselines ---

    def check_integrity(self) -> IntegrityReport:
        """Check all baselined files against their stored hashes."""
        baselines = self.load_baselines()
        results: List[DriftResult] = []

        for _key, entry in baselines.items():
            path = Path(entry.path)
            policy = FilePolicy(entry.policy)
            label = entry.label

            if not path.exists():
                results.append(DriftResult(
                    path=entry.path,
                    status=DriftStatus.MISSING,
                    policy=policy,
                    label=label,
                    baseline_sha256=entry.sha256,
                ))
                continue

            try:
                resolved = self._resolve_safe(path)
            except ValueError:
                results.append(DriftResult(
                    path=entry.path,
                    status=DriftStatus.MODIFIED,
                    policy=policy,
                    label=label,
                    baseline_sha256=entry.sha256,
                ))
                continue

            current_sha = self.hash_file(resolved)
            if current_sha == entry.sha256:
                results.append(DriftResult(
                    path=entry.path,
                    status=DriftStatus.OK,
                    policy=policy,
                    label=label,
                    current_sha256=current_sha,
                    baseline_sha256=entry.sha256,
                ))
            else:
                results.append(DriftResult(
                    path=entry.path,
                    status=DriftStatus.MODIFIED,
                    policy=policy,
                    label=label,
                    current_sha256=current_sha,
                    baseline_sha256=entry.sha256,
                ))

        ok = sum(1 for r in results if r.status == DriftStatus.OK)
        modified = sum(1 for r in results if r.status == DriftStatus.MODIFIED)
        missing = sum(1 for r in results if r.status == DriftStatus.MISSING)

        return IntegrityReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_files=len(results),
            ok_count=ok,
            modified_count=modified,
            missing_count=missing,
            results=results,
        )

    # --- Diff: Show what changed ---

    def diff_file(self, file_path: str) -> Optional[str]:
        """
        Generate a unified diff between the backup and current version.

        Returns:
            Unified diff string, or hash-only fallback, or None if not in baselines.
        """
        baselines = self.load_baselines()
        entry = baselines.get(file_path)
        if entry is None:
            return None

        path = Path(file_path)
        if not path.exists():
            return f"--- {file_path} (baseline)\n+++ /dev/null\n(file deleted)"

        backup_path = self._find_backup(path)
        if backup_path is None or not backup_path.exists():
            current_sha = self.hash_file(path)
            return (
                f"Cannot generate diff: no backup file found for {file_path}.\n"
                f"Baseline SHA-256: {entry.sha256}\n"
                f"Current  SHA-256: {current_sha}"
            )

        try:
            baseline_lines = backup_path.read_text().splitlines(keepends=True)
            current_lines = path.read_text().splitlines(keepends=True)
        except UnicodeDecodeError:
            return f"Cannot diff binary file: {file_path}"

        diff = difflib.unified_diff(
            baseline_lines,
            current_lines,
            fromfile=f"{file_path} (baseline)",
            tofile=f"{file_path} (current)",
        )
        result = "".join(diff)
        return result if result else "(no differences)"

    @staticmethod
    def _find_backup(path: Path) -> Optional[Path]:
        """Find the backup file for a given watched file."""
        if path.name == "settings.json":
            backup = path.with_suffix(".json.tweek-backup")
            if backup.exists():
                return backup
        if "hooks" in str(path) and path.suffix == ".py":
            pkg_hooks = Path(__file__).resolve().parent.parent / "hooks"
            # Map deployed wrapper name to package source
            name_map = {
                "pre_tool_use.py": "wrapper_pre_tool_use.py",
                "post_tool_use.py": "wrapper_post_tool_use.py",
            }
            pkg_name = name_map.get(path.name, path.name)
            pkg_hook = pkg_hooks / pkg_name
            if pkg_hook.exists():
                return pkg_hook
        return None

    # --- Approve: Accept current state as new baseline ---

    def approve_file(self, file_path: str) -> bool:
        """
        Update the baseline for a single file to its current state.

        Returns:
            True if approved, False if file not found in baselines or on disk.
        """
        baselines = self.load_baselines()
        if file_path not in baselines:
            return False

        path = Path(file_path)
        if not path.exists():
            return False

        try:
            resolved = self._resolve_safe(path)
        except ValueError:
            return False

        sha = self.hash_file(resolved)
        stat = resolved.stat()
        now = datetime.now(timezone.utc).isoformat()

        entry = baselines[file_path]
        entry.sha256 = sha
        entry.size = stat.st_size
        entry.mtime = stat.st_mtime
        entry.updated_at = now

        self.save_baselines(baselines)
        return True

    def approve_all(self) -> int:
        """Approve all drifted files (re-baseline everything). Returns count."""
        baselines = self.load_baselines()
        count = 0
        now = datetime.now(timezone.utc).isoformat()

        for _key, entry in list(baselines.items()):
            path = Path(entry.path)
            if not path.exists():
                continue
            try:
                resolved = self._resolve_safe(path)
            except ValueError:
                continue
            sha = self.hash_file(resolved)
            if sha != entry.sha256:
                stat = resolved.stat()
                entry.sha256 = sha
                entry.size = stat.st_size
                entry.mtime = stat.st_mtime
                entry.updated_at = now
                count += 1

        self.save_baselines(baselines)
        return count

    # --- Restore: Quarantine + replace from backup ---

    def restore_file(self, file_path: str) -> Tuple[bool, str]:
        """
        Restore a drifted file from its backup.

        1. Quarantine the current (drifted) file to ~/.tweek/quarantine/
        2. Copy the backup over the drifted file
        3. Update the baseline to match the restored file

        Returns:
            (success, message) tuple
        """
        baselines = self.load_baselines()
        if file_path not in baselines:
            return False, f"Not in baselines: {file_path}"

        entry = baselines[file_path]
        if FilePolicy(entry.policy) != FilePolicy.RESTORE:
            return False, f"File policy is '{entry.policy}', not 'restore'"

        path = Path(file_path)
        backup = self._find_backup(path)
        if backup is None or not backup.exists():
            return False, f"No backup found for {file_path}"

        # Quarantine the drifted file
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        quarantine_name = f"{path.stem}_{ts}{path.suffix}"
        quarantine_path = self.quarantine_dir / quarantine_name

        if path.exists():
            shutil.copy2(str(path), str(quarantine_path))

        # Restore from backup
        shutil.copy2(str(backup), str(path))

        # Update baseline
        try:
            resolved = self._resolve_safe(path)
            sha = self.hash_file(resolved)
            stat = resolved.stat()
            now = datetime.now(timezone.utc).isoformat()

            entry.sha256 = sha
            entry.size = stat.st_size
            entry.mtime = stat.st_mtime
            entry.updated_at = now

            self.save_baselines(baselines)
        except Exception:
            pass  # Restore succeeded even if baseline update fails

        return True, f"Restored from backup. Drifted version quarantined to {quarantine_path}"
