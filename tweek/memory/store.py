"""
Tweek Memory Store

Core SQLite-backed storage for Tweek's agentic memory system.
Handles schema creation, CRUD operations, time decay, and audit logging.

Storage locations:
- Global: ~/.tweek/memory.db
- Per-project: .tweek/memory.db (inside project directory)
"""

import hashlib
import math
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any

from tweek.memory.schemas import (
    ConfidenceAdjustment,
    LearnedWhitelistSuggestion,
    PatternDecisionEntry,
    SourceTrustEntry,
    WorkflowBaseline,
)
from tweek.memory.safety import (
    MIN_APPROVAL_RATIO,
    MIN_CONFIDENCE_SCORE,
    MIN_DECISION_THRESHOLD,
    compute_suggested_decision,
    is_immune_pattern,
)


# Half-life in days for time decay
DECAY_HALF_LIFE_DAYS = 30

# Default global memory DB path
GLOBAL_MEMORY_PATH = Path.home() / ".tweek" / "memory.db"


class MemoryStore:
    """SQLite-backed persistent memory for security decisions.

    Manages 5 tables + 1 view:
    - pattern_decisions: Per-pattern approval/denial history
    - source_trust: URL/file injection history
    - workflow_baselines: Normal tool usage patterns
    - learned_whitelists: Auto-generated whitelist suggestions
    - memory_audit: Accountability log
    - pattern_confidence_view: Computed confidence adjustments
    """

    SCHEMA_VERSION = 1

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or GLOBAL_MEMORY_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._ensure_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create a SQLite connection with WAL mode."""
        if self._conn is None:
            self._conn = sqlite3.connect(
                str(self.db_path),
                timeout=5.0,
                isolation_level=None,  # autocommit
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def close(self):
        """Close the database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _ensure_schema(self):
        """Create tables, indexes, and views if they don't exist."""
        conn = self._get_connection()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            );

            CREATE TABLE IF NOT EXISTS pattern_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_name TEXT NOT NULL,
                pattern_id INTEGER,
                original_severity TEXT NOT NULL,
                original_confidence TEXT NOT NULL,
                decision TEXT NOT NULL,
                user_response TEXT,
                tool_name TEXT NOT NULL,
                content_hash TEXT,
                path_prefix TEXT,
                project_hash TEXT,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                decay_weight REAL NOT NULL DEFAULT 1.0,
                CHECK (NOT (
                    original_severity = 'critical'
                    AND original_confidence = 'deterministic'
                    AND decision = 'allow'
                ))
            );

            CREATE INDEX IF NOT EXISTS idx_pd_pattern_name
                ON pattern_decisions(pattern_name);
            CREATE INDEX IF NOT EXISTS idx_pd_pattern_path
                ON pattern_decisions(pattern_name, path_prefix);
            CREATE INDEX IF NOT EXISTS idx_pd_project
                ON pattern_decisions(project_hash);
            CREATE INDEX IF NOT EXISTS idx_pd_timestamp
                ON pattern_decisions(timestamp);

            CREATE TABLE IF NOT EXISTS source_trust (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_type TEXT NOT NULL,
                source_key TEXT NOT NULL,
                total_scans INTEGER DEFAULT 0,
                injection_detections INTEGER DEFAULT 0,
                trust_score REAL DEFAULT 0.5,
                last_clean_scan TEXT,
                last_injection TEXT,
                timestamp TEXT DEFAULT (datetime('now')),
                decay_weight REAL DEFAULT 1.0,
                UNIQUE(source_type, source_key)
            );

            CREATE INDEX IF NOT EXISTS idx_st_type_key
                ON source_trust(source_type, source_key);

            CREATE TABLE IF NOT EXISTS workflow_baselines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_hash TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                hour_of_day INTEGER,
                invocation_count INTEGER DEFAULT 0,
                denied_count INTEGER DEFAULT 0,
                last_updated TEXT DEFAULT (datetime('now')),
                UNIQUE(project_hash, tool_name, hour_of_day)
            );

            CREATE INDEX IF NOT EXISTS idx_wb_project
                ON workflow_baselines(project_hash);

            CREATE TABLE IF NOT EXISTS learned_whitelists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_name TEXT NOT NULL,
                tool_name TEXT,
                path_prefix TEXT,
                approval_count INTEGER DEFAULT 0,
                denial_count INTEGER DEFAULT 0,
                confidence REAL DEFAULT 0.0,
                suggested_at TEXT,
                human_reviewed INTEGER DEFAULT 0,
                timestamp TEXT DEFAULT (datetime('now')),
                UNIQUE(pattern_name, tool_name, path_prefix)
            );

            CREATE INDEX IF NOT EXISTS idx_lw_pattern
                ON learned_whitelists(pattern_name);

            CREATE TABLE IF NOT EXISTS memory_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation TEXT NOT NULL,
                table_name TEXT NOT NULL,
                key_info TEXT,
                result TEXT,
                timestamp TEXT DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_ma_timestamp
                ON memory_audit(timestamp);
        """)

        # Create or replace the confidence view
        conn.execute("DROP VIEW IF EXISTS pattern_confidence_view")
        conn.execute("""
            CREATE VIEW pattern_confidence_view AS
            SELECT
                pattern_name,
                path_prefix,
                COUNT(*) as total_decisions,
                SUM(CASE WHEN user_response = 'approved' THEN decay_weight ELSE 0 END)
                    as weighted_approvals,
                SUM(CASE WHEN user_response = 'denied' THEN decay_weight ELSE 0 END)
                    as weighted_denials,
                CASE WHEN SUM(decay_weight) > 0 THEN
                    SUM(CASE WHEN user_response = 'approved' THEN decay_weight ELSE 0 END)
                    / SUM(decay_weight)
                ELSE 0.5 END as approval_ratio,
                MAX(timestamp) as last_decision
            FROM pattern_decisions
            WHERE decay_weight > 0.01
            GROUP BY pattern_name, path_prefix
        """)

        # Set schema version
        conn.execute(
            "INSERT OR REPLACE INTO schema_version (version) VALUES (?)",
            (self.SCHEMA_VERSION,),
        )

    # =====================================================================
    # Pattern Decisions
    # =====================================================================

    def record_decision(self, entry: PatternDecisionEntry) -> int:
        """Record a pattern decision.

        Returns the row ID of the inserted record.
        """
        conn = self._get_connection()

        # Safety: never record 'allow' for CRITICAL+deterministic
        if (
            entry.original_severity == "critical"
            and entry.original_confidence == "deterministic"
            and entry.decision == "allow"
        ):
            self._audit("write", "pattern_decisions",
                         f"{entry.pattern_name}:{entry.path_prefix}",
                         "BLOCKED: attempted allow on critical+deterministic")
            return -1

        cursor = conn.execute(
            """
            INSERT INTO pattern_decisions (
                pattern_name, pattern_id, original_severity, original_confidence,
                decision, user_response, tool_name, content_hash,
                path_prefix, project_hash, decay_weight
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.pattern_name,
                entry.pattern_id,
                entry.original_severity,
                entry.original_confidence,
                entry.decision,
                entry.user_response,
                entry.tool_name,
                entry.content_hash,
                entry.path_prefix,
                entry.project_hash,
                entry.decay_weight,
            ),
        )

        row_id = cursor.lastrowid
        self._audit(
            "write", "pattern_decisions",
            f"{entry.pattern_name}:{entry.path_prefix}",
            f"id={row_id}, decision={entry.decision}, response={entry.user_response}",
        )

        # Update learned whitelists
        self._update_learned_whitelist(entry)

        return row_id

    def get_confidence_adjustment(
        self,
        pattern_name: str,
        path_prefix: Optional[str] = None,
        current_decision: str = "ask",
        original_severity: str = "medium",
        original_confidence: str = "heuristic",
    ) -> Optional[ConfidenceAdjustment]:
        """Query memory for a confidence adjustment on a pattern.

        Returns a ConfidenceAdjustment if memory has enough data,
        or None if insufficient data / pattern is immune.
        """
        conn = self._get_connection()

        # Check immunity first
        if is_immune_pattern(original_severity, original_confidence):
            self._audit(
                "read", "pattern_decisions",
                f"{pattern_name}:{path_prefix}",
                "immune_pattern_skipped",
            )
            return None

        # Query the confidence view
        if path_prefix:
            row = conn.execute(
                """
                SELECT * FROM pattern_confidence_view
                WHERE pattern_name = ? AND path_prefix = ?
                """,
                (pattern_name, path_prefix),
            ).fetchone()
        else:
            row = conn.execute(
                """
                SELECT * FROM pattern_confidence_view
                WHERE pattern_name = ? AND path_prefix IS NULL
                """,
                (pattern_name,),
            ).fetchone()

        # Also try without path prefix as fallback
        if not row and path_prefix:
            row = conn.execute(
                """
                SELECT
                    pattern_name,
                    NULL as path_prefix,
                    SUM(total_decisions) as total_decisions,
                    SUM(weighted_approvals) as weighted_approvals,
                    SUM(weighted_denials) as weighted_denials,
                    CASE WHEN SUM(weighted_approvals) + SUM(weighted_denials) > 0 THEN
                        SUM(weighted_approvals) / (SUM(weighted_approvals) + SUM(weighted_denials))
                    ELSE 0.5 END as approval_ratio,
                    MAX(last_decision) as last_decision
                FROM pattern_confidence_view
                WHERE pattern_name = ?
                GROUP BY pattern_name
                """,
                (pattern_name,),
            ).fetchone()

        if not row:
            self._audit(
                "read", "pattern_decisions",
                f"{pattern_name}:{path_prefix}",
                "no_data",
            )
            return None

        total = row["total_decisions"]
        weighted_approvals = row["weighted_approvals"] or 0.0
        weighted_denials = row["weighted_denials"] or 0.0
        approval_ratio = row["approval_ratio"] or 0.5
        total_weighted = weighted_approvals + weighted_denials

        # Compute suggested decision
        suggested = compute_suggested_decision(
            current_decision=current_decision,
            approval_ratio=approval_ratio,
            total_weighted_decisions=total_weighted,
            original_severity=original_severity,
            original_confidence=original_confidence,
        )

        # Confidence score: based on data quantity and consistency
        confidence_score = 0.0
        if total_weighted >= MIN_DECISION_THRESHOLD:
            # Scale 0-1 based on how far above threshold and ratio strength
            data_factor = min(total_weighted / (MIN_DECISION_THRESHOLD * 3), 1.0)
            ratio_factor = approval_ratio if suggested == "log" else (1 - approval_ratio)
            confidence_score = data_factor * ratio_factor

        adjustment = ConfidenceAdjustment(
            pattern_name=pattern_name,
            path_prefix=path_prefix,
            total_decisions=total,
            weighted_approvals=weighted_approvals,
            weighted_denials=weighted_denials,
            approval_ratio=approval_ratio,
            last_decision=row["last_decision"],
            adjusted_decision=suggested,
            confidence_score=confidence_score,
        )

        self._audit(
            "read", "pattern_decisions",
            f"{pattern_name}:{path_prefix}",
            f"total={total}, ratio={approval_ratio:.2f}, suggested={suggested}, "
            f"confidence={confidence_score:.2f}",
        )

        return adjustment

    # =====================================================================
    # Source Trust
    # =====================================================================

    def record_source_scan(
        self,
        source_type: str,
        source_key: str,
        had_injection: bool,
    ) -> None:
        """Record a source scan result (clean or injection detected)."""
        conn = self._get_connection()
        now = datetime.utcnow().isoformat()

        if had_injection:
            conn.execute(
                """
                INSERT INTO source_trust (source_type, source_key, total_scans,
                    injection_detections, trust_score, last_injection, timestamp)
                VALUES (?, ?, 1, 1, 0.0, ?, ?)
                ON CONFLICT(source_type, source_key) DO UPDATE SET
                    total_scans = total_scans + 1,
                    injection_detections = injection_detections + 1,
                    last_injection = excluded.last_injection,
                    trust_score = CASE
                        WHEN total_scans + 1 > 0 THEN
                            1.0 - (CAST(injection_detections + 1 AS REAL) / (total_scans + 1))
                        ELSE 0.5
                    END
                """,
                (source_type, source_key, now, now),
            )
        else:
            conn.execute(
                """
                INSERT INTO source_trust (source_type, source_key, total_scans,
                    injection_detections, trust_score, last_clean_scan, timestamp)
                VALUES (?, ?, 1, 0, 1.0, ?, ?)
                ON CONFLICT(source_type, source_key) DO UPDATE SET
                    total_scans = total_scans + 1,
                    last_clean_scan = excluded.last_clean_scan,
                    trust_score = CASE
                        WHEN total_scans + 1 > 0 THEN
                            1.0 - (CAST(injection_detections AS REAL) / (total_scans + 1))
                        ELSE 0.5
                    END
                """,
                (source_type, source_key, now, now),
            )

        self._audit(
            "write", "source_trust",
            f"{source_type}:{source_key}",
            f"injection={had_injection}",
        )

    def get_source_trust(
        self, source_type: str, source_key: str
    ) -> Optional[SourceTrustEntry]:
        """Get trust information for a source."""
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT * FROM source_trust
            WHERE source_type = ? AND source_key = ?
            """,
            (source_type, source_key),
        ).fetchone()

        if not row:
            # Also check domain-level trust for URLs
            if source_type == "url":
                domain = _extract_domain(source_key)
                if domain:
                    row = conn.execute(
                        """
                        SELECT * FROM source_trust
                        WHERE source_type = 'domain' AND source_key = ?
                        """,
                        (domain,),
                    ).fetchone()

        if not row:
            self._audit("read", "source_trust", f"{source_type}:{source_key}", "no_data")
            return None

        entry = SourceTrustEntry(
            source_type=row["source_type"],
            source_key=row["source_key"],
            total_scans=row["total_scans"],
            injection_detections=row["injection_detections"],
            trust_score=row["trust_score"],
            last_clean_scan=row["last_clean_scan"],
            last_injection=row["last_injection"],
        )

        self._audit(
            "read", "source_trust",
            f"{source_type}:{source_key}",
            f"trust={entry.trust_score:.2f}, scans={entry.total_scans}",
        )

        return entry

    def get_all_sources(self, suspicious_only: bool = False) -> List[SourceTrustEntry]:
        """Get all source trust entries, optionally filtering to suspicious ones."""
        conn = self._get_connection()
        if suspicious_only:
            rows = conn.execute(
                "SELECT * FROM source_trust WHERE trust_score < 0.5 ORDER BY trust_score ASC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM source_trust ORDER BY trust_score ASC"
            ).fetchall()

        return [
            SourceTrustEntry(
                source_type=r["source_type"],
                source_key=r["source_key"],
                total_scans=r["total_scans"],
                injection_detections=r["injection_detections"],
                trust_score=r["trust_score"],
                last_clean_scan=r["last_clean_scan"],
                last_injection=r["last_injection"],
            )
            for r in rows
        ]

    # =====================================================================
    # Workflow Baselines
    # =====================================================================

    def update_workflow(
        self,
        project_hash: str,
        tool_name: str,
        hour_of_day: Optional[int] = None,
        was_denied: bool = False,
    ) -> None:
        """Update workflow baseline for a project+tool+hour."""
        conn = self._get_connection()
        now = datetime.utcnow().isoformat()

        denied_inc = 1 if was_denied else 0
        conn.execute(
            """
            INSERT INTO workflow_baselines (
                project_hash, tool_name, hour_of_day, invocation_count,
                denied_count, last_updated
            ) VALUES (?, ?, ?, 1, ?, ?)
            ON CONFLICT(project_hash, tool_name, hour_of_day) DO UPDATE SET
                invocation_count = invocation_count + 1,
                denied_count = denied_count + ?,
                last_updated = ?
            """,
            (project_hash, tool_name, hour_of_day, denied_inc, now, denied_inc, now),
        )

    def get_workflow_baseline(
        self, project_hash: str
    ) -> List[WorkflowBaseline]:
        """Get all workflow baselines for a project."""
        conn = self._get_connection()
        rows = conn.execute(
            """
            SELECT * FROM workflow_baselines
            WHERE project_hash = ?
            ORDER BY tool_name, hour_of_day
            """,
            (project_hash,),
        ).fetchall()

        self._audit("read", "workflow_baselines", project_hash, f"count={len(rows)}")

        return [
            WorkflowBaseline(
                project_hash=r["project_hash"],
                tool_name=r["tool_name"],
                hour_of_day=r["hour_of_day"],
                invocation_count=r["invocation_count"],
                denied_count=r["denied_count"],
            )
            for r in rows
        ]

    def get_workflow_tool_baseline(
        self, project_hash: str, tool_name: str
    ) -> Optional[WorkflowBaseline]:
        """Get aggregated baseline for a specific tool in a project."""
        conn = self._get_connection()
        row = conn.execute(
            """
            SELECT project_hash, tool_name, NULL as hour_of_day,
                SUM(invocation_count) as invocation_count,
                SUM(denied_count) as denied_count
            FROM workflow_baselines
            WHERE project_hash = ? AND tool_name = ?
            GROUP BY project_hash, tool_name
            """,
            (project_hash, tool_name),
        ).fetchone()

        if not row:
            return None

        return WorkflowBaseline(
            project_hash=row["project_hash"],
            tool_name=row["tool_name"],
            hour_of_day=None,
            invocation_count=row["invocation_count"],
            denied_count=row["denied_count"],
        )

    # =====================================================================
    # Learned Whitelists
    # =====================================================================

    def _update_learned_whitelist(self, entry: PatternDecisionEntry) -> None:
        """Update learned whitelist suggestion based on a new decision."""
        if not entry.user_response:
            return

        conn = self._get_connection()
        now = datetime.utcnow().isoformat()

        approval_inc = 1 if entry.user_response == "approved" else 0
        denial_inc = 1 if entry.user_response == "denied" else 0

        conn.execute(
            """
            INSERT INTO learned_whitelists (
                pattern_name, tool_name, path_prefix,
                approval_count, denial_count, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(pattern_name, tool_name, path_prefix) DO UPDATE SET
                approval_count = approval_count + ?,
                denial_count = denial_count + ?,
                timestamp = ?
            """,
            (
                entry.pattern_name, entry.tool_name, entry.path_prefix,
                approval_inc, denial_inc, now,
                approval_inc, denial_inc, now,
            ),
        )

        # Recompute confidence and check if suggestion threshold met
        row = conn.execute(
            """
            SELECT approval_count, denial_count FROM learned_whitelists
            WHERE pattern_name = ? AND tool_name = ? AND path_prefix IS ?
            """,
            (entry.pattern_name, entry.tool_name, entry.path_prefix),
        ).fetchone()

        if row:
            total = row["approval_count"] + row["denial_count"]
            if total > 0:
                confidence = row["approval_count"] / total
                suggested_at = now if (
                    confidence >= MIN_APPROVAL_RATIO
                    and total >= MIN_DECISION_THRESHOLD
                ) else None

                conn.execute(
                    """
                    UPDATE learned_whitelists
                    SET confidence = ?, suggested_at = ?
                    WHERE pattern_name = ? AND tool_name = ? AND path_prefix IS ?
                    """,
                    (confidence, suggested_at,
                     entry.pattern_name, entry.tool_name, entry.path_prefix),
                )

    def get_whitelist_suggestions(
        self, pending_only: bool = True
    ) -> List[LearnedWhitelistSuggestion]:
        """Get learned whitelist suggestions.

        Args:
            pending_only: If True, only return unreviewed suggestions
        """
        conn = self._get_connection()

        if pending_only:
            rows = conn.execute(
                """
                SELECT * FROM learned_whitelists
                WHERE suggested_at IS NOT NULL AND human_reviewed = 0
                ORDER BY confidence DESC
                """
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM learned_whitelists
                WHERE suggested_at IS NOT NULL
                ORDER BY confidence DESC
                """
            ).fetchall()

        self._audit("read", "learned_whitelists", "suggestions", f"count={len(rows)}")

        return [
            LearnedWhitelistSuggestion(
                id=r["id"],
                pattern_name=r["pattern_name"],
                tool_name=r["tool_name"],
                path_prefix=r["path_prefix"],
                approval_count=r["approval_count"],
                denial_count=r["denial_count"],
                confidence=r["confidence"],
                suggested_at=r["suggested_at"],
                human_reviewed=r["human_reviewed"],
            )
            for r in rows
        ]

    def review_whitelist_suggestion(self, suggestion_id: int, accepted: bool) -> bool:
        """Mark a whitelist suggestion as accepted or rejected.

        Returns True if the suggestion was found and updated.
        """
        conn = self._get_connection()
        status = 1 if accepted else -1
        cursor = conn.execute(
            "UPDATE learned_whitelists SET human_reviewed = ? WHERE id = ?",
            (status, suggestion_id),
        )

        action = "accepted" if accepted else "rejected"
        self._audit("write", "learned_whitelists", f"id={suggestion_id}", action)

        return cursor.rowcount > 0

    # =====================================================================
    # Decay Engine
    # =====================================================================

    def apply_decay(self) -> Dict[str, int]:
        """Apply time-based decay to all weighted entries.

        Uses a 30-day half-life: weight = 2^(-days_elapsed/30)

        Returns count of updated rows per table.
        """
        conn = self._get_connection()
        now = datetime.utcnow()
        results = {}

        # Decay pattern decisions
        rows = conn.execute(
            "SELECT id, timestamp, decay_weight FROM pattern_decisions WHERE decay_weight > 0.01"
        ).fetchall()

        updated = 0
        for row in rows:
            try:
                ts = datetime.fromisoformat(row["timestamp"])
                days_elapsed = (now - ts).total_seconds() / 86400
                new_weight = math.pow(2, -days_elapsed / DECAY_HALF_LIFE_DAYS)
                new_weight = max(new_weight, 0.0)  # Floor at 0

                if abs(new_weight - row["decay_weight"]) > 0.001:
                    conn.execute(
                        "UPDATE pattern_decisions SET decay_weight = ? WHERE id = ?",
                        (new_weight, row["id"]),
                    )
                    updated += 1
            except (ValueError, TypeError):
                continue

        results["pattern_decisions"] = updated

        # Decay source trust
        rows = conn.execute(
            "SELECT id, timestamp, decay_weight FROM source_trust WHERE decay_weight > 0.01"
        ).fetchall()

        updated = 0
        for row in rows:
            try:
                ts = datetime.fromisoformat(row["timestamp"])
                days_elapsed = (now - ts).total_seconds() / 86400
                new_weight = math.pow(2, -days_elapsed / DECAY_HALF_LIFE_DAYS)
                new_weight = max(new_weight, 0.0)

                if abs(new_weight - row["decay_weight"]) > 0.001:
                    conn.execute(
                        "UPDATE source_trust SET decay_weight = ? WHERE id = ?",
                        (new_weight, row["id"]),
                    )
                    updated += 1
            except (ValueError, TypeError):
                continue

        results["source_trust"] = updated

        self._audit("decay", "all", None, str(results))
        return results

    # =====================================================================
    # Stats & Export
    # =====================================================================

    def get_stats(self) -> Dict[str, Any]:
        """Get overall memory statistics."""
        conn = self._get_connection()
        stats = {}

        for table in ("pattern_decisions", "source_trust", "workflow_baselines",
                       "learned_whitelists", "memory_audit"):
            row = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}").fetchone()
            stats[table] = row["cnt"]

        # Last decay
        row = conn.execute(
            """
            SELECT timestamp FROM memory_audit
            WHERE operation = 'decay'
            ORDER BY timestamp DESC LIMIT 1
            """
        ).fetchone()
        stats["last_decay"] = row["timestamp"] if row else None

        # DB file size
        try:
            stats["db_size_bytes"] = self.db_path.stat().st_size
        except OSError:
            stats["db_size_bytes"] = 0

        return stats

    def get_pattern_stats(
        self, min_decisions: int = 0, sort_by: str = "count"
    ) -> List[Dict[str, Any]]:
        """Get per-pattern confidence statistics."""
        conn = self._get_connection()
        rows = conn.execute(
            """
            SELECT * FROM pattern_confidence_view
            WHERE total_decisions >= ?
            """,
            (min_decisions,),
        ).fetchall()

        results = [dict(r) for r in rows]

        if sort_by == "approval":
            results.sort(key=lambda r: r.get("approval_ratio", 0), reverse=True)
        elif sort_by == "name":
            results.sort(key=lambda r: r.get("pattern_name", ""))
        else:  # count
            results.sort(key=lambda r: r.get("total_decisions", 0), reverse=True)

        return results

    def get_audit_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent audit log entries."""
        conn = self._get_connection()
        rows = conn.execute(
            "SELECT * FROM memory_audit ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def export_all(self) -> Dict[str, Any]:
        """Export all memory data as a JSON-serializable dict."""
        conn = self._get_connection()
        data = {}

        for table in ("pattern_decisions", "source_trust", "workflow_baselines",
                       "learned_whitelists"):
            rows = conn.execute(f"SELECT * FROM {table}").fetchall()
            data[table] = [dict(r) for r in rows]

        data["stats"] = self.get_stats()
        return data

    def clear_table(self, table_name: str) -> int:
        """Clear all data from a specific table.

        Returns the number of deleted rows.
        """
        valid_tables = {
            "pattern_decisions", "source_trust", "workflow_baselines",
            "learned_whitelists", "memory_audit",
        }
        if table_name not in valid_tables:
            raise ValueError(f"Invalid table: {table_name}. Must be one of {valid_tables}")

        conn = self._get_connection()
        cursor = conn.execute(f"DELETE FROM {table_name}")
        count = cursor.rowcount

        self._audit("clear", table_name, None, f"deleted={count}")
        return count

    def clear_all(self) -> Dict[str, int]:
        """Clear all memory data. Returns counts per table."""
        results = {}
        for table in ("pattern_decisions", "source_trust", "workflow_baselines",
                       "learned_whitelists"):
            results[table] = self.clear_table(table)

        # Clear audit last (so the clear operations are logged first)
        results["memory_audit"] = self.clear_table("memory_audit")
        return results

    # =====================================================================
    # Audit
    # =====================================================================

    def _audit(
        self,
        operation: str,
        table_name: str,
        key_info: Optional[str],
        result: Optional[str],
    ) -> None:
        """Log an operation to the memory audit table."""
        try:
            conn = self._get_connection()
            conn.execute(
                """
                INSERT INTO memory_audit (operation, table_name, key_info, result)
                VALUES (?, ?, ?, ?)
                """,
                (operation, table_name, key_info, result),
            )
        except Exception:
            pass  # Audit logging should never block operations


# =========================================================================
# Helpers
# =========================================================================


def _extract_domain(url: str) -> Optional[str]:
    """Extract domain from a URL."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None


def content_hash(content: str) -> str:
    """Compute SHA-256 hash of content for deduplication."""
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()


def normalize_path_prefix(path: str, depth: int = 3) -> Optional[str]:
    """Normalize a path to a prefix for memory lookups.

    Strips to first `depth` components from the project root.
    Example: /home/user/project/src/lib/utils.py -> src/lib/utils.py
    """
    if not path:
        return None
    try:
        p = Path(path).resolve()
        parts = p.parts
        if len(parts) <= depth:
            return str(p)
        # Return last `depth` components
        return str(Path(*parts[-depth:]))
    except (ValueError, TypeError):
        return None


def hash_project(working_dir: str) -> Optional[str]:
    """Hash a working directory to a project identifier."""
    if not working_dir:
        return None
    return hashlib.sha256(working_dir.encode()).hexdigest()[:16]


# =========================================================================
# Module-level singleton
# =========================================================================

_global_store: Optional[MemoryStore] = None


def get_memory_store(db_path: Optional[Path] = None) -> MemoryStore:
    """Get the global MemoryStore singleton.

    Args:
        db_path: Override path for the database. If None, uses ~/.tweek/memory.db.
    """
    global _global_store
    if db_path:
        # Custom path - return new instance (don't cache)
        return MemoryStore(db_path=db_path)

    if _global_store is None:
        _global_store = MemoryStore()
    return _global_store


def reset_memory_store() -> None:
    """Reset the global singleton (for testing)."""
    global _global_store
    if _global_store is not None:
        _global_store.close()
    _global_store = None
