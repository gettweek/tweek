"""
Tests for tweek.memory.store — Core MemoryStore CRUD, decay, schema integrity.
"""

import sqlite3
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

pytestmark = pytest.mark.memory

from tweek.memory.schemas import PatternDecisionEntry, SourceTrustEntry
from tweek.memory.store import (
    DECAY_HALF_LIFE_DAYS,
    MemoryStore,
    content_hash,
    hash_project,
    normalize_path_prefix,
)


@pytest.fixture
def store(tmp_path):
    """Create a temporary MemoryStore for testing."""
    db_path = tmp_path / "test_memory.db"
    s = MemoryStore(db_path=db_path)
    yield s
    s.close()


@pytest.fixture
def populated_store(store):
    """Store with some test data pre-loaded."""
    from datetime import datetime, timedelta

    # Record several pattern decisions
    for i in range(15):
        entry = PatternDecisionEntry(
            pattern_name="test_pattern",
            pattern_id=1,
            original_severity="high",
            original_confidence="heuristic",
            decision="ask",
            user_response="approved",
            tool_name="Bash",
            content_hash=f"hash_{i}",
            path_prefix="src/lib",
            project_hash="proj123",
        )
        store.record_decision(entry)

    # Record some denials
    for i in range(3):
        entry = PatternDecisionEntry(
            pattern_name="test_pattern",
            pattern_id=1,
            original_severity="high",
            original_confidence="heuristic",
            decision="ask",
            user_response="denied",
            tool_name="Bash",
            content_hash=f"denied_hash_{i}",
            path_prefix="src/lib",
            project_hash="proj123",
        )
        store.record_decision(entry)

    # Spread timestamps over 2 hours so temporal spread check passes
    conn = store._get_connection()
    rows = conn.execute(
        "SELECT id FROM pattern_decisions ORDER BY id"
    ).fetchall()
    base_time = datetime.utcnow() - timedelta(hours=2)
    for idx, row in enumerate(rows):
        ts = (base_time + timedelta(minutes=idx * 7)).isoformat()
        conn.execute("UPDATE pattern_decisions SET timestamp = ? WHERE id = ?", (ts, row["id"]))
    conn.commit()

    return store


class TestSchema:
    """Test schema creation and integrity."""

    def test_tables_created(self, store):
        conn = store._get_connection()
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {r["name"] for r in tables}

        assert "pattern_decisions" in table_names
        assert "source_trust" in table_names
        assert "workflow_baselines" in table_names
        assert "learned_whitelists" in table_names
        assert "memory_audit" in table_names
        assert "schema_version" in table_names

    def test_view_created(self, store):
        conn = store._get_connection()
        views = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='view'"
        ).fetchall()
        view_names = {r["name"] for r in views}
        assert "pattern_confidence_view" in view_names

    def test_wal_mode(self, store):
        conn = store._get_connection()
        mode = conn.execute("PRAGMA journal_mode").fetchone()
        assert mode[0] == "wal"

    def test_schema_version_set(self, store):
        conn = store._get_connection()
        row = conn.execute("SELECT version FROM schema_version").fetchone()
        assert row["version"] == MemoryStore.SCHEMA_VERSION

    def test_check_constraint_blocks_critical_allow(self, store):
        """CRITICAL+deterministic patterns cannot be recorded as 'allow'."""
        entry = PatternDecisionEntry(
            pattern_name="ssh_key_read",
            pattern_id=99,
            original_severity="critical",
            original_confidence="deterministic",
            decision="allow",
            user_response="approved",
            tool_name="Read",
            content_hash="abc",
            path_prefix=None,
            project_hash=None,
        )
        result = store.record_decision(entry)
        assert result == -1  # Should be blocked by safety check

        # Verify nothing was inserted
        conn = store._get_connection()
        count = conn.execute(
            "SELECT COUNT(*) as cnt FROM pattern_decisions WHERE pattern_name = 'ssh_key_read'"
        ).fetchone()["cnt"]
        assert count == 0

    def test_check_constraint_allows_critical_deny(self, store):
        """CRITICAL+deterministic with deny should be allowed."""
        entry = PatternDecisionEntry(
            pattern_name="ssh_key_read",
            pattern_id=99,
            original_severity="critical",
            original_confidence="deterministic",
            decision="deny",
            user_response="denied",
            tool_name="Read",
            content_hash="abc",
            path_prefix=None,
            project_hash=None,
        )
        result = store.record_decision(entry)
        assert result > 0


class TestPatternDecisions:
    """Test pattern decision recording and querying."""

    def test_record_decision(self, store):
        entry = PatternDecisionEntry(
            pattern_name="env_file_read",
            pattern_id=42,
            original_severity="high",
            original_confidence="heuristic",
            decision="ask",
            user_response="approved",
            tool_name="Read",
            content_hash="abc123",
            path_prefix="/src/config",
            project_hash="proj1",
        )
        row_id = store.record_decision(entry)
        assert row_id > 0

    def test_record_multiple_decisions(self, store):
        for i in range(5):
            entry = PatternDecisionEntry(
                pattern_name="test_pattern",
                pattern_id=1,
                original_severity="medium",
                original_confidence="heuristic",
                decision="ask",
                user_response="approved" if i < 4 else "denied",
                tool_name="Bash",
                content_hash=f"hash_{i}",
                path_prefix="src",
                project_hash="p1",
            )
            store.record_decision(entry)

        stats = store.get_stats()
        assert stats["pattern_decisions"] == 5

    def test_confidence_adjustment_no_data(self, store):
        result = store.get_confidence_adjustment(
            "nonexistent_pattern",
            path_prefix="src",
        )
        assert result is None

    def test_confidence_adjustment_with_data(self, populated_store):
        result = populated_store.get_confidence_adjustment(
            "test_pattern",
            path_prefix="src/lib",
            current_decision="ask",
            original_severity="high",
            original_confidence="heuristic",
        )
        assert result is not None
        assert result.total_decisions == 18  # 15 approved + 3 denied
        assert result.weighted_approvals > 0
        assert result.approval_ratio > 0.5

    def test_confidence_adjustment_immune_pattern(self, store):
        """CRITICAL+deterministic patterns should always return None."""
        result = store.get_confidence_adjustment(
            "ssh_key_read",
            current_decision="deny",
            original_severity="critical",
            original_confidence="deterministic",
        )
        assert result is None

    def test_confidence_view_aggregation(self, populated_store):
        conn = populated_store._get_connection()
        rows = conn.execute(
            "SELECT * FROM pattern_confidence_view WHERE pattern_name = 'test_pattern'"
        ).fetchall()
        assert len(rows) >= 1

        row = rows[0]
        assert row["total_decisions"] == 18
        assert row["weighted_approvals"] > 0


class TestSourceTrust:
    """Test source trust tracking."""

    def test_record_clean_scan(self, store):
        store.record_source_scan("url", "https://example.com/api", had_injection=False)

        entry = store.get_source_trust("url", "https://example.com/api")
        assert entry is not None
        assert entry.total_scans == 1
        assert entry.injection_detections == 0
        assert entry.trust_score == 1.0

    def test_record_injection_scan(self, store):
        store.record_source_scan("url", "https://evil.com/page", had_injection=True)

        entry = store.get_source_trust("url", "https://evil.com/page")
        assert entry is not None
        assert entry.total_scans == 1
        assert entry.injection_detections == 1
        assert entry.trust_score == 0.0

    def test_trust_score_decreases_with_injections(self, store):
        url = "https://sketchy.com/data"
        # 5 clean scans
        for _ in range(5):
            store.record_source_scan("url", url, had_injection=False)
        # 5 injection scans
        for _ in range(5):
            store.record_source_scan("url", url, had_injection=True)

        entry = store.get_source_trust("url", url)
        assert entry is not None
        assert entry.total_scans == 10
        assert entry.injection_detections == 5
        assert entry.trust_score == pytest.approx(0.5, abs=0.05)

    def test_mostly_injections_low_trust(self, store):
        url = "https://bad.com"
        store.record_source_scan("url", url, had_injection=False)
        for _ in range(4):
            store.record_source_scan("url", url, had_injection=True)

        entry = store.get_source_trust("url", url)
        assert entry.trust_score < 0.3

    def test_get_nonexistent_source(self, store):
        entry = store.get_source_trust("url", "https://never-seen.com")
        assert entry is None

    def test_get_all_sources(self, store):
        store.record_source_scan("url", "https://good.com", had_injection=False)
        store.record_source_scan("url", "https://bad.com", had_injection=True)

        all_sources = store.get_all_sources()
        assert len(all_sources) == 2

        suspicious = store.get_all_sources(suspicious_only=True)
        assert len(suspicious) == 1
        assert suspicious[0].source_key == "https://bad.com"


class TestWorkflowBaselines:
    """Test workflow baseline tracking."""

    def test_update_workflow(self, store):
        store.update_workflow("proj1", "Bash", hour_of_day=14)
        store.update_workflow("proj1", "Bash", hour_of_day=14)
        store.update_workflow("proj1", "Read", hour_of_day=14)

        baselines = store.get_workflow_baseline("proj1")
        assert len(baselines) == 2  # Bash and Read

        bash_baseline = [b for b in baselines if b.tool_name == "Bash"][0]
        assert bash_baseline.invocation_count == 2

    def test_update_workflow_with_denial(self, store):
        store.update_workflow("proj1", "Bash", hour_of_day=10, was_denied=True)
        store.update_workflow("proj1", "Bash", hour_of_day=10, was_denied=False)

        baselines = store.get_workflow_baseline("proj1")
        bash_baseline = baselines[0]
        assert bash_baseline.invocation_count == 2
        assert bash_baseline.denied_count == 1

    def test_get_tool_baseline(self, store):
        store.update_workflow("proj1", "Bash", hour_of_day=10)
        store.update_workflow("proj1", "Bash", hour_of_day=14)
        store.update_workflow("proj1", "Bash", hour_of_day=14)

        result = store.get_workflow_tool_baseline("proj1", "Bash")
        assert result is not None
        assert result.invocation_count == 3

    def test_empty_baseline(self, store):
        baselines = store.get_workflow_baseline("nonexistent")
        assert baselines == []


class TestLearnedWhitelists:
    """Test learned whitelist suggestion system."""

    def test_suggestions_generated(self, populated_store):
        suggestions = populated_store.get_whitelist_suggestions()
        # With 15 approvals and 3 denials (83% ratio), shouldn't generate
        # because MIN_APPROVAL_RATIO is 90%
        # Let's add more approvals
        for i in range(10):
            entry = PatternDecisionEntry(
                pattern_name="test_pattern",
                pattern_id=1,
                original_severity="high",
                original_confidence="heuristic",
                decision="ask",
                user_response="approved",
                tool_name="Bash",
                content_hash=f"extra_{i}",
                path_prefix="src/lib",
                project_hash="proj123",
            )
            populated_store.record_decision(entry)

        # Now 25 approved, 3 denied = 89.3% - still below 90%
        # Add more
        for i in range(5):
            entry = PatternDecisionEntry(
                pattern_name="test_pattern",
                pattern_id=1,
                original_severity="high",
                original_confidence="heuristic",
                decision="ask",
                user_response="approved",
                tool_name="Bash",
                content_hash=f"more_{i}",
                path_prefix="src/lib",
                project_hash="proj123",
            )
            populated_store.record_decision(entry)

        # 30 approved, 3 denied = 90.9% - should generate
        suggestions = populated_store.get_whitelist_suggestions()
        assert len(suggestions) >= 1

    def test_review_suggestion(self, store):
        # Create a suggestion manually
        conn = store._get_connection()
        conn.execute(
            """
            INSERT INTO learned_whitelists
            (pattern_name, tool_name, path_prefix, approval_count, denial_count,
             confidence, suggested_at, human_reviewed)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("test_pattern", "Bash", "src", 20, 1, 0.95,
             datetime.utcnow().isoformat(), 0),
        )

        suggestions = store.get_whitelist_suggestions()
        assert len(suggestions) == 1

        store.review_whitelist_suggestion(suggestions[0].id, accepted=True)

        # Should no longer appear in pending
        pending = store.get_whitelist_suggestions(pending_only=True)
        assert len(pending) == 0

        # Should appear in all
        all_suggestions = store.get_whitelist_suggestions(pending_only=False)
        assert len(all_suggestions) == 1
        assert all_suggestions[0].human_reviewed == 1


class TestDecayEngine:
    """Test time-based decay."""

    def test_decay_reduces_weights(self, store):
        # Insert an old entry with a manually set old timestamp
        conn = store._get_connection()
        old_time = (datetime.utcnow() - timedelta(days=60)).isoformat()
        conn.execute(
            """
            INSERT INTO pattern_decisions
            (pattern_name, pattern_id, original_severity, original_confidence,
             decision, tool_name, timestamp, decay_weight)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("old_pattern", 1, "medium", "heuristic", "ask", "Bash", old_time, 1.0),
        )

        results = store.apply_decay()
        assert results["pattern_decisions"] >= 1

        # Check the weight decreased
        row = conn.execute(
            "SELECT decay_weight FROM pattern_decisions WHERE pattern_name = 'old_pattern'"
        ).fetchone()
        # After 60 days with 30-day half-life: weight = 2^(-60/30) = 0.25
        assert row["decay_weight"] == pytest.approx(0.25, abs=0.05)

    def test_decay_preserves_recent(self, store):
        entry = PatternDecisionEntry(
            pattern_name="recent_pattern",
            pattern_id=1,
            original_severity="medium",
            original_confidence="heuristic",
            decision="ask",
            user_response="approved",
            tool_name="Bash",
            content_hash="recent",
            path_prefix=None,
            project_hash=None,
        )
        store.record_decision(entry)

        store.apply_decay()

        conn = store._get_connection()
        row = conn.execute(
            "SELECT decay_weight FROM pattern_decisions WHERE pattern_name = 'recent_pattern'"
        ).fetchone()
        # Recent entries should have weight close to 1.0
        assert row["decay_weight"] > 0.95

    def test_decay_source_trust(self, store):
        conn = store._get_connection()
        old_time = (datetime.utcnow() - timedelta(days=90)).isoformat()
        conn.execute(
            """
            INSERT INTO source_trust
            (source_type, source_key, total_scans, injection_detections,
             trust_score, timestamp, decay_weight)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            ("url", "https://old.com", 10, 5, 0.5, old_time, 1.0),
        )

        results = store.apply_decay()
        assert results["source_trust"] >= 1

        row = conn.execute(
            "SELECT decay_weight FROM source_trust WHERE source_key = 'https://old.com'"
        ).fetchone()
        # After 90 days: 2^(-90/30) = 0.125
        assert row["decay_weight"] == pytest.approx(0.125, abs=0.05)


class TestStatsAndExport:
    """Test statistics and export functionality."""

    def test_get_stats(self, populated_store):
        stats = populated_store.get_stats()
        assert stats["pattern_decisions"] == 18
        assert stats["source_trust"] == 0
        assert stats["db_size_bytes"] > 0

    def test_get_pattern_stats(self, populated_store):
        stats = populated_store.get_pattern_stats()
        assert len(stats) >= 1
        assert stats[0]["pattern_name"] == "test_pattern"

    def test_export_all(self, populated_store):
        data = populated_store.export_all()
        assert "pattern_decisions" in data
        assert len(data["pattern_decisions"]) == 18
        assert "stats" in data

    def test_clear_table(self, populated_store):
        count = populated_store.clear_table("pattern_decisions")
        assert count == 18

        stats = populated_store.get_stats()
        assert stats["pattern_decisions"] == 0

    def test_clear_all(self, populated_store):
        populated_store.record_source_scan("url", "https://test.com", False)
        results = populated_store.clear_all()
        assert results["pattern_decisions"] == 18
        assert results["source_trust"] == 1

    def test_clear_invalid_table(self, store):
        with pytest.raises(ValueError):
            store.clear_table("nonexistent_table")


class TestAuditTrail:
    """Test that operations are audited."""

    def test_record_decision_audited(self, store):
        entry = PatternDecisionEntry(
            pattern_name="test",
            pattern_id=1,
            original_severity="medium",
            original_confidence="heuristic",
            decision="ask",
            user_response="approved",
            tool_name="Bash",
            content_hash="h1",
            path_prefix=None,
            project_hash=None,
        )
        store.record_decision(entry)

        audit = store.get_audit_log(limit=10)
        write_entries = [a for a in audit if a["operation"] == "write"]
        assert len(write_entries) >= 1

    def test_read_audited(self, store):
        store.get_confidence_adjustment("missing_pattern")

        audit = store.get_audit_log(limit=10)
        read_entries = [a for a in audit if a["operation"] == "read"]
        assert len(read_entries) >= 1

    def test_decay_audited(self, store):
        store.apply_decay()

        audit = store.get_audit_log(limit=10)
        decay_entries = [a for a in audit if a["operation"] == "decay"]
        assert len(decay_entries) == 1


class TestHelpers:
    """Test helper functions."""

    def test_content_hash(self):
        h = content_hash("test content")
        assert len(h) == 64  # SHA-256

    def test_content_hash_deterministic(self):
        h1 = content_hash("same content")
        h2 = content_hash("same content")
        assert h1 == h2

    def test_content_hash_different(self):
        h1 = content_hash("content a")
        h2 = content_hash("content b")
        assert h1 != h2

    def test_normalize_path_prefix(self):
        result = normalize_path_prefix("/home/user/project/src/lib/utils.py")
        assert result is not None
        parts = Path(result).parts
        assert len(parts) <= 3

    def test_normalize_path_prefix_short(self):
        result = normalize_path_prefix("/src")
        assert result is not None

    def test_normalize_path_prefix_none(self):
        result = normalize_path_prefix("")
        assert result is None

    def test_hash_project(self):
        h = hash_project("/home/user/myproject")
        assert h is not None
        assert len(h) == 16

    def test_hash_project_deterministic(self):
        h1 = hash_project("/same/path")
        h2 = hash_project("/same/path")
        assert h1 == h2

    def test_hash_project_none(self):
        assert hash_project("") is None
        assert hash_project(None) is None
