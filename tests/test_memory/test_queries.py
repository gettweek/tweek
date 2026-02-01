"""
Tests for tweek.memory.queries — Hook entry point functions, fail-safe behavior.
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from tweek.memory.queries import (
    memory_get_workflow_baseline,
    memory_read_for_pattern,
    memory_read_source_trust,
    memory_update_workflow,
    memory_write_after_decision,
    memory_write_source_scan,
)
from tweek.memory.store import MemoryStore, get_memory_store, reset_memory_store


@pytest.fixture(autouse=True)
def clean_singleton():
    """Reset the global memory store singleton between tests."""
    reset_memory_store()
    yield
    reset_memory_store()


@pytest.fixture
def memory_db(tmp_path):
    """Create a temporary memory DB and patch the singleton."""
    db_path = tmp_path / "test_memory.db"
    store = MemoryStore(db_path=db_path)

    with patch("tweek.memory.queries.get_memory_store", return_value=store):
        yield store

    store.close()


class TestMemoryReadForPattern:
    """Test memory_read_for_pattern query function."""

    def test_no_data_returns_none(self, memory_db):
        result = memory_read_for_pattern(
            pattern_name="unknown_pattern",
            pattern_severity="medium",
            pattern_confidence="heuristic",
            tool_name="Bash",
        )
        assert result is None

    def test_insufficient_data_returns_none(self, memory_db):
        """With fewer than MIN_DECISION_THRESHOLD decisions, no suggestion."""
        from tweek.memory.schemas import PatternDecisionEntry
        for i in range(5):
            memory_db.record_decision(PatternDecisionEntry(
                pattern_name="test", pattern_id=1,
                original_severity="high", original_confidence="heuristic",
                decision="ask", user_response="approved",
                tool_name="Bash", content_hash=f"h{i}",
                path_prefix=None, project_hash=None,
            ))

        result = memory_read_for_pattern(
            pattern_name="test",
            pattern_severity="high",
            pattern_confidence="heuristic",
            tool_name="Bash",
        )
        assert result is None

    def test_high_approval_returns_adjustment(self, memory_db):
        """With enough approvals, should suggest relaxation."""
        from tweek.memory.schemas import PatternDecisionEntry
        for i in range(30):
            memory_db.record_decision(PatternDecisionEntry(
                pattern_name="noisy_pattern", pattern_id=1,
                original_severity="medium", original_confidence="heuristic",
                decision="ask", user_response="approved",
                tool_name="Bash", content_hash=f"h{i}",
                path_prefix=None, project_hash=None,
            ))

        result = memory_read_for_pattern(
            pattern_name="noisy_pattern",
            pattern_severity="medium",
            pattern_confidence="heuristic",
            tool_name="Bash",
        )
        assert result is not None
        assert result["adjusted_decision"] == "log"

    def test_immune_pattern_returns_none(self, memory_db):
        """CRITICAL+deterministic patterns should never get adjustments."""
        result = memory_read_for_pattern(
            pattern_name="ssh_key_read",
            pattern_severity="critical",
            pattern_confidence="deterministic",
            tool_name="Read",
        )
        assert result is None

    def test_exception_returns_none(self):
        """Exceptions should be swallowed and return None."""
        with patch("tweek.memory.queries.get_memory_store", side_effect=Exception("DB error")):
            result = memory_read_for_pattern(
                pattern_name="test",
                pattern_severity="medium",
                pattern_confidence="heuristic",
                tool_name="Bash",
            )
            assert result is None


class TestMemoryWriteAfterDecision:
    """Test memory_write_after_decision function."""

    def test_write_decision(self, memory_db):
        memory_write_after_decision(
            pattern_name="env_file_read",
            pattern_id=42,
            original_severity="high",
            original_confidence="heuristic",
            decision="ask",
            user_response="approved",
            tool_name="Read",
            content="cat .env",
            path_prefix="/src",
            project_hash="proj123",
        )

        stats = memory_db.get_stats()
        assert stats["pattern_decisions"] == 1

    def test_write_exception_silenced(self):
        """Exceptions should be silenced."""
        with patch("tweek.memory.queries.get_memory_store", side_effect=Exception("DB error")):
            # Should not raise
            memory_write_after_decision(
                pattern_name="test", pattern_id=1,
                original_severity="medium", original_confidence="heuristic",
                decision="ask", user_response=None,
                tool_name="Bash", content="test",
            )


class TestMemoryReadSourceTrust:
    """Test memory_read_source_trust function."""

    def test_no_data_returns_none(self, memory_db):
        result = memory_read_source_trust("url", "https://unknown.com")
        assert result is None

    def test_returns_trust_data(self, memory_db):
        memory_db.record_source_scan("url", "https://example.com", had_injection=False)

        result = memory_read_source_trust("url", "https://example.com")
        assert result is not None
        assert result["trust_score"] == 1.0
        assert result["total_scans"] == 1

    def test_exception_returns_none(self):
        with patch("tweek.memory.queries.get_memory_store", side_effect=Exception("DB error")):
            result = memory_read_source_trust("url", "https://test.com")
            assert result is None


class TestMemoryWriteSourceScan:
    """Test memory_write_source_scan function."""

    def test_write_clean_scan(self, memory_db):
        memory_write_source_scan("url", "https://example.com", had_injection=False)

        entry = memory_db.get_source_trust("url", "https://example.com")
        assert entry is not None
        assert entry.total_scans == 1
        assert entry.injection_detections == 0

    def test_write_injection_scan(self, memory_db):
        memory_write_source_scan("url", "https://evil.com", had_injection=True)

        entry = memory_db.get_source_trust("url", "https://evil.com")
        assert entry is not None
        assert entry.injection_detections == 1

    def test_domain_also_recorded(self, memory_db):
        """URL scans should also record domain-level trust."""
        memory_write_source_scan("url", "https://example.com/page", had_injection=True)

        domain_entry = memory_db.get_source_trust("domain", "example.com")
        assert domain_entry is not None
        assert domain_entry.injection_detections == 1

    def test_exception_silenced(self):
        with patch("tweek.memory.queries.get_memory_store", side_effect=Exception("DB error")):
            # Should not raise
            memory_write_source_scan("url", "https://test.com", had_injection=False)


class TestMemoryUpdateWorkflow:
    """Test memory_update_workflow function."""

    def test_update_workflow(self, memory_db):
        memory_update_workflow("proj1", "Bash", was_denied=False)

        baselines = memory_db.get_workflow_baseline("proj1")
        assert len(baselines) == 1
        assert baselines[0].invocation_count == 1

    def test_exception_silenced(self):
        with patch("tweek.memory.queries.get_memory_store", side_effect=Exception("DB error")):
            # Should not raise
            memory_update_workflow("proj1", "Bash")


class TestMemoryGetWorkflowBaseline:
    """Test memory_get_workflow_baseline function."""

    def test_no_data_returns_none(self, memory_db):
        result = memory_get_workflow_baseline("nonexistent")
        assert result is None

    def test_returns_baseline_summary(self, memory_db):
        memory_db.update_workflow("proj1", "Bash", hour_of_day=10)
        memory_db.update_workflow("proj1", "Bash", hour_of_day=14)
        memory_db.update_workflow("proj1", "Read", hour_of_day=10)
        memory_db.update_workflow("proj1", "Bash", hour_of_day=10, was_denied=True)

        result = memory_get_workflow_baseline("proj1")
        assert result is not None
        assert result["total_invocations"] == 4
        assert result["total_denials"] == 1
        assert "Bash" in result["tool_counts"]
        assert "Read" in result["tool_counts"]

    def test_exception_returns_none(self):
        with patch("tweek.memory.queries.get_memory_store", side_effect=Exception("DB error")):
            result = memory_get_workflow_baseline("proj1")
            assert result is None
