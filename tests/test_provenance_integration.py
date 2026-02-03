"""
Tests for provenance integration with hooks — verifies that the taint tracking
system correctly adjusts enforcement decisions in the pre-hook pipeline.

Tests cover:
- _resolve_enforcement with taint_level parameter
- Clean session relaxation (high+heuristic → log)
- Tainted session escalation (log → ask)
- Deny never relaxed by provenance
- End-to-end hook flow with provenance
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from tweek.hooks.pre_tool_use import _resolve_enforcement
from tweek.hooks.overrides import EnforcementPolicy
from tweek.memory.provenance import (
    SessionTaintStore,
    reset_taint_store,
    get_taint_store,
    EXTERNAL_SOURCE_TOOLS,
)

pytestmark = pytest.mark.memory


# =========================================================================
# Fixtures
# =========================================================================

@pytest.fixture(autouse=True)
def clean_singleton():
    """Reset provenance singleton between tests."""
    reset_taint_store()
    yield
    reset_taint_store()


# =========================================================================
# _resolve_enforcement with taint_level
# =========================================================================

class TestResolveEnforcementWithTaint:
    """Test that _resolve_enforcement correctly applies taint-level adjustments."""

    def test_clean_session_relaxes_high_heuristic(self):
        """In a clean session, high+heuristic should be relaxed to log."""
        pattern = {"name": "test", "severity": "high", "confidence": "heuristic"}
        result = _resolve_enforcement(
            pattern_match=pattern,
            enforcement_policy=None,
            taint_level="clean",
        )
        assert result == "log"

    def test_clean_session_relaxes_medium_heuristic(self):
        """In a clean session, medium+heuristic should be relaxed to log."""
        pattern = {"name": "test", "severity": "medium", "confidence": "heuristic"}
        result = _resolve_enforcement(
            pattern_match=pattern,
            enforcement_policy=None,
            taint_level="clean",
        )
        assert result == "log"

    def test_clean_session_keeps_critical_heuristic(self):
        """Critical+heuristic should NOT be relaxed in clean sessions."""
        pattern = {"name": "test", "severity": "critical", "confidence": "heuristic"}
        policy = EnforcementPolicy()
        result = _resolve_enforcement(
            pattern_match=pattern,
            enforcement_policy=policy,
            taint_level="clean",
        )
        assert result == "ask"

    def test_clean_session_keeps_critical_deterministic(self):
        """Critical+deterministic is always deny, regardless of taint."""
        pattern = {"name": "test", "severity": "critical", "confidence": "deterministic"}
        policy = EnforcementPolicy()
        result = _resolve_enforcement(
            pattern_match=pattern,
            enforcement_policy=policy,
            taint_level="clean",
        )
        assert result == "deny"

    def test_low_taint_no_change(self):
        """Low taint level should not change the base decision."""
        pattern = {"name": "test", "severity": "high", "confidence": "heuristic"}
        result = _resolve_enforcement(
            pattern_match=pattern,
            enforcement_policy=None,
            taint_level="low",
        )
        assert result == "ask"

    def test_medium_taint_escalates_high_heuristic_log(self):
        """In medium+ taint, a logged high+heuristic should escalate to ask."""
        pattern = {"name": "test", "severity": "high", "confidence": "heuristic"}
        # Use memory to get base decision to "log" first
        memory_adj = {"adjusted_decision": "log", "confidence_score": 0.95}
        result = _resolve_enforcement(
            pattern_match=pattern,
            enforcement_policy=None,
            memory_adjustment=memory_adj,
            taint_level="medium",
        )
        # Memory relaxes ask→log, but medium taint escalates log→ask for high+heuristic
        assert result == "ask"

    def test_critical_taint_escalates_medium_logged(self):
        """In critical taint, even medium patterns logged should escalate to ask."""
        pattern = {"name": "test", "severity": "medium", "confidence": "heuristic"}
        # Use memory to get base decision to "log"
        memory_adj = {"adjusted_decision": "log", "confidence_score": 0.95}
        result = _resolve_enforcement(
            pattern_match=pattern,
            enforcement_policy=None,
            memory_adjustment=memory_adj,
            taint_level="critical",
        )
        assert result == "ask"

    def test_deny_never_relaxed_by_taint(self):
        """Deny should never be relaxed, even in clean sessions."""
        pattern = {"name": "test", "severity": "critical", "confidence": "deterministic"}
        policy = EnforcementPolicy()
        result = _resolve_enforcement(
            pattern_match=pattern,
            enforcement_policy=policy,
            taint_level="clean",
        )
        assert result == "deny"

    def test_no_pattern_match_ignores_taint(self):
        """Non-pattern triggers should not be affected by taint."""
        result = _resolve_enforcement(
            pattern_match=None,
            enforcement_policy=None,
            has_non_pattern_trigger=True,
            taint_level="clean",
        )
        assert result == "ask"

    def test_low_severity_stays_log_in_tainted(self):
        """Low severity patterns should stay log even in tainted sessions."""
        pattern = {"name": "test", "severity": "low", "confidence": "heuristic"}
        result = _resolve_enforcement(
            pattern_match=pattern,
            enforcement_policy=None,
            taint_level="critical",
        )
        assert result == "log"


# =========================================================================
# Clean Session False Positive Reduction
# =========================================================================

class TestCleanSessionFPReduction:
    """Test that clean sessions produce fewer prompts for common patterns."""

    COMMON_FP_PATTERNS = [
        {"name": "env_file_read", "severity": "high", "confidence": "heuristic"},
        {"name": "env_file_write", "severity": "medium", "confidence": "heuristic"},
        {"name": "config_file_access", "severity": "medium", "confidence": "contextual"},
        {"name": "api_key_pattern", "severity": "high", "confidence": "contextual"},
        {"name": "base64_detection", "severity": "medium", "confidence": "heuristic"},
    ]

    def test_common_patterns_all_log_in_clean(self):
        """All common FP-generating patterns should be 'log' in clean sessions."""
        for pattern in self.COMMON_FP_PATTERNS:
            result = _resolve_enforcement(
                pattern_match=pattern,
                enforcement_policy=None,
                taint_level="clean",
            )
            assert result == "log", (
                f"Pattern {pattern['name']} ({pattern['severity']}+{pattern['confidence']}) "
                f"returned '{result}' instead of 'log' in clean session"
            )

    def test_same_patterns_ask_in_tainted(self):
        """Same patterns should produce 'ask' in medium+ tainted sessions."""
        for pattern in self.COMMON_FP_PATTERNS:
            if pattern["severity"] in ("high",) and pattern["confidence"] in ("heuristic", "deterministic"):
                result = _resolve_enforcement(
                    pattern_match=pattern,
                    enforcement_policy=None,
                    taint_level="medium",
                )
                assert result == "ask", (
                    f"Pattern {pattern['name']} should be 'ask' in tainted session"
                )


# =========================================================================
# Post-hook Taint Marker Integration
# =========================================================================

class TestPostHookTaintMarkers:
    """Test that post-hook correctly writes taint markers."""

    def test_screen_content_writes_taint_on_findings(self, tmp_path):
        """When screen_content finds patterns, it should record taint."""
        db_path = tmp_path / "test_taint.db"
        store = SessionTaintStore(db_path=db_path)

        # Mock get_taint_store to return our test store
        with patch("tweek.memory.provenance.get_taint_store", return_value=store):
            from tweek.hooks.post_tool_use import screen_content

            # Create content with a known pattern match
            # We mock the PatternMatcher to return a finding
            mock_match = [{
                "name": "test_injection",
                "severity": "high",
                "confidence": "heuristic",
                "description": "Test injection pattern",
                "regex": "INJECT_TEST",
            }]

            with patch("tweek.hooks.pre_tool_use.PatternMatcher") as MockMatcher:
                mock_instance = MockMatcher.return_value
                mock_instance.check_all.return_value = mock_match

                # Mock overrides to not filter
                with patch("tweek.hooks.post_tool_use.get_overrides", return_value=None):
                    result = screen_content(
                        content="INJECT_TEST some content",
                        tool_name="Read",
                        tool_input={"file_path": "/tmp/test.txt"},
                        session_id="test-sess-1",
                    )

            # Verify taint was recorded
            state = store.get_session_taint("test-sess-1")
            assert state["taint_level"] == "high"
            assert state["last_taint_source"] == "Read:/tmp/test.txt"

        store.close()

    def test_screen_content_no_taint_without_findings(self, tmp_path):
        """When no patterns found, taint should not be recorded."""
        db_path = tmp_path / "test_taint.db"
        store = SessionTaintStore(db_path=db_path)

        with patch("tweek.memory.provenance.get_taint_store", return_value=store):
            from tweek.hooks.post_tool_use import screen_content

            with patch("tweek.hooks.pre_tool_use.PatternMatcher") as MockMatcher:
                mock_instance = MockMatcher.return_value
                mock_instance.check_all.return_value = []

                with patch("tweek.hooks.post_tool_use.get_overrides", return_value=None):
                    result = screen_content(
                        content="clean safe content",
                        tool_name="Read",
                        tool_input={"file_path": "/tmp/safe.txt"},
                        session_id="test-sess-2",
                    )

            # Should still be clean
            state = store.get_session_taint("test-sess-2")
            assert state["taint_level"] == "clean"

        store.close()


# =========================================================================
# External Ingest Recording
# =========================================================================

class TestExternalIngestRecording:
    """Test that process_hook records external ingests."""

    def test_read_records_external_ingest(self, tmp_path):
        """Read tool responses should record an external ingest event."""
        db_path = tmp_path / "test_taint.db"
        store = SessionTaintStore(db_path=db_path)

        with patch("tweek.memory.provenance.get_taint_store", return_value=store):
            from tweek.hooks.post_tool_use import process_hook

            # Mock all dependencies to isolate the ingest recording
            with patch("tweek.hooks.post_tool_use.get_project_sandbox", return_value=None):
                with patch("tweek.hooks.post_tool_use.get_overrides", return_value=None):
                    with patch("tweek.hooks.post_tool_use.screen_content", return_value={}):
                        process_hook({
                            "tool_name": "Read",
                            "tool_input": {"file_path": "/tmp/data.txt"},
                            "tool_response": "file contents here",
                            "session_id": "test-sess-3",
                            "cwd": "/tmp",
                        })

            state = store.get_session_taint("test-sess-3")
            assert state["total_external_ingests"] == 1

        store.close()

    def test_bash_does_not_record_ingest(self, tmp_path):
        """Bash is not an external source tool — no ingest should be recorded."""
        db_path = tmp_path / "test_taint.db"
        store = SessionTaintStore(db_path=db_path)

        with patch("tweek.memory.provenance.get_taint_store", return_value=store):
            from tweek.hooks.post_tool_use import process_hook

            with patch("tweek.hooks.post_tool_use.get_project_sandbox", return_value=None):
                with patch("tweek.hooks.post_tool_use.get_overrides", return_value=None):
                    with patch("tweek.hooks.post_tool_use.screen_content", return_value={}):
                        process_hook({
                            "tool_name": "Bash",
                            "tool_input": {"command": "ls"},
                            "tool_response": "file1 file2",
                            "session_id": "test-sess-4",
                            "cwd": "/tmp",
                        })

            state = store.get_session_taint("test-sess-4")
            assert state["total_external_ingests"] == 0

        store.close()
