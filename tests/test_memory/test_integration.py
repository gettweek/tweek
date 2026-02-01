"""
Tests for memory integration with hooks, overrides, feedback, and project sandbox.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from tweek.memory.schemas import PatternDecisionEntry
from tweek.memory.store import MemoryStore, reset_memory_store


@pytest.fixture(autouse=True)
def clean_singleton():
    """Reset global singleton between tests."""
    reset_memory_store()
    yield
    reset_memory_store()


@pytest.fixture
def memory_db(tmp_path):
    """Create a temporary memory DB."""
    db_path = tmp_path / "test_memory.db"
    store = MemoryStore(db_path=db_path)
    yield store
    store.close()


class TestOverridesProtection:
    """Test that memory.db is protected from AI modification."""

    def test_memory_db_in_protected_list(self):
        from tweek.hooks.overrides import PROTECTED_CONFIG_FILES
        protected_strs = [str(p) for p in PROTECTED_CONFIG_FILES]
        assert any("memory.db" in s for s in protected_strs)

    def test_is_protected_config_file_catches_memory_db(self):
        from tweek.hooks.overrides import is_protected_config_file
        memory_path = str(Path.home() / ".tweek" / "memory.db")
        assert is_protected_config_file(memory_path) is True

    def test_project_memory_db_protected(self):
        """Project-level .tweek/memory.db should also be protected."""
        from tweek.hooks.overrides import is_protected_config_file
        # Any file inside a .tweek/ directory is protected
        assert is_protected_config_file("/some/project/.tweek/memory.db") is True


class TestResolveEnforcementWithMemory:
    """Test _resolve_enforcement with memory_adjustment parameter."""

    def test_memory_adjustment_relaxes_ask_to_log(self):
        from tweek.hooks.pre_tool_use import _resolve_enforcement

        pattern_match = {
            "name": "test_pattern",
            "severity": "high",
            "confidence": "heuristic",
        }
        memory_adj = {
            "adjusted_decision": "log",
            "confidence_score": 0.95,
        }

        result = _resolve_enforcement(
            pattern_match=pattern_match,
            enforcement_policy=None,
            has_non_pattern_trigger=False,
            memory_adjustment=memory_adj,
        )
        assert result == "log"

    def test_memory_cannot_relax_deny(self):
        from tweek.hooks.pre_tool_use import _resolve_enforcement
        from tweek.hooks.overrides import EnforcementPolicy

        pattern_match = {
            "name": "ssh_key_exfil",
            "severity": "critical",
            "confidence": "deterministic",
        }
        memory_adj = {
            "adjusted_decision": "log",
            "confidence_score": 1.0,
        }

        policy = EnforcementPolicy()
        result = _resolve_enforcement(
            pattern_match=pattern_match,
            enforcement_policy=policy,
            has_non_pattern_trigger=False,
            memory_adjustment=memory_adj,
        )
        assert result == "deny"

    def test_memory_none_no_effect(self):
        from tweek.hooks.pre_tool_use import _resolve_enforcement

        pattern_match = {
            "name": "test_pattern",
            "severity": "high",
            "confidence": "heuristic",
        }

        result = _resolve_enforcement(
            pattern_match=pattern_match,
            enforcement_policy=None,
            has_non_pattern_trigger=False,
            memory_adjustment=None,
        )
        assert result == "ask"

    def test_memory_on_non_pattern_trigger(self):
        """Memory shouldn't affect non-pattern triggers (LLM/session/etc)."""
        from tweek.hooks.pre_tool_use import _resolve_enforcement

        memory_adj = {
            "adjusted_decision": "log",
            "confidence_score": 1.0,
        }

        result = _resolve_enforcement(
            pattern_match=None,
            enforcement_policy=None,
            has_non_pattern_trigger=True,
            memory_adjustment=memory_adj,
        )
        # Non-pattern triggers always return "ask", memory can't affect
        # because there's no pattern_match for immunity check
        assert result == "ask"


class TestFeedbackBridge:
    """Test that FP reports bridge to memory."""

    def test_fp_report_creates_memory_entry(self, memory_db, tmp_path):
        """report_false_positive should bridge to memory store."""
        import json
        from tweek.hooks import feedback

        # Create a temporary feedback file
        feedback_path = tmp_path / "feedback.json"
        feedback_path.write_text(json.dumps({
            "patterns": {
                "test_pattern": {
                    "total_triggers": 5,
                    "false_positives": 0,
                    "fp_rate": 0.0,
                    "last_trigger_at": None,
                    "last_fp_at": None,
                    "auto_demoted": False,
                    "original_severity": "high",
                    "current_severity": "high",
                }
            }
        }))

        # Patch feedback file path and memory store import
        with patch.object(feedback, "FEEDBACK_PATH", feedback_path):
            with patch("tweek.memory.store.get_memory_store", return_value=memory_db):
                result = feedback.report_false_positive("test_pattern", context="false alarm")

        assert result is not None
        assert result.get("false_positives", 0) == 1

        # Verify memory entry was created
        stats = memory_db.get_stats()
        assert stats["pattern_decisions"] >= 1


class TestProjectSandboxMemory:
    """Test ProjectSandbox.get_memory_store()."""

    def test_get_memory_store_creates_db(self, tmp_path):
        from tweek.sandbox.project import ProjectSandbox
        from tweek.sandbox.layers import IsolationLayer

        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        (project_dir / ".git").mkdir()

        sandbox = ProjectSandbox(project_dir)
        sandbox.config.layer = 2  # PROJECT level
        sandbox.layer = IsolationLayer.PROJECT
        sandbox.tweek_dir = project_dir / ".tweek"
        sandbox.tweek_dir.mkdir(parents=True, exist_ok=True)

        store = sandbox.get_memory_store()
        assert store is not None
        assert (project_dir / ".tweek" / "memory.db").exists()

        # Verify it's a working store
        store.record_source_scan("url", "https://test.com", had_injection=False)
        stats = store.get_stats()
        assert stats["source_trust"] == 1

        store.close()


class TestEndToEndMemoryFlow:
    """Test full memory lifecycle: write decisions -> build confidence -> suggest adjustment."""

    def test_full_lifecycle(self, memory_db):
        """Simulate a pattern that keeps getting approved until memory suggests relaxation."""
        # Phase 1: Record many approvals
        for i in range(30):
            entry = PatternDecisionEntry(
                pattern_name="noisy_env_check",
                pattern_id=10,
                original_severity="medium",
                original_confidence="heuristic",
                decision="ask",
                user_response="approved",
                tool_name="Read",
                content_hash=f"content_{i}",
                path_prefix="src/config",
                project_hash="proj1",
            )
            memory_db.record_decision(entry)

        # Phase 2: Query for adjustment
        adjustment = memory_db.get_confidence_adjustment(
            pattern_name="noisy_env_check",
            path_prefix="src/config",
            current_decision="ask",
            original_severity="medium",
            original_confidence="heuristic",
        )
        assert adjustment is not None
        assert adjustment.adjusted_decision == "log"
        assert adjustment.approval_ratio == 1.0
        assert adjustment.total_decisions == 30

        # Phase 3: Validate the adjustment
        from tweek.memory.safety import validate_memory_adjustment
        final = validate_memory_adjustment(
            pattern_name="noisy_env_check",
            original_severity="medium",
            original_confidence="heuristic",
            suggested_decision="log",
            current_decision="ask",
        )
        assert final == "log"

    def test_critical_immune_lifecycle(self, memory_db):
        """Even with 100% approvals, CRITICAL+deterministic stays denied."""
        for i in range(50):
            entry = PatternDecisionEntry(
                pattern_name="ssh_key_exfil",
                pattern_id=99,
                original_severity="critical",
                original_confidence="deterministic",
                decision="deny",
                user_response="denied",
                tool_name="Read",
                content_hash=f"ssh_{i}",
                path_prefix=None,
                project_hash=None,
            )
            memory_db.record_decision(entry)

        # Memory should return None for immune patterns
        adjustment = memory_db.get_confidence_adjustment(
            pattern_name="ssh_key_exfil",
            current_decision="deny",
            original_severity="critical",
            original_confidence="deterministic",
        )
        assert adjustment is None

    def test_source_trust_lifecycle(self, memory_db):
        """Test source trust degradation over multiple scans."""
        url = "https://sketchy-api.com/data"

        # 5 clean scans
        for _ in range(5):
            memory_db.record_source_scan("url", url, had_injection=False)

        entry = memory_db.get_source_trust("url", url)
        assert entry.trust_score == 1.0

        # 5 injection scans
        for _ in range(5):
            memory_db.record_source_scan("url", url, had_injection=True)

        entry = memory_db.get_source_trust("url", url)
        assert entry.trust_score == pytest.approx(0.5, abs=0.05)
        assert entry.total_scans == 10
        assert entry.injection_detections == 5

    def test_whitelist_suggestion_lifecycle(self, memory_db):
        """Pattern with high approval rate generates whitelist suggestion."""
        # Record 30 approvals, 0 denials
        for i in range(30):
            entry = PatternDecisionEntry(
                pattern_name="safe_pattern",
                pattern_id=5,
                original_severity="medium",
                original_confidence="heuristic",
                decision="ask",
                user_response="approved",
                tool_name="Bash",
                content_hash=f"safe_{i}",
                path_prefix="src",
                project_hash="proj1",
            )
            memory_db.record_decision(entry)

        suggestions = memory_db.get_whitelist_suggestions()
        assert len(suggestions) >= 1

        suggestion = suggestions[0]
        assert suggestion.pattern_name == "safe_pattern"
        assert suggestion.confidence >= 0.9
        assert suggestion.human_reviewed == 0

        # Accept the suggestion
        memory_db.review_whitelist_suggestion(suggestion.id, accepted=True)
        pending = memory_db.get_whitelist_suggestions(pending_only=True)
        assert len(pending) == 0

    def test_mixed_approval_no_suggestion(self, memory_db):
        """Pattern with mixed approvals/denials should not generate suggestion."""
        for i in range(10):
            entry = PatternDecisionEntry(
                pattern_name="ambiguous_pattern",
                pattern_id=7,
                original_severity="high",
                original_confidence="heuristic",
                decision="ask",
                user_response="approved" if i < 7 else "denied",
                tool_name="Bash",
                content_hash=f"amb_{i}",
                path_prefix="src",
                project_hash="proj1",
            )
            memory_db.record_decision(entry)

        suggestions = memory_db.get_whitelist_suggestions()
        assert len(suggestions) == 0  # 70% approval, below 90% threshold

    def test_workflow_baseline_comparison(self, memory_db):
        """Test cross-session baseline comparison."""
        # Session 1: normal behavior
        for _ in range(20):
            memory_db.update_workflow("proj1", "Bash", hour_of_day=14)
        for _ in range(5):
            memory_db.update_workflow("proj1", "Read", hour_of_day=14)

        baselines = memory_db.get_workflow_baseline("proj1")
        assert len(baselines) == 2

        bash_bl = memory_db.get_workflow_tool_baseline("proj1", "Bash")
        assert bash_bl.invocation_count == 20

        read_bl = memory_db.get_workflow_tool_baseline("proj1", "Read")
        assert read_bl.invocation_count == 5
