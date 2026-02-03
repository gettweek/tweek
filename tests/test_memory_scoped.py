"""Tests for context-scoped memory thresholds.

Verifies that narrower context requires fewer decisions to relax patterns:
  exact (pattern+tool+path+project) = 1 decision
  tool_project (pattern+tool+project) = 3 decisions
  path (pattern+path) = 5 decisions
  global (pattern only) = NEVER
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from tweek.memory.schemas import PatternDecisionEntry
from tweek.memory.safety import (
    SCOPED_THRESHOLDS,
    compute_suggested_decision,
    is_immune_pattern,
)
from tweek.memory.store import MemoryStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store(tmp_path: Path) -> MemoryStore:
    """Create a fresh MemoryStore backed by a temp file."""
    return MemoryStore(db_path=tmp_path / "test_memory.db")


def _record_approval(
    store: MemoryStore,
    pattern_name: str = "test_pattern",
    tool_name: str = "Bash",
    path_prefix: str = "src/lib",
    project_hash: str = "abc123",
    severity: str = "high",
    confidence: str = "heuristic",
) -> None:
    """Record a single approved decision."""
    store.record_decision(PatternDecisionEntry(
        pattern_name=pattern_name,
        pattern_id=None,
        original_severity=severity,
        original_confidence=confidence,
        decision="ask",
        user_response="approved",
        tool_name=tool_name,
        content_hash=None,
        path_prefix=path_prefix,
        project_hash=project_hash,
    ))


def _record_denial(
    store: MemoryStore,
    pattern_name: str = "test_pattern",
    tool_name: str = "Bash",
    path_prefix: str = "src/lib",
    project_hash: str = "abc123",
    severity: str = "high",
    confidence: str = "heuristic",
) -> None:
    """Record a single denied decision."""
    store.record_decision(PatternDecisionEntry(
        pattern_name=pattern_name,
        pattern_id=None,
        original_severity=severity,
        original_confidence=confidence,
        decision="ask",
        user_response="denied",
        tool_name=tool_name,
        content_hash=None,
        path_prefix=path_prefix,
        project_hash=project_hash,
    ))


# ---------------------------------------------------------------------------
# Threshold constants
# ---------------------------------------------------------------------------

class TestScopedThresholds:
    """Verify the threshold constants are correct."""

    def test_exact_threshold(self):
        assert SCOPED_THRESHOLDS["exact"] == 1

    def test_tool_project_threshold(self):
        assert SCOPED_THRESHOLDS["tool_project"] == 3

    def test_path_threshold(self):
        assert SCOPED_THRESHOLDS["path"] == 5

    def test_no_global_scope(self):
        assert "global" not in SCOPED_THRESHOLDS


# ---------------------------------------------------------------------------
# Exact scope: 1 approval is enough
# ---------------------------------------------------------------------------

class TestExactScope:
    """pattern + tool + path + project — 1 decision threshold."""

    def test_single_approval_relaxes(self, tmp_path):
        store = _make_store(tmp_path)
        _record_approval(store)

        adj = store.get_confidence_adjustment(
            pattern_name="test_pattern",
            tool_name="Bash",
            path_prefix="src/lib",
            project_hash="abc123",
            current_decision="ask",
            original_severity="high",
            original_confidence="heuristic",
        )
        assert adj is not None
        assert adj.adjusted_decision == "log"
        assert adj.scope == "exact"

    def test_single_denial_does_not_relax(self, tmp_path):
        store = _make_store(tmp_path)
        _record_denial(store)

        adj = store.get_confidence_adjustment(
            pattern_name="test_pattern",
            tool_name="Bash",
            path_prefix="src/lib",
            project_hash="abc123",
            current_decision="ask",
            original_severity="high",
            original_confidence="heuristic",
        )
        # Either None or no adjusted_decision (approval ratio = 0%)
        if adj is not None:
            assert adj.adjusted_decision is None

    def test_different_tool_not_exact(self, tmp_path):
        """Approval with Bash should not relax for Read at exact scope."""
        store = _make_store(tmp_path)
        _record_approval(store, tool_name="Bash")

        adj = store.get_confidence_adjustment(
            pattern_name="test_pattern",
            tool_name="Read",  # Different tool
            path_prefix="src/lib",
            project_hash="abc123",
            current_decision="ask",
            original_severity="high",
            original_confidence="heuristic",
        )
        # Should NOT match exact scope (tool mismatch)
        # May match path scope if enough data, but 1 decision < 5 threshold
        if adj is not None:
            assert adj.scope != "exact"


# ---------------------------------------------------------------------------
# Tool+project scope: 3 approvals needed
# ---------------------------------------------------------------------------

class TestToolProjectScope:
    """pattern + tool + project — 3 decision threshold."""

    def test_three_approvals_different_paths_relaxes(self, tmp_path):
        store = _make_store(tmp_path)
        for i in range(3):
            _record_approval(store, path_prefix=f"src/path_{i}")

        adj = store.get_confidence_adjustment(
            pattern_name="test_pattern",
            tool_name="Bash",
            path_prefix="src/new_path",  # New path, no exact match
            project_hash="abc123",
            current_decision="ask",
            original_severity="high",
            original_confidence="heuristic",
        )
        assert adj is not None
        assert adj.adjusted_decision == "log"
        assert adj.scope == "tool_project"

    def test_two_approvals_not_enough(self, tmp_path):
        store = _make_store(tmp_path)
        for i in range(2):
            _record_approval(store, path_prefix=f"src/path_{i}")

        adj = store.get_confidence_adjustment(
            pattern_name="test_pattern",
            tool_name="Bash",
            path_prefix="src/new_path",
            project_hash="abc123",
            current_decision="ask",
            original_severity="high",
            original_confidence="heuristic",
        )
        # 2 < 3 threshold, should not suggest
        if adj is not None:
            assert adj.adjusted_decision is None


# ---------------------------------------------------------------------------
# Path scope: 5 approvals needed
# ---------------------------------------------------------------------------

class TestPathScope:
    """pattern + path_prefix — 5 decision threshold."""

    def test_five_approvals_different_tools_relaxes(self, tmp_path):
        store = _make_store(tmp_path)
        tools = ["Bash", "Read", "Write", "Edit", "WebFetch"]
        for tool in tools:
            _record_approval(store, tool_name=tool, project_hash=f"proj_{tool}")

        adj = store.get_confidence_adjustment(
            pattern_name="test_pattern",
            tool_name="NewTool",  # Different tool
            path_prefix="src/lib",
            project_hash="new_project",  # Different project
            current_decision="ask",
            original_severity="high",
            original_confidence="heuristic",
        )
        assert adj is not None
        assert adj.adjusted_decision == "log"
        assert adj.scope == "path"

    def test_four_approvals_not_enough_for_path(self, tmp_path):
        store = _make_store(tmp_path)
        for i in range(4):
            _record_approval(store, tool_name=f"Tool_{i}", project_hash=f"proj_{i}")

        adj = store.get_confidence_adjustment(
            pattern_name="test_pattern",
            tool_name="NewTool",
            path_prefix="src/lib",
            project_hash="new_project",
            current_decision="ask",
            original_severity="high",
            original_confidence="heuristic",
        )
        if adj is not None:
            assert adj.adjusted_decision is None


# ---------------------------------------------------------------------------
# Global scope: NEVER relaxes
# ---------------------------------------------------------------------------

class TestGlobalNeverRelaxes:
    """Pattern-only (no context) should never trigger relaxation."""

    def test_many_approvals_no_context_no_relaxation(self, tmp_path):
        """20 approvals across totally scattered contexts — should not relax."""
        store = _make_store(tmp_path)
        for i in range(20):
            _record_approval(
                store,
                tool_name=f"Tool_{i}",
                path_prefix=f"path_{i}",
                project_hash=f"proj_{i}",
            )

        # Query with no matching context at any scope
        adj = store.get_confidence_adjustment(
            pattern_name="test_pattern",
            tool_name="UnknownTool",
            path_prefix="unknown/path",
            project_hash="unknown_project",
            current_decision="ask",
            original_severity="high",
            original_confidence="heuristic",
        )
        # No scope should match — each context only has 1 decision
        if adj is not None:
            assert adj.adjusted_decision is None

    def test_no_context_params_returns_none(self, tmp_path):
        """Query with no tool/project/path should return None."""
        store = _make_store(tmp_path)
        for i in range(20):
            _record_approval(store)

        adj = store.get_confidence_adjustment(
            pattern_name="test_pattern",
            tool_name=None,
            path_prefix=None,
            project_hash=None,
            current_decision="ask",
            original_severity="high",
            original_confidence="heuristic",
        )
        # No scopes can be built without context, should return None
        assert adj is None


# ---------------------------------------------------------------------------
# Scope cascade: narrowest wins
# ---------------------------------------------------------------------------

class TestScopeCascade:
    """Exact scope should be checked first, then tool_project, then path."""

    def test_exact_takes_priority_over_tool_project(self, tmp_path):
        store = _make_store(tmp_path)
        # 1 exact match
        _record_approval(store)
        # 3 more in same tool+project but different paths
        for i in range(3):
            _record_approval(store, path_prefix=f"other/path_{i}")

        adj = store.get_confidence_adjustment(
            pattern_name="test_pattern",
            tool_name="Bash",
            path_prefix="src/lib",
            project_hash="abc123",
            current_decision="ask",
            original_severity="high",
            original_confidence="heuristic",
        )
        assert adj is not None
        assert adj.scope == "exact"

    def test_tool_project_used_when_no_exact(self, tmp_path):
        store = _make_store(tmp_path)
        # 3 approvals in same tool+project, different paths
        for i in range(3):
            _record_approval(store, path_prefix=f"src/path_{i}")

        adj = store.get_confidence_adjustment(
            pattern_name="test_pattern",
            tool_name="Bash",
            path_prefix="src/new_path",  # No exact match
            project_hash="abc123",
            current_decision="ask",
            original_severity="high",
            original_confidence="heuristic",
        )
        assert adj is not None
        assert adj.scope == "tool_project"


# ---------------------------------------------------------------------------
# Safety invariants
# ---------------------------------------------------------------------------

class TestSafetyInvariants:
    """Safety rules must hold at all scopes."""

    def test_critical_deterministic_immune(self, tmp_path):
        """Critical+deterministic patterns are never adjusted."""
        store = _make_store(tmp_path)

        # Cannot record allow for critical+deterministic (CHECK constraint)
        # But we can record "ask" with "approved" user response
        store.record_decision(PatternDecisionEntry(
            pattern_name="ssh_key_read",
            pattern_id=None,
            original_severity="critical",
            original_confidence="deterministic",
            decision="ask",
            user_response="approved",
            tool_name="Bash",
            content_hash=None,
            path_prefix="src/lib",
            project_hash="abc123",
        ))

        adj = store.get_confidence_adjustment(
            pattern_name="ssh_key_read",
            tool_name="Bash",
            path_prefix="src/lib",
            project_hash="abc123",
            current_decision="ask",
            original_severity="critical",
            original_confidence="deterministic",
        )
        assert adj is None  # Immune patterns always return None

    def test_deny_never_relaxed(self, tmp_path):
        store = _make_store(tmp_path)
        _record_approval(store)

        adj = store.get_confidence_adjustment(
            pattern_name="test_pattern",
            tool_name="Bash",
            path_prefix="src/lib",
            project_hash="abc123",
            current_decision="deny",  # Current decision is deny
            original_severity="high",
            original_confidence="heuristic",
        )
        # Even with exact match, deny should not be relaxed
        if adj is not None:
            assert adj.adjusted_decision is None

    def test_approval_ratio_enforced_at_exact_scope(self, tmp_path):
        """Even at exact scope, 90% approval ratio is required."""
        store = _make_store(tmp_path)
        _record_approval(store)
        _record_denial(store)  # 50% approval — below 90%

        adj = store.get_confidence_adjustment(
            pattern_name="test_pattern",
            tool_name="Bash",
            path_prefix="src/lib",
            project_hash="abc123",
            current_decision="ask",
            original_severity="high",
            original_confidence="heuristic",
        )
        # 2 decisions >= 1 threshold, but 50% < 90% ratio
        if adj is not None:
            assert adj.adjusted_decision is None


# ---------------------------------------------------------------------------
# compute_suggested_decision with min_threshold
# ---------------------------------------------------------------------------

class TestComputeSuggestedDecisionThreshold:
    """Test the min_threshold parameter."""

    def test_threshold_1_accepts_single_decision(self):
        result = compute_suggested_decision(
            current_decision="ask",
            approval_ratio=1.0,
            total_weighted_decisions=1.0,
            original_severity="high",
            original_confidence="heuristic",
            min_threshold=1,
        )
        assert result == "log"

    def test_threshold_3_rejects_two_decisions(self):
        result = compute_suggested_decision(
            current_decision="ask",
            approval_ratio=1.0,
            total_weighted_decisions=2.0,
            original_severity="high",
            original_confidence="heuristic",
            min_threshold=3,
        )
        assert result is None

    def test_threshold_3_accepts_three_decisions(self):
        result = compute_suggested_decision(
            current_decision="ask",
            approval_ratio=1.0,
            total_weighted_decisions=3.0,
            original_severity="high",
            original_confidence="heuristic",
            min_threshold=3,
        )
        assert result == "log"

    def test_default_threshold_is_path_scope(self):
        """Default min_threshold should be SCOPED_THRESHOLDS['path'] = 5."""
        result = compute_suggested_decision(
            current_decision="ask",
            approval_ratio=1.0,
            total_weighted_decisions=4.0,
            original_severity="high",
            original_confidence="heuristic",
            # No min_threshold — should default to 5
        )
        assert result is None  # 4 < 5

        result = compute_suggested_decision(
            current_decision="ask",
            approval_ratio=1.0,
            total_weighted_decisions=5.0,
            original_severity="high",
            original_confidence="heuristic",
        )
        assert result == "log"  # 5 >= 5
