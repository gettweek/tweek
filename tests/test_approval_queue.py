#!/usr/bin/env python3
"""
Tests for tweek.mcp.approval module.

Tests the SQLite-backed approval queue:
- Enqueue and retrieval
- Decision recording
- Stale request expiry
- Cleanup of old requests
- Edge cases (duplicates, non-existent, already decided)
"""

import json
import sqlite3
import time
from pathlib import Path
from unittest.mock import patch

import pytest

pytestmark = pytest.mark.core

from tweek.mcp.approval import (
    ApprovalQueue,
    ApprovalRequest,
    ApprovalStatus,
)


@pytest.fixture
def db_path(tmp_path):
    """Temporary database path."""
    return tmp_path / "test_approvals.db"


@pytest.fixture
def queue(db_path):
    """Create an ApprovalQueue with a temp database."""
    return ApprovalQueue(db_path=db_path, default_timeout=300)


class TestApprovalRequest:
    """Tests for ApprovalRequest dataclass."""

    def test_basic_properties(self):
        req = ApprovalRequest(
            id="abc-123",
            timestamp="2026-01-29 12:00:00",
            upstream_server="filesystem",
            tool_name="read_file",
            arguments_json='{"path": "/tmp/foo"}',
            screening_reason="Pattern match",
            screening_findings_json='[{"name": "ssh_key"}]',
            risk_level="risky",
            status=ApprovalStatus.PENDING,
            decided_at=None,
            decided_by=None,
            decision_notes=None,
            timeout_seconds=300,
        )
        assert req.short_id == "abc-123"
        assert req.upstream_server == "filesystem"
        assert req.status == ApprovalStatus.PENDING

    def test_arguments_parsing(self):
        req = ApprovalRequest(
            id="test",
            timestamp="2026-01-29 12:00:00",
            upstream_server="fs",
            tool_name="read",
            arguments_json='{"path": "/tmp/foo"}',
            screening_reason="",
            screening_findings_json="[]",
            risk_level="safe",
            status=ApprovalStatus.PENDING,
            decided_at=None,
            decided_by=None,
            decision_notes=None,
            timeout_seconds=60,
        )
        assert req.arguments == {"path": "/tmp/foo"}
        assert req.screening_findings == []

    def test_invalid_json(self):
        req = ApprovalRequest(
            id="test",
            timestamp="2026-01-29 12:00:00",
            upstream_server="fs",
            tool_name="read",
            arguments_json="{invalid",
            screening_reason="",
            screening_findings_json="{invalid",
            risk_level="safe",
            status=ApprovalStatus.PENDING,
            decided_at=None,
            decided_by=None,
            decision_notes=None,
            timeout_seconds=60,
        )
        assert req.arguments == {}
        assert req.screening_findings == []

    def test_short_id(self):
        req = ApprovalRequest(
            id="abcdefgh-1234-5678-9012-ijklmnopqrst",
            timestamp="2026-01-29 12:00:00",
            upstream_server="fs",
            tool_name="read",
            arguments_json="{}",
            screening_reason="",
            screening_findings_json="[]",
            risk_level="safe",
            status=ApprovalStatus.PENDING,
            decided_at=None,
            decided_by=None,
            decision_notes=None,
            timeout_seconds=60,
        )
        assert req.short_id == "abcdefgh"


class TestApprovalQueue:
    """Tests for ApprovalQueue."""

    def test_db_creation(self, db_path, queue):
        """Queue creates database and tables on init."""
        assert db_path.exists()

    def test_enqueue_returns_uuid(self, queue):
        request_id = queue.enqueue(
            upstream_server="filesystem",
            tool_name="read_file",
            arguments={"path": "/tmp/foo"},
            screening_reason="Test reason",
            screening_findings=[],
            risk_level="default",
        )
        assert request_id is not None
        assert len(request_id) == 36  # UUID format

    def test_get_pending(self, queue):
        queue.enqueue(
            upstream_server="filesystem",
            tool_name="read_file",
            arguments={"path": "/tmp/foo"},
            screening_reason="Reason 1",
            screening_findings=[],
        )
        queue.enqueue(
            upstream_server="github",
            tool_name="create_pr",
            arguments={"title": "Test"},
            screening_reason="Reason 2",
            screening_findings=[],
        )

        pending = queue.get_pending()
        assert len(pending) == 2
        assert pending[0].upstream_server == "filesystem"
        assert pending[1].upstream_server == "github"

    def test_get_pending_ordering(self, queue):
        """Requests are ordered by timestamp (earliest first)."""
        id1 = queue.enqueue(
            upstream_server="first",
            tool_name="tool1",
            arguments={},
            screening_reason="",
            screening_findings=[],
        )
        id2 = queue.enqueue(
            upstream_server="second",
            tool_name="tool2",
            arguments={},
            screening_reason="",
            screening_findings=[],
        )

        pending = queue.get_pending()
        assert len(pending) == 2
        assert pending[0].upstream_server == "first"

    def test_get_request_by_id(self, queue):
        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="read",
            arguments={},
            screening_reason="test",
            screening_findings=[],
        )

        req = queue.get_request(request_id)
        assert req is not None
        assert req.id == request_id
        assert req.upstream_server == "fs"
        assert req.tool_name == "read"
        assert req.status == ApprovalStatus.PENDING

    def test_get_request_by_short_id(self, queue):
        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="read",
            arguments={},
            screening_reason="test",
            screening_findings=[],
        )

        short_id = request_id[:8]
        req = queue.get_request(short_id)
        assert req is not None
        assert req.id == request_id

    def test_get_nonexistent_request(self, queue):
        req = queue.get_request("nonexistent-id")
        assert req is None

    def test_decide_approve(self, queue):
        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="write",
            arguments={},
            screening_reason="test",
            screening_findings=[],
        )

        success = queue.decide(request_id, ApprovalStatus.APPROVED, decided_by="cli")
        assert success is True

        req = queue.get_request(request_id)
        assert req.status == ApprovalStatus.APPROVED
        assert req.decided_by == "cli"
        assert req.decided_at is not None

    def test_decide_deny(self, queue):
        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="write",
            arguments={},
            screening_reason="test",
            screening_findings=[],
        )

        success = queue.decide(
            request_id,
            ApprovalStatus.DENIED,
            decided_by="cli",
            notes="Not authorized",
        )
        assert success is True

        req = queue.get_request(request_id)
        assert req.status == ApprovalStatus.DENIED
        assert req.decision_notes == "Not authorized"

    def test_decide_nonexistent(self, queue):
        success = queue.decide("nonexistent", ApprovalStatus.APPROVED)
        assert success is False

    def test_decide_already_decided(self, queue):
        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="write",
            arguments={},
            screening_reason="test",
            screening_findings=[],
        )

        # First decision succeeds
        queue.decide(request_id, ApprovalStatus.APPROVED)

        # Second decision fails (not pending anymore)
        success = queue.decide(request_id, ApprovalStatus.DENIED)
        assert success is False

    def test_get_decision(self, queue):
        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="read",
            arguments={},
            screening_reason="test",
            screening_findings=[],
        )

        # Initially pending
        assert queue.get_decision(request_id) == ApprovalStatus.PENDING

        # After approval
        queue.decide(request_id, ApprovalStatus.APPROVED)
        assert queue.get_decision(request_id) == ApprovalStatus.APPROVED

    def test_get_decision_nonexistent(self, queue):
        assert queue.get_decision("nonexistent") is None

    def test_count_pending(self, queue):
        assert queue.count_pending() == 0

        queue.enqueue(
            upstream_server="fs",
            tool_name="read",
            arguments={},
            screening_reason="",
            screening_findings=[],
        )
        assert queue.count_pending() == 1

        queue.enqueue(
            upstream_server="fs",
            tool_name="write",
            arguments={},
            screening_reason="",
            screening_findings=[],
        )
        assert queue.count_pending() == 2

    def test_get_stats(self, queue):
        id1 = queue.enqueue(
            upstream_server="fs",
            tool_name="read",
            arguments={},
            screening_reason="",
            screening_findings=[],
        )
        queue.enqueue(
            upstream_server="fs",
            tool_name="write",
            arguments={},
            screening_reason="",
            screening_findings=[],
        )

        queue.decide(id1, ApprovalStatus.APPROVED)

        stats = queue.get_stats()
        assert stats.get("approved") == 1
        assert stats.get("pending") == 1

    def test_custom_timeout(self, queue):
        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="read",
            arguments={},
            screening_reason="",
            screening_findings=[],
            timeout_seconds=60,
        )

        req = queue.get_request(request_id)
        assert req.timeout_seconds == 60

    def test_decide_with_invalid_status(self, queue):
        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="read",
            arguments={},
            screening_reason="",
            screening_findings=[],
        )

        with pytest.raises(ValueError, match="Invalid decision status"):
            queue.decide(request_id, ApprovalStatus.PENDING)

    def test_arguments_stored_as_json(self, queue):
        args = {"path": "/tmp/test", "content": "hello world", "nested": {"key": "val"}}
        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="write",
            arguments=args,
            screening_reason="test",
            screening_findings=[{"name": "pattern_1"}],
        )

        req = queue.get_request(request_id)
        # Arguments may have redacted sensitive fields
        assert isinstance(req.arguments, dict)
        assert isinstance(req.screening_findings, list)

    def test_findings_stored_as_json(self, queue):
        findings = [
            {"name": "ssh_key", "severity": "critical"},
            {"name": "eval_usage", "severity": "high"},
        ]
        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="read",
            arguments={},
            screening_reason="test",
            screening_findings=findings,
        )

        req = queue.get_request(request_id)
        assert len(req.screening_findings) == 2
        assert req.screening_findings[0]["name"] == "ssh_key"


class TestExpiryAndCleanup:
    """Tests for expire_stale() and cleanup()."""

    def test_expire_stale_with_zero_timeout(self, db_path):
        """Requests with 0 timeout should expire immediately."""
        queue = ApprovalQueue(db_path=db_path, default_timeout=0)

        queue.enqueue(
            upstream_server="fs",
            tool_name="read",
            arguments={},
            screening_reason="test",
            screening_findings=[],
            timeout_seconds=0,
        )

        # Small delay to ensure timestamp difference
        time.sleep(0.1)

        expired_count = queue.expire_stale()
        assert expired_count == 1

        pending = queue.get_pending()
        assert len(pending) == 0

    def test_expire_stale_preserves_non_expired(self, queue):
        """Requests within timeout should not be expired."""
        queue.enqueue(
            upstream_server="fs",
            tool_name="read",
            arguments={},
            screening_reason="test",
            screening_findings=[],
            timeout_seconds=3600,  # 1 hour
        )

        expired_count = queue.expire_stale()
        assert expired_count == 0

        pending = queue.get_pending()
        assert len(pending) == 1

    def test_expired_status(self, db_path):
        queue = ApprovalQueue(db_path=db_path, default_timeout=0)

        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="read",
            arguments={},
            screening_reason="test",
            screening_findings=[],
            timeout_seconds=0,
        )

        time.sleep(0.1)
        queue.expire_stale()

        req = queue.get_request(request_id)
        assert req.status == ApprovalStatus.EXPIRED
        assert req.decided_by == "timeout"

    def test_cleanup_removes_old_decided(self, queue):
        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="read",
            arguments={},
            screening_reason="test",
            screening_findings=[],
        )
        queue.decide(request_id, ApprovalStatus.APPROVED)

        # Cleanup with 0 days should remove everything decided
        deleted = queue.cleanup(days=0)
        assert deleted == 1

    def test_cleanup_preserves_pending(self, queue):
        queue.enqueue(
            upstream_server="fs",
            tool_name="read",
            arguments={},
            screening_reason="test",
            screening_findings=[],
        )

        # Cleanup should not touch pending requests
        deleted = queue.cleanup(days=0)
        assert deleted == 0
        assert queue.count_pending() == 1


class TestRedaction:
    """Tests for argument redaction in the queue."""

    def test_redaction_on_enqueue(self, queue):
        """Sensitive arguments should be redacted before storage."""
        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="write",
            arguments={
                "path": "/tmp/config",
                "content": "safe content",
                "password": "super_secret_123",
            },
            screening_reason="test",
            screening_findings=[],
        )

        req = queue.get_request(request_id)
        args = req.arguments
        # The LogRedactor should redact the password value
        assert args.get("path") == "/tmp/config"
        # Password should be redacted (contains "password" key)
        assert "super_secret" not in str(args.get("password", ""))
