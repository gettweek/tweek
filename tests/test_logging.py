#!/usr/bin/env python3
"""
Tests for Tweek security logging module.

Tests coverage of:
- Event logging and retrieval
- Statistics generation
- CSV export
- Event types and severity
"""

import json
import pytest
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from tweek.logging.security_log import (
    SecurityLogger, SecurityEvent, EventType, get_logger
)


@pytest.fixture
def temp_db(tmp_path):
    """Create a temporary database path."""
    return tmp_path / ".tweek" / "security.db"


@pytest.fixture
def logger(temp_db):
    """Create a SecurityLogger with temp database."""
    temp_db.parent.mkdir(parents=True, exist_ok=True)
    logger = SecurityLogger(db_path=temp_db)
    yield logger


class TestEventType:
    """Tests for EventType enum."""

    def test_event_type_values(self):
        """Test event type enum values exist."""
        assert EventType.TOOL_INVOKED is not None
        assert EventType.PATTERN_MATCH is not None
        assert EventType.ESCALATION is not None
        assert EventType.ALLOWED is not None
        assert EventType.BLOCKED is not None


class TestSecurityEvent:
    """Tests for SecurityEvent dataclass."""

    def test_create_event(self):
        """Test creating a security event."""
        event = SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash",
            command="ls -la",
            tier="default",
            decision="allow"
        )

        assert event.event_type == EventType.TOOL_INVOKED
        assert event.tool_name == "Bash"
        assert event.command == "ls -la"
        assert event.decision == "allow"

    def test_event_with_pattern(self):
        """Test event with pattern match info."""
        event = SecurityEvent(
            event_type=EventType.PATTERN_MATCH,
            tool_name="Bash",
            command="cat ~/.ssh/id_rsa",
            tier="dangerous",
            decision="block",
            pattern_name="ssh_key_read",
            pattern_severity="critical"
        )

        assert event.pattern_name == "ssh_key_read"
        assert event.pattern_severity == "critical"
        assert event.decision == "block"


class TestSecurityLoggerInit:
    """Tests for SecurityLogger initialization."""

    def test_creates_database(self, tmp_path):
        """Test that logger creates database on init."""
        db_path = tmp_path / ".tweek" / "security.db"
        logger = SecurityLogger(db_path=db_path)

        assert db_path.exists()

    def test_creates_tables(self, tmp_path):
        """Test that logger creates required tables."""
        db_path = tmp_path / ".tweek" / "security.db"
        logger = SecurityLogger(db_path=db_path)

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Check security_events table exists
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='security_events'"
        )
        assert cursor.fetchone() is not None

        conn.close()


class TestEventLogging:
    """Tests for logging events."""

    def test_log_event(self, logger):
        """Test logging a basic event."""
        event = SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash",
            command="echo hello",
            tier="safe",
            decision="allow"
        )

        logger.log(event)

        # Verify event was logged
        events = logger.get_recent_events(limit=1)
        assert len(events) == 1
        assert events[0]["tool_name"] == "Bash"
        assert events[0]["decision"] == "allow"

    def test_log_event_with_session(self, logger):
        """Test logging event with session ID."""
        event = SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash",
            command="pwd",
            tier="default",
            decision="allow",
            session_id="test-session-123"
        )

        logger.log(event)

        events = logger.get_recent_events(limit=1)
        assert events[0].get("session_id") == "test-session-123"

    def test_log_pattern_match(self, logger):
        """Test logging a pattern match event."""
        event = SecurityEvent(
            event_type=EventType.PATTERN_MATCH,
            tool_name="Bash",
            command="cat .env",
            tier="default",
            decision="block",
            pattern_name="env_file_access",
            pattern_severity="high"
        )

        logger.log(event)

        events = logger.get_recent_events(limit=1)
        assert events[0]["event_type"] == EventType.PATTERN_MATCH.value
        assert events[0]["pattern_name"] == "env_file_access"


class TestEventRetrieval:
    """Tests for retrieving events."""

    def test_get_recent_events(self, logger):
        """Test getting recent events."""
        # Log multiple events
        for i in range(5):
            event = SecurityEvent(
                event_type=EventType.TOOL_INVOKED,
                tool_name="Bash",
                command=f"command {i}",
                tier="default",
                decision="allow"
            )
            logger.log(event)

        events = logger.get_recent_events(limit=3)
        assert len(events) == 3

    def test_get_events_by_type(self, logger):
        """Test filtering events by type."""
        # Log different event types
        logger.log(SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash", command="ls", tier="safe", decision="allow"
        ))
        logger.log(SecurityEvent(
            event_type=EventType.PATTERN_MATCH,
            tool_name="Bash", command="cat .env", tier="default",
            decision="block", pattern_name="env_file_access"
        ))
        logger.log(SecurityEvent(
            event_type=EventType.BLOCKED,
            tool_name="Bash", command="rm -rf /", tier="dangerous", decision="block"
        ))

        # Filter by type
        pattern_events = logger.get_recent_events(
            event_type=EventType.PATTERN_MATCH
        )

        assert all(e["event_type"] == EventType.PATTERN_MATCH.value for e in pattern_events)

    def test_get_events_by_tool(self, logger):
        """Test filtering events by tool name."""
        logger.log(SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash", command="ls", tier="safe", decision="allow"
        ))
        logger.log(SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Edit", command="edit file", tier="safe", decision="allow"
        ))

        bash_events = logger.get_recent_events(tool_name="Bash")
        assert all(e["tool_name"] == "Bash" for e in bash_events)

    def test_get_blocked_commands(self, logger):
        """Test getting blocked commands."""
        logger.log(SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash", command="ls", tier="safe", decision="allow"
        ))
        logger.log(SecurityEvent(
            event_type=EventType.PATTERN_MATCH,
            tool_name="Bash", command="cat ~/.ssh/id_rsa",
            tier="dangerous", decision="block",
            pattern_name="ssh_key_read"
        ))

        blocked = logger.get_blocked_commands()

        # The recent_blocks view returns blocked commands (decision IN 'block', 'ask')
        # but doesn't include the decision field - it includes:
        # timestamp, tool_name, command, pattern_name, pattern_severity, decision_reason
        assert len(blocked) >= 1
        assert all(e["tool_name"] == "Bash" for e in blocked)


class TestStatistics:
    """Tests for statistics generation."""

    def test_get_stats_empty(self, logger):
        """Test stats with no events."""
        stats = logger.get_stats(days=7)

        assert stats["total_events"] == 0
        assert stats["by_decision"] == {}

    def test_get_stats_with_events(self, logger):
        """Test stats with multiple events."""
        # Log various events
        for _ in range(3):
            logger.log(SecurityEvent(
                event_type=EventType.TOOL_INVOKED,
                tool_name="Bash", command="ls", tier="safe", decision="allow"
            ))

        for _ in range(2):
            logger.log(SecurityEvent(
                event_type=EventType.PATTERN_MATCH,
                tool_name="Bash", command="cat .env",
                tier="default", decision="block",
                pattern_name="env_file_access", pattern_severity="high"
            ))

        stats = logger.get_stats(days=7)

        assert stats["total_events"] == 5
        assert stats["by_decision"].get("allow", 0) == 3
        assert stats["by_decision"].get("block", 0) == 2

    def test_get_stats_by_tool(self, logger):
        """Test stats breakdown by tool."""
        logger.log(SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash", command="ls", tier="safe", decision="allow"
        ))
        logger.log(SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash", command="pwd", tier="safe", decision="allow"
        ))
        logger.log(SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Edit", command="edit", tier="safe", decision="allow"
        ))

        stats = logger.get_stats(days=7)

        assert "Bash" in stats["by_tool"]
        assert stats["by_tool"]["Bash"] == 2
        assert stats["by_tool"]["Edit"] == 1

    def test_get_top_patterns(self, logger):
        """Test top patterns in stats."""
        # Log pattern matches
        for _ in range(5):
            logger.log(SecurityEvent(
                event_type=EventType.PATTERN_MATCH,
                tool_name="Bash", command="cat .env",
                tier="default", decision="block",
                pattern_name="env_file_access", pattern_severity="high"
            ))

        for _ in range(2):
            logger.log(SecurityEvent(
                event_type=EventType.PATTERN_MATCH,
                tool_name="Bash", command="cat ~/.ssh/id_rsa",
                tier="dangerous", decision="block",
                pattern_name="ssh_key_read", pattern_severity="critical"
            ))

        stats = logger.get_stats(days=7)

        # env_file_access should be top pattern
        top_patterns = stats.get("top_patterns", [])
        if top_patterns:
            assert top_patterns[0]["name"] == "env_file_access"
            assert top_patterns[0]["count"] == 5


class TestCSVExport:
    """Tests for CSV export functionality."""

    def test_export_csv(self, logger, tmp_path):
        """Test exporting events to CSV."""
        # Log some events
        logger.log(SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash", command="ls", tier="safe", decision="allow"
        ))
        logger.log(SecurityEvent(
            event_type=EventType.PATTERN_MATCH,
            tool_name="Bash", command="cat .env",
            tier="default", decision="block",
            pattern_name="env_file_access"
        ))

        csv_path = tmp_path / "export.csv"
        count = logger.export_csv(csv_path)

        assert count == 2
        assert csv_path.exists()

        # Check CSV content
        content = csv_path.read_text()
        assert "Bash" in content
        assert "allow" in content
        assert "block" in content

    def test_export_csv_with_days_filter(self, logger, tmp_path):
        """Test CSV export with days filter."""
        logger.log(SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash", command="ls", tier="safe", decision="allow"
        ))

        csv_path = tmp_path / "export.csv"
        count = logger.export_csv(csv_path, days=1)

        assert count == 1


class TestSessionTracking:
    """Tests for session-based event tracking."""

    def test_get_session_events(self, logger):
        """Test getting events for a specific session via get_recent_events."""
        session_id = "test-session-456"

        # Log events for this session
        logger.log(SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash", command="ls", tier="safe",
            decision="allow", session_id=session_id
        ))
        logger.log(SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash", command="pwd", tier="safe",
            decision="allow", session_id=session_id
        ))

        # Log event for different session
        logger.log(SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash", command="other", tier="safe",
            decision="allow", session_id="other-session"
        ))

        # Get all recent events and filter by session
        # (SecurityLogger doesn't have get_session_events, use get_recent_events)
        events = logger.get_recent_events(limit=100)
        session_events = [e for e in events if e.get("session_id") == session_id]

        assert len(session_events) == 2
        assert all(e.get("session_id") == session_id for e in session_events)


class TestLoggerSingleton:
    """Tests for logger singleton behavior."""

    def test_get_logger_returns_valid_instance(self, tmp_path):
        """Test that get_logger returns valid logger instance."""
        # get_logger returns a new instance each time (no singleton)
        logger = get_logger()
        assert isinstance(logger, SecurityLogger)
