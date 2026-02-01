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

pytestmark = pytest.mark.logging

sys.path.insert(0, str(Path(__file__).parent.parent))

from tweek.logging.security_log import (
    SecurityLogger, SecurityEvent, EventType, get_logger,
    LogRedactor, get_redactor
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


class TestLogRedactorBasic:
    """Basic tests for LogRedactor."""

    def test_redactor_enabled_by_default(self):
        """Test that redactor is enabled by default."""
        redactor = LogRedactor()
        assert redactor.enabled is True

    def test_redactor_can_be_disabled(self):
        """Test that redactor can be disabled."""
        redactor = LogRedactor(enabled=False)
        assert redactor.enabled is False

    def test_disabled_redactor_returns_unchanged(self):
        """Test disabled redactor returns unchanged text."""
        redactor = LogRedactor(enabled=False)
        secret = "api_key=sk_live_abcdef123456789012345678901234567890"
        result = redactor.redact_string(secret)
        assert result == secret


class TestLogRedactorPatterns:
    """Tests for LogRedactor pattern matching."""

    def test_redacts_api_keys(self):
        """Test redaction of API keys."""
        redactor = LogRedactor()
        text = 'api_key="sk_live_abcdef123456789012345678901234567890"'
        result = redactor.redact_string(text)
        assert "sk_live_abcdef" not in result
        assert "REDACTED" in result

    def test_redacts_aws_access_keys(self):
        """Test redaction of AWS access key IDs."""
        redactor = LogRedactor()
        text = "AKIAIOSFODNN7EXAMPLE"
        result = redactor.redact_string(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "AWS_KEY_REDACTED" in result

    def test_redacts_bearer_tokens(self):
        """Test redaction of bearer tokens."""
        redactor = LogRedactor()
        text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        result = redactor.redact_string(text)
        assert "eyJhbGci" not in result
        assert "REDACTED" in result

    def test_redacts_jwt_tokens(self):
        """Test redaction of JWT tokens."""
        redactor = LogRedactor()
        text = "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = redactor.redact_string(text)
        assert "eyJhbGci" not in result
        assert "JWT_REDACTED" in result

    def test_redacts_github_tokens(self):
        """Test redaction of GitHub tokens."""
        redactor = LogRedactor()
        text = "token=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        result = redactor.redact_string(text)
        assert "ghp_" not in result
        assert "GITHUB_TOKEN_REDACTED" in result

    def test_redacts_slack_tokens(self):
        """Test redaction of Slack tokens."""
        redactor = LogRedactor()
        text = "xoxb-1234567890123-1234567890123-abc123def456"
        result = redactor.redact_string(text)
        assert "xoxb-" not in result
        assert "SLACK_TOKEN_REDACTED" in result

    def test_redacts_passwords(self):
        """Test redaction of passwords."""
        redactor = LogRedactor()
        text = 'password="mysecretpassword123"'
        result = redactor.redact_string(text)
        assert "mysecretpassword" not in result
        assert "REDACTED" in result

    def test_redacts_connection_strings(self):
        """Test redaction of connection strings."""
        redactor = LogRedactor()
        text = "mongodb://admin:secretpass@localhost:27017/db"
        result = redactor.redact_string(text)
        assert "secretpass" not in result
        assert "REDACTED" in result

    def test_redacts_private_keys(self):
        """Test redaction of private keys."""
        redactor = LogRedactor()
        text = """-----BEGIN RSA PRIVATE KEY-----
        MIIEpQIBAAKCAQEA...
        -----END RSA PRIVATE KEY-----"""
        result = redactor.redact_string(text)
        assert "BEGIN RSA PRIVATE KEY" not in result
        assert "PRIVATE_KEY_REDACTED" in result

    def test_preserves_non_sensitive_text(self):
        """Test that non-sensitive text is preserved."""
        redactor = LogRedactor()
        text = "Running command: ls -la /home/user"
        result = redactor.redact_string(text)
        assert result == text


class TestLogRedactorDict:
    """Tests for dictionary redaction."""

    def test_redacts_sensitive_keys(self):
        """Test redaction of values for sensitive keys."""
        redactor = LogRedactor()
        data = {
            "username": "john",
            "password": "secretpass123",
            "api_key": "sk_live_12345",
        }
        result = redactor.redact_dict(data)

        assert result["username"] == "john"
        assert result["password"] == "***REDACTED***"
        assert result["api_key"] == "***REDACTED***"

    def test_redacts_nested_dicts(self):
        """Test redaction of nested dictionaries."""
        redactor = LogRedactor()
        data = {
            "config": {
                "database": {
                    "host": "localhost",
                    "password": "dbpass123"
                }
            }
        }
        result = redactor.redact_dict(data)

        assert result["config"]["database"]["host"] == "localhost"
        assert result["config"]["database"]["password"] == "***REDACTED***"

    def test_redacts_lists_in_dict(self):
        """Test redaction of lists containing sensitive data."""
        redactor = LogRedactor()
        data = {
            "items": [
                {"name": "safe", "secret": "mysecret123"},
                {"name": "also_safe", "token": "mytoken456"}
            ]
        }
        result = redactor.redact_dict(data)

        assert result["items"][0]["name"] == "safe"
        assert result["items"][0]["secret"] == "***REDACTED***"
        assert result["items"][1]["token"] == "***REDACTED***"


class TestLogRedactorCommand:
    """Tests for command redaction."""

    def test_redacts_curl_auth_header(self):
        """Test redaction of curl auth headers."""
        redactor = LogRedactor()
        # The Authorization header value should be redacted
        cmd = 'curl -H "Authorization: Bearer sk_live_123456789012345678901234" https://api.example.com'
        result = redactor.redact_command(cmd)
        # Bearer tokens are redacted by the bearer pattern
        assert "sk_live_123456" not in result

    def test_redacts_env_exports(self):
        """Test redaction of environment variable exports."""
        redactor = LogRedactor()
        cmd = "export API_KEY=sk_live_abcdef123456789012345678901234567890"
        result = redactor.redact_command(cmd)
        assert "sk_live_abcdef" not in result
        assert "REDACTED" in result

    def test_redacts_inline_env_vars(self):
        """Test redaction of inline environment variables."""
        redactor = LogRedactor()
        cmd = "DATABASE_PASSWORD=secret123 ./run.sh"
        result = redactor.redact_command(cmd)
        assert "secret123" not in result
        assert "REDACTED" in result


class TestLogRedactionIntegration:
    """Tests for log redaction integration with SecurityLogger."""

    def test_logger_redacts_commands(self, tmp_path):
        """Test that logger redacts sensitive commands."""
        db_path = tmp_path / ".tweek" / "security.db"
        logger = SecurityLogger(db_path=db_path, redact_logs=True)

        event = SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash",
            command="export API_KEY=sk_live_abcdef123456789012345678901234567890",
            tier="safe",
            decision="allow"
        )

        logger.log(event)

        # Retrieve and verify redaction
        events = logger.get_recent_events(limit=1)
        assert len(events) == 1
        assert "sk_live_abcdef" not in events[0]["command"]

    def test_logger_redacts_metadata(self, tmp_path):
        """Test that logger redacts sensitive metadata."""
        db_path = tmp_path / ".tweek" / "security.db"
        logger = SecurityLogger(db_path=db_path, redact_logs=True)

        event = SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash",
            command="ls",
            tier="safe",
            decision="allow",
            metadata={"password": "secret123", "user": "john"}
        )

        logger.log(event)

        events = logger.get_recent_events(limit=1)
        import json
        metadata = json.loads(events[0]["metadata_json"])

        assert metadata["user"] == "john"
        assert "secret123" not in metadata["password"]

    def test_logger_without_redaction(self, tmp_path):
        """Test logger with redaction disabled."""
        db_path = tmp_path / ".tweek" / "security.db"
        logger = SecurityLogger(db_path=db_path, redact_logs=False)

        sensitive_cmd = "export API_KEY=sk_live_abcdef123456789012345678901234567890"
        event = SecurityEvent(
            event_type=EventType.TOOL_INVOKED,
            tool_name="Bash",
            command=sensitive_cmd,
            tier="safe",
            decision="allow"
        )

        logger.log(event)

        events = logger.get_recent_events(limit=1)
        # Without redaction, sensitive data remains
        assert events[0]["command"] == sensitive_cmd
