#!/usr/bin/env python3
"""
Tests for Tweek rate limiter.

Tests coverage of:
- Burst detection
- Repeated command detection
- High volume detection
- Dangerous tier spike detection
- Velocity anomaly detection
"""

import pytest
import sys
import tempfile
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tweek.security.rate_limiter import (
    RateLimiter,
    RateLimitConfig,
    RateLimitResult,
    RateLimitViolation
)


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        yield Path(f.name)


@pytest.fixture
def mock_logger(temp_db):
    """Create a mock logger with a real database."""
    from tweek.logging.security_log import SecurityLogger
    logger = SecurityLogger(db_path=temp_db)
    return logger


@pytest.fixture
def rate_limiter(mock_logger):
    """Create a RateLimiter instance with mock logger."""
    config = RateLimitConfig(
        burst_window=5,
        burst_threshold=5,  # Lower for testing
        max_per_minute=20,
        max_dangerous_per_minute=5,
        max_same_command=3,
        velocity_multiplier=2.0
    )
    return RateLimiter(config=config, logger=mock_logger)


class TestRateLimitConfig:
    """Tests for RateLimitConfig defaults."""

    def test_default_config(self):
        """Test default configuration values."""
        config = RateLimitConfig()
        assert config.burst_window == 5
        assert config.burst_threshold == 15
        assert config.max_per_minute == 60
        assert config.max_dangerous_per_minute == 10

    def test_custom_config(self):
        """Test custom configuration values."""
        config = RateLimitConfig(
            burst_threshold=10,
            max_per_minute=30
        )
        assert config.burst_threshold == 10
        assert config.max_per_minute == 30


class TestRateLimitResult:
    """Tests for RateLimitResult."""

    def test_allowed_result(self):
        """Test result when allowed."""
        result = RateLimitResult(allowed=True)
        assert result.allowed
        assert not result.is_burst
        assert not result.is_repeated

    def test_burst_violation(self):
        """Test result with burst violation."""
        result = RateLimitResult(
            allowed=False,
            violations=[RateLimitViolation.BURST]
        )
        assert not result.allowed
        assert result.is_burst
        assert not result.is_repeated

    def test_multiple_violations(self):
        """Test result with multiple violations."""
        result = RateLimitResult(
            allowed=False,
            violations=[
                RateLimitViolation.BURST,
                RateLimitViolation.REPEATED_COMMAND
            ]
        )
        assert result.is_burst
        assert result.is_repeated


class TestRateLimiterBasic:
    """Basic rate limiter tests."""

    def test_no_session_id(self, rate_limiter):
        """Test behavior with no session ID."""
        result = rate_limiter.check(
            tool_name="Bash",
            command="ls -la",
            session_id=None
        )
        assert result.allowed
        assert "No session ID" in result.message

    def test_first_command(self, rate_limiter):
        """Test first command is allowed."""
        result = rate_limiter.check(
            tool_name="Bash",
            command="ls -la",
            session_id="test-session-123"
        )
        assert result.allowed

    def test_normal_usage(self, rate_limiter, mock_logger):
        """Test normal usage pattern is allowed."""
        session_id = "test-normal-session"

        # Simulate a few normal commands
        for i in range(3):
            from tweek.logging.security_log import EventType
            mock_logger.log_quick(
                EventType.TOOL_INVOKED,
                "Bash",
                command=f"echo {i}",
                session_id=session_id
            )

        result = rate_limiter.check(
            tool_name="Bash",
            command="echo test",
            session_id=session_id
        )
        assert result.allowed


class TestBurstDetection:
    """Tests for burst detection."""

    def test_burst_detection(self, rate_limiter, mock_logger):
        """Test that burst patterns are detected."""
        session_id = "test-burst-session"
        from tweek.logging.security_log import EventType

        # Log many events quickly (simulating burst)
        for i in range(10):
            mock_logger.log_quick(
                EventType.TOOL_INVOKED,
                "Bash",
                command=f"echo {i}",
                session_id=session_id
            )

        result = rate_limiter.check(
            tool_name="Bash",
            command="echo burst",
            session_id=session_id
        )

        # Should detect burst (threshold is 5 in test config)
        assert RateLimitViolation.BURST in result.violations or \
               RateLimitViolation.HIGH_VOLUME in result.violations


class TestRepeatedCommandDetection:
    """Tests for repeated command detection."""

    def test_repeated_command_detection(self, rate_limiter, mock_logger):
        """Test that repeated identical commands are detected."""
        session_id = "test-repeat-session"
        from tweek.logging.security_log import EventType

        repeated_cmd = "cat ~/.ssh/id_rsa"

        # Log same command multiple times
        for _ in range(5):
            mock_logger.log_quick(
                EventType.TOOL_INVOKED,
                "Bash",
                command=repeated_cmd,
                session_id=session_id
            )

        result = rate_limiter.check(
            tool_name="Bash",
            command=repeated_cmd,
            session_id=session_id
        )

        # Should detect repetition (threshold is 3 in test config)
        assert RateLimitViolation.REPEATED_COMMAND in result.violations


class TestDangerousSpikeDetection:
    """Tests for dangerous tier spike detection."""

    def test_dangerous_spike(self, rate_limiter, mock_logger):
        """Test that spike in dangerous commands is detected."""
        session_id = "test-dangerous-session"
        from tweek.logging.security_log import EventType

        # Log many dangerous tier events
        for i in range(10):
            mock_logger.log_quick(
                EventType.TOOL_INVOKED,
                "Bash",
                command=f"sudo rm -rf {i}",
                tier="dangerous",
                session_id=session_id
            )

        result = rate_limiter.check(
            tool_name="Bash",
            command="sudo command",
            session_id=session_id,
            tier="dangerous"
        )

        # Should detect dangerous spike (threshold is 5 in test config)
        assert RateLimitViolation.DANGEROUS_SPIKE in result.violations


class TestSessionStats:
    """Tests for session statistics."""

    def test_session_stats(self, rate_limiter, mock_logger):
        """Test session statistics retrieval."""
        session_id = "test-stats-session"
        from tweek.logging.security_log import EventType

        # Log some events
        for tier in ["safe", "default", "dangerous"]:
            mock_logger.log_quick(
                EventType.TOOL_INVOKED,
                "Bash",
                command=f"echo {tier}",
                tier=tier,
                session_id=session_id
            )

        stats = rate_limiter.get_session_stats(session_id)

        assert "session_id" in stats
        assert "by_tier" in stats
        assert "current_velocity_per_min" in stats


class TestViolationMessage:
    """Tests for violation message formatting."""

    def test_format_burst_message(self, rate_limiter):
        """Test formatting of burst violation message."""
        result = RateLimitResult(
            allowed=False,
            violations=[RateLimitViolation.BURST],
            details={"burst_count": 20}
        )
        message = rate_limiter.format_violation_message(result)
        assert "Burst detected" in message
        assert "20" in message

    def test_format_repeated_message(self, rate_limiter):
        """Test formatting of repeated command message."""
        result = RateLimitResult(
            allowed=False,
            violations=[RateLimitViolation.REPEATED_COMMAND],
            details={"same_command_count": 10}
        )
        message = rate_limiter.format_violation_message(result)
        assert "Repeated command" in message

    def test_format_allowed_message(self, rate_limiter):
        """Test no message for allowed result."""
        result = RateLimitResult(allowed=True)
        message = rate_limiter.format_violation_message(result)
        assert message == ""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
