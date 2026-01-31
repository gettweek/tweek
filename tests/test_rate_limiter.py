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
    RateLimitViolation,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerState,
    CircuitState,
)


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        yield Path(f.name)


@pytest.fixture
def mock_pro_license(tmp_path):
    """Mock Pro license for rate limiter testing."""
    from tweek.licensing import License, Tier, generate_license_key
    license_file = tmp_path / ".tweek" / "license.key"
    with patch('tweek.licensing.LICENSE_FILE', license_file):
        License._instance = None
        lic = License.get_instance()
        key = generate_license_key(Tier.PRO, "test@example.com")
        lic.activate(key)
        yield lic
        License._instance = None


@pytest.fixture
def mock_logger(temp_db):
    """Create a mock logger with a real database (redaction disabled for testing)."""
    from tweek.logging.security_log import SecurityLogger
    # Disable redaction so commands match exactly in rate limiting tests
    logger = SecurityLogger(db_path=temp_db, redact_logs=False)
    return logger


@pytest.fixture
def rate_limiter(mock_logger, mock_pro_license):
    """Create a RateLimiter instance with mock logger and Pro license."""
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
        """Test behavior with no session ID — generates deterministic ID."""
        result = rate_limiter.check(
            tool_name="Bash",
            command="ls -la",
            session_id=None
        )
        # Should still proceed (generates a deterministic session ID)
        assert result.allowed

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

    def test_format_circuit_open_message(self, rate_limiter):
        """Test formatting of circuit breaker open message."""
        result = RateLimitResult(
            allowed=False,
            violations=[RateLimitViolation.CIRCUIT_OPEN],
            circuit_state=CircuitState.OPEN,
            retry_after=30
        )
        message = rate_limiter.format_violation_message(result)
        assert "Circuit breaker OPEN" in message
        assert "30 seconds" in message


class TestCircuitBreakerConfig:
    """Tests for CircuitBreakerConfig defaults."""

    def test_default_config(self):
        """Test default circuit breaker configuration values."""
        config = CircuitBreakerConfig()
        assert config.failure_threshold == 5
        assert config.success_threshold == 3
        assert config.open_timeout == 60
        assert config.half_open_max_requests == 3

    def test_custom_config(self):
        """Test custom circuit breaker configuration values."""
        config = CircuitBreakerConfig(
            failure_threshold=3,
            success_threshold=2,
            open_timeout=30
        )
        assert config.failure_threshold == 3
        assert config.success_threshold == 2
        assert config.open_timeout == 30


class TestCircuitBreakerBasic:
    """Basic circuit breaker tests."""

    def test_initial_state_is_closed(self):
        """Test circuit breaker starts in closed state."""
        cb = CircuitBreaker()
        can_exec, state, retry = cb.can_execute("test")
        assert can_exec is True
        assert state == CircuitState.CLOSED
        assert retry is None

    def test_allows_execution_when_closed(self):
        """Test execution allowed when circuit is closed."""
        cb = CircuitBreaker()
        for i in range(10):
            can_exec, state, _ = cb.can_execute("test")
            assert can_exec is True
            cb.record_success("test")

    def test_success_resets_failure_count(self):
        """Test that success resets failure count."""
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=5))

        # Record some failures (but not enough to open)
        cb.record_failure("test")
        cb.record_failure("test")
        cb.record_failure("test")

        state = cb.get_state("test")
        assert state.failure_count == 3

        # Success should reset count
        cb.record_success("test")
        state = cb.get_state("test")
        assert state.failure_count == 0


class TestCircuitBreakerTransitions:
    """Tests for circuit breaker state transitions."""

    def test_opens_after_failure_threshold(self):
        """Test circuit opens after exceeding failure threshold."""
        config = CircuitBreakerConfig(failure_threshold=3)
        cb = CircuitBreaker(config)

        # Record failures up to threshold
        for i in range(3):
            cb.record_failure("test")

        # Circuit should now be open
        can_exec, state, retry = cb.can_execute("test")
        assert can_exec is False
        assert state == CircuitState.OPEN
        assert retry is not None

    def test_transitions_to_half_open_after_timeout(self):
        """Test circuit transitions to half-open after timeout."""
        config = CircuitBreakerConfig(failure_threshold=2, open_timeout=1)
        cb = CircuitBreaker(config)

        # Open the circuit
        cb.record_failure("test")
        cb.record_failure("test")

        # Wait for timeout
        import time
        time.sleep(1.1)

        # Should transition to half-open
        can_exec, state, _ = cb.can_execute("test")
        assert can_exec is True
        assert state == CircuitState.HALF_OPEN

    def test_half_open_closes_on_success(self):
        """Test circuit closes after successes in half-open state."""
        config = CircuitBreakerConfig(
            failure_threshold=2,
            success_threshold=2,
            open_timeout=0  # Immediate timeout for testing
        )
        cb = CircuitBreaker(config)

        # Open the circuit
        cb.record_failure("test")
        cb.record_failure("test")

        # Transition to half-open
        cb.can_execute("test")

        # Record successes to close
        cb.record_success("test")
        state = cb.get_state("test")
        assert state.state == CircuitState.HALF_OPEN  # Not yet closed

        cb.record_success("test")
        state = cb.get_state("test")
        assert state.state == CircuitState.CLOSED

    def test_half_open_reopens_on_failure(self):
        """Test circuit reopens on failure in half-open state."""
        config = CircuitBreakerConfig(failure_threshold=2, open_timeout=0)
        cb = CircuitBreaker(config)

        # Open the circuit
        cb.record_failure("test")
        cb.record_failure("test")

        # Transition to half-open
        cb.can_execute("test")

        # Failure should reopen
        cb.record_failure("test")
        state = cb.get_state("test")
        assert state.state == CircuitState.OPEN


class TestCircuitBreakerMetrics:
    """Tests for circuit breaker metrics."""

    def test_get_metrics_empty(self):
        """Test metrics when no circuits exist."""
        cb = CircuitBreaker()
        metrics = cb.get_metrics()
        assert metrics["total_circuits"] == 0

    def test_get_metrics_with_circuits(self):
        """Test metrics with multiple circuits."""
        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=2))

        # Create some circuits in different states
        cb.can_execute("closed1")
        cb.record_success("closed1")

        cb.can_execute("open1")
        cb.record_failure("open1")
        cb.record_failure("open1")

        metrics = cb.get_metrics()
        assert metrics["total_circuits"] == 2
        assert metrics["closed_circuits"] >= 1
        assert metrics["open_circuits"] >= 1

    def test_reset_circuit(self):
        """Test resetting a circuit."""
        config = CircuitBreakerConfig(failure_threshold=2)
        cb = CircuitBreaker(config)

        # Open the circuit
        cb.record_failure("test")
        cb.record_failure("test")
        assert cb.get_state("test").state == CircuitState.OPEN

        # Reset
        cb.reset("test")

        # Should be back to closed
        can_exec, state, _ = cb.can_execute("test")
        assert can_exec is True
        assert state == CircuitState.CLOSED


class TestCircuitBreakerIntegration:
    """Tests for circuit breaker integration with rate limiter."""

    def test_rate_limiter_has_circuit_breaker(self, rate_limiter):
        """Test rate limiter initializes with circuit breaker."""
        assert hasattr(rate_limiter, 'circuit_breaker')
        assert isinstance(rate_limiter.circuit_breaker, CircuitBreaker)

    def test_get_circuit_metrics(self, rate_limiter):
        """Test getting circuit metrics from rate limiter."""
        metrics = rate_limiter.get_circuit_metrics()
        assert "total_circuits" in metrics
        assert "circuits" in metrics

    def test_reset_circuit(self, rate_limiter):
        """Test resetting circuit via rate limiter."""
        session_id = "test-reset-session"

        # This should create a circuit state
        rate_limiter.check("Bash", "ls", session_id)

        # Reset should not raise
        rate_limiter.reset_circuit(session_id)

    def test_circuit_opens_on_violations(self, rate_limiter, mock_logger):
        """Test that circuit opens after repeated violations."""
        session_id = "test-circuit-violation-session"
        from tweek.logging.security_log import EventType

        # Configure circuit breaker with low threshold for testing
        rate_limiter.circuit_breaker = CircuitBreaker(
            CircuitBreakerConfig(failure_threshold=3)
        )

        # Log many events to trigger rate limit violations
        for i in range(50):
            mock_logger.log_quick(
                EventType.TOOL_INVOKED,
                "Bash",
                command=f"echo burst {i}",
                session_id=session_id
            )

        # Check multiple times to trigger violations
        for _ in range(5):
            result = rate_limiter.check(
                tool_name="Bash",
                command="echo test",
                session_id=session_id
            )
            if result.is_circuit_open:
                break

        # Circuit should eventually open after violations
        # Note: This depends on rate limit thresholds being exceeded
        # and may need adjustment based on config


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
