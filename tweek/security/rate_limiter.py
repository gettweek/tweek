#!/usr/bin/env python3
"""
Tweek Rate Limiter

Protects against resource theft attacks (MCP sampling abuse, quota drain)
by detecting:
- Burst patterns (many commands in short time)
- Repeated identical commands
- Unusual invocation volume
- Suspicious velocity changes

Based on Unit42 research on MCP sampling attack vectors.
"""

import hashlib
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from tweek.logging.security_log import SecurityLogger, get_logger


class RateLimitViolation(Enum):
    """Types of rate limit violations."""
    BURST = "burst"                      # Too many commands in short window
    REPEATED_COMMAND = "repeated"        # Same command executed too many times
    HIGH_VOLUME = "high_volume"          # Total volume exceeds threshold
    DANGEROUS_SPIKE = "dangerous_spike"  # Spike in dangerous tier commands
    VELOCITY_ANOMALY = "velocity"        # Unusual acceleration in activity
    CIRCUIT_OPEN = "circuit_open"        # Circuit breaker is open


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"      # Normal operation, requests allowed
    OPEN = "open"          # Failures exceeded threshold, requests blocked
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting thresholds."""
    # Time windows (in seconds)
    burst_window: int = 5
    short_window: int = 60
    long_window: int = 300

    # Thresholds
    burst_threshold: int = 15           # Max commands in burst window
    max_per_minute: int = 60            # Max commands per minute
    max_dangerous_per_minute: int = 10  # Max dangerous tier per minute
    max_same_command: int = 5           # Max identical commands per minute
    velocity_multiplier: float = 3.0    # Alert if velocity > N * baseline

    # Baseline learning
    baseline_window_hours: int = 24     # Hours of data for baseline
    min_baseline_samples: int = 100     # Minimum samples for baseline


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker pattern."""
    # Failure thresholds
    failure_threshold: int = 5          # Failures before opening circuit
    success_threshold: int = 3          # Successes in half-open before closing

    # Timing
    open_timeout: int = 60              # Seconds to stay open before half-open
    half_open_max_requests: int = 3     # Max requests to test in half-open

    # What counts as failure
    count_rate_limit_as_failure: bool = True
    count_timeout_as_failure: bool = True


@dataclass
class CircuitBreakerState:
    """Current state of a circuit breaker."""
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[datetime] = None
    last_state_change: Optional[datetime] = None
    half_open_requests: int = 0


@dataclass
class RateLimitResult:
    """Result of rate limit check."""
    allowed: bool
    violations: List[RateLimitViolation] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    message: Optional[str] = None
    circuit_state: CircuitState = CircuitState.CLOSED
    retry_after: Optional[int] = None  # Seconds to wait before retry

    @property
    def is_burst(self) -> bool:
        return RateLimitViolation.BURST in self.violations

    @property
    def is_repeated(self) -> bool:
        return RateLimitViolation.REPEATED_COMMAND in self.violations

    @property
    def is_circuit_open(self) -> bool:
        return self.circuit_state == CircuitState.OPEN


class CircuitBreaker:
    """
    Circuit breaker pattern implementation for fault tolerance.

    States:
    - CLOSED: Normal operation, requests allowed, failures tracked
    - OPEN: Too many failures, requests blocked, waiting for timeout
    - HALF_OPEN: Testing recovery, limited requests allowed

    Based on OpenClaw's circuit breaker implementation for resilience.
    """

    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        """
        Initialize the circuit breaker.

        Args:
            config: Circuit breaker configuration
        """
        self.config = config or CircuitBreakerConfig()
        self._states: Dict[str, CircuitBreakerState] = {}

    def _get_state(self, key: str) -> CircuitBreakerState:
        """Get or create state for a circuit key."""
        if key not in self._states:
            self._states[key] = CircuitBreakerState(
                last_state_change=datetime.now()
            )
        return self._states[key]

    def _transition_to(self, state: CircuitBreakerState, new_state: CircuitState) -> None:
        """Transition circuit to a new state."""
        state.state = new_state
        state.last_state_change = datetime.now()
        if new_state == CircuitState.HALF_OPEN:
            state.half_open_requests = 0
            state.success_count = 0

    def can_execute(self, key: str = "default") -> Tuple[bool, CircuitState, Optional[int]]:
        """
        Check if a request can be executed.

        Args:
            key: Circuit breaker key (e.g., "session:123" or "tool:Bash")

        Returns:
            (allowed, circuit_state, retry_after_seconds)
        """
        state = self._get_state(key)
        now = datetime.now()

        if state.state == CircuitState.CLOSED:
            return True, CircuitState.CLOSED, None

        elif state.state == CircuitState.OPEN:
            # Check if timeout has elapsed
            if state.last_state_change:
                elapsed = (now - state.last_state_change).total_seconds()
                if elapsed >= self.config.open_timeout:
                    # Transition to half-open
                    self._transition_to(state, CircuitState.HALF_OPEN)
                    return True, CircuitState.HALF_OPEN, None
                else:
                    retry_after = int(self.config.open_timeout - elapsed)
                    return False, CircuitState.OPEN, retry_after

            return False, CircuitState.OPEN, self.config.open_timeout

        elif state.state == CircuitState.HALF_OPEN:
            # Allow limited requests in half-open state
            if state.half_open_requests < self.config.half_open_max_requests:
                state.half_open_requests += 1
                return True, CircuitState.HALF_OPEN, None
            else:
                return False, CircuitState.HALF_OPEN, 5  # Short wait

        return True, CircuitState.CLOSED, None

    def record_success(self, key: str = "default") -> CircuitState:
        """
        Record a successful request.

        Args:
            key: Circuit breaker key

        Returns:
            New circuit state
        """
        state = self._get_state(key)

        if state.state == CircuitState.HALF_OPEN:
            state.success_count += 1
            if state.success_count >= self.config.success_threshold:
                # Recovery confirmed, close the circuit
                self._transition_to(state, CircuitState.CLOSED)
                state.failure_count = 0

        elif state.state == CircuitState.CLOSED:
            # Reset failure count on success
            state.failure_count = 0

        return state.state

    def record_failure(self, key: str = "default") -> CircuitState:
        """
        Record a failed request.

        Args:
            key: Circuit breaker key

        Returns:
            New circuit state
        """
        state = self._get_state(key)
        state.failure_count += 1
        state.last_failure_time = datetime.now()

        if state.state == CircuitState.HALF_OPEN:
            # Any failure in half-open reopens the circuit
            self._transition_to(state, CircuitState.OPEN)

        elif state.state == CircuitState.CLOSED:
            if state.failure_count >= self.config.failure_threshold:
                # Too many failures, open the circuit
                self._transition_to(state, CircuitState.OPEN)

        return state.state

    def get_state(self, key: str = "default") -> CircuitBreakerState:
        """
        Get the current state of a circuit.

        Args:
            key: Circuit breaker key

        Returns:
            Current circuit breaker state
        """
        return self._get_state(key)

    def reset(self, key: str = "default") -> None:
        """
        Reset a circuit breaker to closed state.

        Args:
            key: Circuit breaker key
        """
        if key in self._states:
            del self._states[key]

    def get_all_states(self) -> Dict[str, CircuitBreakerState]:
        """Get all circuit breaker states."""
        return self._states.copy()

    def get_metrics(self) -> Dict[str, Any]:
        """
        Get circuit breaker metrics.

        Returns:
            Dictionary with metrics for all circuits
        """
        metrics = {
            "total_circuits": len(self._states),
            "open_circuits": 0,
            "half_open_circuits": 0,
            "closed_circuits": 0,
            "circuits": {}
        }

        for key, state in self._states.items():
            if state.state == CircuitState.OPEN:
                metrics["open_circuits"] += 1
            elif state.state == CircuitState.HALF_OPEN:
                metrics["half_open_circuits"] += 1
            else:
                metrics["closed_circuits"] += 1

            metrics["circuits"][key] = {
                "state": state.state.value,
                "failure_count": state.failure_count,
                "success_count": state.success_count,
            }

        return metrics


class PersistentCircuitBreaker(CircuitBreaker):
    """Circuit breaker with JSON file persistence across process invocations.

    Uses fcntl.flock for safe concurrent access. Falls back to fresh
    in-memory state if the persistence file is corrupted or inaccessible.
    """

    def __init__(
        self,
        config: Optional[CircuitBreakerConfig] = None,
        state_path: Optional[Path] = None,
    ):
        super().__init__(config)
        self._state_path = state_path or (Path.home() / ".tweek" / ".circuit_breaker.json")

    def _load_states(self) -> None:
        """Load persisted states from JSON file under flock."""
        import fcntl
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            if not self._state_path.exists():
                return
            with open(self._state_path, "r") as f:
                fcntl.flock(f, fcntl.LOCK_SH)
                try:
                    raw = json.load(f)
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
            for key, data in raw.items():
                self._states[key] = CircuitBreakerState(
                    state=CircuitState(data.get("state", "closed")),
                    failure_count=data.get("failure_count", 0),
                    success_count=data.get("success_count", 0),
                    last_failure_time=(
                        datetime.fromisoformat(data["last_failure_time"])
                        if data.get("last_failure_time") else None
                    ),
                    last_state_change=(
                        datetime.fromisoformat(data["last_state_change"])
                        if data.get("last_state_change") else None
                    ),
                    half_open_requests=data.get("half_open_requests", 0),
                )
        except (json.JSONDecodeError, OSError, KeyError, ValueError):
            pass  # Corrupt file — start fresh

    def _save_states(self) -> None:
        """Persist current states to JSON file under flock."""
        import fcntl
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            serializable = {}
            for key, state in self._states.items():
                serializable[key] = {
                    "state": state.state.value,
                    "failure_count": state.failure_count,
                    "success_count": state.success_count,
                    "last_failure_time": (
                        state.last_failure_time.isoformat()
                        if state.last_failure_time else None
                    ),
                    "last_state_change": (
                        state.last_state_change.isoformat()
                        if state.last_state_change else None
                    ),
                    "half_open_requests": state.half_open_requests,
                }
            with open(self._state_path, "w") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    json.dump(serializable, f)
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
        except OSError:
            pass  # Best-effort persistence

    def record_success(self, key: str = "default") -> CircuitState:
        self._load_states()
        result = super().record_success(key)
        self._save_states()
        return result

    def record_failure(self, key: str = "default") -> CircuitState:
        self._load_states()
        result = super().record_failure(key)
        self._save_states()
        return result

    def can_execute(self, key: str = "default") -> Tuple[bool, CircuitState, Optional[int]]:
        self._load_states()
        result = super().can_execute(key)
        self._save_states()
        return result


class RateLimiter:
    """
    Rate limiter for detecting resource theft and abuse patterns.

    Uses the security.db to track invocation patterns and detect anomalies.
    Includes circuit breaker for fault tolerance.
    """

    def __init__(
        self,
        config: Optional[RateLimitConfig] = None,
        circuit_config: Optional[CircuitBreakerConfig] = None,
        logger: Optional[SecurityLogger] = None
    ):
        """Initialize the rate limiter.

        Args:
            config: Rate limiting configuration
            circuit_config: Circuit breaker configuration
            logger: Security logger for database access
        """
        self.config = config or RateLimitConfig()
        self.logger = logger or get_logger()
        self.circuit_breaker = CircuitBreaker(circuit_config)
        self._ensure_indexes()

    def _ensure_indexes(self):
        """Ensure necessary database indexes exist for efficient queries."""
        try:
            with self.logger._get_connection() as conn:
                conn.executescript("""
                    -- Index for session + timestamp queries (rate limiting)
                    CREATE INDEX IF NOT EXISTS idx_events_session_time
                        ON security_events(session_id, timestamp);

                    -- Index for command hash queries (repeated command detection)
                    CREATE INDEX IF NOT EXISTS idx_events_command_hash
                        ON security_events(tool_name, command);
                """)
        except Exception:
            # Indexes may already exist or db not initialized
            pass

    def _hash_command(self, command: str) -> str:
        """Create a hash of a command for comparison."""
        return hashlib.md5(command.encode()).hexdigest()[:16]

    def _get_recent_count(
        self,
        conn: sqlite3.Connection,
        session_id: str,
        window_seconds: int,
        tool_name: Optional[str] = None,
        tier: Optional[str] = None
    ) -> int:
        """Get count of recent events in a time window."""
        query = """
            SELECT COUNT(*) as count FROM security_events
            WHERE session_id = ?
            AND timestamp > datetime('now', ?)
            AND event_type = 'tool_invoked'
        """
        params = [session_id, f'-{window_seconds} seconds']

        if tool_name:
            query += " AND tool_name = ?"
            params.append(tool_name)

        if tier:
            query += " AND tier = ?"
            params.append(tier)

        return conn.execute(query, params).fetchone()[0]

    def _get_command_count(
        self,
        conn: sqlite3.Connection,
        session_id: str,
        command: str,
        window_seconds: int
    ) -> int:
        """Get count of identical commands in a time window."""
        query = """
            SELECT COUNT(*) as count FROM security_events
            WHERE session_id = ?
            AND timestamp > datetime('now', ?)
            AND command = ?
            AND event_type = 'tool_invoked'
        """
        return conn.execute(
            query,
            [session_id, f'-{window_seconds} seconds', command]
        ).fetchone()[0]

    def _get_baseline_velocity(
        self,
        conn: sqlite3.Connection,
        session_id: str
    ) -> Optional[float]:
        """Get baseline commands per minute for comparison."""
        query = """
            SELECT COUNT(*) as count,
                   MIN(timestamp) as first_ts,
                   MAX(timestamp) as last_ts
            FROM security_events
            WHERE session_id = ?
            AND timestamp > datetime('now', ?)
            AND event_type = 'tool_invoked'
        """
        result = conn.execute(
            query,
            [session_id, f'-{self.config.baseline_window_hours} hours']
        ).fetchone()

        count = result[0]
        if count < self.config.min_baseline_samples:
            return None

        # Calculate average commands per minute
        try:
            first_ts = datetime.fromisoformat(result[1])
            last_ts = datetime.fromisoformat(result[2])
            duration_minutes = (last_ts - first_ts).total_seconds() / 60
            if duration_minutes > 0:
                return count / duration_minutes
        except (ValueError, TypeError):
            pass

        return None

    def _get_current_velocity(
        self,
        conn: sqlite3.Connection,
        session_id: str,
        window_seconds: int = 60
    ) -> float:
        """Get current commands per minute."""
        count = self._get_recent_count(conn, session_id, window_seconds)
        return count * (60 / window_seconds)

    def check(
        self,
        tool_name: str,
        command: Optional[str],
        session_id: Optional[str],
        tier: Optional[str] = None
    ) -> RateLimitResult:
        """
        Check if an invocation should be rate limited.

        Rate limiting is free and open source.

        Args:
            tool_name: Name of the tool being invoked
            command: The command being executed (for Bash)
            session_id: Current session identifier
            tier: Security tier of the operation

        Returns:
            RateLimitResult with allowed status and any violations
        """
        if not session_id:
            # No session ID - generate unique one per invocation.
            # os.urandom(16) adds 128 bits of entropy so each call is unique
            # even with identical PID/CWD.
            import os as _os
            import uuid as _uuid
            session_id = hashlib.sha256(
                f"tweek-{_os.getpid()}-{_os.getcwd()}-{_uuid.getnode()}".encode()
                + _os.urandom(16)
            ).hexdigest()[:16]

        # Check circuit breaker first
        circuit_key = f"session:{session_id}"
        can_exec, circuit_state, retry_after = self.circuit_breaker.can_execute(circuit_key)

        if not can_exec:
            return RateLimitResult(
                allowed=False,
                violations=[RateLimitViolation.CIRCUIT_OPEN],
                message=f"Circuit breaker is {circuit_state.value}. Too many rate limit violations.",
                circuit_state=circuit_state,
                retry_after=retry_after,
                details={"circuit_key": circuit_key}
            )

        violations = []
        details = {}

        try:
            with self.logger._get_connection() as conn:
                # Check 1: Burst detection (many commands in very short window)
                burst_count = self._get_recent_count(
                    conn, session_id, self.config.burst_window
                )
                details["burst_count"] = burst_count
                if burst_count >= self.config.burst_threshold:
                    violations.append(RateLimitViolation.BURST)
                    details["burst_threshold"] = self.config.burst_threshold

                # Check 2: Per-minute volume
                minute_count = self._get_recent_count(
                    conn, session_id, self.config.short_window
                )
                details["minute_count"] = minute_count
                if minute_count >= self.config.max_per_minute:
                    violations.append(RateLimitViolation.HIGH_VOLUME)
                    details["max_per_minute"] = self.config.max_per_minute

                # Check 3: Dangerous tier spike
                if tier == "dangerous":
                    dangerous_count = self._get_recent_count(
                        conn, session_id, self.config.short_window, tier="dangerous"
                    )
                    details["dangerous_count"] = dangerous_count
                    if dangerous_count >= self.config.max_dangerous_per_minute:
                        violations.append(RateLimitViolation.DANGEROUS_SPIKE)
                        details["max_dangerous"] = self.config.max_dangerous_per_minute

                # Check 4: Repeated command detection
                if command:
                    cmd_count = self._get_command_count(
                        conn, session_id, command, self.config.short_window
                    )
                    details["same_command_count"] = cmd_count
                    if cmd_count >= self.config.max_same_command:
                        violations.append(RateLimitViolation.REPEATED_COMMAND)
                        details["max_same_command"] = self.config.max_same_command

                # Check 5: Velocity anomaly
                baseline = self._get_baseline_velocity(conn, session_id)
                current = self._get_current_velocity(conn, session_id)
                details["current_velocity"] = round(current, 2)

                if baseline:
                    details["baseline_velocity"] = round(baseline, 2)
                    if current > baseline * self.config.velocity_multiplier:
                        violations.append(RateLimitViolation.VELOCITY_ANOMALY)
                        details["velocity_ratio"] = round(current / baseline, 2)

        except Exception as e:
            # Database error - fail closed for safety
            return RateLimitResult(
                allowed=False,
                violations=[RateLimitViolation.BURST],
                message=f"Rate limit check failed (blocking for safety): {e}",
                details={"error": str(e)}
            )

        # Determine if we should block
        allowed = len(violations) == 0

        # Update circuit breaker based on result
        if allowed:
            new_state = self.circuit_breaker.record_success(circuit_key)
        else:
            new_state = self.circuit_breaker.record_failure(circuit_key)

        # Build message
        message = None
        if not allowed:
            violation_names = [v.value for v in violations]
            message = f"Rate limit violations: {', '.join(violation_names)}"

        return RateLimitResult(
            allowed=allowed,
            violations=violations,
            details=details,
            message=message,
            circuit_state=new_state
        )

    def get_session_stats(self, session_id: str) -> Dict[str, Any]:
        """
        Get statistics for a session.

        Args:
            session_id: Session to get stats for

        Returns:
            Dictionary with session statistics
        """
        try:
            with self.logger._get_connection() as conn:
                # Total invocations
                total = self._get_recent_count(
                    conn, session_id, self.config.long_window * 12  # 1 hour
                )

                # By tier
                tiers = {}
                for tier in ["safe", "default", "risky", "dangerous"]:
                    tiers[tier] = self._get_recent_count(
                        conn, session_id, self.config.long_window * 12, tier=tier
                    )

                # Velocity
                current = self._get_current_velocity(conn, session_id)
                baseline = self._get_baseline_velocity(conn, session_id)

                return {
                    "session_id": session_id,
                    "total_invocations_1h": total,
                    "by_tier": tiers,
                    "current_velocity_per_min": round(current, 2),
                    "baseline_velocity_per_min": round(baseline, 2) if baseline else None,
                    "config": {
                        "burst_threshold": self.config.burst_threshold,
                        "max_per_minute": self.config.max_per_minute,
                        "max_dangerous_per_minute": self.config.max_dangerous_per_minute,
                    }
                }
        except Exception as e:
            return {"error": str(e)}

    def format_violation_message(self, result: RateLimitResult) -> str:
        """Format a user-friendly violation message."""
        if result.allowed:
            return ""

        lines = [
            "Rate Limit Alert",
            "=" * 40,
        ]

        if result.is_burst:
            lines.append(
                f"  Burst detected: {result.details.get('burst_count', '?')} "
                f"commands in {self.config.burst_window}s "
                f"(limit: {self.config.burst_threshold})"
            )

        if result.is_repeated:
            lines.append(
                f"  Repeated command: {result.details.get('same_command_count', '?')} "
                f"times in 1 minute (limit: {self.config.max_same_command})"
            )

        if RateLimitViolation.HIGH_VOLUME in result.violations:
            lines.append(
                f"  High volume: {result.details.get('minute_count', '?')} "
                f"commands/min (limit: {self.config.max_per_minute})"
            )

        if RateLimitViolation.DANGEROUS_SPIKE in result.violations:
            lines.append(
                f"  Dangerous tier spike: {result.details.get('dangerous_count', '?')} "
                f"dangerous commands (limit: {self.config.max_dangerous_per_minute})"
            )

        if RateLimitViolation.VELOCITY_ANOMALY in result.violations:
            lines.append(
                f"  Velocity anomaly: {result.details.get('velocity_ratio', '?')}x "
                f"above baseline"
            )

        if result.is_circuit_open:
            lines.append(
                f"  Circuit breaker OPEN: Too many rate limit violations"
            )
            if result.retry_after:
                lines.append(f"  Retry after: {result.retry_after} seconds")

        lines.append("=" * 40)
        lines.append("This may indicate automated abuse or attack.")

        return "\n".join(lines)

    def get_circuit_metrics(self) -> Dict[str, Any]:
        """Get circuit breaker metrics for all sessions."""
        return self.circuit_breaker.get_metrics()

    def reset_circuit(self, session_id: str) -> None:
        """Reset circuit breaker for a session."""
        circuit_key = f"session:{session_id}"
        self.circuit_breaker.reset(circuit_key)


# Singleton instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter(
    config: Optional[RateLimitConfig] = None,
    circuit_config: Optional[CircuitBreakerConfig] = None
) -> RateLimiter:
    """Get the singleton rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter(config=config, circuit_config=circuit_config)
    return _rate_limiter
