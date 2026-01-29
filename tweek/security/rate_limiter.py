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
from typing import Optional, List, Dict, Any

from tweek.logging.security_log import SecurityLogger, get_logger


class RateLimitViolation(Enum):
    """Types of rate limit violations."""
    BURST = "burst"                      # Too many commands in short window
    REPEATED_COMMAND = "repeated"        # Same command executed too many times
    HIGH_VOLUME = "high_volume"          # Total volume exceeds threshold
    DANGEROUS_SPIKE = "dangerous_spike"  # Spike in dangerous tier commands
    VELOCITY_ANOMALY = "velocity"        # Unusual acceleration in activity


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
class RateLimitResult:
    """Result of rate limit check."""
    allowed: bool
    violations: List[RateLimitViolation] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    message: Optional[str] = None

    @property
    def is_burst(self) -> bool:
        return RateLimitViolation.BURST in self.violations

    @property
    def is_repeated(self) -> bool:
        return RateLimitViolation.REPEATED_COMMAND in self.violations


class RateLimiter:
    """
    Rate limiter for detecting resource theft and abuse patterns.

    Uses the security.db to track invocation patterns and detect anomalies.
    """

    def __init__(
        self,
        config: Optional[RateLimitConfig] = None,
        logger: Optional[SecurityLogger] = None
    ):
        """Initialize the rate limiter.

        Args:
            config: Rate limiting configuration
            logger: Security logger for database access
        """
        self.config = config or RateLimitConfig()
        self.logger = logger or get_logger()
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

        This is a PRO feature. Without a Pro license, always allows.

        Args:
            tool_name: Name of the tool being invoked
            command: The command being executed (for Bash)
            session_id: Current session identifier
            tier: Security tier of the operation

        Returns:
            RateLimitResult with allowed status and any violations
        """
        # Check license - rate limiting is a Pro feature
        from tweek.licensing import get_license
        if not get_license().has_feature("rate_limiting"):
            return RateLimitResult(allowed=True, message="Rate limiting requires Pro license")

        if not session_id:
            # No session tracking - allow but log
            return RateLimitResult(allowed=True, message="No session ID for rate limiting")

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
            # Database error - fail open but log
            return RateLimitResult(
                allowed=True,
                message=f"Rate limit check failed: {e}",
                details={"error": str(e)}
            )

        # Determine if we should block
        allowed = len(violations) == 0

        # Build message
        message = None
        if not allowed:
            violation_names = [v.value for v in violations]
            message = f"Rate limit violations: {', '.join(violation_names)}"

        return RateLimitResult(
            allowed=allowed,
            violations=violations,
            details=details,
            message=message
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

        lines.append("=" * 40)
        lines.append("This may indicate automated abuse or attack.")

        return "\n".join(lines)


# Singleton instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter(config: Optional[RateLimitConfig] = None) -> RateLimiter:
    """Get the singleton rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter(config=config)
    return _rate_limiter
