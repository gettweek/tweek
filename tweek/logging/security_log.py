#!/usr/bin/env python3
"""
Tweek Security Logger

SQLite-based audit logging for security events.
Logs all tool/skill invocations, screening decisions, and user responses.

Database location: ~/.tweek/security.db

Includes log redaction for sensitive data based on moltbot's security hardening.
"""

import json
import os
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Pattern


class LogRedactor:
    """
    Redacts sensitive information from log data.

    Based on moltbot's log-redaction security feature.
    Ensures secrets, tokens, and credentials are never written to logs.
    """

    # Patterns for sensitive data that should be redacted
    REDACTION_PATTERNS: List[tuple[str, Pattern, str]] = [
        # API Keys - various formats
        ("api_key", re.compile(
            r'(?i)(api[_-]?key|apikey|secret[_-]?key)[\s:=]+[\'\"]?([A-Za-z0-9_-]{16,})[\'\"]?'
        ), r'\1=***REDACTED***'),

        # AWS Access Keys
        ("aws_key", re.compile(
            r'((?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})'
        ), '***AWS_KEY_REDACTED***'),

        # AWS Secret Keys (40 char)
        ("aws_secret", re.compile(
            r'(?i)(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)[\s:=]+[\'\"]?([A-Za-z0-9/+=]{40})[\'\"]?'
        ), r'\1=***REDACTED***'),

        # Bearer tokens
        ("bearer", re.compile(
            r'(?i)(bearer)\s+([A-Za-z0-9_-]{20,})'
        ), r'\1 ***REDACTED***'),

        # JWT tokens
        ("jwt", re.compile(
            r'(eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)'
        ), '***JWT_REDACTED***'),

        # GitHub tokens
        ("github", re.compile(
            r'(gh[pousr]_[A-Za-z0-9_]{36,})'
        ), '***GITHUB_TOKEN_REDACTED***'),

        # Slack tokens
        ("slack", re.compile(
            r'(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)'
        ), '***SLACK_TOKEN_REDACTED***'),

        # Generic passwords in assignments
        ("password", re.compile(
            r'(?i)(password|passwd|pwd|secret)[\s:=]+[\'\"]?([^\s\'\"\n]{8,})[\'\"]?'
        ), r'\1=***REDACTED***'),

        # Connection strings with credentials
        ("connection_string", re.compile(
            r'(?i)(mongodb|postgres|mysql|redis|amqp)://([^:]+):([^@]+)@'
        ), r'\1://\2:***REDACTED***@'),

        # Private key headers
        ("private_key", re.compile(
            r'(-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----)'
        ), '***PRIVATE_KEY_REDACTED***'),

        # Base64 encoded secrets (long base64 strings in sensitive contexts)
        ("base64_secret", re.compile(
            r'(?i)(secret|key|token|credential)[\s:=]+[\'\"]?([A-Za-z0-9+/]{40,}={0,2})[\'\"]?'
        ), r'\1=***REDACTED***'),

        # Email addresses (for privacy)
        ("email", re.compile(
            r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        ), '***EMAIL_REDACTED***'),

        # Credit card numbers
        ("credit_card", re.compile(
            r'\b([0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4})\b'
        ), '***CARD_REDACTED***'),

        # SSH private key paths being read
        ("ssh_key_read", re.compile(
            r'(?i)(cat|less|more|head|tail|read)\s+["\']?(~?/[^\s]*\.pem|~?/\.ssh/[^\s]*)["\']?'
        ), r'\1 ***SSH_PATH_REDACTED***'),
    ]

    # Keys in dictionaries that should have their values redacted
    SENSITIVE_KEYS = {
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
        'access_key', 'secret_key', 'private_key', 'credential', 'auth',
        'bearer', 'jwt', 'session', 'cookie', 'oauth', 'refresh_token',
        'client_secret', 'app_secret', 'webhook_secret', 'signing_key',
        'encryption_key', 'decryption_key', 'master_key', 'root_password',
    }

    def __init__(self, enabled: bool = True):
        """
        Initialize the log redactor.

        Args:
            enabled: Whether redaction is enabled (default True)
        """
        self.enabled = enabled

    def redact_string(self, text: str) -> str:
        """
        Redact sensitive information from a string.

        Args:
            text: The text to redact

        Returns:
            Redacted text with sensitive data replaced
        """
        if not self.enabled or not text:
            return text

        result = text
        for name, pattern, replacement in self.REDACTION_PATTERNS:
            result = pattern.sub(replacement, result)

        return result

    def redact_dict(self, data: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
        """
        Redact sensitive information from a dictionary.

        Args:
            data: Dictionary to redact
            depth: Current recursion depth (to prevent infinite loops)

        Returns:
            Dictionary with sensitive values redacted
        """
        if not self.enabled or not data or depth > 10:
            return data

        result = {}
        for key, value in data.items():
            key_lower = key.lower()

            # Check if key is sensitive
            is_sensitive = any(
                sensitive in key_lower
                for sensitive in self.SENSITIVE_KEYS
            )

            if is_sensitive and isinstance(value, str):
                # Redact the entire value
                result[key] = "***REDACTED***"
            elif isinstance(value, str):
                # Apply pattern-based redaction
                result[key] = self.redact_string(value)
            elif isinstance(value, dict):
                # Recursively redact nested dicts
                result[key] = self.redact_dict(value, depth + 1)
            elif isinstance(value, list):
                # Redact items in lists
                result[key] = [
                    self.redact_dict(item, depth + 1) if isinstance(item, dict)
                    else self.redact_string(item) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                result[key] = value

        return result

    def redact_command(self, command: str) -> str:
        """
        Redact sensitive information from a command string.

        Args:
            command: Command to redact

        Returns:
            Redacted command
        """
        if not self.enabled or not command:
            return command

        # Apply general string redaction
        result = self.redact_string(command)

        # Additional command-specific patterns
        command_patterns = [
            # curl with auth headers - capture everything after Authorization:
            (re.compile(r'(-H\s+["\']?Authorization:\s*(?:Bearer\s+)?)[^"\']+(["\'])'), r'\1***REDACTED***\2'),
            # curl with data containing secrets
            (re.compile(r'(-d\s+["\'][^"\']*(?:password|secret|token)[^"\']*=)[^&"\'\s]+'), r'\1***REDACTED***'),
            # Environment variable exports with secrets
            (re.compile(r'(?i)(export\s+(?:\w*(?:KEY|SECRET|TOKEN|PASSWORD)\w*)\s*=\s*)[^\s;]+'), r'\1***REDACTED***'),
            # inline environment variables
            (re.compile(r'(?i)(\w*(?:KEY|SECRET|TOKEN|PASSWORD)\w*=)[^\s;]+'), r'\1***REDACTED***'),
        ]

        for pattern, replacement in command_patterns:
            result = pattern.sub(replacement, result)

        return result


# Singleton redactor instance
_redactor: Optional[LogRedactor] = None


def get_redactor(enabled: bool = True) -> LogRedactor:
    """Get the singleton log redactor instance."""
    global _redactor
    if _redactor is None:
        _redactor = LogRedactor(enabled=enabled)
    return _redactor


class EventType(Enum):
    """Types of security events."""
    TOOL_INVOKED = "tool_invoked"           # Tool call received
    PATTERN_MATCH = "pattern_match"         # Regex pattern matched
    LLM_RULE_MATCH = "llm_rule_match"       # LLM rule flagged
    ESCALATION = "escalation"               # Tier escalated due to content
    ALLOWED = "allowed"                     # Execution permitted
    BLOCKED = "blocked"                     # Execution blocked
    USER_PROMPTED = "user_prompted"         # User asked for confirmation
    USER_APPROVED = "user_approved"         # User approved after prompt
    USER_DENIED = "user_denied"             # User denied after prompt
    SANDBOX_PREVIEW = "sandbox_preview"     # Sandbox preview executed
    ERROR = "error"                         # Error during processing


@dataclass
class SecurityEvent:
    """A security event to be logged."""
    event_type: EventType
    tool_name: str
    command: Optional[str] = None
    tier: Optional[str] = None
    pattern_name: Optional[str] = None
    pattern_severity: Optional[str] = None
    decision: Optional[str] = None          # allow, block, ask
    decision_reason: Optional[str] = None
    user_response: Optional[str] = None     # approved, denied
    metadata: Optional[Dict[str, Any]] = None
    session_id: Optional[str] = None
    working_directory: Optional[str] = None


class SecurityLogger:
    """SQLite-based security event logger with automatic redaction."""

    DEFAULT_DB_PATH = Path.home() / ".tweek" / "security.db"

    def __init__(
        self,
        db_path: Optional[Path] = None,
        redact_logs: bool = True
    ):
        """Initialize the security logger.

        Args:
            db_path: Path to SQLite database. Defaults to ~/.tweek/security.db
            redact_logs: Whether to redact sensitive data before logging (default True)
        """
        self.db_path = db_path or self.DEFAULT_DB_PATH
        # Create own redactor instance instead of using singleton
        self.redactor = LogRedactor(enabled=redact_logs)
        self._ensure_db_exists()

    def _ensure_db_exists(self):
        """Create database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with self._get_connection() as conn:
            conn.executescript("""
                -- Main events table
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                    event_type TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    command TEXT,
                    tier TEXT,
                    pattern_name TEXT,
                    pattern_severity TEXT,
                    decision TEXT,
                    decision_reason TEXT,
                    user_response TEXT,
                    session_id TEXT,
                    working_directory TEXT,
                    metadata_json TEXT
                );

                -- Index for common queries
                CREATE INDEX IF NOT EXISTS idx_events_timestamp
                    ON security_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_type
                    ON security_events(event_type);
                CREATE INDEX IF NOT EXISTS idx_events_tool
                    ON security_events(tool_name);
                CREATE INDEX IF NOT EXISTS idx_events_decision
                    ON security_events(decision);
                CREATE INDEX IF NOT EXISTS idx_events_session
                    ON security_events(session_id);

                -- Summary statistics view
                CREATE VIEW IF NOT EXISTS event_summary AS
                SELECT
                    date(timestamp) as date,
                    event_type,
                    tool_name,
                    decision,
                    COUNT(*) as count
                FROM security_events
                GROUP BY date(timestamp), event_type, tool_name, decision;

                -- Recent blocks view
                CREATE VIEW IF NOT EXISTS recent_blocks AS
                SELECT
                    timestamp,
                    tool_name,
                    command,
                    pattern_name,
                    pattern_severity,
                    decision_reason
                FROM security_events
                WHERE decision IN ('block', 'ask')
                ORDER BY timestamp DESC
                LIMIT 100;
            """)

    @contextmanager
    def _get_connection(self):
        """Get a database connection with proper cleanup."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def log(self, event: SecurityEvent) -> int:
        """Log a security event with automatic redaction of sensitive data.

        Args:
            event: The security event to log

        Returns:
            The row ID of the inserted event
        """
        # Redact sensitive data before logging
        redacted_command = self.redactor.redact_command(event.command) if event.command else None
        redacted_reason = self.redactor.redact_string(event.decision_reason) if event.decision_reason else None
        redacted_metadata = self.redactor.redact_dict(event.metadata) if event.metadata else None

        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO security_events (
                    event_type, tool_name, command, tier,
                    pattern_name, pattern_severity,
                    decision, decision_reason, user_response,
                    session_id, working_directory, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_type.value,
                event.tool_name,
                redacted_command,
                event.tier,
                event.pattern_name,
                event.pattern_severity,
                event.decision,
                redacted_reason,
                event.user_response,
                event.session_id,
                event.working_directory,
                json.dumps(redacted_metadata) if redacted_metadata else None
            ))
            return cursor.lastrowid

    def log_quick(
        self,
        event_type: EventType,
        tool_name: str,
        command: Optional[str] = None,
        **kwargs
    ) -> int:
        """Quick logging helper.

        Args:
            event_type: Type of event
            tool_name: Name of the tool
            command: The command being executed
            **kwargs: Additional event fields

        Returns:
            The row ID of the inserted event
        """
        event = SecurityEvent(
            event_type=event_type,
            tool_name=tool_name,
            command=command,
            **kwargs
        )
        return self.log(event)

    def get_recent_events(
        self,
        limit: int = 50,
        event_type: Optional[EventType] = None,
        tool_name: Optional[str] = None
    ) -> List[Dict]:
        """Get recent security events.

        Args:
            limit: Maximum number of events to return
            event_type: Filter by event type
            tool_name: Filter by tool name

        Returns:
            List of event dictionaries
        """
        query = "SELECT * FROM security_events WHERE 1=1"
        params = []

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.value)

        if tool_name:
            query += " AND tool_name = ?"
            params.append(tool_name)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    def get_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get security statistics for the specified period.

        Args:
            days: Number of days to include

        Returns:
            Dictionary with statistics
        """
        with self._get_connection() as conn:
            # Total events
            total = conn.execute("""
                SELECT COUNT(*) as count FROM security_events
                WHERE timestamp > datetime('now', ?)
            """, (f'-{days} days',)).fetchone()['count']

            # Events by decision
            decisions = conn.execute("""
                SELECT decision, COUNT(*) as count
                FROM security_events
                WHERE timestamp > datetime('now', ?)
                AND decision IS NOT NULL
                GROUP BY decision
            """, (f'-{days} days',)).fetchall()

            # Top triggered patterns
            patterns = conn.execute("""
                SELECT pattern_name, pattern_severity, COUNT(*) as count
                FROM security_events
                WHERE timestamp > datetime('now', ?)
                AND pattern_name IS NOT NULL
                GROUP BY pattern_name, pattern_severity
                ORDER BY count DESC
                LIMIT 10
            """, (f'-{days} days',)).fetchall()

            # Events by tool
            by_tool = conn.execute("""
                SELECT tool_name, COUNT(*) as count
                FROM security_events
                WHERE timestamp > datetime('now', ?)
                GROUP BY tool_name
                ORDER BY count DESC
            """, (f'-{days} days',)).fetchall()

            return {
                'period_days': days,
                'total_events': total,
                'by_decision': {row['decision']: row['count'] for row in decisions},
                'top_patterns': [
                    {
                        'name': row['pattern_name'],
                        'severity': row['pattern_severity'],
                        'count': row['count']
                    }
                    for row in patterns
                ],
                'by_tool': {row['tool_name']: row['count'] for row in by_tool}
            }

    def get_blocked_commands(self, limit: int = 20) -> List[Dict]:
        """Get recently blocked or flagged commands.

        Args:
            limit: Maximum number to return

        Returns:
            List of blocked command details
        """
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM recent_blocks LIMIT ?
            """, (limit,)).fetchall()
            return [dict(row) for row in rows]

    def export_csv(self, filepath: Path, days: Optional[int] = None) -> int:
        """Export events to CSV file.

        Args:
            filepath: Path to write CSV
            days: Optional limit to recent N days

        Returns:
            Number of rows exported
        """
        import csv

        query = "SELECT * FROM security_events"
        params = []

        if days:
            query += " WHERE timestamp > datetime('now', ?)"
            params.append(f'-{days} days')

        query += " ORDER BY timestamp DESC"

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()

            if not rows:
                return 0

            with open(filepath, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                for row in rows:
                    writer.writerow(dict(row))

            return len(rows)


# Singleton instance for easy access
_logger: Optional[SecurityLogger] = None


def get_logger(redact_logs: bool = True) -> SecurityLogger:
    """Get the singleton security logger instance.

    Args:
        redact_logs: Whether to enable log redaction (default True)

    Returns:
        SecurityLogger instance
    """
    global _logger
    if _logger is None:
        _logger = SecurityLogger(redact_logs=redact_logs)
    return _logger
