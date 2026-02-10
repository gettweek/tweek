#!/usr/bin/env python3
"""
Tweek Security Logger

SQLite-based audit logging for security events.
Logs all tool/skill invocations, screening decisions, and user responses.

Database location: ~/.tweek/security.db

Includes log redaction for sensitive data based on OpenClaw's security hardening.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Pattern


def _sanitize_for_log(text: Optional[str]) -> Optional[str]:
    """Sanitize text for log storage to prevent log injection.

    Replaces control characters that could break log parsers:
    newlines, carriage returns, tabs, null bytes, and ANSI escapes.
    """
    if text is None:
        return None
    return (
        text
        .replace("\x00", "\\x00")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("\x1b", "\\x1b")
    )


class LogRedactor:
    """
    Redacts sensitive information from log data.

    Based on OpenClaw's log-redaction security feature.
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

            if is_sensitive:
                # Redact entire value for sensitive keys, regardless of type
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
_redactor_lock = threading.Lock()


def get_redactor(enabled: bool = True) -> LogRedactor:
    """Get the singleton log redactor instance."""
    global _redactor
    if _redactor is None:
        with _redactor_lock:
            if _redactor is None:
                _redactor = LogRedactor(enabled=enabled)
    return _redactor


class EventType(Enum):
    """Types of security events."""
    # Core screening events
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

    # Vault events
    VAULT_ACCESS = "vault_access"           # Credential store/get/delete
    VAULT_MIGRATION = "vault_migration"     # .env migration to vault

    # Configuration events
    CONFIG_CHANGE = "config_change"         # Tier/preset/config modification

    # License events
    LICENSE_EVENT = "license_event"         # Activation, deactivation, validation

    # Advanced screening events
    RATE_LIMIT = "rate_limit"               # Rate limit violation
    SESSION_ANOMALY = "session_anomaly"     # Session analysis anomaly detected
    CIRCUIT_BREAKER = "circuit_breaker"     # Circuit breaker state transition

    # Plugin events
    PLUGIN_EVENT = "plugin_event"           # Plugin load, failure, scan result

    # MCP events
    MCP_APPROVAL = "mcp_approval"           # MCP approval queue decision

    # Proxy events
    PROXY_EVENT = "proxy_event"             # HTTP proxy request screening

    # Skill isolation chamber events
    SKILL_CHAMBER_INTAKE = "skill_chamber_intake"       # Skill placed in chamber
    SKILL_SCAN_COMPLETE = "skill_scan_complete"         # Scan pipeline finished
    SKILL_APPROVED = "skill_approved"                   # Skill approved and installed
    SKILL_JAILED = "skill_jailed"                       # Skill quarantined to jail
    SKILL_MANUAL_REVIEW = "skill_manual_review"         # Skill requires human review
    SKILL_INSTALL_BLOCKED = "skill_install_blocked"     # Direct install attempt blocked

    # Project sandbox events
    SANDBOX_PROJECT_INIT = "sandbox_project_init"       # Project .tweek/ created
    SANDBOX_LAYER_CHANGE = "sandbox_layer_change"       # Project isolation layer changed
    SANDBOX_MERGE_VIOLATION = "sandbox_merge_violation"  # Project tried to weaken global

    # Enforcement events
    BREAK_GLASS = "break_glass"                         # Emergency override of hard block
    FALSE_POSITIVE_REPORT = "false_positive_report"     # User reported false positive

    # File integrity events
    FILE_INTEGRITY_VIOLATION = "file_integrity_violation"  # Drift detected
    FILE_INTEGRITY_RESTORE = "file_integrity_restore"      # File restored from backup
    FILE_INTEGRITY_APPROVE = "file_integrity_approve"      # Drift approved by user

    # PII tokenization events
    PII_TOKENIZED = "pii_tokenized"                          # PII replaced with tokens
    PII_DETOKENIZED = "pii_detokenized"                      # Tokens replaced with PII

    # System events
    HEALTH_CHECK = "health_check"           # Diagnostic check results
    STARTUP = "startup"                     # System initialization


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
    correlation_id: Optional[str] = None    # Links related events in a screening pass
    source: Optional[str] = None            # "hooks", "mcp", "mcp_proxy", "http_proxy"


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
        # Harden directory permissions - security logs should be private
        try:
            import os
            os.chmod(self.db_path.parent, 0o700)
        except OSError:
            pass

        with self._get_connection() as conn:
            # Create table first (without views that reference new columns)
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
                    metadata_json TEXT,
                    correlation_id TEXT,
                    source TEXT,
                    entry_hash TEXT
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
            """)

            # Migrate existing databases that lack new columns
            # (must happen BEFORE creating views that reference new columns)
            self._migrate_schema(conn)

            # Now create indexes and views that reference new columns
            conn.executescript("""
                CREATE INDEX IF NOT EXISTS idx_events_correlation
                    ON security_events(correlation_id);
                CREATE INDEX IF NOT EXISTS idx_events_source
                    ON security_events(source);

                -- Summary statistics view (recreate to include new columns)
                DROP VIEW IF EXISTS event_summary;
                CREATE VIEW event_summary AS
                SELECT
                    date(timestamp) as date,
                    event_type,
                    tool_name,
                    decision,
                    source,
                    COUNT(*) as count
                FROM security_events
                GROUP BY date(timestamp), event_type, tool_name, decision, source;

                -- Recent blocks view (recreate to include new columns)
                DROP VIEW IF EXISTS recent_blocks;
                CREATE VIEW recent_blocks AS
                SELECT
                    timestamp,
                    tool_name,
                    command,
                    pattern_name,
                    pattern_severity,
                    decision_reason,
                    correlation_id,
                    source
                FROM security_events
                WHERE decision IN ('block', 'ask')
                ORDER BY timestamp DESC
                LIMIT 100;
            """)

    def _migrate_schema(self, conn):
        """Add new columns to existing databases if missing."""
        existing_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(security_events)").fetchall()
        }
        migrations = [
            ("correlation_id", "TEXT"),
            ("source", "TEXT"),
            ("entry_hash", "TEXT"),
        ]
        for col_name, col_type in migrations:
            if col_name not in existing_columns:
                conn.execute(f"ALTER TABLE security_events ADD COLUMN {col_name} {col_type}")

        # Ensure new indexes exist (safe to re-run)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_correlation ON security_events(correlation_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_source ON security_events(source)"
        )

    @contextmanager
    def _get_connection(self):
        """Get a database connection, reusing persistent connection when possible."""
        if not hasattr(self, '_conn') or self._conn is None:
            self._conn = sqlite3.connect(
                str(self.db_path),
                timeout=5,  # Wait up to 5s for locks (matches approval.py)
            )
            self._conn.row_factory = sqlite3.Row
            # Enable WAL mode for concurrent access from multiple hook processes
            self._conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield self._conn
            self._conn.commit()
        except Exception:
            # On error, close and reset so next call gets a fresh connection
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
            raise

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

        # Sanitize text fields to prevent log injection
        redacted_command = _sanitize_for_log(redacted_command)
        redacted_reason = _sanitize_for_log(redacted_reason)

        with self._get_connection() as conn:
            # Get previous entry's hash for chaining
            prev_row = conn.execute(
                "SELECT entry_hash FROM security_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = prev_row["entry_hash"] if prev_row and prev_row["entry_hash"] else ""

            # Build canonical representation for hashing
            metadata_str = json.dumps(redacted_metadata) if redacted_metadata else None
            entry_hash = self._compute_entry_hash(
                prev_hash=prev_hash,
                event_type=event.event_type.value,
                tool_name=event.tool_name,
                command=redacted_command,
                tier=event.tier,
                pattern_name=event.pattern_name,
                pattern_severity=event.pattern_severity,
                decision=event.decision,
                decision_reason=redacted_reason,
                user_response=event.user_response,
                session_id=event.session_id,
                working_directory=event.working_directory,
                metadata_json=metadata_str,
                correlation_id=event.correlation_id,
                source=event.source,
            )

            cursor = conn.execute("""
                INSERT INTO security_events (
                    event_type, tool_name, command, tier,
                    pattern_name, pattern_severity,
                    decision, decision_reason, user_response,
                    session_id, working_directory, metadata_json,
                    correlation_id, source, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                metadata_str,
                event.correlation_id,
                event.source,
                entry_hash,
            ))
            row_id = cursor.lastrowid

        # Also write to JSON logger if available
        self._write_json_event(event, redacted_command, redacted_reason, redacted_metadata)

        return row_id

    def _write_json_event(
        self,
        event: SecurityEvent,
        redacted_command: Optional[str],
        redacted_reason: Optional[str],
        redacted_metadata: Optional[Dict[str, Any]],
    ):
        """Write event to NDJSON log file if JSON logging is enabled."""
        try:
            from tweek.logging.json_logger import get_json_logger
            json_logger = get_json_logger()
            if json_logger and json_logger.enabled:
                json_logger.write_event(
                    event, redacted_command, redacted_reason, redacted_metadata
                )
        except Exception:
            pass  # JSON logging should never break primary logging

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

    def get_recent(self, limit: int = 10) -> List[SecurityEvent]:
        """Get recent events as SecurityEvent objects.

        Args:
            limit: Maximum number of events

        Returns:
            List of SecurityEvent objects (most recent first)
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()

        events = []
        for row in rows:
            row_dict = dict(row)
            try:
                metadata = json.loads(row_dict.get("metadata_json")) if row_dict.get("metadata_json") else None
            except (json.JSONDecodeError, TypeError):
                metadata = None

            events.append(SecurityEvent(
                event_type=EventType(row_dict["event_type"]),
                tool_name=row_dict["tool_name"],
                command=row_dict.get("command"),
                tier=row_dict.get("tier"),
                pattern_name=row_dict.get("pattern_name"),
                pattern_severity=row_dict.get("pattern_severity"),
                decision=row_dict.get("decision"),
                decision_reason=row_dict.get("decision_reason"),
                user_response=row_dict.get("user_response"),
                metadata=metadata,
                session_id=row_dict.get("session_id"),
                working_directory=row_dict.get("working_directory"),
                correlation_id=row_dict.get("correlation_id"),
                source=row_dict.get("source"),
            ))
        return events

    def delete_events(self, days: Optional[int] = None) -> int:
        """Delete events from the database.

        Args:
            days: If provided, only delete events older than this many days.
                  If None, delete all events.

        Returns:
            Number of events deleted
        """
        with self._get_connection() as conn:
            if days is not None:
                cursor = conn.execute(
                    "DELETE FROM security_events WHERE timestamp < datetime('now', ?)",
                    (f'-{days} days',),
                )
            else:
                cursor = conn.execute("DELETE FROM security_events")
            return cursor.rowcount

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

    # --- Hash chain methods ---

    @staticmethod
    def _compute_entry_hash(
        prev_hash: str,
        event_type: str,
        tool_name: str,
        command: Optional[str] = None,
        tier: Optional[str] = None,
        pattern_name: Optional[str] = None,
        pattern_severity: Optional[str] = None,
        decision: Optional[str] = None,
        decision_reason: Optional[str] = None,
        user_response: Optional[str] = None,
        session_id: Optional[str] = None,
        working_directory: Optional[str] = None,
        metadata_json: Optional[str] = None,
        correlation_id: Optional[str] = None,
        source: Optional[str] = None,
    ) -> str:
        """Compute SHA-256 hash for chain entry.

        Creates a canonical JSON representation of the event fields
        (sorted keys, deterministic), prepends the previous hash,
        and returns the SHA-256 hex digest.
        """
        canonical = json.dumps({
            "command": command,
            "correlation_id": correlation_id,
            "decision": decision,
            "decision_reason": decision_reason,
            "event_type": event_type,
            "metadata_json": metadata_json,
            "pattern_name": pattern_name,
            "pattern_severity": pattern_severity,
            "session_id": session_id,
            "source": source,
            "tier": tier,
            "tool_name": tool_name,
            "user_response": user_response,
            "working_directory": working_directory,
        }, sort_keys=True, separators=(",", ":"))
        payload = prev_hash + canonical
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def verify_chain(self) -> Dict[str, Any]:
        """Verify the integrity of the entire hash chain.

        Walks all entries chronologically and recomputes each hash.

        Returns:
            Dict with keys:
                valid: bool — True if chain is intact
                total: int — total entries checked
                verified: int — entries that passed verification
                broken_at: Optional[int] — first row ID where chain broke
                unchained: int — entries with no entry_hash (legacy)
                errors: List[Dict] — details of each broken link
        """
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM security_events ORDER BY id ASC"
            ).fetchall()

        if not rows:
            return {
                "valid": True,
                "total": 0,
                "verified": 0,
                "broken_at": None,
                "unchained": 0,
                "errors": [],
            }

        prev_hash = ""
        verified = 0
        unchained = 0
        errors = []
        broken_at = None

        for row in rows:
            row_dict = dict(row)
            stored_hash = row_dict.get("entry_hash")

            # Legacy entries without hashes are counted but not verified
            if not stored_hash:
                unchained += 1
                prev_hash = ""  # Reset chain after unchained entry
                continue

            expected = self._compute_entry_hash(
                prev_hash=prev_hash,
                event_type=row_dict["event_type"],
                tool_name=row_dict["tool_name"],
                command=row_dict.get("command"),
                tier=row_dict.get("tier"),
                pattern_name=row_dict.get("pattern_name"),
                pattern_severity=row_dict.get("pattern_severity"),
                decision=row_dict.get("decision"),
                decision_reason=row_dict.get("decision_reason"),
                user_response=row_dict.get("user_response"),
                session_id=row_dict.get("session_id"),
                working_directory=row_dict.get("working_directory"),
                metadata_json=row_dict.get("metadata_json"),
                correlation_id=row_dict.get("correlation_id"),
                source=row_dict.get("source"),
            )

            if expected == stored_hash:
                verified += 1
            else:
                if broken_at is None:
                    broken_at = row_dict["id"]
                errors.append({
                    "id": row_dict["id"],
                    "event_type": row_dict["event_type"],
                    "timestamp": row_dict.get("timestamp", ""),
                    "expected_hash": expected[:16] + "...",
                    "stored_hash": stored_hash[:16] + "...",
                })

            prev_hash = stored_hash

        return {
            "valid": len(errors) == 0,
            "total": len(rows),
            "verified": verified,
            "broken_at": broken_at,
            "unchained": unchained,
            "errors": errors,
        }

    def get_chain_status(self) -> Dict[str, Any]:
        """Quick chain health check (summary only).

        Returns:
            Dict with keys: valid, total, verified, unchained
        """
        result = self.verify_chain()
        return {
            "valid": result["valid"],
            "total": result["total"],
            "verified": result["verified"],
            "unchained": result["unchained"],
        }


# Singleton instance for easy access
_logger: Optional[SecurityLogger] = None
_logger_lock = threading.Lock()


def get_logger(redact_logs: bool = True) -> SecurityLogger:
    """Get the singleton security logger instance.

    Args:
        redact_logs: Whether to enable log redaction (default True)

    Returns:
        SecurityLogger instance
    """
    global _logger
    if _logger is None:
        with _logger_lock:
            if _logger is None:
                _logger = SecurityLogger(redact_logs=redact_logs)
    return _logger
