#!/usr/bin/env python3
"""
Tweek Security Logger

SQLite-based audit logging for security events.
Logs all tool/skill invocations, screening decisions, and user responses.

Database location: ~/.tweek/security.db
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any


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
    """SQLite-based security event logger."""

    DEFAULT_DB_PATH = Path.home() / ".tweek" / "security.db"

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize the security logger.

        Args:
            db_path: Path to SQLite database. Defaults to ~/.tweek/security.db
        """
        self.db_path = db_path or self.DEFAULT_DB_PATH
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
        """Log a security event.

        Args:
            event: The security event to log

        Returns:
            The row ID of the inserted event
        """
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
                event.command,
                event.tier,
                event.pattern_name,
                event.pattern_severity,
                event.decision,
                event.decision_reason,
                event.user_response,
                event.session_id,
                event.working_directory,
                json.dumps(event.metadata) if event.metadata else None
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


def get_logger() -> SecurityLogger:
    """Get the singleton security logger instance."""
    global _logger
    if _logger is None:
        _logger = SecurityLogger()
    return _logger
