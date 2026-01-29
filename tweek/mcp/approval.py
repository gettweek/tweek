#!/usr/bin/env python3
"""
Tweek MCP Approval Queue

SQLite-backed queue for human-in-the-loop approval of MCP proxy requests.
When the screening pipeline flags a tool call as needing confirmation,
the request is queued here. A separate approval daemon (CLI or web)
reads pending requests and records approve/deny decisions.

Database location: ~/.tweek/approvals.db
"""

import json
import logging
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ApprovalStatus(Enum):
    """Status of an approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass
class ApprovalRequest:
    """A pending or decided approval request."""
    id: str
    timestamp: str
    upstream_server: str
    tool_name: str
    arguments_json: str
    screening_reason: str
    screening_findings_json: str
    risk_level: str
    status: ApprovalStatus
    decided_at: Optional[str]
    decided_by: Optional[str]
    decision_notes: Optional[str]
    timeout_seconds: int

    @property
    def arguments(self) -> Dict[str, Any]:
        """Parse arguments from JSON."""
        try:
            return json.loads(self.arguments_json)
        except (json.JSONDecodeError, TypeError):
            return {}

    @property
    def screening_findings(self) -> List[Dict]:
        """Parse findings from JSON."""
        try:
            return json.loads(self.screening_findings_json)
        except (json.JSONDecodeError, TypeError):
            return []

    @property
    def is_expired(self) -> bool:
        """Check if request has exceeded its timeout."""
        if self.status != ApprovalStatus.PENDING:
            return False
        try:
            ts = datetime.fromisoformat(self.timestamp)
            elapsed = (datetime.utcnow() - ts).total_seconds()
            return elapsed >= self.timeout_seconds
        except (ValueError, TypeError):
            return False

    @property
    def time_remaining(self) -> float:
        """Seconds remaining before timeout. Returns 0 if expired."""
        try:
            ts = datetime.fromisoformat(self.timestamp)
            elapsed = (datetime.utcnow() - ts).total_seconds()
            remaining = self.timeout_seconds - elapsed
            return max(0.0, remaining)
        except (ValueError, TypeError):
            return 0.0

    @property
    def short_id(self) -> str:
        """First 8 characters of the ID for display."""
        return self.id[:8]


class ApprovalQueue:
    """
    SQLite-backed approval queue for MCP proxy requests.

    Stores pending approval requests and their decisions.
    Designed for concurrent access from the proxy (writer)
    and approval daemon (reader/writer).
    """

    DEFAULT_DB_PATH = Path.home() / ".tweek" / "approvals.db"
    DEFAULT_TIMEOUT = 300  # 5 minutes
    MAX_RETRIES = 3
    RETRY_BASE_MS = 100

    def __init__(
        self,
        db_path: Optional[Path] = None,
        default_timeout: int = DEFAULT_TIMEOUT,
    ):
        self.db_path = db_path or self.DEFAULT_DB_PATH
        self.default_timeout = default_timeout
        self._ensure_db_exists()

    def _ensure_db_exists(self):
        """Create database and tables if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with self._get_connection() as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS approval_requests (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                    upstream_server TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    arguments_json TEXT NOT NULL,
                    screening_reason TEXT,
                    screening_findings_json TEXT,
                    risk_level TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    decided_at TEXT,
                    decided_by TEXT,
                    decision_notes TEXT,
                    timeout_seconds INTEGER NOT NULL DEFAULT 300
                );

                CREATE INDEX IF NOT EXISTS idx_approval_status
                    ON approval_requests(status);
                CREATE INDEX IF NOT EXISTS idx_approval_timestamp
                    ON approval_requests(timestamp);
            """)

    @contextmanager
    def _get_connection(self):
        """Get a database connection with WAL mode and proper cleanup."""
        conn = sqlite3.connect(str(self.db_path), timeout=5)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _retry_on_lock(self, func, *args, **kwargs):
        """Retry a function on SQLite OperationalError (lock contention)."""
        for attempt in range(self.MAX_RETRIES):
            try:
                return func(*args, **kwargs)
            except sqlite3.OperationalError as e:
                if "locked" in str(e) and attempt < self.MAX_RETRIES - 1:
                    delay_ms = self.RETRY_BASE_MS * (2 ** attempt)
                    time.sleep(delay_ms / 1000.0)
                    continue
                raise
        return None

    def enqueue(
        self,
        upstream_server: str,
        tool_name: str,
        arguments: Dict[str, Any],
        screening_reason: str,
        screening_findings: List[Dict],
        risk_level: str = "unknown",
        timeout_seconds: Optional[int] = None,
    ) -> str:
        """
        Add a new approval request to the queue.

        Args:
            upstream_server: Name of the upstream MCP server
            tool_name: Original tool name (without namespace prefix)
            arguments: Tool call arguments (will be redacted before storage)
            screening_reason: Why screening flagged this call
            screening_findings: Detailed findings from screening
            risk_level: Risk level from screening (safe/default/risky/dangerous)
            timeout_seconds: Custom timeout, or use default

        Returns:
            UUID string for the new request
        """
        request_id = str(uuid.uuid4())
        timeout = timeout_seconds or self.default_timeout

        # Redact arguments before storage
        redacted_args = self._redact_arguments(arguments)

        def _do_enqueue():
            with self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO approval_requests (
                        id, upstream_server, tool_name, arguments_json,
                        screening_reason, screening_findings_json,
                        risk_level, status, timeout_seconds
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                    """,
                    (
                        request_id,
                        upstream_server,
                        tool_name,
                        json.dumps(redacted_args),
                        screening_reason,
                        json.dumps(screening_findings),
                        risk_level,
                        timeout,
                    ),
                )

            # Log the enqueue event
            try:
                from tweek.logging.security_log import get_logger, SecurityEvent, EventType
                get_logger().log(SecurityEvent(
                    event_type=EventType.MCP_APPROVAL,
                    tool_name="approval_queue",
                    decision="allow",
                    metadata={
                        "upstream_server": upstream_server,
                        "tool_name": tool_name,
                        "screening_reason": screening_reason,
                        "risk_level": risk_level,
                    },
                    source="mcp",
                ))
            except Exception:
                pass

            return request_id

        return self._retry_on_lock(_do_enqueue)

    def get_pending(self) -> List[ApprovalRequest]:
        """Get all pending approval requests, ordered by timestamp."""
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM approval_requests
                WHERE status = 'pending'
                ORDER BY timestamp ASC
                """,
            ).fetchall()

        return [self._row_to_request(row) for row in rows]

    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Get a specific approval request by ID (supports short IDs)."""
        with self._get_connection() as conn:
            # Try exact match first
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE id = ?",
                (request_id,),
            ).fetchone()

            # If not found, try prefix match (short ID)
            if row is None and len(request_id) < 36:
                row = conn.execute(
                    "SELECT * FROM approval_requests WHERE id LIKE ?",
                    (f"{request_id}%",),
                ).fetchone()

        return self._row_to_request(row) if row else None

    def decide(
        self,
        request_id: str,
        status: ApprovalStatus,
        decided_by: str = "cli",
        notes: Optional[str] = None,
    ) -> bool:
        """
        Record a decision for an approval request.

        Args:
            request_id: UUID or short ID of the request
            status: APPROVED or DENIED
            decided_by: Who made the decision ("cli", "web", "timeout")
            notes: Optional notes about the decision

        Returns:
            True if updated, False if not found or not pending
        """
        if status not in (ApprovalStatus.APPROVED, ApprovalStatus.DENIED, ApprovalStatus.EXPIRED):
            raise ValueError(f"Invalid decision status: {status}")

        # Resolve short IDs
        request = self.get_request(request_id)
        if request is None:
            return False
        if request.status != ApprovalStatus.PENDING:
            return False

        full_id = request.id

        def _do_decide():
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    UPDATE approval_requests
                    SET status = ?, decided_at = datetime('now'),
                        decided_by = ?, decision_notes = ?
                    WHERE id = ? AND status = 'pending'
                    """,
                    (status.value, decided_by, notes, full_id),
                )
                updated = cursor.rowcount > 0

            if updated:
                try:
                    from tweek.logging.security_log import get_logger, SecurityEvent, EventType
                    get_logger().log(SecurityEvent(
                        event_type=EventType.MCP_APPROVAL,
                        tool_name="approval_queue",
                        decision="allow" if status == ApprovalStatus.APPROVED else "block",
                        metadata={
                            "request_id": full_id,
                            "status": status.value,
                            "decided_by": decided_by,
                        },
                        source="mcp",
                    ))
                except Exception:
                    pass

            return updated

        return self._retry_on_lock(_do_decide)

    def get_decision(self, request_id: str) -> Optional[ApprovalStatus]:
        """Get the current status for a request."""
        request = self.get_request(request_id)
        return request.status if request else None

    def expire_stale(self) -> int:
        """
        Expire all pending requests that have exceeded their timeout.

        Returns:
            Number of requests expired
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE approval_requests
                SET status = 'expired',
                    decided_at = datetime('now'),
                    decided_by = 'timeout',
                    decision_notes = 'Auto-denied: approval timeout exceeded'
                WHERE status = 'pending'
                AND (
                    julianday('now') - julianday(timestamp)
                ) * 86400.0 >= timeout_seconds
                """,
            )
            count = cursor.rowcount

        if count > 0:
            logger.info(f"Expired {count} stale approval request(s)")

            try:
                from tweek.logging.security_log import get_logger, SecurityEvent, EventType
                get_logger().log(SecurityEvent(
                    event_type=EventType.MCP_APPROVAL,
                    tool_name="approval_queue",
                    decision="block",
                    metadata={
                        "expired_count": count,
                    },
                    source="mcp",
                ))
            except Exception:
                pass

        return count

    def cleanup(self, days: int = 7) -> int:
        """
        Delete old decided/expired requests.

        Args:
            days: Delete requests older than this many days

        Returns:
            Number of requests deleted
        """
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                DELETE FROM approval_requests
                WHERE status != 'pending'
                AND julianday('now') - julianday(timestamp) > ?
                """,
                (days,),
            )
            return cursor.rowcount

    def count_pending(self) -> int:
        """Return the number of pending requests."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM approval_requests WHERE status = 'pending'"
            ).fetchone()
            return row["cnt"] if row else 0

    def get_stats(self) -> Dict[str, int]:
        """Return counts by status."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM approval_requests GROUP BY status"
            ).fetchall()
            return {row["status"]: row["cnt"] for row in rows}

    def _row_to_request(self, row: sqlite3.Row) -> ApprovalRequest:
        """Convert a database row to an ApprovalRequest."""
        return ApprovalRequest(
            id=row["id"],
            timestamp=row["timestamp"],
            upstream_server=row["upstream_server"],
            tool_name=row["tool_name"],
            arguments_json=row["arguments_json"],
            screening_reason=row["screening_reason"] or "",
            screening_findings_json=row["screening_findings_json"] or "[]",
            risk_level=row["risk_level"] or "unknown",
            status=ApprovalStatus(row["status"]),
            decided_at=row["decided_at"],
            decided_by=row["decided_by"],
            decision_notes=row["decision_notes"],
            timeout_seconds=row["timeout_seconds"],
        )

    def _redact_arguments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive data from tool arguments before storage."""
        try:
            from tweek.logging.security_log import LogRedactor
            redactor = LogRedactor(enabled=True)
            return redactor.redact_dict(arguments)
        except ImportError:
            # If logging module unavailable, store as-is
            return arguments
