#!/usr/bin/env python3
"""
Tweek PII Token Store — SQLite-backed reversible token persistence.

Stores mappings between PII tokens and original values, scoped by session.
Supports TTL-based expiry and optional Fernet encryption at rest.

Used by PIITokenizer to persist token mappings across pre-hook and post-hook
invocations within the same Claude Code session.
"""
from __future__ import annotations

import base64
import hashlib
import os
import platform
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional


# Optional encryption
_HAS_FERNET = None


def _check_fernet() -> bool:
    """Check if Fernet encryption is available (cached)."""
    global _HAS_FERNET
    if _HAS_FERNET is None:
        try:
            from cryptography.fernet import Fernet  # noqa: F401

            _HAS_FERNET = True
        except ImportError:
            _HAS_FERNET = False
    return _HAS_FERNET


def _get_machine_key() -> bytes:
    """Derive a stable encryption key from machine identity.

    Uses platform node (MAC address / machine name) + username as seed.
    This is NOT cryptographically strong — it's defense-in-depth to prevent
    casual reading of the SQLite file. The real security boundary is
    filesystem permissions on ~/.tweek/.
    """
    seed = f"tweek-pii-{platform.node()}-{os.getenv('USER', 'unknown')}"
    key_bytes = hashlib.sha256(seed.encode()).digest()
    return base64.urlsafe_b64encode(key_bytes)


class TokenStore:
    """SQLite-backed storage for PII token mappings.

    Stores reversible mappings between tokens (e.g. <PII_SSN_a1b2c3>) and
    their original PII values, scoped by Claude Code session ID.

    Features:
    - WAL mode for concurrent access from pre/post hooks
    - Session-scoped isolation (tokens don't leak across sessions)
    - TTL-based automatic expiry
    - Optional Fernet encryption of original values at rest
    """

    DEFAULT_DB_PATH = Path.home() / ".tweek" / "pii_tokens.db"
    DEFAULT_TTL_HOURS = 24

    def __init__(
        self,
        db_path: Optional[Path] = None,
        ttl_hours: int = DEFAULT_TTL_HOURS,
    ):
        self.db_path = db_path or self.DEFAULT_DB_PATH
        self.ttl_hours = ttl_hours
        self._conn: Optional[sqlite3.Connection] = None
        self._fernet = None
        self._init_encryption()
        self._ensure_db()

    def _init_encryption(self) -> None:
        """Initialize Fernet encryption if available."""
        if _check_fernet():
            try:
                from cryptography.fernet import Fernet

                self._fernet = Fernet(_get_machine_key())
            except Exception:
                self._fernet = None

    def _encrypt(self, plaintext: str) -> str:
        """Encrypt a value. Returns plaintext if Fernet unavailable."""
        if self._fernet:
            try:
                return self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")
            except Exception:
                pass
        return plaintext

    def _decrypt(self, ciphertext: str) -> str:
        """Decrypt a value. Returns ciphertext as-is if not encrypted."""
        if self._fernet:
            try:
                return self._fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
            except Exception:
                # Not encrypted or key changed — return as-is
                return ciphertext
        return ciphertext

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create a persistent database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(
                str(self.db_path),
                timeout=5,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
        return self._conn

    def _ensure_db(self) -> None:
        """Create database and schema if they don't exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(str(self.db_path.parent), 0o700)
        except OSError:
            pass

        conn = self._get_connection()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS pii_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                token TEXT NOT NULL,
                original_value TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                direction TEXT NOT NULL DEFAULT 'input',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                UNIQUE(session_id, token)
            );

            CREATE INDEX IF NOT EXISTS idx_pii_session
                ON pii_tokens(session_id);
            CREATE INDEX IF NOT EXISTS idx_pii_token
                ON pii_tokens(token);
            CREATE INDEX IF NOT EXISTS idx_pii_expires
                ON pii_tokens(expires_at);
        """)
        conn.commit()

    def store_token(
        self,
        session_id: str,
        token: str,
        original: str,
        entity_type: str,
        direction: str = "input",
        ttl_hours: Optional[int] = None,
    ) -> None:
        """Store a token→PII mapping.

        Args:
            session_id: Claude Code session identifier
            token: The replacement token (e.g. <PII_SSN_a1b2c3>)
            original: The original PII value
            entity_type: PII type (e.g. SSN, EMAIL, CC)
            direction: 'input' or 'output'
            ttl_hours: Override default TTL
        """
        ttl = ttl_hours if ttl_hours is not None else self.ttl_hours
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=ttl)

        encrypted_original = self._encrypt(original)

        # Use SQLite-compatible timestamp format (no timezone suffix)
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")
        expires_str = expires.strftime("%Y-%m-%d %H:%M:%S")

        conn = self._get_connection()
        conn.execute(
            """INSERT OR REPLACE INTO pii_tokens
               (session_id, token, original_value, entity_type, direction, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                token,
                encrypted_original,
                entity_type,
                direction,
                now_str,
                expires_str,
            ),
        )
        conn.commit()

    def lookup_token(self, token: str, session_id: str) -> Optional[str]:
        """Look up the original PII value for a token.

        Args:
            token: The replacement token
            session_id: Session to search in

        Returns:
            Original PII value, or None if not found/expired
        """
        conn = self._get_connection()
        row = conn.execute(
            """SELECT original_value FROM pii_tokens
               WHERE token = ? AND session_id = ?
               AND expires_at > datetime('now')""",
            (token, session_id),
        ).fetchone()

        if row:
            return self._decrypt(row["original_value"])
        return None

    def get_session_tokens(self, session_id: str) -> Dict[str, str]:
        """Get all active token→original mappings for a session.

        Returns:
            Dict mapping token strings to original PII values
        """
        conn = self._get_connection()
        rows = conn.execute(
            """SELECT token, original_value FROM pii_tokens
               WHERE session_id = ?
               AND expires_at > datetime('now')""",
            (session_id,),
        ).fetchall()

        return {row["token"]: self._decrypt(row["original_value"]) for row in rows}

    def cleanup_expired(self) -> int:
        """Delete expired tokens.

        Returns:
            Number of tokens deleted
        """
        conn = self._get_connection()
        cursor = conn.execute(
            "DELETE FROM pii_tokens WHERE expires_at <= datetime('now')"
        )
        conn.commit()
        return cursor.rowcount

    def clear_session(self, session_id: str) -> int:
        """Delete all tokens for a session.

        Returns:
            Number of tokens deleted
        """
        conn = self._get_connection()
        cursor = conn.execute(
            "DELETE FROM pii_tokens WHERE session_id = ?",
            (session_id,),
        )
        conn.commit()
        return cursor.rowcount

    def clear_all(self) -> int:
        """Delete all tokens.

        Returns:
            Number of tokens deleted
        """
        conn = self._get_connection()
        cursor = conn.execute("DELETE FROM pii_tokens")
        conn.commit()
        return cursor.rowcount

    def get_stats(self) -> Dict:
        """Get token store statistics.

        Returns:
            Dict with total_tokens, active_sessions, db_size_bytes, oldest_token
        """
        conn = self._get_connection()
        total = conn.execute("SELECT COUNT(*) as c FROM pii_tokens").fetchone()["c"]
        active = conn.execute(
            """SELECT COUNT(DISTINCT session_id) as c FROM pii_tokens
               WHERE expires_at > datetime('now')"""
        ).fetchone()["c"]
        oldest = conn.execute(
            "SELECT MIN(created_at) as t FROM pii_tokens"
        ).fetchone()["t"]

        db_size = 0
        try:
            db_size = self.db_path.stat().st_size
        except OSError:
            pass

        return {
            "total_tokens": total,
            "active_sessions": active,
            "db_size_bytes": db_size,
            "oldest_token": oldest,
        }

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
