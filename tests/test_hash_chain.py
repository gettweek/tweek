#!/usr/bin/env python3
"""
Tests for hash-chained audit log integrity.

Verifies that:
- Each log entry gets a SHA-256 hash chaining from the previous entry
- Chain verification detects tampering (modified rows)
- Chain verification detects deletions (missing rows)
- Legacy entries (no hash) are handled gracefully
- CLI `tweek logs verify` works end-to-end
"""
import json
import sqlite3

import pytest

from tweek.logging.security_log import (
    EventType,
    SecurityEvent,
    SecurityLogger,
)


pytestmark = pytest.mark.security


# --- Fixtures ---


@pytest.fixture
def db_path(tmp_path):
    """Return a temporary database path."""
    return tmp_path / "test_security.db"


@pytest.fixture
def logger(db_path):
    """Create a SecurityLogger with a temporary database."""
    return SecurityLogger(db_path=db_path, redact_logs=False)


def _make_event(
    event_type=EventType.TOOL_INVOKED,
    tool_name="Bash",
    command="ls",
    decision="allow",
    **kwargs,
):
    """Helper to create a SecurityEvent with defaults."""
    return SecurityEvent(
        event_type=event_type,
        tool_name=tool_name,
        command=command,
        decision=decision,
        **kwargs,
    )


# --- Core hash chain tests ---


class TestEntryHash:
    """Test that log entries get hash values."""

    def test_first_entry_has_hash(self, logger, db_path):
        """First entry should have an entry_hash."""
        logger.log(_make_event())
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT entry_hash FROM security_events").fetchone()
        conn.close()
        assert row["entry_hash"] is not None
        assert len(row["entry_hash"]) == 64  # SHA-256 hex digest

    def test_multiple_entries_have_different_hashes(self, logger, db_path):
        """Each entry should have a unique hash."""
        logger.log(_make_event(command="ls"))
        logger.log(_make_event(command="pwd"))
        logger.log(_make_event(command="whoami"))

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT entry_hash FROM security_events ORDER BY id"
        ).fetchall()
        conn.close()

        hashes = [r["entry_hash"] for r in rows]
        assert len(hashes) == 3
        assert len(set(hashes)) == 3  # All unique

    def test_identical_events_get_different_hashes(self, logger, db_path):
        """Even identical events should get different hashes due to chaining."""
        logger.log(_make_event(command="ls"))
        logger.log(_make_event(command="ls"))

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT entry_hash FROM security_events ORDER BY id"
        ).fetchall()
        conn.close()

        assert rows[0]["entry_hash"] != rows[1]["entry_hash"]

    def test_hash_chains_from_previous(self, logger, db_path):
        """Second entry's hash should depend on first entry's hash."""
        logger.log(_make_event(command="first"))

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        first_hash = conn.execute(
            "SELECT entry_hash FROM security_events"
        ).fetchone()["entry_hash"]
        conn.close()

        logger.log(_make_event(command="second"))

        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT entry_hash FROM security_events ORDER BY id"
        ).fetchall()
        conn.close()

        # Verify second hash is built from first hash
        expected = SecurityLogger._compute_entry_hash(
            prev_hash=first_hash,
            event_type="tool_invoked",
            tool_name="Bash",
            command="second",
            decision="allow",
        )
        assert rows[1]["entry_hash"] == expected


class TestComputeEntryHash:
    """Test the canonical hash computation."""

    def test_deterministic(self):
        """Same inputs should always produce the same hash."""
        h1 = SecurityLogger._compute_entry_hash(
            prev_hash="abc",
            event_type="tool_invoked",
            tool_name="Bash",
            command="ls",
        )
        h2 = SecurityLogger._compute_entry_hash(
            prev_hash="abc",
            event_type="tool_invoked",
            tool_name="Bash",
            command="ls",
        )
        assert h1 == h2

    def test_different_prev_hash_changes_result(self):
        """Different previous hash should produce different result."""
        h1 = SecurityLogger._compute_entry_hash(
            prev_hash="hash1",
            event_type="tool_invoked",
            tool_name="Bash",
        )
        h2 = SecurityLogger._compute_entry_hash(
            prev_hash="hash2",
            event_type="tool_invoked",
            tool_name="Bash",
        )
        assert h1 != h2

    def test_different_fields_change_result(self):
        """Different event fields should produce different hashes."""
        h1 = SecurityLogger._compute_entry_hash(
            prev_hash="",
            event_type="tool_invoked",
            tool_name="Bash",
            command="ls",
        )
        h2 = SecurityLogger._compute_entry_hash(
            prev_hash="",
            event_type="tool_invoked",
            tool_name="Bash",
            command="pwd",
        )
        assert h1 != h2

    def test_genesis_from_empty_string(self):
        """First entry should chain from empty string."""
        h = SecurityLogger._compute_entry_hash(
            prev_hash="",
            event_type="tool_invoked",
            tool_name="Bash",
        )
        assert len(h) == 64
        assert h != ""

    def test_none_fields_handled(self):
        """None values should be handled without error."""
        h = SecurityLogger._compute_entry_hash(
            prev_hash="",
            event_type="tool_invoked",
            tool_name="Bash",
            command=None,
            tier=None,
            pattern_name=None,
            metadata_json=None,
        )
        assert len(h) == 64


class TestVerifyChain:
    """Test hash chain verification."""

    def test_empty_chain_is_valid(self, logger):
        """Empty database should verify as valid."""
        result = logger.verify_chain()
        assert result["valid"] is True
        assert result["total"] == 0
        assert result["verified"] == 0

    def test_single_entry_chain(self, logger):
        """Single entry should verify."""
        logger.log(_make_event())
        result = logger.verify_chain()
        assert result["valid"] is True
        assert result["total"] == 1
        assert result["verified"] == 1

    def test_multi_entry_chain(self, logger):
        """Multiple entries should all verify."""
        for i in range(10):
            logger.log(_make_event(command=f"cmd_{i}"))

        result = logger.verify_chain()
        assert result["valid"] is True
        assert result["total"] == 10
        assert result["verified"] == 10
        assert result["unchained"] == 0
        assert result["errors"] == []

    def test_detects_tampered_entry(self, logger, db_path):
        """Modifying a row's data should break the chain."""
        logger.log(_make_event(command="first"))
        logger.log(_make_event(command="second"))
        logger.log(_make_event(command="third"))

        # Tamper with the second entry
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "UPDATE security_events SET command = 'TAMPERED' WHERE id = 2"
        )
        conn.commit()
        conn.close()

        result = logger.verify_chain()
        assert result["valid"] is False
        assert result["broken_at"] == 2
        assert len(result["errors"]) >= 1
        assert result["errors"][0]["id"] == 2

    def test_detects_tampered_hash(self, logger, db_path):
        """Directly modifying an entry_hash should break the chain."""
        logger.log(_make_event(command="first"))
        logger.log(_make_event(command="second"))

        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "UPDATE security_events SET entry_hash = 'fakehash' WHERE id = 1"
        )
        conn.commit()
        conn.close()

        result = logger.verify_chain()
        assert result["valid"] is False
        # First entry's hash is wrong, AND second entry can't chain from it
        assert len(result["errors"]) >= 1

    def test_detects_deleted_middle_entry(self, logger, db_path):
        """Deleting a middle entry should break the chain."""
        logger.log(_make_event(command="first"))
        logger.log(_make_event(command="second"))
        logger.log(_make_event(command="third"))

        # Delete the middle entry
        conn = sqlite3.connect(str(db_path))
        conn.execute("DELETE FROM security_events WHERE id = 2")
        conn.commit()
        conn.close()

        result = logger.verify_chain()
        assert result["valid"] is False
        # Entry 3 expects entry 2's hash as prev, but now chains from entry 1
        assert result["broken_at"] == 3

    def test_handles_legacy_entries(self, logger, db_path):
        """Entries without hashes (legacy) should be counted but not break verification."""
        # Insert a legacy entry directly (no entry_hash)
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            INSERT INTO security_events (event_type, tool_name, command, decision)
            VALUES ('tool_invoked', 'Bash', 'legacy_cmd', 'allow')
        """)
        conn.commit()
        conn.close()

        # Now log a new entry (will chain from empty since legacy has no hash)
        logger.log(_make_event(command="new_cmd"))

        result = logger.verify_chain()
        assert result["valid"] is True
        assert result["unchained"] == 1
        assert result["verified"] == 1
        assert result["total"] == 2

    def test_mixed_legacy_and_chained(self, logger, db_path):
        """Legacy entries followed by chained entries should work."""
        # Insert 3 legacy entries
        conn = sqlite3.connect(str(db_path))
        for i in range(3):
            conn.execute("""
                INSERT INTO security_events (event_type, tool_name, command, decision)
                VALUES ('tool_invoked', 'Bash', ?, 'allow')
            """, (f"legacy_{i}",))
        conn.commit()
        conn.close()

        # Log 3 chained entries
        for i in range(3):
            logger.log(_make_event(command=f"chained_{i}"))

        result = logger.verify_chain()
        assert result["valid"] is True
        assert result["unchained"] == 3
        assert result["verified"] == 3
        assert result["total"] == 6


class TestGetChainStatus:
    """Test the quick chain status method."""

    def test_empty_status(self, logger):
        result = logger.get_chain_status()
        assert result["valid"] is True
        assert result["total"] == 0

    def test_clean_status(self, logger):
        logger.log(_make_event())
        logger.log(_make_event(command="two"))
        result = logger.get_chain_status()
        assert result["valid"] is True
        assert result["total"] == 2
        assert result["verified"] == 2
        assert result["unchained"] == 0

    def test_broken_status(self, logger, db_path):
        logger.log(_make_event())
        logger.log(_make_event(command="two"))

        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "UPDATE security_events SET command = 'TAMPERED' WHERE id = 1"
        )
        conn.commit()
        conn.close()

        result = logger.get_chain_status()
        assert result["valid"] is False


class TestSchemaMigration:
    """Test that hash chain works with migrated databases."""

    def test_migration_adds_entry_hash_column(self, db_path):
        """Existing DB without entry_hash should get the column added."""
        # Create a DB with the old schema (no entry_hash)
        conn = sqlite3.connect(str(db_path))
        conn.execute("""
            CREATE TABLE security_events (
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
                source TEXT
            )
        """)
        # Insert a legacy row
        conn.execute("""
            INSERT INTO security_events (event_type, tool_name, decision)
            VALUES ('tool_invoked', 'Bash', 'allow')
        """)
        conn.commit()
        conn.close()

        # Now open with SecurityLogger — should migrate
        logger = SecurityLogger(db_path=db_path, redact_logs=False)

        # Legacy entry should exist without hash
        result = logger.verify_chain()
        assert result["total"] == 1
        assert result["unchained"] == 1

        # New entries should get hashes
        logger.log(_make_event(command="post_migration"))
        result = logger.verify_chain()
        assert result["valid"] is True
        assert result["verified"] == 1
        assert result["unchained"] == 1


class TestVerifyWithMetadata:
    """Test hash chain with complex event data."""

    def test_metadata_included_in_hash(self, logger, db_path):
        """Metadata changes should be detected by the chain."""
        logger.log(_make_event(
            command="cmd1",
            metadata={"key": "value", "nested": {"a": 1}},
        ))
        logger.log(_make_event(command="cmd2"))

        # Tamper with metadata
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "UPDATE security_events SET metadata_json = '{\"key\": \"TAMPERED\"}' WHERE id = 1"
        )
        conn.commit()
        conn.close()

        result = logger.verify_chain()
        assert result["valid"] is False

    def test_all_fields_contribute_to_hash(self, logger, db_path):
        """Tampering any field should break the chain."""
        logger.log(_make_event(
            command="test",
            tier="critical",
            pattern_name="test_pattern",
            pattern_severity="high",
            decision="block",
            decision_reason="suspicious",
            session_id="sess-123",
            correlation_id="corr-456",
            source="hooks",
        ))
        logger.log(_make_event(command="next"))

        # Tamper with tier
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "UPDATE security_events SET tier = 'low' WHERE id = 1"
        )
        conn.commit()
        conn.close()

        result = logger.verify_chain()
        assert result["valid"] is False


class TestCLIVerify:
    """Test the CLI verify command."""

    def test_verify_empty_db(self, tmp_path, monkeypatch):
        """Verify on empty DB should succeed."""
        from click.testing import CliRunner
        from tweek.cli_logs import logs_verify

        db_path = tmp_path / "test.db"
        # Create logger to initialize DB
        SecurityLogger(db_path=db_path, redact_logs=False)

        monkeypatch.setattr(
            "tweek.logging.security_log._logger",
            SecurityLogger(db_path=db_path, redact_logs=False),
        )

        runner = CliRunner()
        result = runner.invoke(logs_verify, [])
        assert result.exit_code == 0
        assert "No log entries" in result.output

    def test_verify_clean_chain(self, tmp_path, monkeypatch):
        """Verify on clean chain should succeed."""
        from click.testing import CliRunner
        from tweek.cli_logs import logs_verify

        db_path = tmp_path / "test.db"
        test_logger = SecurityLogger(db_path=db_path, redact_logs=False)
        test_logger.log(_make_event(command="a"))
        test_logger.log(_make_event(command="b"))

        monkeypatch.setattr(
            "tweek.logging.security_log._logger",
            test_logger,
        )

        runner = CliRunner()
        result = runner.invoke(logs_verify, [])
        assert result.exit_code == 0
        assert "verified" in result.output

    def test_verify_broken_chain(self, tmp_path, monkeypatch):
        """Verify on broken chain should exit 1."""
        from click.testing import CliRunner
        from tweek.cli_logs import logs_verify

        db_path = tmp_path / "test.db"
        test_logger = SecurityLogger(db_path=db_path, redact_logs=False)
        test_logger.log(_make_event(command="a"))
        test_logger.log(_make_event(command="b"))

        # Tamper
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "UPDATE security_events SET command = 'X' WHERE id = 1"
        )
        conn.commit()
        conn.close()

        monkeypatch.setattr(
            "tweek.logging.security_log._logger",
            test_logger,
        )

        runner = CliRunner()
        result = runner.invoke(logs_verify, [])
        assert result.exit_code == 1
        assert "BROKEN" in result.output

    def test_verify_json_output(self, tmp_path, monkeypatch):
        """Verify with --json should output valid JSON."""
        from click.testing import CliRunner
        from tweek.cli_logs import logs_verify

        db_path = tmp_path / "test.db"
        test_logger = SecurityLogger(db_path=db_path, redact_logs=False)
        test_logger.log(_make_event(command="a"))

        monkeypatch.setattr(
            "tweek.logging.security_log._logger",
            test_logger,
        )

        runner = CliRunner()
        result = runner.invoke(logs_verify, ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["valid"] is True
        assert data["verified"] == 1

    def test_verify_quiet_clean(self, tmp_path, monkeypatch):
        """Verify --quiet on clean chain should produce no output."""
        from click.testing import CliRunner
        from tweek.cli_logs import logs_verify

        db_path = tmp_path / "test.db"
        test_logger = SecurityLogger(db_path=db_path, redact_logs=False)
        test_logger.log(_make_event(command="a"))

        monkeypatch.setattr(
            "tweek.logging.security_log._logger",
            test_logger,
        )

        runner = CliRunner()
        result = runner.invoke(logs_verify, ["--quiet"])
        assert result.exit_code == 0
        assert result.output.strip() == ""
