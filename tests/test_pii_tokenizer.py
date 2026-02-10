#!/usr/bin/env python3
"""
Tests for PII tokenization and de-tokenization.

Verifies that:
- Token store persists and retrieves token mappings correctly
- PII detection works via regex (and Presidio when available)
- Tokenization is deterministic and reversible
- Session scoping isolates tokens
- TTL expiry and cleanup work
- Edge cases are handled (empty content, no PII, overlapping matches)
- CLI commands work end-to-end
"""
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from tweek.security.token_store import TokenStore
from tweek.security.pii_tokenizer import (
    PIIMatch,
    PIITokenizer,
    clear_tokenizer_cache,
    get_tokenizer,
    _check_presidio,
)


pytestmark = pytest.mark.security


# --- Fixtures ---


@pytest.fixture
def db_path(tmp_path):
    """Temporary database path."""
    return tmp_path / "test_tokens.db"


@pytest.fixture
def store(db_path):
    """Fresh token store."""
    s = TokenStore(db_path=db_path)
    yield s
    s.close()


@pytest.fixture
def tokenizer(store):
    """PIITokenizer using regex detection (no Presidio)."""
    return PIITokenizer(
        store=store,
        session_id="test-session-001",
        use_presidio=False,
        enabled=True,
    )


@pytest.fixture(autouse=True)
def clear_cache():
    """Clear tokenizer cache between tests."""
    clear_tokenizer_cache()
    yield
    clear_tokenizer_cache()


# --- TokenStore tests ---


class TestTokenStore:
    def test_store_and_lookup(self, store):
        store.store_token("sess1", "<PII_SSN_abc123>", "123-45-6789", "SSN", "input")
        result = store.lookup_token("<PII_SSN_abc123>", "sess1")
        assert result == "123-45-6789"

    def test_lookup_missing_returns_none(self, store):
        assert store.lookup_token("<PII_SSN_xyz999>", "sess1") is None

    def test_session_isolation(self, store):
        store.store_token("sess1", "<PII_SSN_abc123>", "111-22-3333", "SSN", "input")
        store.store_token("sess2", "<PII_SSN_abc123>", "444-55-6666", "SSN", "input")

        assert store.lookup_token("<PII_SSN_abc123>", "sess1") == "111-22-3333"
        assert store.lookup_token("<PII_SSN_abc123>", "sess2") == "444-55-6666"

    def test_get_session_tokens(self, store):
        store.store_token("sess1", "<PII_SSN_a>", "111-22-3333", "SSN", "input")
        store.store_token("sess1", "<PII_EMAIL_b>", "test@test.com", "EMAIL", "input")
        store.store_token("sess2", "<PII_SSN_c>", "444-55-6666", "SSN", "input")

        tokens = store.get_session_tokens("sess1")
        assert len(tokens) == 2
        assert tokens["<PII_SSN_a>"] == "111-22-3333"
        assert tokens["<PII_EMAIL_b>"] == "test@test.com"

    def test_clear_session(self, store):
        store.store_token("sess1", "<PII_SSN_a>", "111-22-3333", "SSN", "input")
        store.store_token("sess2", "<PII_SSN_b>", "444-55-6666", "SSN", "input")

        deleted = store.clear_session("sess1")
        assert deleted == 1
        assert store.lookup_token("<PII_SSN_a>", "sess1") is None
        assert store.lookup_token("<PII_SSN_b>", "sess2") == "444-55-6666"

    def test_clear_all(self, store):
        store.store_token("sess1", "<PII_SSN_a>", "111-22-3333", "SSN", "input")
        store.store_token("sess2", "<PII_SSN_b>", "444-55-6666", "SSN", "input")

        deleted = store.clear_all()
        assert deleted == 2
        assert store.get_stats()["total_tokens"] == 0

    def test_upsert_same_token(self, store):
        """Storing the same token twice updates the value."""
        store.store_token("sess1", "<PII_SSN_a>", "111-22-3333", "SSN", "input")
        store.store_token("sess1", "<PII_SSN_a>", "999-88-7777", "SSN", "input")

        result = store.lookup_token("<PII_SSN_a>", "sess1")
        assert result == "999-88-7777"

    def test_ttl_expiry(self, store):
        """Tokens with 0 TTL expire immediately."""
        store.store_token(
            "sess1", "<PII_SSN_a>", "111-22-3333", "SSN", "input", ttl_hours=0
        )
        # The token was created with expires_at = now, so lookup should
        # not find it (expires_at <= now)
        time.sleep(0.1)  # Brief pause to ensure expiry
        assert store.lookup_token("<PII_SSN_a>", "sess1") is None

    def test_cleanup_expired(self, store):
        """cleanup_expired removes expired tokens."""
        # Store with 0 TTL (already expired)
        store.store_token(
            "sess1", "<PII_SSN_a>", "111-22-3333", "SSN", "input", ttl_hours=0
        )
        # Store with normal TTL
        store.store_token("sess1", "<PII_SSN_b>", "444-55-6666", "SSN", "input")

        time.sleep(0.1)
        deleted = store.cleanup_expired()
        assert deleted == 1
        assert store.get_stats()["total_tokens"] == 1

    def test_get_stats(self, store):
        store.store_token("sess1", "<PII_SSN_a>", "111-22-3333", "SSN", "input")
        store.store_token("sess2", "<PII_EMAIL_b>", "x@y.com", "EMAIL", "output")

        stats = store.get_stats()
        assert stats["total_tokens"] == 2
        assert stats["active_sessions"] == 2
        assert stats["db_size_bytes"] > 0
        assert stats["oldest_token"] is not None

    def test_direction_tracking(self, store):
        """Input and output tokens are stored separately."""
        store.store_token("sess1", "<PII_SSN_in>", "111-22-3333", "SSN", "input")
        store.store_token("sess1", "<PII_SSN_out>", "444-55-6666", "SSN", "output")

        tokens = store.get_session_tokens("sess1")
        assert len(tokens) == 2


class TestTokenStoreEncryption:
    def test_encrypt_decrypt_roundtrip(self, store):
        """Values survive encrypt→store→retrieve→decrypt cycle."""
        original = "123-45-6789"
        store.store_token("sess1", "<PII_SSN_a>", original, "SSN", "input")
        result = store.lookup_token("<PII_SSN_a>", "sess1")
        assert result == original

    def test_encryption_changes_stored_value(self, db_path):
        """If Fernet is available, stored value differs from original."""
        store = TokenStore(db_path=db_path)
        if store._fernet is None:
            pytest.skip("Fernet not available")

        original = "123-45-6789"
        store.store_token("sess1", "<PII_SSN_a>", original, "SSN", "input")

        # Read raw value from DB
        import sqlite3

        conn = sqlite3.connect(str(db_path))
        row = conn.execute(
            "SELECT original_value FROM pii_tokens WHERE token = '<PII_SSN_a>'"
        ).fetchone()
        conn.close()

        assert row[0] != original  # Should be encrypted
        store.close()


# --- PIITokenizer regex detection tests ---


class TestPIITokenizerRegex:
    def test_tokenize_ssn(self, tokenizer):
        content = "My SSN is 123-45-6789"
        tokenized, matches = tokenizer.tokenize(content)

        assert len(matches) == 1
        assert matches[0].entity_type == "SSN"
        assert matches[0].original_text == "123-45-6789"
        assert "123-45-6789" not in tokenized
        assert "<PII_SSN_" in tokenized

    def test_tokenize_email(self, tokenizer):
        content = "Contact: john.doe@example.com"
        tokenized, matches = tokenizer.tokenize(content)

        assert len(matches) == 1
        assert matches[0].entity_type == "EMAIL"
        assert "john.doe@example.com" not in tokenized
        assert "<PII_EMAIL_" in tokenized

    def test_tokenize_credit_card(self, tokenizer):
        content = "Card: 4532-1234-5678-9012"
        tokenized, matches = tokenizer.tokenize(content)

        assert len(matches) == 1
        assert matches[0].entity_type == "CREDIT_CARD"
        assert "4532-1234-5678-9012" not in tokenized

    def test_tokenize_us_phone(self, tokenizer):
        content = "Call me at (555) 123-4567"
        tokenized, matches = tokenizer.tokenize(content)

        assert len(matches) == 1
        assert matches[0].entity_type == "PHONE"
        assert "(555) 123-4567" not in tokenized

    def test_tokenize_iban(self, tokenizer):
        content = "IBAN: GB29 NWBK 6016 1331 9268 19"
        tokenized, matches = tokenizer.tokenize(content)

        assert len(matches) == 1
        assert matches[0].entity_type == "IBAN"

    def test_tokenize_multiple_pii(self, tokenizer):
        content = "SSN: 123-45-6789, Email: test@example.com"
        tokenized, matches = tokenizer.tokenize(content)

        assert len(matches) == 2
        types = {m.entity_type for m in matches}
        assert "SSN" in types
        assert "EMAIL" in types
        assert "123-45-6789" not in tokenized
        assert "test@example.com" not in tokenized

    def test_deterministic_tokens(self, tokenizer):
        """Same PII always gets the same token in the same session."""
        content1 = "SSN: 123-45-6789"
        content2 = "Another SSN: 123-45-6789"

        _, matches1 = tokenizer.tokenize(content1)
        _, matches2 = tokenizer.tokenize(content2)

        assert matches1[0].token == matches2[0].token

    def test_different_pii_different_tokens(self, tokenizer):
        # Note: SSN regex excludes 9xx prefixes (invalid SSNs), so use valid prefixes
        content = "SSN1: 123-45-6789, SSN2: 456-78-1234"
        _, matches = tokenizer.tokenize(content)

        assert len(matches) == 2
        assert matches[0].token != matches[1].token


class TestDetokenize:
    def test_roundtrip(self, tokenizer):
        """tokenize → detokenize recovers original content."""
        original = "My SSN is 123-45-6789 and email is test@example.com"
        tokenized, matches = tokenizer.tokenize(original)

        assert len(matches) == 2
        assert "123-45-6789" not in tokenized
        assert "test@example.com" not in tokenized

        restored = tokenizer.detokenize(tokenized)
        assert restored == original

    def test_detokenize_no_tokens(self, tokenizer):
        content = "No PII tokens here"
        assert tokenizer.detokenize(content) == content

    def test_detokenize_unknown_token(self, tokenizer):
        """Unknown tokens are left as-is."""
        content = "Value: <PII_SSN_zzzzzz>"
        assert tokenizer.detokenize(content) == content

    def test_detokenize_partial(self, tokenizer):
        """Only known tokens are replaced."""
        # Tokenize one value
        tokenizer.tokenize("SSN: 123-45-6789")

        # Content has both known and unknown tokens
        content = "Known: <PII_SSN_" + tokenizer._generate_token("SSN", "123-45-6789")[9:] + " Unknown: <PII_SSN_ffffff>"
        restored = tokenizer.detokenize(content)

        assert "123-45-6789" in restored
        assert "<PII_SSN_ffffff>" in restored  # Unknown left as-is


class TestTokenFormat:
    def test_token_format_valid(self, tokenizer):
        content = "SSN: 123-45-6789"
        _, matches = tokenizer.tokenize(content)

        token = matches[0].token
        assert token.startswith("<PII_SSN_")
        assert token.endswith(">")
        # Hash part is 6 hex chars
        hash_part = token[len("<PII_SSN_"):-1]
        assert len(hash_part) == 6
        assert all(c in "0123456789abcdef" for c in hash_part)

    def test_token_regex_matches(self, tokenizer):
        """TOKEN_PATTERN correctly matches generated tokens."""
        content = "SSN: 123-45-6789"
        tokenized, _ = tokenizer.tokenize(content)

        import re
        found = PIITokenizer.TOKEN_PATTERN.findall(tokenized)
        assert len(found) == 1
        assert found[0][0] == "SSN"
        assert len(found[0][1]) == 6


class TestEdgeCases:
    def test_empty_content(self, tokenizer):
        tokenized, matches = tokenizer.tokenize("")
        assert tokenized == ""
        assert matches == []

    def test_no_pii(self, tokenizer):
        content = "Just a normal sentence with no sensitive data."
        tokenized, matches = tokenizer.tokenize(content)
        assert tokenized == content
        assert matches == []

    def test_disabled_tokenizer(self, store):
        tokenizer = PIITokenizer(
            store=store, session_id="s", use_presidio=False, enabled=False
        )
        content = "SSN: 123-45-6789"
        tokenized, matches = tokenizer.tokenize(content)
        assert tokenized == content
        assert matches == []

    def test_very_long_content(self, tokenizer):
        """Tokenizer handles large content without issues."""
        padding = "x" * 10000
        content = f"{padding} SSN: 123-45-6789 {padding}"
        tokenized, matches = tokenizer.tokenize(content)
        assert len(matches) == 1
        assert "123-45-6789" not in tokenized

    def test_none_content_detokenize(self, tokenizer):
        assert tokenizer.detokenize("") == ""

    def test_direction_input_vs_output(self, tokenizer):
        """Tokens from input direction are retrievable."""
        content = "SSN: 123-45-6789"
        tokenizer.tokenize(content, direction="input")
        tokenizer.tokenize(content, direction="output")

        tokens = tokenizer._store.get_session_tokens(tokenizer._session_id)
        # Same token should be stored (deterministic)
        assert len(tokens) >= 1


class TestPresidioIntegration:
    """Tests for Presidio integration (skipped if not installed)."""

    @pytest.fixture
    def presidio_tokenizer(self, store):
        if not _check_presidio():
            pytest.skip("Presidio not installed")
        return PIITokenizer(
            store=store,
            session_id="presidio-test",
            use_presidio=True,
            enabled=True,
        )

    def test_presidio_detects_ssn(self, presidio_tokenizer):
        content = "My SSN is 123-45-6789"
        tokenized, matches = presidio_tokenizer.tokenize(content)
        assert len(matches) >= 1
        assert "123-45-6789" not in tokenized

    def test_presidio_detects_email(self, presidio_tokenizer):
        content = "Email: john.doe@example.com"
        tokenized, matches = presidio_tokenizer.tokenize(content)
        assert len(matches) >= 1
        assert "john.doe@example.com" not in tokenized

    def test_presidio_roundtrip(self, presidio_tokenizer):
        original = "SSN: 123-45-6789"
        tokenized, _ = presidio_tokenizer.tokenize(original)
        restored = presidio_tokenizer.detokenize(tokenized)
        assert restored == original


class TestHookIntegration:
    """Test the full pre-hook → post-hook tokenization lifecycle."""

    def test_prehook_tokenize_posthook_detokenize(self, store):
        """Simulate pre-hook tokenization and post-hook de-tokenization."""
        session_id = "hook-test-session"

        # Pre-hook: tokenize user input
        pre_tokenizer = PIITokenizer(
            store=store, session_id=session_id, use_presidio=False, enabled=True
        )
        user_input = "Send to 123-45-6789 at test@example.com"
        tokenized_input, matches = pre_tokenizer.tokenize(user_input, direction="input")

        assert len(matches) == 2
        assert "123-45-6789" not in tokenized_input
        assert "test@example.com" not in tokenized_input

        # Post-hook: de-tokenize the response that echoes back tokens
        post_tokenizer = PIITokenizer(
            store=store, session_id=session_id, use_presidio=False, enabled=True
        )
        # Simulate AI response that contains the tokens
        ai_response = f"I'll send to {matches[0].token} at {matches[1].token}"
        restored = post_tokenizer.detokenize(ai_response)

        assert "123-45-6789" in restored
        assert "test@example.com" in restored

    def test_cross_session_isolation(self, store):
        """Tokens from session A can't be resolved in session B."""
        tok_a = PIITokenizer(
            store=store, session_id="session-A", use_presidio=False, enabled=True
        )
        tok_b = PIITokenizer(
            store=store, session_id="session-B", use_presidio=False, enabled=True
        )

        tokenized, matches = tok_a.tokenize("SSN: 123-45-6789")
        assert len(matches) == 1

        # Session B cannot detokenize session A's tokens
        result = tok_b.detokenize(tokenized)
        assert "123-45-6789" not in result  # Token stays as-is


class TestGetTokenizer:
    def test_factory_creates_tokenizer(self, db_path):
        tok = get_tokenizer(session_id="test", db_path=db_path)
        assert tok.is_enabled()

    def test_factory_caches_tokenizer(self, db_path):
        tok1 = get_tokenizer(session_id="test", db_path=db_path)
        tok2 = get_tokenizer(session_id="test", db_path=db_path)
        assert tok1 is tok2

    def test_factory_different_sessions(self, db_path):
        tok1 = get_tokenizer(session_id="s1", db_path=db_path)
        tok2 = get_tokenizer(session_id="s2", db_path=db_path)
        assert tok1 is not tok2

    def test_disabled_via_config(self, db_path, tmp_path, monkeypatch):
        """Tokenizer respects .tweek.yaml enabled=false."""
        config_path = tmp_path / ".tweek.yaml"
        config_path.write_text("pii:\n  enabled: false\n")
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        clear_tokenizer_cache()
        tok = get_tokenizer(session_id="test-disabled", db_path=db_path)
        assert not tok.is_enabled()


class TestCLIPII:
    def test_pii_status(self, db_path):
        from click.testing import CliRunner
        from tweek.cli_pii import pii_status

        store = TokenStore(db_path=db_path)
        store.store_token("s1", "<PII_SSN_a>", "111-22-3333", "SSN", "input")
        store.close()

        runner = CliRunner()
        with patch("tweek.cli_pii._get_store", return_value=TokenStore(db_path=db_path)):
            result = runner.invoke(pii_status)
        assert result.exit_code == 0
        assert "token" in result.output.lower() or "1" in result.output

    def test_pii_cleanup(self, db_path):
        from click.testing import CliRunner
        from tweek.cli_pii import pii_cleanup

        store = TokenStore(db_path=db_path)
        store.store_token("s1", "<PII_SSN_a>", "111-22-3333", "SSN", "input", ttl_hours=0)
        store.close()

        runner = CliRunner()
        time.sleep(0.1)
        with patch("tweek.cli_pii._get_store", return_value=TokenStore(db_path=db_path)):
            result = runner.invoke(pii_cleanup)
        assert result.exit_code == 0

    def test_pii_cleanup_all(self, db_path):
        from click.testing import CliRunner
        from tweek.cli_pii import pii_cleanup

        store = TokenStore(db_path=db_path)
        store.store_token("s1", "<PII_SSN_a>", "111-22-3333", "SSN", "input")
        store.close()

        runner = CliRunner()
        with patch("tweek.cli_pii._get_store", return_value=TokenStore(db_path=db_path)):
            result = runner.invoke(pii_cleanup, ["--all"])
        assert result.exit_code == 0

    def test_pii_test_command(self, db_path):
        from click.testing import CliRunner
        from tweek.cli_pii import pii_test

        runner = CliRunner()
        with patch("tweek.cli_pii._get_store", return_value=TokenStore(db_path=db_path)):
            result = runner.invoke(pii_test, ["My SSN is 123-45-6789"])
        assert result.exit_code == 0
        assert "SSN" in result.output or "PII" in result.output
