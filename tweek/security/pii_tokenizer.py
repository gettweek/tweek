#!/usr/bin/env python3
"""
Tweek PII Tokenizer — Reversible PII replacement for AI tool calls.

Detects PII in content and replaces it with deterministic tokens that can
be reversed later. Uses Microsoft Presidio when available, falls back to
regex patterns from pii_scanner.py.

Token lifecycle:
1. Pre-hook: tokenize() replaces PII with <PII_TYPE_hash> tokens
2. Token mapping stored in SQLite (session-scoped)
3. Post-hook: detokenize() restores original PII values

Designed as a hook-layer integration — screening plugins detect PII,
the tokenizer performs the actual replacement.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from tweek.security.token_store import TokenStore


# --- Presidio availability check ---

_HAS_PRESIDIO = None


def _check_presidio() -> bool:
    """Check if Presidio analyzer is available (cached)."""
    global _HAS_PRESIDIO
    if _HAS_PRESIDIO is None:
        try:
            from presidio_analyzer import AnalyzerEngine  # noqa: F401

            _HAS_PRESIDIO = True
        except ImportError:
            _HAS_PRESIDIO = False
    return _HAS_PRESIDIO


# --- Data structures ---


@dataclass
class PIIMatch:
    """A single PII entity detected in content."""

    entity_type: str  # e.g. SSN, EMAIL, CREDIT_CARD
    start: int  # Start offset in original content
    end: int  # End offset in original content
    original_text: str  # The raw PII value
    token: str  # The replacement token
    score: float = 1.0  # Detection confidence (0.0-1.0)
    source: str = "regex"  # 'presidio' or 'regex'


# --- Entity type mapping ---

# Map pii_scanner.py pattern names to normalized entity types
_REGEX_TYPE_MAP = {
    "pii_email_address": "EMAIL",
    "pii_us_ssn": "SSN",
    "pii_credit_card": "CREDIT_CARD",
    "pii_us_phone": "PHONE",
    "pii_intl_phone": "PHONE",
    "pii_iban": "IBAN",
}

# Map Presidio entity types to our normalized types
_PRESIDIO_TYPE_MAP = {
    "EMAIL_ADDRESS": "EMAIL",
    "US_SSN": "SSN",
    "CREDIT_CARD": "CREDIT_CARD",
    "PHONE_NUMBER": "PHONE",
    "US_BANK_NUMBER": "BANK",
    "IBAN_CODE": "IBAN",
}


# --- Core tokenizer ---


class PIITokenizer:
    """Reversible PII tokenization with session-scoped token storage.

    Detects PII using Presidio (preferred) or regex fallback, replaces
    with deterministic tokens, and stores mappings for later reversal.

    Token format: <PII_{TYPE}_{hash6}>
    - TYPE: normalized entity type (SSN, EMAIL, CREDIT_CARD, etc.)
    - hash6: first 6 chars of SHA-256(session_id + original_text)
    - Deterministic: same PII value always gets same token in same session
    """

    # Presidio entities to detect (US-focused)
    PRESIDIO_ENTITIES = [
        "EMAIL_ADDRESS",
        "US_SSN",
        "CREDIT_CARD",
        "PHONE_NUMBER",
        "IBAN_CODE",
    ]

    # Token regex for finding tokens in content during detokenization
    TOKEN_PATTERN = re.compile(r"<PII_([A-Z_]+)_([a-f0-9]{6})>")

    def __init__(
        self,
        store: TokenStore,
        session_id: str,
        use_presidio: bool = True,
        enabled: bool = True,
    ):
        self._store = store
        self._session_id = session_id
        self._use_presidio = use_presidio and _check_presidio()
        self._enabled = enabled
        self._analyzer = None

    def is_enabled(self) -> bool:
        """Check if PII tokenization is enabled."""
        return self._enabled

    def _generate_token(self, entity_type: str, original_text: str) -> str:
        """Generate a deterministic token for a PII value.

        Same PII text always produces the same token within a session,
        so repeated references to the same PII are consistent.
        """
        seed = f"{self._session_id}:{original_text}"
        hash6 = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:6]
        return f"<PII_{entity_type}_{hash6}>"

    def _detect_regex(self, content: str) -> List[PIIMatch]:
        """Detect PII using regex patterns from pii_scanner.py."""
        from tweek.security.pii_scanner import PII_PATTERNS

        matches = []
        for pattern_def in PII_PATTERNS:
            entity_type = _REGEX_TYPE_MAP.get(pattern_def["name"])
            if not entity_type:
                continue

            regex = pattern_def["regex"]
            for m in regex.finditer(content):
                original = m.group()
                token = self._generate_token(entity_type, original)
                matches.append(
                    PIIMatch(
                        entity_type=entity_type,
                        start=m.start(),
                        end=m.end(),
                        original_text=original,
                        token=token,
                        score=1.0,
                        source="regex",
                    )
                )

        return matches

    def _detect_presidio(self, content: str) -> List[PIIMatch]:
        """Detect PII using Microsoft Presidio AnalyzerEngine."""
        if not _check_presidio():
            return []

        try:
            from presidio_analyzer import AnalyzerEngine

            if self._analyzer is None:
                self._analyzer = AnalyzerEngine()

            results = self._analyzer.analyze(
                text=content,
                entities=self.PRESIDIO_ENTITIES,
                language="en",
            )

            matches = []
            for result in results:
                original = content[result.start : result.end]
                entity_type = _PRESIDIO_TYPE_MAP.get(
                    result.entity_type, result.entity_type
                )
                token = self._generate_token(entity_type, original)
                matches.append(
                    PIIMatch(
                        entity_type=entity_type,
                        start=result.start,
                        end=result.end,
                        original_text=original,
                        token=token,
                        score=result.score,
                        source="presidio",
                    )
                )

            return matches
        except Exception:
            # Fall back to regex on any Presidio error
            return self._detect_regex(content)

    def _deduplicate_matches(self, matches: List[PIIMatch]) -> List[PIIMatch]:
        """Remove overlapping matches, preferring higher-score and longer spans."""
        if not matches:
            return []

        # Sort by start position, then by length (longer first), then by score
        sorted_matches = sorted(
            matches, key=lambda m: (m.start, -(m.end - m.start), -m.score)
        )

        result = []
        last_end = -1
        for match in sorted_matches:
            if match.start >= last_end:
                result.append(match)
                last_end = match.end

        return result

    def tokenize(
        self, content: str, direction: str = "input"
    ) -> Tuple[str, List[PIIMatch]]:
        """Replace PII in content with tokens.

        Args:
            content: Text content to scan and tokenize
            direction: 'input' (pre-hook) or 'output' (post-hook)

        Returns:
            (tokenized_content, list of PIIMatch objects)
        """
        if not content or not self._enabled:
            return content, []

        # Detect PII
        if self._use_presidio:
            matches = self._detect_presidio(content)
        else:
            matches = self._detect_regex(content)

        if not matches:
            return content, []

        # Deduplicate overlapping matches
        matches = self._deduplicate_matches(matches)

        # Replace from end to start to preserve offsets
        tokenized = content
        for match in sorted(matches, key=lambda m: m.start, reverse=True):
            tokenized = tokenized[: match.start] + match.token + tokenized[match.end :]

            # Store mapping in SQLite
            self._store.store_token(
                session_id=self._session_id,
                token=match.token,
                original=match.original_text,
                entity_type=match.entity_type,
                direction=direction,
            )

        return tokenized, matches

    def detokenize(self, content: str, session_id: Optional[str] = None) -> str:
        """Replace tokens in content with original PII values.

        Args:
            content: Text containing PII tokens
            session_id: Session to look up tokens in (defaults to self._session_id)

        Returns:
            Content with tokens replaced by original PII values
        """
        if not content:
            return content

        sid = session_id or self._session_id

        # Find all tokens in content
        token_matches = list(self.TOKEN_PATTERN.finditer(content))
        if not token_matches:
            return content

        # Look up all session tokens at once (more efficient than per-token)
        session_tokens = self._store.get_session_tokens(sid)
        if not session_tokens:
            return content

        # Replace tokens with originals (from end to start)
        result = content
        for m in reversed(token_matches):
            token = m.group()
            original = session_tokens.get(token)
            if original:
                result = result[: m.start()] + original + result[m.end() :]

        return result


# --- Module-level factory ---

_tokenizer_cache: Dict[str, PIITokenizer] = {}


def get_tokenizer(
    session_id: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> PIITokenizer:
    """Get or create a PIITokenizer for the given session.

    Uses a module-level cache to reuse tokenizers across hook invocations
    within the same process (hooks run as separate processes, so in practice
    each invocation creates a fresh one — the cache helps with testing).

    Args:
        session_id: Claude Code session ID (uses 'default' if None)
        db_path: Override token store DB path (for testing)

    Returns:
        PIITokenizer instance
    """
    sid = session_id or "default"

    # Check if tokenization is enabled in config
    enabled = _is_pii_enabled()

    cache_key = f"{sid}:{db_path or 'default'}"
    if cache_key not in _tokenizer_cache:
        store = TokenStore(db_path=db_path)
        _tokenizer_cache[cache_key] = PIITokenizer(
            store=store,
            session_id=sid,
            enabled=enabled,
        )

    return _tokenizer_cache[cache_key]


def _is_pii_enabled() -> bool:
    """Check if PII tokenization is enabled in .tweek.yaml or defaults."""
    try:
        import yaml

        config_path = Path.home() / ".tweek.yaml"
        if not config_path.exists():
            config_path = Path(".tweek.yaml")
        if config_path.exists():
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            return config.get("pii", {}).get("enabled", True)
    except Exception:
        pass
    return True


def clear_tokenizer_cache() -> None:
    """Clear the module-level tokenizer cache (for testing)."""
    _tokenizer_cache.clear()
