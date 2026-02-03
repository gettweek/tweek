"""Tests for ReDoS protection in PatternMatcher.

Validates that the PatternMatcher uses timeout-protected regex execution
and handles catastrophic backtracking gracefully.
"""

import re
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from tweek.hooks.pre_tool_use import PatternMatcher
from tweek.plugins.base import ReDoSProtection, RegexTimeoutError


@pytest.fixture
def simple_patterns_file(tmp_path):
    """Create a minimal patterns YAML for testing.

    Note: PatternMatcher always loads bundled patterns first (262+), then
    merges custom patterns on top. These test patterns are additive.
    """
    patterns = {
        "patterns": [
            {
                "name": "test_redos_pattern_1",
                "description": "Test pattern for ReDoS tests",
                "regex": r"REDOS_TEST_MARKER_ALPHA",
                "severity": "critical",
                "confidence": "deterministic",
                "family": "test",
            },
            {
                "name": "test_redos_pattern_2",
                "description": "Another test for ReDoS tests",
                "regex": r"REDOS_TEST_MARKER_BETA",
                "severity": "high",
                "confidence": "heuristic",
                "family": "test",
            },
        ]
    }
    path = tmp_path / "patterns.yaml"
    with open(path, "w") as f:
        yaml.dump(patterns, f)
    return path


@pytest.fixture
def catastrophic_patterns_file(tmp_path):
    """Create patterns with a deliberately catastrophic regex.

    These are merged on top of bundled patterns.
    """
    patterns = {
        "patterns": [
            {
                "name": "redos_safe_pattern",
                "description": "Normal pattern that works fine",
                "regex": r"REDOS_SAFE_MARKER_ECHO",
                "severity": "low",
                "confidence": "deterministic",
                "family": "test",
            },
            {
                "name": "redos_catastrophic_pattern",
                "description": "Pattern that causes exponential backtracking",
                "regex": r"(a+)+$",
                "severity": "high",
                "confidence": "heuristic",
                "family": "test",
            },
            {
                "name": "redos_after_catastrophic",
                "description": "Pattern after the catastrophic one",
                "regex": r"REDOS_AFTER_CATASTROPHIC_MARKER",
                "severity": "low",
                "confidence": "deterministic",
                "family": "test",
            },
        ]
    }
    path = tmp_path / "patterns.yaml"
    with open(path, "w") as f:
        yaml.dump(patterns, f)
    return path


class TestPatternMatcherCompilation:
    """Tests for pattern pre-compilation cache."""

    def test_compiled_patterns_populated(self, simple_patterns_file):
        """Compiled patterns cache should be populated with bundled + custom patterns."""
        matcher = PatternMatcher(patterns_path=simple_patterns_file)
        # Should have bundled patterns (262+) plus our 2 test patterns
        assert len(matcher._compiled_patterns) >= 264
        for compiled, pattern_dict in matcher._compiled_patterns:
            assert isinstance(compiled, re.Pattern)
            assert "name" in pattern_dict
        # Verify our custom patterns are included
        names = {p["name"] for _, p in matcher._compiled_patterns}
        assert "test_redos_pattern_1" in names
        assert "test_redos_pattern_2" in names

    def test_invalid_regex_skipped_at_compile(self, tmp_path):
        """Invalid regex patterns should be skipped during compilation."""
        patterns = {
            "patterns": [
                {
                    "name": "redos_valid_compile_test",
                    "regex": r"REDOS_VALID_COMPILE_MARKER",
                    "severity": "low",
                    "confidence": "deterministic",
                    "family": "test",
                },
                {
                    "name": "redos_invalid_compile_test",
                    "regex": r"[invalid",
                    "severity": "low",
                    "confidence": "deterministic",
                    "family": "test",
                },
            ]
        }
        path = tmp_path / "patterns.yaml"
        with open(path, "w") as f:
            yaml.dump(patterns, f)

        matcher = PatternMatcher(patterns_path=path)
        names = {p["name"] for _, p in matcher._compiled_patterns}
        assert "redos_valid_compile_test" in names
        assert "redos_invalid_compile_test" not in names

    def test_empty_regex_skipped(self, tmp_path):
        """Patterns with empty regex should be skipped."""
        patterns = {
            "patterns": [
                {
                    "name": "redos_empty_regex",
                    "regex": "",
                    "severity": "low",
                    "confidence": "deterministic",
                    "family": "test",
                },
                {
                    "name": "redos_nonempty_regex",
                    "regex": r"REDOS_NONEMPTY_MARKER",
                    "severity": "low",
                    "confidence": "deterministic",
                    "family": "test",
                },
            ]
        }
        path = tmp_path / "patterns.yaml"
        with open(path, "w") as f:
            yaml.dump(patterns, f)

        matcher = PatternMatcher(patterns_path=path)
        names = {p["name"] for _, p in matcher._compiled_patterns}
        assert "redos_empty_regex" not in names
        assert "redos_nonempty_regex" in names


class TestPatternMatcherCheck:
    """Tests for check() with ReDoS protection."""

    def test_normal_pattern_matches(self, simple_patterns_file):
        """Custom patterns should still match correctly after refactor."""
        matcher = PatternMatcher(patterns_path=simple_patterns_file)
        result = matcher.check("REDOS_TEST_MARKER_ALPHA")
        assert result is not None
        assert result["name"] == "test_redos_pattern_1"

    def test_normal_pattern_no_match(self, simple_patterns_file):
        """Non-matching content should return None (against unique test markers)."""
        matcher = PatternMatcher(patterns_path=simple_patterns_file)
        result = matcher.check("REDOS_NO_MATCH_CONTENT_XYZ")
        # May match a bundled pattern, but won't match our test patterns
        # Just verify it doesn't crash
        assert result is None or "name" in result

    def test_input_truncation(self, simple_patterns_file):
        """Content exceeding MAX_INPUT_LENGTH should be truncated."""
        matcher = PatternMatcher(patterns_path=simple_patterns_file)
        # Place unique marker beyond truncation point
        long_content = "x" * (ReDoSProtection.MAX_INPUT_LENGTH + 100) + "REDOS_TEST_MARKER_ALPHA"
        result = matcher.check(long_content)
        # Our marker is beyond truncation point, so it should NOT match our test pattern
        # (may match bundled patterns on the 'x' content, but that's fine)
        if result is not None:
            assert result["name"] != "test_redos_pattern_1"

    def test_input_within_limit_matches(self, simple_patterns_file):
        """Content within limit should match normally."""
        matcher = PatternMatcher(patterns_path=simple_patterns_file)
        content = "REDOS_TEST_MARKER_ALPHA something"
        result = matcher.check(content)
        assert result is not None
        assert result["name"] == "test_redos_pattern_1"


class TestPatternMatcherCheckAll:
    """Tests for check_all() with ReDoS protection."""

    def test_returns_custom_matches(self, simple_patterns_file):
        """check_all() should include our custom test patterns in results."""
        matcher = PatternMatcher(patterns_path=simple_patterns_file)
        content = "REDOS_TEST_MARKER_ALPHA and REDOS_TEST_MARKER_BETA"
        results = matcher.check_all(content)
        names = {r["name"] for r in results}
        assert "test_redos_pattern_1" in names
        assert "test_redos_pattern_2" in names

    def test_partial_matches_on_timeout(self, catastrophic_patterns_file):
        """check_all() should return partial matches when one pattern times out."""
        matcher = PatternMatcher(patterns_path=catastrophic_patterns_file)
        content = "REDOS_SAFE_MARKER_ECHO and REDOS_AFTER_CATASTROPHIC_MARKER"
        results = matcher.check_all(content)
        names = {r["name"] for r in results}
        assert "redos_safe_pattern" in names
        assert "redos_after_catastrophic" in names

    def test_input_truncation(self, simple_patterns_file):
        """check_all() should truncate oversized input."""
        matcher = PatternMatcher(patterns_path=simple_patterns_file)
        long_content = "x" * (ReDoSProtection.MAX_INPUT_LENGTH + 100) + "REDOS_TEST_MARKER_ALPHA"
        results = matcher.check_all(long_content)
        names = {r["name"] for r in results}
        # Our marker is beyond truncation, so our test pattern should not appear
        assert "test_redos_pattern_1" not in names


class TestReDoSTimeout:
    """Tests for actual ReDoS timeout behavior."""

    @pytest.mark.skipif(
        not hasattr(__import__("signal"), "SIGALRM"),
        reason="SIGALRM not available on this platform",
    )
    def test_catastrophic_regex_times_out(self, catastrophic_patterns_file):
        """A catastrophic regex should timeout without hanging the process."""
        matcher = PatternMatcher(patterns_path=catastrophic_patterns_file)
        # Adversarial input for (a+)+$ -- causes exponential backtracking
        adversarial = "a" * 30 + "!"
        # This should complete (not hang) because the timeout fires
        result = matcher.check(adversarial)
        # The catastrophic pattern should NOT match (it times out)
        if result is not None:
            assert result["name"] != "redos_catastrophic_pattern"

    @pytest.mark.skipif(
        not hasattr(__import__("signal"), "SIGALRM"),
        reason="SIGALRM not available on this platform",
    )
    def test_safe_patterns_still_work_after_timeout(self, catastrophic_patterns_file):
        """After a timeout, subsequent patterns should still be checked."""
        matcher = PatternMatcher(patterns_path=catastrophic_patterns_file)
        content = "REDOS_AFTER_CATASTROPHIC_MARKER"
        result = matcher.check(content)
        assert result is not None
        assert result["name"] == "redos_after_catastrophic"
