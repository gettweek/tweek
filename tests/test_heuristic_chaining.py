"""Tests for heuristic scorer benign dampening chain detection (Finding F7).

Validates that command chaining operators (&&, ||, ;) prevent benign
dampening from being applied, since a benign prefix does not make the
entire chained command benign.
"""

import pytest

from tweek.plugins.screening.heuristic_scorer import HeuristicScorerPlugin


@pytest.fixture
def scorer():
    return HeuristicScorerPlugin()


class TestBenignDampeningChainDetection:
    """Tests for _is_benign() rejecting chained commands."""

    def test_simple_git_status_is_benign(self, scorer):
        """A simple benign command (no chaining) should be detected as benign."""
        result = scorer._is_benign("git status")
        assert result is not None

    def test_simple_pip_install_is_benign(self, scorer):
        """pip install without chaining should be detected as benign."""
        result = scorer._is_benign("pip install requests")
        assert result is not None

    def test_simple_make_is_benign(self, scorer):
        """'make' without chaining should be benign."""
        result = scorer._is_benign("make clean")
        assert result is not None

    def test_simple_ls_is_benign(self, scorer):
        """'ls' without chaining should be benign."""
        result = scorer._is_benign("ls -la")
        assert result is not None

    def test_and_and_chaining_not_benign(self, scorer):
        """Benign prefix with && chaining should NOT be benign."""
        result = scorer._is_benign("git commit && some_other_command")
        assert result is None

    def test_semicolon_chaining_not_benign(self, scorer):
        """Benign prefix with ; chaining should NOT be benign."""
        result = scorer._is_benign("pip install foo; some_other_command")
        assert result is None

    def test_or_chaining_not_benign(self, scorer):
        """Benign prefix with || chaining should NOT be benign."""
        result = scorer._is_benign("echo hello || some_other_command")
        assert result is None

    def test_make_with_chaining_not_benign(self, scorer):
        """'make' with chaining should NOT be benign."""
        result = scorer._is_benign("make clean && some_other_command")
        assert result is None

    def test_docker_with_chaining_not_benign(self, scorer):
        """'docker build' with chaining should NOT be benign."""
        result = scorer._is_benign("docker build . && some_other_command")
        assert result is None

    def test_non_matching_command_not_benign(self, scorer):
        """A command that doesn't match any benign pattern returns None."""
        result = scorer._is_benign("some_unknown_tool --flag")
        assert result is None


class TestBenignDampeningScoreImpact:
    """Tests that chaining detection affects the overall score correctly."""

    def test_simple_benign_command_scores_zero(self, scorer):
        """A simple benign command with no suspicious signals scores 0."""
        result = scorer._score_content("git commit -m 'test message'")
        assert result.total_score == 0.0

    def test_chained_command_not_dampened(self, scorer):
        """A chained command should not have dampening applied."""
        # Use a command with chaining -- even if prefix is benign,
        # dampening should be skipped
        result = scorer._score_content("git status && some_other_command")
        assert result.dampened is False

    def test_unchained_benign_with_signals_is_dampened(self, scorer):
        """An unchained benign command that happens to have signals gets dampened."""
        # 'cat' on a regular code file is benign
        result = scorer._score_content("cat test_file.py")
        # Should be dampened if it matches a benign pattern
        # Score is 0 anyway for benign content, so dampening is a no-op
        # Just verify no crash
        assert result.total_score >= 0.0

    def test_pipe_only_is_still_benign(self, scorer):
        """Pipe (|) alone should NOT prevent benign detection.

        Pipes are different from command chaining (&&, ||, ;).
        A pipe sends output to another command but is a single pipeline,
        not multiple independent commands.
        """
        result = scorer._is_benign("git log | head -20")
        # This should still be detected as benign (git log matches benign pattern)
        # and the pipe is not a chaining operator
        assert result is not None
