"""Tests for soul.md security policy loader and LLM integration."""
from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import patch

from tweek.config.soul import (
    GLOBAL_SOUL_PATH,
    MAX_SOUL_SIZE,
    SOUL_FILENAME,
    PROJECT_SOUL_DIR,
    load_soul_policy,
    reset_soul_cache,
    _read_soul_file,
    _merge_policies,
    _strip_frontmatter,
)


@pytest.fixture(autouse=True)
def clear_soul_cache():
    """Reset the module-level cache before and after each test."""
    reset_soul_cache()
    yield
    reset_soul_cache()


# =========================================================================
# Soul Loader Tests
# =========================================================================

class TestSoulLoader:
    """Tests for the soul.md loading and merging logic."""

    def test_no_soul_files_returns_none(self, tmp_path):
        """When no soul.md files exist, load_soul_policy returns None."""
        with patch("tweek.config.soul.GLOBAL_SOUL_PATH", tmp_path / "nonexistent.md"):
            result = load_soul_policy(
                project_dir=tmp_path, _bypass_cache=True,
            )
        assert result is None

    def test_global_soul_only(self, tmp_path):
        """Global soul.md is loaded when no project soul exists."""
        global_soul = tmp_path / "soul.md"
        global_soul.write_text("## Philosophy\nStrict security posture.", encoding="utf-8")

        with patch("tweek.config.soul.GLOBAL_SOUL_PATH", global_soul):
            result = load_soul_policy(
                project_dir=tmp_path / "no-project", _bypass_cache=True,
            )

        assert result is not None
        assert "Strict security posture" in result

    def test_project_soul_only(self, tmp_path):
        """Project soul.md is loaded when no global soul exists."""
        project_soul_dir = tmp_path / PROJECT_SOUL_DIR
        project_soul_dir.mkdir()
        (project_soul_dir / SOUL_FILENAME).write_text(
            "## Strict Rules\n- Never read .env.production", encoding="utf-8"
        )

        with patch("tweek.config.soul.GLOBAL_SOUL_PATH", tmp_path / "nonexistent.md"):
            result = load_soul_policy(
                project_dir=tmp_path, _bypass_cache=True,
            )

        assert result is not None
        assert ".env.production" in result

    def test_merged_global_and_project(self, tmp_path):
        """Both global and project soul.md are merged with separator."""
        global_soul = tmp_path / "global_soul.md"
        global_soul.write_text("## Philosophy\nGlobal policy here.", encoding="utf-8")

        project_dir = tmp_path / "myproject"
        project_soul_dir = project_dir / PROJECT_SOUL_DIR
        project_soul_dir.mkdir(parents=True)
        (project_soul_dir / SOUL_FILENAME).write_text(
            "## Strict Rules\nProject-specific rule.", encoding="utf-8"
        )

        with patch("tweek.config.soul.GLOBAL_SOUL_PATH", global_soul):
            result = load_soul_policy(
                project_dir=project_dir, _bypass_cache=True,
            )

        assert result is not None
        assert "Global policy here" in result
        assert "Project-specific rule" in result
        assert "---" in result
        assert "project-level policy takes precedence" in result

    def test_size_limit_enforced(self, tmp_path):
        """Files exceeding MAX_SOUL_SIZE are skipped."""
        oversized = tmp_path / "soul.md"
        oversized.write_text("x" * (MAX_SOUL_SIZE + 1), encoding="utf-8")

        result = _read_soul_file(oversized)
        assert result is None

    def test_size_at_limit_is_accepted(self, tmp_path):
        """Files exactly at MAX_SOUL_SIZE are accepted."""
        at_limit = tmp_path / "soul.md"
        at_limit.write_text("x" * MAX_SOUL_SIZE, encoding="utf-8")

        result = _read_soul_file(at_limit)
        assert result is not None

    def test_utf8_validation(self, tmp_path):
        """Non-UTF-8 files are rejected gracefully."""
        bad_encoding = tmp_path / "soul.md"
        bad_encoding.write_bytes(b"\xff\xfe Invalid UTF-8 content \x80\x81")

        result = _read_soul_file(bad_encoding)
        assert result is None

    def test_empty_file_returns_none(self, tmp_path):
        """Empty or whitespace-only files return None."""
        empty = tmp_path / "soul.md"
        empty.write_text("   \n\n  \n", encoding="utf-8")

        result = _read_soul_file(empty)
        assert result is None

    def test_frontmatter_stripped(self, tmp_path):
        """YAML front-matter is stripped before returning content."""
        with_frontmatter = tmp_path / "soul.md"
        with_frontmatter.write_text(
            "---\ntitle: My Policy\n---\n## Philosophy\nActual content.",
            encoding="utf-8",
        )

        result = _read_soul_file(with_frontmatter)
        assert result is not None
        assert "title: My Policy" not in result
        assert "Actual content" in result

    def test_caching_returns_same_result(self, tmp_path):
        """Subsequent calls return cached result without re-reading files."""
        global_soul = tmp_path / "soul.md"
        global_soul.write_text("## Philosophy\nCached content.", encoding="utf-8")

        with patch("tweek.config.soul.GLOBAL_SOUL_PATH", global_soul):
            first = load_soul_policy(_bypass_cache=True)
            # Mutate the file — cache should still return old value
            global_soul.write_text("## Changed\nNew content.", encoding="utf-8")
            second = load_soul_policy()  # uses cache

        assert first == second
        assert "Cached content" in second

    def test_no_project_dir_loads_global_only(self, tmp_path):
        """When project_dir is None, only global soul is loaded."""
        global_soul = tmp_path / "soul.md"
        global_soul.write_text("## Philosophy\nGlobal only.", encoding="utf-8")

        with patch("tweek.config.soul.GLOBAL_SOUL_PATH", global_soul):
            result = load_soul_policy(project_dir=None, _bypass_cache=True)

        assert result is not None
        assert "Global only" in result


# =========================================================================
# Frontmatter Stripping
# =========================================================================

class TestStripFrontmatter:
    def test_no_frontmatter(self):
        assert _strip_frontmatter("## Hello\nWorld") == "## Hello\nWorld"

    def test_with_frontmatter(self):
        text = "---\nkey: value\n---\n## Content"
        assert _strip_frontmatter(text) == "## Content"

    def test_unclosed_frontmatter(self):
        text = "---\nkey: value\n## Content"
        assert _strip_frontmatter(text) == text


# =========================================================================
# Merge Policies
# =========================================================================

class TestMergePolicies:
    def test_both_none(self):
        assert _merge_policies(None, None) is None

    def test_global_only(self):
        assert _merge_policies("global", None) == "global"

    def test_project_only(self):
        assert _merge_policies(None, "project") == "project"

    def test_both_present(self):
        result = _merge_policies("global rules", "project rules")
        assert "global rules" in result
        assert "project rules" in result
        assert "---" in result


# =========================================================================
# LLM Prompt Integration
# =========================================================================

class TestSoulInLLMPrompt:
    """Tests for soul policy integration in the LLM reviewer prompt."""

    def test_soul_policy_included_in_prompt(self):
        from tweek.security.llm_reviewer import LLMReviewer

        prompt = LLMReviewer._build_analysis_prompt(
            command="ls -la",
            tool="Bash",
            tier="default",
            context="No context",
            soul_policy="## Strict Rules\n- Never allow reading .env",
        )

        assert "security_policy_" in prompt
        assert "Never allow reading .env" in prompt
        assert "operator has defined" in prompt

    def test_no_soul_prompt_unchanged(self):
        from tweek.security.llm_reviewer import LLMReviewer

        prompt = LLMReviewer._build_analysis_prompt(
            command="ls -la",
            tool="Bash",
            tier="default",
            context="No context",
            soul_policy=None,
        )

        assert "security_policy_" not in prompt
        assert "operator has defined" not in prompt
        # Core prompt structure still present
        assert "untrusted_command_" in prompt
        assert "Analyze the command" in prompt

    def test_soul_nonce_tags_present(self):
        from tweek.security.llm_reviewer import LLMReviewer

        prompt = LLMReviewer._build_analysis_prompt(
            command="echo hello",
            tool="Bash",
            tier="safe",
            context="test",
            soul_policy="Be strict.",
        )

        # Both nonce tags should be present with hex suffixes
        import re
        policy_tags = re.findall(r"security_policy_[0-9a-f]{16}", prompt)
        command_tags = re.findall(r"untrusted_command_[0-9a-f]{16}", prompt)
        assert len(policy_tags) >= 2  # opening + closing
        assert len(command_tags) >= 2

    def test_soul_before_untrusted_command(self):
        from tweek.security.llm_reviewer import LLMReviewer

        prompt = LLMReviewer._build_analysis_prompt(
            command="dangerous command",
            tool="Bash",
            tier="dangerous",
            context="test",
            soul_policy="My policy here.",
        )

        # Policy section should appear before the untrusted command section
        policy_pos = prompt.index("My policy here")
        command_pos = prompt.index("dangerous command")
        assert policy_pos < command_pos


# =========================================================================
# Self-Protection
# =========================================================================

class TestSoulProtection:
    """Tests for soul.md protection from AI modification."""

    def test_soul_md_in_protected_config_files(self):
        from tweek.hooks.overrides import PROTECTED_CONFIG_FILES

        soul_path = Path.home() / ".tweek" / "soul.md"
        assert soul_path in PROTECTED_CONFIG_FILES

    def test_global_soul_path_is_protected(self):
        from tweek.hooks.overrides import is_protected_config_file

        assert is_protected_config_file(str(Path.home() / ".tweek" / "soul.md"))

    def test_project_soul_path_is_protected(self, tmp_path):
        """Project-level .tweek/soul.md is protected by the .tweek/ directory check."""
        from tweek.hooks.overrides import is_protected_config_file

        project_soul = tmp_path / ".tweek" / "soul.md"
        project_soul.parent.mkdir()
        project_soul.touch()

        assert is_protected_config_file(str(project_soul))
