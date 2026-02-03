"""Tests for Tweek configuration templates and config edit UX."""

import os
import stat

import pytest
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from tweek.config.templates import (
    CONFIG_FILES,
    TEMPLATES_DIR,
    get_template_content,
    deploy_template,
    deploy_all_templates,
    resolve_target_path,
    append_active_section,
)


class TestTemplateFiles:
    """Verify template files exist and are well-formed."""

    def test_templates_directory_exists(self):
        assert TEMPLATES_DIR.exists()
        assert TEMPLATES_DIR.is_dir()

    def test_all_registered_templates_exist(self):
        for entry in CONFIG_FILES:
            if entry["template"]:
                path = TEMPLATES_DIR / entry["template"]
                assert path.exists(), f"Missing template: {entry['template']}"

    def test_config_template_yaml_sections_valid(self):
        """config.yaml.template should contain recognizable YAML sections when uncommented."""
        content = get_template_content("config.yaml.template")
        # Extract only the commented-out YAML key-value lines (# key: value)
        # and verify they are valid YAML individually
        yaml_lines = []
        for line in content.split("\n"):
            stripped = line.strip()
            # Match commented YAML entries like "# llm_review:" or "#   enabled: true"
            if stripped.startswith("# ") and ":" in stripped:
                candidate = stripped[2:]
                # Skip prose/documentation lines (contain multiple spaces between words)
                if candidate.strip() and not candidate.strip().startswith("-"):
                    try:
                        yaml.safe_load(candidate)
                        yaml_lines.append(candidate)
                    except yaml.YAMLError:
                        pass
        # Should have found many valid YAML lines
        assert len(yaml_lines) > 10, f"Only found {len(yaml_lines)} YAML lines in template"

    def test_env_template_has_no_real_keys(self):
        """env.template must NEVER contain real API keys."""
        content = get_template_content("env.template")
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            # Any uncommented line with = should only have placeholders
            if "=" in line:
                assert "your-" in line.lower() or "your_" in line.lower(), \
                    f"env.template has uncommented key that doesn't look like a placeholder: {line}"

    def test_env_template_mentions_billing_warning(self):
        content = get_template_content("env.template")
        assert "billed" in content.lower() or "separately" in content.lower()

    def test_env_template_recommends_google(self):
        content = get_template_content("env.template")
        assert "RECOMMENDED" in content or "recommended" in content

    def test_overrides_template_has_all_sections(self):
        content = get_template_content("overrides.yaml.template")
        assert "whitelist" in content.lower()
        assert "pattern" in content.lower()
        assert "trust" in content.lower()
        assert "enforcement" in content.lower()

    def test_tweek_yaml_template_has_hooks(self):
        content = get_template_content("tweek.yaml.template")
        parsed = yaml.safe_load(content)
        assert parsed is not None
        assert "hooks" in parsed
        assert parsed["hooks"]["pre_tool_use"] is True
        assert parsed["hooks"]["post_tool_use"] is True

    def test_config_files_registry_complete(self):
        """All entries have required fields."""
        required_fields = {"id", "name", "template", "target_path", "description", "editable"}
        for entry in CONFIG_FILES:
            missing = required_fields - set(entry.keys())
            assert not missing, f"Entry {entry.get('id', '?')} missing fields: {missing}"

    def test_config_files_ids_unique(self):
        ids = [e["id"] for e in CONFIG_FILES]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"


class TestTemplateDeploy:
    """Test template deployment logic."""

    def test_deploy_creates_file(self, tmp_path):
        target = tmp_path / "config.yaml"
        result = deploy_template("config.yaml.template", target)
        assert result is True
        assert target.exists()
        assert len(target.read_text()) > 100  # Non-trivial content

    def test_deploy_does_not_overwrite(self, tmp_path):
        target = tmp_path / "config.yaml"
        target.write_text("existing content")
        result = deploy_template("config.yaml.template", target, overwrite=False)
        assert result is False
        assert target.read_text() == "existing content"

    def test_deploy_overwrites_when_requested(self, tmp_path):
        target = tmp_path / "config.yaml"
        target.write_text("old content")
        result = deploy_template("config.yaml.template", target, overwrite=True)
        assert result is True
        assert "old content" not in target.read_text()

    def test_deploy_env_sets_permissions(self, tmp_path):
        target = tmp_path / ".env"
        deploy_template("env.template", target)
        mode = target.stat().st_mode
        # Should not be group/other readable
        assert not (mode & stat.S_IRGRP)
        assert not (mode & stat.S_IROTH)
        assert not (mode & stat.S_IWGRP)
        assert not (mode & stat.S_IWOTH)

    def test_deploy_creates_parent_dirs(self, tmp_path):
        target = tmp_path / "subdir" / "deep" / "config.yaml"
        result = deploy_template("config.yaml.template", target)
        assert result is True
        assert target.exists()

    def test_deploy_all_templates(self, tmp_path):
        with patch("tweek.config.templates.resolve_target_path") as mock_resolve:
            # Make all paths point to tmp_path subdirs
            def side_effect(entry, global_scope=True):
                return tmp_path / entry["id"] / os.path.basename(entry["target_path"])
            mock_resolve.side_effect = side_effect

            results = deploy_all_templates(global_scope=True)
            # Should have entries for all templates (excluding defaults which has no template)
            template_count = sum(1 for e in CONFIG_FILES if e["template"])
            assert len(results) == template_count
            # All should be created
            assert all(created for _, _, created in results)

    def test_get_template_missing_raises(self):
        with pytest.raises(FileNotFoundError):
            get_template_content("nonexistent.template")


class TestResolveTargetPath:
    """Test path resolution for different scopes."""

    def test_home_path_resolves(self):
        entry = {"target_path": "~/.tweek/config.yaml"}
        result = resolve_target_path(entry, global_scope=True)
        assert str(result).startswith(str(Path.home()))
        assert ".tweek" in str(result)

    def test_relative_path_global_scope(self):
        entry = {"target_path": ".tweek.yaml"}
        result = resolve_target_path(entry, global_scope=True)
        assert str(result).startswith(str(Path.home()))

    def test_relative_path_project_scope(self):
        entry = {"target_path": ".tweek.yaml"}
        result = resolve_target_path(entry, global_scope=False)
        assert str(result).startswith(str(Path.cwd()))


class TestAppendActiveSection:
    """Test the comment-preserving config writer."""

    def test_appends_to_template(self, tmp_path):
        target = tmp_path / "config.yaml"
        target.write_text("# Template header\n# All commented out\n")

        append_active_section(target, "llm_review:\n  provider: google\n")

        content = target.read_text()
        assert "# Template header" in content
        assert "# --- Active Configuration" in content
        assert "provider: google" in content

    def test_replaces_existing_active_section(self, tmp_path):
        target = tmp_path / "config.yaml"
        target.write_text(
            "# Template header\n\n"
            "# --- Active Configuration (set during install) ---\n"
            "llm_review:\n  provider: openai\n"
        )

        append_active_section(target, "llm_review:\n  provider: google\n")

        content = target.read_text()
        assert "provider: google" in content
        assert "provider: openai" not in content
        assert content.count("Active Configuration") == 1

    def test_creates_file_if_missing(self, tmp_path):
        target = tmp_path / "new_config.yaml"
        append_active_section(target, "llm_review:\n  enabled: true\n")
        assert target.exists()
        assert "enabled: true" in target.read_text()


class TestConfigEditCommand:
    """Test the tweek config edit CLI command."""

    def test_config_edit_shows_file_list(self):
        from tweek.cli_config import config
        runner = CliRunner()
        # Input "5" to select defaults (read-only, will try to open pager)
        with patch("subprocess.run"):
            result = runner.invoke(config, ["edit"], input="5\n")
        assert "Security Settings" in result.output
        assert "API Keys" in result.output

    def test_config_edit_invalid_id(self):
        from tweek.cli_config import config
        runner = CliRunner()
        result = runner.invoke(config, ["edit", "nonexistent"])
        assert "Unknown file" in result.output

    def test_config_edit_no_editor(self):
        from tweek.cli_config import config
        runner = CliRunner()
        with patch.dict(os.environ, {}, clear=True):
            with patch("shutil.which", return_value=None):
                result = runner.invoke(config, ["edit", "config"])
        assert "No editor" in result.output or result.exit_code != 0

    def test_show_defaults_command(self):
        from tweek.cli_config import config
        runner = CliRunner()
        with patch("subprocess.run") as mock_run:
            result = runner.invoke(config, ["show-defaults"])
        # Should try to open the pager
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "tiers.yaml" in args[1]
