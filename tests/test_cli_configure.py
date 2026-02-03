#!/usr/bin/env python3
"""
Tests for the `tweek configure` command group.

Verifies:
- All subcommands are registered and accessible
- `tweek configure preset` applies presets correctly
- `tweek configure llm` delegates to LLM configuration
- `tweek configure vault` scans and reports .env files
- `tweek configure wizard` invokes the full install wizard
- The "balanced" preset is the default for --quick
"""

import json
import shutil
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

from tweek.cli import main

pytestmark = pytest.mark.cli


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture(autouse=True)
def clean_llm_env(monkeypatch):
    """Remove LLM API keys to avoid side effects."""
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def mock_claude_on_path():
    """Mock Claude Code binary as available."""
    _original = shutil.which
    def _which(cmd):
        if cmd == "claude":
            return "/usr/local/bin/claude"
        return _original(cmd)
    with patch('tweek.cli_install.shutil.which', new=_which):
        yield


# ═══════════════════════════════════════════════════════════════
# Command registration
# ═══════════════════════════════════════════════════════════════

class TestConfigureRegistration:
    """Verify configure command group is properly registered."""

    def test_configure_command_exists(self, runner):
        """tweek configure should be a registered command."""
        result = runner.invoke(main, ['configure', '--help'])
        assert result.exit_code == 0
        assert "Configure Tweek" in result.output

    def test_configure_subcommands_listed(self, runner):
        """All subcommands should appear in help."""
        result = runner.invoke(main, ['configure', '--help'])
        assert result.exit_code == 0
        for subcmd in ["llm", "preset", "vault", "proxy", "mcp", "sandbox", "wizard"]:
            assert subcmd in result.output, f"Subcommand '{subcmd}' not found in help"


# ═══════════════════════════════════════════════════════════════
# tweek configure preset
# ═══════════════════════════════════════════════════════════════

class TestConfigurePreset:
    """Tests for the preset subcommand."""

    def test_apply_balanced_preset(self, runner, tmp_path):
        """tweek configure preset balanced should apply the balanced preset."""
        with patch('tweek.config.manager.ConfigManager.USER_CONFIG',
                   tmp_path / "config.yaml"):
            result = runner.invoke(main, ['configure', 'preset', 'balanced'])

        assert result.exit_code == 0
        assert "balanced" in result.output.lower()

    def test_apply_paranoid_preset(self, runner, tmp_path):
        """tweek configure preset paranoid should apply the paranoid preset."""
        with patch('tweek.config.manager.ConfigManager.USER_CONFIG',
                   tmp_path / "config.yaml"):
            result = runner.invoke(main, ['configure', 'preset', 'paranoid'])

        assert result.exit_code == 0
        assert "paranoid" in result.output.lower()

    def test_apply_cautious_preset(self, runner, tmp_path):
        """tweek configure preset cautious should apply the cautious preset."""
        with patch('tweek.config.manager.ConfigManager.USER_CONFIG',
                   tmp_path / "config.yaml"):
            result = runner.invoke(main, ['configure', 'preset', 'cautious'])

        assert result.exit_code == 0
        assert "cautious" in result.output.lower()

    def test_apply_trusted_preset(self, runner, tmp_path):
        """tweek configure preset trusted should apply the trusted preset."""
        with patch('tweek.config.manager.ConfigManager.USER_CONFIG',
                   tmp_path / "config.yaml"):
            result = runner.invoke(main, ['configure', 'preset', 'trusted'])

        assert result.exit_code == 0
        assert "trusted" in result.output.lower()

    def test_invalid_preset_rejected(self, runner):
        """Invalid preset name should be rejected by Click."""
        result = runner.invoke(main, ['configure', 'preset', 'invalid'])
        assert result.exit_code != 0

    def test_interactive_preset_selection(self, runner, tmp_path):
        """No argument should show interactive selection."""
        with patch('tweek.config.manager.ConfigManager.USER_CONFIG',
                   tmp_path / "config.yaml"):
            result = runner.invoke(
                main,
                ['configure', 'preset'],
                input='2\n',  # Select balanced
            )

        assert result.exit_code == 0
        assert "balanced" in result.output.lower()


# ═══════════════════════════════════════════════════════════════
# tweek configure llm
# ═══════════════════════════════════════════════════════════════

class TestConfigureLLM:
    """Tests for the llm subcommand."""

    def test_llm_subcommand_exists(self, runner):
        """tweek configure llm --help should work."""
        result = runner.invoke(main, ['configure', 'llm', '--help'])
        assert result.exit_code == 0
        assert "LLM" in result.output or "llm" in result.output.lower()

    def test_llm_delegates_to_configure(self, runner, tmp_path):
        """tweek configure llm should call _configure_llm_provider."""
        mock_result = {
            "provider": "auto",
            "provider_display": "Auto-detect",
            "model_display": None,
        }
        with patch('tweek.cli_install._configure_llm_provider', return_value=mock_result) as mock_cfg:
            result = runner.invoke(main, ['configure', 'llm'], input='1\n')

        assert result.exit_code == 0
        mock_cfg.assert_called_once()


# ═══════════════════════════════════════════════════════════════
# tweek configure vault
# ═══════════════════════════════════════════════════════════════

class TestConfigureVault:
    """Tests for the vault subcommand."""

    def test_vault_dry_run_no_env_files(self, runner, tmp_path, monkeypatch):
        """Dry run with no .env files should report cleanly."""
        monkeypatch.chdir(tmp_path)
        with patch('tweek.cli_install.scan_for_env_files', return_value=[]):
            result = runner.invoke(main, ['configure', 'vault', '--dry-run'])

        assert result.exit_code == 0
        assert "No .env files" in result.output

    def test_vault_dry_run_shows_findings(self, runner, tmp_path, monkeypatch):
        """Dry run with .env files should list them."""
        monkeypatch.chdir(tmp_path)

        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=secret\nDATABASE_PASSWORD=pass\n")

        findings = [(env_file, ["API_KEY", "DATABASE_PASSWORD"])]
        with patch('tweek.cli_install.scan_for_env_files', return_value=findings):
            result = runner.invoke(main, ['configure', 'vault', '--dry-run'])

        assert result.exit_code == 0
        assert "API_KEY" in result.output
        assert "DATABASE_PASSWORD" in result.output
        assert "Dry run" in result.output


# ═══════════════════════════════════════════════════════════════
# tweek configure mcp
# ═══════════════════════════════════════════════════════════════

class TestConfigureMCP:
    """Tests for the mcp subcommand."""

    def test_mcp_no_tools_detected(self, runner):
        """When no MCP tools detected, should report cleanly."""
        with patch('tweek.cli_helpers._detect_all_tools', return_value=[]):
            result = runner.invoke(main, ['configure', 'mcp'])

        assert result.exit_code == 0
        assert "No MCP" in result.output

    def test_mcp_shows_protected_tools(self, runner):
        """Should show already-protected tools."""
        tools = [
            ("claude-desktop", "Claude Desktop", True, True, ""),
        ]
        with patch('tweek.cli_helpers._detect_all_tools', return_value=tools):
            result = runner.invoke(main, ['configure', 'mcp'])

        assert result.exit_code == 0
        assert "Claude Desktop" in result.output
        assert "protected" in result.output


# ═══════════════════════════════════════════════════════════════
# tweek configure sandbox
# ═══════════════════════════════════════════════════════════════

class TestConfigureSandbox:
    """Tests for the sandbox subcommand."""

    def test_sandbox_non_linux(self, runner):
        """On non-Linux, should report not available."""
        with patch('tweek.platform.IS_LINUX', False):
            with patch('tweek.platform.get_capabilities') as mock_caps:
                mock_caps.return_value = MagicMock(platform=MagicMock(value="darwin"))
                result = runner.invoke(main, ['configure', 'sandbox'])

        assert result.exit_code == 0
        assert "Linux" in result.output


# ═══════════════════════════════════════════════════════════════
# Balanced preset is default for --quick
# ═══════════════════════════════════════════════════════════════

class TestBalancedDefault:
    """Verify that balanced is the default preset for quick installs."""

    def test_balanced_preset_exists(self):
        """The balanced preset should be defined in ConfigManager."""
        from tweek.config.manager import ConfigManager
        assert "balanced" in ConfigManager.PRESETS

    def test_balanced_has_same_tiers_as_cautious(self):
        """Balanced should have the same tool tiers as cautious."""
        from tweek.config.manager import ConfigManager
        balanced = ConfigManager.PRESETS["balanced"]
        cautious = ConfigManager.PRESETS["cautious"]
        assert balanced["tools"] == cautious["tools"]
        assert balanced["default_tier"] == cautious["default_tier"]

    def test_quick_install_uses_balanced(self, runner, tmp_path):
        """tweek protect claude-code --quick should use balanced preset."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--quick'],
                    catch_exceptions=False,
                )

        assert result.exit_code == 0
        assert "balanced" in result.output.lower()

    def test_quick_with_explicit_preset_overrides(self, runner, tmp_path):
        """--quick --preset paranoid should use paranoid, not balanced."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--quick', '--preset', 'paranoid'],
                    catch_exceptions=False,
                )

        assert result.exit_code == 0
        assert "paranoid" in result.output.lower()

    def test_install_summary_shows_configure(self, runner, tmp_path):
        """Quick install summary should mention tweek configure."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--quick'],
                    catch_exceptions=False,
                )

        assert "tweek configure" in result.output
