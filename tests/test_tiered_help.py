"""Tests for TieredGroup CLI help progressive disclosure."""
from __future__ import annotations

from click.testing import CliRunner

from tweek.cli import main
from tweek.cli_helpers import COMMAND_TIERS, TieredGroup, _TIERED_COMMANDS


runner = CliRunner()


# ---- Default --help --------------------------------------------------------

class TestDefaultHelp:
    """Default help should show tiered categories, not a flat list."""

    def test_shows_getting_started_section(self):
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Getting Started:" in result.output

    def test_shows_security_trust_section(self):
        result = runner.invoke(main, ["--help"])
        assert "Security & Trust:" in result.output

    def test_shows_all_other_commands_section(self):
        result = runner.invoke(main, ["--help"])
        assert "All other commands:" in result.output

    def test_shows_help_all_hint(self):
        result = runner.invoke(main, ["--help"])
        assert "--help-all" in result.output

    def test_core_commands_have_descriptions(self):
        """Core tier commands should show their full help text."""
        result = runner.invoke(main, ["--help"])
        for cmd_name in COMMAND_TIERS["Getting Started"]:
            assert cmd_name in result.output

    def test_other_commands_compressed(self):
        """Non-tiered commands appear as comma-separated names, not with descriptions."""
        result = runner.invoke(main, ["--help"])
        # "plugins" is not in any default tier — should appear compressed
        assert "plugins" in result.output
        # But its description should NOT appear in the default help
        assert "Manage Tweek plugins" not in result.output

    def test_no_flat_alphabetical_list(self):
        """Should NOT show all 24 commands with descriptions (the old behavior)."""
        result = runner.invoke(main, ["--help"])
        # Count lines that look like "  command_name  Description..."
        # In the old flat format every command had its own description line.
        # In the new format, "All other commands" section has compressed names.
        # A rough check: the "All other commands" section should NOT contain
        # the description of commands like "proxy", "mcp", etc.
        assert "LLM API security proxy" not in result.output
        assert "MCP Security Gateway" not in result.output


# ---- --help-all ------------------------------------------------------------

class TestHelpAll:
    """--help-all should show every command grouped into full categories."""

    def test_exit_code_zero(self):
        result = runner.invoke(main, ["--help-all"])
        assert result.exit_code == 0

    def test_shows_all_five_sections(self):
        result = runner.invoke(main, ["--help-all"])
        for section in [
            "Getting Started:",
            "Security & Trust:",
            "Diagnostics:",
            "Infrastructure:",
            "Lifecycle:",
        ]:
            assert section in result.output

    def test_every_command_appears(self):
        """Every registered command should appear in --help-all."""
        result = runner.invoke(main, ["--help-all"])
        for name in main.commands:
            assert name in result.output, f"Command '{name}' missing from --help-all"

    def test_descriptions_shown(self):
        """In --help-all, even compressed commands should have descriptions."""
        result = runner.invoke(main, ["--help-all"])
        # These are in the "Infrastructure" tier and should have descriptions
        assert "Manage credentials" in result.output  # vault
        assert "LLM API security proxy" in result.output  # proxy


# ---- Subcommand help unaffected -------------------------------------------

class TestSubcommandHelp:
    """TieredGroup should not affect subcommand --help."""

    def test_vault_subcommands(self):
        result = runner.invoke(main, ["vault", "--help"])
        assert result.exit_code == 0
        assert "store" in result.output
        assert "get" in result.output

    def test_protect_subcommands(self):
        result = runner.invoke(main, ["protect", "--help"])
        assert result.exit_code == 0
        assert "claude-code" in result.output

    def test_config_subcommands(self):
        result = runner.invoke(main, ["config", "--help"])
        assert result.exit_code == 0
        assert "list" in result.output
        assert "set" in result.output


# ---- Tier integrity --------------------------------------------------------

class TestTierIntegrity:
    """Tier definitions should be consistent with registered commands."""

    def test_all_tiered_commands_exist(self):
        """Every command listed in COMMAND_TIERS must actually be registered."""
        for cmd_name in _TIERED_COMMANDS:
            assert cmd_name in main.commands, (
                f"Tiered command '{cmd_name}' is not registered in main CLI"
            )

    def test_full_tiers_cover_all_commands(self):
        """_FULL_TIERS in TieredGroup should cover every registered command."""
        all_in_full = set()
        for cmds in TieredGroup._FULL_TIERS.values():
            all_in_full.update(cmds)
        for name in main.commands:
            assert name in all_in_full, (
                f"Command '{name}' is missing from _FULL_TIERS — "
                "add it to a category in TieredGroup._FULL_TIERS"
            )

    def test_no_duplicates_across_tiers(self):
        """No command should appear in multiple tiers."""
        seen = {}
        for tier_name, cmds in TieredGroup._FULL_TIERS.items():
            for cmd in cmds:
                assert cmd not in seen, (
                    f"Command '{cmd}' appears in both "
                    f"'{seen[cmd]}' and '{tier_name}'"
                )
                seen[cmd] = tier_name
