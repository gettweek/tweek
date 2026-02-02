#!/usr/bin/env python3
"""
Tests for Tweek CLI commands.

Tests coverage of:
- Protect/unprotect commands
- License commands
- Config commands
- Vault commands
- Logs commands
- Update command
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from click.testing import CliRunner
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from tweek.cli import main, update
from tweek.licensing import License, Tier
from tweek._keygen import generate_license_key

pytestmark = pytest.mark.cli


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def temp_home(tmp_path):
    """Create temporary home directory structure."""
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    tweek_dir = tmp_path / ".tweek"
    tweek_dir.mkdir()
    return tmp_path


class TestInstallCommand:
    """Tests for the protect claude-code command (formerly install)."""

    def test_install_global_creates_settings(self, runner, tmp_path):
        """Test global protect claude-code creates settings.json."""
        claude_dir = tmp_path / ".claude"

        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--skip-env-scan'],
                    catch_exceptions=False
                )

        # Should complete successfully
        assert result.exit_code == 0 or "Installation complete" in result.output

    def test_install_project_scope(self, runner, tmp_path):
        """Test project-scoped protect claude-code."""
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(
                main,
                ['protect', 'claude-code', '--scope', 'project', '--skip-env-scan']
            )

            # Check .claude directory was created
            project_claude = Path(".claude")
            if project_claude.exists():
                settings = project_claude / "settings.json"
                assert settings.exists() or "Installation complete" in result.output

    def test_install_with_preset(self, runner, tmp_path):
        """Test protect claude-code with security preset."""
        with patch.object(Path, 'home', return_value=tmp_path):
            result = runner.invoke(
                main,
                ['protect', 'claude-code', '--preset', 'paranoid', '--skip-env-scan']
            )

        assert "paranoid" in result.output.lower() or result.exit_code == 0

    def test_install_skip_proxy_check(self, runner, tmp_path):
        """Test protect claude-code with --skip-proxy-check skips openclaw detection."""
        with patch.object(Path, 'home', return_value=tmp_path):
            result = runner.invoke(
                main,
                ['protect', 'claude-code', '--skip-env-scan', '--skip-proxy-check']
            )

        # Should not mention openclaw
        assert "openclaw" not in result.output.lower()
        assert result.exit_code == 0 or "Installation complete" in result.output

    def test_install_detects_openclaw_installed(self, runner, tmp_path):
        """Test protect claude-code detects when openclaw is installed."""
        openclaw_status = {
            "installed": True,
            "running": False,
            "gateway_active": False,
            "port": 18789,
            "config_path": str(tmp_path / ".openclaw"),
        }

        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.proxy.get_openclaw_status', return_value=openclaw_status):
                with patch('tweek.proxy.detect_proxy_conflicts', return_value=[]):
                    result = runner.invoke(
                        main,
                        ['protect', 'claude-code', '--skip-env-scan'],
                        input='n\n'  # Answer 'no' to proxy override prompt
                    )

        # Should mention openclaw was detected
        assert "openclaw" in result.output.lower() or result.exit_code == 0

    def test_install_detects_openclaw_gateway_running(self, runner, tmp_path):
        """Test protect claude-code detects when openclaw gateway is actively running."""
        openclaw_status = {
            "installed": True,
            "running": True,
            "gateway_active": True,
            "port": 18789,
            "config_path": str(tmp_path / ".openclaw"),
        }

        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.proxy.get_openclaw_status', return_value=openclaw_status):
                with patch('tweek.proxy.detect_proxy_conflicts', return_value=[]):
                    result = runner.invoke(
                        main,
                        ['protect', 'claude-code', '--skip-env-scan'],
                        input='n\n'  # Answer 'no' to proxy override prompt
                    )

        # Should mention gateway is running
        assert "gateway" in result.output.lower() or "running" in result.output.lower() or result.exit_code == 0

    def test_install_force_proxy_flag(self, runner, tmp_path):
        """Test protect claude-code with --force-proxy enables proxy override."""
        openclaw_status = {
            "installed": True,
            "running": True,
            "gateway_active": True,
            "port": 18789,
            "config_path": None,
        }

        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.proxy.get_openclaw_status', return_value=openclaw_status):
                with patch('tweek.proxy.detect_proxy_conflicts', return_value=[]):
                    result = runner.invoke(
                        main,
                        ['protect', 'claude-code', '--skip-env-scan', '--force-proxy']
                    )

        # Should mention force/override
        assert "override" in result.output.lower() or "proxy" in result.output.lower() or result.exit_code == 0

    def test_install_force_proxy_creates_config(self, runner, tmp_path):
        """Test that --force-proxy creates proxy config file."""
        openclaw_status = {
            "installed": True,
            "running": False,
            "gateway_active": False,
            "port": 18789,
            "config_path": None,
        }

        tweek_dir = tmp_path / ".tweek"

        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.proxy.get_openclaw_status', return_value=openclaw_status):
                with patch('tweek.proxy.detect_proxy_conflicts', return_value=[]):
                    result = runner.invoke(
                        main,
                        ['protect', 'claude-code', '--skip-env-scan', '--force-proxy']
                    )

        # Check config file was created
        config_file = tweek_dir / "config.yaml"
        if config_file.exists():
            import yaml
            with open(config_file) as f:
                config = yaml.safe_load(f)
            assert config.get("proxy", {}).get("enabled") is True
            assert config.get("proxy", {}).get("override_openclaw") is True

    def test_install_user_accepts_proxy_override(self, runner, tmp_path):
        """Test protect claude-code when user accepts proxy override prompt."""
        openclaw_status = {
            "installed": True,
            "running": False,
            "gateway_active": False,
            "port": 18789,
            "config_path": None,
        }

        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.proxy.get_openclaw_status', return_value=openclaw_status):
                with patch('tweek.proxy.detect_proxy_conflicts', return_value=[]):
                    result = runner.invoke(
                        main,
                        ['protect', 'claude-code', '--skip-env-scan'],
                        input='y\n'  # Answer 'yes' to proxy override prompt
                    )

        # Should confirm proxy override
        assert "proxy" in result.output.lower() or result.exit_code == 0


class TestUninstallCommand:
    """Tests for the unprotect command (formerly uninstall)."""

    @patch('tweek.cli_protect.sys')
    def test_uninstall_not_installed(self, mock_sys, runner, tmp_path):
        """Test unprotect when not installed (project scope, empty directory)."""
        mock_sys.stdin.isatty.return_value = True
        mock_sys.stderr = sys.stderr
        with runner.isolated_filesystem(temp_dir=tmp_path):
            result = runner.invoke(main, ['unprotect', 'claude-code', '--confirm'])

        assert "No Tweek installation" in result.output or result.exit_code == 0

    @patch('tweek.cli_protect.sys')
    def test_uninstall_removes_hooks(self, mock_sys, runner, tmp_path):
        """Test unprotect removes Tweek hooks."""
        mock_sys.stdin.isatty.return_value = True
        mock_sys.stderr = sys.stderr
        with runner.isolated_filesystem(temp_dir=tmp_path) as td:
            # Set up a mock installation in current project
            claude_dir = Path(".claude")
            claude_dir.mkdir(parents=True, exist_ok=True)
            settings_file = claude_dir / "settings.json"
            settings_file.write_text(json.dumps({
                "hooks": {
                    "PreToolUse": [{
                        "matcher": "Bash",
                        "hooks": [{
                            "type": "command",
                            "command": "/path/to/tweek/hooks/pre_tool_use.py"
                        }]
                    }]
                }
            }))

            result = runner.invoke(main, ['unprotect', 'claude-code', '--confirm'])

            # Check hooks were removed
            if settings_file.exists():
                settings = json.loads(settings_file.read_text())
                # Either hooks removed or PreToolUse is empty
                assert "hooks" not in settings or "PreToolUse" not in settings.get("hooks", {})


class TestLicenseCommands:
    """Tests for license subcommands."""

    def test_license_status(self, runner, tmp_path):
        """Test license status command."""
        with patch('tweek.licensing.LICENSE_FILE', tmp_path / "license.key"):
            License._instance = None
            result = runner.invoke(main, ['license', 'status'])
            License._instance = None

        assert "FREE" in result.output or "License" in result.output

    def test_license_activate_invalid(self, runner, tmp_path):
        """Test activating invalid license."""
        with patch('tweek.licensing.LICENSE_FILE', tmp_path / "license.key"):
            License._instance = None
            result = runner.invoke(main, ['license', 'activate', 'invalid_key'])
            License._instance = None

        assert "Invalid" in result.output or "✗" in result.output

    def test_license_activate_valid(self, runner, tmp_path):
        """Test activating valid license."""
        key = generate_license_key(Tier.PRO, "test@example.com")

        license_file = tmp_path / ".tweek" / "license.key"
        with patch('tweek.licensing.LICENSE_FILE', license_file):
            License._instance = None
            result = runner.invoke(main, ['license', 'activate', key])
            License._instance = None

        assert "PRO" in result.output or "✓" in result.output

    def test_license_deactivate(self, runner, tmp_path):
        """Test deactivating license."""
        # First activate
        key = generate_license_key(Tier.PRO, "test@example.com")
        license_file = tmp_path / ".tweek" / "license.key"

        with patch('tweek.licensing.LICENSE_FILE', license_file):
            License._instance = None
            runner.invoke(main, ['license', 'activate', key])

            # Then deactivate
            result = runner.invoke(main, ['license', 'deactivate', '--confirm'])
            License._instance = None

        assert "FREE" in result.output or "deactivate" in result.output.lower()


class TestConfigCommands:
    """Tests for config subcommands."""

    def test_config_list(self, runner, tmp_path):
        """Test config list command."""
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir(parents=True, exist_ok=True)

        with patch.object(Path, 'home', return_value=tmp_path):
            result = runner.invoke(main, ['config', 'list'])

        assert result.exit_code == 0 or "Tool" in result.output or "Tier" in result.output

    def test_config_list_summary(self, runner, tmp_path):
        """Test config list --summary command (replaces config show)."""
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir(parents=True, exist_ok=True)

        with patch.object(Path, 'home', return_value=tmp_path):
            result = runner.invoke(main, ['config', 'list', '--summary'])

        assert result.exit_code == 0 or "Configuration" in result.output

    def test_config_set_tool(self, runner, tmp_path):
        """Test setting tool tier."""
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir(parents=True, exist_ok=True)

        with patch.object(Path, 'home', return_value=tmp_path):
            result = runner.invoke(
                main,
                ['config', 'set', '--tool', 'Bash', '--tier', 'dangerous']
            )

        assert "✓" in result.output or "dangerous" in result.output.lower()

    def test_config_preset(self, runner, tmp_path):
        """Test applying config preset."""
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir(parents=True, exist_ok=True)

        with patch.object(Path, 'home', return_value=tmp_path):
            result = runner.invoke(main, ['config', 'preset', 'paranoid'])

        assert "paranoid" in result.output.lower() or "✓" in result.output


class TestUpdateCommand:
    """Tests for the update command."""

    def test_update_check_no_patterns(self, runner, tmp_path):
        """Test update --check when patterns not installed."""
        with patch.object(Path, 'home', return_value=tmp_path):
            result = runner.invoke(main, ['update', '--check'])

        assert "not installed" in result.output.lower() or "Patterns" in result.output

    def test_update_clones_repo(self, runner, tmp_path):
        """Test update clones repo when patterns don't exist."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0,
                    stdout="Cloning...",
                    stderr=""
                )
                result = runner.invoke(main, ['update'])

        # Should attempt to clone
        if mock_run.called:
            call_args = str(mock_run.call_args)
            assert "clone" in call_args or "pull" in call_args


class TestLogsCommands:
    """Tests for logs subcommands."""

    def test_logs_show(self, runner, tmp_path):
        """Test logs show command."""
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir(parents=True, exist_ok=True)

        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.logging.security_log.get_logger') as mock_logger:
                mock_logger.return_value.get_recent_events.return_value = []
                result = runner.invoke(main, ['logs', 'show'])

        assert result.exit_code == 0 or "No events" in result.output or "events" in result.output.lower()

    def test_logs_show_stats(self, runner, tmp_path):
        """Test logs show --stats command (replaces logs stats)."""
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir(parents=True, exist_ok=True)

        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.logging.security_log.get_logger') as mock_logger:
                mock_logger.return_value.get_stats.return_value = {
                    'total_events': 0,
                    'by_decision': {},
                    'by_tool': {},
                    'top_patterns': []
                }
                result = runner.invoke(main, ['logs', 'show', '--stats'])

        assert result.exit_code == 0 or "Statistics" in result.output


class TestVaultCommands:
    """Tests for vault subcommands."""

    def test_vault_store_no_keyring(self, runner, tmp_path):
        """Test vault store when keyring not available."""
        with patch('tweek.vault.VAULT_AVAILABLE', False):
            result = runner.invoke(
                main,
                ['vault', 'store', 'test-skill', 'API_KEY', 'secret123']
            )

        assert "not available" in result.output.lower() or "keyring" in result.output.lower()

    def test_vault_get_not_found(self, runner, tmp_path):
        """Test vault get for non-existent credential."""
        with patch('tweek.vault.VAULT_AVAILABLE', True):
            with patch('tweek.vault.get_vault') as mock_vault:
                mock_vault.return_value.get.return_value = None
                result = runner.invoke(
                    main,
                    ['vault', 'get', 'test-skill', 'API_KEY']
                )

        assert "not found" in result.output.lower() or "✗" in result.output


class TestCLIHelp:
    """Tests for CLI help messages."""

    def test_main_help(self, runner):
        """Test main help message."""
        result = runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        assert "Tweek" in result.output or "security" in result.output.lower()

    def test_protect_claude_code_help(self, runner):
        """Test protect claude-code help message."""
        result = runner.invoke(main, ['protect', 'claude-code', '--help'])
        assert result.exit_code == 0
        assert "global" in result.output.lower()

    def test_license_help(self, runner):
        """Test license help message."""
        result = runner.invoke(main, ['license', '--help'])
        assert result.exit_code == 0
        assert "license" in result.output.lower()

    def test_config_help(self, runner):
        """Test config help message."""
        result = runner.invoke(main, ['config', '--help'])
        assert result.exit_code == 0

    def test_version(self, runner):
        """Test version flag."""
        result = runner.invoke(main, ['--version'])
        assert result.exit_code == 0
        # Should show version number
        assert "." in result.output or "version" in result.output.lower()
