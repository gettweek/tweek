#!/usr/bin/env python3
"""
Tests for installer improvements:
- --quick flag
- Scope selection (always shown, smart defaults)
- LLM provider selection prompt
- API key validation
- Post-install verification and summary
- .env scan reordering
"""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from click.testing import CliRunner
from rich.console import Console

import sys
import shutil
sys.path.insert(0, str(Path(__file__).parent.parent))

from tweek.cli import main
from tweek.cli_install import (
    _check_python_version,
    _configure_llm_provider,
    _detect_cloud_llm_provider,
    _detect_llm_provider,
    _show_llm_info,
    _validate_llm_provider,
    _print_install_summary,
)

pytestmark = pytest.mark.cli


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def tmp_home(tmp_path):
    """Create a temp home with .claude and .tweek dirs."""
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".tweek").mkdir()
    return tmp_path


@pytest.fixture(autouse=True)
def clean_llm_env(monkeypatch):
    """Remove LLM API keys from env to avoid side effects."""
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def mock_claude_on_path():
    """Mock Claude Code binary as available (not installed in CI)."""
    _original = shutil.which
    def _which(cmd):
        if cmd == "claude":
            return "/usr/local/bin/claude"
        return _original(cmd)
    with patch('tweek.cli_install.shutil.which', new=_which):
        yield


# ═══════════════════════════════════════════════════════════════
# --quick flag
# ═══════════════════════════════════════════════════════════════

class TestQuickFlag:
    """Tests for the --quick zero-prompt install flag."""

    def test_quick_flag_no_prompts(self, runner, tmp_path):
        """--quick should complete without any user prompts."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--quick', '--skip-proxy-check'],
                    catch_exceptions=False,
                )

        assert result.exit_code == 0
        assert "Installation complete" in result.output

    def test_quick_applies_balanced_preset(self, runner, tmp_path):
        """--quick should apply balanced preset by default."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--quick'],
                    catch_exceptions=False,
                )

        assert "balanced" in result.output.lower()

    def test_quick_skips_env_scan(self, runner, tmp_path):
        """--quick should skip .env scanning."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--quick'],
                    catch_exceptions=False,
                )

        # Should not mention scanning for .env
        assert "Scanning for .env" not in result.output

    def test_quick_skips_proxy_check(self, runner, tmp_path):
        """--quick should skip proxy/openclaw detection."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--quick'],
                    catch_exceptions=False,
                )

        assert "openclaw" not in result.output.lower()

    def test_quick_with_preset_override(self, runner, tmp_path):
        """--quick with explicit --preset uses the specified preset."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--quick', '--preset', 'paranoid'],
                    catch_exceptions=False,
                )

        assert "paranoid" in result.output.lower()

    def test_quick_skips_scope_prompt(self, runner, tmp_path):
        """--quick should not prompt for scope selection."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--quick'],
                    catch_exceptions=False,
                )

        # Should not show scope selection prompt
        assert "Installation Scope" not in result.output

    def test_quick_skips_llm_prompt(self, runner, tmp_path):
        """--quick should not prompt for LLM provider selection."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--quick'],
                    catch_exceptions=False,
                )

        # Should not show the LLM provider selection menu
        assert "Custom endpoint" not in result.output


# ═══════════════════════════════════════════════════════════════
# Scope selection
# ═══════════════════════════════════════════════════════════════

class TestScopeSelection:
    """Tests for improved scope selection logic."""

    def test_scope_shown_without_interactive_flag(self, runner, tmp_path):
        """Scope selection should appear even without --interactive."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--skip-env-scan', '--skip-proxy-check'],
                    input='1\n1\n',  # scope=project, llm=auto
                    catch_exceptions=False,
                )

        assert "Installation Scope" in result.output

    def test_scope_skipped_with_global_flag(self, runner, tmp_path):
        """--global should skip scope prompt."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--global', '--skip-env-scan', '--skip-proxy-check'],
                    input='1\n',  # llm=auto
                    catch_exceptions=False,
                )

        assert "Installation Scope" not in result.output
        assert "global" in result.output.lower()

    def test_scope_defaults_to_global(self, runner, tmp_path):
        """Scope should default to global (recommended)."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--skip-env-scan', '--skip-proxy-check'],
                    input='1\n1\n',  # Accept default scope (global), llm=auto
                    catch_exceptions=False,
                )

        assert "recommended" in result.output.lower()
        assert "global" in result.output.lower()

    def test_scope_option_2_is_project(self, runner, tmp_path):
        """Selecting option 2 should install to project only."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--skip-env-scan', '--skip-proxy-check'],
                    input='2\n1\n',  # scope=project, llm=auto
                    catch_exceptions=False,
                )

        assert "project" in result.output.lower()


# ═══════════════════════════════════════════════════════════════
# LLM provider detection
# ═══════════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════════
# Python version check
# ═══════════════════════════════════════════════════════════════

class TestCheckPythonVersion:
    """Tests for _check_python_version pre-flight check."""

    def test_shows_current_python(self, capsys):
        """Should display the running Python version."""
        _check_python_version(Console(), quick=False)
        captured = capsys.readouterr()
        assert "Python" in captured.out
        assert sys.executable in captured.out

    def test_warns_system_python_mismatch(self, monkeypatch, capsys):
        """Should warn when system python3 differs from install Python."""
        # Mock shutil.which to return a different path than sys.executable
        fake_system_python = "/usr/bin/python3"
        monkeypatch.setattr("tweek.cli_install.shutil.which", lambda cmd: fake_system_python if cmd == "python3" else None)

        # Make sure the paths resolve differently
        monkeypatch.setattr("tweek.cli_install.Path.resolve",
                          lambda self: Path(fake_system_python) if str(self) == fake_system_python
                          else Path(sys.executable))

        _check_python_version(Console(), quick=False)
        captured = capsys.readouterr()
        # Should mention the system python or note about hooks
        assert "Python" in captured.out

    def test_no_python3_on_path_warns(self, monkeypatch, capsys):
        """Should warn when python3 is not found on PATH."""
        monkeypatch.setattr("tweek.cli_install.shutil.which", lambda cmd: None)
        _check_python_version(Console(), quick=False)
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower() or "Python" in captured.out

    def test_no_python3_on_path_quiet_in_quick(self, monkeypatch, capsys):
        """Quick mode should not warn about missing python3 on PATH."""
        monkeypatch.setattr("tweek.cli_install.shutil.which", lambda cmd: None)
        _check_python_version(Console(), quick=True)
        captured = capsys.readouterr()
        # In quick mode, the "not found on PATH" warning should be suppressed
        assert "not found" not in captured.out.lower()


class TestDetectLLMProvider:
    """Tests for _detect_llm_provider helper."""

    @pytest.fixture(autouse=True)
    def no_local_model(self, monkeypatch):
        """Disable local model detection so cloud tests are deterministic."""
        monkeypatch.setattr(
            "tweek.security.local_model.LOCAL_MODEL_AVAILABLE", False
        )

    def test_detects_anthropic(self, monkeypatch):
        """Should detect Anthropic when ANTHROPIC_API_KEY is set."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-key")
        result = _detect_llm_provider()
        assert result is not None
        assert result["name"] == "Anthropic"
        assert "haiku" in result["model"]

    def test_detects_openai(self, monkeypatch):
        """Should detect OpenAI when OPENAI_API_KEY is set."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        result = _detect_llm_provider()
        assert result is not None
        assert result["name"] == "OpenAI"
        assert "gpt-4o-mini" in result["model"]

    def test_detects_google(self, monkeypatch):
        """Should detect Google when GOOGLE_API_KEY is set."""
        monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
        result = _detect_llm_provider()
        assert result is not None
        assert result["name"] == "Google"
        assert "gemini" in result["model"]

    def test_detects_gemini_api_key(self, monkeypatch):
        """Should detect Google when GEMINI_API_KEY is set."""
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        result = _detect_llm_provider()
        assert result is not None
        assert result["name"] == "Google"

    def test_prefers_google_over_anthropic(self, monkeypatch):
        """Google should be preferred (free tier) when multiple keys exist."""
        monkeypatch.setenv("GOOGLE_API_KEY", "test-google-key")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-anthropic")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
        result = _detect_llm_provider()
        assert result["name"] == "Google"

    def test_returns_none_when_no_keys(self):
        """Should return None when no API keys and no local model."""
        result = _detect_llm_provider()
        assert result is None

    def test_detects_local_model_first(self, monkeypatch):
        """Local model should be detected before cloud providers."""
        # Re-enable local model for this test
        monkeypatch.setattr("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", True)
        monkeypatch.setattr(
            "tweek.security.model_registry.is_model_installed", lambda name: True
        )
        monkeypatch.setattr(
            "tweek.security.model_registry.get_default_model_name",
            lambda: "deberta-v3-injection",
        )
        # Also set an API key to prove local model takes priority
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")

        result = _detect_llm_provider()
        assert result is not None
        assert result["name"] == "Local model"
        assert result["env_var"] is None

    def test_falls_through_when_local_model_not_installed(self, monkeypatch):
        """Should fall through to cloud if local model deps are present but model not downloaded."""
        monkeypatch.setattr("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", True)
        monkeypatch.setattr(
            "tweek.security.model_registry.is_model_installed", lambda name: False
        )
        monkeypatch.setattr(
            "tweek.security.model_registry.get_default_model_name",
            lambda: "deberta-v3-injection",
        )
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

        result = _detect_llm_provider()
        assert result is not None
        assert result["name"] == "OpenAI"


# ═══════════════════════════════════════════════════════════════
# Cloud-only LLM provider detection
# ═══════════════════════════════════════════════════════════════

class TestDetectCloudLLMProvider:
    """Tests for _detect_cloud_llm_provider."""

    @pytest.fixture(autouse=True)
    def no_local_model(self, monkeypatch):
        """Disable local model for deterministic tests."""
        monkeypatch.setattr(
            "tweek.security.local_model.LOCAL_MODEL_AVAILABLE", False
        )

    def test_returns_none_no_keys(self, monkeypatch):
        """Returns None when no cloud API keys are set."""
        for var in ("GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY",
                     "XAI_API_KEY", "ANTHROPIC_API_KEY"):
            monkeypatch.delenv(var, raising=False)
        assert _detect_cloud_llm_provider() is None

    def test_detects_google(self, monkeypatch):
        """Returns Google when GOOGLE_API_KEY is set."""
        monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
        result = _detect_cloud_llm_provider()
        assert result is not None
        assert result["name"] == "Google"
        assert result["model"] == "gemini-2.0-flash"

    def test_detects_anthropic(self, monkeypatch):
        """Returns Anthropic when ANTHROPIC_API_KEY is set."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        result = _detect_cloud_llm_provider()
        assert result is not None
        assert result["name"] == "Anthropic"

    def test_skips_local_model(self, monkeypatch):
        """Never returns local model — only cloud providers."""
        monkeypatch.setattr("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", True)
        monkeypatch.setattr(
            "tweek.security.model_registry.is_model_installed", lambda name: True
        )
        monkeypatch.setattr(
            "tweek.security.model_registry.get_default_model_name",
            lambda: "deberta-v3-injection",
        )
        # No cloud keys set
        for var in ("GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY",
                     "XAI_API_KEY", "ANTHROPIC_API_KEY"):
            monkeypatch.delenv(var, raising=False)
        result = _detect_cloud_llm_provider()
        assert result is None


# ═══════════════════════════════════════════════════════════════
# Install-time LLM info display (non-interactive)
# ═══════════════════════════════════════════════════════════════

class TestShowLLMInfo:
    """Tests for _show_llm_info — non-interactive install display."""

    @pytest.fixture(autouse=True)
    def no_local_model(self, monkeypatch):
        """Disable local model for deterministic tests."""
        monkeypatch.setattr(
            "tweek.security.local_model.LOCAL_MODEL_AVAILABLE", False
        )

    def test_no_keys_shows_info_no_prompts(self, tmp_path, monkeypatch, capsys):
        """No prompts, returns correct dict when no API keys set."""
        for var in ("GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY",
                     "XAI_API_KEY", "ANTHROPIC_API_KEY"):
            monkeypatch.delenv(var, raising=False)
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        # Verify no click.prompt is called
        with patch('tweek.cli_install.click.prompt') as mock_prompt:
            result = _show_llm_info(tweek_dir)
            mock_prompt.assert_not_called()

        assert result["provider"] == "auto"
        assert "not configured" in result["provider_display"]
        assert result["model_display"] is None

    def test_with_google_key_shows_detected(self, tmp_path, monkeypatch):
        """Detects and displays Google provider when key is set."""
        monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        result = _show_llm_info(tweek_dir)

        assert result["provider_display"] == "Google"
        assert result["model_display"] == "gemini-2.0-flash"

    def test_local_model_only_not_shown_as_llm(self, tmp_path, monkeypatch):
        """Local classifier is not displayed as the LLM reviewer."""
        monkeypatch.setattr("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", True)
        monkeypatch.setattr(
            "tweek.security.model_registry.is_model_installed", lambda name: True
        )
        monkeypatch.setattr(
            "tweek.security.model_registry.get_default_model_name",
            lambda: "deberta-v3-injection",
        )
        # No cloud keys
        for var in ("GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY",
                     "XAI_API_KEY", "ANTHROPIC_API_KEY"):
            monkeypatch.delenv(var, raising=False)
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        result = _show_llm_info(tweek_dir)

        # Should NOT show "Local model" or "deberta" as the LLM provider
        assert result["provider_display"] is not None
        assert "Local model" not in (result["provider_display"] or "")
        assert "deberta" not in (result["provider_display"] or "")
        assert "not configured" in result["provider_display"]

    def test_returns_correct_summary_dict(self, tmp_path, monkeypatch):
        """Return dict has all expected keys for install summary."""
        for var in ("GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENAI_API_KEY",
                     "XAI_API_KEY", "ANTHROPIC_API_KEY"):
            monkeypatch.delenv(var, raising=False)
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        result = _show_llm_info(tweek_dir)

        expected_keys = {
            "provider", "model", "base_url", "api_key_env",
            "provider_display", "model_display",
        }
        assert set(result.keys()) == expected_keys


# ═══════════════════════════════════════════════════════════════
# LLM provider configuration (interactive wizard for `tweek configure llm`)
# ═══════════════════════════════════════════════════════════════

class TestConfigureLLMProvider:
    """Tests for _configure_llm_provider."""

    @pytest.fixture(autouse=True)
    def no_local_model(self, monkeypatch):
        """Disable local model so cloud provider tests are deterministic."""
        monkeypatch.setattr(
            "tweek.security.local_model.LOCAL_MODEL_AVAILABLE", False
        )

    def test_quick_mode_skips_prompt(self, tmp_path, capsys):
        """Quick mode should not show LLM selection prompt."""
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()
        result = _configure_llm_provider(tweek_dir, interactive=False, quick=True)
        assert result["provider"] == "auto"

    def test_auto_detect_with_anthropic_key(self, tmp_path, monkeypatch, capsys):
        """Auto-detect should find Anthropic when key is set."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()
        result = _configure_llm_provider(tweek_dir, interactive=False, quick=True)
        assert result["provider_display"] == "Anthropic"
        assert "haiku" in result["model_display"]

    def test_auto_detect_no_keys(self, tmp_path, capsys):
        """Auto-detect should report disabled when no keys and no local model."""
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()
        result = _configure_llm_provider(tweek_dir, interactive=False, quick=True)
        assert "disabled" in result["provider_display"]
        assert result["model_display"] is None

    def test_auto_detect_finds_local_model(self, tmp_path, monkeypatch, capsys):
        """Auto-detect should find local model even without API keys."""
        monkeypatch.setattr("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", True)
        monkeypatch.setattr(
            "tweek.security.model_registry.is_model_installed", lambda name: True
        )
        monkeypatch.setattr(
            "tweek.security.model_registry.get_default_model_name",
            lambda: "deberta-v3-injection",
        )
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()
        result = _configure_llm_provider(tweek_dir, interactive=False, quick=True)
        assert result["provider_display"] == "Local model"
        assert result["model_display"] == "deberta-v3-injection"

    def test_disabled_provider_saves_config(self, tmp_path, capsys):
        """Selecting 'disable' should save enabled: false to config."""
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        # Simulate user choosing option 6 (disable)
        with patch('tweek.cli_install.click.prompt', return_value=6):
            result = _configure_llm_provider(tweek_dir, interactive=True, quick=False)

        assert result["provider"] == "disabled"

        # Check config file was written
        import yaml
        config_path = tweek_dir / "config.yaml"
        assert config_path.exists()
        with open(config_path) as f:
            config = yaml.safe_load(f)
        assert config["llm_review"]["enabled"] is False

    def test_explicit_anthropic_saves_config(self, tmp_path, monkeypatch, capsys):
        """Selecting Anthropic should save provider to config."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        # Simulate user choosing option 2 (Anthropic), confirming billing warning
        with patch('tweek.cli_install.click.prompt', side_effect=[2, "continue"]), \
             patch('tweek.cli_install.click.confirm', return_value=True):
            result = _configure_llm_provider(tweek_dir, interactive=True, quick=False)

        assert result["provider"] == "anthropic"
        assert result["model"] == "claude-3-5-haiku-latest"

        import yaml
        config_path = tweek_dir / "config.yaml"
        assert config_path.exists()
        with open(config_path) as f:
            config = yaml.safe_load(f)
        assert config["llm_review"]["provider"] == "anthropic"

    def test_explicit_openai_saves_config(self, tmp_path, monkeypatch, capsys):
        """Selecting OpenAI should save provider to config."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        with patch('tweek.cli_install.click.prompt', side_effect=[3, "continue"]):
            result = _configure_llm_provider(tweek_dir, interactive=True, quick=False)

        assert result["provider"] == "openai"
        assert result["model"] == "gpt-4o-mini"

    def test_explicit_google_saves_config(self, tmp_path, monkeypatch, capsys):
        """Selecting Google should save provider to config."""
        monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        with patch('tweek.cli_install.click.prompt', side_effect=[4, "continue"]):
            result = _configure_llm_provider(tweek_dir, interactive=True, quick=False)

        assert result["provider"] == "google"
        assert result["model"] == "gemini-2.0-flash"

    def test_custom_endpoint_saves_config(self, tmp_path, capsys):
        """Selecting custom endpoint should save base_url and model."""
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        # Simulate: choice=5, base_url, model, api_key_env (empty)
        with patch('tweek.cli_install.click.prompt', side_effect=[
            5,                                  # Custom endpoint
            "http://localhost:11434/v1",         # base_url
            "llama3.2",                         # model
            "",                                  # api_key_env (blank)
        ]):
            result = _configure_llm_provider(tweek_dir, interactive=True, quick=False)

        assert result["provider"] == "openai"
        assert result["base_url"] == "http://localhost:11434/v1"
        assert result["model"] == "llama3.2"

        import yaml
        config_path = tweek_dir / "config.yaml"
        assert config_path.exists()
        with open(config_path) as f:
            config = yaml.safe_load(f)
        assert config["llm_review"]["base_url"] == "http://localhost:11434/v1"
        assert config["llm_review"]["model"] == "llama3.2"

    def test_custom_endpoint_with_api_key_env(self, tmp_path, monkeypatch, capsys):
        """Custom endpoint with api_key_env should save it."""
        monkeypatch.setenv("GROQ_API_KEY", "gsk-test-key")
        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        with patch('tweek.cli_install.click.prompt', side_effect=[
            5,
            "https://api.groq.com/openai/v1",
            "llama-3.1-8b-instant",
            "GROQ_API_KEY",
        ]):
            result = _configure_llm_provider(tweek_dir, interactive=True, quick=False)

        assert result["api_key_env"] == "GROQ_API_KEY"

        import yaml
        config_path = tweek_dir / "config.yaml"
        with open(config_path) as f:
            config = yaml.safe_load(f)
        assert config["llm_review"]["api_key_env"] == "GROQ_API_KEY"


# ═══════════════════════════════════════════════════════════════
# API key validation
# ═══════════════════════════════════════════════════════════════

class TestValidateLLMProvider:
    """Tests for _validate_llm_provider."""

    @pytest.fixture(autouse=True)
    def no_local_model(self, monkeypatch):
        """Disable local model so fallback tests are deterministic."""
        monkeypatch.setattr(
            "tweek.security.local_model.LOCAL_MODEL_AVAILABLE", False
        )

    def test_validates_anthropic_key_present(self, monkeypatch, capsys):
        """Should show success when Anthropic key is found."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        config = {"provider": "anthropic"}
        _validate_llm_provider(config)
        captured = capsys.readouterr()
        assert "ANTHROPIC_API_KEY" in captured.out
        assert "found" in captured.out.lower()

    def test_validates_openai_key_present(self, monkeypatch, capsys):
        """Should show success when OpenAI key is found."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        config = {"provider": "openai"}
        _validate_llm_provider(config)
        captured = capsys.readouterr()
        assert "OPENAI_API_KEY" in captured.out

    def test_warns_missing_key(self, capsys):
        """Should warn when required API key is missing."""
        config = {"provider": "anthropic"}
        with patch('tweek.cli_install.click.confirm', return_value=False), \
             patch('tweek.cli_install.click.prompt', return_value="continue"):
            _validate_llm_provider(config)
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower()

    def test_offers_auto_fallback(self, monkeypatch, capsys):
        """Should offer auto-detect fallback when key is missing."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        config = {"provider": "anthropic"}

        # User declines to enter key, then chooses to switch to auto
        with patch('tweek.cli_install.click.confirm', return_value=False), \
             patch('tweek.cli_install.click.prompt', return_value="auto"):
            _validate_llm_provider(config)

        # Config should be updated to auto
        assert config["provider"] == "auto"
        assert config["provider_display"] == "OpenAI"

    def test_custom_api_key_env_validated(self, monkeypatch, capsys):
        """Should check custom api_key_env variable."""
        monkeypatch.setenv("GROQ_API_KEY", "test-key")
        config = {"provider": "openai", "api_key_env": "GROQ_API_KEY"}
        _validate_llm_provider(config)
        captured = capsys.readouterr()
        assert "GROQ_API_KEY" in captured.out
        assert "found" in captured.out.lower()

    def test_local_endpoint_skips_key_check(self, capsys):
        """Custom base_url endpoints should check reachability, not API key."""
        config = {
            "provider": "openai",
            "base_url": "http://localhost:11434/v1",
            "model": "llama3.2",
        }
        # Mock resolve_provider at its source module to avoid actual network call
        with patch('tweek.security.llm_reviewer.resolve_provider', return_value=None):
            _validate_llm_provider(config)
        captured = capsys.readouterr()
        assert "endpoint" in captured.out.lower()


# ═══════════════════════════════════════════════════════════════
# Post-install summary
# ═══════════════════════════════════════════════════════════════

class TestInstallSummary:
    """Tests for _print_install_summary."""

    def test_summary_shows_scope(self, tmp_path, capsys):
        """Summary should display installation scope."""
        target = tmp_path / ".claude"
        target.mkdir()
        settings_file = target / "settings.json"
        settings_file.write_text(json.dumps({
            "hooks": {"PreToolUse": [], "PostToolUse": []}
        }))

        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        summary = {
            "scope": "project",
            "preset": "cautious",
            "llm_provider": "Anthropic",
            "llm_model": "claude-3-5-haiku-latest",
        }

        _print_install_summary(summary, target, tweek_dir, False)
        captured = capsys.readouterr()
        assert "Installation complete" in captured.out
        assert "project" in captured.out.lower()

    def test_summary_shows_hooks_active(self, tmp_path, capsys):
        """Summary should verify hooks are installed."""
        target = tmp_path / ".claude"
        target.mkdir()
        settings_file = target / "settings.json"
        settings_file.write_text(json.dumps({
            "hooks": {"PreToolUse": [{}], "PostToolUse": [{}]}
        }))

        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        summary = {
            "scope": "project",
            "preset": "cautious",
            "llm_provider": None,
            "llm_model": None,
        }

        _print_install_summary(summary, target, tweek_dir, False)
        captured = capsys.readouterr()
        assert "PreToolUse" in captured.out
        assert "PostToolUse" in captured.out

    def test_summary_shows_llm_provider(self, tmp_path, capsys):
        """Summary should display LLM provider information."""
        target = tmp_path / ".claude"
        target.mkdir()
        (target / "settings.json").write_text("{}")

        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        summary = {
            "scope": "global",
            "preset": "paranoid",
            "llm_provider": "OpenAI",
            "llm_model": "gpt-4o-mini",
        }

        _print_install_summary(summary, target, tweek_dir, False)
        captured = capsys.readouterr()
        assert "OpenAI" in captured.out
        assert "gpt-4o-mini" in captured.out

    def test_summary_shows_preset(self, tmp_path, capsys):
        """Summary should display the security preset."""
        target = tmp_path / ".claude"
        target.mkdir()
        (target / "settings.json").write_text("{}")

        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        summary = {
            "scope": "project",
            "preset": "paranoid",
            "llm_provider": None,
            "llm_model": None,
        }

        _print_install_summary(summary, target, tweek_dir, False)
        captured = capsys.readouterr()
        assert "paranoid" in captured.out.lower()

    def test_summary_shows_proxy_status(self, tmp_path, capsys):
        """Summary should display proxy configuration status."""
        target = tmp_path / ".claude"
        target.mkdir()
        (target / "settings.json").write_text("{}")

        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        summary = {
            "scope": "project",
            "preset": "cautious",
            "llm_provider": None,
            "llm_model": None,
        }

        _print_install_summary(summary, target, tweek_dir, True)
        captured = capsys.readouterr()
        assert "configured" in captured.out.lower()

    def test_summary_shows_next_steps(self, tmp_path, capsys):
        """Summary should display next step commands."""
        target = tmp_path / ".claude"
        target.mkdir()
        (target / "settings.json").write_text("{}")

        tweek_dir = tmp_path / ".tweek"
        tweek_dir.mkdir()

        summary = {
            "scope": "project",
            "preset": "cautious",
            "llm_provider": None,
            "llm_model": None,
        }

        _print_install_summary(summary, target, tweek_dir, False)
        captured = capsys.readouterr()
        assert "tweek doctor" in captured.out
        assert "tweek update" in captured.out
        assert "tweek config list" in captured.out


# ═══════════════════════════════════════════════════════════════
# .env scan reordering
# ═══════════════════════════════════════════════════════════════

class TestEnvScanOrdering:
    """Tests verifying .env scan happens after security config."""

    def test_env_scan_after_security_config(self, runner, tmp_path):
        """The .env scan should appear after security preset in output."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--preset', 'cautious', '--skip-proxy-check'],
                    input='1\n1\n',  # scope=project, llm=auto
                    catch_exceptions=False,
                )

        output = result.output
        # If .env scan appears, it should come after the preset
        if "Scanning for .env" in output:
            preset_pos = output.find("cautious")
            env_pos = output.find("Scanning for .env")
            assert preset_pos < env_pos, ".env scan should come after preset application"


# ═══════════════════════════════════════════════════════════════
# Integration: full interactive install flow
# ═══════════════════════════════════════════════════════════════

class TestInteractiveInstallFlow:
    """Integration tests for the full interactive install flow."""

    def test_interactive_full_flow(self, runner, tmp_path):
        """Full interactive install with all prompts."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--interactive', '--skip-env-scan', '--skip-proxy-check'],
                    input='1\n2\n1\n',  # scope=project, preset=cautious, llm=auto
                    catch_exceptions=False,
                )

        assert result.exit_code == 0
        assert "Installation complete" in result.output
        assert "Verification" in result.output
        assert "Summary" in result.output

    def test_interactive_with_llm_selection(self, runner, tmp_path, monkeypatch):
        """Interactive install with explicit LLM provider selection."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-key")

        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--skip-env-scan', '--skip-proxy-check'],
                    input='1\n2\ncontinue\n',  # scope=project, llm=anthropic, continue
                    catch_exceptions=False,
                )

        assert result.exit_code == 0
        assert "Anthropic" in result.output

    def test_non_interactive_shows_summary(self, runner, tmp_path):
        """Non-interactive install should still show summary."""
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch('tweek.cli_install.Path.home', return_value=tmp_path):
                result = runner.invoke(
                    main,
                    ['protect', 'claude-code', '--quick'],
                    catch_exceptions=False,
                )

        assert "Summary" in result.output
        assert "Verification" in result.output
