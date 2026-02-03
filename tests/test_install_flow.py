"""Tests for install flow improvements.

Covers: auto model deps, multi-tool detection, API key validation,
preset descriptions, and doctor --fix mode.
"""
from __future__ import annotations

import os
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path


@pytest.mark.cli
class TestAutoModelDeps:
    """_ensure_local_model_deps installs missing packages."""

    def test_deps_already_available(self):
        """Returns True immediately when deps are importable."""
        from tweek.cli_install import _ensure_local_model_deps

        with patch("builtins.__import__", side_effect=lambda name, *a, **kw: MagicMock()):
            result = _ensure_local_model_deps()
            assert result is True

    def test_deps_install_failure_returns_false(self):
        """Returns False when pip install fails."""
        from tweek.cli_install import _ensure_local_model_deps

        # First import raises ImportError, subprocess fails
        original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

        def mock_import(name, *args, **kwargs):
            if name in ("onnxruntime", "tokenizers", "numpy"):
                raise ImportError(f"No module named '{name}'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=1, stderr="pip error")
                result = _ensure_local_model_deps()
                assert result is False


@pytest.mark.cli
class TestDetectLlmProvider:
    """_detect_llm_provider checks both API key and SDK availability."""

    def test_google_key_without_sdk_skipped(self):
        """Google key present but SDK not importable returns None."""
        from importlib import import_module as real_import_module
        from tweek.cli_install import _detect_llm_provider

        def selective_import(name, *args, **kwargs):
            """Block only the SDK modules, let everything else through."""
            if name in ("google.generativeai", "openai", "anthropic"):
                raise ImportError(f"No module named '{name}'")
            return real_import_module(name, *args, **kwargs)

        # Ensure no other API keys leak through
        env_clean = {
            "GOOGLE_API_KEY": "test-key",
            "OPENAI_API_KEY": "",
            "XAI_API_KEY": "",
            "ANTHROPIC_API_KEY": "",
            "GEMINI_API_KEY": "",
        }

        with patch.dict(os.environ, env_clean, clear=False):
            with patch("tweek.cli_install.LOCAL_MODEL_AVAILABLE", False, create=True):
                with patch("importlib.import_module", side_effect=selective_import):
                    result = _detect_llm_provider()
                    assert result is None

    def test_google_key_with_sdk_detected(self):
        """Google key + SDK returns Google provider."""
        from tweek.cli_install import _detect_llm_provider

        with patch.dict(os.environ, {"GOOGLE_API_KEY": "test-key"}, clear=False):
            with patch("importlib.import_module", return_value=MagicMock()):
                with patch("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", False):
                    result = _detect_llm_provider()
                    assert result is not None
                    assert result["name"] == "Google"

    def test_local_model_takes_priority(self):
        """Local model is preferred over cloud providers."""
        from tweek.cli_install import _detect_llm_provider

        with patch.dict(os.environ, {"GOOGLE_API_KEY": "test-key"}, clear=False):
            with patch("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", True):
                with patch("tweek.security.model_registry.is_model_installed", return_value=True):
                    with patch("tweek.security.model_registry.get_default_model_name", return_value="deberta"):
                        result = _detect_llm_provider()
                        assert result is not None
                        assert result["name"] == "Local model"


@pytest.mark.cli
class TestDetectAndShowTools:
    """_detect_and_show_tools returns unprotected tools."""

    def test_returns_unprotected_only(self):
        """Only installed+unprotected tools are returned."""
        from tweek.cli_install import _detect_and_show_tools

        mock_tools = [
            ("claude-code", "Claude Code", True, True, ""),
            ("gemini", "Gemini CLI", True, False, ""),
            ("chatgpt", "ChatGPT Desktop", False, False, ""),
        ]
        with patch("tweek.cli_install._detect_all_tools", return_value=mock_tools):
            result = _detect_and_show_tools()
            assert len(result) == 1
            assert result[0][0] == "gemini"

    def test_returns_empty_when_all_protected(self):
        """Returns empty list when all tools are already protected."""
        from tweek.cli_install import _detect_and_show_tools

        mock_tools = [
            ("claude-code", "Claude Code", True, True, ""),
        ]
        with patch("tweek.cli_install._detect_all_tools", return_value=mock_tools):
            result = _detect_and_show_tools()
            assert len(result) == 0


@pytest.mark.core
class TestDoctorFixFlag:
    """tweek doctor --fix triggers interactive mode."""

    def test_run_health_checks_accepts_interactive(self):
        """run_health_checks accepts interactive parameter."""
        from tweek.diagnostics import run_health_checks

        # Should not raise even with interactive=True
        # (it just won't prompt since there may be no fixable issues)
        with patch("tweek.diagnostics._offer_interactive_fixes") as mock_fix:
            results = run_health_checks(verbose=False, interactive=True)
            mock_fix.assert_called_once()
            assert isinstance(results, list)

    def test_non_interactive_skips_fixes(self):
        """Default mode does not call _offer_interactive_fixes."""
        from tweek.diagnostics import run_health_checks

        with patch("tweek.diagnostics._offer_interactive_fixes") as mock_fix:
            results = run_health_checks(verbose=False, interactive=False)
            mock_fix.assert_not_called()
