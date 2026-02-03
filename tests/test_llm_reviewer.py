#!/usr/bin/env python3
"""
Tests for Tweek LLM Reviewer — Multi-Provider Support

Tests cover:
- Provider auto-detection chain
- Explicit provider selection
- OpenAI-compatible endpoint support (base_url)
- Custom API key env vars
- Model auto-resolution to provider defaults
- Error handling (timeout, API errors, parse failures)
- Response parsing (JSON extraction)
- ReviewProvider interface contracts
- Singleton behavior
- Configuration flow from tiers.yaml
"""

import json
import os
import pytest
from unittest.mock import patch, MagicMock

import tweek.security.llm_reviewer as llm_mod

HAS_ANTHROPIC = hasattr(llm_mod, 'anthropic')
HAS_OPENAI = hasattr(llm_mod, 'openai')
HAS_GENAI = hasattr(llm_mod, 'genai')

from tweek.security.llm_reviewer import (
    RiskLevel,
    LLMReviewResult,
    LLMReviewer,
    ReviewProvider,
    ReviewProviderError,
    AnthropicReviewProvider,
    OpenAIReviewProvider,
    GoogleReviewProvider,
    resolve_provider,
    get_llm_reviewer,
    DEFAULT_MODELS,
    DEFAULT_API_KEY_ENVS,
    _get_api_key,
    _auto_detect_provider,
    _create_explicit_provider,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture(autouse=True)
def reset_singleton():
    """Reset the singleton LLM reviewer between tests."""
    import tweek.security.llm_reviewer as mod
    mod._llm_reviewer = None
    yield
    mod._llm_reviewer = None


@pytest.fixture
def clean_env():
    """Remove all LLM-related env vars for clean testing."""
    env_vars = [
        "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
        "GOOGLE_API_KEY", "GEMINI_API_KEY",
        "TOGETHER_API_KEY", "GROQ_API_KEY",
    ]
    saved = {}
    for var in env_vars:
        if var in os.environ:
            saved[var] = os.environ.pop(var)
    yield
    for var, val in saved.items():
        os.environ[var] = val
    for var in env_vars:
        if var not in saved and var in os.environ:
            del os.environ[var]


# =============================================================================
# RISK LEVEL AND RESULT TESTS
# =============================================================================

class TestRiskLevel:
    def test_values(self):
        assert RiskLevel.SAFE.value == "safe"
        assert RiskLevel.SUSPICIOUS.value == "suspicious"
        assert RiskLevel.DANGEROUS.value == "dangerous"


class TestLLMReviewResult:
    def test_is_dangerous(self):
        result = LLMReviewResult(
            risk_level=RiskLevel.DANGEROUS, reason="test",
            confidence=0.9, details={}, should_prompt=True,
        )
        assert result.is_dangerous is True
        assert result.is_suspicious is True

    def test_is_suspicious(self):
        result = LLMReviewResult(
            risk_level=RiskLevel.SUSPICIOUS, reason="test",
            confidence=0.7, details={}, should_prompt=True,
        )
        assert result.is_dangerous is False
        assert result.is_suspicious is True

    def test_is_safe(self):
        result = LLMReviewResult(
            risk_level=RiskLevel.SAFE, reason="test",
            confidence=0.1, details={}, should_prompt=False,
        )
        assert result.is_dangerous is False
        assert result.is_suspicious is False


# =============================================================================
# REVIEW PROVIDER ERROR TESTS
# =============================================================================

class TestReviewProviderError:
    def test_basic_error(self):
        err = ReviewProviderError("something broke")
        assert str(err) == "something broke"
        assert err.is_timeout is False

    def test_timeout_error(self):
        err = ReviewProviderError("timed out", is_timeout=True)
        assert err.is_timeout is True


# =============================================================================
# API KEY RESOLUTION TESTS
# =============================================================================

class TestGetApiKey:
    def test_custom_env_var(self, clean_env):
        os.environ["MY_CUSTOM_KEY"] = "custom-key-123"
        assert _get_api_key("openai", api_key_env="MY_CUSTOM_KEY") == "custom-key-123"
        del os.environ["MY_CUSTOM_KEY"]

    def test_anthropic_default_env(self, clean_env):
        os.environ["ANTHROPIC_API_KEY"] = "ant-key"
        assert _get_api_key("anthropic") == "ant-key"

    def test_openai_default_env(self, clean_env):
        os.environ["OPENAI_API_KEY"] = "oai-key"
        assert _get_api_key("openai") == "oai-key"

    def test_google_primary_env(self, clean_env):
        os.environ["GOOGLE_API_KEY"] = "goog-key"
        assert _get_api_key("google") == "goog-key"

    def test_google_fallback_env(self, clean_env):
        os.environ["GEMINI_API_KEY"] = "gem-key"
        assert _get_api_key("google") == "gem-key"

    def test_google_primary_takes_precedence(self, clean_env):
        os.environ["GOOGLE_API_KEY"] = "goog-key"
        os.environ["GEMINI_API_KEY"] = "gem-key"
        assert _get_api_key("google") == "goog-key"

    def test_no_key_returns_none(self, clean_env):
        assert _get_api_key("anthropic") is None
        assert _get_api_key("openai") is None
        assert _get_api_key("google") is None

    def test_unknown_provider_returns_none(self, clean_env):
        assert _get_api_key("unknown_provider") is None

    def test_custom_env_missing_returns_none(self, clean_env):
        assert _get_api_key("openai", api_key_env="NONEXISTENT_KEY") is None


# =============================================================================
# PROVIDER AUTO-DETECTION TESTS
# =============================================================================

class TestAutoDetection:
    @patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", True)
    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True)
    @patch("tweek.security.llm_reviewer.GOOGLE_AVAILABLE", True)
    def test_anthropic_preferred_when_available(self, clean_env):
        os.environ["ANTHROPIC_API_KEY"] = "ant-key"
        os.environ["OPENAI_API_KEY"] = "oai-key"

        with patch("tweek.security.llm_reviewer.AnthropicReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            provider = _auto_detect_provider("auto", None, None, None, 5.0)
            mock_cls.assert_called_once_with(
                model=DEFAULT_MODELS["anthropic"], api_key="ant-key", timeout=5.0,
            )

    @patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", False)
    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True)
    @patch("tweek.security.llm_reviewer.GOOGLE_AVAILABLE", True)
    def test_openai_fallback_when_no_anthropic(self, clean_env):
        os.environ["OPENAI_API_KEY"] = "oai-key"

        with patch("tweek.security.llm_reviewer.OpenAIReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            provider = _auto_detect_provider("auto", None, None, None, 5.0)
            mock_cls.assert_called_once_with(
                model=DEFAULT_MODELS["openai"], api_key="oai-key", timeout=5.0,
            )

    @patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", False)
    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", False)
    @patch("tweek.security.llm_reviewer.GOOGLE_AVAILABLE", True)
    def test_google_fallback_when_no_anthropic_or_openai(self, clean_env):
        os.environ["GOOGLE_API_KEY"] = "goog-key"

        with patch("tweek.security.llm_reviewer.GoogleReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            provider = _auto_detect_provider("auto", None, None, None, 5.0)
            mock_cls.assert_called_once_with(
                model=DEFAULT_MODELS["google"], api_key="goog-key", timeout=5.0,
            )

    @patch("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", False)
    @patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", False)
    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", False)
    @patch("tweek.security.llm_reviewer.GOOGLE_AVAILABLE", False)
    def test_none_when_no_providers(self, clean_env):
        provider = _auto_detect_provider("auto", None, None, None, 5.0)
        assert provider is None

    @patch("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", False)
    @patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", True)
    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True)
    def test_no_keys_returns_none(self, clean_env):
        provider = _auto_detect_provider("auto", None, None, None, 5.0)
        assert provider is None

    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True)
    def test_base_url_forces_openai(self, clean_env):
        with patch("tweek.security.llm_reviewer.OpenAIReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            provider = _auto_detect_provider(
                "auto", "http://localhost:11434/v1", None, None, 5.0,
            )
            mock_cls.assert_called_once()
            call_kwargs = mock_cls.call_args
            assert call_kwargs[1]["base_url"] == "http://localhost:11434/v1"
            assert call_kwargs[1]["api_key"] == "not-needed"


# =============================================================================
# EXPLICIT PROVIDER CREATION TESTS
# =============================================================================

class TestExplicitProvider:
    @patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", True)
    def test_explicit_anthropic(self, clean_env):
        with patch("tweek.security.llm_reviewer.AnthropicReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            provider = _create_explicit_provider(
                "anthropic", "claude-3-opus-latest", None, None, "key123", 5.0,
            )
            mock_cls.assert_called_once_with(
                model="claude-3-opus-latest", api_key="key123", timeout=5.0,
            )

    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True)
    def test_explicit_openai_with_base_url(self, clean_env):
        with patch("tweek.security.llm_reviewer.OpenAIReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            provider = _create_explicit_provider(
                "openai", "llama3.2", "http://localhost:11434/v1", None, None, 5.0,
            )
            mock_cls.assert_called_once_with(
                model="llama3.2", api_key="not-needed",
                timeout=5.0, base_url="http://localhost:11434/v1",
            )

    @patch("tweek.security.llm_reviewer.GOOGLE_AVAILABLE", True)
    def test_explicit_google(self, clean_env):
        with patch("tweek.security.llm_reviewer.GoogleReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            provider = _create_explicit_provider(
                "google", "gemini-2.0-flash", None, None, "gkey", 5.0,
            )
            mock_cls.assert_called_once_with(
                model="gemini-2.0-flash", api_key="gkey", timeout=5.0,
            )

    @patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", False)
    def test_unavailable_sdk_returns_none(self, clean_env):
        provider = _create_explicit_provider(
            "anthropic", "auto", None, None, "key", 5.0,
        )
        assert provider is None

    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True)
    def test_unknown_provider_treated_as_openai_compatible(self, clean_env):
        with patch("tweek.security.llm_reviewer.OpenAIReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            provider = _create_explicit_provider(
                "groq", "llama-3.1-8b", "https://api.groq.com/openai/v1",
                "GROQ_API_KEY", None, 5.0,
            )
            mock_cls.assert_called_once()

    def test_no_key_no_base_url_returns_none(self, clean_env):
        with patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True):
            provider = _create_explicit_provider(
                "openai", "gpt-4o-mini", None, None, None, 5.0,
            )
            assert provider is None


# =============================================================================
# MODEL AUTO-RESOLUTION TESTS
# =============================================================================

class TestModelAutoResolution:
    @patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", True)
    def test_auto_resolves_to_anthropic_default(self, clean_env):
        with patch("tweek.security.llm_reviewer.AnthropicReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            _create_explicit_provider("anthropic", "auto", None, None, "key", 5.0)
            assert mock_cls.call_args[1]["model"] == "claude-3-5-haiku-latest"

    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True)
    def test_auto_resolves_to_openai_default(self, clean_env):
        with patch("tweek.security.llm_reviewer.OpenAIReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            _create_explicit_provider("openai", "auto", None, None, "key", 5.0)
            assert mock_cls.call_args[1]["model"] == "gpt-4o-mini"

    @patch("tweek.security.llm_reviewer.GOOGLE_AVAILABLE", True)
    def test_auto_resolves_to_google_default(self, clean_env):
        with patch("tweek.security.llm_reviewer.GoogleReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            _create_explicit_provider("google", "auto", None, None, "key", 5.0)
            assert mock_cls.call_args[1]["model"] == "gemini-2.0-flash"

    @patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", True)
    def test_explicit_model_preserved(self, clean_env):
        with patch("tweek.security.llm_reviewer.AnthropicReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            _create_explicit_provider("anthropic", "claude-3-opus-latest", None, None, "key", 5.0)
            assert mock_cls.call_args[1]["model"] == "claude-3-opus-latest"


# =============================================================================
# RESOLVE_PROVIDER INTEGRATION TESTS
# =============================================================================

class TestResolveProvider:
    @patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", True)
    def test_auto_mode(self, clean_env):
        os.environ["ANTHROPIC_API_KEY"] = "test-key"
        with patch("tweek.security.llm_reviewer.AnthropicReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            provider = resolve_provider(provider="auto")
            assert provider is not None

    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True)
    def test_explicit_mode(self, clean_env):
        with patch("tweek.security.llm_reviewer.OpenAIReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            provider = resolve_provider(
                provider="openai", model="gpt-4o", api_key="key",
            )
            assert provider is not None

    def test_no_providers_returns_none(self, clean_env):
        with patch("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", False), \
             patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", False), \
             patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", False), \
             patch("tweek.security.llm_reviewer.GOOGLE_AVAILABLE", False):
            provider = resolve_provider()
            assert provider is None


# =============================================================================
# LLM REVIEWER TESTS
# =============================================================================

class TestLLMReviewer:
    def _make_reviewer_with_mock_provider(self, response_text="{}"):
        """Create an LLMReviewer with a mock provider."""
        mock_provider = MagicMock(spec=ReviewProvider)
        mock_provider.is_available.return_value = True
        mock_provider.call.return_value = response_text
        mock_provider.name = "mock"
        mock_provider.model_name = "mock-model"

        reviewer = LLMReviewer.__new__(LLMReviewer)
        reviewer._provider_instance = mock_provider
        reviewer.enabled = True
        reviewer.timeout = 5.0
        return reviewer, mock_provider

    def test_disabled_returns_safe(self):
        reviewer = LLMReviewer(enabled=False)
        result = reviewer.review("ls -la", "Bash", "safe")
        assert result.risk_level == RiskLevel.SAFE
        assert result.should_prompt is False
        assert result.details.get("disabled") is True

    def test_review_safe_response(self):
        response = json.dumps({
            "risk_level": "safe", "reason": "Simple listing", "confidence": 0.95,
        })
        reviewer, mock_prov = self._make_reviewer_with_mock_provider(response)
        result = reviewer.review("ls -la", "Bash", "safe")

        assert result.risk_level == RiskLevel.SAFE
        assert result.confidence == 0.95
        assert result.should_prompt is False
        assert result.details["provider"] == "mock"
        assert result.details["model"] == "mock-model"

    def test_review_dangerous_response(self):
        response = json.dumps({
            "risk_level": "dangerous", "reason": "SSH key exfiltration", "confidence": 0.99,
        })
        reviewer, _ = self._make_reviewer_with_mock_provider(response)
        result = reviewer.review("cat ~/.ssh/id_rsa", "Bash", "dangerous")

        assert result.risk_level == RiskLevel.DANGEROUS
        assert result.should_prompt is True

    def test_review_suspicious_high_confidence_prompts(self):
        response = json.dumps({
            "risk_level": "suspicious", "reason": "Unusual access", "confidence": 0.8,
        })
        reviewer, _ = self._make_reviewer_with_mock_provider(response)
        result = reviewer.review("cat /etc/passwd", "Bash", "risky")

        assert result.risk_level == RiskLevel.SUSPICIOUS
        assert result.should_prompt is True  # >= 0.7

    def test_review_suspicious_low_confidence_no_prompt(self):
        response = json.dumps({
            "risk_level": "suspicious", "reason": "Might be odd", "confidence": 0.5,
        })
        reviewer, _ = self._make_reviewer_with_mock_provider(response)
        result = reviewer.review("ls /tmp", "Bash", "default")

        assert result.risk_level == RiskLevel.SUSPICIOUS
        assert result.should_prompt is False  # < 0.7

    def test_review_timeout_fails_closed(self):
        reviewer, mock_prov = self._make_reviewer_with_mock_provider()
        mock_prov.call.side_effect = ReviewProviderError("timeout", is_timeout=True)

        result = reviewer.review("slow command", "Bash", "dangerous")
        assert result.risk_level == RiskLevel.SUSPICIOUS
        assert result.should_prompt is True
        assert "timed out" in result.reason

    def test_review_api_error_fails_closed(self):
        reviewer, mock_prov = self._make_reviewer_with_mock_provider()
        mock_prov.call.side_effect = ReviewProviderError("rate limited")

        result = reviewer.review("some command", "Bash", "risky")
        assert result.risk_level == RiskLevel.SUSPICIOUS
        assert result.should_prompt is True

    def test_review_unexpected_error_fails_closed(self):
        reviewer, mock_prov = self._make_reviewer_with_mock_provider()
        mock_prov.call.side_effect = RuntimeError("unexpected")

        result = reviewer.review("some command", "Bash", "risky")
        assert result.risk_level == RiskLevel.SUSPICIOUS
        assert result.should_prompt is True

    def test_review_command_truncated_to_2000(self):
        reviewer, mock_prov = self._make_reviewer_with_mock_provider(
            json.dumps({"risk_level": "safe", "reason": "ok", "confidence": 0.9})
        )
        long_command = "x" * 5000
        reviewer.review(long_command, "Bash", "default")

        call_args = mock_prov.call.call_args
        user_prompt = call_args[1]["user_prompt"]
        # The command in the prompt should be truncated
        assert "x" * 2000 in user_prompt
        assert "x" * 2001 not in user_prompt

    def test_model_property(self):
        reviewer, _ = self._make_reviewer_with_mock_provider()
        assert reviewer.model == "mock-model"

    def test_provider_name_property(self):
        reviewer, _ = self._make_reviewer_with_mock_provider()
        assert reviewer.provider_name == "mock"

    def test_model_when_disabled(self):
        reviewer = LLMReviewer(enabled=False)
        assert reviewer.model == "none"
        assert reviewer.provider_name == "none"


# =============================================================================
# RESPONSE PARSING TESTS
# =============================================================================

class TestResponseParsing:
    def _make_reviewer(self):
        reviewer = LLMReviewer.__new__(LLMReviewer)
        reviewer._provider_instance = None
        reviewer.enabled = False
        reviewer.timeout = 5.0
        return reviewer

    def test_parse_clean_json(self):
        reviewer = self._make_reviewer()
        result = reviewer._parse_response('{"risk_level": "safe", "reason": "ok", "confidence": 0.9}')
        assert result["risk_level"] == "safe"

    def test_parse_json_with_surrounding_text(self):
        reviewer = self._make_reviewer()
        result = reviewer._parse_response('Here is my analysis: {"risk_level": "suspicious", "reason": "odd", "confidence": 0.7}')
        assert result["risk_level"] == "suspicious"

    def test_parse_invalid_json_returns_suspicious(self):
        reviewer = self._make_reviewer()
        result = reviewer._parse_response("This is not JSON at all")
        assert result["risk_level"] == "suspicious"
        assert result["confidence"] == 0.5

    def test_parse_empty_returns_suspicious(self):
        reviewer = self._make_reviewer()
        result = reviewer._parse_response("")
        assert result["risk_level"] == "suspicious"

    def test_parse_invalid_risk_level_defaults_to_suspicious(self):
        response = json.dumps({
            "risk_level": "invalid_level", "reason": "test", "confidence": 0.5,
        })
        reviewer, _ = TestLLMReviewer()._make_reviewer_with_mock_provider(response)
        result = reviewer.review("test", "Bash", "default")
        assert result.risk_level == RiskLevel.SUSPICIOUS


# =============================================================================
# TRANSLATE TESTS
# =============================================================================

class TestTranslate:
    def test_translate_disabled(self):
        reviewer = LLMReviewer(enabled=False)
        result = reviewer.translate("Bonjour le monde")
        assert result["translated_text"] == "Bonjour le monde"
        assert result["error"] == "LLM review disabled"

    def test_translate_success(self):
        mock_provider = MagicMock(spec=ReviewProvider)
        mock_provider.is_available.return_value = True
        mock_provider.call.return_value = json.dumps({
            "translated_text": "Hello world",
            "detected_language": "French",
            "confidence": 0.95,
        })
        mock_provider.name = "mock"
        mock_provider.model_name = "mock-model"

        reviewer = LLMReviewer.__new__(LLMReviewer)
        reviewer._provider_instance = mock_provider
        reviewer.enabled = True
        reviewer.timeout = 5.0

        result = reviewer.translate("Bonjour le monde")
        assert result["translated_text"] == "Hello world"
        assert result["detected_language"] == "French"
        assert result["provider"] == "mock"

    def test_translate_error_returns_original(self):
        mock_provider = MagicMock(spec=ReviewProvider)
        mock_provider.is_available.return_value = True
        mock_provider.call.side_effect = RuntimeError("API down")
        mock_provider.name = "mock"
        mock_provider.model_name = "mock-model"

        reviewer = LLMReviewer.__new__(LLMReviewer)
        reviewer._provider_instance = mock_provider
        reviewer.enabled = True
        reviewer.timeout = 5.0

        result = reviewer.translate("Bonjour")
        assert result["translated_text"] == "Bonjour"
        assert "error" in result


# =============================================================================
# FORMAT REVIEW MESSAGE TESTS
# =============================================================================

class TestFormatReviewMessage:
    def test_no_prompt_returns_empty(self):
        reviewer = LLMReviewer(enabled=False)
        result = LLMReviewResult(
            risk_level=RiskLevel.SAFE, reason="ok",
            confidence=0.9, details={}, should_prompt=False,
        )
        assert reviewer.format_review_message(result) == ""

    def test_dangerous_format(self):
        reviewer = LLMReviewer(enabled=False)
        result = LLMReviewResult(
            risk_level=RiskLevel.DANGEROUS, reason="SSH exfil",
            confidence=0.99, details={}, should_prompt=True,
        )
        msg = reviewer.format_review_message(result)
        assert "LLM SECURITY REVIEW" in msg
        assert "DANGEROUS" in msg
        assert "99%" in msg
        assert "SSH exfil" in msg


# =============================================================================
# CONTEXT BUILDING TESTS
# =============================================================================

class TestBuildContext:
    def _make_reviewer(self):
        reviewer = LLMReviewer.__new__(LLMReviewer)
        reviewer._provider_instance = None
        reviewer.enabled = False
        reviewer.timeout = 5.0
        return reviewer

    def test_empty_context(self):
        reviewer = self._make_reviewer()
        assert reviewer._build_context() == "No additional context"

    def test_file_path_context(self):
        reviewer = self._make_reviewer()
        ctx = reviewer._build_context(tool_input={"file_path": "/tmp/test.txt"})
        assert "Target file: /tmp/test.txt" in ctx

    def test_url_context(self):
        reviewer = self._make_reviewer()
        ctx = reviewer._build_context(tool_input={"url": "https://example.com"})
        assert "URL: https://example.com" in ctx

    def test_session_context(self):
        reviewer = self._make_reviewer()
        ctx = reviewer._build_context(session_context="session:abc123")
        assert "Session: session:abc123" in ctx

    def test_combined_context(self):
        reviewer = self._make_reviewer()
        ctx = reviewer._build_context(
            tool_input={"file_path": "/tmp/x", "url": "https://y.com"},
            session_context="session:z",
        )
        assert "Target file:" in ctx
        assert "URL:" in ctx
        assert "Session:" in ctx


# =============================================================================
# SINGLETON TESTS
# =============================================================================

class TestGetLLMReviewer:
    def test_returns_same_instance(self, clean_env):
        with patch("tweek.security.llm_reviewer.resolve_provider", return_value=None):
            r1 = get_llm_reviewer()
            r2 = get_llm_reviewer()
            assert r1 is r2

    def test_passes_params_to_constructor(self, clean_env):
        with patch("tweek.security.llm_reviewer.resolve_provider", return_value=None) as mock_resolve:
            reviewer = get_llm_reviewer(
                model="gpt-4o", provider="openai",
                base_url="http://localhost:11434/v1",
                api_key_env="MY_KEY",
            )
            # Verify core params are passed through (local_config/fallback_config
            # are loaded from tiers.yaml and may vary)
            call_kwargs = mock_resolve.call_args[1]
            assert call_kwargs["provider"] == "openai"
            assert call_kwargs["model"] == "gpt-4o"
            assert call_kwargs["base_url"] == "http://localhost:11434/v1"
            assert call_kwargs["api_key_env"] == "MY_KEY"
            assert call_kwargs["api_key"] is None
            assert call_kwargs["timeout"] == 5.0

    def test_disabled_when_no_provider(self, clean_env):
        with patch("tweek.security.llm_reviewer.resolve_provider", return_value=None):
            reviewer = get_llm_reviewer()
            assert reviewer.enabled is False


# =============================================================================
# DEFAULT MODELS AND ENV VARS TESTS
# =============================================================================

class TestDefaults:
    def test_default_models_defined(self):
        assert "anthropic" in DEFAULT_MODELS
        assert "openai" in DEFAULT_MODELS
        assert "google" in DEFAULT_MODELS

    def test_default_api_key_envs_defined(self):
        assert "anthropic" in DEFAULT_API_KEY_ENVS
        assert "openai" in DEFAULT_API_KEY_ENVS
        assert "google" in DEFAULT_API_KEY_ENVS

    def test_google_has_multiple_env_vars(self):
        envs = DEFAULT_API_KEY_ENVS["google"]
        assert isinstance(envs, list)
        assert len(envs) >= 2


# =============================================================================
# PROVIDER IMPLEMENTATION TESTS (with mocked SDKs)
# =============================================================================

@pytest.mark.skipif(not HAS_ANTHROPIC, reason="anthropic SDK not installed")
class TestAnthropicReviewProvider:
    @patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", True)
    def test_properties(self):
        with patch("tweek.security.llm_reviewer.anthropic") as mock_anthropic:
            mock_anthropic.Anthropic.return_value = MagicMock()
            provider = AnthropicReviewProvider(
                model="claude-3-5-haiku-latest", api_key="test-key",
            )
            assert provider.name == "anthropic"
            assert provider.model_name == "claude-3-5-haiku-latest"
            assert provider.is_available() is True

    @patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", True)
    def test_call_success(self):
        with patch("tweek.security.llm_reviewer.anthropic") as mock_anthropic:
            mock_client = MagicMock()
            mock_anthropic.Anthropic.return_value = mock_client

            mock_response = MagicMock()
            mock_response.content = [MagicMock(text='{"risk_level": "safe"}')]
            mock_client.messages.create.return_value = mock_response

            provider = AnthropicReviewProvider(
                model="claude-3-5-haiku-latest", api_key="test-key",
            )
            result = provider.call("system", "user")
            assert result == '{"risk_level": "safe"}'

    @patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", True)
    def test_call_timeout(self):
        with patch("tweek.security.llm_reviewer.anthropic") as mock_anthropic:
            mock_client = MagicMock()
            mock_anthropic.Anthropic.return_value = mock_client
            # Create proper exception hierarchy
            _APITimeoutError = type("APITimeoutError", (Exception,), {})
            _APIError = type("APIError", (Exception,), {})
            mock_anthropic.APITimeoutError = _APITimeoutError
            mock_anthropic.APIError = _APIError
            mock_client.messages.create.side_effect = _APITimeoutError("timeout")

            provider = AnthropicReviewProvider(
                model="claude-3-5-haiku-latest", api_key="test-key",
            )
            with pytest.raises(ReviewProviderError) as exc_info:
                provider.call("system", "user")
            assert exc_info.value.is_timeout is True

    @patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", True)
    def test_call_api_error(self):
        with patch("tweek.security.llm_reviewer.anthropic") as mock_anthropic:
            mock_client = MagicMock()
            mock_anthropic.Anthropic.return_value = mock_client
            # Create proper exception hierarchy
            _APITimeoutError = type("APITimeoutError", (Exception,), {})
            _APIError = type("APIError", (Exception,), {})
            mock_anthropic.APITimeoutError = _APITimeoutError
            mock_anthropic.APIError = _APIError
            mock_client.messages.create.side_effect = _APIError("rate limited")

            provider = AnthropicReviewProvider(
                model="claude-3-5-haiku-latest", api_key="test-key",
            )
            with pytest.raises(ReviewProviderError) as exc_info:
                provider.call("system", "user")
            assert exc_info.value.is_timeout is False


@pytest.mark.skipif(not HAS_OPENAI, reason="openai SDK not installed")
class TestOpenAIReviewProvider:
    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True)
    def test_properties(self):
        with patch("tweek.security.llm_reviewer.openai") as mock_openai:
            mock_openai.OpenAI.return_value = MagicMock()
            provider = OpenAIReviewProvider(
                model="gpt-4o-mini", api_key="test-key",
            )
            assert provider.name == "openai"
            assert provider.model_name == "gpt-4o-mini"
            assert provider.is_available() is True

    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True)
    def test_name_with_base_url(self):
        with patch("tweek.security.llm_reviewer.openai") as mock_openai:
            mock_openai.OpenAI.return_value = MagicMock()
            provider = OpenAIReviewProvider(
                model="llama3.2", api_key="not-needed",
                base_url="http://localhost:11434/v1",
            )
            assert "openai-compatible" in provider.name
            assert "localhost:11434" in provider.name

    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True)
    def test_is_available_with_base_url_no_key(self):
        with patch("tweek.security.llm_reviewer.openai") as mock_openai:
            mock_openai.OpenAI.return_value = MagicMock()
            provider = OpenAIReviewProvider(
                model="local", api_key="",
                base_url="http://localhost:11434/v1",
            )
            assert provider.is_available() is True

    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True)
    def test_call_success(self):
        with patch("tweek.security.llm_reviewer.openai") as mock_openai:
            mock_client = MagicMock()
            mock_openai.OpenAI.return_value = mock_client

            mock_choice = MagicMock()
            mock_choice.message.content = '{"risk_level": "safe"}'
            mock_response = MagicMock()
            mock_response.choices = [mock_choice]
            mock_client.chat.completions.create.return_value = mock_response

            provider = OpenAIReviewProvider(
                model="gpt-4o-mini", api_key="test-key",
            )
            result = provider.call("system", "user")
            assert result == '{"risk_level": "safe"}'

    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True)
    def test_call_timeout(self):
        with patch("tweek.security.llm_reviewer.openai") as mock_openai:
            mock_client = MagicMock()
            mock_openai.OpenAI.return_value = mock_client
            _APITimeoutError = type("APITimeoutError", (Exception,), {})
            _APIError = type("APIError", (Exception,), {})
            mock_openai.APITimeoutError = _APITimeoutError
            mock_openai.APIError = _APIError
            mock_client.chat.completions.create.side_effect = _APITimeoutError("timeout")

            provider = OpenAIReviewProvider(
                model="gpt-4o-mini", api_key="test-key",
            )
            with pytest.raises(ReviewProviderError) as exc_info:
                provider.call("system", "user")
            assert exc_info.value.is_timeout is True


@pytest.mark.skipif(not HAS_GENAI, reason="google-generativeai SDK not installed")
class TestGoogleReviewProvider:
    @patch("tweek.security.llm_reviewer.GOOGLE_AVAILABLE", True)
    def test_properties(self):
        with patch("tweek.security.llm_reviewer.genai") as mock_genai:
            mock_genai.GenerativeModel.return_value = MagicMock()
            provider = GoogleReviewProvider(
                model="gemini-2.0-flash", api_key="test-key",
            )
            assert provider.name == "google"
            assert provider.model_name == "gemini-2.0-flash"
            assert provider.is_available() is True

    @patch("tweek.security.llm_reviewer.GOOGLE_AVAILABLE", True)
    def test_call_success(self):
        with patch("tweek.security.llm_reviewer.genai") as mock_genai:
            mock_model = MagicMock()
            mock_genai.GenerativeModel.return_value = mock_model
            mock_response = MagicMock()
            mock_response.text = '{"risk_level": "safe"}'
            mock_model.generate_content.return_value = mock_response

            provider = GoogleReviewProvider(
                model="gemini-2.0-flash", api_key="test-key",
            )
            result = provider.call("system", "user")
            assert result == '{"risk_level": "safe"}'

    @patch("tweek.security.llm_reviewer.GOOGLE_AVAILABLE", True)
    def test_call_timeout_detection(self):
        with patch("tweek.security.llm_reviewer.genai") as mock_genai:
            mock_model = MagicMock()
            mock_genai.GenerativeModel.return_value = mock_model
            mock_model.generate_content.side_effect = Exception("Deadline exceeded timeout")

            provider = GoogleReviewProvider(
                model="gemini-2.0-flash", api_key="test-key",
            )
            with pytest.raises(ReviewProviderError) as exc_info:
                provider.call("system", "user")
            assert exc_info.value.is_timeout is True

    @patch("tweek.security.llm_reviewer.GOOGLE_AVAILABLE", True)
    def test_call_generic_error(self):
        with patch("tweek.security.llm_reviewer.genai") as mock_genai:
            mock_model = MagicMock()
            mock_genai.GenerativeModel.return_value = mock_model
            mock_model.generate_content.side_effect = Exception("Permission denied")

            provider = GoogleReviewProvider(
                model="gemini-2.0-flash", api_key="test-key",
            )
            with pytest.raises(ReviewProviderError) as exc_info:
                provider.call("system", "user")
            assert exc_info.value.is_timeout is False


# =============================================================================
# INIT WITH PROVIDER CONFIG TESTS
# =============================================================================

class TestLLMReviewerInit:
    def test_disabled_creates_no_provider(self):
        reviewer = LLMReviewer(enabled=False)
        assert reviewer.enabled is False
        assert reviewer._provider_instance is None

    def test_enabled_with_no_provider_disables(self, clean_env):
        with patch("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", False), \
             patch("tweek.security.llm_reviewer.ANTHROPIC_AVAILABLE", False), \
             patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", False), \
             patch("tweek.security.llm_reviewer.GOOGLE_AVAILABLE", False):
            reviewer = LLMReviewer(enabled=True)
            assert reviewer.enabled is False

    def test_enabled_with_provider(self, clean_env):
        mock_provider = MagicMock(spec=ReviewProvider)
        mock_provider.is_available.return_value = True
        with patch("tweek.security.llm_reviewer.resolve_provider", return_value=mock_provider):
            reviewer = LLMReviewer(enabled=True, provider="openai", api_key="key")
            assert reviewer.enabled is True
            assert reviewer._provider_instance is mock_provider

    def test_provider_param_passed_through(self, clean_env):
        with patch("tweek.security.llm_reviewer.resolve_provider", return_value=None) as mock_resolve:
            reviewer = LLMReviewer(
                model="llama3.2",
                provider="openai",
                base_url="http://localhost:11434/v1",
                api_key_env="MY_KEY",
                api_key="direct-key",
                timeout=3.0,
            )
            # Verify core params are passed through (local_config/fallback_config
            # default to None when called directly via LLMReviewer)
            call_kwargs = mock_resolve.call_args[1]
            assert call_kwargs["provider"] == "openai"
            assert call_kwargs["model"] == "llama3.2"
            assert call_kwargs["base_url"] == "http://localhost:11434/v1"
            assert call_kwargs["api_key_env"] == "MY_KEY"
            assert call_kwargs["api_key"] == "direct-key"
            assert call_kwargs["timeout"] == 3.0


# =============================================================================
# CUSTOM ENV VAR TESTS (end-to-end)
# =============================================================================

class TestCustomApiKeyEnv:
    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True)
    def test_together_ai_config(self, clean_env):
        os.environ["TOGETHER_API_KEY"] = "together-key"
        with patch("tweek.security.llm_reviewer.OpenAIReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            mock_cls.return_value.is_available.return_value = True
            provider = resolve_provider(
                provider="openai",
                model="meta-llama/Llama-3.1-8B-Instruct-Turbo",
                base_url="https://api.together.xyz/v1",
                api_key_env="TOGETHER_API_KEY",
            )
            assert provider is not None
            mock_cls.assert_called_once_with(
                model="meta-llama/Llama-3.1-8B-Instruct-Turbo",
                api_key="together-key",
                timeout=5.0,
                base_url="https://api.together.xyz/v1",
            )

    @patch("tweek.security.llm_reviewer.OPENAI_AVAILABLE", True)
    def test_groq_config(self, clean_env):
        os.environ["GROQ_API_KEY"] = "groq-key"
        with patch("tweek.security.llm_reviewer.OpenAIReviewProvider") as mock_cls:
            mock_cls.return_value = MagicMock(spec=ReviewProvider)
            mock_cls.return_value.is_available.return_value = True
            provider = resolve_provider(
                provider="openai",
                model="llama-3.1-8b-instant",
                base_url="https://api.groq.com/openai/v1",
                api_key_env="GROQ_API_KEY",
            )
            assert provider is not None
            mock_cls.assert_called_once_with(
                model="llama-3.1-8b-instant",
                api_key="groq-key",
                timeout=5.0,
                base_url="https://api.groq.com/openai/v1",
            )
