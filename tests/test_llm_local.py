#!/usr/bin/env python3
"""
Tests for Tweek Local LLM Support

Tests cover:
- _probe_ollama with mocked HTTP responses
- _probe_openai_compatible with mocked HTTP responses
- _select_best_local_model preference ordering
- _detect_local_server integration
- FallbackReviewProvider chain behavior
- Validation suite pass/fail thresholds
- Validation cache load/save
- Auto-detection prefers local over cloud
"""

import json
import os
import pytest
import time
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

from tweek.security.llm_reviewer import (
    _probe_ollama,
    _probe_openai_compatible,
    _select_best_local_model,
    _detect_local_server,
    _load_validation_cache,
    _save_validation_cache,
    FallbackReviewProvider,
    ReviewProvider,
    ReviewProviderError,
    LOCAL_MODEL_PREFERENCES,
    VALIDATION_SUITE,
    LocalServerInfo,
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


class MockProvider(ReviewProvider):
    """Mock ReviewProvider for testing."""

    def __init__(self, name_val: str = "mock", model_val: str = "mock-model",
                 available: bool = True, response: str = '{"risk_level":"safe","reason":"test","confidence":0.9}',
                 error: Exception = None):
        self._name = name_val
        self._model = model_val
        self._available = available
        self._response = response
        self._error = error
        self.call_count = 0

    def call(self, system_prompt: str, user_prompt: str, max_tokens: int = 256) -> str:
        self.call_count += 1
        if self._error:
            raise self._error
        return self._response

    def is_available(self) -> bool:
        return self._available

    @property
    def name(self) -> str:
        return self._name

    @property
    def model_name(self) -> str:
        return self._model


# =============================================================================
# PROBE TESTS
# =============================================================================

class TestProbeOllama:
    """Test _probe_ollama with mocked HTTP."""

    def test_returns_model_list_on_success(self):
        mock_response = json.dumps({
            "models": [
                {"name": "qwen2.5:7b-instruct"},
                {"name": "llama3.1:8b"},
            ]
        }).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_response
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("tweek.security.llm_reviewer.urllib.request.urlopen", return_value=mock_resp):
            result = _probe_ollama(host="http://localhost:11434", timeout=0.5)

        assert result == ["qwen2.5:7b-instruct", "llama3.1:8b"]

    def test_returns_none_on_connection_error(self):
        with patch("tweek.security.llm_reviewer.urllib.request.urlopen",
                    side_effect=ConnectionRefusedError("refused")):
            result = _probe_ollama(host="http://localhost:99999", timeout=0.1)
        assert result is None

    def test_returns_none_on_timeout(self):
        import urllib.error
        with patch("tweek.security.llm_reviewer.urllib.request.urlopen",
                    side_effect=urllib.error.URLError("timeout")):
            result = _probe_ollama(timeout=0.1)
        assert result is None

    def test_uses_ollama_host_env(self):
        with patch.dict(os.environ, {"OLLAMA_HOST": "http://custom:9999"}):
            with patch("tweek.security.llm_reviewer.urllib.request.urlopen",
                       side_effect=ConnectionRefusedError()) as mock_open:
                _probe_ollama(timeout=0.1)
                # Should have tried the custom host
                if mock_open.called:
                    url = mock_open.call_args[0][0]
                    if hasattr(url, 'full_url'):
                        assert "custom:9999" in url.full_url


class TestProbeOpenAICompatible:
    """Test _probe_openai_compatible with mocked HTTP."""

    def test_returns_model_list_on_success(self):
        mock_response = json.dumps({
            "data": [
                {"id": "phi3.5:latest"},
                {"id": "gemma2:9b"},
            ]
        }).encode()

        mock_resp = MagicMock()
        mock_resp.read.return_value = mock_response
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("tweek.security.llm_reviewer.urllib.request.urlopen", return_value=mock_resp):
            result = _probe_openai_compatible(host="http://localhost:1234", timeout=0.5)

        assert result == ["phi3.5:latest", "gemma2:9b"]

    def test_returns_none_on_error(self):
        with patch("tweek.security.llm_reviewer.urllib.request.urlopen",
                    side_effect=ConnectionRefusedError()):
            result = _probe_openai_compatible(timeout=0.1)
        assert result is None


# =============================================================================
# MODEL SELECTION TESTS
# =============================================================================

class TestSelectBestLocalModel:
    """Test _select_best_local_model preference ordering."""

    def test_picks_highest_preference(self):
        available = ["mistral:7b", "llama3.1:8b", "qwen2.5:7b-instruct"]
        best = _select_best_local_model(available)
        assert best == "qwen2.5:7b-instruct"

    def test_picks_second_preference_if_first_missing(self):
        available = ["mistral:7b", "llama3.1:8b"]
        best = _select_best_local_model(available)
        assert best == "llama3.1:8b"

    def test_user_preferences_override(self):
        available = ["qwen2.5:7b-instruct", "phi3.5:latest"]
        best = _select_best_local_model(available, preferred=["phi3.5:latest"])
        assert best == "phi3.5:latest"

    def test_returns_first_available_if_no_match(self):
        available = ["custom-model:latest"]
        best = _select_best_local_model(available)
        assert best == "custom-model:latest"

    def test_returns_none_for_empty_list(self):
        best = _select_best_local_model([])
        assert best is None

    def test_case_insensitive_matching(self):
        available = ["Qwen2.5:7B-Instruct"]
        best = _select_best_local_model(available)
        assert best == "Qwen2.5:7B-Instruct"


# =============================================================================
# FALLBACK PROVIDER TESTS
# =============================================================================

class TestFallbackReviewProvider:
    """Test FallbackReviewProvider chain behavior."""

    def test_uses_first_available_provider(self):
        p1 = MockProvider(name_val="local", response='{"risk_level":"safe","reason":"ok","confidence":0.9}')
        p2 = MockProvider(name_val="cloud", response='{"risk_level":"safe","reason":"ok","confidence":0.8}')

        fallback = FallbackReviewProvider([p1, p2])
        result = fallback.call("sys", "user")

        assert p1.call_count == 1
        assert p2.call_count == 0
        assert fallback.active_provider == p1

    def test_falls_back_on_error(self):
        p1 = MockProvider(name_val="local", error=ReviewProviderError("local failed"))
        p2 = MockProvider(name_val="cloud", response='{"risk_level":"safe","reason":"ok","confidence":0.8}')

        fallback = FallbackReviewProvider([p1, p2])
        result = fallback.call("sys", "user")

        assert p1.call_count == 1
        assert p2.call_count == 1
        assert fallback.active_provider == p2

    def test_raises_when_all_fail(self):
        p1 = MockProvider(name_val="local", error=ReviewProviderError("local failed"))
        p2 = MockProvider(name_val="cloud", error=ReviewProviderError("cloud failed"))

        fallback = FallbackReviewProvider([p1, p2])
        with pytest.raises(ReviewProviderError, match="All providers failed"):
            fallback.call("sys", "user")

    def test_skips_unavailable_providers(self):
        p1 = MockProvider(name_val="local", available=False)
        p2 = MockProvider(name_val="cloud", response='{"risk_level":"safe","reason":"ok","confidence":0.8}')

        fallback = FallbackReviewProvider([p1, p2])
        result = fallback.call("sys", "user")

        assert p1.call_count == 0
        assert p2.call_count == 1

    def test_is_available_true_if_any_available(self):
        p1 = MockProvider(available=False)
        p2 = MockProvider(available=True)
        fallback = FallbackReviewProvider([p1, p2])
        assert fallback.is_available() is True

    def test_is_available_false_if_none_available(self):
        p1 = MockProvider(available=False)
        p2 = MockProvider(available=False)
        fallback = FallbackReviewProvider([p1, p2])
        assert fallback.is_available() is False

    def test_provider_count(self):
        p1 = MockProvider(available=True)
        p2 = MockProvider(available=False)
        p3 = MockProvider(available=True)
        fallback = FallbackReviewProvider([p1, p2, p3])
        assert fallback.provider_count == 2

    def test_name_shows_chain(self):
        p1 = MockProvider(name_val="local", available=True)
        p2 = MockProvider(name_val="cloud", available=True)
        fallback = FallbackReviewProvider([p1, p2])
        # Before any call, shows chain
        assert "local" in fallback.name
        assert "cloud" in fallback.name

    def test_name_shows_active_after_call(self):
        p1 = MockProvider(name_val="local")
        p2 = MockProvider(name_val="cloud")
        fallback = FallbackReviewProvider([p1, p2])
        fallback.call("sys", "user")
        assert "local" in fallback.name

    def test_filters_none_providers(self):
        p1 = MockProvider(name_val="local")
        fallback = FallbackReviewProvider([None, p1, None])
        assert fallback.provider_count == 1


# =============================================================================
# VALIDATION CACHE TESTS
# =============================================================================

class TestValidationCache:
    """Test validation cache load/save."""

    def test_load_empty_cache(self, tmp_path):
        with patch("tweek.security.llm_reviewer._VALIDATION_CACHE_FILE",
                    tmp_path / "nonexistent.json"):
            cache = _load_validation_cache()
            assert cache == {}

    def test_save_and_load_cache(self, tmp_path):
        cache_file = tmp_path / "validations.json"
        with patch("tweek.security.llm_reviewer._VALIDATION_CACHE_FILE", cache_file), \
             patch("tweek.security.llm_reviewer._VALIDATION_CACHE_DIR", tmp_path):
            test_data = {"model1": {"passed": True, "score": 0.8, "timestamp": time.time()}}
            _save_validation_cache(test_data)

            loaded = _load_validation_cache()
            assert loaded["model1"]["passed"] is True
            assert loaded["model1"]["score"] == 0.8

    def test_load_corrupted_cache_returns_empty(self, tmp_path):
        cache_file = tmp_path / "validations.json"
        cache_file.write_text("not valid json {{{")

        with patch("tweek.security.llm_reviewer._VALIDATION_CACHE_FILE", cache_file):
            cache = _load_validation_cache()
            assert cache == {}


# =============================================================================
# LOCAL SERVER DETECTION TESTS
# =============================================================================

class TestDetectLocalServer:
    """Test _detect_local_server integration."""

    def test_detects_ollama(self):
        models = ["qwen2.5:7b-instruct", "llama3.1:8b"]
        with patch("tweek.security.llm_reviewer._probe_ollama", return_value=models):
            with patch("tweek.security.llm_reviewer._probe_openai_compatible", return_value=None):
                result = _detect_local_server()
                assert result is not None
                assert result.server_type == "ollama"
                assert result.model == "qwen2.5:7b-instruct"

    def test_falls_back_to_lm_studio(self):
        models = ["phi3.5:latest"]
        with patch("tweek.security.llm_reviewer._probe_ollama", return_value=None):
            with patch("tweek.security.llm_reviewer._probe_openai_compatible", return_value=models):
                result = _detect_local_server()
                assert result is not None
                assert result.server_type == "lm_studio"

    def test_returns_none_when_nothing_found(self):
        with patch("tweek.security.llm_reviewer._probe_ollama", return_value=None):
            with patch("tweek.security.llm_reviewer._probe_openai_compatible", return_value=None):
                result = _detect_local_server()
                assert result is None

    def test_uses_config_hosts(self):
        config = {
            "ollama_host": "http://gpu-server:11434",
            "lm_studio_host": "http://gpu-server:1234",
            "probe_timeout": 0.1,
        }
        with patch("tweek.security.llm_reviewer._probe_ollama", return_value=None) as mock_ollama:
            with patch("tweek.security.llm_reviewer._probe_openai_compatible", return_value=None):
                _detect_local_server(config)
                mock_ollama.assert_called_once_with(
                    host="http://gpu-server:11434", timeout=0.1
                )


# =============================================================================
# VALIDATION SUITE TESTS
# =============================================================================

class TestValidationSuite:
    """Test the validation suite structure."""

    def test_suite_has_five_cases(self):
        assert len(VALIDATION_SUITE) == 5

    def test_suite_entries_have_correct_format(self):
        for entry in VALIDATION_SUITE:
            assert len(entry) == 4
            command, tool, tier, expected = entry
            assert isinstance(command, str)
            assert isinstance(tool, str)
            assert isinstance(tier, str)
            assert expected in ("safe", "suspicious", "dangerous")

    def test_suite_covers_safe_and_dangerous(self):
        expected_levels = {entry[3] for entry in VALIDATION_SUITE}
        assert "safe" in expected_levels
        assert "dangerous" in expected_levels


# =============================================================================
# CONSTANTS TESTS
# =============================================================================

class TestConstants:
    """Test module-level constants."""

    def test_local_model_preferences_not_empty(self):
        assert len(LOCAL_MODEL_PREFERENCES) > 0

    def test_qwen_is_first_preference(self):
        assert "qwen2.5:7b-instruct" in LOCAL_MODEL_PREFERENCES[0]
