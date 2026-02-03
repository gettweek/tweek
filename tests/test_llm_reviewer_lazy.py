"""Regression tests for GoogleReviewProvider lazy initialization.

Ensures that constructing a GoogleReviewProvider does NOT trigger API
calls at init time — configuration is deferred to the first call().
"""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock


@pytest.mark.security
class TestGoogleProviderLazyInit:
    """GoogleReviewProvider must not call genai at construction time."""

    def test_init_no_api_calls(self):
        """GoogleReviewProvider.__init__ must not call genai.configure() or GenerativeModel."""
        with patch("tweek.security.llm_reviewer.genai") as mock_genai:
            from tweek.security.llm_reviewer import GoogleReviewProvider

            provider = GoogleReviewProvider(
                model="gemini-2.0-flash",
                api_key="test-key-not-real",
            )

            mock_genai.configure.assert_not_called()
            mock_genai.GenerativeModel.assert_not_called()
            assert provider._configured is False

    def test_configures_on_first_call(self):
        """GoogleReviewProvider should call genai.configure() on first call()."""
        with patch("tweek.security.llm_reviewer.genai") as mock_genai:
            mock_model = MagicMock()
            mock_model.generate_content.return_value.text = "SAFE: no issues"
            mock_genai.GenerativeModel.return_value = mock_model

            from tweek.security.llm_reviewer import GoogleReviewProvider

            provider = GoogleReviewProvider(
                model="gemini-2.0-flash",
                api_key="test-key-not-real",
            )

            # Before call — not configured
            mock_genai.configure.assert_not_called()

            # First call triggers configuration
            result = provider.call("You are a security reviewer.", "Is this safe?")

            mock_genai.configure.assert_called_once_with(api_key="test-key-not-real")
            assert provider._configured is True
            assert "SAFE" in result

    def test_configures_only_once(self):
        """genai.configure() should only be called once across multiple calls."""
        with patch("tweek.security.llm_reviewer.genai") as mock_genai:
            mock_model = MagicMock()
            mock_model.generate_content.return_value.text = "SAFE"
            mock_genai.GenerativeModel.return_value = mock_model

            from tweek.security.llm_reviewer import GoogleReviewProvider

            provider = GoogleReviewProvider(
                model="gemini-2.0-flash",
                api_key="test-key-not-real",
            )

            provider.call("system", "user1")
            provider.call("system", "user2")
            provider.call("system", "user3")

            # configure called exactly once, not three times
            mock_genai.configure.assert_called_once()
