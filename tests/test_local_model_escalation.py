"""Tests for local model confidence escalation cap (Finding F6).

Validates that dangerous-tier commands always escalate to cloud LLM review
regardless of local model confidence, when always_escalate_dangerous is True.
"""

import pytest
from unittest.mock import patch, MagicMock
from dataclasses import dataclass

from tweek.plugins.screening.local_model_reviewer import LocalModelReviewerPlugin


@dataclass
class MockLocalModelResult:
    """Mock for LocalModelResult."""
    risk_level: str = "safe"
    label: str = "benign"
    confidence: float = 0.95
    all_scores: dict = None
    should_escalate: bool = False
    is_suspicious: bool = False
    is_dangerous: bool = False
    model_name: str = "test-model"
    inference_time_ms: float = 10.0

    def __post_init__(self):
        if self.all_scores is None:
            self.all_scores = {"benign": self.confidence}


class TestAlwaysEscalateDangerous:
    """Tests for the always_escalate_dangerous flag."""

    def _make_plugin(self, always_escalate=True):
        """Create a plugin with specified config."""
        return LocalModelReviewerPlugin(
            config={"always_escalate_dangerous": always_escalate}
        )

    @patch("tweek.security.local_model.get_local_model")
    @patch("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", True)
    def test_dangerous_tier_forces_escalation(self, mock_get_model):
        """With always_escalate_dangerous=True, dangerous tier should force escalation."""
        mock_model = MagicMock()
        result = MockLocalModelResult(
            risk_level="safe", confidence=0.95, should_escalate=False
        )
        mock_model.predict.return_value = result
        mock_get_model.return_value = mock_model

        plugin = self._make_plugin(always_escalate=True)
        plugin.screen("Bash", "some command", {"tier": "dangerous"})

        # The result's should_escalate should have been overridden to True
        assert result.should_escalate is True

    @patch("tweek.security.local_model.get_local_model")
    @patch("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", True)
    def test_dangerous_tier_no_override_when_disabled(self, mock_get_model):
        """With always_escalate_dangerous=False, dangerous tier should NOT force escalation."""
        mock_model = MagicMock()
        result = MockLocalModelResult(
            risk_level="safe", confidence=0.95, should_escalate=False
        )
        mock_model.predict.return_value = result
        mock_get_model.return_value = mock_model

        plugin = self._make_plugin(always_escalate=False)
        plugin.screen("Bash", "some command", {"tier": "dangerous"})

        assert result.should_escalate is False

    @patch("tweek.security.local_model.get_local_model")
    @patch("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", True)
    def test_non_dangerous_tier_not_affected(self, mock_get_model):
        """Non-dangerous tiers should NOT be affected by always_escalate_dangerous."""
        mock_model = MagicMock()
        result = MockLocalModelResult(
            risk_level="safe", confidence=0.95, should_escalate=False
        )
        mock_model.predict.return_value = result
        mock_get_model.return_value = mock_model

        plugin = self._make_plugin(always_escalate=True)

        for tier in ["safe", "default", "risky"]:
            result.should_escalate = False
            plugin.screen("Bash", "some command", {"tier": tier})
            assert result.should_escalate is False, f"Escalation forced for tier={tier}"

    @patch("tweek.security.local_model.get_local_model")
    @patch("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", True)
    def test_already_escalating_not_changed(self, mock_get_model):
        """If already escalating, the flag should not change it."""
        mock_model = MagicMock()
        result = MockLocalModelResult(
            risk_level="safe", confidence=0.5, should_escalate=True
        )
        mock_model.predict.return_value = result
        mock_get_model.return_value = mock_model

        plugin = self._make_plugin(always_escalate=True)
        plugin.screen("Bash", "some command", {"tier": "dangerous"})

        assert result.should_escalate is True

    @patch("tweek.security.local_model.get_local_model")
    @patch("tweek.security.local_model.LOCAL_MODEL_AVAILABLE", True)
    def test_default_config_enables_escalation(self, mock_get_model):
        """Default config (no explicit setting) should enable always_escalate_dangerous."""
        mock_model = MagicMock()
        result = MockLocalModelResult(
            risk_level="safe", confidence=0.95, should_escalate=False
        )
        mock_model.predict.return_value = result
        mock_get_model.return_value = mock_model

        # No config at all -- should default to True
        plugin = LocalModelReviewerPlugin(config=None)
        plugin.screen("Bash", "some command", {"tier": "dangerous"})

        assert result.should_escalate is True
