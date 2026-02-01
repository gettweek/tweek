#!/usr/bin/env python3
"""
Tweek Local Model Review Provider

Bridges the local ONNX model into the ReviewProvider interface used by
LLMReviewer. This allows the local model to be a drop-in replacement
for cloud LLM providers with zero changes to the hook pipeline.

Two-tier escalation:
- High-confidence local results are returned directly (~20ms)
- Uncertain results escalate to cloud LLM if available (~500-5000ms)
- If no cloud LLM is available, local result is used as-is
"""

import json
import re
from typing import Optional

from tweek.security.llm_reviewer import ReviewProvider, ReviewProviderError


class LocalModelReviewProvider(ReviewProvider):
    """ReviewProvider backed by a local ONNX model.

    Runs inference locally and returns JSON-formatted results compatible
    with LLMReviewer._parse_response(). Optionally escalates uncertain
    results to a cloud LLM provider.
    """

    def __init__(
        self,
        model_name: str = "prompt-guard-86m",
        escalation_provider: Optional[ReviewProvider] = None,
    ):
        """Initialize the local model review provider.

        Args:
            model_name: Name of the local model to use.
            escalation_provider: Optional cloud LLM provider for uncertain results.
        """
        self._model_name = model_name
        self._escalation_provider = escalation_provider

    def call(self, system_prompt: str, user_prompt: str, max_tokens: int = 256) -> str:
        """Run local inference and return JSON result.

        Extracts the command from <untrusted_command> tags in the user prompt,
        runs local inference, and returns a JSON string in the same format
        that LLMReviewer._parse_response() expects.

        If the local model is uncertain and an escalation provider is
        available, the request is forwarded to the cloud LLM.

        Args:
            system_prompt: System-level instructions (used for escalation only).
            user_prompt: User message containing <untrusted_command> tags.
            max_tokens: Max tokens (used for escalation only).

        Returns:
            JSON string with risk_level, reason, and confidence.
        """
        from tweek.security.local_model import get_local_model

        # Extract command from untrusted_command tags
        command = self._extract_command(user_prompt)
        if not command:
            return json.dumps({
                "risk_level": "safe",
                "reason": "No command content to analyze",
                "confidence": 1.0,
            })

        model = get_local_model(self._model_name)
        if model is None:
            # Model not available — fall through to escalation or safe default
            if self._escalation_provider:
                return self._escalation_provider.call(
                    system_prompt, user_prompt, max_tokens
                )
            return json.dumps({
                "risk_level": "safe",
                "reason": "Local model not available",
                "confidence": 0.0,
            })

        # Run local inference
        result = model.predict(command)

        # Check if we should escalate to cloud LLM
        if result.should_escalate and self._escalation_provider:
            try:
                return self._escalation_provider.call(
                    system_prompt, user_prompt, max_tokens
                )
            except ReviewProviderError:
                # Cloud LLM failed — fall back to local result
                pass

        # Map local result to LLM reviewer JSON format
        return json.dumps({
            "risk_level": result.risk_level,
            "reason": (
                f"Local model ({result.model_name}): "
                f"{result.label} (confidence: {result.confidence:.1%})"
            ),
            "confidence": result.confidence,
        })

    def is_available(self) -> bool:
        """Check if the local model is available."""
        from tweek.security.local_model import LOCAL_MODEL_AVAILABLE, get_local_model

        if not LOCAL_MODEL_AVAILABLE:
            return False

        model = get_local_model(self._model_name)
        return model is not None

    @property
    def name(self) -> str:
        return "local"

    @property
    def model_name(self) -> str:
        return self._model_name

    @staticmethod
    def _extract_command(user_prompt: str) -> str:
        """Extract the command from <untrusted_command> tags.

        Args:
            user_prompt: The full user prompt from LLMReviewer.

        Returns:
            The extracted command text, or the full prompt if no tags found.
        """
        match = re.search(
            r"<untrusted_command>\s*(.*?)\s*</untrusted_command>",
            user_prompt,
            re.DOTALL,
        )
        if match:
            return match.group(1).strip()

        # Fallback: use the whole prompt (minus any obvious framing text)
        return user_prompt.strip()
