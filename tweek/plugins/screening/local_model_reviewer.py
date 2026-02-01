#!/usr/bin/env python3
"""
Tweek Local Model Reviewer Screening Plugin

On-device prompt injection classifier using ONNX model.
No API key needed — inference runs entirely locally.

Requires optional dependencies: pip install tweek[local-models]
"""

from typing import Optional, Dict, Any
from tweek.plugins.base import (
    ScreeningPlugin,
    ScreeningResult,
    Finding,
    Severity,
    ActionType,
)


class LocalModelReviewerPlugin(ScreeningPlugin):
    """
    Local ONNX model screening plugin.

    Uses a local prompt injection classifier for on-device security
    analysis. No cloud API calls needed. Runs in ~20ms on CPU.
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Local ONNX model for prompt injection detection"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["screening", "local-model", "onnx", "prompt-injection"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)

    @property
    def name(self) -> str:
        return "local_model_reviewer"

    def screen(
        self,
        tool_name: str,
        content: str,
        context: Dict[str, Any],
    ) -> ScreeningResult:
        """Screen content using local ONNX model.

        Args:
            tool_name: Name of the tool being invoked.
            content: Command or content to analyze.
            context: Should include 'tier', optionally 'tool_input'.

        Returns:
            ScreeningResult with local model analysis.
        """
        try:
            from tweek.security.local_model import (
                LOCAL_MODEL_AVAILABLE,
                get_local_model,
            )
        except ImportError:
            return ScreeningResult(
                allowed=True,
                plugin_name=self.name,
                reason="Local model dependencies not installed",
            )

        if not LOCAL_MODEL_AVAILABLE:
            return ScreeningResult(
                allowed=True,
                plugin_name=self.name,
                reason="Local model dependencies not installed",
            )

        model = get_local_model()
        if model is None:
            return ScreeningResult(
                allowed=True,
                plugin_name=self.name,
                reason="Local model not downloaded",
            )

        try:
            result = model.predict(content)
        except Exception as e:
            return ScreeningResult(
                allowed=True,
                plugin_name=self.name,
                reason=f"Local model inference error: {e}",
            )

        # Map risk levels to screening result
        risk_severity_map = {
            "safe": Severity.LOW,
            "suspicious": Severity.MEDIUM,
            "dangerous": Severity.HIGH,
        }

        severity = risk_severity_map.get(result.risk_level, Severity.MEDIUM)

        findings = []
        if result.is_suspicious:
            findings.append(
                Finding(
                    pattern_name="local_model",
                    matched_text=content[:100],
                    severity=severity,
                    description=(
                        f"Local model ({result.model_name}): "
                        f"{result.label} ({result.confidence:.1%})"
                    ),
                    recommended_action=(
                        ActionType.BLOCK
                        if result.is_dangerous and result.confidence > 0.9
                        else ActionType.ASK
                    ),
                    metadata={
                        "confidence": result.confidence,
                        "model": result.model_name,
                        "label": result.label,
                        "inference_ms": result.inference_time_ms,
                        "all_scores": result.all_scores,
                    },
                )
            )

        return ScreeningResult(
            allowed=not result.is_dangerous,
            plugin_name=self.name,
            reason=(
                f"Local model: {result.label} ({result.confidence:.1%})"
                if result.is_suspicious
                else "Local model: benign"
            ),
            risk_level=result.risk_level,
            confidence=result.confidence,
            should_prompt=result.is_suspicious,
            findings=findings,
            details={
                "model": result.model_name,
                "label": result.label,
                "inference_ms": result.inference_time_ms,
                "all_scores": result.all_scores,
            },
        )

    def is_available(self) -> bool:
        """Check if local model is available."""
        try:
            from tweek.security.local_model import (
                LOCAL_MODEL_AVAILABLE,
                get_local_model,
            )

            if not LOCAL_MODEL_AVAILABLE:
                return False
            return get_local_model() is not None
        except ImportError:
            return False
