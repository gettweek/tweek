#!/usr/bin/env python3
"""
Tweek LLM Reviewer Screening Plugin

Semantic analysis using LLM for risky/dangerous operations:
- Sensitive path access detection
- Data exfiltration potential
- System configuration changes
- Prompt injection indicators
- Privilege escalation attempts

Supports multiple providers: Anthropic, OpenAI, Google, and any
OpenAI-compatible endpoint. Free and open source. Requires an API key
for any supported provider (BYOK).
"""

from typing import Optional, Dict, Any, List
from tweek.plugins.base import (
    ScreeningPlugin,
    ScreeningResult,
    Finding,
    Severity,
    ActionType,
)


class LLMReviewerPlugin(ScreeningPlugin):
    """
    LLM-based security reviewer plugin.

    Uses a fast, cheap LLM to analyze commands that pass regex screening
    but may still be malicious. Supports multiple providers: Anthropic
    (Claude), OpenAI (GPT), Google (Gemini), and any OpenAI-compatible
    endpoint (Ollama, LM Studio, Together, Groq, etc.).

    Free and open source. Requires an API key for any supported provider (BYOK).
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Semantic security analysis using LLM"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["screening", "llm", "semantic-analysis"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._reviewer = None

    @property
    def name(self) -> str:
        return "llm_reviewer"

    def _get_reviewer(self):
        """Lazy initialization of LLM reviewer."""
        if self._reviewer is None:
            try:
                from tweek.security.llm_reviewer import LLMReviewer

                self._reviewer = LLMReviewer(
                    model=self._config.get("model", "auto"),
                    api_key=self._config.get("api_key"),
                    timeout=self._config.get("timeout", 5.0),
                    enabled=self._config.get("enabled", True),
                    provider=self._config.get("provider", "auto"),
                    base_url=self._config.get("base_url"),
                    api_key_env=self._config.get("api_key_env"),
                )
            except ImportError:
                pass

        return self._reviewer

    def screen(
        self,
        tool_name: str,
        content: str,
        context: Dict[str, Any]
    ) -> ScreeningResult:
        """
        Screen content using LLM semantic analysis.

        Args:
            tool_name: Name of the tool being invoked
            content: Command or content to analyze
            context: Should include 'tier', optionally 'tool_input', 'session_id'

        Returns:
            ScreeningResult with LLM analysis
        """
        reviewer = self._get_reviewer()
        if reviewer is None or not reviewer.enabled:
            return ScreeningResult(
                allowed=True,
                plugin_name=self.name,
                reason="LLM reviewer not available or disabled",
            )

        tier = context.get("tier", "default")
        tool_input = context.get("tool_input")
        session_id = context.get("session_id")

        result = reviewer.review(
            command=content,
            tool=tool_name,
            tier=tier,
            tool_input=tool_input,
            session_context=f"session:{session_id}" if session_id else None,
        )

        # Convert RiskLevel to severity
        from tweek.security.llm_reviewer import RiskLevel

        risk_severity_map = {
            RiskLevel.SAFE: Severity.LOW,
            RiskLevel.SUSPICIOUS: Severity.MEDIUM,
            RiskLevel.DANGEROUS: Severity.HIGH,
        }

        risk_level_map = {
            RiskLevel.SAFE: "safe",
            RiskLevel.SUSPICIOUS: "suspicious",
            RiskLevel.DANGEROUS: "dangerous",
        }

        severity = risk_severity_map.get(result.risk_level, Severity.MEDIUM)
        risk_level = risk_level_map.get(result.risk_level, "suspicious")

        findings = []
        if result.is_suspicious:
            findings.append(Finding(
                pattern_name="llm_review",
                matched_text=content[:100],
                severity=severity,
                description=result.reason,
                recommended_action=ActionType.ASK if result.should_prompt else ActionType.WARN,
                metadata={
                    "confidence": result.confidence,
                    "model": result.details.get("model", "unknown"),
                    "provider": result.details.get("provider", "unknown"),
                }
            ))

        return ScreeningResult(
            allowed=not result.is_dangerous,
            plugin_name=self.name,
            reason=result.reason,
            risk_level=risk_level,
            confidence=result.confidence,
            should_prompt=result.should_prompt,
            findings=findings,
            details=result.details,
        )

    def is_available(self) -> bool:
        """Check if LLM reviewer is available and configured."""
        reviewer = self._get_reviewer()
        return reviewer is not None and reviewer.enabled
