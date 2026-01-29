#!/usr/bin/env python3
"""
Tweek Session Analyzer Screening Plugin

Cross-turn anomaly detection for conversation hijacking:
- Privilege escalation patterns
- Repeated denial attacks
- Behavior shift detection
- Instruction persistence
- ACIP graduated escalation

PRO feature - requires Pro license.
"""

from typing import Optional, Dict, Any, List
from tweek.plugins.base import (
    ScreeningPlugin,
    ScreeningResult,
    Finding,
    Severity,
    ActionType,
)


class SessionAnalyzerPlugin(ScreeningPlugin):
    """
    Session analyzer screening plugin.

    Analyzes session history to detect cross-turn anomalies
    that would be missed by single-command analysis.

    PRO feature - requires Pro license.
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Cross-turn anomaly detection for session analysis"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "pro"
    TAGS = ["screening", "session-analysis", "anomaly-detection"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._analyzer = None

    @property
    def name(self) -> str:
        return "session_analyzer"

    def _get_analyzer(self):
        """Lazy initialization of session analyzer."""
        if self._analyzer is None:
            try:
                from tweek.security.session_analyzer import SessionAnalyzer

                self._analyzer = SessionAnalyzer(
                    lookback_minutes=self._config.get("lookback_minutes", 30),
                )
            except ImportError:
                pass

        return self._analyzer

    def screen(
        self,
        tool_name: str,
        content: str,
        context: Dict[str, Any]
    ) -> ScreeningResult:
        """
        Analyze session for cross-turn anomalies.

        Args:
            tool_name: Name of the tool being invoked
            content: Command or content (used for context)
            context: Must include 'session_id'

        Returns:
            ScreeningResult with session analysis
        """
        analyzer = self._get_analyzer()
        if analyzer is None:
            return ScreeningResult(
                allowed=True,
                plugin_name=self.name,
                reason="Session analyzer not available",
            )

        session_id = context.get("session_id")
        if not session_id:
            return ScreeningResult(
                allowed=True,
                plugin_name=self.name,
                reason="No session ID for analysis",
            )

        result = analyzer.analyze(session_id)

        if not result.is_suspicious:
            return ScreeningResult(
                allowed=True,
                plugin_name=self.name,
                risk_level="safe",
                details=result.details,
            )

        # Convert anomalies to findings
        from tweek.security.session_analyzer import AnomalyType

        anomaly_severity = {
            AnomalyType.PRIVILEGE_ESCALATION: Severity.HIGH,
            AnomalyType.PATH_ESCALATION: Severity.HIGH,
            AnomalyType.REPEATED_DENIALS: Severity.MEDIUM,
            AnomalyType.BEHAVIOR_SHIFT: Severity.MEDIUM,
            AnomalyType.SUSPICIOUS_PATTERN: Severity.HIGH,
            AnomalyType.VELOCITY_CHANGE: Severity.LOW,
            AnomalyType.TIER_DRIFT: Severity.MEDIUM,
            AnomalyType.CAPABILITY_AGGREGATION: Severity.HIGH,
            AnomalyType.GRADUATED_ESCALATION: Severity.HIGH,
        }

        findings = []
        for anomaly in result.anomalies:
            findings.append(Finding(
                pattern_name=f"session_{anomaly.value}",
                matched_text=f"Session: {session_id[:20]}...",
                severity=anomaly_severity.get(anomaly, Severity.MEDIUM),
                description=anomaly.value.replace("_", " ").title(),
                recommended_action=ActionType.ASK,
                metadata={"anomaly_type": anomaly.value}
            ))

        risk_level = "dangerous" if result.is_high_risk else "suspicious"

        return ScreeningResult(
            allowed=not result.is_high_risk,
            plugin_name=self.name,
            reason=f"Session anomalies detected: {', '.join(a.value for a in result.anomalies)}",
            risk_level=risk_level,
            confidence=result.risk_score,
            should_prompt=result.is_suspicious,
            findings=findings,
            details={
                "risk_score": result.risk_score,
                "anomalies": [a.value for a in result.anomalies],
                "recommendations": result.recommendations,
                **result.details,
            }
        )

    def get_session_profile(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get the stored profile for a session."""
        analyzer = self._get_analyzer()
        if analyzer is None:
            return None

        # Would need to add this method to SessionAnalyzer
        # For now, just return the analysis
        result = analyzer.analyze(session_id)
        return result.details if result else None
