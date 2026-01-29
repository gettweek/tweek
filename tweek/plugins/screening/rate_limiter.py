#!/usr/bin/env python3
"""
Tweek Rate Limiter Screening Plugin

Wraps the rate limiter security module as a screening plugin.
Detects resource theft attacks and abuse patterns:
- Burst detection
- Repeated command detection
- Velocity anomalies
- Circuit breaker pattern
"""

from typing import Optional, Dict, Any, List
from tweek.plugins.base import (
    ScreeningPlugin,
    ScreeningResult,
    Finding,
    Severity,
    ActionType,
)


class RateLimiterPlugin(ScreeningPlugin):
    """
    Rate limiter screening plugin.

    Detects patterns indicating resource theft or automated abuse:
    - Burst patterns (many commands in short window)
    - Repeated identical commands
    - Unusual velocity changes
    - Dangerous tier spikes

    PRO feature - requires Pro license.
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Detect resource theft and abuse patterns via rate limiting"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "pro"
    TAGS = ["screening", "rate-limiting", "abuse-detection"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._rate_limiter = None

    @property
    def name(self) -> str:
        return "rate_limiter"

    def _get_rate_limiter(self):
        """Lazy initialization of rate limiter."""
        if self._rate_limiter is None:
            try:
                from tweek.security.rate_limiter import (
                    RateLimiter,
                    RateLimitConfig,
                    CircuitBreakerConfig,
                )

                # Build config from plugin config
                rate_config = RateLimitConfig(
                    burst_window=self._config.get("burst_window", 5),
                    burst_threshold=self._config.get("burst_threshold", 15),
                    max_per_minute=self._config.get("max_per_minute", 60),
                    max_dangerous_per_minute=self._config.get("max_dangerous_per_minute", 10),
                    max_same_command=self._config.get("max_same_command", 5),
                    velocity_multiplier=self._config.get("velocity_multiplier", 3.0),
                )

                circuit_config = CircuitBreakerConfig(
                    failure_threshold=self._config.get("circuit_failure_threshold", 5),
                    open_timeout=self._config.get("circuit_open_timeout", 60),
                )

                self._rate_limiter = RateLimiter(
                    config=rate_config,
                    circuit_config=circuit_config,
                )

            except ImportError:
                pass

        return self._rate_limiter

    def screen(
        self,
        tool_name: str,
        content: str,
        context: Dict[str, Any]
    ) -> ScreeningResult:
        """
        Screen for rate limit violations.

        Args:
            tool_name: Name of the tool being invoked
            content: Command or content
            context: Must include 'session_id', optionally 'tier'

        Returns:
            ScreeningResult with rate limit decision
        """
        rate_limiter = self._get_rate_limiter()
        if rate_limiter is None:
            return ScreeningResult(
                allowed=True,
                plugin_name=self.name,
                reason="Rate limiter not available",
            )

        session_id = context.get("session_id")
        tier = context.get("tier")

        # Only pass command for Bash tool
        command = content if tool_name == "Bash" else None

        result = rate_limiter.check(
            tool_name=tool_name,
            command=command,
            session_id=session_id,
            tier=tier,
        )

        if result.allowed:
            return ScreeningResult(
                allowed=True,
                plugin_name=self.name,
                risk_level="safe",
                details=result.details,
            )

        # Convert violations to findings
        findings = []
        from tweek.security.rate_limiter import RateLimitViolation

        violation_severity = {
            RateLimitViolation.BURST: Severity.HIGH,
            RateLimitViolation.REPEATED_COMMAND: Severity.MEDIUM,
            RateLimitViolation.HIGH_VOLUME: Severity.MEDIUM,
            RateLimitViolation.DANGEROUS_SPIKE: Severity.HIGH,
            RateLimitViolation.VELOCITY_ANOMALY: Severity.MEDIUM,
            RateLimitViolation.CIRCUIT_OPEN: Severity.CRITICAL,
        }

        for violation in result.violations:
            findings.append(Finding(
                pattern_name=f"rate_limit_{violation.value}",
                matched_text=f"{tool_name}: {content[:50]}...",
                severity=violation_severity.get(violation, Severity.MEDIUM),
                description=f"Rate limit violation: {violation.value}",
                recommended_action=ActionType.ASK,
            ))

        return ScreeningResult(
            allowed=False,
            plugin_name=self.name,
            reason=result.message,
            risk_level="dangerous" if result.is_circuit_open else "suspicious",
            should_prompt=True,
            details=result.details,
            findings=findings,
        )

    def get_session_stats(self, session_id: str) -> Dict[str, Any]:
        """Get statistics for a session."""
        rate_limiter = self._get_rate_limiter()
        if rate_limiter:
            return rate_limiter.get_session_stats(session_id)
        return {}

    def reset_circuit(self, session_id: str) -> None:
        """Reset circuit breaker for a session."""
        rate_limiter = self._get_rate_limiter()
        if rate_limiter:
            rate_limiter.reset_circuit(session_id)
