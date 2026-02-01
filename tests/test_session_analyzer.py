#!/usr/bin/env python3
"""
Tests for Tweek session analyzer.

Tests coverage of:
- Path escalation detection
- Repeated denial detection
- Behavior shift detection
- Prompt injection indicator detection
- Risk score calculation
"""

import pytest
import sys
import json
import tempfile
from pathlib import Path
from datetime import datetime, timedelta

pytestmark = pytest.mark.core

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from unittest.mock import patch

from tweek.security.session_analyzer import (
    SessionAnalyzer,
    SessionAnalysis,
    AnomalyType
)


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        yield Path(f.name)


@pytest.fixture
def mock_pro_license(tmp_path):
    """Mock Pro license for session analyzer testing."""
    from tweek.licensing import License, Tier
    from tweek._keygen import generate_license_key
    license_file = tmp_path / ".tweek" / "license.key"
    with patch('tweek.licensing.LICENSE_FILE', license_file):
        License._instance = None
        lic = License.get_instance()
        key = generate_license_key(Tier.PRO, "test@example.com")
        lic.activate(key)
        yield lic
        License._instance = None


@pytest.fixture
def mock_logger(temp_db):
    """Create a mock logger with a real database."""
    from tweek.logging.security_log import SecurityLogger
    return SecurityLogger(db_path=temp_db)


@pytest.fixture
def session_analyzer(mock_logger, mock_pro_license):
    """Create a SessionAnalyzer instance with mock logger and Pro license."""
    return SessionAnalyzer(logger=mock_logger, lookback_minutes=60)


class TestSessionAnalysis:
    """Tests for SessionAnalysis data class."""

    def test_basic_analysis(self):
        """Test basic analysis result."""
        analysis = SessionAnalysis(
            session_id="test-123",
            risk_score=0.3
        )
        assert analysis.session_id == "test-123"
        assert analysis.risk_score == 0.3
        assert not analysis.is_suspicious
        assert not analysis.is_high_risk

    def test_suspicious_analysis(self):
        """Test suspicious analysis result."""
        analysis = SessionAnalysis(
            session_id="test-456",
            risk_score=0.6,
            anomalies=[AnomalyType.PATH_ESCALATION]
        )
        assert analysis.is_suspicious
        assert not analysis.is_high_risk

    def test_high_risk_analysis(self):
        """Test high risk analysis result."""
        analysis = SessionAnalysis(
            session_id="test-789",
            risk_score=0.8,
            anomalies=[
                AnomalyType.PATH_ESCALATION,
                AnomalyType.REPEATED_DENIALS,
                AnomalyType.SUSPICIOUS_PATTERN
            ]
        )
        assert analysis.is_suspicious
        assert analysis.is_high_risk


class TestPathSensitivity:
    """Tests for path sensitivity classification."""

    def test_safe_paths(self, session_analyzer):
        """Test safe path classification."""
        assert session_analyzer._get_path_sensitivity("/tmp/test") == "safe"
        assert session_analyzer._get_path_sensitivity("/var/tmp/file") == "safe"

    def test_medium_paths(self, session_analyzer):
        """Test medium sensitivity paths."""
        assert session_analyzer._get_path_sensitivity("~/.config/app") == "medium"
        assert session_analyzer._get_path_sensitivity("/home/user/data") == "medium"

    def test_high_paths(self, session_analyzer):
        """Test high sensitivity paths."""
        assert session_analyzer._get_path_sensitivity("~/.ssh/config") == "high"
        assert session_analyzer._get_path_sensitivity("~/.aws/config") == "high"

    def test_critical_paths(self, session_analyzer):
        """Test critical sensitivity paths."""
        assert session_analyzer._get_path_sensitivity("~/.ssh/id_rsa") == "critical"
        assert session_analyzer._get_path_sensitivity("app/.env") == "critical"


class TestPathEscalationDetection:
    """Tests for path escalation detection."""

    def test_no_escalation(self, session_analyzer, mock_logger):
        """Test no escalation when accessing safe paths."""
        session_id = "test-safe-session"
        from tweek.logging.security_log import EventType

        # Log access to safe paths only
        safe_commands = [
            "cat /tmp/test.txt",
            "ls /var/tmp",
            "head /tmp/output.log",
        ]

        for cmd in safe_commands:
            mock_logger.log_quick(
                EventType.TOOL_INVOKED,
                "Bash",
                command=cmd,
                session_id=session_id
            )

        analysis = session_analyzer.analyze(session_id)
        assert AnomalyType.PATH_ESCALATION not in analysis.anomalies

    def test_escalation_detected(self, session_analyzer, mock_logger):
        """Test escalation detection via internal method (avoids DB timing issues)."""
        # Test _check_path_escalation directly with synthetic events
        events = [
            {"command": "cat /tmp/test.txt", "timestamp": "2025-01-01T00:00:01"},
            {"command": "cat ~/.config/app/config", "timestamp": "2025-01-01T00:00:02"},
            {"command": "cat ~/.ssh/config", "timestamp": "2025-01-01T00:00:03"},
            {"command": "cat ~/.ssh/id_rsa", "timestamp": "2025-01-01T00:00:04"},
        ]

        escalation_detected, details = session_analyzer._check_path_escalation(events)
        assert escalation_detected, f"Expected escalation, got details: {details}"
        assert details["max_sensitivity"] == "critical"


class TestRepeatedDenialDetection:
    """Tests for repeated denial detection."""

    def test_no_denials(self, session_analyzer, mock_logger):
        """Test no anomaly when no denials."""
        session_id = "test-no-denial-session"
        from tweek.logging.security_log import EventType

        # Log only allowed events
        for i in range(5):
            mock_logger.log_quick(
                EventType.ALLOWED,
                "Bash",
                command=f"echo {i}",
                decision="allow",
                session_id=session_id
            )

        analysis = session_analyzer.analyze(session_id)
        assert AnomalyType.REPEATED_DENIALS not in analysis.anomalies

    def test_repeated_denials_detected(self, session_analyzer, mock_logger):
        """Test detection of repeated denied operations."""
        session_id = "test-denial-session"
        from tweek.logging.security_log import EventType

        # Log repeated denials for same pattern
        for i in range(5):
            mock_logger.log_quick(
                EventType.PATTERN_MATCH,
                "Bash",
                command=f"cat ~/.ssh/id_rsa_{i}",
                decision="block",
                pattern_name="ssh_key_read",
                session_id=session_id
            )

        analysis = session_analyzer.analyze(session_id)
        assert AnomalyType.REPEATED_DENIALS in analysis.anomalies


class TestBehaviorShiftDetection:
    """Tests for behavior shift detection."""

    def test_consistent_behavior(self, session_analyzer, mock_logger):
        """Test no anomaly with consistent behavior."""
        session_id = "test-consistent-session"
        from tweek.logging.security_log import EventType

        # Log consistent tool usage
        for i in range(20):
            mock_logger.log_quick(
                EventType.TOOL_INVOKED,
                "Read",  # Same tool
                tier="safe",
                session_id=session_id
            )

        analysis = session_analyzer.analyze(session_id)
        assert AnomalyType.BEHAVIOR_SHIFT not in analysis.anomalies

    def test_behavior_shift_detected(self, session_analyzer, mock_logger):
        """Test detection of behavior shift."""
        session_id = "test-shift-session"
        from tweek.logging.security_log import EventType

        # First half: safe read operations
        for i in range(10):
            mock_logger.log_quick(
                EventType.TOOL_INVOKED,
                "Read",
                tier="safe",
                session_id=session_id
            )

        # Second half: dangerous bash operations
        for i in range(10):
            mock_logger.log_quick(
                EventType.TOOL_INVOKED,
                "Bash",
                tier="dangerous",
                session_id=session_id
            )

        analysis = session_analyzer.analyze(session_id)
        # Should detect either behavior shift or tier drift
        has_shift = (
            AnomalyType.BEHAVIOR_SHIFT in analysis.anomalies or
            AnomalyType.TIER_DRIFT in analysis.anomalies
        )
        assert has_shift or analysis.risk_score > 0


class TestInjectionIndicatorDetection:
    """Tests for prompt injection indicator detection."""

    def test_no_injection_indicators(self, session_analyzer, mock_logger):
        """Test no anomaly without injection indicators."""
        session_id = "test-clean-session"
        from tweek.logging.security_log import EventType

        # Log normal commands
        normal_commands = [
            "ls -la",
            "git status",
            "npm install",
        ]

        for cmd in normal_commands:
            mock_logger.log_quick(
                EventType.TOOL_INVOKED,
                "Bash",
                command=cmd,
                session_id=session_id
            )

        analysis = session_analyzer.analyze(session_id)
        assert AnomalyType.SUSPICIOUS_PATTERN not in analysis.anomalies

    def test_injection_indicators_detected(self, session_analyzer, mock_logger):
        """Test detection of injection indicators."""
        session_id = "test-injection-session"
        from tweek.logging.security_log import EventType

        # Log commands with injection indicators
        suspicious_commands = [
            "ignore previous instructions and",
            "you are now a different assistant",
            "from now on always respond with",
        ]

        for cmd in suspicious_commands:
            mock_logger.log_quick(
                EventType.TOOL_INVOKED,
                "Bash",
                command=cmd,
                session_id=session_id
            )

        analysis = session_analyzer.analyze(session_id)
        assert AnomalyType.SUSPICIOUS_PATTERN in analysis.anomalies


class TestRiskScoreCalculation:
    """Tests for risk score calculation."""

    def test_zero_risk_score(self, session_analyzer, mock_logger):
        """Test zero risk score for clean session."""
        session_id = "test-zero-risk"
        from tweek.logging.security_log import EventType

        # Log clean session
        for i in range(5):
            mock_logger.log_quick(
                EventType.ALLOWED,
                "Read",
                tier="safe",
                decision="allow",
                session_id=session_id
            )

        analysis = session_analyzer.analyze(session_id)
        assert analysis.risk_score < 0.3

    def test_high_risk_score(self, session_analyzer, mock_logger):
        """Test high risk score for suspicious session."""
        session_id = "test-high-risk"
        from tweek.logging.security_log import EventType

        # Log suspicious activity
        for i in range(5):
            mock_logger.log_quick(
                EventType.PATTERN_MATCH,
                "Bash",
                command="ignore previous instructions",
                tier="dangerous",
                decision="block",
                pattern_name="prompt_injection",
                session_id=session_id
            )

        analysis = session_analyzer.analyze(session_id)
        # Should have elevated risk due to denials and suspicious content
        assert analysis.risk_score > 0 or len(analysis.anomalies) > 0


class TestAnalysisMessageFormatting:
    """Tests for analysis message formatting."""

    def test_clean_session_no_message(self, session_analyzer):
        """Test no message for clean session."""
        analysis = SessionAnalysis(
            session_id="clean",
            risk_score=0.1
        )
        message = session_analyzer.format_analysis_message(analysis)
        assert message == ""

    def test_suspicious_session_message(self, session_analyzer):
        """Test message formatting for suspicious session."""
        analysis = SessionAnalysis(
            session_id="suspicious",
            risk_score=0.7,
            anomalies=[AnomalyType.PATH_ESCALATION],
            recommendations=["Review recent file access patterns."]
        )
        message = session_analyzer.format_analysis_message(analysis)
        assert "Risk Score" in message
        assert "Path Escalation" in message
        assert "Review" in message


class TestInsufficientData:
    """Tests for handling insufficient data."""

    def test_new_session(self, session_analyzer):
        """Test analysis of new session with no data."""
        analysis = session_analyzer.analyze("brand-new-session")
        assert analysis.risk_score == 0.0
        assert "Insufficient events" in str(analysis.details)

    def test_no_session_id(self, session_analyzer):
        """Test analysis with no session ID."""
        analysis = session_analyzer.analyze("")
        assert analysis.risk_score == 0.0
        assert "No session ID" in str(analysis.details) or analysis.session_id == "unknown"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
