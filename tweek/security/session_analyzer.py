#!/usr/bin/env python3
"""
Tweek Session Analyzer

Detects cross-turn anomalies indicating conversation hijacking or persistent
prompt injection attacks.

Key detection patterns:
- Privilege escalation: Progressive access to more sensitive paths
- Repeated denial attacks: Retrying blocked operations with variations
- Behavior shift: Sudden change in command patterns
- Instruction persistence: Signs of injected instructions affecting multiple turns

Based on research showing 52.9% of RAG backdoor attacks and 82.4% of inter-agent
trust exploits succeed by persisting across conversation turns.
"""

import json
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Set, Tuple

from tweek.logging.security_log import SecurityLogger, get_logger, EventType


class AnomalyType(Enum):
    """Types of session anomalies."""
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PATH_ESCALATION = "path_escalation"
    REPEATED_DENIALS = "repeated_denials"
    BEHAVIOR_SHIFT = "behavior_shift"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    VELOCITY_CHANGE = "velocity_change"
    TIER_DRIFT = "tier_drift"
    CAPABILITY_AGGREGATION = "capability_aggregation"  # ACIP: multi-turn goal building
    GRADUATED_ESCALATION = "graduated_escalation"      # ACIP: 3+ denials triggers


@dataclass
class SessionAnalysis:
    """Result of session analysis."""
    session_id: str
    risk_score: float  # 0.0 - 1.0
    anomalies: List[AnomalyType] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return self.risk_score >= 0.5 or len(self.anomalies) >= 2

    @property
    def is_high_risk(self) -> bool:
        return self.risk_score >= 0.75 or len(self.anomalies) >= 3


class SessionAnalyzer:
    """
    Analyzes session history to detect cross-turn anomalies.

    Uses pattern analysis across multiple conversation turns to detect
    attacks that would be missed by single-command analysis.
    """

    # Path sensitivity levels for escalation detection
    PATH_SENSITIVITY = {
        "safe": [r"/tmp/", r"/var/tmp/", r"\.cache/"],
        "medium": [r"/home/", r"~/", r"\.config/"],
        "high": [r"\.ssh/", r"\.aws/", r"\.kube/", r"\.gnupg/"],
        "critical": [r"id_rsa", r"id_ed25519", r"credentials", r"\.env$", r"secrets"],
    }

    # Patterns indicating persistent injection
    INJECTION_INDICATORS = [
        r"ignore\s+previous",
        r"you\s+are\s+now",
        r"from\s+now\s+on",
        r"always\s+do",
        r"for\s+all\s+future",
        r"remember\s+to\s+always",
    ]

    def __init__(
        self,
        logger: Optional[SecurityLogger] = None,
        lookback_minutes: int = 30
    ):
        """Initialize the session analyzer.

        Args:
            logger: Security logger for database access
            lookback_minutes: How far back to analyze
        """
        self.logger = logger or get_logger()
        self.lookback_minutes = lookback_minutes
        self._ensure_tables()

    def _ensure_tables(self):
        """Ensure session tracking tables exist."""
        try:
            with self.logger._get_connection() as conn:
                conn.executescript("""
                    -- Session profiles for tracking session-level metrics
                    CREATE TABLE IF NOT EXISTS session_profiles (
                        session_id TEXT PRIMARY KEY,
                        first_seen TEXT NOT NULL,
                        last_seen TEXT NOT NULL,
                        total_invocations INTEGER DEFAULT 0,
                        dangerous_count INTEGER DEFAULT 0,
                        denied_count INTEGER DEFAULT 0,
                        risk_score REAL DEFAULT 0.0,
                        anomaly_flags TEXT,  -- JSON array
                        metadata TEXT        -- JSON object
                    );

                    -- Index for time-based queries
                    CREATE INDEX IF NOT EXISTS idx_session_last_seen
                        ON session_profiles(last_seen);
                """)
        except Exception:
            pass

    def _get_session_events(
        self,
        conn: sqlite3.Connection,
        session_id: str
    ) -> List[Dict]:
        """Get recent events for a session."""
        query = """
            SELECT * FROM security_events
            WHERE session_id = ?
            AND timestamp > datetime('now', ?)
            ORDER BY timestamp ASC
        """
        rows = conn.execute(
            query,
            [session_id, f'-{self.lookback_minutes} minutes']
        ).fetchall()
        return [dict(row) for row in rows]

    def _get_path_sensitivity(self, path: str) -> str:
        """Determine sensitivity level of a path."""
        for level in ["critical", "high", "medium", "safe"]:
            patterns = self.PATH_SENSITIVITY.get(level, [])
            for pattern in patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    return level
        return "unknown"

    def _extract_paths(self, events: List[Dict]) -> List[Tuple[str, str]]:
        """Extract paths from events with their timestamps."""
        paths = []
        for event in events:
            command = event.get("command", "")
            if not command:
                continue

            # Extract paths from commands
            path_patterns = [
                r'(?:cat|head|tail|less|more|read)\s+([^\s|>]+)',
                r'(?:ls|cd|find)\s+([^\s|>]+)',
                r'(?:cp|mv|rm)\s+[^\s]+\s+([^\s|>]+)',
                r'(?:chmod|chown)\s+[^\s]+\s+([^\s|>]+)',
            ]

            for pattern in path_patterns:
                matches = re.findall(pattern, command)
                for match in matches:
                    paths.append((event.get("timestamp", ""), match))

        return paths

    def _check_path_escalation(self, events: List[Dict]) -> Tuple[bool, Dict]:
        """Check for progressive access to more sensitive paths."""
        paths = self._extract_paths(events)
        if len(paths) < 3:
            return False, {}

        sensitivity_order = {"safe": 0, "medium": 1, "high": 2, "critical": 3, "unknown": 0}
        sensitivity_sequence = []

        for timestamp, path in paths:
            level = self._get_path_sensitivity(path)
            sensitivity_sequence.append((timestamp, path, level))

        # Check for escalation pattern
        max_seen = 0
        escalation_detected = False
        escalation_path = []

        for ts, path, level in sensitivity_sequence:
            level_num = sensitivity_order.get(level, 0)
            if level_num > max_seen:
                if max_seen > 0:  # Not first access
                    escalation_detected = True
                max_seen = level_num
                escalation_path.append({"path": path, "level": level})

        return escalation_detected, {
            "max_sensitivity": list(sensitivity_order.keys())[max_seen] if max_seen else "safe",
            "escalation_path": escalation_path[-5:] if escalation_path else []
        }

    def _check_repeated_denials(self, events: List[Dict]) -> Tuple[bool, Dict]:
        """Check for repeated attempts after denials."""
        denials = [e for e in events if e.get("decision") in ("block", "ask")]
        if len(denials) < 2:
            return False, {}

        # Group denials by pattern/tool
        denial_patterns = Counter()
        for denial in denials:
            key = (denial.get("tool_name"), denial.get("pattern_name"))
            denial_patterns[key] += 1

        # Check for repeated attempts
        repeated = [(k, v) for k, v in denial_patterns.items() if v >= 2]

        if repeated:
            return True, {
                "repeated_denials": [
                    {"tool": k[0], "pattern": k[1], "count": v}
                    for k, v in repeated
                ],
                "total_denials": len(denials)
            }

        return False, {"total_denials": len(denials)}

    def _check_behavior_shift(self, events: List[Dict]) -> Tuple[bool, Dict]:
        """Check for sudden changes in behavior patterns."""
        if len(events) < 10:
            return False, {}

        # Split into first half and second half
        mid = len(events) // 2
        first_half = events[:mid]
        second_half = events[mid:]

        # Compare tool usage distribution
        first_tools = Counter(e.get("tool_name") for e in first_half)
        second_tools = Counter(e.get("tool_name") for e in second_half)

        # Calculate Jaccard distance
        all_tools = set(first_tools.keys()) | set(second_tools.keys())
        common_tools = set(first_tools.keys()) & set(second_tools.keys())

        if len(all_tools) == 0:
            return False, {}

        jaccard = len(common_tools) / len(all_tools)
        behavior_shift = jaccard < 0.5  # Less than 50% overlap

        # Compare tier distribution
        first_tiers = Counter(e.get("tier") for e in first_half)
        second_tiers = Counter(e.get("tier") for e in second_half)

        # Check for dangerous tier increase
        first_dangerous = first_tiers.get("dangerous", 0) / max(len(first_half), 1)
        second_dangerous = second_tiers.get("dangerous", 0) / max(len(second_half), 1)
        tier_shift = second_dangerous > first_dangerous * 2  # 2x increase

        return (behavior_shift or tier_shift), {
            "tool_overlap": round(jaccard, 2),
            "first_half_tools": dict(first_tools),
            "second_half_tools": dict(second_tools),
            "dangerous_ratio_change": {
                "first": round(first_dangerous, 2),
                "second": round(second_dangerous, 2)
            }
        }

    def _check_injection_indicators(self, events: List[Dict]) -> Tuple[bool, Dict]:
        """Check for signs of persistent prompt injection."""
        injection_matches = []

        for event in events:
            command = event.get("command", "") or ""
            metadata = event.get("metadata_json")
            if metadata:
                try:
                    meta = json.loads(metadata)
                    tool_input = meta.get("tool_input", {})
                    if isinstance(tool_input, dict):
                        command += " " + str(tool_input)
                except json.JSONDecodeError:
                    pass

            for pattern in self.INJECTION_INDICATORS:
                if re.search(pattern, command, re.IGNORECASE):
                    injection_matches.append({
                        "timestamp": event.get("timestamp"),
                        "pattern": pattern,
                        "tool": event.get("tool_name")
                    })

        if injection_matches:
            return True, {
                "injection_indicators": injection_matches[:5],
                "total_matches": len(injection_matches)
            }

        return False, {}

    def _check_graduated_escalation(self, events: List[Dict]) -> Tuple[bool, Dict]:
        """
        Check for ACIP-style graduated escalation trigger.

        After 3+ denied/blocked attempts in a session, trigger elevated scrutiny.
        This implements ACIP's "graduated response posture" concept.
        """
        denials = [e for e in events if e.get("decision") in ("block", "ask")]
        denial_count = len(denials)

        # ACIP threshold: 3+ refused attempts triggers escalation
        if denial_count >= 3:
            return True, {
                "denial_count": denial_count,
                "threshold": 3,
                "message": "ACIP graduated escalation: 3+ blocked attempts in session"
            }

        return False, {"denial_count": denial_count}

    def _check_capability_aggregation(self, events: List[Dict]) -> Tuple[bool, Dict]:
        """
        Check for ACIP-style capability aggregation (drip attack).

        Detects patterns where information is gathered incrementally
        across multiple turns toward a potentially harmful goal.
        """
        # Track progression of sensitive path access
        sensitive_accesses = []
        for event in events:
            command = event.get("command", "") or ""
            # Track access to security-relevant paths
            if any(p in command.lower() for p in [
                ".ssh", ".aws", ".env", "credentials", "password",
                "secret", "token", "key", "config"
            ]):
                sensitive_accesses.append({
                    "timestamp": event.get("timestamp"),
                    "command": command[:100]
                })

        # If accessing multiple different sensitive areas, flag as aggregation
        unique_areas = set()
        for access in sensitive_accesses:
            cmd = access.get("command", "").lower()
            for area in [".ssh", ".aws", ".env", "credentials", "password", "token", "key"]:
                if area in cmd:
                    unique_areas.add(area)

        if len(unique_areas) >= 3:
            return True, {
                "unique_sensitive_areas": list(unique_areas),
                "total_sensitive_accesses": len(sensitive_accesses),
                "message": "ACIP capability aggregation: accessing multiple sensitive areas"
            }

        return False, {"unique_sensitive_areas": list(unique_areas)}

    def _calculate_risk_score(
        self,
        anomalies: List[AnomalyType],
        events: List[Dict],
        details: Dict[str, Any]
    ) -> float:
        """Calculate overall risk score for the session."""
        score = 0.0

        # Base score from anomaly count
        anomaly_weights = {
            AnomalyType.PRIVILEGE_ESCALATION: 0.3,
            AnomalyType.PATH_ESCALATION: 0.25,
            AnomalyType.REPEATED_DENIALS: 0.2,
            AnomalyType.BEHAVIOR_SHIFT: 0.15,
            AnomalyType.SUSPICIOUS_PATTERN: 0.25,
            AnomalyType.VELOCITY_CHANGE: 0.1,
            AnomalyType.TIER_DRIFT: 0.15,
            AnomalyType.CAPABILITY_AGGREGATION: 0.3,   # ACIP
            AnomalyType.GRADUATED_ESCALATION: 0.25,   # ACIP
        }

        for anomaly in anomalies:
            score += anomaly_weights.get(anomaly, 0.1)

        # Adjust based on denial ratio
        denials = len([e for e in events if e.get("decision") in ("block", "ask")])
        total = len(events)
        if total > 0:
            denial_ratio = denials / total
            if denial_ratio > 0.3:
                score += 0.1

        # Adjust based on dangerous command ratio
        dangerous = len([e for e in events if e.get("tier") == "dangerous"])
        if total > 0 and (dangerous / total) > 0.5:
            score += 0.1

        # Cap at 1.0
        return min(score, 1.0)

    def analyze(self, session_id: str) -> SessionAnalysis:
        """
        Analyze a session for cross-turn anomalies.

        Session analysis is free and open source.

        Args:
            session_id: Session to analyze

        Returns:
            SessionAnalysis with risk score and detected anomalies
        """
        if not session_id:
            return SessionAnalysis(
                session_id="unknown",
                risk_score=0.0,
                details={"error": "No session ID provided"}
            )

        try:
            with self.logger._get_connection() as conn:
                events = self._get_session_events(conn, session_id)

                if len(events) < 3:
                    return SessionAnalysis(
                        session_id=session_id,
                        risk_score=0.0,
                        details={"message": "Insufficient events for analysis"}
                    )

                anomalies = []
                all_details = {"total_events": len(events)}

                # Check for path escalation
                path_esc, path_details = self._check_path_escalation(events)
                if path_esc:
                    anomalies.append(AnomalyType.PATH_ESCALATION)
                all_details["path_analysis"] = path_details

                # Check for repeated denials
                repeated, denial_details = self._check_repeated_denials(events)
                if repeated:
                    anomalies.append(AnomalyType.REPEATED_DENIALS)
                all_details["denial_analysis"] = denial_details

                # Check for behavior shift
                behavior_shift, behavior_details = self._check_behavior_shift(events)
                if behavior_shift:
                    anomalies.append(AnomalyType.BEHAVIOR_SHIFT)
                all_details["behavior_analysis"] = behavior_details

                # Check for injection indicators
                injection, injection_details = self._check_injection_indicators(events)
                if injection:
                    anomalies.append(AnomalyType.SUSPICIOUS_PATTERN)
                all_details["injection_analysis"] = injection_details

                # ACIP: Check for graduated escalation (3+ denials)
                graduated, graduated_details = self._check_graduated_escalation(events)
                if graduated:
                    anomalies.append(AnomalyType.GRADUATED_ESCALATION)
                all_details["graduated_escalation"] = graduated_details

                # ACIP: Check for capability aggregation
                aggregation, aggregation_details = self._check_capability_aggregation(events)
                if aggregation:
                    anomalies.append(AnomalyType.CAPABILITY_AGGREGATION)
                all_details["capability_aggregation"] = aggregation_details

                # Memory: read cross-session workflow baselines
                try:
                    from tweek.memory.queries import memory_get_workflow_baseline
                    from tweek.memory.store import hash_project
                    # Use session_id as a proxy for project context
                    baseline = memory_get_workflow_baseline(session_id)
                    if baseline:
                        all_details["memory_baseline"] = baseline
                        # Flag if current denial ratio significantly exceeds baseline
                        current_denial_ratio = len(
                            [e for e in events if e.get("decision") in ("block", "ask")]
                        ) / max(len(events), 1)
                        baseline_ratio = baseline.get("denial_ratio", 0)
                        if (
                            current_denial_ratio > baseline_ratio * 2
                            and current_denial_ratio > 0.2
                            and baseline.get("total_invocations", 0) >= 20
                        ):
                            all_details["memory_baseline_exceeded"] = True
                except Exception:
                    pass  # Memory is best-effort

                # Calculate risk score
                risk_score = self._calculate_risk_score(anomalies, events, all_details)

                # Generate recommendations
                recommendations = []
                if AnomalyType.PATH_ESCALATION in anomalies:
                    recommendations.append(
                        "Progressive access to sensitive paths detected. "
                        "Review recent file access patterns."
                    )
                if AnomalyType.REPEATED_DENIALS in anomalies:
                    recommendations.append(
                        "Multiple blocked operations may indicate attack attempts. "
                        "Consider ending session."
                    )
                if AnomalyType.BEHAVIOR_SHIFT in anomalies:
                    recommendations.append(
                        "Significant behavior change detected mid-session. "
                        "Verify current task context."
                    )
                if AnomalyType.SUSPICIOUS_PATTERN in anomalies:
                    recommendations.append(
                        "Prompt injection indicators detected. "
                        "Session may be compromised."
                    )
                if AnomalyType.GRADUATED_ESCALATION in anomalies:
                    recommendations.append(
                        "ACIP graduated response: 3+ blocked attempts. "
                        "Applying elevated scrutiny to all operations."
                    )
                if AnomalyType.CAPABILITY_AGGREGATION in anomalies:
                    recommendations.append(
                        "ACIP capability aggregation: Accessing multiple sensitive areas. "
                        "Possible drip attack in progress."
                    )

                # Update session profile
                self._update_session_profile(conn, session_id, events, risk_score, anomalies)

                return SessionAnalysis(
                    session_id=session_id,
                    risk_score=risk_score,
                    anomalies=anomalies,
                    details=all_details,
                    recommendations=recommendations
                )

        except Exception as e:
            # Fail closed: analysis failure is itself suspicious
            return SessionAnalysis(
                session_id=session_id,
                risk_score=0.5,
                anomalies=[AnomalyType.SUSPICIOUS_PATTERN],
                details={"error": str(e), "fail_closed": True}
            )

    def _update_session_profile(
        self,
        conn: sqlite3.Connection,
        session_id: str,
        events: List[Dict],
        risk_score: float,
        anomalies: List[AnomalyType]
    ):
        """Update the session profile table."""
        try:
            now = datetime.now().isoformat()
            dangerous_count = len([e for e in events if e.get("tier") == "dangerous"])
            denied_count = len([e for e in events if e.get("decision") in ("block", "ask")])
            anomaly_flags = json.dumps([a.value for a in anomalies])

            conn.execute("""
                INSERT INTO session_profiles (
                    session_id, first_seen, last_seen, total_invocations,
                    dangerous_count, denied_count, risk_score, anomaly_flags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    total_invocations = excluded.total_invocations,
                    dangerous_count = excluded.dangerous_count,
                    denied_count = excluded.denied_count,
                    risk_score = excluded.risk_score,
                    anomaly_flags = excluded.anomaly_flags
            """, (
                session_id, now, now, len(events),
                dangerous_count, denied_count, risk_score, anomaly_flags
            ))
        except Exception:
            pass

    def format_analysis_message(self, analysis: SessionAnalysis) -> str:
        """Format a user-friendly analysis message."""
        if not analysis.is_suspicious:
            return ""

        lines = [
            "Session Analysis Alert",
            "=" * 45,
            f"Risk Score: {analysis.risk_score:.0%}",
        ]

        if analysis.anomalies:
            lines.append("\nDetected Anomalies:")
            for anomaly in analysis.anomalies:
                lines.append(f"  - {anomaly.value.replace('_', ' ').title()}")

        if analysis.recommendations:
            lines.append("\nRecommendations:")
            for rec in analysis.recommendations:
                lines.append(f"  - {rec}")

        lines.append("=" * 45)
        return "\n".join(lines)


# Singleton instance
_session_analyzer: Optional[SessionAnalyzer] = None


def get_session_analyzer() -> SessionAnalyzer:
    """Get the singleton session analyzer instance."""
    global _session_analyzer
    if _session_analyzer is None:
        _session_analyzer = SessionAnalyzer()
    return _session_analyzer
