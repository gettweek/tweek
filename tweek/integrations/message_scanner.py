"""
Tweek Message Scanner — Scan inbound/outbound messages for the OpenClaw Gateway.

Provides prompt injection detection on inbound messages and PII/credential
leakage detection on outbound messages. Reuses existing pattern libraries
from the scanning pipeline.

Used by the OpenClaw scanning server endpoints:
    POST /message          — inbound injection detection
    POST /message/outbound — outbound PII and secret detection
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Inbound message scanning — prompt injection detection
# ---------------------------------------------------------------------------

# Patterns reused from tweek/skills/scanner.py (SKILL_INJECTION_PATTERNS)
# and tweek/security/session_analyzer.py (INJECTION_INDICATORS).
# We import them at call time to avoid circular imports and keep this module
# lightweight for import.

def _get_inbound_patterns() -> List[Dict[str, Any]]:
    """Load prompt injection patterns from existing modules."""
    patterns: List[Dict[str, Any]] = []

    # Primary: skill injection patterns (20+ patterns, high quality)
    try:
        from tweek.skills.scanner import SKILL_INJECTION_PATTERNS
        for p in SKILL_INJECTION_PATTERNS:
            patterns.append({
                "name": p["name"],
                "severity": p["severity"],
                "description": p["description"],
                "regex": re.compile(p["regex"], re.IGNORECASE) if isinstance(p["regex"], str) else p["regex"],
            })
    except ImportError:
        pass

    # Secondary: session analyzer injection indicators (6 patterns)
    try:
        from tweek.security.session_analyzer import SessionAnalyzer
        for pattern_str in SessionAnalyzer.INJECTION_INDICATORS:
            patterns.append({
                "name": "injection_indicator",
                "severity": "high",
                "description": f"Persistent injection indicator: {pattern_str[:40]}",
                "regex": re.compile(pattern_str, re.IGNORECASE),
            })
    except ImportError:
        pass

    return patterns


# Cache compiled patterns after first load
_inbound_patterns_cache: Optional[List[Dict[str, Any]]] = None


def _get_cached_inbound_patterns() -> List[Dict[str, Any]]:
    global _inbound_patterns_cache
    if _inbound_patterns_cache is None:
        _inbound_patterns_cache = _get_inbound_patterns()
    return _inbound_patterns_cache


def scan_inbound_message(content: str, role: str = "user") -> Dict[str, Any]:
    """Scan an inbound message for prompt injection patterns.

    Args:
        content: Message text to scan.
        role: Message role ("user", "assistant", "system", "tool").

    Returns:
        Dict with keys:
            flagged: bool — True if any injection patterns detected
            risk_level: str — "none", "medium", "high", "critical"
            findings: list — Individual pattern matches
            recommendations: list — Human-readable recommendations
    """
    if not content or not content.strip():
        return {
            "flagged": False,
            "risk_level": "none",
            "findings": [],
            "recommendations": [],
        }

    patterns = _get_cached_inbound_patterns()
    findings: List[Dict[str, str]] = []
    max_severity = "none"
    severity_rank = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    for pattern_def in patterns:
        regex = pattern_def["regex"]
        match = regex.search(content)
        if match:
            severity = pattern_def["severity"]
            findings.append({
                "pattern": pattern_def["name"],
                "severity": severity,
                "description": pattern_def["description"],
                "matched_text": match.group(0)[:80],
            })
            if severity_rank.get(severity, 0) > severity_rank.get(max_severity, 0):
                max_severity = severity

    flagged = len(findings) > 0
    recommendations: List[str] = []

    if flagged:
        if max_severity == "critical":
            recommendations.append(
                "Critical injection pattern detected. Message should be blocked."
            )
        elif max_severity == "high":
            recommendations.append(
                "High-severity injection pattern detected. Manual review recommended."
            )
        else:
            recommendations.append(
                "Suspicious pattern detected. Monitor session for escalation."
            )

        if role == "tool":
            recommendations.append(
                "Injection originated from tool output — possible indirect injection."
            )

    return {
        "flagged": flagged,
        "risk_level": max_severity,
        "findings": findings,
        "recommendations": recommendations,
    }


# ---------------------------------------------------------------------------
# Outbound message scanning — PII and credential leakage detection
# ---------------------------------------------------------------------------

# Secret patterns for detecting leaked credentials in outbound content.
# These complement the PII patterns from pii_scanner.py.
_SECRET_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "leaked_api_key",
        "severity": "high",
        "description": "API key pattern detected in outbound message",
        "regex": re.compile(
            r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}",
            re.IGNORECASE,
        ),
    },
    {
        "name": "leaked_bearer_token",
        "severity": "high",
        "description": "Bearer token detected in outbound message",
        "regex": re.compile(
            r"Bearer\s+[A-Za-z0-9_\-\.]{20,}",
        ),
    },
    {
        "name": "leaked_private_key",
        "severity": "critical",
        "description": "Private key material detected in outbound message",
        "regex": re.compile(
            r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        ),
    },
    {
        "name": "leaked_aws_key",
        "severity": "critical",
        "description": "AWS access key detected in outbound message",
        "regex": re.compile(
            r"AKIA[0-9A-Z]{16}",
        ),
    },
    {
        "name": "leaked_password_assignment",
        "severity": "high",
        "description": "Password assignment detected in outbound message",
        "regex": re.compile(
            r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{8,}",
            re.IGNORECASE,
        ),
    },
]


def scan_outbound_message(content: str) -> Dict[str, Any]:
    """Scan an outbound message for PII and credential leakage.

    Args:
        content: Message text to scan.

    Returns:
        Dict with keys:
            flagged: bool — True if PII or secrets detected
            pii_findings: list — PII pattern matches
            secret_findings: list — Credential/secret matches
            redacted: str|None — Redacted version if PII found (None if clean)
    """
    if not content or not content.strip():
        return {
            "flagged": False,
            "pii_findings": [],
            "secret_findings": [],
            "redacted": None,
        }

    # PII detection via existing scanner
    pii_findings: List[Dict[str, Any]] = []
    try:
        from tweek.security.pii_scanner import scan_for_pii
        raw_pii = scan_for_pii(content, source="outbound_message")
        pii_findings = raw_pii
    except ImportError:
        pass

    # Secret/credential detection
    secret_findings: List[Dict[str, Any]] = []
    for pattern_def in _SECRET_PATTERNS:
        match = pattern_def["regex"].search(content)
        if match:
            secret_findings.append({
                "name": pattern_def["name"],
                "severity": pattern_def["severity"],
                "description": pattern_def["description"],
                "matched_text": match.group(0)[:50],
            })

    flagged = len(pii_findings) > 0 or len(secret_findings) > 0

    # Build redacted version if anything was found
    redacted: Optional[str] = None
    if flagged:
        redacted = content
        # Redact secrets
        for pattern_def in _SECRET_PATTERNS:
            redacted = pattern_def["regex"].sub("[REDACTED]", redacted)
        # Redact PII
        try:
            from tweek.security.pii_scanner import PII_PATTERNS
            for pii_pat in PII_PATTERNS:
                redacted = pii_pat["regex"].sub("[PII_REDACTED]", redacted)
        except ImportError:
            pass

    return {
        "flagged": flagged,
        "pii_findings": pii_findings,
        "secret_findings": secret_findings,
        "redacted": redacted,
    }
