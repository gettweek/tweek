"""
Tweek PII Scanner — Detect personally identifiable information in tool output.

Provides regex-based detection of common PII types in text content.
Used by post-tool-use hooks to warn when tool output contains sensitive data.

PII patterns adapted from Knostic OpenClaw Shield (Apache 2.0).
See THIRD-PARTY-NOTICES.md for attribution.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List


# PII detection patterns
# Each pattern returns findings with severity "medium" (warnings, not blocks)
PII_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "pii_email_address",
        "description": "Email address detected in output",
        "severity": "medium",
        "regex": re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        ),
    },
    {
        "name": "pii_us_ssn",
        "description": "US Social Security Number detected in output",
        "severity": "high",
        "regex": re.compile(
            # SSN format: XXX-XX-XXXX (excludes invalid prefixes 000, 666, 9xx)
            r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
        ),
    },
    {
        "name": "pii_credit_card",
        "description": "Credit card number detected in output",
        "severity": "high",
        "regex": re.compile(
            # Visa, Mastercard, Amex, Discover (with optional separators)
            r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
            r"[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{1,4}\b"
        ),
    },
    {
        "name": "pii_us_phone",
        "description": "US phone number detected in output",
        "severity": "medium",
        "regex": re.compile(
            r"\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"
        ),
    },
    {
        "name": "pii_intl_phone",
        "description": "International phone number detected in output",
        "severity": "medium",
        "regex": re.compile(
            r"\+[1-9]\d{1,2}[\s.-]?\d{2,4}[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b"
        ),
    },
    {
        "name": "pii_iban",
        "description": "IBAN bank account number detected in output",
        "severity": "high",
        "regex": re.compile(
            r"\b[A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?(?:[A-Z0-9]{4}[\s]?){2,7}[A-Z0-9]{1,4}\b"
        ),
    },
]

# Sensitive file path patterns that supplement existing tiers.yaml path blocking
SENSITIVE_FILE_PATTERNS: List[Dict[str, str]] = [
    {"pattern": r"\.p12$", "description": "PKCS#12 keystore file"},
    {"pattern": r"\.pfx$", "description": "PKCS#12 keystore file (PFX)"},
    {"pattern": r"known_hosts$", "description": "SSH known hosts file"},
    {"pattern": r"secrets\.(yaml|yml|json|toml)$", "description": "Secrets configuration file"},
    {"pattern": r"\.kube/config$", "description": "Kubernetes config file"},
    {"pattern": r"tokens?\.(json|yaml|yml)$", "description": "Token storage file"},
]


def scan_for_pii(content: str, source: str = "") -> List[Dict[str, Any]]:
    """Scan text content for PII patterns.

    Args:
        content: Text content to scan.
        source: Source identifier for reporting (e.g., filename or tool name).

    Returns:
        List of finding dicts with keys: name, severity, description, matched_text, source.
    """
    findings = []

    for pattern_def in PII_PATTERNS:
        matches = pattern_def["regex"].findall(content)
        if matches:
            # Report first match only (avoid flooding with duplicates)
            matched_text = matches[0] if isinstance(matches[0], str) else str(matches[0])
            findings.append({
                "name": pattern_def["name"],
                "severity": pattern_def["severity"],
                "description": pattern_def["description"],
                "matched_text": matched_text[:50],
                "source": source,
                "count": len(matches),
            })

    return findings


def check_sensitive_path(file_path: str) -> List[Dict[str, str]]:
    """Check if a file path matches sensitive file patterns.

    Args:
        file_path: File path to check.

    Returns:
        List of finding dicts with keys: pattern, description, file.
    """
    findings = []

    for pattern_def in SENSITIVE_FILE_PATTERNS:
        if re.search(pattern_def["pattern"], file_path, re.IGNORECASE):
            findings.append({
                "pattern": pattern_def["pattern"],
                "description": pattern_def["description"],
                "file": file_path,
            })

    return findings
