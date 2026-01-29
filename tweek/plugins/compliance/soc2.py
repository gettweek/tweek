#!/usr/bin/env python3
"""
Tweek SOC2 Compliance Plugin

Detects patterns indicating SOC2-relevant security and compliance concerns:
- Access control indicators (passwords, API keys in logs)
- Audit log patterns (security events, access logs)
- Change management markers
- Incident response indicators
- Risk assessment markers
- Security policy references

SOC2 Trust Services Criteria:
- Security
- Availability
- Processing Integrity
- Confidentiality
- Privacy

Supports bidirectional scanning:
- OUTPUT: Detect LLM generating content that could violate SOC2 controls
- INPUT: Detect sensitive SOC2-relevant data in incoming content
"""

from typing import Optional, List, Dict, Any
from tweek.plugins.base import (
    CompliancePlugin,
    ScanDirection,
    ActionType,
    Severity,
    PatternDefinition,
)


class SOC2CompliancePlugin(CompliancePlugin):
    """
    SOC2 compliance plugin.

    Detects patterns relevant to SOC2 Trust Services Criteria,
    helping prevent exposure of security-sensitive information.
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Detect SOC2-relevant security and compliance patterns"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "enterprise"
    TAGS = ["compliance", "soc2", "security", "audit"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._patterns: Optional[List[PatternDefinition]] = None

    @property
    def name(self) -> str:
        return "soc2"

    @property
    def scan_direction(self) -> ScanDirection:
        direction = self._config.get("scan_direction", "both")
        return ScanDirection(direction)

    def get_patterns(self) -> List[PatternDefinition]:
        """Return SOC2 compliance patterns."""
        if self._patterns is not None:
            return self._patterns

        self._patterns = [
            # =================================================================
            # Access Control (Security Criteria)
            # =================================================================
            PatternDefinition(
                name="access_credentials",
                regex=r"(?i)(?:admin|root|service)\s*(?:password|pwd|pass|credential)[:\s=]+\S+",
                severity=Severity.CRITICAL,
                description="Administrative credentials exposure",
                default_action=ActionType.BLOCK,
                tags=["soc2", "security", "access-control"],
            ),
            PatternDefinition(
                name="api_key_exposure",
                regex=r"(?i)(?:api[_-]?key|auth[_-]?token|bearer[_-]?token|access[_-]?token)[:\s=]+['\"]?[\w-]{20,}['\"]?",
                severity=Severity.CRITICAL,
                description="API key or token exposure",
                default_action=ActionType.REDACT,
                tags=["soc2", "security", "access-control"],
            ),
            PatternDefinition(
                name="connection_string",
                regex=r"(?i)(?:connection[_-]?string|conn[_-]?str)[:\s=]+['\"]?[^'\"]{20,}['\"]?",
                severity=Severity.HIGH,
                description="Database connection string exposure",
                default_action=ActionType.REDACT,
                tags=["soc2", "security", "access-control"],
            ),
            PatternDefinition(
                name="private_key_header",
                regex=r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
                severity=Severity.CRITICAL,
                description="Private key header detected",
                default_action=ActionType.BLOCK,
                tags=["soc2", "security", "cryptography"],
            ),

            # =================================================================
            # Audit Logging (Security/Processing Integrity)
            # =================================================================
            PatternDefinition(
                name="audit_log_tampering",
                regex=r"(?i)(?:delete|truncate|drop)\s+(?:from\s+)?(?:audit|security|access)[_-]?logs?",
                severity=Severity.CRITICAL,
                description="Audit log tampering attempt",
                default_action=ActionType.BLOCK,
                tags=["soc2", "audit", "integrity"],
            ),
            PatternDefinition(
                name="log_manipulation",
                regex=r"(?i)(?:modify|alter|update)\s+(?:audit|security)[_-]?(?:log|trail|record)",
                severity=Severity.HIGH,
                description="Security log manipulation",
                default_action=ActionType.WARN,
                tags=["soc2", "audit", "integrity"],
            ),
            PatternDefinition(
                name="disable_logging",
                regex=r"(?i)(?:disable|stop|pause|turn\s*off)\s+(?:audit|security|access)[_-]?log",
                severity=Severity.HIGH,
                description="Attempt to disable security logging",
                default_action=ActionType.WARN,
                tags=["soc2", "audit"],
            ),

            # =================================================================
            # Change Management (Processing Integrity)
            # =================================================================
            PatternDefinition(
                name="unauthorized_change",
                regex=r"(?i)(?:bypass|skip|disable)\s+(?:change[_-]?management|approval|review)",
                severity=Severity.HIGH,
                description="Change management bypass attempt",
                default_action=ActionType.WARN,
                tags=["soc2", "change-management"],
            ),
            PatternDefinition(
                name="production_direct_access",
                regex=r"(?i)direct\s+(?:production|prod)\s+(?:access|modification|change)",
                severity=Severity.MEDIUM,
                description="Direct production access indication",
                default_action=ActionType.WARN,
                tags=["soc2", "change-management"],
            ),

            # =================================================================
            # Incident Response (Security/Availability)
            # =================================================================
            PatternDefinition(
                name="security_incident",
                regex=r"(?i)(?:security\s+)?(?:incident|breach|compromise|intrusion)\s+(?:report|detected|confirmed)",
                severity=Severity.HIGH,
                description="Security incident indicator",
                default_action=ActionType.WARN,
                tags=["soc2", "incident-response"],
            ),
            PatternDefinition(
                name="data_breach",
                regex=r"(?i)data\s+(?:breach|leak|exposure|exfiltration)",
                severity=Severity.CRITICAL,
                description="Data breach indicator",
                default_action=ActionType.WARN,
                tags=["soc2", "incident-response", "confidentiality"],
            ),
            PatternDefinition(
                name="unauthorized_access",
                regex=r"(?i)unauthorized\s+(?:access|login|entry|attempt)",
                severity=Severity.HIGH,
                description="Unauthorized access indicator",
                default_action=ActionType.WARN,
                tags=["soc2", "incident-response", "security"],
            ),

            # =================================================================
            # Confidentiality Controls
            # =================================================================
            PatternDefinition(
                name="confidential_marker",
                regex=r"(?i)\[?\s*(?:CONFIDENTIAL|INTERNAL\s+ONLY|RESTRICTED)\s*\]?",
                severity=Severity.MEDIUM,
                description="Confidentiality marking",
                default_action=ActionType.WARN,
                tags=["soc2", "confidentiality"],
            ),
            PatternDefinition(
                name="customer_data_exposure",
                regex=r"(?i)(?:customer|client|user)\s+(?:pii|personal\s+data|sensitive\s+data)",
                severity=Severity.HIGH,
                description="Customer sensitive data reference",
                default_action=ActionType.WARN,
                tags=["soc2", "confidentiality", "privacy"],
            ),

            # =================================================================
            # Risk Assessment
            # =================================================================
            PatternDefinition(
                name="vulnerability_disclosure",
                regex=r"(?i)(?:vulnerability|cve-\d{4}-\d+|security\s+flaw)\s+(?:in|affecting|found)",
                severity=Severity.MEDIUM,
                description="Vulnerability disclosure",
                default_action=ActionType.WARN,
                tags=["soc2", "risk", "security"],
            ),
            PatternDefinition(
                name="risk_assessment",
                regex=r"(?i)(?:high|critical)\s+risk\s+(?:identified|assessment|finding)",
                severity=Severity.MEDIUM,
                description="High risk assessment finding",
                default_action=ActionType.WARN,
                tags=["soc2", "risk"],
            ),

            # =================================================================
            # Security Policy
            # =================================================================
            PatternDefinition(
                name="policy_exception",
                regex=r"(?i)(?:security\s+)?policy\s+exception\s+(?:granted|approved|requested)",
                severity=Severity.MEDIUM,
                description="Security policy exception",
                default_action=ActionType.WARN,
                tags=["soc2", "policy"],
            ),
            PatternDefinition(
                name="compliance_violation",
                regex=r"(?i)(?:compliance|regulatory|policy)\s+violation",
                severity=Severity.HIGH,
                description="Compliance violation indicator",
                default_action=ActionType.WARN,
                tags=["soc2", "compliance"],
            ),
        ]

        return self._patterns

    def _format_message(
        self,
        findings: List,
        direction: ScanDirection
    ) -> Optional[str]:
        """Format a SOC2-specific message."""
        if not findings:
            return None

        # Group findings by SOC2 criteria
        security = [f for f in findings if "security" in f.metadata.get("pattern_tags", [])]
        confidentiality = [f for f in findings if "confidentiality" in f.metadata.get("pattern_tags", [])]
        audit = [f for f in findings if "audit" in f.metadata.get("pattern_tags", [])]

        if direction == ScanDirection.OUTPUT:
            lines = [
                f"WARNING: LLM output contains {len(findings)} SOC2-relevant finding(s).",
                "Review for potential security/compliance concerns:"
            ]
        else:
            lines = [
                f"ALERT: Input contains {len(findings)} SOC2-relevant finding(s).",
                "Verify proper handling according to security policies:"
            ]

        if security:
            lines.append(f"  Security: {len(security)} finding(s)")
        if confidentiality:
            lines.append(f"  Confidentiality: {len(confidentiality)} finding(s)")
        if audit:
            lines.append(f"  Audit: {len(audit)} finding(s)")

        return "\n".join(lines)
