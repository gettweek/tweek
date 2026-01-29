#!/usr/bin/env python3
"""
Tweek GDPR Compliance Plugin

Detects patterns indicating GDPR-relevant personal data:
- Personal identifiers (names, emails, phone numbers)
- Special category data (health, biometric, genetic)
- Location data
- Online identifiers (IP addresses, cookies, device IDs)
- Data subject rights markers
- Cross-border transfer indicators
- Consent and legal basis references

GDPR Article 4 Categories:
- Personal Data (any data relating to an identified/identifiable person)
- Special Categories (Article 9 - sensitive data requiring explicit consent)

Supports bidirectional scanning:
- OUTPUT: Detect LLM generating personal data inappropriately
- INPUT: Detect personal data in incoming content for proper handling
"""

from typing import Optional, List, Dict, Any
from tweek.plugins.base import (
    CompliancePlugin,
    ScanDirection,
    ActionType,
    Severity,
    PatternDefinition,
)


class GDPRCompliancePlugin(CompliancePlugin):
    """
    GDPR compliance plugin.

    Detects personal data patterns under GDPR, helping ensure
    proper handling of EU residents' data.
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Detect GDPR-relevant personal data patterns"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "enterprise"
    TAGS = ["compliance", "gdpr", "privacy", "eu"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._patterns: Optional[List[PatternDefinition]] = None

    @property
    def name(self) -> str:
        return "gdpr"

    @property
    def scan_direction(self) -> ScanDirection:
        direction = self._config.get("scan_direction", "both")
        return ScanDirection(direction)

    def get_patterns(self) -> List[PatternDefinition]:
        """Return GDPR compliance patterns."""
        if self._patterns is not None:
            return self._patterns

        self._patterns = [
            # =================================================================
            # Direct Personal Identifiers (Article 4(1))
            # =================================================================
            PatternDefinition(
                name="eu_national_id",
                regex=r"(?i)(?:national\s+id|passport\s+(?:no|number|#))[:\s]+[A-Z0-9]{6,12}",
                severity=Severity.HIGH,
                description="EU national ID or passport number",
                default_action=ActionType.REDACT,
                tags=["gdpr", "personal-data", "identifier"],
            ),
            PatternDefinition(
                name="eu_phone_number",
                regex=r"\+(?:31|32|33|34|39|43|44|45|46|47|48|49)\s*\d[\d\s-]{8,}",
                severity=Severity.MEDIUM,
                description="EU phone number format",
                default_action=ActionType.WARN,
                tags=["gdpr", "personal-data", "contact"],
            ),
            PatternDefinition(
                name="eu_iban",
                regex=r"\b[A-Z]{2}\d{2}\s*(?:[A-Z0-9]{4}\s*){4,7}[A-Z0-9]{0,3}\b",
                severity=Severity.HIGH,
                description="EU IBAN bank account number",
                default_action=ActionType.REDACT,
                tags=["gdpr", "personal-data", "financial"],
            ),
            PatternDefinition(
                name="eu_vat_number",
                regex=r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[A-Z0-9]{8,12}\b",
                severity=Severity.MEDIUM,
                description="EU VAT identification number",
                default_action=ActionType.WARN,
                tags=["gdpr", "personal-data", "business"],
            ),

            # =================================================================
            # Online Identifiers (Recital 30)
            # =================================================================
            PatternDefinition(
                name="ipv4_address",
                regex=r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
                severity=Severity.MEDIUM,
                description="IPv4 address (online identifier)",
                default_action=ActionType.WARN,
                tags=["gdpr", "online-identifier"],
            ),
            PatternDefinition(
                name="ipv6_address",
                regex=r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|(?:[0-9a-f]{1,4}:){1,7}:|(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}",
                severity=Severity.MEDIUM,
                description="IPv6 address (online identifier)",
                default_action=ActionType.WARN,
                tags=["gdpr", "online-identifier"],
            ),
            PatternDefinition(
                name="device_id",
                regex=r"(?i)(?:device[_-]?id|imei|udid|idfa|gaid)[:\s=]+['\"]?[A-Za-z0-9-]{16,}['\"]?",
                severity=Severity.MEDIUM,
                description="Device identifier",
                default_action=ActionType.WARN,
                tags=["gdpr", "online-identifier"],
            ),
            PatternDefinition(
                name="cookie_identifier",
                regex=r"(?i)(?:tracking[_-]?id|session[_-]?id|visitor[_-]?id)[:\s=]+['\"]?[A-Za-z0-9-]{16,}['\"]?",
                severity=Severity.LOW,
                description="Tracking cookie identifier",
                default_action=ActionType.WARN,
                tags=["gdpr", "online-identifier"],
            ),

            # =================================================================
            # Special Category Data (Article 9)
            # =================================================================
            PatternDefinition(
                name="health_data",
                regex=r"(?i)(?:diagnosis|medical\s+condition|treatment\s+for|prescribed)\s*:\s*\w+",
                severity=Severity.CRITICAL,
                description="Health data (Article 9 special category)",
                default_action=ActionType.BLOCK,
                tags=["gdpr", "special-category", "health"],
            ),
            PatternDefinition(
                name="biometric_data",
                regex=r"(?i)(?:fingerprint|facial\s+recognition|iris\s+scan|biometric)[:\s]+[A-Za-z0-9+/=]{20,}",
                severity=Severity.CRITICAL,
                description="Biometric data (Article 9 special category)",
                default_action=ActionType.BLOCK,
                tags=["gdpr", "special-category", "biometric"],
            ),
            PatternDefinition(
                name="genetic_data",
                regex=r"(?i)(?:dna|genetic|genome)\s+(?:sequence|data|profile|test)",
                severity=Severity.CRITICAL,
                description="Genetic data (Article 9 special category)",
                default_action=ActionType.BLOCK,
                tags=["gdpr", "special-category", "genetic"],
            ),
            PatternDefinition(
                name="political_opinion",
                regex=r"(?i)(?:political\s+(?:party|affiliation|opinion)|voting\s+(?:record|preference))",
                severity=Severity.HIGH,
                description="Political opinion data (Article 9)",
                default_action=ActionType.WARN,
                tags=["gdpr", "special-category", "political"],
            ),
            PatternDefinition(
                name="religious_belief",
                regex=r"(?i)(?:religious?\s+(?:belief|affiliation)|church\s+member)",
                severity=Severity.HIGH,
                description="Religious belief data (Article 9)",
                default_action=ActionType.WARN,
                tags=["gdpr", "special-category", "religious"],
            ),
            PatternDefinition(
                name="trade_union",
                regex=r"(?i)(?:trade|labor)\s+union\s+(?:member|affiliation)",
                severity=Severity.HIGH,
                description="Trade union membership (Article 9)",
                default_action=ActionType.WARN,
                tags=["gdpr", "special-category", "union"],
            ),
            PatternDefinition(
                name="sexual_orientation",
                regex=r"(?i)sexual\s+(?:orientation|preference)|gender\s+identity",
                severity=Severity.HIGH,
                description="Sexual orientation/identity data (Article 9)",
                default_action=ActionType.WARN,
                tags=["gdpr", "special-category", "sensitive"],
            ),

            # =================================================================
            # Location Data (Recital 30)
            # =================================================================
            PatternDefinition(
                name="precise_location",
                regex=r"(?i)(?:location|coordinates?|gps)[:\s]+[-+]?\d+\.?\d*[,\s]+[-+]?\d+\.?\d*",
                severity=Severity.MEDIUM,
                description="Precise location coordinates",
                default_action=ActionType.WARN,
                tags=["gdpr", "location"],
            ),
            PatternDefinition(
                name="home_address",
                regex=r"(?i)(?:home|residential)\s+address[:\s]+.{10,}",
                severity=Severity.HIGH,
                description="Home/residential address",
                default_action=ActionType.WARN,
                tags=["gdpr", "personal-data", "address"],
            ),

            # =================================================================
            # Data Subject Rights (Chapter III)
            # =================================================================
            PatternDefinition(
                name="data_subject_request",
                regex=r"(?i)(?:subject\s+access|deletion|erasure|portability|rectification)\s+request",
                severity=Severity.MEDIUM,
                description="Data subject rights request",
                default_action=ActionType.WARN,
                tags=["gdpr", "data-subject-rights"],
            ),
            PatternDefinition(
                name="right_to_be_forgotten",
                regex=r"(?i)right\s+to\s+(?:be\s+forgotten|erasure)|article\s+17",
                severity=Severity.MEDIUM,
                description="Right to be forgotten reference",
                default_action=ActionType.WARN,
                tags=["gdpr", "data-subject-rights", "erasure"],
            ),

            # =================================================================
            # Cross-Border Transfers (Chapter V)
            # =================================================================
            PatternDefinition(
                name="cross_border_transfer",
                regex=r"(?i)(?:transfer|export)\s+(?:to|outside)\s+(?:eu|eea|european)",
                severity=Severity.MEDIUM,
                description="Cross-border data transfer indicator",
                default_action=ActionType.WARN,
                tags=["gdpr", "transfer"],
            ),
            PatternDefinition(
                name="adequacy_decision",
                regex=r"(?i)(?:adequacy\s+decision|standard\s+contractual\s+clauses|scc|bcr)",
                severity=Severity.LOW,
                description="Transfer mechanism reference",
                default_action=ActionType.WARN,
                tags=["gdpr", "transfer", "legal-basis"],
            ),

            # =================================================================
            # Consent and Legal Basis (Article 6/7)
            # =================================================================
            PatternDefinition(
                name="consent_indicator",
                regex=r"(?i)(?:consent\s+(?:withdrawn|revoked|given)|opt[_-]?out\s+requested)",
                severity=Severity.MEDIUM,
                description="Consent status indicator",
                default_action=ActionType.WARN,
                tags=["gdpr", "consent", "legal-basis"],
            ),
            PatternDefinition(
                name="legitimate_interest",
                regex=r"(?i)legitimate\s+interest\s+(?:assessment|basis|applied)",
                severity=Severity.LOW,
                description="Legitimate interest reference",
                default_action=ActionType.WARN,
                tags=["gdpr", "legal-basis"],
            ),

            # =================================================================
            # Data Breach (Article 33/34)
            # =================================================================
            PatternDefinition(
                name="personal_data_breach",
                regex=r"(?i)personal\s+data\s+(?:breach|incident|exposure)",
                severity=Severity.HIGH,
                description="Personal data breach indicator",
                default_action=ActionType.WARN,
                tags=["gdpr", "breach", "incident"],
            ),
            PatternDefinition(
                name="dpa_notification",
                regex=r"(?i)(?:dpa|supervisory\s+authority|data\s+protection\s+authority)\s+(?:notification|notified)",
                severity=Severity.MEDIUM,
                description="DPA notification reference",
                default_action=ActionType.WARN,
                tags=["gdpr", "breach", "regulatory"],
            ),
        ]

        return self._patterns

    def _format_message(
        self,
        findings: List,
        direction: ScanDirection
    ) -> Optional[str]:
        """Format a GDPR-specific message."""
        if not findings:
            return None

        # Group findings by GDPR category
        special_category = [f for f in findings if "special-category" in f.metadata.get("pattern_tags", [])]
        personal_data = [f for f in findings if "personal-data" in f.metadata.get("pattern_tags", [])]
        online_id = [f for f in findings if "online-identifier" in f.metadata.get("pattern_tags", [])]

        if direction == ScanDirection.OUTPUT:
            lines = [
                f"WARNING: LLM output contains {len(findings)} GDPR-relevant finding(s).",
                "Personal data should not be generated/exposed without proper basis:"
            ]
        else:
            lines = [
                f"ALERT: Input contains {len(findings)} GDPR-relevant finding(s).",
                "Ensure proper legal basis and handling for personal data:"
            ]

        if special_category:
            lines.append(f"  Article 9 Special Category: {len(special_category)} finding(s) - REQUIRES EXPLICIT CONSENT")
        if personal_data:
            lines.append(f"  Personal Identifiers: {len(personal_data)} finding(s)")
        if online_id:
            lines.append(f"  Online Identifiers: {len(online_id)} finding(s)")

        return "\n".join(lines)
