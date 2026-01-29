#!/usr/bin/env python3
"""
Tweek Legal Compliance Plugin

Detects legal privilege and confidentiality markers:
- Attorney-client privilege
- Work product doctrine
- Confidential communications
- Settlement discussions
- Trade secrets
- NDA-protected information

Helps prevent inadvertent waiver of legal privileges through LLM processing.
"""

from typing import Optional, List, Dict, Any
from tweek.plugins.base import (
    CompliancePlugin,
    ScanDirection,
    ActionType,
    Severity,
    PatternDefinition,
)


class LegalCompliancePlugin(CompliancePlugin):
    """
    Legal privilege and confidentiality compliance plugin.

    Detects markers indicating legally protected communications
    that should not be processed by external AI systems.
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Detect legal privilege and confidentiality markers"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "enterprise"
    TAGS = ["compliance", "legal", "privilege", "confidential"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._patterns: Optional[List[PatternDefinition]] = None

    @property
    def name(self) -> str:
        return "legal"

    @property
    def scan_direction(self) -> ScanDirection:
        direction = self._config.get("scan_direction", "both")
        return ScanDirection(direction)

    def get_patterns(self) -> List[PatternDefinition]:
        """Return legal privilege patterns."""
        if self._patterns is not None:
            return self._patterns

        self._patterns = [
            # =================================================================
            # Attorney-Client Privilege
            # =================================================================
            PatternDefinition(
                name="attorney_client_privilege",
                regex=r"(?i)ATTORNEY[\s-]*CLIENT\s+PRIVILEG(?:E|ED)",
                severity=Severity.HIGH,
                description="Attorney-client privilege marker",
                default_action=ActionType.WARN,
                tags=["privilege", "attorney-client"],
            ),
            PatternDefinition(
                name="privileged_confidential",
                regex=r"(?i)PRIVILEGED\s+(?:AND\s+)?CONFIDENTIAL",
                severity=Severity.HIGH,
                description="Privileged and confidential marker",
                default_action=ActionType.WARN,
                tags=["privilege", "confidential"],
            ),
            PatternDefinition(
                name="legal_privilege",
                regex=r"(?i)(?:SUBJECT\s+TO|PROTECTED\s+BY)\s+(?:LEGAL\s+)?PRIVILEG(?:E|ED)",
                severity=Severity.HIGH,
                description="Legal privilege protection marker",
                default_action=ActionType.WARN,
                tags=["privilege"],
            ),
            PatternDefinition(
                name="solicitor_privilege",
                regex=r"(?i)SOLICITOR[\s-]*CLIENT\s+PRIVILEG(?:E|ED)|LEGAL\s+PROFESSIONAL\s+PRIVILEGE",
                severity=Severity.HIGH,
                description="Solicitor-client privilege (UK/Commonwealth)",
                default_action=ActionType.WARN,
                tags=["privilege", "solicitor-client"],
            ),

            # =================================================================
            # Work Product Doctrine
            # =================================================================
            PatternDefinition(
                name="work_product",
                regex=r"(?i)(?:ATTORNEY|LEGAL|LAWYER)\s+WORK\s+PRODUCT",
                severity=Severity.HIGH,
                description="Attorney work product doctrine",
                default_action=ActionType.WARN,
                tags=["privilege", "work-product"],
            ),
            PatternDefinition(
                name="trial_preparation",
                regex=r"(?i)TRIAL\s+PREPARATION\s+MATERIALS?",
                severity=Severity.HIGH,
                description="Trial preparation materials",
                default_action=ActionType.WARN,
                tags=["privilege", "work-product"],
            ),
            PatternDefinition(
                name="litigation_hold",
                regex=r"(?i)LITIGATION\s+HOLD|LEGAL\s+HOLD|PRESERVATION\s+NOTICE",
                severity=Severity.MEDIUM,
                description="Litigation hold notice",
                default_action=ActionType.WARN,
                tags=["litigation"],
            ),

            # =================================================================
            # Confidential Communications
            # =================================================================
            PatternDefinition(
                name="confidential_header",
                regex=r"(?i)^[-=]*\s*CONFIDENTIAL\s*[-=]*$",
                severity=Severity.MEDIUM,
                description="Confidential header/footer",
                default_action=ActionType.WARN,
                tags=["confidential"],
            ),
            PatternDefinition(
                name="strictly_confidential",
                regex=r"(?i)STRICTLY\s+CONFIDENTIAL",
                severity=Severity.HIGH,
                description="Strictly confidential marker",
                default_action=ActionType.WARN,
                tags=["confidential"],
            ),
            PatternDefinition(
                name="confidential_info",
                regex=r"(?i)THIS\s+(?:DOCUMENT|COMMUNICATION|EMAIL|MESSAGE)\s+(?:IS|CONTAINS?)\s+CONFIDENTIAL",
                severity=Severity.MEDIUM,
                description="Confidential communication notice",
                default_action=ActionType.WARN,
                tags=["confidential"],
            ),

            # =================================================================
            # Settlement and Mediation
            # =================================================================
            PatternDefinition(
                name="settlement_privilege",
                regex=r"(?i)SETTLEMENT\s+(?:PRIVILEGE|NEGOTIATIONS?|DISCUSSION)",
                severity=Severity.HIGH,
                description="Settlement privilege/negotiations",
                default_action=ActionType.WARN,
                tags=["privilege", "settlement"],
            ),
            PatternDefinition(
                name="mediation_confidential",
                regex=r"(?i)(?:MEDIATION|ARBITRATION)\s+(?:PRIVILEGE|CONFIDENTIAL)",
                severity=Severity.HIGH,
                description="Mediation/arbitration confidentiality",
                default_action=ActionType.WARN,
                tags=["privilege", "adr"],
            ),
            PatternDefinition(
                name="without_prejudice",
                regex=r"(?i)WITHOUT\s+PREJUDICE",
                severity=Severity.MEDIUM,
                description="Without prejudice marker (settlement protection)",
                default_action=ActionType.WARN,
                tags=["privilege", "settlement"],
            ),
            PatternDefinition(
                name="rule_408",
                regex=r"(?i)(?:FRE|FEDERAL\s+RULES?\s+OF\s+EVIDENCE)\s+(?:RULE\s+)?408|SETTLEMENT\s+COMMUNICATIONS?",
                severity=Severity.MEDIUM,
                description="FRE 408 settlement communication",
                default_action=ActionType.WARN,
                tags=["privilege", "settlement"],
            ),

            # =================================================================
            # Trade Secrets
            # =================================================================
            PatternDefinition(
                name="trade_secret",
                regex=r"(?i)TRADE\s+SECRET|PROPRIETARY\s+(?:AND\s+)?CONFIDENTIAL",
                severity=Severity.HIGH,
                description="Trade secret marker",
                default_action=ActionType.WARN,
                tags=["trade-secret", "confidential"],
            ),
            PatternDefinition(
                name="dtsa_protected",
                regex=r"(?i)(?:DTSA|DEFEND\s+TRADE\s+SECRETS\s+ACT)\s+PROTECTED",
                severity=Severity.HIGH,
                description="DTSA protected information",
                default_action=ActionType.WARN,
                tags=["trade-secret"],
            ),

            # =================================================================
            # Non-Disclosure Agreements
            # =================================================================
            PatternDefinition(
                name="nda_protected",
                regex=r"(?i)(?:NDA|NON[\s-]?DISCLOSURE\s+AGREEMENT)\s+PROTECTED",
                severity=Severity.MEDIUM,
                description="NDA-protected information",
                default_action=ActionType.WARN,
                tags=["nda", "confidential"],
            ),
            PatternDefinition(
                name="confidentiality_agreement",
                regex=r"(?i)(?:SUBJECT\s+TO|PROTECTED\s+BY|COVERED\s+BY)\s+(?:A\s+)?(?:CONFIDENTIALITY|NON[\s-]?DISCLOSURE)\s+AGREEMENT",
                severity=Severity.MEDIUM,
                description="Confidentiality agreement reference",
                default_action=ActionType.WARN,
                tags=["nda", "confidential"],
            ),

            # =================================================================
            # Regulatory and Compliance
            # =================================================================
            PatternDefinition(
                name="export_controlled",
                regex=r"(?i)(?:EXPORT\s+CONTROLLED?|ITAR|EAR)\s+(?:INFORMATION|DATA|MATERIAL)",
                severity=Severity.HIGH,
                description="Export controlled information (ITAR/EAR)",
                default_action=ActionType.WARN,
                tags=["export-control", "regulatory"],
            ),
            PatternDefinition(
                name="material_non_public",
                regex=r"(?i)MATERIAL\s+NON[\s-]?PUBLIC\s+INFORMATION|MNPI",
                severity=Severity.CRITICAL,
                description="Material non-public information (insider trading)",
                default_action=ActionType.BLOCK,
                tags=["mnpi", "securities"],
            ),

            # =================================================================
            # Legal Disclaimers and Warnings
            # =================================================================
            PatternDefinition(
                name="unauthorized_disclosure",
                regex=r"(?i)UNAUTHORIZED\s+(?:DISCLOSURE|DISTRIBUTION|USE|ACCESS)\s+(?:IS\s+)?(?:STRICTLY\s+)?PROHIBITED",
                severity=Severity.MEDIUM,
                description="Unauthorized disclosure warning",
                default_action=ActionType.WARN,
                tags=["disclaimer"],
            ),
            PatternDefinition(
                name="intended_recipient",
                regex=r"(?i)(?:INTENDED\s+(?:ONLY\s+)?FOR|SOLELY\s+FOR)\s+(?:THE\s+)?(?:NAMED\s+)?RECIPIENT",
                severity=Severity.LOW,
                description="Intended recipient notice",
                default_action=ActionType.WARN,
                tags=["disclaimer"],
            ),
            PatternDefinition(
                name="delete_if_received",
                regex=r"(?i)(?:IF\s+YOU\s+(?:HAVE\s+)?RECEIVED\s+THIS\s+(?:IN\s+)?ERROR|PLEASE\s+DELETE|NOTIFY\s+THE\s+SENDER)",
                severity=Severity.LOW,
                description="Error receipt notice",
                default_action=ActionType.WARN,
                tags=["disclaimer"],
            ),

            # =================================================================
            # Legal Document Types
            # =================================================================
            PatternDefinition(
                name="draft_document",
                regex=r"(?i)(?:DRAFT|PRELIMINARY)\s+[-–]\s+(?:PRIVILEGED|CONFIDENTIAL|NOT\s+FOR\s+DISTRIBUTION)",
                severity=Severity.MEDIUM,
                description="Draft/preliminary document marker",
                default_action=ActionType.WARN,
                tags=["draft", "confidential"],
            ),
            PatternDefinition(
                name="legal_memo",
                regex=r"(?i)(?:ATTORNEY|LEGAL)\s+(?:MEMORANDUM|MEMO)\s+[-–]\s+(?:PRIVILEGED|CONFIDENTIAL)",
                severity=Severity.HIGH,
                description="Legal memorandum marker",
                default_action=ActionType.WARN,
                tags=["memo", "privilege"],
            ),
        ]

        return self._patterns

    def _format_message(
        self,
        findings: List,
        direction: ScanDirection
    ) -> Optional[str]:
        """Format a legal-specific message."""
        if not findings:
            return None

        privilege_findings = [f for f in findings if "privilege" in f.metadata.get("pattern_tags", [])]
        trade_secret_findings = [f for f in findings if "trade-secret" in f.metadata.get("pattern_tags", [])]

        if direction == ScanDirection.OUTPUT:
            msg = f"WARNING: LLM output contains {len(findings)} legal/privilege marker(s).\n"
            msg += "These may be hallucinated and do not confer actual privilege.\n"
            msg += "Do NOT rely on these markers for legal protection."
        else:
            msg = f"ALERT: Input contains {len(findings)} legal/privilege marker(s).\n"
            if privilege_findings:
                msg += f"  {len(privilege_findings)} privilege marker(s) - may constitute waiver if shared\n"
            if trade_secret_findings:
                msg += f"  {len(trade_secret_findings)} trade secret marker(s)\n"
            msg += "Processing privileged content through external AI may waive protections."

        return msg
