#!/usr/bin/env python3
"""
Tweek Government Classification Compliance Plugin

Detects and handles government classification markings:
- Classification levels (TOP SECRET, SECRET, CONFIDENTIAL)
- Portion markings ((TS), (S), (C))
- Handling caveats (NOFORN, ORCON, REL TO)
- Controlled Unclassified Information (CUI, FOUO)

Supports bidirectional scanning:
- OUTPUT: Detect hallucinated classification markings in LLM responses
- INPUT: Detect real classification markings in incoming data

IMPORTANT: This plugin detects MARKERS, not actual classified content.
It helps prevent:
1. LLMs hallucinating classification markings on unclassified content
2. Accidental exposure of marked content to LLMs
"""

from typing import Optional, List, Dict, Any
from tweek.plugins.base import (
    CompliancePlugin,
    ScanDirection,
    ActionType,
    Severity,
    PatternDefinition,
)


class GovCompliancePlugin(CompliancePlugin):
    """
    Government classification compliance plugin.

    Detects classification markings, portion markings, and handling caveats
    used in US government documents and communications.
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Detect government classification markings and handling caveats"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "enterprise"
    TAGS = ["compliance", "government", "classification", "cui"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._patterns: Optional[List[PatternDefinition]] = None

    @property
    def name(self) -> str:
        return "gov"

    @property
    def scan_direction(self) -> ScanDirection:
        # Configurable, defaults to BOTH
        direction = self._config.get("scan_direction", "both")
        return ScanDirection(direction)

    def get_patterns(self) -> List[PatternDefinition]:
        """Return government classification patterns."""
        if self._patterns is not None:
            return self._patterns

        self._patterns = [
            # =================================================================
            # TOP SECRET Level
            # =================================================================
            PatternDefinition(
                name="top_secret_banner",
                regex=r"(?i)\bTOP\s*SECRET\b(?:\s*/\s*(?:SCI|TK|NOFORN|ORCON|REL\s+TO\s+[\w,\s]+))*",
                severity=Severity.CRITICAL,
                description="Top Secret classification marking",
                default_action=ActionType.BLOCK,
                tags=["classification", "top-secret"],
            ),
            PatternDefinition(
                name="ts_sci",
                regex=r"(?i)\bTS\s*/\s*SCI\b",
                severity=Severity.CRITICAL,
                description="Top Secret/Sensitive Compartmented Information",
                default_action=ActionType.BLOCK,
                tags=["classification", "top-secret", "sci"],
            ),
            PatternDefinition(
                name="portion_marking_ts",
                regex=r"\(TS(?:\s*/\s*[A-Z]+)*\)",
                severity=Severity.CRITICAL,
                description="Top Secret portion marking",
                default_action=ActionType.BLOCK,
                tags=["classification", "portion-marking", "top-secret"],
            ),

            # =================================================================
            # SECRET Level
            # =================================================================
            PatternDefinition(
                name="secret_banner",
                regex=r"(?i)(?<!/)\bSECRET\b(?!\s*/\s*(?:SERVICE|KEY|TOKEN|PASSWORD|API))",
                severity=Severity.CRITICAL,
                description="Secret classification marking",
                default_action=ActionType.BLOCK,
                tags=["classification", "secret"],
            ),
            PatternDefinition(
                name="portion_marking_s",
                regex=r"\(S(?:\s*/\s*[A-Z]+)*\)(?!\s*[a-z])",
                severity=Severity.CRITICAL,
                description="Secret portion marking",
                default_action=ActionType.BLOCK,
                tags=["classification", "portion-marking", "secret"],
            ),

            # =================================================================
            # CONFIDENTIAL Level
            # =================================================================
            PatternDefinition(
                name="confidential_banner",
                regex=r"(?i)(?<!/)\bCONFIDENTIAL\b(?!\s+(?:INFORMATION|DATA|FILE|DOCUMENT))",
                severity=Severity.HIGH,
                description="Confidential classification marking",
                default_action=ActionType.WARN,
                tags=["classification", "confidential"],
            ),
            PatternDefinition(
                name="portion_marking_c",
                regex=r"\(C(?:\s*/\s*[A-Z]+)*\)(?!\s*[a-z])",
                severity=Severity.HIGH,
                description="Confidential portion marking",
                default_action=ActionType.WARN,
                tags=["classification", "portion-marking", "confidential"],
            ),

            # =================================================================
            # Handling Caveats
            # =================================================================
            PatternDefinition(
                name="noforn",
                regex=r"(?i)\bNOFORN\b|NO\s*FOREIGN\s*(?:NATIONALS?|DISSEMINATION)",
                severity=Severity.CRITICAL,
                description="No Foreign Nationals handling caveat",
                default_action=ActionType.BLOCK,
                tags=["caveat", "noforn"],
            ),
            PatternDefinition(
                name="orcon",
                regex=r"(?i)\bORCON\b|ORIGINATOR\s*CONTROLLED",
                severity=Severity.HIGH,
                description="Originator Controlled handling caveat",
                default_action=ActionType.WARN,
                tags=["caveat", "orcon"],
            ),
            PatternDefinition(
                name="rel_to",
                regex=r"(?i)REL(?:EASABLE)?\s*TO\s+(?:USA|FVEY|[\w,\s]+)",
                severity=Severity.HIGH,
                description="Releasable To specific countries",
                default_action=ActionType.WARN,
                tags=["caveat", "rel-to"],
            ),
            PatternDefinition(
                name="fvey",
                regex=r"(?i)\bFVEY\b|FIVE\s*EYES",
                severity=Severity.HIGH,
                description="Five Eyes intelligence sharing",
                default_action=ActionType.WARN,
                tags=["caveat", "fvey"],
            ),
            PatternDefinition(
                name="wnintel",
                regex=r"(?i)\bWNINTEL\b|WARNING\s*NOTICE",
                severity=Severity.HIGH,
                description="Warning Notice Intelligence Sources",
                default_action=ActionType.WARN,
                tags=["caveat", "wnintel"],
            ),
            PatternDefinition(
                name="propin",
                regex=r"(?i)\bPROPIN\b|PROPRIETARY\s*INFORMATION",
                severity=Severity.MEDIUM,
                description="Proprietary Information caveat",
                default_action=ActionType.WARN,
                tags=["caveat", "propin"],
            ),

            # =================================================================
            # Controlled Unclassified Information (CUI)
            # =================================================================
            PatternDefinition(
                name="cui",
                regex=r"(?i)\bCUI\b(?!\s*(?:BASIC|SPECIFIED))|\bCONTROLLED\s+UNCLASSIFIED\s+INFORMATION\b",
                severity=Severity.MEDIUM,
                description="Controlled Unclassified Information",
                default_action=ActionType.WARN,
                tags=["cui"],
            ),
            PatternDefinition(
                name="cui_specified",
                regex=r"(?i)CUI\s*//?\s*(?:SP|SPECIFIED)",
                severity=Severity.HIGH,
                description="CUI Specified (higher protection)",
                default_action=ActionType.WARN,
                tags=["cui", "specified"],
            ),
            PatternDefinition(
                name="fouo",
                regex=r"(?i)\bFOUO\b|FOR\s+OFFICIAL\s+USE\s+ONLY",
                severity=Severity.MEDIUM,
                description="For Official Use Only (legacy CUI)",
                default_action=ActionType.WARN,
                tags=["cui", "fouo", "legacy"],
            ),
            PatternDefinition(
                name="law_enforcement_sensitive",
                regex=r"(?i)\bLES\b(?:\s*/\s*[A-Z]+)*|LAW\s+ENFORCEMENT\s+SENSITIVE",
                severity=Severity.MEDIUM,
                description="Law Enforcement Sensitive",
                default_action=ActionType.WARN,
                tags=["cui", "les"],
            ),

            # =================================================================
            # Classification Headers/Footers
            # =================================================================
            PatternDefinition(
                name="classification_header",
                regex=r"^(?:UNCLASSIFIED|CONFIDENTIAL|SECRET|TOP\s*SECRET)(?:\s*//\s*[A-Z/\s]+)?$",
                severity=Severity.HIGH,
                description="Classification header/footer line",
                default_action=ActionType.WARN,
                tags=["classification", "header"],
            ),
            PatternDefinition(
                name="classification_banner_line",
                regex=r"[-=]{3,}\s*(?:UNCLASSIFIED|CONFIDENTIAL|SECRET|TOP\s*SECRET)\s*[-=]{3,}",
                severity=Severity.HIGH,
                description="Classification banner line",
                default_action=ActionType.WARN,
                tags=["classification", "banner"],
            ),

            # =================================================================
            # Special Programs
            # =================================================================
            PatternDefinition(
                name="sap_marker",
                regex=r"(?i)\bSAP\b(?:\s*/\s*[A-Z]+)*|SPECIAL\s+ACCESS\s+PROGRAM",
                severity=Severity.CRITICAL,
                description="Special Access Program marker",
                default_action=ActionType.BLOCK,
                tags=["classification", "sap"],
            ),
            PatternDefinition(
                name="waived_sap",
                regex=r"(?i)WAIVED\s+SAP|UNACKNOWLEDGED\s+SAP",
                severity=Severity.CRITICAL,
                description="Waived/Unacknowledged SAP reference",
                default_action=ActionType.BLOCK,
                tags=["classification", "sap"],
            ),

            # =================================================================
            # NATO Classifications
            # =================================================================
            PatternDefinition(
                name="nato_classification",
                regex=r"(?i)NATO\s+(?:UNCLASSIFIED|RESTRICTED|CONFIDENTIAL|SECRET|COSMIC\s+TOP\s+SECRET)",
                severity=Severity.HIGH,
                description="NATO classification marking",
                default_action=ActionType.WARN,
                tags=["classification", "nato"],
            ),

            # =================================================================
            # Declassification Markings
            # =================================================================
            PatternDefinition(
                name="declassification_date",
                regex=r"(?i)DECLAS(?:SIFY)?(?:\s+ON)?:\s*\d{4}[-/]\d{2}[-/]\d{2}",
                severity=Severity.MEDIUM,
                description="Declassification date marking",
                default_action=ActionType.WARN,
                tags=["classification", "declassification"],
            ),
            PatternDefinition(
                name="classified_by",
                regex=r"(?i)CLASSIFIED\s+BY:\s*[\w\s]+",
                severity=Severity.MEDIUM,
                description="Classified By line",
                default_action=ActionType.WARN,
                tags=["classification", "attribution"],
            ),
            PatternDefinition(
                name="derived_from",
                regex=r"(?i)DERIVED\s+FROM:\s*[\w\s]+",
                severity=Severity.MEDIUM,
                description="Derived From line",
                default_action=ActionType.WARN,
                tags=["classification", "attribution"],
            ),
        ]

        return self._patterns

    def _format_message(
        self,
        findings: List,
        direction: ScanDirection
    ) -> Optional[str]:
        """Format a government-specific message."""
        if not findings:
            return None

        if direction == ScanDirection.OUTPUT:
            return (
                f"WARNING: LLM output contains {len(findings)} classification marking(s).\n"
                "These are likely HALLUCINATED and do not indicate actual classified content.\n"
                "Do NOT treat this content as classified - verify with proper authorities."
            )
        else:
            return (
                f"ALERT: Input contains {len(findings)} classification marking(s).\n"
                "If this is actual classified material, it should NOT be processed by this system.\n"
                "Verify proper handling procedures and need-to-know."
            )
