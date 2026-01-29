#!/usr/bin/env python3
"""
Tweek HIPAA Compliance Plugin

Detects Protected Health Information (PHI) identifiers:
- Patient identifiers (MRN, patient ID)
- Medical record references
- Diagnosis codes (ICD-10)
- Prescription information
- Healthcare facility identifiers
- Insurance information

Based on the 18 HIPAA identifiers that constitute PHI.
"""

from typing import Optional, List, Dict, Any
from tweek.plugins.base import (
    CompliancePlugin,
    ScanDirection,
    ActionType,
    Severity,
    PatternDefinition,
)


class HIPAACompliancePlugin(CompliancePlugin):
    """
    HIPAA/PHI compliance plugin.

    Detects patterns that may indicate Protected Health Information (PHI)
    as defined by HIPAA regulations.
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Detect HIPAA Protected Health Information (PHI) patterns"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "enterprise"
    TAGS = ["compliance", "hipaa", "healthcare", "phi"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._patterns: Optional[List[PatternDefinition]] = None

    @property
    def name(self) -> str:
        return "hipaa"

    @property
    def scan_direction(self) -> ScanDirection:
        direction = self._config.get("scan_direction", "both")
        return ScanDirection(direction)

    def get_patterns(self) -> List[PatternDefinition]:
        """Return HIPAA PHI patterns."""
        if self._patterns is not None:
            return self._patterns

        self._patterns = [
            # =================================================================
            # Patient Identifiers
            # =================================================================
            PatternDefinition(
                name="mrn",
                regex=r"(?i)(?:MRN|MEDICAL\s*RECORD\s*(?:NUMBER|#|NO\.?))[:\s#]*[A-Z]?\d{5,12}",
                severity=Severity.HIGH,
                description="Medical Record Number",
                default_action=ActionType.WARN,
                tags=["phi", "identifier", "mrn"],
            ),
            PatternDefinition(
                name="patient_id",
                regex=r"(?i)PATIENT\s*(?:ID|#|NUMBER|NO\.?)[:\s#]*[\w-]{4,20}",
                severity=Severity.HIGH,
                description="Patient identifier",
                default_action=ActionType.WARN,
                tags=["phi", "identifier"],
            ),
            PatternDefinition(
                name="account_number",
                regex=r"(?i)(?:HOSPITAL|MEDICAL|PATIENT)\s*(?:ACCOUNT|ACCT)\s*(?:#|NUMBER|NO\.?)[:\s#]*\d{6,15}",
                severity=Severity.HIGH,
                description="Medical account number",
                default_action=ActionType.WARN,
                tags=["phi", "identifier", "account"],
            ),

            # =================================================================
            # Diagnosis Codes
            # =================================================================
            PatternDefinition(
                name="icd10_code",
                regex=r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b",
                severity=Severity.MEDIUM,
                description="ICD-10 diagnosis code",
                default_action=ActionType.WARN,
                tags=["phi", "diagnosis", "icd10"],
            ),
            PatternDefinition(
                name="diagnosis_context",
                regex=r"(?i)(?:DIAGNOSED?\s+WITH|DX|DIAGNOSIS)[:\s]+[\w\s]{3,50}",
                severity=Severity.MEDIUM,
                description="Diagnosis context",
                default_action=ActionType.WARN,
                tags=["phi", "diagnosis"],
            ),
            PatternDefinition(
                name="cpt_code",
                regex=r"(?i)CPT[:\s#]*\d{5}",
                severity=Severity.MEDIUM,
                description="CPT procedure code",
                default_action=ActionType.WARN,
                tags=["phi", "procedure", "cpt"],
            ),

            # =================================================================
            # Prescription Information
            # =================================================================
            PatternDefinition(
                name="prescription",
                regex=r"(?i)(?:PRESCRIBED?|RX|MEDICATION)[:\s]+[\w\s-]+(?:\d+\s*(?:mg|ml|mcg|g|units?))",
                severity=Severity.MEDIUM,
                description="Prescription or medication with dosage",
                default_action=ActionType.WARN,
                tags=["phi", "prescription"],
            ),
            PatternDefinition(
                name="dea_number",
                regex=r"(?i)DEA\s*(?:#|NUMBER|NO\.?)?[:\s]*[A-Z]{2}\d{7}",
                severity=Severity.HIGH,
                description="DEA number (prescriber identifier)",
                default_action=ActionType.WARN,
                tags=["phi", "identifier", "dea"],
            ),
            PatternDefinition(
                name="ndc_code",
                regex=r"(?i)NDC[:\s#]*\d{4,5}-\d{3,4}-\d{1,2}",
                severity=Severity.MEDIUM,
                description="National Drug Code",
                default_action=ActionType.WARN,
                tags=["phi", "medication", "ndc"],
            ),

            # =================================================================
            # Insurance Information
            # =================================================================
            PatternDefinition(
                name="health_plan_id",
                regex=r"(?i)(?:HEALTH\s*PLAN|INSURANCE|POLICY)\s*(?:ID|#|NUMBER|NO\.?)[:\s#]*[\w-]{6,20}",
                severity=Severity.HIGH,
                description="Health plan/insurance identifier",
                default_action=ActionType.WARN,
                tags=["phi", "insurance"],
            ),
            PatternDefinition(
                name="medicare_id",
                regex=r"(?i)MEDICARE\s*(?:ID|#|NUMBER|NO\.?|BENEFICIARY)[:\s#]*\d[A-Z]\d[A-Z]-?[A-Z]{2}\d-?[A-Z]{2}\d{2}",
                severity=Severity.HIGH,
                description="Medicare Beneficiary Identifier",
                default_action=ActionType.WARN,
                tags=["phi", "medicare", "identifier"],
            ),
            PatternDefinition(
                name="medicaid_id",
                regex=r"(?i)MEDICAID\s*(?:ID|#|NUMBER|NO\.?)[:\s#]*[\w-]{8,15}",
                severity=Severity.HIGH,
                description="Medicaid identifier",
                default_action=ActionType.WARN,
                tags=["phi", "medicaid", "identifier"],
            ),

            # =================================================================
            # Provider Identifiers
            # =================================================================
            PatternDefinition(
                name="npi",
                regex=r"(?i)NPI[:\s#]*\d{10}",
                severity=Severity.MEDIUM,
                description="National Provider Identifier",
                default_action=ActionType.WARN,
                tags=["phi", "provider", "npi"],
            ),
            PatternDefinition(
                name="physician_context",
                regex=r"(?i)(?:ATTENDING|TREATING|PRIMARY)\s*(?:PHYSICIAN|DOCTOR|DR\.?)[:\s]+[\w\s]{3,40}",
                severity=Severity.LOW,
                description="Physician reference with context",
                default_action=ActionType.WARN,
                tags=["phi", "provider"],
            ),

            # =================================================================
            # Facility Information
            # =================================================================
            PatternDefinition(
                name="facility_id",
                regex=r"(?i)(?:FACILITY|HOSPITAL|CLINIC)\s*(?:ID|#|NUMBER|NO\.?)[:\s#]*[\w-]{4,20}",
                severity=Severity.MEDIUM,
                description="Healthcare facility identifier",
                default_action=ActionType.WARN,
                tags=["phi", "facility"],
            ),
            PatternDefinition(
                name="bed_location",
                regex=r"(?i)(?:ROOM|BED|UNIT)[:\s#]*[\w-]{1,10}",
                severity=Severity.LOW,
                description="Patient room/bed location",
                default_action=ActionType.WARN,
                tags=["phi", "location"],
            ),

            # =================================================================
            # Medical Conditions (Sensitive)
            # =================================================================
            PatternDefinition(
                name="hiv_status",
                regex=r"(?i)HIV\s*(?:\+|\-|POSITIVE|NEGATIVE|STATUS|TEST)",
                severity=Severity.CRITICAL,
                description="HIV status information",
                default_action=ActionType.BLOCK,
                tags=["phi", "sensitive", "hiv"],
            ),
            PatternDefinition(
                name="mental_health",
                regex=r"(?i)(?:PSYCH(?:IATRIC)?|MENTAL\s*HEALTH)\s*(?:DIAGNOSIS|HISTORY|TREATMENT|EVAL)",
                severity=Severity.HIGH,
                description="Mental health information",
                default_action=ActionType.WARN,
                tags=["phi", "sensitive", "mental-health"],
            ),
            PatternDefinition(
                name="substance_abuse",
                regex=r"(?i)(?:SUBSTANCE\s*ABUSE|DRUG\s*(?:ABUSE|ADDICTION)|ALCOHOL(?:ISM)?)\s*(?:HISTORY|TREATMENT|PROGRAM)",
                severity=Severity.HIGH,
                description="Substance abuse information",
                default_action=ActionType.WARN,
                tags=["phi", "sensitive", "substance-abuse"],
            ),

            # =================================================================
            # Dates (PHI when combined with health info)
            # =================================================================
            PatternDefinition(
                name="date_of_service",
                regex=r"(?i)(?:DATE\s*OF\s*(?:SERVICE|VISIT|ADMISSION|DISCHARGE)|DOS)[:\s]*\d{1,2}[-/]\d{1,2}[-/]\d{2,4}",
                severity=Severity.LOW,
                description="Date of healthcare service",
                default_action=ActionType.WARN,
                tags=["phi", "date"],
            ),
            PatternDefinition(
                name="dob_context",
                regex=r"(?i)(?:DOB|DATE\s*OF\s*BIRTH|BIRTH\s*DATE)[:\s]*\d{1,2}[-/]\d{1,2}[-/]\d{2,4}",
                severity=Severity.HIGH,
                description="Date of birth in healthcare context",
                default_action=ActionType.WARN,
                tags=["phi", "date", "dob"],
            ),
        ]

        return self._patterns

    def _format_message(
        self,
        findings: List,
        direction: ScanDirection
    ) -> Optional[str]:
        """Format a HIPAA-specific message."""
        if not findings:
            return None

        # Categorize findings
        high_severity = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]

        if direction == ScanDirection.OUTPUT:
            msg = f"WARNING: LLM output may contain {len(findings)} PHI indicator(s).\n"
            if high_severity:
                msg += f"  {len(high_severity)} HIGH/CRITICAL severity pattern(s) detected.\n"
            msg += "Review output before sharing to ensure HIPAA compliance."
            return msg
        else:
            msg = f"ALERT: Input may contain {len(findings)} PHI indicator(s).\n"
            if high_severity:
                msg += f"  {len(high_severity)} HIGH/CRITICAL severity pattern(s) detected.\n"
            msg += "Ensure this data is handled in accordance with HIPAA requirements."
            return msg
