#!/usr/bin/env python3
"""
Tweek PCI-DSS Compliance Plugin

Detects payment card industry data:
- Credit/debit card numbers (with Luhn validation)
- CVV/CVC codes
- Bank account and routing numbers
- Payment tokens and references
- Cardholder data markers

Based on PCI-DSS requirements for protecting cardholder data.
"""

from typing import Optional, List, Dict, Any
from tweek.plugins.base import (
    CompliancePlugin,
    ScanDirection,
    ActionType,
    Severity,
    PatternDefinition,
    Finding,
)


def luhn_checksum(card_number: str) -> bool:
    """
    Validate a card number using the Luhn algorithm.

    Args:
        card_number: Card number string (digits only)

    Returns:
        True if valid according to Luhn algorithm
    """
    # Remove non-digits
    digits = ''.join(c for c in card_number if c.isdigit())

    if len(digits) < 13 or len(digits) > 19:
        return False

    # Luhn algorithm
    total = 0
    reverse_digits = digits[::-1]

    for i, digit in enumerate(reverse_digits):
        n = int(digit)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n

    return total % 10 == 0


class PCICompliancePlugin(CompliancePlugin):
    """
    PCI-DSS compliance plugin.

    Detects payment card data and related financial information
    that must be protected under PCI-DSS requirements.
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Detect PCI-DSS payment card and financial data"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "enterprise"
    TAGS = ["compliance", "pci", "financial", "payment"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._patterns: Optional[List[PatternDefinition]] = None
        self._validate_luhn = config.get("validate_luhn", True) if config else True

    @property
    def name(self) -> str:
        return "pci"

    @property
    def scan_direction(self) -> ScanDirection:
        direction = self._config.get("scan_direction", "both")
        return ScanDirection(direction)

    def get_patterns(self) -> List[PatternDefinition]:
        """Return PCI-DSS patterns."""
        if self._patterns is not None:
            return self._patterns

        self._patterns = [
            # =================================================================
            # Credit Card Numbers
            # =================================================================
            PatternDefinition(
                name="visa",
                regex=r"\b4[0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
                severity=Severity.CRITICAL,
                description="Visa card number",
                default_action=ActionType.REDACT,
                tags=["pci", "card", "visa"],
            ),
            PatternDefinition(
                name="mastercard",
                regex=r"\b5[1-5][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
                severity=Severity.CRITICAL,
                description="Mastercard number",
                default_action=ActionType.REDACT,
                tags=["pci", "card", "mastercard"],
            ),
            PatternDefinition(
                name="mastercard_2_series",
                regex=r"\b2[2-7][0-9]{2}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
                severity=Severity.CRITICAL,
                description="Mastercard 2-series number",
                default_action=ActionType.REDACT,
                tags=["pci", "card", "mastercard"],
            ),
            PatternDefinition(
                name="amex",
                regex=r"\b3[47][0-9]{2}[\s-]?[0-9]{6}[\s-]?[0-9]{5}\b",
                severity=Severity.CRITICAL,
                description="American Express card number",
                default_action=ActionType.REDACT,
                tags=["pci", "card", "amex"],
            ),
            PatternDefinition(
                name="discover",
                regex=r"\b6(?:011|5[0-9]{2})[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
                severity=Severity.CRITICAL,
                description="Discover card number",
                default_action=ActionType.REDACT,
                tags=["pci", "card", "discover"],
            ),
            PatternDefinition(
                name="diners",
                regex=r"\b3(?:0[0-5]|[68][0-9])[0-9][\s-]?[0-9]{6}[\s-]?[0-9]{4}\b",
                severity=Severity.CRITICAL,
                description="Diners Club card number",
                default_action=ActionType.REDACT,
                tags=["pci", "card", "diners"],
            ),
            PatternDefinition(
                name="jcb",
                regex=r"\b(?:2131|1800|35[0-9]{2})[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b",
                severity=Severity.CRITICAL,
                description="JCB card number",
                default_action=ActionType.REDACT,
                tags=["pci", "card", "jcb"],
            ),
            PatternDefinition(
                name="generic_card",
                regex=r"\b(?:[0-9]{4}[\s-]?){3}[0-9]{4}\b",
                severity=Severity.HIGH,
                description="Potential card number (16 digits)",
                default_action=ActionType.WARN,
                tags=["pci", "card", "generic"],
            ),

            # =================================================================
            # CVV/CVC/Security Codes
            # =================================================================
            PatternDefinition(
                name="cvv_labeled",
                regex=r"(?i)(?:CVV|CVC|CVV2|CVC2|CSC|CID)[:\s#]*[0-9]{3,4}",
                severity=Severity.CRITICAL,
                description="Card security code (CVV/CVC)",
                default_action=ActionType.REDACT,
                tags=["pci", "cvv"],
            ),
            PatternDefinition(
                name="security_code",
                regex=r"(?i)(?:SECURITY\s*CODE|CARD\s*CODE|VERIFICATION\s*(?:CODE|VALUE))[:\s#]*[0-9]{3,4}",
                severity=Severity.CRITICAL,
                description="Card security/verification code",
                default_action=ActionType.REDACT,
                tags=["pci", "cvv"],
            ),

            # =================================================================
            # Expiration Dates
            # =================================================================
            PatternDefinition(
                name="expiry_labeled",
                regex=r"(?i)(?:EXP(?:IRY|IRATION)?|VALID\s*(?:THRU|UNTIL))[:\s]*(?:0[1-9]|1[0-2])[\s/\-]?(?:[0-9]{2}|20[2-9][0-9])",
                severity=Severity.HIGH,
                description="Card expiration date",
                default_action=ActionType.WARN,
                tags=["pci", "expiry"],
            ),

            # =================================================================
            # Bank Account Information
            # =================================================================
            PatternDefinition(
                name="bank_account",
                regex=r"(?i)(?:BANK\s*)?(?:ACCOUNT|ACCT)[\s#:]*[0-9]{8,17}",
                severity=Severity.HIGH,
                description="Bank account number",
                default_action=ActionType.WARN,
                tags=["pci", "bank", "account"],
            ),
            PatternDefinition(
                name="routing_number",
                regex=r"(?i)(?:ROUTING|ABA|RTN)[\s#:]*[0-9]{9}",
                severity=Severity.HIGH,
                description="Bank routing number",
                default_action=ActionType.WARN,
                tags=["pci", "bank", "routing"],
            ),
            PatternDefinition(
                name="iban",
                regex=r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b",
                severity=Severity.HIGH,
                description="International Bank Account Number (IBAN)",
                default_action=ActionType.WARN,
                tags=["pci", "bank", "iban"],
            ),
            PatternDefinition(
                name="swift_bic",
                regex=r"(?i)(?:SWIFT|BIC)[:\s]*[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?",
                severity=Severity.MEDIUM,
                description="SWIFT/BIC code",
                default_action=ActionType.WARN,
                tags=["pci", "bank", "swift"],
            ),

            # =================================================================
            # Payment Tokens and References
            # =================================================================
            PatternDefinition(
                name="stripe_token",
                regex=r"(?i)(?:tok|pm|pi|ch|cus|sub|inv|in)_[a-zA-Z0-9]{14,}",
                severity=Severity.MEDIUM,
                description="Stripe payment token/ID",
                default_action=ActionType.WARN,
                tags=["pci", "token", "stripe"],
            ),
            PatternDefinition(
                name="paypal_transaction",
                regex=r"(?i)(?:PAYPAL|PP)\s*(?:TRANSACTION|TXN|ID)[:\s#]*[A-Z0-9]{17}",
                severity=Severity.MEDIUM,
                description="PayPal transaction ID",
                default_action=ActionType.WARN,
                tags=["pci", "token", "paypal"],
            ),

            # =================================================================
            # Cardholder Data
            # =================================================================
            PatternDefinition(
                name="cardholder_name",
                regex=r"(?i)(?:CARDHOLDER|CARD\s*HOLDER|NAME\s*ON\s*CARD)[:\s]+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+",
                severity=Severity.MEDIUM,
                description="Cardholder name",
                default_action=ActionType.WARN,
                tags=["pci", "cardholder"],
            ),
            PatternDefinition(
                name="billing_address",
                regex=r"(?i)(?:BILLING\s*ADDRESS|CARD\s*ADDRESS)[:\s]+[\w\s,.-]+",
                severity=Severity.LOW,
                description="Billing address",
                default_action=ActionType.WARN,
                tags=["pci", "cardholder", "address"],
            ),

            # =================================================================
            # PCI Context Markers
            # =================================================================
            PatternDefinition(
                name="pan_marker",
                regex=r"(?i)\bPAN\b[:\s]+|PRIMARY\s*ACCOUNT\s*NUMBER",
                severity=Severity.HIGH,
                description="Primary Account Number reference",
                default_action=ActionType.WARN,
                tags=["pci", "marker"],
            ),
            PatternDefinition(
                name="magnetic_stripe",
                regex=r"(?i)(?:TRACK\s*[12]|MAGNETIC\s*STRIPE|MAG\s*STRIPE)\s*DATA",
                severity=Severity.CRITICAL,
                description="Magnetic stripe data reference",
                default_action=ActionType.BLOCK,
                tags=["pci", "magnetic", "sensitive"],
            ),
            PatternDefinition(
                name="pin_block",
                regex=r"(?i)PIN\s*BLOCK|ENCRYPTED\s*PIN",
                severity=Severity.CRITICAL,
                description="PIN block reference",
                default_action=ActionType.BLOCK,
                tags=["pci", "pin", "sensitive"],
            ),
        ]

        return self._patterns

    def scan(self, content: str, direction: ScanDirection) -> "ScanResult":
        """
        Scan content for PCI data with Luhn validation for card numbers.

        Overrides base scan to add Luhn validation for card numbers.
        """
        from tweek.plugins.base import ScanResult

        result = super().scan(content, direction)

        if not self._validate_luhn:
            return result

        # Filter card findings through Luhn validation
        validated_findings = []
        for finding in result.findings:
            if finding.pattern_name in (
                "visa", "mastercard", "mastercard_2_series", "amex",
                "discover", "diners", "jcb", "generic_card"
            ):
                # Validate with Luhn
                if luhn_checksum(finding.matched_text):
                    validated_findings.append(finding)
                # else: skip false positive
            else:
                # Non-card patterns pass through
                validated_findings.append(finding)

        return ScanResult(
            passed=len(validated_findings) == 0,
            findings=validated_findings,
            action=self._determine_action(validated_findings),
            message=self._format_message(validated_findings, direction),
            scan_direction=direction,
            plugin_name=self.name
        )

    def _format_message(
        self,
        findings: List,
        direction: ScanDirection
    ) -> Optional[str]:
        """Format a PCI-specific message."""
        if not findings:
            return None

        card_findings = [f for f in findings if "card" in f.metadata.get("pattern_tags", [])]
        cvv_findings = [f for f in findings if "cvv" in f.metadata.get("pattern_tags", [])]

        msg_parts = []

        if direction == ScanDirection.OUTPUT:
            msg_parts.append(f"WARNING: LLM output contains {len(findings)} potential PCI data element(s).")
        else:
            msg_parts.append(f"ALERT: Input contains {len(findings)} potential PCI data element(s).")

        if card_findings:
            msg_parts.append(f"  {len(card_findings)} card number(s) detected (Luhn validated)")
        if cvv_findings:
            msg_parts.append(f"  {len(cvv_findings)} CVV/security code(s) detected")

        msg_parts.append("This data must be protected per PCI-DSS requirements.")

        return "\n".join(msg_parts)
