"""Tests for compliance plugins."""

import pytest
from tweek.plugins.base import ScanDirection, ActionType, Severity


class TestGovCompliancePlugin:
    """Tests for government classification compliance plugin."""

    @pytest.fixture
    def plugin(self):
        from tweek.plugins.compliance.gov import GovCompliancePlugin
        return GovCompliancePlugin()

    def test_plugin_name(self, plugin):
        """Test plugin name."""
        assert plugin.name == "gov"

    def test_scan_direction(self, plugin):
        """Test default scan direction is BOTH."""
        assert plugin.scan_direction == ScanDirection.BOTH

    def test_detect_top_secret(self, plugin):
        """Test detection of TOP SECRET marking."""
        content = "This document is TOP SECRET"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert len(result.findings) >= 1
        assert result.action == ActionType.BLOCK

    def test_detect_ts_sci(self, plugin):
        """Test detection of TS/SCI marking."""
        content = "Classified as TS/SCI"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "ts_sci" for f in result.findings)

    def test_detect_noforn(self, plugin):
        """Test detection of NOFORN caveat."""
        content = "This information is NOFORN"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "noforn" for f in result.findings)

    def test_detect_portion_marking(self, plugin):
        """Test detection of portion markings."""
        content = "(TS) This paragraph is classified."
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any("portion_marking" in f.pattern_name for f in result.findings)

    def test_detect_cui(self, plugin):
        """Test detection of CUI marking."""
        content = "This is CUI information"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "cui" for f in result.findings)

    def test_detect_fouo(self, plugin):
        """Test detection of FOUO marking."""
        content = "FOR OFFICIAL USE ONLY"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "fouo" for f in result.findings)

    def test_clean_content_passes(self, plugin):
        """Test that clean content passes."""
        content = "This is a normal document with no classification markings."
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is True
        assert len(result.findings) == 0

    def test_message_formatting_output(self, plugin):
        """Test message formatting for output direction."""
        content = "TOP SECRET document"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.message is not None
        assert "HALLUCINATED" in result.message

    def test_message_formatting_input(self, plugin):
        """Test message formatting for input direction."""
        content = "TOP SECRET document"
        result = plugin.scan(content, ScanDirection.INPUT)

        assert result.message is not None
        assert "ALERT" in result.message


class TestHIPAACompliancePlugin:
    """Tests for HIPAA PHI compliance plugin."""

    @pytest.fixture
    def plugin(self):
        from tweek.plugins.compliance.hipaa import HIPAACompliancePlugin
        return HIPAACompliancePlugin()

    def test_plugin_name(self, plugin):
        """Test plugin name."""
        assert plugin.name == "hipaa"

    def test_detect_mrn(self, plugin):
        """Test detection of Medical Record Number."""
        content = "Patient MRN: 123456789"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "mrn" for f in result.findings)

    def test_detect_patient_id(self, plugin):
        """Test detection of patient identifier."""
        content = "Patient ID: ABC-12345"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "patient_id" for f in result.findings)

    def test_detect_icd10(self, plugin):
        """Test detection of ICD-10 codes."""
        content = "Diagnosis: J18.9"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "icd10_code" for f in result.findings)

    def test_detect_prescription(self, plugin):
        """Test detection of prescription information."""
        content = "Prescribed Lisinopril 10 mg"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "prescription" for f in result.findings)

    def test_detect_hiv_status(self, plugin):
        """Test detection of HIV status (critical)."""
        content = "HIV positive test result"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "hiv_status" for f in result.findings)
        assert any(f.severity == Severity.CRITICAL for f in result.findings)

    def test_clean_content_passes(self, plugin):
        """Test that clean content passes."""
        content = "The patient reported feeling better after treatment."
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is True


class TestPCICompliancePlugin:
    """Tests for PCI-DSS compliance plugin."""

    @pytest.fixture
    def plugin(self):
        from tweek.plugins.compliance.pci import PCICompliancePlugin
        return PCICompliancePlugin()

    def test_plugin_name(self, plugin):
        """Test plugin name."""
        assert plugin.name == "pci"

    def test_detect_visa(self, plugin):
        """Test detection of Visa card number."""
        # Valid Luhn checksum
        content = "Card: 4532015112830366"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "visa" for f in result.findings)

    def test_detect_mastercard(self, plugin):
        """Test detection of Mastercard number."""
        # Valid Luhn checksum
        content = "Card: 5425233430109903"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "mastercard" for f in result.findings)

    def test_detect_cvv(self, plugin):
        """Test detection of CVV code."""
        content = "CVV: 123"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "cvv_labeled" for f in result.findings)

    def test_detect_bank_account(self, plugin):
        """Test detection of bank account number."""
        content = "Bank account: 12345678901"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "bank_account" for f in result.findings)

    def test_luhn_validation(self, plugin):
        """Test that invalid Luhn numbers are filtered."""
        # Invalid Luhn checksum
        content = "Card: 4532015112830367"  # Changed last digit
        result = plugin.scan(content, ScanDirection.OUTPUT)

        # Should not match Visa pattern due to Luhn failure
        visa_findings = [f for f in result.findings if f.pattern_name == "visa"]
        assert len(visa_findings) == 0

    def test_clean_content_passes(self, plugin):
        """Test that clean content passes."""
        content = "Payment was processed successfully."
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is True

    def test_redact_action(self, plugin):
        """Test that card numbers trigger redact action."""
        content = "Card: 4532015112830366"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.action == ActionType.REDACT


class TestLegalCompliancePlugin:
    """Tests for legal privilege compliance plugin."""

    @pytest.fixture
    def plugin(self):
        from tweek.plugins.compliance.legal import LegalCompliancePlugin
        return LegalCompliancePlugin()

    def test_plugin_name(self, plugin):
        """Test plugin name."""
        assert plugin.name == "legal"

    def test_detect_attorney_client(self, plugin):
        """Test detection of attorney-client privilege marker."""
        content = "This communication is protected by attorney-client privilege"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "attorney_client_privilege" for f in result.findings)

    def test_detect_work_product(self, plugin):
        """Test detection of work product doctrine marker."""
        content = "This is attorney work product"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "work_product" for f in result.findings)

    def test_detect_privileged_confidential(self, plugin):
        """Test detection of privileged and confidential marker."""
        content = "PRIVILEGED AND CONFIDENTIAL"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "privileged_confidential" for f in result.findings)

    def test_detect_settlement(self, plugin):
        """Test detection of settlement privilege marker."""
        content = "This is a settlement discussion"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "settlement_privilege" for f in result.findings)

    def test_detect_without_prejudice(self, plugin):
        """Test detection of without prejudice marker."""
        content = "Without Prejudice"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "without_prejudice" for f in result.findings)

    def test_detect_trade_secret(self, plugin):
        """Test detection of trade secret marker."""
        content = "This contains trade secret information"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "trade_secret" for f in result.findings)

    def test_detect_nda_protected(self, plugin):
        """Test detection of NDA-protected marker."""
        content = "This information is NDA protected"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "nda_protected" for f in result.findings)

    def test_detect_mnpi(self, plugin):
        """Test detection of MNPI (material non-public information)."""
        content = "This is material non-public information"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "material_non_public" for f in result.findings)
        assert result.action == ActionType.BLOCK

    def test_clean_content_passes(self, plugin):
        """Test that clean content passes."""
        content = "Please review the attached contract."
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is True


class TestCompliancePluginConfiguration:
    """Tests for compliance plugin configuration."""

    def test_action_override(self):
        """Test overriding default actions via config."""
        from tweek.plugins.compliance.gov import GovCompliancePlugin

        config = {
            "actions": {
                "top_secret_banner": "warn",  # Override from block to warn
                "secret_banner": "warn",  # Also override SECRET pattern
            }
        }
        plugin = GovCompliancePlugin(config)

        content = "TOP SECRET document"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        # Should now warn instead of block (both patterns overridden)
        assert result.action == ActionType.WARN

    def test_scan_direction_config(self):
        """Test configuring scan direction."""
        from tweek.plugins.compliance.gov import GovCompliancePlugin

        config = {"scan_direction": "input"}
        plugin = GovCompliancePlugin(config)

        assert plugin.scan_direction == ScanDirection.INPUT

        # Should not scan output when configured for input only
        content = "TOP SECRET document"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is True  # Skipped because wrong direction

    def test_allowlist_exact_match(self):
        """Test that allowlist suppresses exact string matches."""
        from tweek.plugins.compliance.pci import PCICompliancePlugin

        # This is a valid Visa test card number
        test_card = "4532015112830366"

        # Without allowlist - should fail
        plugin = PCICompliancePlugin()
        content = f"Card: {test_card}"
        result = plugin.scan(content, ScanDirection.OUTPUT)
        assert result.passed is False

        # With allowlist - should pass
        config = {"allowlist": [test_card]}
        plugin_with_allowlist = PCICompliancePlugin(config)
        result = plugin_with_allowlist.scan(content, ScanDirection.OUTPUT)
        assert result.passed is True

    def test_allowlist_pattern_match(self):
        """Test that allowlist patterns suppress regex matches."""
        from tweek.plugins.compliance.pci import PCICompliancePlugin

        # Test card numbers that pass Luhn validation
        test_card = "4532015112830366"

        # Without allowlist pattern - should fail
        plugin = PCICompliancePlugin()
        content = f"Test card: {test_card}"
        result = plugin.scan(content, ScanDirection.OUTPUT)
        assert result.passed is False

        # With allowlist pattern that matches the card number format
        # The pattern matches the exact matched_text (the card number)
        config = {"allowlist_patterns": [r"^453201511283\d{4}$"]}
        plugin_with_pattern = PCICompliancePlugin(config)
        result = plugin_with_pattern.scan(content, ScanDirection.OUTPUT)
        assert result.passed is True

    def test_suppressed_patterns(self):
        """Test that suppressed_patterns disables specific patterns."""
        from tweek.plugins.compliance.gov import GovCompliancePlugin

        content = "This is FOUO information"

        # Without suppression - should fail
        plugin = GovCompliancePlugin()
        result = plugin.scan(content, ScanDirection.OUTPUT)
        assert result.passed is False
        assert any(f.pattern_name == "fouo" for f in result.findings)

        # With suppressed pattern - should pass
        config = {"suppressed_patterns": ["fouo"]}
        plugin_suppressed = GovCompliancePlugin(config)
        result = plugin_suppressed.scan(content, ScanDirection.OUTPUT)
        assert result.passed is True


class TestSOC2CompliancePlugin:
    """Tests for SOC2 compliance plugin."""

    @pytest.fixture
    def plugin(self):
        from tweek.plugins.compliance.soc2 import SOC2CompliancePlugin
        return SOC2CompliancePlugin()

    def test_plugin_name(self, plugin):
        """Test plugin name."""
        assert plugin.name == "soc2"

    def test_detect_api_key_exposure(self, plugin):
        """Test detection of API key exposure."""
        content = "api_key: sk_live_abc123def456xyz789"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "api_key_exposure" for f in result.findings)

    def test_detect_private_key(self, plugin):
        """Test detection of private key header."""
        content = "-----BEGIN PRIVATE KEY-----"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "private_key_header" for f in result.findings)

    def test_detect_audit_log_tampering(self, plugin):
        """Test detection of audit log tampering attempt."""
        content = "DELETE FROM audit_logs WHERE date < '2024-01-01'"
        result = plugin.scan(content, ScanDirection.INPUT)

        assert result.passed is False
        assert any(f.pattern_name == "audit_log_tampering" for f in result.findings)

    def test_detect_security_incident(self, plugin):
        """Test detection of security incident indicator."""
        content = "Security incident detected in production environment"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "security_incident" for f in result.findings)

    def test_clean_content_passes(self, plugin):
        """Test that clean content passes."""
        content = "The application is running normally with no issues."
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is True


class TestGDPRCompliancePlugin:
    """Tests for GDPR compliance plugin."""

    @pytest.fixture
    def plugin(self):
        from tweek.plugins.compliance.gdpr import GDPRCompliancePlugin
        return GDPRCompliancePlugin()

    def test_plugin_name(self, plugin):
        """Test plugin name."""
        assert plugin.name == "gdpr"

    def test_detect_eu_iban(self, plugin):
        """Test detection of EU IBAN."""
        content = "Bank account: DE89 3704 0044 0532 0130 00"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "eu_iban" for f in result.findings)

    def test_detect_health_data(self, plugin):
        """Test detection of health data (Article 9)."""
        content = "diagnosis: diabetes type 2"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "health_data" for f in result.findings)
        assert result.action == ActionType.BLOCK

    def test_detect_genetic_data(self, plugin):
        """Test detection of genetic data (Article 9)."""
        content = "Patient DNA sequence analysis complete"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "genetic_data" for f in result.findings)

    def test_detect_ipv4_address(self, plugin):
        """Test detection of IPv4 address."""
        content = "User logged in from 192.168.1.100"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "ipv4_address" for f in result.findings)

    def test_detect_personal_data_breach(self, plugin):
        """Test detection of personal data breach indicator."""
        content = "We discovered a personal data breach affecting 1000 users"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "personal_data_breach" for f in result.findings)

    def test_detect_data_subject_request(self, plugin):
        """Test detection of data subject rights request."""
        content = "Processing subject access request #12345"
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is False
        assert any(f.pattern_name == "data_subject_request" for f in result.findings)

    def test_clean_content_passes(self, plugin):
        """Test that clean content passes."""
        content = "Our service is available in multiple European countries."
        result = plugin.scan(content, ScanDirection.OUTPUT)

        assert result.passed is True
