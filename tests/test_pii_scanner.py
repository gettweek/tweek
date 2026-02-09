"""Tests for the PII scanner module."""

import pytest

from tweek.security.pii_scanner import (
    PII_PATTERNS,
    SENSITIVE_FILE_PATTERNS,
    check_sensitive_path,
    scan_for_pii,
)


@pytest.mark.security
class TestPIIDetection:
    """Test PII pattern detection."""

    def test_detect_email(self):
        """Detects email addresses."""
        findings = scan_for_pii("Contact us at user@example.com for info")
        assert any(f["name"] == "pii_email_address" for f in findings)

    def test_detect_us_ssn(self):
        """Detects US Social Security Numbers."""
        findings = scan_for_pii("SSN: 123-45-6789")
        assert any(f["name"] == "pii_us_ssn" for f in findings)

    def test_ssn_excludes_invalid_prefixes(self):
        """SSN pattern excludes known invalid prefixes (000, 666, 9xx)."""
        # 000 prefix - invalid
        findings = scan_for_pii("SSN: 000-45-6789")
        assert not any(f["name"] == "pii_us_ssn" for f in findings)

        # 666 prefix - invalid
        findings = scan_for_pii("SSN: 666-45-6789")
        assert not any(f["name"] == "pii_us_ssn" for f in findings)

        # 900+ prefix - invalid
        findings = scan_for_pii("SSN: 900-45-6789")
        assert not any(f["name"] == "pii_us_ssn" for f in findings)

    def test_detect_credit_card_visa(self):
        """Detects Visa credit card numbers."""
        findings = scan_for_pii("Card: 4111-1111-1111-1111")
        assert any(f["name"] == "pii_credit_card" for f in findings)

    def test_detect_credit_card_mastercard(self):
        """Detects Mastercard credit card numbers."""
        findings = scan_for_pii("Card: 5500 0000 0000 0004")
        assert any(f["name"] == "pii_credit_card" for f in findings)

    def test_detect_us_phone(self):
        """Detects US phone numbers."""
        findings = scan_for_pii("Call (555) 123-4567")
        assert any(f["name"] == "pii_us_phone" for f in findings)

    def test_detect_intl_phone(self):
        """Detects international phone numbers."""
        findings = scan_for_pii("Phone: +44 20 7946 0958")
        assert any(f["name"] == "pii_intl_phone" for f in findings)

    def test_detect_iban(self):
        """Detects IBAN bank account numbers."""
        findings = scan_for_pii("IBAN: GB29 NWBK 6016 1331 9268 19")
        assert any(f["name"] == "pii_iban" for f in findings)

    def test_no_false_positives_on_benign_content(self):
        """Benign text produces no high-severity PII findings."""
        findings = scan_for_pii(
            "This is a normal code review comment about implementing "
            "the login feature with proper error handling."
        )
        high_findings = [f for f in findings if f["severity"] in ("high", "critical")]
        assert len(high_findings) == 0

    def test_finding_includes_source(self):
        """Findings include the source identifier."""
        findings = scan_for_pii("SSN: 123-45-6789", source="Read output")
        assert findings[0]["source"] == "Read output"

    def test_finding_includes_count(self):
        """Findings include the match count."""
        findings = scan_for_pii(
            "Emails: a@b.com and c@d.com and e@f.com"
        )
        email_finding = next(f for f in findings if f["name"] == "pii_email_address")
        assert email_finding["count"] == 3

    def test_matched_text_truncated(self):
        """Matched text is truncated to 50 characters."""
        # Long email
        long_email = "a" * 60 + "@example.com"
        findings = scan_for_pii(f"Email: {long_email}")
        if findings:
            assert len(findings[0]["matched_text"]) <= 50


@pytest.mark.security
class TestSensitiveFilePaths:
    """Test sensitive file path detection."""

    def test_detect_p12_file(self):
        """Detects .p12 keystore files."""
        findings = check_sensitive_path("certs/server.p12")
        assert len(findings) > 0
        assert findings[0]["description"] == "PKCS#12 keystore file"

    def test_detect_pfx_file(self):
        """Detects .pfx keystore files."""
        findings = check_sensitive_path("certs/client.pfx")
        assert len(findings) > 0

    def test_detect_known_hosts(self):
        """Detects SSH known_hosts file."""
        findings = check_sensitive_path(".ssh/known_hosts")
        assert len(findings) > 0

    def test_detect_secrets_yaml(self):
        """Detects secrets configuration files."""
        for ext in ("yaml", "yml", "json", "toml"):
            findings = check_sensitive_path(f"config/secrets.{ext}")
            assert len(findings) > 0, f"Failed to detect secrets.{ext}"

    def test_detect_kube_config(self):
        """Detects Kubernetes config file."""
        findings = check_sensitive_path(".kube/config")
        assert len(findings) > 0

    def test_detect_token_files(self):
        """Detects token storage files."""
        findings = check_sensitive_path("auth/token.json")
        assert len(findings) > 0

        findings = check_sensitive_path("auth/tokens.yaml")
        assert len(findings) > 0

    def test_no_false_positive_on_normal_files(self):
        """Normal files do not trigger sensitive path detection."""
        findings = check_sensitive_path("src/main.py")
        assert len(findings) == 0

        findings = check_sensitive_path("README.md")
        assert len(findings) == 0


@pytest.mark.security
class TestPIIPatternsIntegrity:
    """Test PII pattern list integrity."""

    def test_all_patterns_have_required_keys(self):
        """All PII patterns have name, description, severity, and regex."""
        for pattern in PII_PATTERNS:
            assert "name" in pattern
            assert "description" in pattern
            assert "severity" in pattern
            assert "regex" in pattern

    def test_all_patterns_have_valid_severity(self):
        """All PII patterns use valid severity levels."""
        valid_severities = {"low", "medium", "high", "critical"}
        for pattern in PII_PATTERNS:
            assert pattern["severity"] in valid_severities, (
                f"{pattern['name']} has invalid severity: {pattern['severity']}"
            )

    def test_sensitive_file_patterns_have_required_keys(self):
        """All sensitive file patterns have pattern and description."""
        for pattern in SENSITIVE_FILE_PATTERNS:
            assert "pattern" in pattern
            assert "description" in pattern
