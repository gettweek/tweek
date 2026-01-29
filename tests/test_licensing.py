#!/usr/bin/env python3
"""
Tests for Tweek licensing module.

Tests coverage of:
- License key generation and validation
- Tier features and permissions
- License activation/deactivation
- Feature gating decorators
"""

import base64
import hashlib
import hmac
import json
import pytest
import time
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from tweek.licensing import (
    License, LicenseInfo, Tier, LicenseError,
    get_license, require_tier, require_pro, require_feature,
    generate_license_key, TIER_FEATURES, LICENSE_SECRET
)


class TestTier:
    """Tests for Tier enum."""

    def test_tier_values(self):
        """Test tier enum values."""
        assert Tier.FREE.value == "free"
        assert Tier.PRO.value == "pro"

    def test_tier_from_string(self):
        """Test creating tier from string."""
        assert Tier("free") == Tier.FREE
        assert Tier("pro") == Tier.PRO


class TestLicenseInfo:
    """Tests for LicenseInfo dataclass."""

    def test_is_expired_none(self):
        """Test license with no expiration never expires."""
        info = LicenseInfo(
            tier=Tier.PRO,
            email="test@example.com",
            issued_at=int(time.time()),
            expires_at=None,
            features=[]
        )
        assert info.is_expired is False
        assert info.is_valid is True

    def test_is_expired_future(self):
        """Test license with future expiration is valid."""
        info = LicenseInfo(
            tier=Tier.PRO,
            email="test@example.com",
            issued_at=int(time.time()),
            expires_at=int(time.time()) + 86400,  # Tomorrow
            features=[]
        )
        assert info.is_expired is False
        assert info.is_valid is True

    def test_is_expired_past(self):
        """Test license with past expiration is expired."""
        info = LicenseInfo(
            tier=Tier.PRO,
            email="test@example.com",
            issued_at=int(time.time()) - 172800,  # 2 days ago
            expires_at=int(time.time()) - 86400,  # Yesterday
            features=[]
        )
        assert info.is_expired is True
        assert info.is_valid is False


class TestLicenseKeyGeneration:
    """Tests for license key generation."""

    def test_generate_basic_key(self):
        """Test generating a basic license key."""
        key = generate_license_key(
            tier=Tier.PRO,
            email="test@example.com"
        )

        # Key should have format: base64.signature
        assert "." in key
        payload_b64, signature = key.rsplit(".", 1)

        # Should be valid base64
        payload = json.loads(base64.b64decode(payload_b64))
        assert payload["tier"] == "pro"
        assert payload["email"] == "test@example.com"
        assert "issued_at" in payload

    def test_generate_key_with_expiration(self):
        """Test generating a key with expiration."""
        expires = int(time.time()) + 86400 * 30  # 30 days
        key = generate_license_key(
            tier=Tier.PRO,
            email="test@example.com",
            expires_at=expires
        )

        payload_b64, _ = key.rsplit(".", 1)
        payload = json.loads(base64.b64decode(payload_b64))
        assert payload["expires_at"] == expires

    def test_generate_key_with_features(self):
        """Test generating a key with additional features."""
        key = generate_license_key(
            tier=Tier.FREE,
            email="test@example.com",
            features=["beta_feature", "early_access"]
        )

        payload_b64, _ = key.rsplit(".", 1)
        payload = json.loads(base64.b64decode(payload_b64))
        assert "beta_feature" in payload["features"]
        assert "early_access" in payload["features"]

    def test_signature_verification(self):
        """Test that generated keys have valid signatures."""
        key = generate_license_key(
            tier=Tier.PRO,
            email="test@example.com"
        )

        payload_b64, signature = key.rsplit(".", 1)

        # Verify signature matches
        expected_sig = hmac.new(
            LICENSE_SECRET.encode(),
            payload_b64.encode(),
            hashlib.sha256
        ).hexdigest()[:32]

        assert signature == expected_sig


class TestLicenseValidation:
    """Tests for license validation."""

    @pytest.fixture
    def license_manager(self, tmp_path):
        """Create a License instance with temp file."""
        with patch('tweek.licensing.LICENSE_FILE', tmp_path / "license.key"):
            # Reset singleton
            License._instance = None
            yield License.get_instance()
            License._instance = None

    def test_validate_valid_key(self, license_manager):
        """Test validating a valid key."""
        key = generate_license_key(Tier.PRO, "test@example.com")
        info = license_manager._validate_license_key(key)

        assert info is not None
        assert info.tier == Tier.PRO
        assert info.email == "test@example.com"

    def test_validate_invalid_signature(self, license_manager):
        """Test rejecting key with invalid signature."""
        key = generate_license_key(Tier.PRO, "test@example.com")
        # Tamper with signature
        payload_b64, _ = key.rsplit(".", 1)
        tampered_key = f"{payload_b64}.invalid_signature_here"

        info = license_manager._validate_license_key(tampered_key)
        assert info is None

    def test_validate_tampered_payload(self, license_manager):
        """Test rejecting key with tampered payload."""
        # Create a key, then modify the payload
        original_key = generate_license_key(Tier.FREE, "test@example.com")
        _, signature = original_key.rsplit(".", 1)

        # Create different payload
        tampered_payload = base64.b64encode(json.dumps({
            "tier": "pro",  # Changed from free to pro
            "email": "test@example.com",
            "issued_at": int(time.time())
        }).encode()).decode()

        tampered_key = f"{tampered_payload}.{signature}"

        info = license_manager._validate_license_key(tampered_key)
        assert info is None  # Should reject due to signature mismatch

    def test_validate_malformed_key(self, license_manager):
        """Test rejecting malformed keys."""
        assert license_manager._validate_license_key("not_a_valid_key") is None
        assert license_manager._validate_license_key("") is None
        assert license_manager._validate_license_key("abc.def.ghi") is None


class TestLicenseActivation:
    """Tests for license activation/deactivation."""

    @pytest.fixture
    def license_manager(self, tmp_path):
        """Create a License instance with temp file."""
        license_file = tmp_path / ".tweek" / "license.key"
        with patch('tweek.licensing.LICENSE_FILE', license_file):
            License._instance = None
            yield License.get_instance()
            License._instance = None

    def test_activate_valid_key(self, license_manager, tmp_path):
        """Test activating a valid license key."""
        key = generate_license_key(Tier.PRO, "test@example.com")

        success, message = license_manager.activate(key)

        assert success is True
        assert "PRO" in message
        assert license_manager.tier == Tier.PRO
        assert license_manager.is_pro is True

    def test_activate_invalid_key(self, license_manager):
        """Test activating an invalid key fails."""
        success, message = license_manager.activate("invalid_key")

        assert success is False
        assert "Invalid" in message

    def test_activate_expired_key(self, license_manager):
        """Test activating an expired key fails."""
        key = generate_license_key(
            Tier.PRO,
            "test@example.com",
            expires_at=int(time.time()) - 86400  # Expired yesterday
        )

        success, message = license_manager.activate(key)

        assert success is False
        assert "expired" in message.lower()

    def test_deactivate(self, license_manager, tmp_path):
        """Test deactivating a license."""
        # First activate
        key = generate_license_key(Tier.PRO, "test@example.com")
        license_manager.activate(key)
        assert license_manager.tier == Tier.PRO

        # Then deactivate
        success, message = license_manager.deactivate()

        assert success is True
        assert license_manager.tier == Tier.FREE


class TestTierFeatures:
    """Tests for tier feature checking."""

    @pytest.fixture
    def free_license(self, tmp_path):
        """Create a free tier license."""
        with patch('tweek.licensing.LICENSE_FILE', tmp_path / "license.key"):
            License._instance = None
            yield License.get_instance()
            License._instance = None

    @pytest.fixture
    def pro_license(self, tmp_path):
        """Create a pro tier license."""
        license_file = tmp_path / ".tweek" / "license.key"
        with patch('tweek.licensing.LICENSE_FILE', license_file):
            License._instance = None
            lic = License.get_instance()
            key = generate_license_key(Tier.PRO, "test@example.com")
            lic.activate(key)
            yield lic
            License._instance = None

    def test_free_tier_features(self, free_license):
        """Test free tier has correct features."""
        assert free_license.has_feature("pattern_matching")
        assert free_license.has_feature("basic_logging")
        assert free_license.has_feature("vault_storage")
        assert free_license.has_feature("cli_commands")

    def test_free_tier_missing_pro_features(self, free_license):
        """Test free tier doesn't have pro features."""
        assert not free_license.has_feature("llm_review")
        assert not free_license.has_feature("session_analysis")
        assert not free_license.has_feature("rate_limiting")

    def test_pro_tier_has_all_features(self, pro_license):
        """Test pro tier has all features."""
        # Free features
        assert pro_license.has_feature("pattern_matching")
        assert pro_license.has_feature("basic_logging")

        # Pro features
        assert pro_license.has_feature("llm_review")
        assert pro_license.has_feature("session_analysis")
        assert pro_license.has_feature("rate_limiting")

    def test_get_available_features(self, pro_license):
        """Test getting all available features."""
        features = pro_license.get_available_features()

        # Should include both free and pro features
        assert "pattern_matching" in features
        assert "llm_review" in features


class TestFeatureGatingDecorators:
    """Tests for feature gating decorators."""

    def test_require_pro_allows_pro(self, tmp_path):
        """Test require_pro decorator allows pro users."""
        license_file = tmp_path / ".tweek" / "license.key"
        with patch('tweek.licensing.LICENSE_FILE', license_file):
            License._instance = None
            lic = License.get_instance()
            key = generate_license_key(Tier.PRO, "test@example.com")
            lic.activate(key)

            @require_pro
            def pro_function():
                return "success"

            assert pro_function() == "success"
            License._instance = None

    def test_require_pro_blocks_free(self, tmp_path):
        """Test require_pro decorator blocks free users."""
        with patch('tweek.licensing.LICENSE_FILE', tmp_path / "license.key"):
            License._instance = None

            @require_pro
            def pro_function():
                return "success"

            with pytest.raises(LicenseError) as exc_info:
                pro_function()

            assert "PRO" in str(exc_info.value)
            License._instance = None

    def test_require_feature_allows_when_present(self, tmp_path):
        """Test require_feature allows when feature is available."""
        with patch('tweek.licensing.LICENSE_FILE', tmp_path / "license.key"):
            License._instance = None

            @require_feature("pattern_matching")
            def pattern_function():
                return "patterns work"

            # Free tier has pattern_matching
            assert pattern_function() == "patterns work"
            License._instance = None

    def test_require_feature_blocks_when_missing(self, tmp_path):
        """Test require_feature blocks when feature is missing."""
        with patch('tweek.licensing.LICENSE_FILE', tmp_path / "license.key"):
            License._instance = None

            @require_feature("llm_review")
            def llm_function():
                return "llm works"

            # Free tier doesn't have llm_review
            with pytest.raises(LicenseError) as exc_info:
                llm_function()

            assert "llm_review" in str(exc_info.value)
            License._instance = None


class TestLicenseSingleton:
    """Tests for license singleton behavior."""

    def test_get_instance_returns_same_object(self, tmp_path):
        """Test that get_instance returns the same object."""
        with patch('tweek.licensing.LICENSE_FILE', tmp_path / "license.key"):
            License._instance = None

            lic1 = License.get_instance()
            lic2 = License.get_instance()

            assert lic1 is lic2
            License._instance = None

    def test_get_license_returns_instance(self, tmp_path):
        """Test that get_license function returns instance."""
        with patch('tweek.licensing.LICENSE_FILE', tmp_path / "license.key"):
            License._instance = None

            lic = get_license()

            assert isinstance(lic, License)
            License._instance = None
