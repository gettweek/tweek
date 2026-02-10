#!/usr/bin/env python3
"""
Tests for Ed25519 pattern file signing and verification.

Verifies that:
- Keypair generation produces valid Ed25519 keys
- Signing produces verifiable signatures
- Tampered files are detected
- Missing signatures are handled gracefully
- Key rotation (multiple trusted keys) works
- CLI commands work end-to-end
"""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from tweek.security.pattern_signer import (
    CryptoUnavailableError,
    SignatureVerificationError,
    compute_key_id,
    generate_keypair,
    read_signature,
    sign_file,
    verify_file,
    verify_patterns_file,
    write_signature,
)


pytestmark = pytest.mark.security


# --- Fixtures ---


@pytest.fixture
def keypair():
    """Generate a fresh Ed25519 keypair."""
    return generate_keypair()


@pytest.fixture
def sample_file(tmp_path):
    """Create a sample patterns file."""
    p = tmp_path / "patterns.yaml"
    p.write_text(
        "version: 1\n"
        "pattern_count: 1\n"
        "patterns:\n"
        "  - id: 1\n"
        "    name: test_pattern\n"
        "    description: test\n"
        "    regex: 'test'\n"
        "    severity: low\n"
        "    confidence: heuristic\n"
    )
    return p


@pytest.fixture
def signed_file(sample_file, keypair):
    """Create a sample file with a valid signature."""
    private_pem, public_pem = keypair
    sig = sign_file(sample_file, private_pem)
    sig_path = sample_file.with_suffix(".yaml.sig")
    write_signature(sig_path, sig)
    return sample_file, public_pem, sig


# --- Keypair tests ---


class TestKeypairGeneration:
    def test_generates_pem_format(self, keypair):
        private_pem, public_pem = keypair
        assert "BEGIN PRIVATE KEY" in private_pem
        assert "END PRIVATE KEY" in private_pem
        assert "BEGIN PUBLIC KEY" in public_pem
        assert "END PUBLIC KEY" in public_pem

    def test_different_each_time(self):
        k1 = generate_keypair()
        k2 = generate_keypair()
        assert k1[0] != k2[0]  # Different private keys
        assert k1[1] != k2[1]  # Different public keys

    def test_key_id_deterministic(self, keypair):
        _, public_pem = keypair
        id1 = compute_key_id(public_pem)
        id2 = compute_key_id(public_pem)
        assert id1 == id2
        assert len(id1) == 16  # 16 hex chars

    def test_different_keys_different_ids(self):
        _, pub1 = generate_keypair()
        _, pub2 = generate_keypair()
        assert compute_key_id(pub1) != compute_key_id(pub2)


# --- Signing tests ---


class TestSignFile:
    def test_produces_signature(self, sample_file, keypair):
        private_pem, _ = keypair
        sig = sign_file(sample_file, private_pem)
        assert "signature" in sig
        assert "key_id" in sig
        assert "timestamp" in sig
        assert "sha256" in sig
        assert sig["algorithm"] == "Ed25519"

    def test_signature_is_base64(self, sample_file, keypair):
        import base64
        private_pem, _ = keypair
        sig = sign_file(sample_file, private_pem)
        # Should decode without error
        decoded = base64.b64decode(sig["signature"])
        assert len(decoded) == 64  # Ed25519 signature is 64 bytes

    def test_key_id_matches_public_key(self, sample_file, keypair):
        private_pem, public_pem = keypair
        sig = sign_file(sample_file, private_pem)
        assert sig["key_id"] == compute_key_id(public_pem)

    def test_sha256_correct(self, sample_file, keypair):
        import hashlib
        private_pem, _ = keypair
        sig = sign_file(sample_file, private_pem)
        expected = hashlib.sha256(sample_file.read_bytes()).hexdigest()
        assert sig["sha256"] == expected


# --- Signature file I/O ---


class TestSignatureIO:
    def test_write_and_read_roundtrip(self, tmp_path):
        sig_data = {"signature": "abc", "key_id": "123"}
        sig_path = tmp_path / "test.sig"
        write_signature(sig_path, sig_data)
        loaded = read_signature(sig_path)
        assert loaded == sig_data

    def test_read_missing_returns_none(self, tmp_path):
        assert read_signature(tmp_path / "nonexistent.sig") is None

    def test_read_invalid_json_returns_none(self, tmp_path):
        bad = tmp_path / "bad.sig"
        bad.write_text("not json {{")
        assert read_signature(bad) is None


# --- Verification tests ---


class TestVerifyFile:
    def test_valid_signature_passes(self, signed_file):
        file_path, public_pem, sig = signed_file
        assert verify_file(file_path, sig, [public_pem]) is True

    def test_tampered_content_fails(self, signed_file):
        file_path, public_pem, sig = signed_file
        # Tamper with file
        file_path.write_text(file_path.read_text() + "\n# tampered\n")
        with pytest.raises(SignatureVerificationError, match="SHA-256 mismatch"):
            verify_file(file_path, sig, [public_pem])

    def test_wrong_key_fails(self, signed_file):
        file_path, _, sig = signed_file
        # Generate a different key
        _, other_pub = generate_keypair()
        with pytest.raises(SignatureVerificationError, match="does not match"):
            verify_file(file_path, sig, [other_pub])

    def test_missing_file_fails(self, tmp_path, keypair):
        _, public_pem = keypair
        sig = {"signature": "abc", "key_id": "123"}
        with pytest.raises(SignatureVerificationError, match="File not found"):
            verify_file(tmp_path / "gone.yaml", sig, [public_pem])

    def test_empty_signature_fails(self, sample_file, keypair):
        _, public_pem = keypair
        with pytest.raises(SignatureVerificationError, match="No signature"):
            verify_file(sample_file, {}, [public_pem])

    def test_invalid_base64_fails(self, sample_file, keypair):
        _, public_pem = keypair
        sig = {"signature": "!!!not-base64!!!", "key_id": "abc"}
        with pytest.raises(SignatureVerificationError, match="Invalid base64"):
            verify_file(sample_file, sig, [public_pem])


class TestKeyRotation:
    """Test that multiple trusted keys are supported."""

    def test_old_key_still_verifies(self):
        """Patterns signed with old key still verify after rotation."""
        old_priv, old_pub = generate_keypair()
        new_priv, new_pub = generate_keypair()

        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("test content")
            f.flush()
            path = Path(f.name)

        try:
            sig = sign_file(path, old_priv)
            # Both old and new keys in trusted list
            assert verify_file(path, sig, [new_pub, old_pub]) is True
        finally:
            path.unlink()

    def test_new_key_verifies(self):
        """Patterns signed with new key verify."""
        old_priv, old_pub = generate_keypair()
        new_priv, new_pub = generate_keypair()

        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("test content")
            f.flush()
            path = Path(f.name)

        try:
            sig = sign_file(path, new_priv)
            assert verify_file(path, sig, [old_pub, new_pub]) is True
        finally:
            path.unlink()


# --- High-level verify_patterns_file ---


class TestVerifyPatternsFile:
    def test_valid_signature(self, signed_file):
        file_path, public_pem, _ = signed_file
        result = verify_patterns_file(file_path, trusted_keys=[public_pem])
        assert result["verified"] is True
        assert result["reason"] == "valid"
        assert result["sig_found"] is True

    def test_no_sig_file(self, sample_file):
        result = verify_patterns_file(sample_file, trusted_keys=[])
        assert result["verified"] is False
        assert result["reason"] == "no_signature_file"
        assert result["sig_found"] is False

    def test_tampered_file(self, signed_file):
        file_path, public_pem, _ = signed_file
        file_path.write_text(file_path.read_text() + "# tampered")
        result = verify_patterns_file(file_path, trusted_keys=[public_pem])
        assert result["verified"] is False
        assert result["sig_found"] is True

    def test_invalid_sig_json(self, sample_file):
        sig_path = sample_file.with_suffix(".yaml.sig")
        sig_path.write_text("not json")
        result = verify_patterns_file(sample_file, trusted_keys=[])
        assert result["verified"] is False
        assert result["reason"] == "invalid_signature_file"

    def test_crypto_unavailable(self, signed_file):
        file_path, public_pem, _ = signed_file
        with patch("tweek.security.pattern_signer._HAS_CRYPTO", False):
            result = verify_patterns_file(file_path, trusted_keys=[public_pem])
            assert result["verified"] is False
            assert result["reason"] == "cryptography_unavailable"
            assert result["sig_found"] is True


# --- Bundled patterns verification ---


class TestBundledPatterns:
    """Test that the actual bundled patterns.yaml has a valid signature."""

    def test_bundled_sig_exists(self):
        sig_path = (
            Path(__file__).parent.parent / "tweek" / "config" / "patterns.yaml.sig"
        )
        assert sig_path.exists(), "Bundled patterns.yaml.sig is missing"

    def test_bundled_sig_valid_json(self):
        sig_path = (
            Path(__file__).parent.parent / "tweek" / "config" / "patterns.yaml.sig"
        )
        sig = read_signature(sig_path)
        assert sig is not None
        assert "signature" in sig
        assert "key_id" in sig

    def test_bundled_patterns_verify(self):
        patterns_path = (
            Path(__file__).parent.parent / "tweek" / "config" / "patterns.yaml"
        )
        result = verify_patterns_file(patterns_path)
        assert result["verified"] is True, f"Bundled patterns failed verification: {result['reason']}"


# --- CLI tests ---


class TestCLIVerify:
    def test_verify_bundled(self):
        from click.testing import CliRunner
        from tweek.cli_patterns import patterns_verify

        runner = CliRunner()
        result = runner.invoke(patterns_verify, [])
        assert result.exit_code == 0
        assert "verified" in result.output.lower()

    def test_verify_json(self):
        from click.testing import CliRunner
        from tweek.cli_patterns import patterns_verify

        runner = CliRunner()
        result = runner.invoke(patterns_verify, ["--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["verified"] is True

    def test_verify_missing_sig(self, tmp_path):
        from click.testing import CliRunner
        from tweek.cli_patterns import patterns_verify

        # Create a file with no .sig
        p = tmp_path / "test.yaml"
        p.write_text("version: 1\npatterns: []\n")

        runner = CliRunner()
        result = runner.invoke(patterns_verify, ["--path", str(p)])
        assert result.exit_code == 1
        assert "No signature" in result.output


class TestCLIKeygen:
    def test_keygen_creates_files(self, tmp_path):
        from click.testing import CliRunner
        from tweek.cli_patterns import patterns_keygen

        runner = CliRunner()
        prefix = str(tmp_path / "test_key")
        result = runner.invoke(patterns_keygen, ["--output", prefix])
        assert result.exit_code == 0

        priv_path = Path(f"{prefix}.pem")
        pub_path = Path(f"{prefix}.pub")
        assert priv_path.exists()
        assert pub_path.exists()
        assert "BEGIN PRIVATE KEY" in priv_path.read_text()
        assert "BEGIN PUBLIC KEY" in pub_path.read_text()


class TestCLISign:
    def test_sign_creates_sig(self, tmp_path):
        from click.testing import CliRunner
        from tweek.cli_patterns import patterns_sign

        # Generate a key
        priv, pub = generate_keypair()
        key_path = tmp_path / "key.pem"
        key_path.write_text(priv)

        # Create a patterns file
        p = tmp_path / "patterns.yaml"
        p.write_text("version: 1\npatterns: []\n")

        runner = CliRunner()
        result = runner.invoke(patterns_sign, [
            "--key", str(key_path),
            "--path", str(p),
        ])
        assert result.exit_code == 0
        assert "Signed" in result.output

        sig_path = p.with_suffix(".yaml.sig")
        assert sig_path.exists()

    def test_sign_then_verify(self, tmp_path):
        from click.testing import CliRunner
        from tweek.cli_patterns import patterns_sign, patterns_verify

        # Generate keypair and embed the public key
        priv, pub = generate_keypair()
        key_path = tmp_path / "key.pem"
        key_path.write_text(priv)

        p = tmp_path / "patterns.yaml"
        p.write_text("version: 1\npatterns: []\n")

        runner = CliRunner()

        # Sign
        result = runner.invoke(patterns_sign, [
            "--key", str(key_path),
            "--path", str(p),
        ])
        assert result.exit_code == 0

        # Verify with the matching public key
        result = verify_patterns_file(p, trusted_keys=[pub])
        assert result["verified"] is True


# --- Pattern matcher integration ---


class TestPatternMatcherIntegration:
    """Test that the pattern matcher verifies signatures at load time."""

    def test_loads_patterns_with_valid_sig(self):
        """Pattern matcher should load bundled patterns successfully."""
        from tweek.plugins.screening.pattern_matcher import PatternMatcherPlugin

        plugin = PatternMatcherPlugin()
        count = plugin.get_pattern_count()
        assert count > 0

    def test_signature_status_available(self):
        """After loading, signature status should be accessible."""
        from tweek.plugins.screening.pattern_matcher import PatternMatcherPlugin

        plugin = PatternMatcherPlugin()
        plugin.get_pattern_count()  # Force load
        assert hasattr(plugin, "_signature_status")
        assert plugin._signature_status["verified"] is True
