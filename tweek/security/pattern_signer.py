#!/usr/bin/env python3
"""
Tweek Pattern Signature Verification

Ed25519-based cryptographic signing for pattern files (patterns.yaml).
Detects post-install tampering of bundled security patterns.

- Sign: Developer signs patterns.yaml with private key → patterns.yaml.sig
- Verify: At load time, verify .sig against embedded public keys
- Keygen: Generate new Ed25519 keypair for key rotation

Requires `cryptography` library (optional dependency).
Gracefully degrades when unavailable.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Lazy import — cryptography is optional
_HAS_CRYPTO = None


def _check_crypto() -> bool:
    """Check if cryptography library is available (cached)."""
    global _HAS_CRYPTO
    if _HAS_CRYPTO is None:
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
            _HAS_CRYPTO = True
        except ImportError:
            _HAS_CRYPTO = False
    return _HAS_CRYPTO


class CryptoUnavailableError(RuntimeError):
    """Raised when cryptography library is not installed."""

    def __init__(self):
        super().__init__(
            "cryptography library required. Install: pip install cryptography"
        )


class SignatureVerificationError(Exception):
    """Raised when signature verification fails."""

    def __init__(self, reason: str, path: str = ""):
        self.reason = reason
        self.path = path
        super().__init__(f"Signature verification failed for {path}: {reason}")


# --- Key ID ---


def compute_key_id(public_key_pem: str) -> str:
    """Compute a short key ID from a public key PEM (first 16 hex chars of SHA-256)."""
    return hashlib.sha256(public_key_pem.strip().encode()).hexdigest()[:16]


# --- Keypair Generation ---


def generate_keypair() -> Tuple[str, str]:
    """Generate a new Ed25519 keypair.

    Returns:
        (private_key_pem, public_key_pem) tuple
    """
    if not _check_crypto():
        raise CryptoUnavailableError()

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


# --- Signing ---


def sign_file(file_path: Path, private_key_pem: str) -> Dict[str, Any]:
    """Sign a file with an Ed25519 private key.

    Args:
        file_path: Path to the file to sign
        private_key_pem: PEM-encoded Ed25519 private key

    Returns:
        Signature dict with: signature, key_id, timestamp, sha256
    """
    if not _check_crypto():
        raise CryptoUnavailableError()

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Key is not an Ed25519 private key")

    # Read file content
    content = file_path.read_bytes()

    # Compute SHA-256 for reference
    file_sha256 = hashlib.sha256(content).hexdigest()

    # Sign the raw file content
    signature_bytes = private_key.sign(content)
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

    # Derive public key and compute key ID
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    key_id = compute_key_id(public_pem)

    return {
        "signature": signature_b64,
        "key_id": key_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sha256": file_sha256,
        "algorithm": "Ed25519",
    }


def write_signature(sig_path: Path, sig_data: Dict[str, Any]) -> None:
    """Write a signature dict to a .sig JSON file."""
    sig_path.write_text(json.dumps(sig_data, indent=2) + "\n")


def read_signature(sig_path: Path) -> Optional[Dict[str, Any]]:
    """Read a .sig JSON file. Returns None if missing or invalid."""
    if not sig_path.exists():
        return None
    try:
        return json.loads(sig_path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


# --- Verification ---


def verify_file(
    file_path: Path,
    sig_data: Dict[str, Any],
    trusted_keys: List[str],
) -> bool:
    """Verify a file's signature against a list of trusted public keys.

    Args:
        file_path: Path to the file to verify
        sig_data: Signature dict (from .sig file)
        trusted_keys: List of PEM-encoded Ed25519 public keys

    Returns:
        True if signature is valid and signed by a trusted key

    Raises:
        SignatureVerificationError: If verification fails with details
        CryptoUnavailableError: If cryptography library not installed
    """
    if not _check_crypto():
        raise CryptoUnavailableError()

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    # Check file exists first
    if not file_path.exists():
        raise SignatureVerificationError("File not found", str(file_path))

    # Extract signature
    sig_b64 = sig_data.get("signature")
    sig_key_id = sig_data.get("key_id")

    if not sig_b64:
        raise SignatureVerificationError("No signature in .sig file", str(file_path))

    try:
        signature_bytes = base64.b64decode(sig_b64)
    except Exception:
        raise SignatureVerificationError("Invalid base64 signature", str(file_path))
    content = file_path.read_bytes()

    # Optional SHA-256 pre-check
    if sig_data.get("sha256"):
        actual_sha = hashlib.sha256(content).hexdigest()
        if actual_sha != sig_data["sha256"]:
            raise SignatureVerificationError(
                f"SHA-256 mismatch (file modified since signing)",
                str(file_path),
            )

    # Try each trusted key
    for key_pem in trusted_keys:
        key_id = compute_key_id(key_pem)

        # If sig has a key_id, only try matching keys (optimization)
        if sig_key_id and key_id != sig_key_id:
            continue

        try:
            public_key = serialization.load_pem_public_key(
                key_pem.strip().encode("utf-8")
            )
            if not isinstance(public_key, Ed25519PublicKey):
                continue

            public_key.verify(signature_bytes, content)
            return True  # Signature valid
        except InvalidSignature:
            continue
        except Exception:
            continue

    raise SignatureVerificationError(
        "Signature does not match any trusted key",
        str(file_path),
    )


def verify_patterns_file(
    patterns_path: Path,
    trusted_keys: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Verify a patterns.yaml file against its .sig file.

    High-level convenience function used by the pattern loader.

    Args:
        patterns_path: Path to patterns.yaml
        trusted_keys: List of trusted public keys (defaults to embedded keys)

    Returns:
        Dict with: verified (bool), reason (str), key_id (str|None),
                    sig_found (bool)
    """
    if trusted_keys is None:
        from tweek.config.signing_keys import TRUSTED_PUBLIC_KEYS
        trusted_keys = TRUSTED_PUBLIC_KEYS

    sig_path = patterns_path.with_suffix(patterns_path.suffix + ".sig")

    # No signature file
    if not sig_path.exists():
        return {
            "verified": False,
            "reason": "no_signature_file",
            "key_id": None,
            "sig_found": False,
        }

    sig_data = read_signature(sig_path)
    if sig_data is None:
        return {
            "verified": False,
            "reason": "invalid_signature_file",
            "key_id": None,
            "sig_found": True,
        }

    if not _check_crypto():
        return {
            "verified": False,
            "reason": "cryptography_unavailable",
            "key_id": sig_data.get("key_id"),
            "sig_found": True,
        }

    try:
        verify_file(patterns_path, sig_data, trusted_keys)
        return {
            "verified": True,
            "reason": "valid",
            "key_id": sig_data.get("key_id"),
            "sig_found": True,
        }
    except SignatureVerificationError as e:
        return {
            "verified": False,
            "reason": str(e.reason),
            "key_id": sig_data.get("key_id"),
            "sig_found": True,
        }
