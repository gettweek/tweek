#!/usr/bin/env python3
"""
Tweek Trusted Public Keys

Ed25519 public keys trusted for verifying pattern file signatures.
These keys are embedded in the package source and used to verify
that patterns.yaml has not been tampered with after installation.

Key rotation: Add new keys to the list when rotating. Old keys
remain to verify patterns signed before rotation.
"""

# List of trusted Ed25519 public keys (PEM format).
# Patterns signed by ANY of these keys are considered authentic.
TRUSTED_PUBLIC_KEYS = [
    # Key 1 — initial signing key (2026-02-10)
    # Key ID: e20bc77a2535d3d8
    """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAw20tusp+WNm6ioSL9uDp38NRVoUJxbOmukBQWY+sVb4=
-----END PUBLIC KEY-----""",
    # Key 2 — post-CTAP enrichment re-signing (2026-02-10)
    # Key ID: e810117671eeb618
    """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAM2cFlaXbl1h8j+xlvJ/hcIDVKXjODFobgWbT42viFx0=
-----END PUBLIC KEY-----""",
    # Key 3 — post FP-reduction pattern refinement (2026-02-13)
    # Key ID: db9693bdc959724d
    """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAiG1NTtQElD8OkpcI++ky9yrNL09SAHg+NZSHjPK29ZU=
-----END PUBLIC KEY-----""",
]
