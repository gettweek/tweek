#!/usr/bin/env python3
"""
Tweek CLI — patterns command group

Pattern file signing and verification for supply chain defense.
"""
from __future__ import annotations

import sys
from pathlib import Path

import click

from tweek.cli_helpers import console


@click.group()
def patterns():
    """Pattern file signing and verification.

    Cryptographic Ed25519 signatures protect bundled security patterns
    from post-install tampering.
    """
    pass


@patterns.command("verify")
@click.option("--path", "-p", type=click.Path(exists=True),
              help="Path to patterns.yaml (default: bundled)")
@click.option("--json", "json_out", is_flag=True, help="Output as JSON")
def patterns_verify(path: str, json_out: bool):
    """Verify the cryptographic signature of pattern files.

    Checks that patterns.yaml has not been modified since it was
    signed by a trusted Tweek maintainer key.

    Exit code 0 if verified, 1 if failed.
    """
    from tweek.security.pattern_signer import verify_patterns_file

    if path:
        patterns_path = Path(path)
    else:
        patterns_path = Path(__file__).parent / "config" / "patterns.yaml"

    result = verify_patterns_file(patterns_path)

    if json_out:
        import json as json_mod
        click.echo(json_mod.dumps(result, indent=2))
        if not result["verified"]:
            sys.exit(1)
        return

    if result["verified"]:
        console.print(
            f"[green]\u2713[/green] Pattern signature verified "
            f"(key: {result['key_id']})"
        )
        return

    if not result["sig_found"]:
        console.print(
            "[yellow]No signature file found for patterns.yaml[/yellow]"
        )
        console.print(
            "[dim]Bundled patterns should have a .sig file. "
            "Re-install tweek to restore it.[/dim]"
        )
        sys.exit(1)

    console.print(
        f"[red]\u2717 Pattern signature INVALID: {result['reason']}[/red]"
    )
    console.print(
        "[dim]This may indicate tampering with the pattern file. "
        "Re-install tweek to restore authentic patterns.[/dim]"
    )
    sys.exit(1)


@patterns.command("keygen")
@click.option("--output", "-o", default="tweek_signing_key",
              help="Output file prefix (creates .pem and .pub)")
def patterns_keygen(output: str):
    """Generate a new Ed25519 signing keypair.

    Developer tool for key rotation. The public key must be added
    to tweek/config/signing_keys.py.
    """
    from tweek.security.pattern_signer import (
        CryptoUnavailableError,
        compute_key_id,
        generate_keypair,
    )

    try:
        private_pem, public_pem = generate_keypair()
    except CryptoUnavailableError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    key_id = compute_key_id(public_pem)

    # Write private key
    priv_path = Path(f"{output}.pem")
    priv_path.write_text(private_pem)
    import os
    os.chmod(str(priv_path), 0o600)

    # Write public key
    pub_path = Path(f"{output}.pub")
    pub_path.write_text(public_pem)

    console.print(f"[green]\u2713[/green] Keypair generated")
    console.print(f"  Private key: {priv_path} (keep secret!)")
    console.print(f"  Public key:  {pub_path}")
    console.print(f"  Key ID:      {key_id}")
    console.print()
    console.print(
        "[dim]Add the public key to tweek/config/signing_keys.py "
        "for signature verification.[/dim]"
    )


@patterns.command("sign")
@click.option("--key", "-k", required=True,
              type=click.Path(exists=True),
              help="Path to Ed25519 private key (.pem)")
@click.option("--path", "-p",
              type=click.Path(exists=True),
              help="Path to patterns.yaml (default: bundled)")
def patterns_sign(key: str, path: str):
    """Sign a patterns.yaml file with an Ed25519 private key.

    Developer tool for creating .sig files. The private key
    should be kept securely and never committed to the repository.
    """
    from tweek.security.pattern_signer import (
        CryptoUnavailableError,
        sign_file,
        write_signature,
    )

    if path:
        patterns_path = Path(path)
    else:
        patterns_path = Path(__file__).parent / "config" / "patterns.yaml"

    try:
        private_pem = Path(key).read_text()
        sig_data = sign_file(patterns_path, private_pem)
    except CryptoUnavailableError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Signing failed: {e}[/red]")
        sys.exit(1)

    sig_path = patterns_path.with_suffix(patterns_path.suffix + ".sig")
    write_signature(sig_path, sig_data)

    console.print(f"[green]\u2713[/green] Signed: {patterns_path}")
    console.print(f"  Signature:  {sig_path}")
    console.print(f"  Key ID:     {sig_data['key_id']}")
    console.print(f"  SHA-256:    {sig_data['sha256'][:16]}...")
