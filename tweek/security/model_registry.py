#!/usr/bin/env python3
"""
Tweek Local Model Registry

Manages the catalog of local security models, downloads from HuggingFace,
and handles model directory lifecycle.

Models are stored in ~/.tweek/models/<model-name>/ with:
- model.onnx       — ONNX model file
- tokenizer.json   — Tokenizer configuration
- model_meta.yaml  — Metadata (catalog info + download timestamps)
"""

import hashlib
import shutil
import urllib.request
import urllib.error
import os
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

import yaml


@dataclass
class ModelDefinition:
    """Definition of a model in the catalog."""

    name: str
    display_name: str
    hf_repo: str
    description: str
    num_labels: int
    label_map: Dict[int, str]
    risk_map: Dict[str, str]  # label -> risk level (safe/suspicious/dangerous)
    max_length: int = 512
    license: str = "unknown"
    size_mb: float = 0.0  # approximate download size
    files: List[str] = field(default_factory=list)
    file_hashes: Dict[str, str] = field(default_factory=dict)  # filename -> sha256
    hf_subfolder: str = ""  # subfolder in the HF repo (e.g., "onnx")
    hf_revision: str = "main"  # git revision (commit SHA for pinned downloads)
    requires_auth: bool = False
    default: bool = False

    # Confidence thresholds for escalation
    escalate_min_confidence: float = 0.1
    escalate_max_confidence: float = 0.9


# ============================================================================
# MODEL CATALOG
# ============================================================================

MODEL_CATALOG: Dict[str, ModelDefinition] = {
    "deberta-v3-injection": ModelDefinition(
        name="deberta-v3-injection",
        display_name="ProtectAI DeBERTa v3 Prompt Injection v2",
        hf_repo="protectai/deberta-v3-base-prompt-injection-v2",
        description=(
            "Binary prompt injection classifier based on DeBERTa-v3-base. "
            "Detects prompt injection attacks in English text. "
            "Apache 2.0 license, no authentication required."
        ),
        num_labels=2,
        label_map={0: "safe", 1: "injection"},
        risk_map={
            "safe": "safe",
            "injection": "dangerous",
        },
        max_length=512,
        license="Apache-2.0",
        size_mb=750.0,
        files=["model.onnx", "tokenizer.json"],
        file_hashes={
            "model.onnx": "f0ea7f239f765aedbde7c9e163a7cb38a79c5b8853d3f76db5152172047b228c",
            "tokenizer.json": "752fe5f0d5678ad563e1bd2ecc1ddf7a3ba7e2024d0ac1dba1a72975e26dff2f",
        },
        hf_subfolder="onnx",
        hf_revision="e6535ca4ce3ba852083e75ec585d7c8aeb4be4c5",
        requires_auth=False,
        default=True,
        escalate_min_confidence=0.1,
        escalate_max_confidence=0.9,
    ),
}

DEFAULT_MODEL = "deberta-v3-injection"


# ============================================================================
# DIRECTORY MANAGEMENT
# ============================================================================


def get_models_dir() -> Path:
    """Get the models directory (~/.tweek/models/)."""
    models_dir = Path.home() / ".tweek" / "models"
    return models_dir


def get_model_dir(name: str) -> Path:
    """Get the directory for a specific model."""
    return get_models_dir() / name


def get_default_model_name() -> str:
    """Get the configured default model name.

    Checks user config first, falls back to catalog default.
    """
    config_path = Path.home() / ".tweek" / "config.yaml"
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
            local_model_cfg = config.get("local_model", {})
            model = local_model_cfg.get("model", "auto")
            if model != "auto" and model in MODEL_CATALOG:
                return model
        except Exception:
            pass

    return DEFAULT_MODEL


def is_model_installed(name: str) -> bool:
    """Check if a model is installed with all required files."""
    if name not in MODEL_CATALOG:
        return False

    model_dir = get_model_dir(name)
    if not model_dir.exists():
        return False

    definition = MODEL_CATALOG[name]
    for filename in definition.files:
        if not (model_dir / filename).exists():
            return False

    return True


def list_installed_models() -> List[str]:
    """List all installed model names."""
    models_dir = get_models_dir()
    if not models_dir.exists():
        return []

    installed = []
    for name in MODEL_CATALOG:
        if is_model_installed(name):
            installed.append(name)

    return installed


def get_model_definition(name: str) -> Optional[ModelDefinition]:
    """Get the catalog definition for a model."""
    return MODEL_CATALOG.get(name)


# ============================================================================
# MODEL DOWNLOAD
# ============================================================================


class ModelDownloadError(Exception):
    """Error during model download."""

    pass


def _build_hf_url(repo: str, filename: str, subfolder: str = "", revision: str = "main") -> str:
    """Build a HuggingFace CDN download URL.

    When *revision* is a commit SHA, the URL points to an immutable
    snapshot — the same bytes every time, safe to verify with SHA-256.
    """
    if subfolder:
        return f"https://huggingface.co/{repo}/resolve/{revision}/{subfolder}/{filename}"
    return f"https://huggingface.co/{repo}/resolve/{revision}/{filename}"


def _get_hf_headers() -> Dict[str, str]:
    """Get HTTP headers for HuggingFace requests."""
    headers = {
        "User-Agent": "tweek/0.1.0",
    }

    # Support HF_TOKEN for gated models (like Prompt Guard)
    hf_token = os.environ.get("HF_TOKEN") or os.environ.get("HUGGING_FACE_HUB_TOKEN")
    if hf_token:
        headers["Authorization"] = f"Bearer {hf_token}"

    return headers


def download_model(
    name: str,
    progress_callback: Optional[Callable[[str, int, int], None]] = None,
    force: bool = False,
) -> Path:
    """Download a model from HuggingFace.

    Args:
        name: Model name from the catalog.
        progress_callback: Optional callback(filename, bytes_downloaded, total_bytes).
        force: If True, re-download even if already installed.

    Returns:
        Path to the model directory.

    Raises:
        ModelDownloadError: If the model is not in the catalog or download fails.
    """
    definition = MODEL_CATALOG.get(name)
    if definition is None:
        available = ", ".join(MODEL_CATALOG.keys())
        raise ModelDownloadError(
            f"Unknown model '{name}'. Available models: {available}"
        )

    model_dir = get_model_dir(name)

    if is_model_installed(name) and not force:
        return model_dir

    # Create directory
    model_dir.mkdir(parents=True, exist_ok=True)

    headers = _get_hf_headers()

    if definition.requires_auth and "Authorization" not in headers:
        raise ModelDownloadError(
            f"Model '{name}' requires HuggingFace authentication. "
            f"Set HF_TOKEN environment variable with a token that has "
            f"access to {definition.hf_repo}. "
            f"Get a token at https://huggingface.co/settings/tokens"
        )

    # Create SSL context
    ssl_context = ssl.create_default_context()

    # Download each file, pinned to a specific revision for reproducibility
    for filename in definition.files:
        url = _build_hf_url(
            definition.hf_repo, filename,
            definition.hf_subfolder, definition.hf_revision,
        )
        dest = model_dir / filename
        tmp_dest = model_dir / f".{filename}.tmp"

        try:
            request = urllib.request.Request(url, headers=headers)
            response = urllib.request.urlopen(request, context=ssl_context)

            total = int(response.headers.get("Content-Length", 0))
            downloaded = 0
            chunk_size = 1024 * 1024  # 1MB chunks

            with open(tmp_dest, "wb") as f:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback:
                        progress_callback(filename, downloaded, total)

            # Verify SHA-256 if the catalog provides an expected hash
            expected_hash = definition.file_hashes.get(filename)
            if expected_hash:
                actual_hash = hashlib.sha256(tmp_dest.read_bytes()).hexdigest()
                if actual_hash != expected_hash:
                    tmp_dest.unlink(missing_ok=True)
                    raise ModelDownloadError(
                        f"SHA-256 mismatch for {filename}: "
                        f"expected {expected_hash[:16]}..., "
                        f"got {actual_hash[:16]}... "
                        f"The file may be corrupted or tampered with. "
                        f"Try again with --force, or report this issue."
                    )

            # Atomic rename
            tmp_dest.rename(dest)

        except urllib.error.HTTPError as e:
            tmp_dest.unlink(missing_ok=True)
            if e.code == 401:
                raise ModelDownloadError(
                    f"Authentication failed for '{name}'. "
                    f"Check your HF_TOKEN has access to {definition.hf_repo}. "
                    f"You may need to accept the license at "
                    f"https://huggingface.co/{definition.hf_repo}"
                ) from e
            elif e.code == 404:
                raise ModelDownloadError(
                    f"File '{filename}' not found in {definition.hf_repo}. "
                    f"The model may have been moved or renamed."
                ) from e
            else:
                raise ModelDownloadError(
                    f"HTTP {e.code} downloading {filename}: {e.reason}"
                ) from e
        except urllib.error.URLError as e:
            tmp_dest.unlink(missing_ok=True)
            raise ModelDownloadError(
                f"Network error downloading {filename}: {e.reason}"
            ) from e
        except ModelDownloadError:
            raise  # Re-raise SHA mismatch without wrapping
        except Exception as e:
            tmp_dest.unlink(missing_ok=True)
            raise ModelDownloadError(
                f"Failed to download {filename}: {e}"
            ) from e

    # Write metadata
    meta = {
        "name": definition.name,
        "display_name": definition.display_name,
        "hf_repo": definition.hf_repo,
        "num_labels": definition.num_labels,
        "label_map": definition.label_map,
        "risk_map": definition.risk_map,
        "max_length": definition.max_length,
        "license": definition.license,
        "downloaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": definition.files,
    }

    with open(model_dir / "model_meta.yaml", "w") as f:
        yaml.dump(meta, f, default_flow_style=False, sort_keys=False)

    return model_dir


def remove_model(name: str) -> bool:
    """Remove a downloaded model.

    Args:
        name: Model name.

    Returns:
        True if the model was removed, False if not found.
    """
    model_dir = get_model_dir(name)
    if model_dir.exists():
        shutil.rmtree(model_dir)
        return True
    return False


def verify_model(name: str) -> Dict[str, bool]:
    """Verify a model installation (file existence only).

    Args:
        name: Model name.

    Returns:
        Dict mapping filename to exists status.
    """
    definition = MODEL_CATALOG.get(name)
    if definition is None:
        return {}

    model_dir = get_model_dir(name)
    status = {}

    for filename in definition.files:
        status[filename] = (model_dir / filename).exists()

    status["model_meta.yaml"] = (model_dir / "model_meta.yaml").exists()


def verify_model_hashes(name: str) -> Dict[str, Optional[str]]:
    """Verify SHA-256 integrity of an installed model's files.

    Args:
        name: Model name from the catalog.

    Returns:
        Dict mapping filename to verification status:
        - ``"ok"`` — hash matches catalog
        - ``"mismatch"`` — hash does not match (corrupted or tampered)
        - ``"missing"`` — file not found on disk
        - ``"no_hash"`` — catalog has no expected hash for this file
        Returns empty dict if model is not in the catalog.
    """
    definition = MODEL_CATALOG.get(name)
    if definition is None:
        return {}

    model_dir = get_model_dir(name)
    results: Dict[str, Optional[str]] = {}

    for filename in definition.files:
        expected = definition.file_hashes.get(filename)
        path = model_dir / filename

        if not path.exists():
            results[filename] = "missing"
        elif not expected:
            results[filename] = "no_hash"
        else:
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            results[filename] = "ok" if actual == expected else "mismatch"

    return results

    return status


def get_model_size(name: str) -> Optional[int]:
    """Get the total size of an installed model in bytes.

    Args:
        name: Model name.

    Returns:
        Total size in bytes, or None if not installed.
    """
    model_dir = get_model_dir(name)
    if not model_dir.exists():
        return None

    total = 0
    for path in model_dir.iterdir():
        if path.is_file():
            total += path.stat().st_size

    return total
