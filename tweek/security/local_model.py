#!/usr/bin/env python3
"""
Tweek Local Model Inference Engine

Runs ONNX-based security classifiers for local prompt injection detection.
No cloud API calls needed — inference runs entirely on-device.

Dependencies (optional):
    pip install onnxruntime tokenizers numpy

When dependencies are not installed, the module gracefully degrades:
LOCAL_MODEL_AVAILABLE will be False, and get_local_model() returns None.
"""

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

# Optional dependency guards
try:
    import onnxruntime as ort

    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False

try:
    from tokenizers import Tokenizer

    TOKENIZERS_AVAILABLE = True
except ImportError:
    TOKENIZERS_AVAILABLE = False

try:
    import numpy as np

    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

LOCAL_MODEL_AVAILABLE = ONNX_AVAILABLE and TOKENIZERS_AVAILABLE and NUMPY_AVAILABLE


# ============================================================================
# DATA CLASSES
# ============================================================================


@dataclass
class LocalModelResult:
    """Result from local model inference."""

    risk_level: str  # "safe", "suspicious", "dangerous"
    label: str  # Raw label from model (e.g., "benign", "injection", "jailbreak")
    confidence: float  # 0.0 - 1.0, confidence in the predicted label
    all_scores: Dict[str, float]  # All label scores
    should_escalate: bool  # Whether to escalate to cloud LLM
    model_name: str
    inference_time_ms: float

    @property
    def is_dangerous(self) -> bool:
        return self.risk_level == "dangerous"

    @property
    def is_suspicious(self) -> bool:
        return self.risk_level in ("suspicious", "dangerous")


# ============================================================================
# INFERENCE ENGINE
# ============================================================================


class LocalModelInference:
    """ONNX-based local model inference engine.

    Thread-safe with lazy loading. The model is loaded on first predict()
    call and cached for subsequent calls.
    """

    def __init__(self, model_dir: Path, model_name: str = "unknown"):
        self._model_dir = model_dir
        self._model_name = model_name
        self._session: Optional[object] = None  # ort.InferenceSession
        self._tokenizer: Optional[object] = None  # Tokenizer
        self._lock = threading.Lock()
        self._loaded = False

        # Load metadata
        self._label_map: Dict[int, str] = {}
        self._risk_map: Dict[str, str] = {}
        self._max_length: int = 512
        self._escalate_min: float = 0.1
        self._escalate_max: float = 0.9

    def _load_metadata(self) -> None:
        """Load model metadata from catalog or meta file."""
        from tweek.security.model_registry import get_model_definition

        definition = get_model_definition(self._model_name)
        if definition:
            self._label_map = definition.label_map
            self._risk_map = definition.risk_map
            self._max_length = definition.max_length
            self._escalate_min = definition.escalate_min_confidence
            self._escalate_max = definition.escalate_max_confidence
            return

        # Fallback: try to load from model_meta.yaml
        meta_path = self._model_dir / "model_meta.yaml"
        if meta_path.exists():
            import yaml

            with open(meta_path) as f:
                meta = yaml.safe_load(f) or {}

            self._label_map = {
                int(k): v for k, v in meta.get("label_map", {}).items()
            }
            self._risk_map = meta.get("risk_map", {})
            self._max_length = meta.get("max_length", 512)

    def load(self) -> None:
        """Load the model and tokenizer. Thread-safe."""
        if self._loaded:
            return

        with self._lock:
            if self._loaded:
                return

            if not LOCAL_MODEL_AVAILABLE:
                raise RuntimeError(
                    "Local model dependencies not installed. "
                    "Install with: pip install tweek[local-models]"
                )

            model_path = self._model_dir / "model.onnx"
            tokenizer_path = self._model_dir / "tokenizer.json"

            if not model_path.exists():
                raise FileNotFoundError(
                    f"Model file not found: {model_path}. "
                    f"Run 'tweek model download' to install."
                )

            if not tokenizer_path.exists():
                raise FileNotFoundError(
                    f"Tokenizer file not found: {tokenizer_path}. "
                    f"Run 'tweek model download' to install."
                )

            # Load ONNX session with CPU-only execution
            sess_options = ort.SessionOptions()
            sess_options.graph_optimization_level = (
                ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            )
            sess_options.intra_op_num_threads = 1  # Minimize CPU impact

            self._session = ort.InferenceSession(
                str(model_path),
                sess_options,
                providers=["CPUExecutionProvider"],
            )

            # Load tokenizer
            self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
            self._tokenizer.enable_truncation(max_length=self._max_length)
            self._tokenizer.enable_padding(
                length=self._max_length, pad_id=0, pad_token="[PAD]"
            )

            # Load metadata
            self._load_metadata()

            self._loaded = True

    def is_loaded(self) -> bool:
        """Check if the model is loaded."""
        return self._loaded

    def unload(self) -> None:
        """Unload the model and free memory."""
        with self._lock:
            self._session = None
            self._tokenizer = None
            self._loaded = False

    def predict(self, text: str) -> LocalModelResult:
        """Run inference on the given text.

        Args:
            text: The command or content to classify.

        Returns:
            LocalModelResult with classification and confidence.
        """
        self.load()

        start_time = time.perf_counter()

        # Tokenize
        encoding = self._tokenizer.encode(text)
        input_ids = np.array([encoding.ids], dtype=np.int64)
        attention_mask = np.array([encoding.attention_mask], dtype=np.int64)

        # Run inference
        feeds = {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
        }

        # Some models also need token_type_ids
        input_names = [inp.name for inp in self._session.get_inputs()]
        if "token_type_ids" in input_names:
            token_type_ids = np.zeros_like(input_ids)
            feeds["token_type_ids"] = token_type_ids

        outputs = self._session.run(None, feeds)
        logits = outputs[0][0]  # First output, first batch item

        # Softmax
        scores = _softmax(logits)

        # Get predicted label
        predicted_idx = int(np.argmax(scores))
        confidence = float(scores[predicted_idx])

        # Map to label and risk
        label = self._label_map.get(predicted_idx, f"label_{predicted_idx}")
        risk_level = self._risk_map.get(label, "suspicious")

        # Build all scores dict
        all_scores = {}
        for idx, score in enumerate(scores):
            lbl = self._label_map.get(idx, f"label_{idx}")
            all_scores[lbl] = float(score)

        # Determine escalation
        should_escalate = self._escalate_min <= confidence <= self._escalate_max
        # If the prediction is "safe" with high confidence, don't escalate
        if risk_level == "safe" and confidence > self._escalate_max:
            should_escalate = False
        # If the prediction is "dangerous" with high confidence, don't escalate
        if risk_level == "dangerous" and confidence > self._escalate_max:
            should_escalate = False

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return LocalModelResult(
            risk_level=risk_level,
            label=label,
            confidence=confidence,
            all_scores=all_scores,
            should_escalate=should_escalate,
            model_name=self._model_name,
            inference_time_ms=round(elapsed_ms, 2),
        )


# ============================================================================
# UTILITIES
# ============================================================================


def _softmax(logits) -> "np.ndarray":
    """Compute softmax over logits."""
    exp_logits = np.exp(logits - np.max(logits))
    return exp_logits / exp_logits.sum()


# ============================================================================
# SINGLETON
# ============================================================================

_local_model: Optional[LocalModelInference] = None
_local_model_lock = threading.Lock()


def get_local_model(model_name: Optional[str] = None) -> Optional[LocalModelInference]:
    """Get the singleton local model instance.

    Returns None if local model dependencies are not installed or
    the model is not downloaded.

    Args:
        model_name: Override model name. None = use configured default.

    Returns:
        LocalModelInference instance, or None if unavailable.
    """
    if not LOCAL_MODEL_AVAILABLE:
        return None

    global _local_model

    if _local_model is not None:
        return _local_model

    with _local_model_lock:
        if _local_model is not None:
            return _local_model

        from tweek.security.model_registry import (
            get_default_model_name,
            get_model_dir,
            is_model_installed,
        )

        name = model_name or get_default_model_name()
        if not is_model_installed(name):
            return None

        _local_model = LocalModelInference(
            model_dir=get_model_dir(name),
            model_name=name,
        )

    return _local_model


def reset_local_model() -> None:
    """Reset the singleton local model (for testing)."""
    global _local_model
    with _local_model_lock:
        if _local_model is not None:
            _local_model.unload()
        _local_model = None
