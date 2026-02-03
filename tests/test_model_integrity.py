"""Tests for model integrity verification (Finding F5).

Tests the verify_model() return fix and verify_model_hashes() behavior.
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from tweek.security.model_registry import verify_model, verify_model_hashes


class TestVerifyModel:
    """Tests for verify_model() return value fix."""

    def test_unknown_model_returns_empty_dict(self):
        """verify_model() should return empty dict for unknown model names."""
        result = verify_model("nonexistent_model_xyz")
        assert result == {}

    def test_returns_dict_not_none(self):
        """verify_model() should return a dict, not None."""
        # Even for unknown models, it should return a dict
        result = verify_model("nonexistent_model_xyz")
        assert isinstance(result, dict)


class TestVerifyModelHashes:
    """Tests for verify_model_hashes() behavior."""

    def test_unknown_model_returns_empty_dict(self):
        """verify_model_hashes() should return empty dict for unknown model names."""
        result = verify_model_hashes("nonexistent_model_xyz")
        assert result == {}

    def test_returns_dict_not_none(self):
        """verify_model_hashes() should return a dict, not None."""
        result = verify_model_hashes("nonexistent_model_xyz")
        assert isinstance(result, dict)

    @patch("tweek.security.model_registry.get_model_dir")
    @patch("tweek.security.model_registry.MODEL_CATALOG")
    def test_missing_files_report_missing(self, mock_catalog, mock_get_dir, tmp_path):
        """Files that don't exist should be reported as 'missing'."""
        mock_definition = MagicMock()
        mock_definition.files = ["model.onnx", "tokenizer.json"]
        mock_definition.file_hashes = {
            "model.onnx": "abc123",
            "tokenizer.json": "def456",
        }
        mock_catalog.get.return_value = mock_definition
        mock_get_dir.return_value = tmp_path  # Empty dir, no files exist

        result = verify_model_hashes("test_model")
        assert result["model.onnx"] == "missing"
        assert result["tokenizer.json"] == "missing"

    @patch("tweek.security.model_registry.get_model_dir")
    @patch("tweek.security.model_registry.MODEL_CATALOG")
    def test_matching_hash_reports_ok(self, mock_catalog, mock_get_dir, tmp_path):
        """Files with matching hashes should be reported as 'ok'."""
        import hashlib

        # Create a test file and compute its real hash
        test_content = b"test model content"
        test_file = tmp_path / "model.onnx"
        test_file.write_bytes(test_content)
        expected_hash = hashlib.sha256(test_content).hexdigest()

        mock_definition = MagicMock()
        mock_definition.files = ["model.onnx"]
        mock_definition.file_hashes = {"model.onnx": expected_hash}
        mock_catalog.get.return_value = mock_definition
        mock_get_dir.return_value = tmp_path

        result = verify_model_hashes("test_model")
        assert result["model.onnx"] == "ok"

    @patch("tweek.security.model_registry.get_model_dir")
    @patch("tweek.security.model_registry.MODEL_CATALOG")
    def test_mismatching_hash_reports_mismatch(self, mock_catalog, mock_get_dir, tmp_path):
        """Files with wrong hashes should be reported as 'mismatch'."""
        test_file = tmp_path / "model.onnx"
        test_file.write_bytes(b"actual content")

        mock_definition = MagicMock()
        mock_definition.files = ["model.onnx"]
        mock_definition.file_hashes = {"model.onnx": "wrong_hash_value"}
        mock_catalog.get.return_value = mock_definition
        mock_get_dir.return_value = tmp_path

        result = verify_model_hashes("test_model")
        assert result["model.onnx"] == "mismatch"

    @patch("tweek.security.model_registry.get_model_dir")
    @patch("tweek.security.model_registry.MODEL_CATALOG")
    def test_no_hash_in_catalog(self, mock_catalog, mock_get_dir, tmp_path):
        """Files without catalog hashes should be reported as 'no_hash'."""
        test_file = tmp_path / "model.onnx"
        test_file.write_bytes(b"content")

        mock_definition = MagicMock()
        mock_definition.files = ["model.onnx"]
        mock_definition.file_hashes = {}  # No hashes in catalog
        mock_catalog.get.return_value = mock_definition
        mock_get_dir.return_value = tmp_path

        result = verify_model_hashes("test_model")
        assert result["model.onnx"] == "no_hash"


class TestLocalModelIntegrityOnLoad:
    """Tests for integrity verification during model load.

    The actual load() requires ONNX runtime and model files, so we test
    the hash verification logic through model_registry tests above.
    This test verifies that _integrity_verified flag is initialized.
    """

    def test_integrity_flag_initialized_false(self):
        """LocalModelInference should start with _integrity_verified=False."""
        try:
            from tweek.security.local_model import LocalModelInference
        except ImportError:
            pytest.skip("local model dependencies not installed")

        model = LocalModelInference(Path("/tmp/fake_model"), "test_model")
        assert model._integrity_verified is False
