#!/usr/bin/env python3
"""
Tests for tweek.plugins.git_security module.

Tests the 5-layer security validation pipeline:
1. Manifest validation
2. Checksum signature verification
3. File checksum verification
4. AST static analysis
5. Base class enforcement
"""

import pytest

pytestmark = pytest.mark.plugins

import hashlib
import hmac
import json
import os
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from tweek.plugins.git_security import (
    FORBIDDEN_CALLS,
    FORBIDDEN_IMPORTS,
    FORBIDDEN_NETWORK_IMPORTS,
    TWEEK_SIGNING_KEY,
    PluginSecurityError,
    _analyze_ast,
    _compute_file_sha256,
    _is_valid_version,
    generate_checksums,
    sign_checksums,
    static_analyze_python_files,
    validate_manifest,
    validate_plugin_full,
    verify_checksum_signature,
    verify_checksums,
)


@pytest.fixture
def tmp_plugin_dir(tmp_path):
    """Create a temporary plugin directory with valid files."""
    plugin_dir = tmp_path / "test-plugin"
    plugin_dir.mkdir()

    # Write a safe plugin file
    safe_code = textwrap.dedent("""\
        from tweek.plugins.base import ToolDetectorPlugin, DetectionResult

        class TestDetector(ToolDetectorPlugin):
            VERSION = "1.0.0"
            DESCRIPTION = "Test detector"

            @property
            def name(self):
                return "test"

            def detect(self):
                return DetectionResult(detected=False, tool_name="test")

            def get_conflicts(self):
                return []
    """)
    (plugin_dir / "plugin.py").write_text(safe_code)
    (plugin_dir / "__init__.py").write_text("from .plugin import TestDetector\n")

    return plugin_dir


@pytest.fixture
def valid_manifest(tmp_plugin_dir):
    """Create a valid manifest in the plugin directory."""
    manifest = {
        "name": "tweek-plugin-test-detector",
        "version": "1.0.0",
        "category": "detectors",
        "entry_point": "plugin:TestDetector",
        "description": "A test detector plugin",
        "author": "Tweek",
        "requires_license_tier": "free",
    }
    manifest_path = tmp_plugin_dir / "tweek_plugin.json"
    manifest_path.write_text(json.dumps(manifest))
    return manifest_path


class TestManifestValidation:
    """Tests for validate_manifest()."""

    def test_valid_manifest(self, valid_manifest):
        valid, manifest, issues = validate_manifest(valid_manifest)
        assert valid is True
        assert manifest is not None
        assert manifest["name"] == "tweek-plugin-test-detector"
        assert len(issues) == 0

    def test_missing_manifest_file(self, tmp_path):
        valid, manifest, issues = validate_manifest(tmp_path / "nonexistent.json")
        assert valid is False
        assert manifest is None
        assert "not found" in issues[0]

    def test_invalid_json(self, tmp_path):
        bad_json = tmp_path / "tweek_plugin.json"
        bad_json.write_text("{invalid json")
        valid, manifest, issues = validate_manifest(bad_json)
        assert valid is False
        assert "Invalid JSON" in issues[0]

    def test_non_object_json(self, tmp_path):
        array_json = tmp_path / "tweek_plugin.json"
        array_json.write_text('["not", "an", "object"]')
        valid, manifest, issues = validate_manifest(array_json)
        assert valid is False
        assert "JSON object" in issues[0]

    def test_missing_required_fields(self, tmp_path):
        manifest = tmp_path / "tweek_plugin.json"
        manifest.write_text(json.dumps({"name": "test"}))
        valid, _, issues = validate_manifest(manifest)
        assert valid is False
        # Should report missing fields: version, category, entry_point, description
        assert len(issues) >= 3

    def test_invalid_category(self, tmp_path):
        manifest = tmp_path / "tweek_plugin.json"
        data = {
            "name": "test",
            "version": "1.0.0",
            "category": "invalid_category",
            "entry_point": "plugin:TestClass",
            "description": "test",
        }
        manifest.write_text(json.dumps(data))
        valid, _, issues = validate_manifest(manifest)
        assert valid is False
        assert any("Invalid category" in i for i in issues)

    def test_invalid_license_tier(self, tmp_path):
        manifest = tmp_path / "tweek_plugin.json"
        data = {
            "name": "test",
            "version": "1.0.0",
            "category": "detectors",
            "entry_point": "plugin:TestClass",
            "description": "test",
            "requires_license_tier": "platinum",
        }
        manifest.write_text(json.dumps(data))
        valid, _, issues = validate_manifest(manifest)
        assert valid is False
        assert any("Invalid license tier" in i for i in issues)

    def test_invalid_entry_point_format(self, tmp_path):
        manifest = tmp_path / "tweek_plugin.json"
        data = {
            "name": "test",
            "version": "1.0.0",
            "category": "detectors",
            "entry_point": "no_colon_here",
            "description": "test",
        }
        manifest.write_text(json.dumps(data))
        valid, _, issues = validate_manifest(manifest)
        assert valid is False
        assert any("entry_point" in i for i in issues)

    def test_invalid_version_format(self, tmp_path):
        manifest = tmp_path / "tweek_plugin.json"
        data = {
            "name": "test",
            "version": "abc",
            "category": "detectors",
            "entry_point": "plugin:TestClass",
            "description": "test",
        }
        manifest.write_text(json.dumps(data))
        valid, _, issues = validate_manifest(manifest)
        assert valid is False
        assert any("Invalid version" in i for i in issues)


class TestVersionValidation:
    """Tests for _is_valid_version()."""

    def test_valid_three_part(self):
        assert _is_valid_version("1.2.3") is True

    def test_valid_two_part(self):
        assert _is_valid_version("1.0") is True

    def test_invalid_single_part(self):
        assert _is_valid_version("1") is False

    def test_invalid_four_parts(self):
        assert _is_valid_version("1.2.3.4") is False

    def test_invalid_non_numeric(self):
        assert _is_valid_version("1.2.beta") is False

    def test_empty_string(self):
        assert _is_valid_version("") is False


class TestChecksumVerification:
    """Tests for verify_checksums()."""

    def test_valid_checksums(self, tmp_plugin_dir):
        # Generate actual checksums
        checksums = generate_checksums(tmp_plugin_dir)
        valid, issues = verify_checksums(tmp_plugin_dir, checksums)
        assert valid is True
        assert len(issues) == 0

    def test_checksum_mismatch(self, tmp_plugin_dir):
        checksums = {
            "plugin.py": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "__init__.py": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        }
        valid, issues = verify_checksums(tmp_plugin_dir, checksums)
        assert valid is False
        assert any("mismatch" in i for i in issues)

    def test_missing_expected_file(self, tmp_plugin_dir):
        checksums = {
            "nonexistent.py": "sha256:abc123",
        }
        valid, issues = verify_checksums(tmp_plugin_dir, checksums)
        assert valid is False
        assert any("missing" in i.lower() for i in issues)

    def test_unexpected_file(self, tmp_path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        (plugin_dir / "expected.py").write_text("# expected")
        (plugin_dir / "surprise.py").write_text("# unexpected")

        checksums = generate_checksums(plugin_dir)
        # Only include expected.py
        limited_checksums = {"expected.py": checksums["expected.py"]}
        valid, issues = verify_checksums(plugin_dir, limited_checksums)
        assert valid is False
        assert any("Unexpected" in i for i in issues)

    def test_sha256_prefix_handling(self, tmp_plugin_dir):
        # Test that both "sha256:hash" and plain "hash" formats work
        checksums = generate_checksums(tmp_plugin_dir)
        # Strip prefix from one entry
        for key in checksums:
            if checksums[key].startswith("sha256:"):
                checksums[key] = checksums[key][7:]
                break
        valid, issues = verify_checksums(tmp_plugin_dir, checksums)
        assert valid is True


class TestSignatureVerification:
    """Tests for verify_checksum_signature() and sign_checksums()."""

    TEST_SIGNING_KEY = "test-signing-key-for-pytest"

    def test_sign_and_verify(self):
        content = b"test checksum content"
        signature = sign_checksums(content, signing_key=self.TEST_SIGNING_KEY)
        assert verify_checksum_signature(content, signature, signing_key=self.TEST_SIGNING_KEY) is True

    def test_invalid_signature(self):
        content = b"test checksum content"
        assert verify_checksum_signature(content, "invalid_signature", signing_key=self.TEST_SIGNING_KEY) is False

    def test_tampered_content(self):
        content = b"original content"
        signature = sign_checksums(content, signing_key=self.TEST_SIGNING_KEY)
        assert verify_checksum_signature(b"tampered content", signature, signing_key=self.TEST_SIGNING_KEY) is False

    def test_custom_signing_key(self):
        content = b"test content"
        key = "custom-key-123"
        signature = sign_checksums(content, signing_key=key)
        assert verify_checksum_signature(content, signature, signing_key=key) is True
        # Wrong key should fail
        assert verify_checksum_signature(content, signature, signing_key="wrong-key") is False


class TestASTStaticAnalysis:
    """Tests for static_analyze_python_files()."""

    def test_safe_code_passes(self, tmp_plugin_dir):
        safe, issues = static_analyze_python_files(tmp_plugin_dir)
        assert safe is True
        assert len(issues) == 0

    def test_forbidden_import_subprocess(self, tmp_path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        (plugin_dir / "bad.py").write_text("import subprocess\n")
        safe, issues = static_analyze_python_files(plugin_dir)
        assert safe is False
        assert any("subprocess" in i for i in issues)

    def test_forbidden_import_ctypes(self, tmp_path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        (plugin_dir / "bad.py").write_text("import ctypes\n")
        safe, issues = static_analyze_python_files(plugin_dir)
        assert safe is False
        assert any("ctypes" in i for i in issues)

    def test_forbidden_from_import(self, tmp_path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        (plugin_dir / "bad.py").write_text("from os import system\n")
        safe, issues = static_analyze_python_files(plugin_dir)
        assert safe is False
        assert any("os.system" in i for i in issues)

    def test_forbidden_eval_call(self, tmp_path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        (plugin_dir / "bad.py").write_text("result = eval('1+1')\n")
        safe, issues = static_analyze_python_files(plugin_dir)
        assert safe is False
        assert any("eval" in i for i in issues)

    def test_forbidden_exec_call(self, tmp_path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        (plugin_dir / "bad.py").write_text("exec('print(1)')\n")
        safe, issues = static_analyze_python_files(plugin_dir)
        assert safe is False
        assert any("exec" in i for i in issues)

    def test_forbidden_network_import(self, tmp_path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        (plugin_dir / "bad.py").write_text("import requests\n")
        safe, issues = static_analyze_python_files(plugin_dir)
        assert safe is False
        assert any("requests" in i for i in issues)

    def test_forbidden_socket_import(self, tmp_path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        (plugin_dir / "bad.py").write_text("import socket\n")
        safe, issues = static_analyze_python_files(plugin_dir)
        assert safe is False
        assert any("socket" in i for i in issues)

    def test_forbidden_os_system_call(self, tmp_path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        (plugin_dir / "bad.py").write_text("import os\nos.system('ls')\n")
        safe, issues = static_analyze_python_files(plugin_dir)
        assert safe is False
        assert any("os.system" in i for i in issues)

    def test_forbidden_shutil_rmtree(self, tmp_path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        (plugin_dir / "bad.py").write_text("import shutil\nshutil.rmtree('/tmp')\n")
        safe, issues = static_analyze_python_files(plugin_dir)
        assert safe is False
        assert any("shutil.rmtree" in i for i in issues)

    def test_skip_test_files(self, tmp_path):
        plugin_dir = tmp_path / "plugin"
        test_dir = plugin_dir / "test"
        test_dir.mkdir(parents=True)
        # Dangerous code in test directory should be skipped
        (test_dir / "test_bad.py").write_text("import subprocess\n")
        safe, issues = static_analyze_python_files(plugin_dir)
        assert safe is True

    def test_syntax_error_in_file(self, tmp_path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        (plugin_dir / "bad.py").write_text("def broken(\n")
        safe, issues = static_analyze_python_files(plugin_dir)
        assert safe is False
        assert any("Syntax error" in i for i in issues)

    def test_multiple_violations(self, tmp_path):
        plugin_dir = tmp_path / "plugin"
        plugin_dir.mkdir()
        code = "import subprocess\nimport requests\neval('test')\n"
        (plugin_dir / "bad.py").write_text(code)
        safe, issues = static_analyze_python_files(plugin_dir)
        assert safe is False
        assert len(issues) >= 3


class TestGenerateChecksums:
    """Tests for generate_checksums()."""

    def test_generates_for_all_py_files(self, tmp_plugin_dir):
        checksums = generate_checksums(tmp_plugin_dir)
        assert "plugin.py" in checksums
        assert "__init__.py" in checksums
        assert all(v.startswith("sha256:") for v in checksums.values())

    def test_checksums_are_deterministic(self, tmp_plugin_dir):
        c1 = generate_checksums(tmp_plugin_dir)
        c2 = generate_checksums(tmp_plugin_dir)
        assert c1 == c2

    def test_empty_directory(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        checksums = generate_checksums(empty)
        assert checksums == {}


class TestFullValidation:
    """Tests for validate_plugin_full()."""

    def test_valid_plugin_with_skip_signature(self, tmp_plugin_dir, valid_manifest):
        with open(valid_manifest) as f:
            manifest = json.load(f)

        is_safe, issues = validate_plugin_full(
            tmp_plugin_dir,
            manifest,
            skip_signature=True,
        )
        assert is_safe is True
        assert len(issues) == 0

    def test_invalid_category_fails(self, tmp_plugin_dir):
        manifest = {"category": "invalid"}
        is_safe, issues = validate_plugin_full(
            tmp_plugin_dir,
            manifest,
            skip_signature=True,
        )
        assert is_safe is False
        assert any("Invalid category" in i for i in issues)

    def test_missing_checksums_file_without_skip(self, tmp_plugin_dir, valid_manifest):
        with open(valid_manifest) as f:
            manifest = json.load(f)
        manifest["checksum_signature"] = "abc"

        is_safe, issues = validate_plugin_full(
            tmp_plugin_dir,
            manifest,
            skip_signature=False,
        )
        assert is_safe is False
        assert any("CHECKSUMS.sha256" in i for i in issues)

    def test_valid_with_checksums_and_signature(self, tmp_plugin_dir, valid_manifest):
        with open(valid_manifest) as f:
            manifest = json.load(f)

        # Generate checksums file
        checksums = generate_checksums(tmp_plugin_dir)
        checksums_content = json.dumps(checksums, sort_keys=True).encode()
        checksums_file = tmp_plugin_dir / "CHECKSUMS.sha256"
        checksums_file.write_bytes(checksums_content)

        # Sign it with a test key
        test_key = "test-signing-key-for-pytest"
        signature = sign_checksums(checksums_content, signing_key=test_key)
        manifest["checksum_signature"] = signature

        # Re-write manifest
        valid_manifest.write_text(json.dumps(manifest))

        # Patch the signing key so validate_plugin_full can verify
        from unittest.mock import patch
        with patch("tweek.plugins.git_security.TWEEK_SIGNING_KEY", test_key):
            is_safe, issues = validate_plugin_full(
                tmp_plugin_dir,
                manifest,
                registry_checksums=checksums,
                skip_signature=False,
            )
        assert is_safe is True
        assert len(issues) == 0
