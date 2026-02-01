"""Pytest configuration and fixtures for Tweek tests."""

import pytest
from pathlib import Path
from unittest.mock import patch

# Test license secret — used by all license-related tests
TEST_LICENSE_SECRET = "tweek-test-secret-key-for-pytest"


@pytest.fixture(autouse=True)
def _set_test_license_secret():
    """Ensure LICENSE_SECRET is set for all tests that validate licenses."""
    with patch("tweek.licensing.LICENSE_SECRET", TEST_LICENSE_SECRET), \
         patch("tweek._keygen.LICENSE_SECRET", TEST_LICENSE_SECRET):
        yield


@pytest.fixture
def tweek_root():
    """Return the Tweek project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture
def patterns_file(tweek_root):
    """Return the path to the patterns YAML file."""
    return tweek_root / "tweek" / "config" / "patterns.yaml"
