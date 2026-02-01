"""Pytest configuration and fixtures for Tweek tests."""

import pytest
import tempfile
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


@pytest.fixture(autouse=True)
def _isolate_memory_store(tmp_path):
    """Isolate memory store so tests never read/write the real ~/.tweek/memory.db.

    This prevents test data from accumulating in the global memory DB and
    prevents real memory data from affecting test outcomes.
    """
    from tweek.memory.store import reset_memory_store, MemoryStore, GLOBAL_MEMORY_PATH

    # Reset any existing singleton
    reset_memory_store()

    # Patch the global path so any new MemoryStore created during tests
    # uses an isolated temporary DB
    isolated_path = tmp_path / "test_memory.db"
    with patch("tweek.memory.store.GLOBAL_MEMORY_PATH", isolated_path):
        yield

    # Clean up after test
    reset_memory_store()


@pytest.fixture
def tweek_root():
    """Return the Tweek project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture
def patterns_file(tweek_root):
    """Return the path to the patterns YAML file."""
    return tweek_root / "tweek" / "config" / "patterns.yaml"
