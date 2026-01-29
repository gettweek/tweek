"""Pytest configuration and fixtures for Tweek tests."""

import pytest
from pathlib import Path


@pytest.fixture
def tweek_root():
    """Return the Tweek project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture
def patterns_file(tweek_root):
    """Return the path to the patterns YAML file."""
    return tweek_root / "tweek" / "config" / "patterns.yaml"
