#!/usr/bin/env python3
"""
Tests for Tweek Pattern Families

Tests cover:
- families.yaml parses without errors
- All 262 patterns have a family field
- Pattern IDs in families match actual patterns
- No duplicate pattern IDs across families
- Family structure validation
"""

import pytest
import yaml
from pathlib import Path


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def families_path(tweek_root):
    """Return path to families.yaml."""
    return tweek_root / "tweek" / "config" / "families.yaml"


@pytest.fixture
def families_data(families_path):
    """Load and return families.yaml data."""
    with open(families_path) as f:
        return yaml.safe_load(f)


@pytest.fixture
def patterns_data(patterns_file):
    """Load and return patterns.yaml data."""
    with open(patterns_file) as f:
        return yaml.safe_load(f)


# =============================================================================
# FAMILIES.YAML STRUCTURE TESTS
# =============================================================================

class TestFamiliesStructure:
    """Validate families.yaml file structure."""

    def test_file_exists(self, families_path):
        assert families_path.exists(), f"families.yaml not found at {families_path}"

    def test_parses_without_errors(self, families_data):
        assert families_data is not None
        assert "families" in families_data

    def test_has_families(self, families_data):
        families = families_data["families"]
        assert len(families) >= 11, f"Expected at least 11 families, got {len(families)}"

    def test_family_has_required_fields(self, families_data):
        families = families_data["families"]
        required_fields = {"display_name", "description", "pattern_ids", "heuristic_signals"}
        for name, family in families.items():
            missing = required_fields - set(family.keys())
            assert not missing, f"Family '{name}' missing fields: {missing}"

    def test_pattern_ids_are_lists(self, families_data):
        families = families_data["families"]
        for name, family in families.items():
            assert isinstance(family["pattern_ids"], list), \
                f"Family '{name}' pattern_ids should be a list"

    def test_heuristic_signals_are_dicts(self, families_data):
        families = families_data["families"]
        for name, family in families.items():
            assert isinstance(family["heuristic_signals"], dict), \
                f"Family '{name}' heuristic_signals should be a dict"

    def test_each_family_has_signals(self, families_data):
        families = families_data["families"]
        for name, family in families.items():
            signals = family["heuristic_signals"]
            total = sum(len(v) for v in signals.values() if isinstance(v, list))
            assert total > 0, \
                f"Family '{name}' has no heuristic_signals entries"


# =============================================================================
# PATTERN COVERAGE TESTS
# =============================================================================

class TestPatternCoverage:
    """Ensure all 262 patterns are assigned to families."""

    def test_all_patterns_have_family_field(self, patterns_data):
        patterns = patterns_data.get("patterns", [])
        missing = [p["id"] for p in patterns if "family" not in p]
        assert not missing, f"Patterns missing 'family' field: {missing[:10]}..."

    def test_259_patterns_exist(self, patterns_data):
        patterns = patterns_data.get("patterns", [])
        assert len(patterns) == 262, f"Expected 262 patterns, got {len(patterns)}"

    def test_pattern_families_are_valid(self, patterns_data, families_data):
        """Every pattern's family field should reference an existing family."""
        families = set(families_data["families"].keys())
        patterns = patterns_data.get("patterns", [])
        invalid = [
            (p["id"], p.get("family", "MISSING"))
            for p in patterns
            if p.get("family") not in families
        ]
        assert not invalid, \
            f"Patterns with invalid family: {invalid[:10]}"


# =============================================================================
# PATTERN ID INTEGRITY TESTS
# =============================================================================

class TestPatternIdIntegrity:
    """Validate pattern IDs in families match actual patterns."""

    def test_no_duplicate_pattern_ids_across_families(self, families_data):
        """Each pattern ID should appear in exactly one family."""
        seen = {}
        families = families_data["families"]
        duplicates = []
        for name, family in families.items():
            for pid in family["pattern_ids"]:
                if pid in seen:
                    duplicates.append((pid, seen[pid], name))
                seen[pid] = name
        assert not duplicates, \
            f"Duplicate pattern IDs: {duplicates[:10]}"

    def test_family_pattern_ids_exist_in_patterns(self, families_data, patterns_data):
        """All pattern IDs referenced in families should exist in patterns.yaml."""
        actual_ids = {p["id"] for p in patterns_data.get("patterns", [])}
        families = families_data["families"]
        missing = []
        for name, family in families.items():
            for pid in family["pattern_ids"]:
                if pid not in actual_ids:
                    missing.append((pid, name))
        assert not missing, \
            f"Pattern IDs in families not found in patterns.yaml: {missing[:10]}"

    def test_all_pattern_ids_assigned_to_family(self, families_data, patterns_data):
        """Every pattern ID in patterns.yaml should appear in some family."""
        assigned_ids = set()
        families = families_data["families"]
        for family in families.values():
            assigned_ids.update(family["pattern_ids"])

        actual_ids = {p["id"] for p in patterns_data.get("patterns", [])}
        unassigned = actual_ids - assigned_ids
        assert not unassigned, \
            f"Pattern IDs not in any family: {sorted(unassigned)[:10]}"
