"""Tests for the sandbox layers module."""

import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

pytestmark = pytest.mark.sandbox

from tweek.sandbox.layers import (
    IsolationLayer,
    LAYER_CAPABILITIES,
    SEVERITY_ORDER,
    layer_has_capability,
    get_layer_description,
    stricter_severity,
)


class TestIsolationLayerEnum:
    """Tests for IsolationLayer enum values."""

    def test_bypass_value(self):
        assert IsolationLayer.BYPASS == 0

    def test_skills_value(self):
        assert IsolationLayer.SKILLS == 1

    def test_project_value(self):
        assert IsolationLayer.PROJECT == 2

    def test_is_int_enum(self):
        assert isinstance(IsolationLayer.BYPASS, int)
        assert isinstance(IsolationLayer.SKILLS, int)
        assert isinstance(IsolationLayer.PROJECT, int)

    def test_ordering(self):
        assert IsolationLayer.BYPASS < IsolationLayer.SKILLS < IsolationLayer.PROJECT


class TestIsolationLayerFromValue:
    """Tests for IsolationLayer.from_value()."""

    def test_valid_zero(self):
        assert IsolationLayer.from_value(0) == IsolationLayer.BYPASS

    def test_valid_one(self):
        assert IsolationLayer.from_value(1) == IsolationLayer.SKILLS

    def test_valid_two(self):
        assert IsolationLayer.from_value(2) == IsolationLayer.PROJECT

    def test_negative_clamps_to_bypass(self):
        assert IsolationLayer.from_value(-1) == IsolationLayer.BYPASS

    def test_large_negative_clamps_to_bypass(self):
        assert IsolationLayer.from_value(-100) == IsolationLayer.BYPASS

    def test_above_range_clamps_to_project(self):
        assert IsolationLayer.from_value(3) == IsolationLayer.PROJECT

    def test_large_above_range_clamps_to_project(self):
        assert IsolationLayer.from_value(999) == IsolationLayer.PROJECT


class TestLayerCapabilities:
    """Tests for LAYER_CAPABILITIES matrix."""

    def test_bypass_has_no_capabilities(self):
        assert LAYER_CAPABILITIES[IsolationLayer.BYPASS] == set()

    def test_skills_has_skill_capabilities(self):
        caps = LAYER_CAPABILITIES[IsolationLayer.SKILLS]
        assert "skill_scanning" in caps
        assert "skill_fingerprints" in caps
        assert "skill_guard" in caps

    def test_skills_has_no_project_capabilities(self):
        caps = LAYER_CAPABILITIES[IsolationLayer.SKILLS]
        assert "project_security_db" not in caps
        assert "project_overrides" not in caps
        assert "project_fingerprints" not in caps
        assert "project_config" not in caps

    def test_project_has_all_skill_capabilities(self):
        caps = LAYER_CAPABILITIES[IsolationLayer.PROJECT]
        assert "skill_scanning" in caps
        assert "skill_fingerprints" in caps
        assert "skill_guard" in caps

    def test_project_has_project_capabilities(self):
        caps = LAYER_CAPABILITIES[IsolationLayer.PROJECT]
        assert "project_security_db" in caps
        assert "project_overrides" in caps
        assert "project_fingerprints" in caps
        assert "project_config" in caps

    def test_project_is_superset_of_skills(self):
        skills_caps = LAYER_CAPABILITIES[IsolationLayer.SKILLS]
        project_caps = LAYER_CAPABILITIES[IsolationLayer.PROJECT]
        assert skills_caps.issubset(project_caps)

    def test_all_layers_represented(self):
        for layer in IsolationLayer:
            assert layer in LAYER_CAPABILITIES


class TestLayerHasCapability:
    """Tests for layer_has_capability()."""

    def test_bypass_has_nothing(self):
        assert layer_has_capability(IsolationLayer.BYPASS, "skill_scanning") is False

    def test_skills_has_skill_scanning(self):
        assert layer_has_capability(IsolationLayer.SKILLS, "skill_scanning") is True

    def test_skills_lacks_project_db(self):
        assert layer_has_capability(IsolationLayer.SKILLS, "project_security_db") is False

    def test_project_has_project_db(self):
        assert layer_has_capability(IsolationLayer.PROJECT, "project_security_db") is True

    def test_project_has_skill_scanning(self):
        assert layer_has_capability(IsolationLayer.PROJECT, "skill_scanning") is True

    def test_nonexistent_capability(self):
        assert layer_has_capability(IsolationLayer.PROJECT, "nonexistent") is False


class TestGetLayerDescription:
    """Tests for get_layer_description()."""

    def test_bypass_description_not_empty(self):
        desc = get_layer_description(IsolationLayer.BYPASS)
        assert len(desc) > 0

    def test_skills_description_not_empty(self):
        desc = get_layer_description(IsolationLayer.SKILLS)
        assert len(desc) > 0

    def test_project_description_not_empty(self):
        desc = get_layer_description(IsolationLayer.PROJECT)
        assert len(desc) > 0

    def test_bypass_mentions_no_isolation(self):
        desc = get_layer_description(IsolationLayer.BYPASS)
        assert "No isolation" in desc

    def test_skills_mentions_skill(self):
        desc = get_layer_description(IsolationLayer.SKILLS)
        assert "Skill" in desc

    def test_project_mentions_project(self):
        desc = get_layer_description(IsolationLayer.PROJECT)
        assert "project" in desc.lower()

    def test_project_mentions_additive_only(self):
        desc = get_layer_description(IsolationLayer.PROJECT)
        assert "additive-only" in desc


class TestSeverityOrder:
    """Tests for SEVERITY_ORDER ranking."""

    def test_critical_is_rank_0(self):
        assert SEVERITY_ORDER["critical"] == 0

    def test_high_is_rank_1(self):
        assert SEVERITY_ORDER["high"] == 1

    def test_medium_is_rank_2(self):
        assert SEVERITY_ORDER["medium"] == 2

    def test_low_is_rank_3(self):
        assert SEVERITY_ORDER["low"] == 3

    def test_low_has_highest_rank(self):
        assert SEVERITY_ORDER["low"] > SEVERITY_ORDER["medium"]
        assert SEVERITY_ORDER["low"] > SEVERITY_ORDER["high"]
        assert SEVERITY_ORDER["low"] > SEVERITY_ORDER["critical"]


class TestStricterSeverity:
    """Tests for stricter_severity() - core additive-only merge logic.

    Key semantics:
    - "low" screens everything (low+medium+high+critical) = STRICTEST
    - "critical" screens only critical = MOST PERMISSIVE
    - Higher rank number = screens more = stricter
    """

    def test_low_vs_high_returns_low(self):
        """low screens more than high, so low is stricter."""
        assert stricter_severity("low", "high") == "low"

    def test_high_vs_low_returns_low(self):
        """Order shouldn't matter."""
        assert stricter_severity("high", "low") == "low"

    def test_low_vs_critical_returns_low(self):
        assert stricter_severity("low", "critical") == "low"

    def test_critical_vs_low_returns_low(self):
        assert stricter_severity("critical", "low") == "low"

    def test_medium_vs_high_returns_medium(self):
        assert stricter_severity("medium", "high") == "medium"

    def test_high_vs_medium_returns_medium(self):
        assert stricter_severity("high", "medium") == "medium"

    def test_medium_vs_critical_returns_medium(self):
        assert stricter_severity("medium", "critical") == "medium"

    def test_high_vs_critical_returns_high(self):
        assert stricter_severity("high", "critical") == "high"

    def test_critical_vs_high_returns_high(self):
        assert stricter_severity("critical", "high") == "high"

    def test_same_low_returns_low(self):
        assert stricter_severity("low", "low") == "low"

    def test_same_medium_returns_medium(self):
        assert stricter_severity("medium", "medium") == "medium"

    def test_same_high_returns_high(self):
        assert stricter_severity("high", "high") == "high"

    def test_same_critical_returns_critical(self):
        assert stricter_severity("critical", "critical") == "critical"

    def test_unknown_severity_defaults_to_low_rank(self):
        """Unknown severity gets rank 3 (same as low), which is strictest."""
        result = stricter_severity("unknown", "critical")
        assert result == "unknown"

    def test_both_unknown_returns_first(self):
        result = stricter_severity("foo", "bar")
        assert result == "foo"

    def test_all_pairwise_combinations(self):
        """Exhaustive check: stricter_severity always returns the one with higher rank."""
        severities = ["critical", "high", "medium", "low"]
        for a in severities:
            for b in severities:
                result = stricter_severity(a, b)
                rank_a = SEVERITY_ORDER[a]
                rank_b = SEVERITY_ORDER[b]
                if rank_a >= rank_b:
                    assert result == a
                else:
                    assert result == b
