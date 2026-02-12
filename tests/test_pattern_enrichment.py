"""Tests validating CTAP enrichment of patterns.yaml.

Structural validation that every pattern has valid classification metadata,
taxonomy IDs, tags, and CVE references after enrichment.
"""

from __future__ import annotations

import re

import pytest
import yaml

from tweek.config.models import PatternsConfig
from tweek.config.taxonomy import (
    ATTACK_CATEGORIES,
    MITRE_ATLAS,
    OWASP_AGENTIC_TOP_10,
    OWASP_LLM_TOP_10,
)

pytestmark = pytest.mark.enrichment


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def patterns_config():
    """Load and validate the enriched patterns.yaml."""
    from pathlib import Path

    patterns_path = Path(__file__).resolve().parent.parent / "tweek" / "config" / "patterns.yaml"
    with open(patterns_path) as f:
        data = yaml.safe_load(f)
    return PatternsConfig(**data)


@pytest.fixture(scope="module")
def patterns(patterns_config):
    """Return the list of PatternDefinition objects."""
    return patterns_config.patterns


# ---------------------------------------------------------------------------
# Header Validation
# ---------------------------------------------------------------------------


class TestPatternsHeader:
    def test_version_bumped(self, patterns_config):
        assert patterns_config.version >= 7

    def test_pattern_count_matches(self, patterns_config):
        assert patterns_config.pattern_count == len(patterns_config.patterns)

    def test_pattern_count_291(self, patterns_config):
        assert len(patterns_config.patterns) == 291


# ---------------------------------------------------------------------------
# Classification Completeness
# ---------------------------------------------------------------------------


class TestClassificationPresent:
    def test_all_patterns_have_classification(self, patterns):
        missing = [p.id for p in patterns if p.classification is None]
        assert missing == [], f"Patterns missing classification: {missing}"

    def test_all_classifications_have_category(self, patterns):
        for p in patterns:
            assert p.classification is not None
            assert p.classification.category, f"Pattern {p.id} has empty category"

    def test_all_categories_valid(self, patterns):
        for p in patterns:
            assert p.classification is not None
            assert p.classification.category in ATTACK_CATEGORIES, (
                f"Pattern {p.id} has unknown category: {p.classification.category}"
            )


# ---------------------------------------------------------------------------
# Taxonomy ID Validity
# ---------------------------------------------------------------------------


class TestTaxonomyIds:
    def test_mitre_ids_valid(self, patterns):
        for p in patterns:
            assert p.classification is not None
            for mid in p.classification.mitre_atlas:
                assert mid in MITRE_ATLAS, f"Pattern {p.id} has unknown MITRE ID: {mid}"

    def test_mitre_ids_non_empty(self, patterns):
        empty = [p.id for p in patterns if p.classification and len(p.classification.mitre_atlas) == 0]
        assert empty == [], f"Patterns with no MITRE mapping: {empty}"

    def test_owasp_llm_ids_valid(self, patterns):
        for p in patterns:
            assert p.classification is not None
            for oid in p.classification.owasp_llm:
                assert oid in OWASP_LLM_TOP_10, f"Pattern {p.id} has unknown OWASP LLM ID: {oid}"

    def test_owasp_llm_ids_non_empty(self, patterns):
        empty = [p.id for p in patterns if p.classification and len(p.classification.owasp_llm) == 0]
        assert empty == [], f"Patterns with no OWASP LLM mapping: {empty}"

    def test_owasp_agentic_ids_valid(self, patterns):
        for p in patterns:
            assert p.classification is not None
            for aid in p.classification.owasp_agentic:
                assert aid in OWASP_AGENTIC_TOP_10, f"Pattern {p.id} has unknown OWASP Agentic ID: {aid}"

    def test_owasp_agentic_ids_non_empty(self, patterns):
        empty = [p.id for p in patterns if p.classification and len(p.classification.owasp_agentic) == 0]
        assert empty == [], f"Patterns with no OWASP Agentic mapping: {empty}"


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------


class TestTags:
    def test_all_patterns_have_tags(self, patterns):
        empty = [p.id for p in patterns if len(p.tags) == 0]
        assert empty == [], f"Patterns with no tags: {empty}"

    def test_tags_include_family(self, patterns):
        """Tags should include the family name."""
        for p in patterns:
            if p.family:
                assert p.family in p.tags, f"Pattern {p.id} tags don't include family {p.family}"


# ---------------------------------------------------------------------------
# CVE References
# ---------------------------------------------------------------------------


CVE_RE = re.compile(r"CVE-\d{4}-\d+")


class TestReferences:
    def test_cve_in_description_has_reference(self, patterns):
        """Patterns with CVE in description should have matching references."""
        for p in patterns:
            cves_in_desc = CVE_RE.findall(p.description)
            ref_ids = {r.id for r in p.references}
            for cve in cves_in_desc:
                assert cve in ref_ids, (
                    f"Pattern {p.id} has CVE {cve} in description but not in references"
                )

    def test_reference_type_is_cve(self, patterns):
        for p in patterns:
            for ref in p.references:
                assert ref.type == "cve", f"Pattern {p.id} has non-cve reference type: {ref.type}"

    def test_reference_count(self, patterns):
        """Should have at least 30 patterns with CVE references."""
        with_refs = sum(1 for p in patterns if len(p.references) > 0)
        assert with_refs >= 30, f"Only {with_refs} patterns have CVE references"


# ---------------------------------------------------------------------------
# Backward Compatibility
# ---------------------------------------------------------------------------


class TestBackwardCompat:
    def test_original_fields_preserved(self, patterns):
        """All original fields still present and non-empty."""
        for p in patterns:
            assert p.id > 0
            assert p.name
            assert p.description
            assert p.regex
            assert p.severity
            assert p.confidence

    def test_family_preserved(self, patterns):
        """Family field still populated."""
        missing = [p.id for p in patterns if not p.family]
        assert missing == [], f"Patterns missing family: {missing}"

    def test_ids_sequential(self, patterns):
        """IDs should be sequential from 1 to 291."""
        ids = sorted(p.id for p in patterns)
        assert ids[0] == 1
        assert ids[-1] == 291

    def test_unique_names(self, patterns):
        names = [p.name for p in patterns]
        assert len(names) == len(set(names)), "Duplicate pattern names found"


# ---------------------------------------------------------------------------
# Target Type and Attack Surface
# ---------------------------------------------------------------------------


class TestClassificationFields:
    VALID_TARGETS = {"agent", "llm", "tool", "system", "skill"}
    VALID_SURFACES = {"tool_use", "llm", "mcp", "code_execution", "supply_chain"}

    def test_target_type_valid(self, patterns):
        for p in patterns:
            assert p.classification is not None
            assert p.classification.target_type in self.VALID_TARGETS, (
                f"Pattern {p.id} has unknown target_type: {p.classification.target_type}"
            )

    def test_attack_surface_valid(self, patterns):
        for p in patterns:
            assert p.classification is not None
            assert p.classification.attack_surface in self.VALID_SURFACES, (
                f"Pattern {p.id} has unknown attack_surface: {p.classification.attack_surface}"
            )
