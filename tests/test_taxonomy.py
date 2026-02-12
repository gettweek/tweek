"""Tests for tweek.config.taxonomy — CTAP-compatible taxonomy mappings."""

from __future__ import annotations

import pytest

from tweek.config.taxonomy import (
    ATTACK_CATEGORIES,
    FAMILY_TO_CATEGORY,
    FAMILY_TO_SURFACE,
    FAMILY_TO_TARGET,
    MITRE_ATLAS,
    OWASP_AGENTIC_TOP_10,
    OWASP_LLM_TOP_10,
    SURFACE_TO_ASI,
    map_category_to_mitre,
    map_category_to_owasp,
    map_category_to_owasp_agentic,
    map_family_to_category,
    map_family_to_surface,
    map_family_to_target,
    map_surface_to_asi,
)

pytestmark = pytest.mark.taxonomy


# ---------------------------------------------------------------------------
# Reference Data Integrity
# ---------------------------------------------------------------------------


class TestMitreAtlas:
    def test_all_ids_have_name(self):
        for tid, info in MITRE_ATLAS.items():
            assert "name" in info, f"MITRE {tid} missing name"
            assert "tactic" in info, f"MITRE {tid} missing tactic"

    def test_id_format(self):
        for tid in MITRE_ATLAS:
            assert tid.startswith("AML.T"), f"Invalid MITRE ID: {tid}"

    def test_count(self):
        assert len(MITRE_ATLAS) == 11


class TestOwaspLlm:
    def test_all_ids_have_name(self):
        for oid, info in OWASP_LLM_TOP_10.items():
            assert "name" in info, f"OWASP LLM {oid} missing name"

    def test_id_format(self):
        for oid in OWASP_LLM_TOP_10:
            assert oid.startswith("LLM"), f"Invalid OWASP LLM ID: {oid}"

    def test_count(self):
        assert len(OWASP_LLM_TOP_10) == 10


class TestOwaspAgentic:
    def test_all_ids_have_name(self):
        for aid, info in OWASP_AGENTIC_TOP_10.items():
            assert "name" in info, f"OWASP Agentic {aid} missing name"

    def test_id_format(self):
        for aid in OWASP_AGENTIC_TOP_10:
            assert aid.startswith("ASI"), f"Invalid OWASP Agentic ID: {aid}"

    def test_count(self):
        assert len(OWASP_AGENTIC_TOP_10) == 10


# ---------------------------------------------------------------------------
# Category Mapping Validity
# ---------------------------------------------------------------------------


class TestCategoryMappings:
    def test_mitre_ids_valid(self):
        """All MITRE IDs in category mappings exist in the reference."""
        for category in ATTACK_CATEGORIES:
            for mid in map_category_to_mitre(category):
                assert mid in MITRE_ATLAS, f"Category {category} maps to unknown MITRE ID {mid}"

    def test_owasp_llm_ids_valid(self):
        """All OWASP LLM IDs in category mappings exist in the reference."""
        for category in ATTACK_CATEGORIES:
            for oid in map_category_to_owasp(category):
                assert oid in OWASP_LLM_TOP_10, f"Category {category} maps to unknown OWASP LLM ID {oid}"

    def test_owasp_agentic_ids_valid(self):
        """All OWASP Agentic IDs in category mappings exist in the reference."""
        for category in ATTACK_CATEGORIES:
            for aid in map_category_to_owasp_agentic(category):
                assert aid in OWASP_AGENTIC_TOP_10, f"Category {category} maps to unknown OWASP Agentic ID {aid}"

    def test_all_categories_have_mitre(self):
        """Every category has at least one MITRE mapping."""
        for category in ATTACK_CATEGORIES:
            assert len(map_category_to_mitre(category)) > 0, f"Category {category} has no MITRE mapping"

    def test_all_categories_have_owasp(self):
        """Every category has at least one OWASP LLM mapping."""
        for category in ATTACK_CATEGORIES:
            assert len(map_category_to_owasp(category)) > 0, f"Category {category} has no OWASP LLM mapping"

    def test_all_categories_have_agentic(self):
        """Every category has at least one OWASP Agentic mapping."""
        for category in ATTACK_CATEGORIES:
            assert len(map_category_to_owasp_agentic(category)) > 0, f"Category {category} has no OWASP Agentic mapping"


# ---------------------------------------------------------------------------
# Family Mappings
# ---------------------------------------------------------------------------


class TestFamilyMappings:
    TWEEK_FAMILIES = [
        "credential_theft",
        "prompt_injection",
        "data_exfiltration",
        "privilege_escalation",
        "code_injection",
        "evasion_techniques",
        "mcp_attacks",
        "persistence",
        "sandbox_escape",
        "supply_chain",
        "system_recon",
        "path_traversal",
        "destructive_ops",
        "covert_channels",
    ]

    def test_all_families_have_category(self):
        for family in self.TWEEK_FAMILIES:
            assert family in FAMILY_TO_CATEGORY, f"Family {family} missing from FAMILY_TO_CATEGORY"

    def test_all_families_have_surface(self):
        for family in self.TWEEK_FAMILIES:
            assert family in FAMILY_TO_SURFACE, f"Family {family} missing from FAMILY_TO_SURFACE"

    def test_all_families_have_target(self):
        for family in self.TWEEK_FAMILIES:
            assert family in FAMILY_TO_TARGET, f"Family {family} missing from FAMILY_TO_TARGET"

    def test_category_values_valid(self):
        """All family->category mappings produce valid CTAP categories."""
        for family in self.TWEEK_FAMILIES:
            category = map_family_to_category(family)
            assert category in ATTACK_CATEGORIES, f"Family {family} maps to unknown category {category}"

    def test_exact_matches(self):
        """Families that match CTAP categories exactly."""
        assert map_family_to_category("credential_theft") == "credential_theft"
        assert map_family_to_category("prompt_injection") == "prompt_injection"
        assert map_family_to_category("data_exfiltration") == "data_exfiltration"
        assert map_family_to_category("privilege_escalation") == "privilege_escalation"

    def test_translated_matches(self):
        """Families that translate to different CTAP categories."""
        assert map_family_to_category("code_injection") == "code_security"
        assert map_family_to_category("evasion_techniques") == "encoding_evasion"
        assert map_family_to_category("mcp_attacks") == "tool_abuse"

    def test_unknown_family_defaults(self):
        """Unknown families get a sensible default."""
        assert map_family_to_category("nonexistent") == "tool_abuse"
        assert map_family_to_surface("nonexistent") == "tool_use"
        assert map_family_to_target("nonexistent") == "agent"


# ---------------------------------------------------------------------------
# Surface Mappings
# ---------------------------------------------------------------------------


class TestSurfaceMappings:
    def test_all_surfaces_have_asi(self):
        for surface in SURFACE_TO_ASI:
            ids = map_surface_to_asi(surface)
            assert len(ids) > 0, f"Surface {surface} has no ASI mapping"

    def test_asi_ids_valid(self):
        for surface, ids in SURFACE_TO_ASI.items():
            for aid in ids:
                assert aid in OWASP_AGENTIC_TOP_10, f"Surface {surface} maps to unknown ASI ID {aid}"


# ---------------------------------------------------------------------------
# Round-Trip: Family → Category → Taxonomy IDs
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_family_to_mitre_round_trip(self):
        """Every Tweek family produces non-empty MITRE IDs via category."""
        for family in FAMILY_TO_CATEGORY:
            category = map_family_to_category(family)
            mitre = map_category_to_mitre(category)
            assert len(mitre) > 0, f"Family {family} → category {category} has no MITRE IDs"

    def test_family_to_owasp_round_trip(self):
        """Every Tweek family produces non-empty OWASP LLM IDs via category."""
        for family in FAMILY_TO_CATEGORY:
            category = map_family_to_category(family)
            owasp = map_category_to_owasp(category)
            assert len(owasp) > 0, f"Family {family} → category {category} has no OWASP LLM IDs"

    def test_family_to_agentic_round_trip(self):
        """Every Tweek family produces non-empty OWASP Agentic IDs via category."""
        for family in FAMILY_TO_CATEGORY:
            category = map_family_to_category(family)
            agentic = map_category_to_owasp_agentic(category)
            assert len(agentic) > 0, f"Family {family} → category {category} has no OWASP Agentic IDs"
