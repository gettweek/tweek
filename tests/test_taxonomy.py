"""Tests for tweek.config.taxonomy — CTAP-compatible taxonomy mappings."""

from __future__ import annotations

import pytest

from tweek.config.taxonomy import (
    AGENTIC_THREATS,
    ATTACK_CATEGORIES,
    CATEGORY_TO_THREAT,
    FAMILY_TO_CATEGORY,
    FAMILY_TO_SURFACE,
    FAMILY_TO_TARGET,
    MITRE_ATLAS,
    OWASP_AGENTIC_TOP_10,
    OWASP_LLM_TOP_10,
    SURFACE_TO_ASI,
    THREAT_TO_RISK,
    map_category_to_mitre,
    map_category_to_owasp,
    map_category_to_owasp_agentic,
    map_category_to_risk,
    map_category_to_threat,
    map_family_to_category,
    map_family_to_surface,
    map_family_to_target,
    map_surface_to_asi,
    map_threat_to_risk,
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


# ---------------------------------------------------------------------------
# Tier 2: Agentic Threats (T01-T17)
# ---------------------------------------------------------------------------


class TestAgenticThreats:
    def test_count(self):
        assert len(AGENTIC_THREATS) == 17

    def test_id_format(self):
        for tid in AGENTIC_THREATS:
            assert tid.startswith("T"), f"Invalid threat ID: {tid}"
            num = int(tid[1:])
            assert 1 <= num <= 17, f"Threat ID out of range: {tid}"

    def test_all_have_required_fields(self):
        for tid, info in AGENTIC_THREATS.items():
            assert "name" in info, f"Threat {tid} missing name"
            assert "description" in info, f"Threat {tid} missing description"
            assert "parent_risk" in info, f"Threat {tid} missing parent_risk"

    def test_parent_risks_valid(self):
        """Every threat's parent_risk references an existing ASI risk."""
        for tid, info in AGENTIC_THREATS.items():
            assert info["parent_risk"] in OWASP_AGENTIC_TOP_10, (
                f"Threat {tid} parent_risk {info['parent_risk']} not in OWASP Agentic Top 10"
            )

    def test_threat_to_risk_derived_correctly(self):
        """THREAT_TO_RISK matches parent_risk field in AGENTIC_THREATS."""
        for tid, info in AGENTIC_THREATS.items():
            assert THREAT_TO_RISK[tid] == info["parent_risk"], (
                f"THREAT_TO_RISK[{tid}] = {THREAT_TO_RISK[tid]} != {info['parent_risk']}"
            )


# ---------------------------------------------------------------------------
# Three-Tier Total Function Chain: Category → Threat → Risk
# ---------------------------------------------------------------------------


class TestThreeTierChain:
    """Validates the three-tier total function chain matching crab-trap oracle."""

    def test_category_to_threat_is_total(self):
        """Every ATTACK_CATEGORY has a mapping in CATEGORY_TO_THREAT."""
        for category in ATTACK_CATEGORIES:
            assert category in CATEGORY_TO_THREAT, (
                f"Category {category} missing from CATEGORY_TO_THREAT (not total)"
            )

    def test_threat_to_risk_is_total(self):
        """Every AGENTIC_THREAT has a mapping in THREAT_TO_RISK."""
        for tid in AGENTIC_THREATS:
            assert tid in THREAT_TO_RISK, (
                f"Threat {tid} missing from THREAT_TO_RISK (not total)"
            )

    def test_category_to_threat_values_valid(self):
        """Every category maps to a valid threat ID (T01-T17)."""
        for category, tid in CATEGORY_TO_THREAT.items():
            assert tid in AGENTIC_THREATS, (
                f"Category {category} maps to unknown threat {tid}"
            )

    def test_threat_to_risk_values_valid(self):
        """Every threat maps to a valid ASI risk (ASI01-ASI10)."""
        for tid, risk in THREAT_TO_RISK.items():
            assert risk in OWASP_AGENTIC_TOP_10, (
                f"Threat {tid} maps to unknown risk {risk}"
            )

    def test_composition_is_total(self):
        """Category → Threat → Risk composition works for all categories."""
        for category in ATTACK_CATEGORIES:
            risk = map_category_to_risk(category)
            assert risk is not None, (
                f"Category {category} has no composed risk mapping"
            )
            assert risk in OWASP_AGENTIC_TOP_10, (
                f"Category {category} → risk {risk} not in OWASP Agentic Top 10"
            )

    def test_composition_matches_manual(self):
        """Composed result equals manual chaining."""
        for category in ATTACK_CATEGORIES:
            threat = map_category_to_threat(category)
            risk_via_threat = map_threat_to_risk(threat)
            risk_composed = map_category_to_risk(category)
            assert risk_via_threat == risk_composed, (
                f"Category {category}: manual chain {risk_via_threat} != composed {risk_composed}"
            )

    def test_all_risks_reachable(self):
        """At least 7 of 10 ASI risks are reachable from attack categories.

        Unreachable risks (via current categories):
        - ASI08 (Cascading Failures): only via T07/T15 (no category maps there)
        - ASI09 (Human-Agent Trust Exploit): only via T12 (no category)
        - ASI10 (Rogue Agents): only via T14 (no category)
        These are still reachable via the many-to-many _CATEGORY_TO_OWASP_AGENTIC.
        """
        reachable = set()
        for category in ATTACK_CATEGORIES:
            risk = map_category_to_risk(category)
            if risk:
                reachable.add(risk)
        assert len(reachable) >= 7, (
            f"Only {len(reachable)}/10 risks reachable: {sorted(reachable)}"
        )


# ---------------------------------------------------------------------------
# Three-Tier Lookup Helpers
# ---------------------------------------------------------------------------


class TestThreeTierHelpers:
    def test_map_category_to_threat_known(self):
        assert map_category_to_threat("prompt_injection") == "T01"
        assert map_category_to_threat("credential_theft") == "T04"
        assert map_category_to_threat("supply_chain_attack") == "T16"

    def test_map_category_to_threat_unknown(self):
        assert map_category_to_threat("nonexistent") is None

    def test_map_threat_to_risk_known(self):
        assert map_threat_to_risk("T01") == "ASI01"
        assert map_threat_to_risk("T04") == "ASI03"
        assert map_threat_to_risk("T16") == "ASI04"

    def test_map_threat_to_risk_unknown(self):
        assert map_threat_to_risk("T99") is None

    def test_map_category_to_risk_known(self):
        # prompt_injection → T01 → ASI01
        assert map_category_to_risk("prompt_injection") == "ASI01"
        # credential_theft → T04 → ASI03
        assert map_category_to_risk("credential_theft") == "ASI03"
        # code_security → T17 → ASI05
        assert map_category_to_risk("code_security") == "ASI05"

    def test_map_category_to_risk_unknown(self):
        assert map_category_to_risk("nonexistent") is None


# ---------------------------------------------------------------------------
# Cross-Repository Alignment: Tweek ↔ crab-trap
# ---------------------------------------------------------------------------


class TestCrabTrapAlignment:
    """Verify Tweek's taxonomy matches the crab-trap oracle.

    These are the key mappings that MUST stay in sync.
    If crab-trap changes its taxonomy, these tests catch the drift.
    """

    # Expected mappings from crab-trap oracle (Threat.lean)
    CRAB_TRAP_CATEGORY_TO_THREAT = {
        "credential_theft": "T04",
        "prompt_injection": "T01",
        "tool_abuse": "T10",
        "skill_injection": "T10",
        "data_exfiltration": "T02",
        "privilege_escalation": "T05",
        "social_engineering": "T09",
        "encoding_evasion": "T01",
        "context_overflow": "T08",
        "multi_turn_manipulation": "T13",
        "code_security": "T17",
        "rag_poisoning": "T08",
        "return_injection": "T10",
        "serialization_attack": "T17",
        "supply_chain_attack": "T16",
        "approval_bypass": "T06",
        "multimodal_injection": "T01",
    }

    CRAB_TRAP_THREAT_TO_RISK = {
        "T01": "ASI01", "T02": "ASI01", "T03": "ASI02",
        "T04": "ASI03", "T05": "ASI03", "T06": "ASI02",
        "T07": "ASI08", "T08": "ASI06", "T09": "ASI07",
        "T10": "ASI02", "T11": "ASI03", "T12": "ASI09",
        "T13": "ASI07", "T14": "ASI10", "T15": "ASI08",
        "T16": "ASI04", "T17": "ASI05",
    }

    def test_category_to_threat_matches_crab_trap(self):
        """CATEGORY_TO_THREAT exactly matches crab-trap oracle."""
        for cat, expected_threat in self.CRAB_TRAP_CATEGORY_TO_THREAT.items():
            actual = CATEGORY_TO_THREAT.get(cat)
            assert actual == expected_threat, (
                f"DRIFT: {cat} → {actual} (tweek) vs {expected_threat} (crab-trap)"
            )

    def test_threat_to_risk_matches_crab_trap(self):
        """THREAT_TO_RISK exactly matches crab-trap oracle."""
        for threat, expected_risk in self.CRAB_TRAP_THREAT_TO_RISK.items():
            actual = THREAT_TO_RISK.get(threat)
            assert actual == expected_risk, (
                f"DRIFT: {threat} → {actual} (tweek) vs {expected_risk} (crab-trap)"
            )
