"""
Tests for Tweek graduated security enforcement (R1/R2/R3).

Validates:
- R1: _resolve_enforcement() produces correct deny/ask/log decisions
- R2: All 262 patterns in patterns.yaml have a valid confidence field
- R3: EnforcementPolicy class — default matrix, custom config, merge
"""

import sys
from pathlib import Path

import yaml
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

pytestmark = pytest.mark.security

from tweek.hooks.overrides import (
    EnforcementPolicy,
    DECISION_RANK,
)


# =========================================================================
# R3: EnforcementPolicy — default matrix
# =========================================================================


class TestEnforcementPolicyDefaults:
    """Default matrix: critical+det=deny, low=log, everything else=ask."""

    def test_critical_deterministic_deny(self):
        policy = EnforcementPolicy()
        assert policy.resolve("critical", "deterministic") == "deny"

    def test_critical_heuristic_ask(self):
        policy = EnforcementPolicy()
        assert policy.resolve("critical", "heuristic") == "ask"

    def test_critical_contextual_ask(self):
        policy = EnforcementPolicy()
        assert policy.resolve("critical", "contextual") == "ask"

    def test_high_deterministic_ask(self):
        policy = EnforcementPolicy()
        assert policy.resolve("high", "deterministic") == "ask"

    def test_high_heuristic_ask(self):
        policy = EnforcementPolicy()
        assert policy.resolve("high", "heuristic") == "ask"

    def test_high_contextual_ask(self):
        policy = EnforcementPolicy()
        assert policy.resolve("high", "contextual") == "ask"

    def test_medium_all_ask(self):
        policy = EnforcementPolicy()
        for conf in ("deterministic", "heuristic", "contextual"):
            assert policy.resolve("medium", conf) == "ask"

    def test_low_all_log(self):
        policy = EnforcementPolicy()
        for conf in ("deterministic", "heuristic", "contextual"):
            assert policy.resolve("low", conf) == "log"


# =========================================================================
# R3: EnforcementPolicy — unknown inputs fallback
# =========================================================================


class TestEnforcementPolicyFallbacks:
    """Unknown severity or confidence should fall back gracefully."""

    def test_unknown_severity_falls_back_to_medium(self):
        policy = EnforcementPolicy()
        # Unknown severity defaults to medium row (all "ask")
        assert policy.resolve("unknown", "deterministic") == "ask"

    def test_unknown_confidence_falls_back_to_ask(self):
        policy = EnforcementPolicy()
        assert policy.resolve("critical", "unknown") == "ask"

    def test_both_unknown_falls_back_to_ask(self):
        policy = EnforcementPolicy()
        assert policy.resolve("unknown", "unknown") == "ask"

    def test_empty_string_severity(self):
        policy = EnforcementPolicy()
        assert policy.resolve("", "deterministic") == "ask"


# =========================================================================
# R3: EnforcementPolicy — custom config merge
# =========================================================================


class TestEnforcementPolicyCustomConfig:
    """Custom enforcement config merges with defaults."""

    def test_override_single_cell(self):
        config = {"critical": {"heuristic": "deny"}}
        policy = EnforcementPolicy(config)
        # Overridden cell
        assert policy.resolve("critical", "heuristic") == "deny"
        # Untouched cells retain defaults
        assert policy.resolve("critical", "deterministic") == "deny"
        assert policy.resolve("low", "heuristic") == "log"

    def test_override_entire_severity(self):
        config = {
            "high": {
                "deterministic": "deny",
                "heuristic": "deny",
                "contextual": "ask",
            }
        }
        policy = EnforcementPolicy(config)
        assert policy.resolve("high", "deterministic") == "deny"
        assert policy.resolve("high", "heuristic") == "deny"
        assert policy.resolve("high", "contextual") == "ask"

    def test_invalid_decision_ignored(self):
        config = {"critical": {"deterministic": "nuke"}}
        policy = EnforcementPolicy(config)
        # Invalid value "nuke" is ignored, default "deny" preserved
        assert policy.resolve("critical", "deterministic") == "deny"

    def test_empty_config_produces_defaults(self):
        policy = EnforcementPolicy({})
        assert policy.resolve("critical", "deterministic") == "deny"
        assert policy.resolve("low", "contextual") == "log"

    def test_none_config_produces_defaults(self):
        policy = EnforcementPolicy(None)
        assert policy.resolve("critical", "deterministic") == "deny"


# =========================================================================
# R3: EnforcementPolicy — stricter_decision()
# =========================================================================


class TestStricterDecision:
    """stricter_decision returns the higher-rank decision."""

    def test_deny_beats_ask(self):
        assert EnforcementPolicy.stricter_decision("deny", "ask") == "deny"

    def test_deny_beats_log(self):
        assert EnforcementPolicy.stricter_decision("deny", "log") == "deny"

    def test_ask_beats_log(self):
        assert EnforcementPolicy.stricter_decision("ask", "log") == "ask"

    def test_same_returns_same(self):
        for d in ("deny", "ask", "log"):
            assert EnforcementPolicy.stricter_decision(d, d) == d

    def test_order_irrelevant(self):
        assert EnforcementPolicy.stricter_decision("log", "deny") == "deny"
        assert EnforcementPolicy.stricter_decision("log", "ask") == "ask"


# =========================================================================
# R3: EnforcementPolicy — merge_additive_only()
# =========================================================================


class TestMergeAdditiveOnly:
    """Project policy can only escalate decisions, never downgrade."""

    def test_project_escalation_applied(self):
        """Project can escalate low log -> ask."""
        global_policy = EnforcementPolicy()
        project_config = {"low": {"deterministic": "ask"}}
        project_policy = EnforcementPolicy(project_config)
        merged = EnforcementPolicy.merge_additive_only(global_policy, project_policy)
        assert merged.resolve("low", "deterministic") == "ask"

    def test_project_downgrade_rejected(self):
        """Project cannot downgrade critical deny -> log."""
        global_policy = EnforcementPolicy()
        project_config = {"critical": {"deterministic": "log"}}
        project_policy = EnforcementPolicy(project_config)
        merged = EnforcementPolicy.merge_additive_only(global_policy, project_policy)
        # Global "deny" wins because it's stricter
        assert merged.resolve("critical", "deterministic") == "deny"

    def test_project_same_decision_preserved(self):
        """When both agree, the shared decision is kept."""
        global_policy = EnforcementPolicy()
        project_policy = EnforcementPolicy()
        merged = EnforcementPolicy.merge_additive_only(global_policy, project_policy)
        assert merged.resolve("high", "heuristic") == "ask"

    def test_full_matrix_only_escalated(self):
        """Project that tries to loosen everything still gets global's strictness."""
        global_policy = EnforcementPolicy()
        loosen_all = {
            sev: {conf: "log" for conf in EnforcementPolicy.VALID_CONFIDENCES}
            for sev in EnforcementPolicy.VALID_SEVERITIES
        }
        project_policy = EnforcementPolicy(loosen_all)
        merged = EnforcementPolicy.merge_additive_only(global_policy, project_policy)
        # Global's defaults are stricter everywhere except low (which is already log)
        assert merged.resolve("critical", "deterministic") == "deny"
        assert merged.resolve("critical", "heuristic") == "ask"
        assert merged.resolve("high", "deterministic") == "ask"
        assert merged.resolve("low", "heuristic") == "log"


# =========================================================================
# R3: DECISION_RANK constant
# =========================================================================


class TestDecisionRank:
    """DECISION_RANK ordering: log < ask < deny."""

    def test_rank_ordering(self):
        assert DECISION_RANK["log"] < DECISION_RANK["ask"]
        assert DECISION_RANK["ask"] < DECISION_RANK["deny"]

    def test_all_decisions_present(self):
        assert set(DECISION_RANK.keys()) == {"log", "ask", "deny"}


# =========================================================================
# R1: _resolve_enforcement() — graduated decisions
# =========================================================================


class TestResolveEnforcement:
    """Test _resolve_enforcement logic for the severity+confidence matrix.

    Since _resolve_enforcement references _log (a closure from process_hook),
    we monkeypatch break_glass.check_override to return None so the _log
    path is never reached.
    """

    @pytest.fixture(autouse=True)
    def isolate_break_glass(self, monkeypatch, tmp_path):
        """Ensure no break-glass overrides interfere with tests."""
        from tweek.hooks import break_glass
        monkeypatch.setattr(break_glass, "BREAK_GLASS_PATH", tmp_path / "bg.json")

    def _resolve(self, pattern_match, policy=None, has_non_pattern=False):
        from tweek.hooks.pre_tool_use import _resolve_enforcement
        return _resolve_enforcement(pattern_match, policy, has_non_pattern)

    def test_critical_deterministic_deny(self):
        match = {"severity": "critical", "confidence": "deterministic", "name": "ssh_key_read"}
        assert self._resolve(match, EnforcementPolicy()) == "deny"

    def test_critical_heuristic_ask(self):
        match = {"severity": "critical", "confidence": "heuristic", "name": "test"}
        assert self._resolve(match, EnforcementPolicy()) == "ask"

    def test_high_deterministic_ask(self):
        match = {"severity": "high", "confidence": "deterministic", "name": "test"}
        assert self._resolve(match, EnforcementPolicy()) == "ask"

    def test_low_any_confidence_log(self):
        for conf in ("deterministic", "heuristic", "contextual"):
            match = {"severity": "low", "confidence": conf, "name": "test"}
            assert self._resolve(match, EnforcementPolicy()) == "log"

    def test_no_pattern_no_trigger_log(self):
        """No pattern match and no non-pattern trigger -> log (silent allow)."""
        assert self._resolve(None, EnforcementPolicy(), has_non_pattern=False) == "log"

    def test_no_pattern_with_non_pattern_trigger_ask(self):
        """No pattern match but LLM/session triggered -> ask."""
        assert self._resolve(None, EnforcementPolicy(), has_non_pattern=True) == "ask"

    def test_missing_confidence_defaults_to_heuristic(self):
        """Pattern without confidence field defaults to 'heuristic'."""
        match = {"severity": "critical", "name": "test"}
        assert self._resolve(match, EnforcementPolicy()) == "ask"

    def test_missing_severity_defaults_to_medium(self):
        """Pattern without severity field defaults to 'medium'."""
        match = {"confidence": "deterministic", "name": "test"}
        assert self._resolve(match, EnforcementPolicy()) == "ask"

    def test_fallback_without_policy_critical_deterministic(self):
        """Fallback logic when enforcement_policy is None."""
        match = {"severity": "critical", "confidence": "deterministic", "name": "test"}
        assert self._resolve(match, None) == "deny"

    def test_fallback_without_policy_low(self):
        match = {"severity": "low", "confidence": "heuristic", "name": "test"}
        assert self._resolve(match, None) == "log"

    def test_fallback_without_policy_medium(self):
        match = {"severity": "medium", "confidence": "heuristic", "name": "test"}
        assert self._resolve(match, None) == "ask"

    def test_custom_policy_overrides_default(self):
        """Custom policy: escalate high+deterministic to deny."""
        config = {"high": {"deterministic": "deny"}}
        policy = EnforcementPolicy(config)
        match = {"severity": "high", "confidence": "deterministic", "name": "test"}
        assert self._resolve(match, policy) == "deny"


# =========================================================================
# R1: _resolve_enforcement() — break-glass integration
# =========================================================================


class TestResolveEnforcementBreakGlass:
    """Test that break-glass downgrades deny -> ask."""

    @pytest.fixture(autouse=True)
    def isolate_break_glass(self, monkeypatch, tmp_path):
        """Redirect break-glass state to temp dir."""
        from tweek.hooks import break_glass
        self._bg_path = tmp_path / "bg.json"
        monkeypatch.setattr(break_glass, "BREAK_GLASS_PATH", self._bg_path)

    @pytest.fixture(autouse=True)
    def inject_log(self, monkeypatch):
        """Inject a no-op _log into pre_tool_use module scope so break-glass
        path doesn't crash with NameError."""
        import tweek.hooks.pre_tool_use as ptu
        # _log is normally a closure, inject a module-level fallback
        monkeypatch.setattr(ptu, "_log", lambda *a, **kw: None, raising=False)

    def test_break_glass_downgrades_deny_to_ask(self):
        from tweek.hooks.break_glass import create_override
        from tweek.hooks.pre_tool_use import _resolve_enforcement

        create_override(pattern_name="ssh_key_read", mode="once", reason="migration")

        match = {"severity": "critical", "confidence": "deterministic", "name": "ssh_key_read"}
        result = _resolve_enforcement(match, EnforcementPolicy())
        assert result == "ask"

    def test_no_break_glass_keeps_deny(self):
        from tweek.hooks.pre_tool_use import _resolve_enforcement

        match = {"severity": "critical", "confidence": "deterministic", "name": "ssh_key_read"}
        result = _resolve_enforcement(match, EnforcementPolicy())
        assert result == "deny"

    def test_break_glass_consumed_after_use(self):
        from tweek.hooks.break_glass import create_override
        from tweek.hooks.pre_tool_use import _resolve_enforcement

        create_override(pattern_name="ssh_key_read", mode="once", reason="one-time")

        match = {"severity": "critical", "confidence": "deterministic", "name": "ssh_key_read"}
        # First call: override active -> ask
        assert _resolve_enforcement(match, EnforcementPolicy()) == "ask"
        # Second call: override consumed -> deny
        assert _resolve_enforcement(match, EnforcementPolicy()) == "deny"

    def test_break_glass_only_affects_deny(self):
        """Break-glass has no effect on 'ask' decisions."""
        from tweek.hooks.break_glass import create_override
        from tweek.hooks.pre_tool_use import _resolve_enforcement

        create_override(pattern_name="test_pattern", mode="once", reason="test")

        match = {"severity": "high", "confidence": "heuristic", "name": "test_pattern"}
        # high+heuristic = "ask" by default, break-glass doesn't change it
        assert _resolve_enforcement(match, EnforcementPolicy()) == "ask"


# =========================================================================
# R2: Pattern confidence field validation
# =========================================================================


class TestPatternConfidenceClassification:
    """Every pattern in patterns.yaml must have a valid confidence field."""

    @pytest.fixture(scope="class")
    def patterns(self):
        patterns_path = Path(__file__).parent.parent / "tweek" / "config" / "patterns.yaml"
        with open(patterns_path) as f:
            data = yaml.safe_load(f)
        return data.get("patterns", [])

    def test_all_patterns_have_confidence(self, patterns):
        missing = [p["name"] for p in patterns if "confidence" not in p]
        assert missing == [], f"Patterns missing confidence field: {missing}"

    def test_confidence_values_valid(self, patterns):
        valid = {"deterministic", "heuristic", "contextual"}
        invalid = [
            (p["name"], p.get("confidence"))
            for p in patterns
            if p.get("confidence") not in valid
        ]
        assert invalid == [], f"Patterns with invalid confidence: {invalid}"

    def test_at_least_one_deterministic(self, patterns):
        det = [p for p in patterns if p.get("confidence") == "deterministic"]
        assert len(det) > 0, "Expected at least one deterministic pattern"

    def test_at_least_one_heuristic(self, patterns):
        heu = [p for p in patterns if p.get("confidence") == "heuristic"]
        assert len(heu) > 0, "Expected at least one heuristic pattern"

    def test_at_least_one_contextual(self, patterns):
        ctx = [p for p in patterns if p.get("confidence") == "contextual"]
        assert len(ctx) > 0, "Expected at least one contextual pattern"

    def test_total_pattern_count(self, patterns):
        """Sanity check: we expect ~262 patterns (allow some tolerance for additions)."""
        assert len(patterns) >= 200, f"Expected 200+ patterns, got {len(patterns)}"

    def test_critical_deterministic_patterns_exist(self, patterns):
        """At least some CRITICAL patterns should be deterministic (key for R1 deny)."""
        crit_det = [
            p["name"] for p in patterns
            if p.get("severity") == "critical" and p.get("confidence") == "deterministic"
        ]
        assert len(crit_det) >= 5, (
            f"Expected at least 5 critical+deterministic patterns, got {len(crit_det)}: {crit_det}"
        )

    def test_all_patterns_have_required_fields(self, patterns):
        required = {"id", "name", "description", "regex", "severity", "confidence"}
        for p in patterns:
            missing = required - set(p.keys())
            assert missing == set(), (
                f"Pattern '{p.get('name', 'UNKNOWN')}' missing fields: {missing}"
            )


# =========================================================================
# R3: SecurityOverrides.get_enforcement_policy()
# =========================================================================


class TestSecurityOverridesEnforcement:
    """SecurityOverrides.get_enforcement_policy() returns correct policy."""

    def test_empty_config_returns_default_policy(self):
        from tweek.hooks.overrides import SecurityOverrides
        overrides = SecurityOverrides.__new__(SecurityOverrides)
        overrides.config = {}
        overrides.path = None
        policy = overrides.get_enforcement_policy()
        assert isinstance(policy, EnforcementPolicy)
        assert policy.resolve("critical", "deterministic") == "deny"

    def test_config_with_enforcement_section(self):
        from tweek.hooks.overrides import SecurityOverrides
        overrides = SecurityOverrides.__new__(SecurityOverrides)
        overrides.config = {
            "enforcement": {
                "high": {"deterministic": "deny"},
            }
        }
        overrides.path = None
        policy = overrides.get_enforcement_policy()
        assert policy.resolve("high", "deterministic") == "deny"
        # Default cells still work
        assert policy.resolve("low", "heuristic") == "log"
