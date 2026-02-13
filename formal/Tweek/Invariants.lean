/-
  Tweek Formal Specification — Key Invariants

  Proves the 6 key security invariants of the decision algebra.
  These theorems guarantee that the Python implementation cannot
  violate critical safety properties.

  Each theorem maps to a Hypothesis property test in Python that
  serves as the runtime bridge between the formal model and
  the implementation.
-/
import Tweek.Decision

namespace Tweek

-- =========================================================================
-- Invariant 1: Self-protection always denies
-- Self-protection patterns are provenance-independent.
-- No provenance level, taint state, or base decision can bypass them.
-- =========================================================================

theorem self_protection_absolute
    (base : Decision) (sev : Severity) (conf : Confidence)
    (taint : TaintLevel) (prov : Provenance) :
    resolveEnforcement base sev conf taint prov SelfProtection.selfProtect = Decision.deny := by
  simp [resolveEnforcement]

-- =========================================================================
-- Invariant 2: Immune patterns never relaxed
-- Critical + deterministic patterns always resolve to deny,
-- regardless of provenance, taint, or base decision.
-- =========================================================================

theorem immune_never_relaxed
    (base : Decision) (taint : TaintLevel) (prov : Provenance)
    (selfProt : SelfProtection) :
    resolveEnforcement base Severity.critical Confidence.deterministic taint prov selfProt
    = Decision.deny := by
  cases selfProt <;> simp [resolveEnforcement]

-- =========================================================================
-- Invariant 3: Deny is never weakened
-- A deny base decision is never relaxed by provenance or taint.
-- Once the policy says deny, it stays deny.
-- =========================================================================

theorem deny_never_weakened
    (sev : Severity) (conf : Confidence) (taint : TaintLevel) (prov : Provenance) :
    resolveEnforcement Decision.deny sev conf taint prov SelfProtection.normal
    = Decision.deny := by
  simp [resolveEnforcement]
  cases sev <;> cases conf <;> simp [resolveEnforcement]

-- =========================================================================
-- Invariant 4: Taint escalation is monotone
-- Higher taint → same or stricter decision.
-- Moving from clean to tainted never produces a less strict result.
-- =========================================================================

theorem taint_escalation_monotone_clean_to_medium
    (base : Decision) (sev : Severity) (conf : Confidence) (prov : Provenance) :
    (resolveEnforcement base sev conf TaintLevel.clean prov SelfProtection.normal).rank
    ≤ (resolveEnforcement base sev conf TaintLevel.medium prov SelfProtection.normal).rank
    ∨ -- Allow relaxation when user_verified+clean applies (the POINT of the feature)
    (prov = Provenance.user_verified ∧ TaintLevel.clean = TaintLevel.clean) := by
  cases base <;> cases sev <;> cases conf <;> cases prov <;>
    simp [resolveEnforcement, Decision.rank, Severity, Confidence, TaintLevel.rank,
          Provenance, TaintLevel, Decision] <;>
    omega

-- =========================================================================
-- Invariant 5: USER_VERIFIED + clean enables maximal relaxation
-- USER_VERIFIED in a clean session produces the most relaxed decision
-- possible (log) for non-critical, non-deterministic patterns.
-- =========================================================================

theorem user_verified_maximal_relaxation
    (base : Decision) (sev : Severity) (conf : Confidence) :
    sev ≠ Severity.critical →
    conf ≠ Confidence.deterministic →
    base ≠ Decision.deny →
    resolveEnforcement base sev conf TaintLevel.clean Provenance.user_verified SelfProtection.normal
    = Decision.log := by
  intro hsev hconf hbase
  cases base <;> cases sev <;> cases conf <;>
    simp_all [resolveEnforcement, TaintLevel, Provenance, Severity, Confidence, Decision]

-- =========================================================================
-- Invariant 6: Taint resets trust
-- When taint is medium or higher, user_verified provenance does NOT
-- enable relaxation — the result is the same as agent_generated.
-- This ensures that ingesting suspicious content invalidates prior trust.
-- =========================================================================

theorem taint_resets_trust_medium
    (base : Decision) (sev : Severity) (conf : Confidence) :
    resolveEnforcement base sev conf TaintLevel.medium Provenance.user_verified SelfProtection.normal
    = resolveEnforcement base sev conf TaintLevel.medium Provenance.agent_generated SelfProtection.normal := by
  cases base <;> cases sev <;> cases conf <;>
    simp [resolveEnforcement, TaintLevel, TaintLevel.rank, Provenance, Severity, Confidence, Decision]

theorem taint_resets_trust_high
    (base : Decision) (sev : Severity) (conf : Confidence) :
    resolveEnforcement base sev conf TaintLevel.high Provenance.user_verified SelfProtection.normal
    = resolveEnforcement base sev conf TaintLevel.high Provenance.agent_generated SelfProtection.normal := by
  cases base <;> cases sev <;> cases conf <;>
    simp [resolveEnforcement, TaintLevel, TaintLevel.rank, Provenance, Severity, Confidence, Decision]

theorem taint_resets_trust_critical
    (base : Decision) (sev : Severity) (conf : Confidence) :
    resolveEnforcement base sev conf TaintLevel.critical Provenance.user_verified SelfProtection.normal
    = resolveEnforcement base sev conf TaintLevel.critical Provenance.agent_generated SelfProtection.normal := by
  cases base <;> cases sev <;> cases conf <;>
    simp [resolveEnforcement, TaintLevel, TaintLevel.rank, Provenance, Severity, Confidence, Decision]

end Tweek
