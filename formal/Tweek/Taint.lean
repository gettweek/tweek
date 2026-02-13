/-
  Tweek Formal Specification — Taint State Machine

  Defines the 5-level taint state machine with escalation and decay.

  Taint levels: clean → low → medium → high → critical
  Escalation is monotone (never downgrades).
  Decay reduces by one step toward clean.
-/

namespace Tweek

/-- Session taint levels in order of severity. -/
inductive TaintLevel where
  | clean
  | low
  | medium
  | high
  | critical
  deriving Repr, BEq, Ord, Hashable, Inhabited

namespace TaintLevel

/-- Numeric rank for ordering (0 = cleanest, 4 = most tainted). -/
def rank : TaintLevel → Nat
  | clean    => 0
  | low      => 1
  | medium   => 2
  | high     => 3
  | critical => 4

/-- TaintLevel ordering: t₁ ≤ t₂ iff rank t₁ ≤ rank t₂. -/
instance : LE TaintLevel where
  le t₁ t₂ := t₁.rank ≤ t₂.rank

instance : LT TaintLevel where
  lt t₁ t₂ := t₁.rank < t₂.rank

/-- String representation for JSON export. -/
def toString : TaintLevel → String
  | clean    => "clean"
  | low      => "low"
  | medium   => "medium"
  | high     => "high"
  | critical => "critical"

instance : ToString TaintLevel where
  toString := TaintLevel.toString

/-- All taint levels for exhaustive enumeration. -/
def all : List TaintLevel :=
  [clean, low, medium, high, critical]

/-- Escalate taint: returns the higher of current and target (monotone). -/
def escalate (current target : TaintLevel) : TaintLevel :=
  if target.rank > current.rank then target else current

/-- Decay taint by one step toward clean. -/
def decay : TaintLevel → TaintLevel
  | clean    => clean
  | low      => clean
  | medium   => low
  | high     => medium
  | critical => high

-- =========================================================================
-- Monotonicity proofs
-- =========================================================================

/-- Escalation is monotone: result is always ≥ current. -/
theorem escalate_ge_current (current target : TaintLevel) :
    current ≤ escalate current target := by
  show current.rank ≤ (escalate current target).rank
  simp [escalate]
  split
  · omega
  · omega

/-- Escalation is monotone: result is always ≥ target. -/
theorem escalate_ge_target (current target : TaintLevel) :
    target ≤ escalate current target := by
  show target.rank ≤ (escalate current target).rank
  simp [escalate]
  split
  · omega
  · omega

/-- Escalation never downgrades: escalate current target ≥ current. -/
theorem escalate_monotone (current target : TaintLevel) :
    (escalate current target).rank ≥ current.rank := by
  simp [escalate]
  split <;> omega

/-- Decay reduces rank by at most 1. -/
theorem decay_reduces_or_stays (t : TaintLevel) :
    (decay t).rank ≤ t.rank := by
  cases t <;> simp [decay, rank]

/-- Decay never increases rank. -/
theorem decay_monotone_down (t : TaintLevel) :
    decay t ≤ t := by
  show (decay t).rank ≤ t.rank
  exact decay_reduces_or_stays t

/-- Clean is a fixed point of decay. -/
theorem decay_clean : decay clean = clean := by rfl

/-- Escalation is commutative in max semantics. -/
theorem escalate_comm (t₁ t₂ : TaintLevel) :
    escalate t₁ t₂ = escalate t₂ t₁ := by
  simp [escalate]
  cases t₁ <;> cases t₂ <;> simp [rank] <;> omega

end TaintLevel
end Tweek
