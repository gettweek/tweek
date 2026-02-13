/-
  Tweek Formal Specification — Provenance Lattice

  Defines the 6-level provenance lattice that classifies the origin
  of every tool call. Higher levels indicate more trust.

  Lattice (lowest → highest):
    unknown → taint_influenced → skill_context →
    agent_generated → user_initiated → user_verified
-/

namespace Tweek

/-- Action provenance levels ordered by trust (lowest → highest). -/
inductive Provenance where
  | unknown
  | taint_influenced
  | skill_context
  | agent_generated
  | user_initiated
  | user_verified
  deriving Repr, BEq, Ord, Hashable, Inhabited

namespace Provenance

/-- Numeric rank for ordering (0 = least trusted, 5 = most trusted). -/
def rank : Provenance → Nat
  | unknown          => 0
  | taint_influenced => 1
  | skill_context    => 2
  | agent_generated  => 3
  | user_initiated   => 4
  | user_verified    => 5

/-- Provenance ordering: p₁ ≤ p₂ iff rank p₁ ≤ rank p₂. -/
instance : LE Provenance where
  le p₁ p₂ := p₁.rank ≤ p₂.rank

/-- Provenance strict ordering. -/
instance : LT Provenance where
  lt p₁ p₂ := p₁.rank < p₂.rank

/-- Join (least upper bound) in the provenance lattice. -/
def join (p₁ p₂ : Provenance) : Provenance :=
  if p₂.rank ≥ p₁.rank then p₂ else p₁

/-- Meet (greatest lower bound) in the provenance lattice. -/
def meet (p₁ p₂ : Provenance) : Provenance :=
  if p₁.rank ≤ p₂.rank then p₁ else p₂

/-- String representation for JSON export. -/
def toString : Provenance → String
  | unknown          => "unknown"
  | taint_influenced => "taint_influenced"
  | skill_context    => "skill_context"
  | agent_generated  => "agent_generated"
  | user_initiated   => "user_initiated"
  | user_verified    => "user_verified"

instance : ToString Provenance where
  toString := Provenance.toString

/-- All provenance levels for exhaustive enumeration. -/
def all : List Provenance :=
  [unknown, taint_influenced, skill_context, agent_generated, user_initiated, user_verified]

-- =========================================================================
-- Ordering proofs
-- =========================================================================

theorem rank_le_iff (p₁ p₂ : Provenance) : (p₁ ≤ p₂) ↔ p₁.rank ≤ p₂.rank := by
  constructor <;> intro h <;> exact h

theorem unknown_is_bottom (p : Provenance) : unknown ≤ p := by
  show unknown.rank ≤ p.rank
  simp [rank]
  omega

theorem user_verified_is_top (p : Provenance) : p ≤ user_verified := by
  show p.rank ≤ user_verified.rank
  cases p <;> simp [rank] <;> omega

theorem join_comm (p₁ p₂ : Provenance) : join p₁ p₂ = join p₂ p₁ := by
  simp [join]
  cases p₁ <;> cases p₂ <;> simp [rank] <;> omega

theorem meet_comm (p₁ p₂ : Provenance) : meet p₁ p₂ = meet p₂ p₁ := by
  simp [meet]
  cases p₁ <;> cases p₂ <;> simp [rank] <;> omega

end Provenance
end Tweek
