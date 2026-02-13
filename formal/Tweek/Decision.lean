/-
  Tweek Formal Specification — Enforcement Decision Algebra

  Defines the types and functions for enforcement decision resolution.
  This is the core algebra that determines whether a tool call is
  allowed, prompted, or blocked based on pattern severity, confidence,
  taint level, and action provenance.
-/
import Tweek.Provenance
import Tweek.Taint

namespace Tweek

/-- Enforcement decisions ordered by strictness. -/
inductive Decision where
  | log   -- Silent allow (logged)
  | ask   -- Prompt user for confirmation
  | deny  -- Hard block
  deriving Repr, BEq, Ord, Hashable, Inhabited

namespace Decision

def rank : Decision → Nat
  | log  => 0
  | ask  => 1
  | deny => 2

instance : LE Decision where
  le d₁ d₂ := d₁.rank ≤ d₂.rank

def toString : Decision → String
  | log  => "log"
  | ask  => "ask"
  | deny => "deny"

instance : ToString Decision where
  toString := Decision.toString

def all : List Decision := [log, ask, deny]

end Decision

/-- Pattern severity levels. -/
inductive Severity where
  | low
  | medium
  | high
  | critical
  deriving Repr, BEq, Ord, Hashable, Inhabited

namespace Severity

def rank : Severity → Nat
  | low      => 0
  | medium   => 1
  | high     => 2
  | critical => 3

def toString : Severity → String
  | low      => "low"
  | medium   => "medium"
  | high     => "high"
  | critical => "critical"

instance : ToString Severity where
  toString := Severity.toString

def all : List Severity := [low, medium, high, critical]

end Severity

/-- Pattern confidence levels. -/
inductive Confidence where
  | contextual
  | heuristic
  | deterministic
  deriving Repr, BEq, Ord, Hashable, Inhabited

namespace Confidence

def rank : Confidence → Nat
  | contextual    => 0
  | heuristic     => 1
  | deterministic => 2

def toString : Confidence → String
  | contextual    => "contextual"
  | heuristic     => "heuristic"
  | deterministic => "deterministic"

instance : ToString Confidence where
  toString := Confidence.toString

def all : List Confidence := [contextual, heuristic, deterministic]

end Confidence

/-- Whether a pattern is an immune (self-protection) pattern. -/
inductive SelfProtection where
  | normal       -- Regular pattern
  | selfProtect  -- Self-protection pattern (always deny)
  deriving Repr, BEq, Hashable, Inhabited

namespace SelfProtection

def all : List SelfProtection := [normal, selfProtect]

end SelfProtection

-- =========================================================================
-- Core Resolution Function
-- =========================================================================

/--
  Resolve the final enforcement decision given all inputs.

  This function encodes the complete decision algebra:
  1. Self-protection always denies (provenance-independent)
  2. Critical+deterministic always denies (immune patterns)
  3. Deny is never weakened by provenance
  4. In clean sessions with user_verified provenance, relax
     non-critical heuristic/contextual patterns to log
  5. In tainted sessions (medium+), escalate log→ask for
     heuristic patterns with high/critical severity
  6. In critically tainted sessions, escalate everything
-/
def resolveEnforcement
    (base : Decision)
    (severity : Severity)
    (confidence : Confidence)
    (taint : TaintLevel)
    (provenance : Provenance)
    (selfProt : SelfProtection) : Decision :=
  -- Rule 1: Self-protection always denies
  match selfProt with
  | SelfProtection.selfProtect => Decision.deny
  | SelfProtection.normal =>
    -- Rule 2: Critical + deterministic always denies (immune)
    match severity, confidence with
    | Severity.critical, Confidence.deterministic => Decision.deny
    | _, _ =>
      -- Rule 3: Deny base is never weakened
      match base with
      | Decision.deny => Decision.deny
      | _ =>
        -- Rule 4: User-verified + clean → relax non-critical to log
        -- (only heuristic/contextual, never deterministic)
        if taint == TaintLevel.clean
           && provenance == Provenance.user_verified
           && severity != Severity.critical
           && confidence != Confidence.deterministic then
          Decision.log
        -- Rule 5: Tainted (medium+) → escalate log→ask for heuristic high/critical
        else if taint.rank ≥ TaintLevel.medium.rank
                && base == Decision.log
                && (confidence == Confidence.heuristic || confidence == Confidence.deterministic)
                && (severity == Severity.critical || severity == Severity.high) then
          Decision.ask
        -- Rule 6: Critical taint → escalate all log to ask for medium+
        else if taint == TaintLevel.critical
                && base == Decision.log
                && (severity == Severity.critical || severity == Severity.high || severity == Severity.medium) then
          Decision.ask
        else
          base

end Tweek
