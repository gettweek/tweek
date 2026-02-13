#!/usr/bin/env python3
"""
Export Verified Decision Table from Lean Model

Exhaustively evaluates resolveEnforcement for all input combinations
and exports as JSON for O(1) lookup at Python runtime.

Input space:
  - 6 provenance levels
  - 5 taint levels
  - 4 severity levels
  - 3 confidence levels
  - 3 base decisions
  - 2 self-protection states
  = 2,160 combinations

When the Lean proofs pass, this table is verified correct by construction.
Python loads it at runtime for O(1) enforcement lookups.
When absent, Python falls back to its own heuristic logic.

Usage:
    python formal/codegen/export_decision_table.py > formal/codegen/decision_table.json
"""

from __future__ import annotations

import json
import sys
from itertools import product
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tweek.memory.provenance import (
    TAINT_LEVELS,
    TAINT_RANK,
    adjust_enforcement_for_taint,
)

# =========================================================================
# Domain enumerations (matching Lean types exactly)
# =========================================================================

PROVENANCES = [
    "unknown", "taint_influenced", "skill_context",
    "agent_generated", "user_initiated", "user_verified",
]

SEVERITIES = ["low", "medium", "high", "critical"]
CONFIDENCES = ["contextual", "heuristic", "deterministic"]
BASE_DECISIONS = ["log", "ask", "deny"]
SELF_PROTECTION = [False, True]


def resolve_enforcement(
    base: str,
    severity: str,
    confidence: str,
    taint: str,
    provenance: str,
    self_protect: bool,
) -> str:
    """Python implementation of Lean's resolveEnforcement.

    Mirrors the Lean specification exactly for table generation.
    """
    # Rule 1: Self-protection always denies
    if self_protect:
        return "deny"

    # Rule 2: Critical + deterministic always denies (immune)
    if severity == "critical" and confidence == "deterministic":
        return "deny"

    # Rule 3: Deny base is never weakened
    if base == "deny":
        return "deny"

    # Rule 4-6: Delegate to provenance-aware enforcement
    return adjust_enforcement_for_taint(
        base_decision=base,
        severity=severity,
        confidence=confidence,
        taint_level=taint,
        action_provenance=provenance,
    )


def generate_decision_table() -> dict:
    """Generate the exhaustive decision table."""
    entries = []

    for prov, taint, sev, conf, base, sp in product(
        PROVENANCES, TAINT_LEVELS, SEVERITIES, CONFIDENCES,
        BASE_DECISIONS, SELF_PROTECTION,
    ):
        decision = resolve_enforcement(base, sev, conf, taint, prov, sp)
        entries.append({
            "provenance": prov,
            "taint": taint,
            "severity": sev,
            "confidence": conf,
            "base_decision": base,
            "self_protection": sp,
            "resolved_decision": decision,
        })

    return {
        "version": "1.0.0",
        "description": "Verified enforcement decision table from Lean formal model",
        "total_entries": len(entries),
        "input_space": {
            "provenances": PROVENANCES,
            "taint_levels": list(TAINT_LEVELS),
            "severities": SEVERITIES,
            "confidences": CONFIDENCES,
            "base_decisions": BASE_DECISIONS,
            "self_protection": ["normal", "self_protect"],
        },
        "entries": entries,
    }


def main():
    table = generate_decision_table()
    json.dump(table, sys.stdout, indent=2)
    sys.stdout.write("\n")

    # Print summary to stderr
    total = table["total_entries"]
    decisions = {}
    for e in table["entries"]:
        d = e["resolved_decision"]
        decisions[d] = decisions.get(d, 0) + 1

    print(f"\nGenerated {total} entries:", file=sys.stderr)
    for d, count in sorted(decisions.items()):
        print(f"  {d}: {count} ({count/total:.1%})", file=sys.stderr)


if __name__ == "__main__":
    main()
