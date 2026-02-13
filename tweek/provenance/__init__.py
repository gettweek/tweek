"""
Tweek Action Provenance — Intent Classification for False-Positive Reduction.

This package provides a formal provenance layer that classifies action origin,
uses the `ask` approval as a verified intent signal, and reduces false positives
for clean user-driven sessions.

Provenance Lattice (lowest → highest trust):
  UNKNOWN → TAINT_INFLUENCED → SKILL_CONTEXT → AGENT_GENERATED → USER_INITIATED → USER_VERIFIED
"""

from tweek.provenance.action_provenance import (
    ActionProvenance,
    PROVENANCE_NAMES,
    classify_provenance,
)

__all__ = [
    "ActionProvenance",
    "PROVENANCE_NAMES",
    "classify_provenance",
]
