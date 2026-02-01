"""
Tweek Agentic Memory

Persistent, structured memory that enables Tweek to learn from past security
decisions and make better screening choices over time.

Features:
- Pattern decision history with time-decay weighting
- Source trustworthiness tracking (URL/file injection history)
- Cross-session workflow baselines
- Learned whitelist suggestions from approval patterns

Safety Invariants:
- CRITICAL+deterministic patterns are immune from memory adjustment
- Memory can only relax ask -> log (never deny -> anything)
- Project memory can escalate but never relax global decisions
- Minimum 10 weighted decisions before any adjustment suggested
- 30-day half-life for time decay
- Full audit trail for every memory operation
"""

from tweek.memory.store import MemoryStore, get_memory_store

__all__ = ["MemoryStore", "get_memory_store"]
