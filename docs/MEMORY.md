# Tweek Agentic Memory

Persistent, structured memory that enables Tweek to learn from past security decisions and make better screening choices over time.

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Safety Invariants](#safety-invariants)
- [Database Schema](#database-schema)
- [Memory Features](#memory-features)
- [Integration Points](#integration-points)
- [Time Decay](#time-decay)
- [CLI Commands](#cli-commands)
- [Configuration](#configuration)

---

## Overview

Tweek's agentic memory is a zero-dependency SQLite-backed system that tracks security decisions across sessions, enabling four capabilities:

1. **Learned user workflows** -- Auto-quiets repeated safe patterns (e.g., a pattern that fires every time you run your build script and you always approve)
2. **Source trustworthiness tracking** -- Flags URLs and files with injection history, trusts sources with clean track records
3. **Cross-session behavioral baselines** -- Compares current session activity against historical norms per project
4. **Whitelist suggestions** -- Surfaces patterns with consistently high approval rates for human review

Memory is stored locally in SQLite with WAL mode for concurrent safety:

| Location | Scope |
|----------|-------|
| `~/.tweek/memory.db` | Global (all projects) |
| `.tweek/memory.db` | Per-project (project root) |

Per-project memory can only **escalate** decisions (add caution), never relax global decisions. This is the additive-only merge invariant.

---

## How It Works

Memory integrates into the existing screening pipeline at two points:

```
PreToolUse Hook                              PostToolUse Hook
┌──────────────────────────┐                ┌──────────────────────────┐
│                          │                │                          │
│  1. Pattern Matching     │                │  1. Source Trust READ     │
│           │              │                │     (before screening)   │
│  2. Memory READ ◄────────┤── reads ──┐   │           │              │
│     (confidence adjust)  │           │   │  2. Content Screening    │
│           │              │           │   │           │              │
│  3. Enforcement Decision │           │   │  3. Source Trust WRITE   │
│     (with memory input)  │    memory.db  │     (after screening)    │
│           │              │           │   │                          │
│  4. Memory WRITE ────────┤── writes ─┘   └──────────────────────────┘
│     (record decision)    │
│           │              │
│  5. Workflow Baseline    │
│     WRITE                │
└──────────────────────────┘
```

### PreToolUse Flow

After Layer 2 (Pattern Matching) produces a match, and before the enforcement decision is resolved:

1. **Memory Read** -- Queries `pattern_decisions` for this `(pattern_name, path_prefix)` combo. If 10+ weighted decisions exist with 90%+ approval ratio, memory suggests relaxing `ask` to `log`.
2. **Enforcement Resolution** -- The `_resolve_enforcement()` function receives the memory adjustment as an optional parameter. If present, it validates the suggestion through safety checks before applying.
3. **Memory Write** -- After the final decision (deny, ask, log, or allow), records the decision in `pattern_decisions` for future reference.
4. **Workflow Baseline** -- Updates `workflow_baselines` with the tool invocation for cross-session comparison.

### PostToolUse Flow

1. **Source Trust Read** -- Before screening response content, queries `source_trust` for the file path or URL. Provides context about whether this source has delivered injections before.
2. **Source Trust Write** -- After screening completes, records whether the source was clean or had injection detected.

---

## Safety Invariants

These rules are non-negotiable and enforced at multiple layers (application code, SQL CHECK constraints, and validation functions):

### 1. CRITICAL+Deterministic Immunity

Memory can **never** auto-approve or relax CRITICAL+deterministic patterns. These are patterns like `ssh_key_read`, `aws_credentials`, and `passwd_file_read` that have near-zero false positive rates.

Enforcement:
- **SQL CHECK constraint** on `pattern_decisions`: rejects `INSERT` where `severity='critical' AND confidence='deterministic' AND decision='allow'`
- **`is_immune_pattern()`** function: checked before every memory read and write
- **`validate_memory_adjustment()`**: rejects any suggestion targeting immune patterns

### 2. One-Step Maximum Relaxation

Memory can only suggest one step down the decision hierarchy:

| Current Decision | Max Relaxation Target |
|-----|-----|
| `deny` | `deny` (never relaxed) |
| `ask` | `log` |
| `log` | `log` (already minimum) |

Memory can suggest: `ask → log`. It can **never** suggest: `deny → anything` or `ask → allow`.

### 3. Additive-Only Project Merge

Project-scoped memory (`ProjectSandbox.get_memory_store()`) can only escalate decisions. If global memory says `log` but project memory shows injection history, the stricter decision wins.

### 4. Minimum Decision Threshold

Memory only suggests adjustments after **10+ weighted decisions** for a `(pattern_name, path_prefix)` combination. This prevents premature relaxation from a small sample size.

### 5. High Approval Ratio

Relaxation is only suggested when the weighted approval ratio is **>= 90%**. Combined with the 10-decision minimum, this means at least ~9 out of 10 historical decisions approved the pattern.

### 6. Confidence Gate

Even if memory suggests a relaxation, it's only applied when the confidence score is **>= 0.80**. The confidence score factors in both data quantity (how far above the threshold) and consistency (how strong the approval ratio).

### 7. Time Decay

Older decisions lose influence via exponential decay with a **30-day half-life**. A 60-day-old decision has 25% of its original weight. This ensures memory stays current with evolving usage patterns.

### 8. Full Audit Trail

Every memory read and write is logged to the `memory_audit` table. The audit trail is queryable via `tweek memory audit`.

### 9. Protected from AI

`memory.db` is added to `PROTECTED_CONFIG_FILES` in `overrides.py`, preventing AI agents from modifying the memory database.

---

## Database Schema

### `pattern_decisions`

Per-pattern approval/denial history with time-decay weighting.

| Column | Type | Purpose |
|---|---|---|
| `id` | INTEGER PK | Auto-incrementing ID |
| `pattern_name` | TEXT NOT NULL | Name of the matched pattern |
| `pattern_id` | INTEGER | Pattern ID from patterns.yaml |
| `original_severity` | TEXT NOT NULL | `critical`, `high`, `medium`, `low` |
| `original_confidence` | TEXT NOT NULL | `deterministic`, `heuristic`, `contextual` |
| `decision` | TEXT NOT NULL | `deny`, `ask`, `log`, `allow` |
| `user_response` | TEXT | `approved`, `denied`, or NULL |
| `tool_name` | TEXT NOT NULL | Tool that triggered the match |
| `content_hash` | TEXT | SHA-256 of content (deduplication) |
| `path_prefix` | TEXT | Normalized path context |
| `project_hash` | TEXT | SHA-256 prefix of working directory |
| `timestamp` | TEXT | ISO 8601 (default: `datetime('now')`) |
| `decay_weight` | REAL | Current decay weight (default: 1.0) |

**CHECK constraint**: `NOT (original_severity = 'critical' AND original_confidence = 'deterministic' AND decision = 'allow')`

**Indexes**: `pattern_name`, `(pattern_name, path_prefix)`, `project_hash`, `timestamp`

### `source_trust`

URL/file/domain injection history for PostToolUse source trustworthiness.

| Column | Type | Purpose |
|---|---|---|
| `id` | INTEGER PK | Auto-incrementing ID |
| `source_type` | TEXT NOT NULL | `url`, `file`, or `domain` |
| `source_key` | TEXT NOT NULL | URL, file path, or domain name |
| `total_scans` | INTEGER | Total number of scans |
| `injection_detections` | INTEGER | Number of scans with injection found |
| `trust_score` | REAL | 0.0 (bad) to 1.0 (good) |
| `last_clean_scan` | TEXT | Timestamp of last clean scan |
| `last_injection` | TEXT | Timestamp of last injection detected |
| `timestamp` | TEXT | Created/updated timestamp |
| `decay_weight` | REAL | Current decay weight |

**UNIQUE constraint**: `(source_type, source_key)`

Trust score is computed as: `1.0 - (injection_detections / total_scans)`

### `workflow_baselines`

Normal tool usage patterns per project, bucketed by hour of day.

| Column | Type | Purpose |
|---|---|---|
| `id` | INTEGER PK | Auto-incrementing ID |
| `project_hash` | TEXT NOT NULL | Project identifier |
| `tool_name` | TEXT NOT NULL | Tool name |
| `hour_of_day` | INTEGER | UTC hour (0-23) |
| `invocation_count` | INTEGER | Total invocations |
| `denied_count` | INTEGER | Denied invocations |
| `last_updated` | TEXT | Last update timestamp |

**UNIQUE constraint**: `(project_hash, tool_name, hour_of_day)`

Used by `session_analyzer.py` for cross-session behavioral comparison.

### `learned_whitelists`

Auto-generated whitelist suggestions from approval patterns.

| Column | Type | Purpose |
|---|---|---|
| `id` | INTEGER PK | Auto-incrementing ID |
| `pattern_name` | TEXT NOT NULL | Pattern with high approval rate |
| `tool_name` | TEXT | Tool context |
| `path_prefix` | TEXT | Path context |
| `approval_count` | INTEGER | Total approvals recorded |
| `denial_count` | INTEGER | Total denials recorded |
| `confidence` | REAL | Computed approval confidence |
| `suggested_at` | TEXT | When suggestion threshold was met |
| `human_reviewed` | INTEGER | 0=pending, 1=accepted, -1=rejected |

**UNIQUE constraint**: `(pattern_name, tool_name, path_prefix)`

Suggestions appear when: `confidence >= 0.90 AND total_decisions >= 10`. Accept via `tweek memory accept <id>`.

### `memory_audit`

Accountability log for all memory operations.

| Column | Type | Purpose |
|---|---|---|
| `id` | INTEGER PK | Auto-incrementing ID |
| `operation` | TEXT NOT NULL | `read`, `write`, `decay`, `clear` |
| `table_name` | TEXT NOT NULL | Table affected |
| `key_info` | TEXT | Key identifying the record |
| `result` | TEXT | Operation result summary |
| `timestamp` | TEXT | Operation timestamp |

### `pattern_confidence_view`

Computed view that aggregates `pattern_decisions` into per-pattern confidence statistics:

| Column | Source | Purpose |
|---|---|---|
| `pattern_name` | GROUP BY | Pattern identifier |
| `path_prefix` | GROUP BY | Path context |
| `total_decisions` | COUNT(*) | Total decision records |
| `weighted_approvals` | SUM | Decay-weighted approval count |
| `weighted_denials` | SUM | Decay-weighted denial count |
| `approval_ratio` | computed | `weighted_approvals / (weighted_approvals + weighted_denials)` |
| `last_decision` | MAX | Most recent decision timestamp |

Only includes rows where `decay_weight > 0.01` (effectively expired entries are excluded).

---

## Memory Features

### Pattern Confidence Adjustment

When a pattern match occurs, memory looks up the historical approval/denial ratio for that `(pattern_name, path_prefix)` combination. If the data is sufficient and consistent:

```
Pattern "base64_exfil" in "src/lib/encoding.py":
  - 15 total decisions (weighted: 14.2)
  - 14 approved, 1 denied (ratio: 0.93)
  - Confidence score: 0.87
  - Suggestion: ask → log
```

The confidence score combines data quantity and consistency:
```
data_factor = min(total_weighted / (MIN_THRESHOLD * 3), 1.0)
ratio_factor = approval_ratio
confidence_score = data_factor × ratio_factor
```

### Source Trustworthiness

Every URL and file processed by PostToolUse screening gets a trust score:

```
https://example.com/api:
  - 50 scans, 0 injections → trust: 1.0 (clean)

https://sketchy-site.com/data:
  - 10 scans, 8 injections → trust: 0.2 (suspicious)
```

Domain-level trust is also tracked: if `evil.com/page1` has injections, `evil.com/page2` inherits domain-level suspicion.

### Cross-Session Baselines

The session analyzer reads workflow baselines from memory to detect anomalies:

```python
# If this project normally uses Bash 200x/day and Read 150x/day,
# but today's session has 50 Write calls and 30 WebFetch calls,
# the behavior shift anomaly detector will flag this.
```

### Learned Whitelists

When a pattern reaches 90% approval with 10+ decisions, a whitelist suggestion is generated. Suggestions require explicit human review:

```
$ tweek memory suggestions

ID  Pattern              Tool   Path Prefix        Approvals  Confidence
1   base64_exfil         Bash   src/lib/encoding   14/15      0.93
3   hex_encode_data      Bash   tests/fixtures     11/11      1.00

Accept: tweek memory accept <id>
Reject: tweek memory reject <id>
```

Accepting a suggestion writes the pattern to the overrides whitelist. Rejecting marks it as reviewed without action.

### False Positive Bridge

When a user reports a false positive via `tweek feedback fp <pattern>`, the report is also recorded in memory as an `approved` decision, helping build the approval history for future confidence adjustments.

---

## Integration Points

### Files Modified

| File | Integration |
|------|-------------|
| `tweek/hooks/pre_tool_use.py` | Memory read (after L2 pattern match), enforcement adjustment (`_resolve_enforcement()`), memory write (all decision branches), workflow baseline update |
| `tweek/hooks/post_tool_use.py` | Source trust read (before `screen_content()`), source trust write (after screening) |
| `tweek/hooks/overrides.py` | `memory.db` added to `PROTECTED_CONFIG_FILES` |
| `tweek/hooks/feedback.py` | FP reports bridged to memory as approved decisions |
| `tweek/security/session_analyzer.py` | Cross-session baseline read in `analyze()` |
| `tweek/sandbox/project.py` | `get_memory_store()` method on `ProjectSandbox` |

### Module Map

```
tweek/memory/
├── __init__.py        # Package exports: get_memory_store, MemoryStore
├── schemas.py         # Dataclasses: PatternDecisionEntry, ConfidenceAdjustment,
│                      #   SourceTrustEntry, WorkflowBaseline, LearnedWhitelistSuggestion
├── safety.py          # Safety invariants: is_immune_pattern(), validate_memory_adjustment(),
│                      #   compute_suggested_decision(), get_max_relaxation()
├── store.py           # Core MemoryStore class (SQLite CRUD, decay engine, stats, export)
└── queries.py         # Hook entry points: memory_read_for_pattern(),
                       #   memory_write_after_decision(), memory_read_source_trust(),
                       #   memory_write_source_scan(), memory_update_workflow()
```

### Best-Effort Design

All memory operations are wrapped in `try/except` blocks that fail silently. Memory is an optimization layer -- it should **never** block or interfere with security screening. If the memory database is corrupted, inaccessible, or throws any exception, screening continues exactly as it would without memory.

---

## Time Decay

Memory uses exponential decay with a **30-day half-life** to ensure recent decisions carry more weight than old ones:

```
weight = 2^(-days_elapsed / 30)
```

| Age | Weight |
|-----|--------|
| 0 days | 1.000 |
| 15 days | 0.707 |
| 30 days | 0.500 |
| 60 days | 0.250 |
| 90 days | 0.125 |
| 180 days | 0.016 |

Entries with `decay_weight < 0.01` are excluded from the confidence view. Decay is applied automatically or can be triggered manually:

```bash
tweek memory decay          # Apply decay to all tables
```

---

## CLI Commands

All memory management is available via `tweek memory`:

| Command | Description |
|---------|-------------|
| `tweek memory status` | Overall stats: table sizes, last decay, DB size |
| `tweek memory patterns` | Per-pattern confidence adjustments |
| `tweek memory sources` | Source trustworthiness scores |
| `tweek memory suggestions` | Pending whitelist suggestions |
| `tweek memory accept <id>` | Accept a whitelist suggestion |
| `tweek memory reject <id>` | Reject a whitelist suggestion |
| `tweek memory baseline` | Workflow baseline for current project |
| `tweek memory audit` | Memory operation audit log |
| `tweek memory clear` | Clear memory data (with confirmation) |
| `tweek memory export` | Export all memory to JSON |
| `tweek memory decay` | Manually trigger time decay |

See [CLI Reference](CLI_REFERENCE.md) for full option details.

---

## Configuration

Memory operates with sensible defaults and requires no configuration. The following constants are defined in `tweek/memory/safety.py`:

| Constant | Value | Purpose |
|----------|-------|---------|
| `MIN_DECISION_THRESHOLD` | 10 | Minimum weighted decisions before suggesting adjustment |
| `MIN_APPROVAL_RATIO` | 0.90 | Minimum approval ratio to suggest relaxation |
| `MIN_CONFIDENCE_SCORE` | 0.80 | Minimum confidence score to apply an adjustment |
| `DECAY_HALF_LIFE_DAYS` | 30 | Time decay half-life in days |

Memory data files are protected from AI modification via the `PROTECTED_CONFIG_FILES` list in `tweek/hooks/overrides.py`.

---

## Further Reading

- [Architecture](ARCHITECTURE.md) -- System design and module map
- [Defense Layers](DEFENSE_LAYERS.md) -- Screening pipeline and decision flow
- [CLI Reference](CLI_REFERENCE.md) -- Full `tweek memory` command reference
- [Configuration](CONFIGURATION.md) -- Config files, tiers, and presets
