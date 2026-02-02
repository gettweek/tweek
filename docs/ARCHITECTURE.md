# Tweek Architecture

## Table of Contents

- [System Overview](#system-overview)
- [Three Interception Points](#three-interception-points)
- [Unified ScreeningContext](#unified-screeningcontext)
- [Screening Pipeline (5+1 Layers)](#screening-pipeline-51-layers)
- [Data Architecture](#data-architecture)
- [Plugin System](#plugin-system)
- [Module Map](#module-map)

---

## System Overview

Tweek is a defense-in-depth security layer for AI coding assistants. It intercepts
tool calls at three points in the AI assistant call chain, routes them through a unified
screening pipeline, and returns allow/deny/prompt decisions.

```
                          +---------------------------+
                          |    AI Coding Assistant     |
                          | (Claude, Cursor, Copilot)  |
                          +---------------------------+
                                    |
                    +---------------+---------------+
                    |               |               |
              +-----v-----+  +-----v-----+  +------v------+
              |   Hooks    |  | MCP Proxy |  | HTTP Proxy  |
              | (Layer A)  |  | (Layer B) |  | (Layer C)   |
              +-----+------+  +-----+-----+  +------+------+
                    |               |               |
                    +-------+-------+-------+-------+
                            |               |
                    +-------v-------+       |
                    | ScreeningContext|<-----+
                    +-------+-------+
                            |
               +------------v-----------+
               |   Screening Pipeline   |
               |  L0: Compliance        |
               |  L1: Rate Limiting     |
               |  L2: Pattern Matching  |
               |  L3: LLM Review        |
               |  L4: Session Analysis  |
               |  L5: Sandbox Preview   |
               +------------+-----------+
                            |
                   +--------v--------+
                   |    Decision     |
                   | allow/deny/ask  |
                   +-----------------+
```

---

## Three Interception Points

### Layer A: Git Hooks (`tweek/hooks/`)

The primary interception point for Claude Code. Registers as a pre-tool-use hook that
receives JSON on stdin (`tool_name`, `tool_input`, `session_id`, `cwd`) and returns a
decision on stdout (`{}` for allow, or `permissionDecision: "ask"|"deny"` with reason).

**Key file**: `tweek/hooks/pre_tool_use.py` -- contains `TierManager`, `PatternMatcher`,
`process_hook()`, and the full Layer 0-5 orchestration.

### Layer B: MCP Proxy (`tweek/mcp/`)

A transparent MCP proxy for desktop AI clients (Claude Desktop, ChatGPT, Gemini).
Architecture: `LLM Client <--stdio--> TweekMCPProxy <--stdio--> Upstream MCP Server(s)`.
Tool names are namespaced as `{upstream}__{tool}` to prevent collisions.

**Key files**: `proxy.py` (transport/upstream management), `screening.py` (shared pipeline),
`approval.py` (SQLite approval queue at `~/.tweek/approvals.db`), `approval_cli.py`
(CLI daemon), `clients/` (adapters for ChatGPT, Claude Desktop, Gemini).

### Layer C: HTTP Proxy (`tweek/proxy/`)

An HTTPS proxy (via mitmproxy) intercepting LLM API traffic for any HTTP-based client.
Monitors `api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`,
and `bedrock-runtime.*.amazonaws.com`.

**Key files**: `addon.py` (`TweekProxyAddon`), `interceptor.py` (`LLMAPIInterceptor`
for provider detection and tool call extraction).

---

## Unified ScreeningContext

**File**: `tweek/screening/context.py`

All three interception layers construct a `ScreeningContext` dataclass that carries
the full context needed by every screening layer. This ensures consistent behavior
regardless of which interception point triggered the screening.

```python
@dataclass
class ScreeningContext:
    tool_name: str                            # "Bash", "Read", "Write", etc.
    content: str                              # Command/path/URL to screen
    tier: str                                 # "safe", "default", "risky", "dangerous"
    working_dir: str                          # Current working directory
    session_id: Optional[str] = None          # Session identifier for cross-turn analysis
    skill_name: Optional[str] = None          # Claude skill name (if applicable)
    source: str = "hooks"                     # Interception layer: "hooks", "mcp", "proxy"
    client_name: Optional[str] = None         # "claude-desktop", "chatgpt", "gemini-cli"
    mcp_server: Optional[str] = None          # Upstream MCP server name
    project_config_path: Optional[str] = None # Path to project-level .tweek/config.yaml
    tool_input: Optional[Dict[str, Any]] = None  # Raw tool input dict
    metadata: Dict[str, Any] = field(default_factory=dict)
```

The `ScreeningContext` provides two serialization methods:

- `to_dict()` -- Full serialization for new plugins
- `to_legacy_dict()` -- Backward-compatible format for existing screening plugins that expect `{"session_id", "tier", "tool_name", "working_dir"}`

---

## Screening Pipeline (5+1 Layers)

The screening pipeline runs sequentially. Each layer can independently trigger a
`deny` (hard block) or `ask` (prompt user) decision. If no layer triggers, the
operation is allowed.

### Layer 0: Compliance Scanning

Runs **before** tier resolution. Domain-specific compliance plugins scan content for
regulated data patterns (HIPAA PHI, PCI card numbers, government classification markings, etc.).

- **Decision**: `deny` if compliance plugin returns `BLOCK` action
- **Scope**: All tiers, all tool types
- **Direction**: Bidirectional (scans both input and output)

### Layer 1: Rate Limiting

Detects resource theft and abuse patterns by tracking invocation statistics in
`security.db`.

- **Decision**: `ask` if any rate limit violation detected
- **Checks**: Burst detection, repeated commands, high volume, dangerous tier spikes, velocity anomalies
- **Circuit breaker**: Opens after 5 consecutive violations, blocks all requests for 60 seconds

### Layer 2: Pattern Matching

Regex-based detection of 259 known attack patterns loaded from `tweek/config/patterns.yaml`.

- **Decision**: `ask` if any pattern matches
- **Scope**: Tiers with `regex` in their screening list (`default`, `risky`, `dangerous`)
- **Content extraction**: `Bash` -> `command`, `Read`/`Write`/`Edit` -> `file_path`, `WebFetch` -> `url`

### Layer 3: LLM Review

Semantic analysis using Claude 3.5 Haiku for commands that pass pattern matching but
may still be malicious.

- **Decision**: `ask` if risk is `dangerous` or `suspicious` with >= 70% confidence
- **Scope**: Tiers with `llm` in their screening list (`risky`, `dangerous`)
- **Timeout**: 5 seconds (fails open to `suspicious` with 30% confidence on timeout)

### Layer 4: Session Analysis

Cross-turn anomaly detection using the session event history in `security.db`.

- **Decision**: `ask` if risk score >= 0.5 or 2+ anomaly types detected
- **Scope**: `risky` and `dangerous` tiers with a valid `session_id`
- **Lookback window**: 30 minutes of session history

### Layer 5: Sandbox Preview

Speculative execution in a macOS `sandbox-exec` (or Linux `firejail`) environment.

- **Decision**: `ask` if sandbox detects violations (sensitive path access, network attempts, denied operations)
- **Scope**: Tiers with `sandbox` in their screening list (`dangerous` only)
- **Timeout**: 3 seconds for preview execution

### Decision Logic

```
If Layer 0 blocks:           return deny
If Layer 1 triggers:         return ask
If safe tier:                return allow
If Layer 2 matches:          set triggered
If Layer 3 flags:            set triggered
If Layer 4 detects anomaly:  set triggered
If Layer 5 detects violation: set triggered
If any triggered:            return ask (with combined messages)
Otherwise:                   return allow
```

---

## Data Architecture

### SQLite: `~/.tweek/security.db`

Primary audit database managed by `tweek/logging/security_log.py`.

**`security_events` table**:

| Column | Type | Purpose |
|---|---|---|
| `id` | INTEGER PRIMARY KEY | Auto-incrementing event ID |
| `timestamp` | TEXT | ISO 8601 timestamp |
| `event_type` | TEXT | `tool_invoked`, `pattern_match`, `llm_rule_match`, `user_prompted`, `allowed`, `blocked`, `error`, `escalation`, `sandbox_preview`, `config_change` |
| `tool_name` | TEXT | Tool that triggered the event |
| `command` | TEXT | Command content (redacted by `LogRedactor`) |
| `tier` | TEXT | Effective security tier |
| `pattern_name` | TEXT | Name of matched pattern (if applicable) |
| `pattern_severity` | TEXT | `critical`, `high`, `medium`, `low` |
| `decision` | TEXT | `allow`, `block`, `ask` |
| `decision_reason` | TEXT | Human-readable explanation |
| `session_id` | TEXT | Session identifier for grouping |
| `correlation_id` | TEXT | Links events from the same screening pass |
| `source` | TEXT | `hooks`, `mcp`, `proxy`, `sandbox` |
| `metadata_json` | TEXT | JSON blob for plugin-specific data |

**Indexes**:
- `idx_events_session_time` on `(session_id, timestamp)` -- rate limiting queries
- `idx_events_command_hash` on `(tool_name, command)` -- repeated command detection

**`session_profiles` table** (created by session analyzer):

| Column | Type | Purpose |
|---|---|---|
| `session_id` | TEXT PRIMARY KEY | Session identifier |
| `first_seen` | TEXT | First event timestamp |
| `last_seen` | TEXT | Last event timestamp |
| `total_invocations` | INTEGER | Total tool calls in session |
| `dangerous_count` | INTEGER | Count of dangerous-tier operations |
| `denied_count` | INTEGER | Count of blocked/prompted operations |
| `risk_score` | REAL | Computed risk score (0.0-1.0) |
| `anomaly_flags` | TEXT | JSON array of detected anomaly types |

### SQLite: `~/.tweek/approvals.db`

MCP proxy approval queue managed by `tweek/mcp/approval.py`.

Stores pending, approved, denied, and expired tool call approval requests for
the human-in-the-loop workflow.

### YAML Configuration

| File | Location | Purpose |
|---|---|---|
| `tweek/config/tiers.yaml` | Bundled | Default tier definitions, tool/skill classifications, escalation patterns, LLM/rate-limit/session config |
| `tweek/config/patterns.yaml` | Bundled | 259 attack pattern definitions with regex, severity, description |
| `tweek/config/allowed_dirs.yaml` | Bundled | Directory allowlist controlling where Tweek activates |
| `~/.tweek/config.yaml` | User home | User-level configuration overrides |
| `.tweek/config.yaml` | Project root | Project-level configuration overrides |

### SQLite: `~/.tweek/memory.db`

Persistent agentic memory database managed by `tweek/memory/store.py`. Enables Tweek
to learn from past security decisions across sessions.

**5 tables + 1 view**:

| Table | Purpose |
|---|---|
| `pattern_decisions` | Per-pattern approval/denial history with time-decay weighting |
| `source_trust` | URL/file/domain injection history and trust scores |
| `workflow_baselines` | Normal tool usage patterns per project (bucketed by hour) |
| `learned_whitelists` | Auto-generated whitelist suggestions from approval patterns |
| `memory_audit` | Accountability log for all memory reads/writes |
| `pattern_confidence_view` | Computed view: per-pattern confidence adjustments |

**Safety invariants**: CRITICAL+deterministic patterns are immune from any memory adjustment
(enforced via SQL CHECK constraint). Maximum relaxation is one step: `ask` → `log` only.
Memory requires 10+ weighted decisions at 90%+ approval ratio before suggesting changes.

**Time decay**: 30-day half-life. Entries below 0.01 weight are excluded from queries.

**Per-project memory**: `ProjectSandbox.get_memory_store()` provides project-scoped
memory that can only escalate (never relax) global decisions.

See [MEMORY.md](MEMORY.md) for the full schema and safety invariant documentation.

### NDJSON Log: `~/.tweek/security_events.jsonl`

Structured newline-delimited JSON log managed by `tweek/logging/json_logger.py`.
Supplements the SQLite database with a format suitable for log aggregation systems
(ELK, Splunk, Datadog). Automatically rotates at 10 MB with 5 rotated file retention.

---

## Plugin System

**File**: `tweek/plugins/base.py`

Tweek uses a plugin architecture with four plugin categories:

### Plugin Categories

| Category | Base Class | Purpose | License |
|---|---|---|---|
| **Compliance** | `CompliancePlugin` | Domain-specific sensitive data scanning | Enterprise |
| **Screening** | `ScreeningPlugin` | Security screening methods (rate limit, pattern, LLM, session) | Free / Pro |
| **Providers** | `LLMProviderPlugin` | LLM API format detection and parsing | Free |
| **Detectors** | `ToolDetectorPlugin` | AI tool/IDE detection (Cursor, Copilot, etc.) | Free |

### Security Infrastructure

- **ReDoS Protection** (`ReDoSProtection` class): Validates regex patterns against known
  dangerous constructs (nested quantifiers, overlapping alternation), enforces 1000-char
  pattern length limits, provides timeout-protected execution via `SIGALRM`, and caps input
  length at 1 MB.

- **Log Redaction** (`LogRedactor` class): Automatically strips API keys, AWS credentials,
  JWT tokens, GitHub tokens, private keys, passwords, connection strings, and credit card
  numbers from all log entries before writing to disk.

- **Finding Redaction**: The `Finding` dataclass redacts `matched_text` by default in
  `to_dict()` output, showing only first/last 2 characters with masked middle. Raw text
  is only accessible via `include_raw=True` for internal processing.

---

## Module Map

```
tweek/
+-- __init__.py                    # Package metadata (v0.1.0)
+-- cli.py                         # CLI entry point (tweek command)
+-- cli_helpers.py                 # CLI utility functions
+-- diagnostics.py                 # System diagnostics and health checks
+-- licensing.py                   # License management (Free/Pro/Enterprise)
|
+-- config/                        # Configuration management
|   +-- __init__.py
|   +-- manager.py                 # ConfigManager: 3-layer config, presets, validation
|   +-- tiers.yaml                 # Tier definitions, tool/skill defaults, escalations
|   +-- patterns.yaml              # 259 attack pattern definitions
|   +-- allowed_dirs.yaml          # Directory activation allowlist
|
+-- screening/                     # Unified screening context
|   +-- __init__.py
|   +-- context.py                 # ScreeningContext dataclass
|
+-- hooks/                         # Hook-based interception (Layer A)
|   +-- __init__.py
|   +-- pre_tool_use.py            # Main hook: TierManager, PatternMatcher, process_hook()
|
+-- mcp/                           # MCP proxy interception (Layer B)
|   +-- __init__.py
|   +-- proxy.py                   # TweekMCPProxy: transparent stdio proxy
|   +-- server.py                  # MCP server wrapper
|   +-- screening.py               # run_mcp_screening(): shared pipeline
|   +-- approval.py                # ApprovalQueue: SQLite approval queue
|   +-- approval_cli.py            # CLI daemon for approval decisions
|   +-- clients/                   # Client adapters
|       +-- chatgpt.py             # ChatGPT Desktop adapter
|       +-- claude_desktop.py      # Claude Desktop adapter
|       +-- gemini.py              # Gemini CLI adapter
|
+-- proxy/                         # HTTP proxy interception (Layer C)
|   +-- __init__.py
|   +-- server.py                  # Mitmproxy launcher
|   +-- addon.py                   # TweekProxyAddon: request/response interception
|   +-- interceptor.py             # LLMAPIInterceptor: provider detection, tool extraction
|
+-- security/                      # Core security engines
|   +-- __init__.py
|   +-- rate_limiter.py            # RateLimiter + CircuitBreaker
|   +-- llm_reviewer.py            # LLMReviewer: Claude Haiku semantic analysis
|   +-- session_analyzer.py        # SessionAnalyzer: cross-turn anomaly detection
|   +-- secret_scanner.py          # Secret scanning utilities
|
+-- sandbox/                       # Process sandboxing (Layer 5)
|   +-- __init__.py
|   +-- executor.py                # SandboxExecutor: preview_command(), execute_sandboxed()
|   +-- profile_generator.py       # ProfileGenerator: .sb profile generation from manifests
|   +-- linux.py                   # LinuxSandbox: firejail/bubblewrap fallback
|
+-- plugins/                       # Plugin architecture
|   +-- __init__.py                # PluginRegistry, PluginCategory
|   +-- base.py                    # Base classes, ReDoS protection, Finding, ScanResult
|   +-- scope.py                   # Plugin scoping logic
|   +-- git_discovery.py           # Git repository discovery
|   +-- git_installer.py           # Git hook installation
|   +-- git_lockfile.py            # Git lockfile management
|   +-- git_registry.py            # Plugin registry via git
|   +-- git_security.py            # Git security utilities
|   +-- compliance/                # Compliance plugins (Enterprise)
|   |   +-- __init__.py
|   |   +-- gov.py                 # Government classification markings
|   |   +-- hipaa.py               # HIPAA PHI detection
|   |   +-- pci.py                 # PCI-DSS cardholder data (with Luhn validation)
|   |   +-- legal.py               # Attorney-client privilege markers
|   |   +-- soc2.py                # SOC2 trust services criteria patterns
|   |   +-- gdpr.py                # GDPR personal data detection
|   +-- screening/                 # Screening method plugins
|   |   +-- __init__.py
|   |   +-- rate_limiter.py        # Rate limiting plugin wrapper
|   |   +-- pattern_matcher.py     # Pattern matching plugin wrapper
|   |   +-- llm_reviewer.py        # LLM review plugin wrapper
|   |   +-- session_analyzer.py    # Session analysis plugin wrapper
|   +-- providers/                 # LLM provider plugins
|   |   +-- __init__.py
|   |   +-- anthropic.py           # Anthropic API parser
|   |   +-- openai.py              # OpenAI API parser
|   |   +-- google.py              # Google AI API parser
|   |   +-- bedrock.py             # AWS Bedrock API parser
|   |   +-- azure_openai.py        # Azure OpenAI API parser
|   +-- detectors/                 # Tool/IDE detector plugins
|       +-- __init__.py
|       +-- cursor.py              # Cursor IDE detection
|       +-- copilot.py             # GitHub Copilot detection
|       +-- continue_dev.py        # Continue.dev detection
|       +-- windsurf.py            # Windsurf detection
|       +-- openclaw.py            # OpenClaw detection
|
+-- logging/                       # Audit logging
|   +-- __init__.py
|   +-- security_log.py            # SecurityLogger: SQLite event logging + LogRedactor
|   +-- json_logger.py             # JsonEventLogger: NDJSON output for log aggregation
|   +-- bundle.py                  # Log bundle export
|
+-- memory/                        # Agentic memory (cross-session learning)
|   +-- __init__.py                # Exports: get_memory_store, MemoryStore
|   +-- schemas.py                 # Dataclasses: PatternDecisionEntry, ConfidenceAdjustment,
|   |                              #   SourceTrustEntry, WorkflowBaseline, LearnedWhitelistSuggestion
|   +-- safety.py                  # Safety invariants: is_immune_pattern(), validate_memory_adjustment()
|   +-- store.py                   # MemoryStore: SQLite CRUD, decay engine, stats, export
|   +-- queries.py                 # Hook entry points: memory_read_for_pattern(),
|                                  #   memory_write_after_decision(), memory_read_source_trust(),
|                                  #   memory_write_source_scan(), memory_update_workflow()
|
+-- vault/                         # Credential vaulting
|   +-- __init__.py
|   +-- keychain.py                # macOS Keychain integration
|   +-- cross_platform.py          # Cross-platform credential storage
|
+-- platform/                      # Platform detection
    +-- __init__.py                # OS detection, package manager detection
```

---

## Further Reading

- [PHILOSOPHY.md](PHILOSOPHY.md) - Threat model and design principles
- [DEFENSE_LAYERS.md](DEFENSE_LAYERS.md) - Detailed documentation of each screening layer
- [MEMORY.md](MEMORY.md) - Agentic memory system (cross-session learning)
- [CONFIGURATION.md](CONFIGURATION.md) - Configuration system and security tiers
