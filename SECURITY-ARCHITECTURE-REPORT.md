# Tweek Security Architecture Report

**Date**: 2026-02-02
**Scope**: tweek-public repository (open source prompt injection detection for AI coding assistants)
**Methodology**: Multi-agent parallel audit with manual verification of all findings

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Audit Methodology](#2-audit-methodology)
3. [Architecture Overview](#3-architecture-overview)
4. [Defense-in-Depth Layer Analysis](#4-defense-in-depth-layer-analysis)
5. [Verified Security Findings](#5-verified-security-findings)
6. [Corrected False Positives](#6-corrected-false-positives)
7. [Architecture Strengths](#7-architecture-strengths)
8. [Risk Matrix](#8-risk-matrix)
9. [Recommendations](#9-recommendations)

---

## 1. Executive Summary

Tweek implements a **defense-in-depth security architecture** that intercepts every tool call an AI coding assistant makes, applying up to six screening layers before allowing execution. The system uses Claude Code's hook protocol to bracket tool calls with pre-execution screening (request analysis) and post-execution screening (response analysis for injection).

**Overall Assessment**: The architecture is well-designed with multiple redundant layers, fail-closed error handling, and strong self-protection mechanisms. However, **2 critical**, **5 high**, **7 medium**, and **4 low** severity findings were identified that could weaken or bypass specific layers under adversarial conditions.

**Key Strengths**: Fail-closed defaults, additive-only configuration merges, self-protection against AI config modification, memory safety invariants that make critical patterns immune from learning-based relaxation, and Unicode normalization before all pattern matching.

**Key Risks**: Regex denial-of-service via catastrophic backtracking, XML delimiter escape in LLM review prompts, and several race conditions in file-based state management.

---

## 2. Audit Methodology

Three specialized audit agents examined the codebase in parallel, each focusing on a different security domain:

| Agent | Focus Area | Files Examined |
|-------|-----------|----------------|
| **Agent A** | Core security modules | patterns.yaml, llm_reviewer.py, rate_limiter.py, session_analyzer.py, sandbox/executor.py, language.py, local_model.py, heuristic_scorer.py |
| **Agent B** | Trust model and configuration | overrides.py, break_glass.py, memory/store.py, memory/safety.py, security/integrity.py, skills/guard.py, skills/isolation.py, plugins/base.py, vault/ |
| **Agent C** | Input validation and edge cases | JSON/YAML parsing, path handling, regex safety, error handling, concurrency, env vars, subprocess usage, logging, test coverage |

All findings were then **manually verified** by reading critical source code sections. Four agent findings were determined to be false positives where the code already handles the flagged issue (see [Section 6](#6-corrected-false-positives)).

---

## 3. Architecture Overview

### 3.1 Four Security Tiers

Every tool invocation is classified into one of four tiers, each enabling progressively more screening:

```
TIER            SCREENING LAYERS                    EXAMPLE TOOLS
-----------     --------------------------------    --------------------------
safe            (none)                              Glob, Grep, Skill
default         regex (262 patterns)                Read, Edit, Task
risky           regex + LLM semantic review         Write, WebFetch, WebSearch
dangerous       regex + LLM + sandbox preview       Bash
```

Configuration: `tweek/config/tiers.yaml:80-122`

Tiers can be **escalated** (never relaxed) by:
- Content patterns (e.g., `sudo`, recursive deletion, credential file paths)
- Path boundary violations (accessing files outside project directory)
- Skill context (e.g., a `deploy` skill escalates Read to dangerous)
- Non-English language detection (escalates to at least risky)
- Heuristic scoring (escalates to LLM review when score > 0.4)

### 3.2 Hook Architecture

```
                         +-----------------------------------+
    Claude Code          |         TOOL CALL                  |
    requests a  -------> |  (tool_name, tool_input)           |
    tool call            +----------------+------------------+
                                          |
                                          v
                         +-----------------------------------+
                         |     PRE-TOOL-USE HOOK              |
                         |  (tweek/hooks/pre_tool_use.py)     |
                         |                                    |
                         |  Layer 0: Compliance scanning      |
                         |  Self-protection checks            |
                         |  Skill guard                       |
                         |  Tier determination + escalation   |
                         |  Layer 1: Rate limiting            |
                         |  Layer 2: Pattern matching (262)   |
                         |  Layer 2.5: Heuristic scoring      |
                         |  Layer 3: LLM semantic review      |
                         |  Layer 4: Session analysis         |
                         |  Layer 5: Sandbox preview          |
                         |                                    |
                         |  Decision: DENY / ASK / ALLOW      |
                         +----------------+------------------+
                                          |
                              +-----------+-----------+
                              |                       |
                         DENY/ASK                 ALLOW
                         (blocked or              (tool executes)
                          user prompted)               |
                                                       v
                         +-----------------------------------+
                         |     POST-TOOL-USE HOOK             |
                         |  (tweek/hooks/post_tool_use.py)    |
                         |                                    |
                         |  Language detection                 |
                         |  Pattern matching on response       |
                         |  LLM review (if non-English)       |
                         |  Content redaction (critical)       |
                         |  Warning injection into context     |
                         |                                    |
                         |  Warning injected or silent         |
                         +-----------------------------------+
```

### 3.3 Enforcement Policy Matrix

The system resolves pattern severity + confidence into a decision using a configurable matrix:

```
                 DETERMINISTIC    HEURISTIC    CONTEXTUAL
CRITICAL              DENY          ASK          ASK
HIGH                  ASK           ASK          ASK
MEDIUM                ASK           ASK          ASK
LOW                   LOG           LOG          LOG
```

Source: `tweek/hooks/overrides.py:466-471` (EnforcementPolicy.DEFAULT_MATRIX)

Decisions can be modified by:
- **Break-glass overrides**: Human-created temporary downgrades (deny to ask only)
- **Memory adjustments**: Learning-based relaxation (ask to log only, with strict safety invariants)
- **Trust level filtering**: Interactive sessions may suppress low-severity patterns

### 3.4 Self-Protection

The system prevents AI agents from modifying its own security configuration:

| Protected Resource | Protection Mechanism | Source |
|---|---|---|
| `~/.tweek/overrides.yaml` | Explicit path check + bash regex | `overrides.py:32,368-412` |
| `~/.tweek/skills/` | Explicit path check | `overrides.py:34` |
| `~/.tweek/memory.db` | Explicit path check | `overrides.py:36` |
| Any file inside `.tweek/` dir | Directory part check | `overrides.py:343-347` |
| Any `.tweek.yaml` file | Filename check | `overrides.py:350-351` |
| `tweek uninstall/trust/untrust` | Command regex | `pre_tool_use.py:972-1003` |
| Skill directories | Skill guard module | `skills/guard.py:31-35` |

---

## 4. Defense-in-Depth Layer Analysis

### Layer 0: Compliance Scanning
- **Purpose**: Plugin-based regulatory/policy scanning
- **Trigger**: All tool calls (runs first)
- **Actions**: BLOCK (hard deny) or ASK
- **Source**: `pre_tool_use.py:63-147`

### Layer 1: Rate Limiting
- **Purpose**: Detect burst attacks, resource theft, and MCP sampling abuse
- **Detection Types**: Burst (15/5s), high volume (60/min), repeated command (5/min), dangerous tier spike (10/min), velocity anomaly
- **State**: In-memory per process invocation (see Finding #11)
- **Source**: `tweek/security/rate_limiter.py`

### Layer 2: Pattern Matching
- **Purpose**: Regex detection of 262 known attack vectors
- **Pattern Categories**: Credential theft (23), data exfiltration (15), prompt injection (40+), destructive operations, persistence, evasion, social engineering
- **Preprocessing**: NFKC Unicode normalization before matching (`pre_tool_use.py:591-594`)
- **Severity/Confidence**: Each pattern tagged with severity (critical/high/medium/low) and confidence (deterministic/heuristic/contextual)
- **Source**: `tweek/config/patterns.yaml` (262 patterns), `pre_tool_use.py:596-620`

### Layer 2.5: Heuristic Scoring
- **Purpose**: Bridge between regex and LLM for novel attack variants
- **Trigger**: Only when no regex match AND LLM not already scheduled
- **Signals**: Sensitive paths, exfiltration verbs, encoding tools, shell expansion, pipe complexity
- **Threshold**: Score > 0.4 escalates to LLM review
- **Source**: `tweek/plugins/screening/heuristic_scorer.py`

### Layer 3: LLM Semantic Review
- **Purpose**: Semantic understanding of command intent beyond regex
- **Providers**: Local ONNX model, Ollama, LM Studio, Claude Haiku, GPT-4o-mini, Gemini Flash, Grok (auto-detected)
- **Trigger Criteria**: `risk_level == DANGEROUS` or `(risk_level == SUSPICIOUS and confidence >= 0.7)`
- **Source**: `tweek/security/llm_reviewer.py`

### Layer 4: Session Analysis
- **Purpose**: Cross-turn anomaly detection
- **Detection Types**: Privilege escalation across turns, path escalation, repeated denials, behavior shift, injection indicators, graduated escalation, capability aggregation, velocity change
- **Trigger**: Risk score >= 0.5 or >= 2 anomalies
- **Source**: `tweek/security/session_analyzer.py`

### Layer 5: Sandbox Preview
- **Purpose**: Speculative execution in isolated environment
- **Scope**: Bash commands at dangerous tier only
- **Implementation**: macOS `sandbox-exec` with restrictive profile
- **Source**: `tweek/sandbox/executor.py`

### Post-Tool Response Screening
- **Purpose**: Detect prompt injection in fetched/read content before AI acts on it
- **Screened Tools**: Read, WebFetch, Bash, Grep, WebSearch
- **Pipeline**: Language detection, pattern matching, LLM review (if non-English), content redaction, warning injection
- **Source**: `tweek/hooks/post_tool_use.py`

---

## 5. Verified Security Findings

> **Note on examples**: Attack examples are described abstractly rather than with literal
> command strings, because the report itself is screened by Tweek's post-tool-use hook.
> Literal attack strings in report content would trigger pattern matches (as observed during
> report generation, proving the system works as designed).

### CRITICAL Severity

#### Finding 1: ReDoS Risk in Pattern Matching (No Per-Pattern Timeout)

**Location**: `tweek/hooks/pre_tool_use.py:604,616`

**Description**: All 262 regex patterns are executed via `re.search()` with `re.IGNORECASE | re.DOTALL` flags. There is no per-pattern timeout mechanism. Patterns containing greedy quantifiers can exhibit catastrophic backtracking on adversarially crafted input.

Python's `re` module does not support timeouts. The only protection is `except re.error`, which catches malformed regex but not exponential backtracking.

**Attack Vector**: An attacker provides a 10KB+ command or file content designed to trigger O(2^n) matching against patterns with nested quantifiers. The hook freezes, causing Claude Code to timeout.

**Impact**: Denial-of-service against the screening system. While the tool call would not proceed (timeout = fail-closed), the user experience degrades and repeated exploitation could render Tweek unusable.

**Note**: The `plugins/base.py` module includes `safe_search()` with SIGALRM-based timeout for plugin patterns, but this is not used for the core 262 patterns in the pre-tool-use hook.

---

#### Finding 2: XML Delimiter Escape in LLM Reviewer

**Location**: `tweek/security/llm_reviewer.py:1096-1099,1251`

**Description**: The ANALYSIS_PROMPT template uses `<untrusted_command>` XML delimiters to isolate untrusted content. However, the content is inserted via Python `.format()` without XML escaping.

**Attack Vector**: If the command being analyzed contains a closing XML tag matching the delimiter, it prematurely closes the untrusted block. The attacker can then inject text that appears to be part of the analysis instructions rather than the untrusted content, potentially manipulating the LLM into classifying dangerous commands as safe.

**Mitigation**: The system prompt explicitly warns the LLM not to follow instructions within the tags, but sophisticated prompt injection could exploit the delimiter escape.

**Recommendation**: Escape `<` and `>` characters in the command before insertion, or use a unique random delimiter per invocation.

---

### HIGH Severity

#### Finding 3: LLM Reviewer Fails Open on Provider Errors

**Location**: `tweek/security/llm_reviewer.py:1296-1331`

**Description**: When the cloud LLM provider is unavailable (timeout, auth failure, rate limit, network error), the reviewer returns `risk_level=SAFE, should_prompt=False` with `graceful_degradation=True`. This is a deliberate design decision documented in code comments -- pattern matching is the primary defense, and the LLM is supplementary.

**Risk**: An attacker who can cause LLM service degradation (DNS poisoning, API endpoint blocking, or exhausting rate limits) effectively disables the entire LLM review layer. Novel attacks that bypass regex patterns but would be caught by semantic analysis proceed unchecked.

**Mitigating Factor**: Pattern matching (262 patterns) and heuristic scoring still provide coverage. The alternative (fail-closed on LLM unavailability) would make Tweek unusable when API keys are missing or LLM services are down.

---

#### Finding 4: Race Condition in Break-Glass Consumption

**Location**: `tweek/hooks/break_glass.py:96-127`

**Description**: `check_override()` loads state from JSON, checks/consumes an override, and saves state -- all without file locking. If two hook invocations race, both could read the same unused override before either writes the consumed state. A single-use override could be consumed twice.

**Impact**: Minor in practice -- break-glass overrides only downgrade deny to ask (user still sees prompt). The practical risk is low since Claude Code hook calls are largely sequential, but the pattern is architecturally unsound.

**Recommendation**: Use `fcntl.flock()` (already used in the vault module) for atomic read-modify-write.

---

#### Finding 5: No Model Integrity Verification

**Location**: `tweek/security/local_model.py`, `tweek/security/model_registry.py`

**Description**: The ONNX model download process does not verify SHA-256 checksums against a trusted manifest. Downloaded model files are used directly for inference without integrity verification.

**Attack Vector**: A MITM attacker on the network path between the user and HuggingFace CDN could replace the model binary with a poisoned version that classifies malicious inputs as safe.

**Mitigating Factor**: Downloads use HTTPS (TLS), which provides transport security. The attack requires compromising the system certificate store or the CDN itself.

**Recommendation**: Ship SHA-256 hashes in the model catalog and verify after download.

---

#### Finding 6: Local Model Confidence Escalation Logic

**Location**: `tweek/config/tiers.yaml:77-78`

**Description**: The local ONNX model uses confidence thresholds to decide when to escalate to cloud LLM:
- Below 0.1: definitely safe, no escalation
- Between 0.1 and 0.9: uncertain, escalate to cloud
- Above 0.9: use local result directly, no escalation

**Risk**: If the local model produces a high-confidence (>0.9) false negative (classifies a dangerous input as "safe" with 95% confidence), the cloud LLM never gets a chance to catch it. Adversarial examples specifically crafted to fool the DeBERTa classifier could exploit this.

**Mitigating Factor**: Pattern matching (Layer 2) runs before the local model and would catch known attack patterns regardless.

---

#### Finding 7: Heuristic Scorer Benign Dampening Exploitable

**Location**: `tweek/plugins/screening/heuristic_scorer.py`

**Description**: The heuristic scorer applies a 0.8x multiplicative dampening when content matches known-benign patterns (e.g., a `git commit` prefix). An attacker could prefix a malicious command with a benign pattern joined by `&&` to trigger dampening.

If the base heuristic score was 0.48 (above threshold), dampening reduces it to 0.384 (below the 0.4 threshold), preventing LLM escalation.

**Mitigating Factor**: The heuristic scorer only runs when no regex pattern matched. Known attack vectors would be caught by the 262 regex patterns in Layer 2 before the heuristic scorer ever runs.

**Risk**: Novel attacks that evade all 262 regex patterns but have a benign prefix could exploit this dampening to also evade heuristic-to-LLM escalation.

---

### MEDIUM Severity

#### Finding 8: TOCTOU in Path Boundary Checks

**Location**: `tweek/hooks/pre_tool_use.py:454-456`

**Description**: Path boundary checks use `Path.resolve()` to determine if a target is inside the project directory. A window exists between this check and actual tool execution where a symlink could be swapped to point to a sensitive location.

**Practical Risk**: Low. Claude Code hooks are synchronous -- the check and execution happen in the same process without yielding. An external process would need to swap the symlink in the microseconds between check and use.

---

#### Finding 9: TWEEK_TRUST_LEVEL Environment Variable Manipulation

**Location**: `tweek/hooks/overrides.py:276`

**Description**: The `TWEEK_TRUST_LEVEL` environment variable (set by the parent process) determines severity thresholds. Setting it to `interactive` instead of `automated` lowers the minimum severity for prompting.

**Mitigating Factor**: Validation at `overrides.py:277` only accepts `interactive` or `automated`. The variable cannot disable screening entirely -- it only adjusts the severity threshold.

---

#### Finding 10: Memory Approval Ratio Poisoning

**Location**: `tweek/memory/safety.py:47`

**Description**: The memory system suggests relaxing `ask` to `log` when a pattern has a 90% approval ratio. The `exact` scope requires only 1 weighted decision. An attacker could approve a pattern for a benign file path, building up approval history that later relaxes enforcement for a similar-looking invocation.

**Mitigating Factors**:
- CRITICAL+deterministic patterns are immune (never adjusted) -- `safety.py:53-62`
- `deny` decisions are never relaxed -- `safety.py:99-101`
- Maximum one-step relaxation (ask to log, never further) -- `safety.py:27-32`
- 30-day half-life decay reduces old decision weight
- Project-scoped hashing prevents cross-project confusion

---

#### Finding 11: Rate Limiter State In-Memory Only

**Location**: `tweek/security/rate_limiter.py`

**Description**: Rate limiter state (burst counts, per-minute counts, circuit breaker state) is stored in Python process memory. Each hook invocation is a fresh process, so state does not persist across calls.

**Impact**: Rate limiting provides no cross-invocation protection. An attacker making many calls would see each one evaluated independently rather than as an accumulating burst.

**Mitigating Factor**: Session analysis (Layer 4) provides cross-turn detection via persistent database state.

---

#### Finding 12: Missing Subprocess Timeouts

**Location**: `tweek/plugins/git_installer.py`, `tweek/plugins/git_discovery.py`

**Description**: Some `subprocess.run()` calls in git-related plugins do not specify explicit timeout parameters. A hanging git operation could block the hook indefinitely.

---

#### Finding 13: SQL F-String Table Interpolation (Code Smell)

**Location**: `tweek/memory/store.py:823,884,903`

**Description**: Table names are interpolated into SQL statements via f-strings. All table name sources are hardcoded string tuples defined 2-3 lines above the query. The `clear_table()` function validates against a whitelist set before execution (`store.py:895-900`). **Not exploitable**, but violates secure coding best practices.

---

#### Finding 14: Post-Tool Hook Does Not Screen All Tool Outputs

**Location**: `tweek/hooks/post_tool_use.py:359`

**Description**: The post-tool-use hook only screens responses from: Read, WebFetch, Bash, Grep, WebSearch. Tool responses from Task (subagents), Skill, NotebookEdit, and others are not screened for injection.

**Risk**: Content returned by a Task subagent or a Skill execution could contain prompt injection that bypasses post-screening.

---

### LOW Severity

#### Finding 15: Session ID Predictability

**Location**: `tweek/security/rate_limiter.py`

**Description**: Fallback session ID generation uses a hash of PID, CWD, and MAC address -- all predictable values.

**Impact**: Minimal. Session IDs are used for internal rate limiting correlation, not authentication.

---

#### Finding 16: Incomplete ReDoS Detection in Plugin Validator

**Location**: `tweek/plugins/base.py`

**Description**: The plugin pattern validator checks for 6 dangerous regex constructs but does not cover all catastrophic backtracking patterns. Advanced constructs like nested alternation groups are not detected.

**Impact**: Low. This validator applies to user-contributed plugin patterns, not the core 262 curated patterns.

---

#### Finding 17: Extended Latin Language Detection Threshold

**Location**: `tweek/security/language.py`

**Description**: The 8% threshold for extended Latin character density can trigger false positives on English text containing accented names.

---

#### Finding 18: No Log Injection Prevention

**Location**: `tweek/logging/security_log.py`

**Description**: Newline characters in logged commands are not escaped, potentially allowing crafted commands to create misleading log entries.

**Impact**: Minimal. Logs are stored in SQLite (structured storage), not flat text files. The `LogRedactor` class handles sensitive data redaction comprehensively (API keys, tokens, passwords, emails, credit cards).

---

## 6. Corrected False Positives

The following items were flagged by automated analysis but verified to be correctly handled by existing code:

### FP-1: "No Unicode Normalization Before Pattern Matching"

**Agent Claim**: Homoglyph attacks (Cyrillic characters substituted for Latin) bypass pattern matching.

**Reality**: The `PatternMatcher._normalize()` method at `pre_tool_use.py:591-594` applies NFKC Unicode normalization before all pattern matching. Both `check()` (line 601) and `check_all()` (line 612) call `self._normalize(content)` as their first operation. This is the correct defense against homoglyph evasion.

### FP-2: "Skill Guard Path Traversal via Substring Matching"

**Agent Claim**: `guard.py:148` uses substring matching, allowing `../` traversal to bypass.

**Reality**: `Path.resolve()` at `guard.py:124` resolves all `..` components to absolute paths before any string comparison. The substring check at line 148 operates on the fully resolved path. The primary check at lines 129-135 uses `Path.relative_to()` which is architecturally sound.

### FP-3: "break_glass.json Not Protected from AI Modification"

**Agent Claim**: The break-glass state file is not in `PROTECTED_CONFIG_FILES` list.

**Reality**: `overrides.py:343-347` contains a directory-level check that matches `.tweek` as a path component:
```python
for part in resolved.parts:
    if part == ".tweek":
        return True
```
This catches ALL files inside any `.tweek/` directory, including break_glass.json and fingerprints.json.

### FP-4: "SQL Injection via Table Name F-Strings"

**Agent Claim**: F-string interpolation of table names in `store.py` enables SQL injection.

**Reality**: All table names in the affected queries (`store.py:821-822,882-883`) are hardcoded string tuples defined immediately above the query. The `clear_table()` function includes explicit whitelist validation at line 895-900. No user input reaches these table name variables.

---

## 7. Architecture Strengths

### 7.1 Fail-Closed Error Handling
Both hooks return hard deny (`permissionDecision: "deny"`) on JSON parse errors and unhandled exceptions. Invalid input or crashes never result in silent tool execution.
- Pre-tool-use: `pre_tool_use.py:1830-1860`
- Post-tool-use: `post_tool_use.py:445-477`

### 7.2 Additive-Only Configuration Merges
Project-level configuration can only escalate decisions (log to ask, ask to deny), never relax them. This is enforced by `EnforcementPolicy.merge_additive_only()` at `overrides.py:519-535` and by the tier system where skills can only escalate tool tiers (`pre_tool_use.py:371-383`).

### 7.3 Memory Safety Invariants
The memory system has four non-negotiable safety rules (`safety.py:1-11`):
1. CRITICAL+deterministic patterns are **immune** -- memory never adjusts them
2. `deny` decisions are **never** relaxed by memory
3. Maximum one-step relaxation: ask to log only
4. Minimum 90% approval ratio + 80% confidence score required

### 7.4 Self-Protection
The AI agent cannot modify security configuration files, run `tweek uninstall/trust/untrust`, or bypass the skill isolation chamber. Protection is enforced at both the Write/Edit tool level and the Bash command level with regex matching.

### 7.5 Post-Tool Response Screening
Unique among security tools -- Tweek screens content **returned** by tools (not just requests) to catch prompt injection in fetched web pages, read files, and command output. Critical patterns are redacted from the content before it reaches the AI.

### 7.6 Multi-Provider LLM Support
The LLM review layer supports local-first inference (ONNX on-device, Ollama, LM Studio) with automatic cloud fallback (Google, OpenAI, xAI, Anthropic). This reduces latency, cost, and API dependency.

### 7.7 Comprehensive Logging
Every screening decision is logged with correlation IDs, session IDs, event types, and full metadata to SQLite. The `LogRedactor` class prevents sensitive data (API keys, passwords, etc.) from appearing in logs.

### 7.8 Live Validation During This Audit
During the generation of this report, Tweek's own screening system triggered multiple times:
- **Pre-tool-use hook** blocked writing this report because the content contained literal attack examples (credential file paths, recursive deletion commands). The report was revised to use abstract descriptions.
- **Post-tool-use hook** flagged every source code read because the patterns.yaml and hook source files contain regex strings referencing attack vectors.

This demonstrates the system is operationally effective and screens its own source code.

---

## 8. Risk Matrix

| # | Finding | Severity | Confidence | Exploitability | Layer Affected |
|---|---------|----------|------------|----------------|----------------|
| 1 | ReDoS in pattern matching | **CRITICAL** | High | High | Layer 2 |
| 2 | XML delimiter escape in LLM reviewer | **CRITICAL** | High | Medium | Layer 3 |
| 3 | LLM fails open on provider errors | HIGH | High | Medium | Layer 3 |
| 4 | Break-glass race condition | HIGH | High | Low | Self-protection |
| 5 | No model integrity verification | HIGH | High | Low | Layer 3 (local) |
| 6 | Local model confidence escalation | HIGH | Medium | Low | Layer 3 (local) |
| 7 | Heuristic benign dampening exploit | HIGH | Medium | Low | Layer 2.5 |
| 8 | TOCTOU in path checks | MEDIUM | High | Low | Tier escalation |
| 9 | Trust level env var manipulation | MEDIUM | High | Medium | Trust filtering |
| 10 | Memory approval ratio poisoning | MEDIUM | Medium | Low | Memory |
| 11 | Rate limiter state in-memory | MEDIUM | High | High | Layer 1 |
| 12 | Missing subprocess timeouts | MEDIUM | High | Low | Plugins |
| 13 | SQL f-string code smell | MEDIUM | High | None | Memory |
| 14 | Post-tool screening gaps | MEDIUM | High | Medium | Post-screening |
| 15 | Session ID predictability | LOW | High | Low | Layer 1 |
| 16 | Incomplete ReDoS detection | LOW | Medium | Low | Plugins |
| 17 | Language detection false positives | LOW | Medium | N/A | Tier escalation |
| 18 | No log injection prevention | LOW | Medium | Low | Logging |

---

## 9. Recommendations

### Priority 1: Critical Fixes

**R1. Add per-pattern regex timeout** (addresses Finding 1)

Use Python's `regex` library (drop-in replacement for `re`) with built-in timeout support:
```python
import regex
regex.search(pattern, content, timeout=2.0, flags=regex.IGNORECASE | regex.DOTALL)
```
Alternatively, pre-validate all 262 patterns for catastrophic backtracking potential during CI.

**R2. Escape XML delimiters in LLM review prompt** (addresses Finding 2)

Replace angle brackets in untrusted content before insertion, or use a random per-invocation delimiter:
```python
import secrets
delimiter = f"TWEEK_BOUNDARY_{secrets.token_hex(8)}"
prompt = f"<{delimiter}>\n{command}\n</{delimiter}>"
```

### Priority 2: High-Impact Improvements

**R3. Add model checksum verification** (addresses Finding 5)

Ship SHA-256 hashes in the `MODEL_CATALOG` dict and verify after download.

**R4. Add file locking to break-glass state** (addresses Finding 4)

Apply the same `fcntl.flock()` pattern already used in the vault module.

**R5. Review benign dampening in heuristic scorer** (addresses Finding 7)

Consider requiring the benign pattern to be the **only** command (not part of a chain with `&&`, `||`, `;`, `|`).

### Priority 3: Moderate Improvements

**R6. Persist rate limiter state** (addresses Finding 11)

Use the existing SQLite infrastructure for cross-invocation rate tracking.

**R7. Expand post-tool screening to Task/Skill outputs** (addresses Finding 14)

Add Task and Skill to the `screened_tools` set at `post_tool_use.py:359`.

**R8. Add subprocess timeouts to all subprocess.run() calls** (addresses Finding 12)

**R9. Parameterize SQL table names** (addresses Finding 13)

Replace f-strings with an explicit table name mapping dict, even though current code is not exploitable.

### Priority 4: Low-Impact Hardening

**R10.** Use cryptographically random session IDs instead of PID/MAC hash (Finding 15)

**R11.** Expand ReDoS detection patterns in plugin validator (Finding 16)

**R12.** Tune extended Latin detection threshold (Finding 17)

**R13.** Escape newlines in logged commands (Finding 18)

---

*Report generated via multi-agent parallel security audit with manual verification.*
*All line number references verified against source code as of 2026-02-02.*
