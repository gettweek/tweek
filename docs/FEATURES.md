# Tweek — Full Feature List

## Security (all free)

- **259 attack patterns** across 22 categories (credential theft, prompt injection, data exfiltration, MCP CVEs, social engineering, RAG poisoning, multi-agent attacks, encoding/obfuscation detection, and more)
- **Graduated enforcement** — severity × confidence decision matrix: CRITICAL+deterministic → hard deny, HIGH/MEDIUM → user prompt, LOW → log-only (configurable via `overrides.yaml`)
- **Pattern confidence classification** — every pattern classified as `deterministic` (59 patterns, near-zero FP), `heuristic` (144, good signal), or `contextual` (56, context-dependent)
- **Content redaction** — CRITICAL+deterministic matches in tool responses are auto-redacted (`[REDACTED BY TWEEK]`) before the AI agent can act on them
- **Break-glass override** — emergency deny→ask downgrade via `tweek override --pattern <name> --once` with full audit trail (never downgrades to allow)
- **False-positive feedback loop** — per-pattern FP tracking with auto-demotion at 5% threshold (min 20 triggers); CRITICAL patterns immune from auto-demotion
- **Bidirectional screening** — PreToolUse hooks screen requests, PostToolUse hooks screen responses
- **Non-English content detection** — Unicode script analysis for CJK, Cyrillic, Arabic, Hebrew, Thai, Devanagari, and Latin-script European language keyword matching (French, German, Spanish, Portuguese, Italian, Dutch)
- **Configurable non-English handling** — escalate to LLM review (default), translate, both, or none
- **Skill audit** — one-time security analysis of skill files with language detection, optional translation, pattern matching, and LLM semantic review (`tweek audit`)
- **LLM semantic review** via Claude Haiku with translation support (bring your own API key)
- **Session anomaly detection** — 9 anomaly types including path escalation, behavior shift, capability aggregation
- **Rate limiting** with burst detection, velocity anomaly, and circuit breaker
- **Sandbox preview** — speculative execution on macOS (sandbox-exec) and Linux (firejail/bwrap)
- **Credential vault** with OS keychain integration (macOS Keychain, GNOME Keyring, Windows Credential Locker)
- **Agentic memory** — persistent cross-session learning from past security decisions with time-decay weighting, source trust tracking, workflow baselines, and learned whitelist suggestions (`tweek memory`)
- **Security event logging** with automatic redaction to SQLite
- **NDJSON structured log export** (for ELK/Splunk/Datadog)
- **CLI hooks** for Claude Code (global or per-project, both PreToolUse and PostToolUse)
- **MCP proxy** with human-in-the-loop approval queue
- **HTTP proxy** for Cursor, Windsurf, Continue.dev
- **Plugin system** — 4 categories (compliance, LLM providers, tool detectors, screening) with git-based installation
- **5 LLM provider parsers** — Anthropic, OpenAI, Google Gemini, Azure OpenAI, AWS Bedrock
- **5 tool detectors** — Moltbot, Cursor, Continue.dev, GitHub Copilot, Windsurf
- **Health diagnostics** (`tweek doctor`)
- **Interactive setup wizard** (`tweek quickstart`)
- **Security presets** — `paranoid`, `cautious`, `trusted`
- **Automatic tier escalation** — content-based escalation for production references, destructive SQL, cloud deployments, sudo commands
- **Custom pattern authoring**
- **Secret scanning** for hardcoded credentials in files
- **CSV export** and log bundling for diagnostics

## Teams (coming soon)

- **Compliance scanning** — HIPAA, PCI-DSS, GDPR, SOC2, Government classification (6 compliance plugins)
- **Centralized configuration** management
- **Team license** administration
- **Audit log API** access
- **Priority support**

## Enterprise (coming soon)

- **SSO integration** (SAML/OIDC)
- **Custom pattern development**
- **SLA-backed support**
- **Dedicated account manager**

---

## Graduated Enforcement

Not all threats are equal. Tweek uses a **severity × confidence** matrix:

| | **Deterministic** | **Heuristic** | **Contextual** |
|---|:---:|:---:|:---:|
| **CRITICAL** | `deny` (hard block) | `ask` (user prompt) | `ask` |
| **HIGH** | `ask` | `ask` | `ask` |
| **MEDIUM** | `ask` | `ask` | `ask` |
| **LOW** | `log` (allow + audit) | `log` | `log` |

**Pattern confidence levels:**

- **Deterministic** (59 patterns) — Precise regex targeting specific file paths or commands. Near-zero false positive rate.
- **Heuristic** (144 patterns) — Good signal but may trigger in legitimate contexts.
- **Contextual** (56 patterns) — Depends heavily on surrounding context.

The enforcement matrix is fully configurable via `overrides.yaml`. Project-level overrides can only **escalate** decisions (e.g., `log` → `ask`), never downgrade — enforced by additive-only merge.

---

## Platform Support

| Feature | macOS | Linux | Windows |
|---------|:-----:|:-----:|:-------:|
| CLI Hooks | Yes | Yes | Yes |
| Pattern Matching | Yes | Yes | Yes |
| Language Detection | Yes | Yes | Yes |
| Credential Vault | Keychain | Secret Service | Credential Locker |
| Sandbox | sandbox-exec | firejail/bwrap | — |
| HTTP Proxy | Yes | Yes | Yes |
| MCP Proxy | Yes | Yes | Yes |

**Requirements:** Python 3.10+
