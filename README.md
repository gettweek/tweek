<![CDATA[# Tweek

**Defense-in-depth security for AI coding assistants.**

Tweek intercepts, screens, and audits every tool call made by AI assistants like Claude Code, Claude Desktop, ChatGPT Desktop, and Cursor — catching prompt injection, credential theft, and data exfiltration before damage is done.

---

## Table of Contents

- [Why Tweek](#why-tweek)
- [Quick Start](#quick-start)
- [Architecture Overview](#architecture-overview)
- [Three Interception Layers](#three-interception-layers)
- [Five-Layer Screening Pipeline](#five-layer-screening-pipeline)
- [Configuration](#configuration)
- [CLI Reference](#cli-reference)
- [Security Features](#security-features)
- [Credential Vault](#credential-vault)
- [MCP Integration](#mcp-integration)
- [HTTP Proxy](#http-proxy)
- [Plugin System](#plugin-system)
- [Logging & Audit](#logging--audit)
- [Platform Support](#platform-support)
- [Licensing](#licensing)
- [Troubleshooting](#troubleshooting)
- [Data Locations](#data-locations)
- [Contributing](#contributing)

---

## Why Tweek

AI coding assistants execute tools — Bash commands, file reads/writes, web fetches — based on what they see in your codebase, terminal output, and web content. A single malicious instruction hidden in a README, error message, or MCP server response can trick the AI into:

- **Stealing credentials** — SSH keys, API tokens, .env files exfiltrated via curl/wget
- **Exfiltrating source code** — proprietary code sent to attacker-controlled servers
- **Compromising your system** — reverse shells, malware downloads, config tampering
- **Hijacking the session** — prompt injection that redirects the AI's behavior

Tweek applies defense-in-depth security: three interception layers with a multi-stage screening pipeline ensure that no single bypass defeats all protections. Every action is logged for forensic analysis.

For a deeper discussion, see [docs/PHILOSOPHY.md](docs/PHILOSOPHY.md).

---

## Quick Start

```bash
# Install via pip
pip install tweek

# Or install from GitHub
pip install git+https://github.com/gettweek/tweek.git

# Install hooks globally (protects all projects)
tweek install

# Or for just this project
tweek install --scope project

# Verify installation
tweek doctor

# Check protection status
tweek status
```

After installation, Tweek automatically screens every tool call. No configuration is required — sensible defaults protect you immediately.

---

## Architecture Overview

Tweek provides three independent interception layers that feed into a unified screening pipeline:

```
                    ┌─────────────────┐
                    │  AI Assistant    │
                    │  (Claude, GPT,  │
                    │   Cursor, etc.) │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
     ┌────────────┐  ┌────────────┐  ┌────────────┐
     │   CLI      │  │   MCP      │  │   HTTP     │
     │   Hooks    │  │   Proxy    │  │   Proxy    │
     │            │  │            │  │            │
     │ Claude     │  │ Desktop    │  │ Cursor,    │
     │ Code       │  │ Clients    │  │ API calls  │
     └─────┬──────┘  └─────┬──────┘  └─────┬──────┘
           │               │               │
           └───────────────┼───────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │  Unified Screening     │
              │  Pipeline              │
              │                        │
              │  0. Compliance Scan    │
              │  1. Rate Limiting      │
              │  2. Pattern Matching   │
              │  3. LLM Review (PRO)   │
              │  4. Session Analysis   │
              │  5. Sandbox Preview    │
              └────────────┬───────────┘
                           │
                    ┌──────┴──────┐
                    │  Decision:  │
                    │  Allow /    │
                    │  Prompt /   │
                    │  Block      │
                    └──────┬──────┘
                           │
                    ┌──────┴──────┐
                    │  Audit Log  │
                    │  (SQLite +  │
                    │   NDJSON)   │
                    └─────────────┘
```

Every tool call, regardless of origin, passes through the same screening pipeline. Results are logged with correlation IDs linking all events from a single screening pass.

---

## Three Interception Layers

### Layer 1: CLI Hooks (Claude Code)

Tweek uses Claude Code's native hook system (`PreToolUse` / `PostToolUse`) to intercept tool calls before execution:

```bash
tweek install                    # Install globally
tweek install --scope project    # Install per-project
```

This is the primary interception layer for Claude Code users. Hooks are registered in `.claude/settings.json` and receive tool call data via stdin.

### Layer 2: MCP Proxy (Desktop Clients)

For Claude Desktop, ChatGPT Desktop, and Gemini, Tweek operates as a transparent MCP proxy that sits between the client and upstream MCP servers:

```
Desktop Client → Tweek MCP Proxy → Upstream MCP Server
                      │
                 Screening Pipeline
```

Configure in your MCP client settings to route through Tweek:

```bash
tweek mcp setup claude-desktop     # Auto-configure Claude Desktop
tweek mcp setup chatgpt-desktop    # Auto-configure ChatGPT
tweek mcp proxy --port 8765        # Start proxy server
```

The proxy also exposes Tweek Gateway tools (`tweek_vault_get`, `tweek_status`) directly to the AI client.

### Layer 3: HTTP Proxy (API-based Clients)

For Cursor, Windsurf, Continue.dev, and other API-based clients, Tweek operates as an HTTPS interception proxy using mitmproxy:

```bash
tweek proxy start                  # Start HTTP proxy
tweek proxy trust                  # Install CA certificate
tweek proxy setup cursor           # Auto-configure Cursor
```

The proxy intercepts LLM API traffic (Anthropic, OpenAI, Google, AWS Bedrock), extracts tool calls from responses, and screens them through the pipeline.

See [docs/HTTP_PROXY.md](docs/HTTP_PROXY.md) for CA certificate setup and advanced configuration.

---

## Five-Layer Screening Pipeline

Every tool call passes through up to six screening stages. Earlier layers are fast and cheap; later layers are slower but catch more sophisticated attacks.

### Layer 0: Compliance Scanning

Scans content for regulatory compliance violations before processing. Plugins check for PII, PHI (HIPAA), payment card data (PCI-DSS), classified markings (government), legal privilege markers, and SOC2/GDPR violations.

**Enterprise tier only.** See [docs/DEFENSE_LAYERS.md](docs/DEFENSE_LAYERS.md).

### Layer 1: Rate Limiting

Detects resource theft and brute-force patterns:
- Rapid tool invocation frequency
- Repeated access to the same sensitive paths
- Circuit breaker for sustained abuse

**PRO tier.** See [docs/DEFENSE_LAYERS.md](docs/DEFENSE_LAYERS.md).

### Layer 2: Pattern Matching

116+ regex patterns organized into six categories:
- **Credential theft** — SSH key reads, .env access, keychain queries
- **Data exfiltration** — curl/wget to suspicious hosts, DNS tunneling
- **Prompt injection** — system prompt overrides, instruction hijacking
- **MCP vulnerabilities** — known CVEs in MCP implementations
- **macOS-specific** — Keychain dumping, TCC database access
- **AI-specific** — model weight theft, training data extraction

Patterns are updated independently via `tweek update` and can be extended with custom patterns (Enterprise).

**Included in FREE tier.** See [docs/ATTACK_PATTERNS.md](docs/ATTACK_PATTERNS.md).

### Layer 3: LLM Review

Semantic analysis using Claude Haiku for novel attacks that bypass regex:
- Obfuscated commands (base64, hex encoding, variable interpolation)
- Multi-step attack chains
- Context-aware risk assessment

**PRO tier.** See [docs/DEFENSE_LAYERS.md](docs/DEFENSE_LAYERS.md).

### Layer 4: Session Analysis

Cross-turn anomaly detection identifies multi-step attack patterns:
- Path escalation (moving from safe to sensitive directories)
- Graduated probing (testing boundaries before attacking)
- Behavior shifts (sudden change in tool usage patterns)
- Denial response patterns (repeated attempts after blocks)
- Capability aggregation (combining individually-safe operations)

Nine anomaly types with risk scoring. **PRO tier.**

### Layer 5: Sandbox Preview

Speculative execution in a macOS sandbox (`sandbox-exec`) or Linux sandbox (firejail/bubblewrap):
- Command runs with restricted permissions
- File access, network attempts, and process spawns are captured
- Violations trigger security prompts

**PRO tier, macOS/Linux only.** See [docs/SANDBOX.md](docs/SANDBOX.md).

---

## Configuration

Tweek uses a three-layer configuration system:

```
Project (./.tweek/config.yaml)     ← Highest priority
   ↓
User (~/.tweek/config.yaml)
   ↓
Built-in defaults                  ← Lowest priority
```

### Security Tiers

Each tool is assigned a security tier that determines which screening layers activate:

| Tier | Screening | Behavior |
|------|-----------|----------|
| `safe` | None | Allow without screening |
| `default` | Pattern matching | Log + allow if clean |
| `risky` | All layers | Prompt user if flagged |
| `dangerous` | All layers + sandbox | Block or prompt for all |

### Presets

Apply a preset to configure all tools at once:

```bash
tweek config preset paranoid    # Maximum security (everything risky/dangerous)
tweek config preset cautious    # Balanced (default)
tweek config preset trusted     # Minimal prompts (most tools safe)
```

### Per-Tool Configuration

```bash
# Set a specific tool tier
tweek config set --tool Bash --tier dangerous
tweek config set --tool WebFetch --tier risky
tweek config set --tool Read --tier safe

# Set a skill tier
tweek config set --skill code-review --tier trusted

# View current configuration
tweek config list

# Show diff between presets
tweek config diff --preset paranoid

# Validate configuration
tweek config validate

# Reset to defaults
tweek config reset
```

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for the complete configuration reference.

---

## CLI Reference

### Top-Level Commands

| Command | Description |
|---------|-------------|
| `tweek install` | Install hooks (global or project scope) |
| `tweek uninstall` | Remove hooks |
| `tweek update` | Update attack patterns from GitHub |
| `tweek doctor` | Run health checks on installation |
| `tweek status` | Show protection status and active configuration |
| `tweek quickstart` | Interactive setup wizard |

### Configuration (`tweek config`)

| Command | Description |
|---------|-------------|
| `tweek config list` | Show current tool/skill tiers |
| `tweek config set` | Set tool or skill tier |
| `tweek config preset <name>` | Apply paranoid/cautious/trusted preset |
| `tweek config reset` | Reset to defaults |
| `tweek config validate` | Check configuration for errors |
| `tweek config diff` | Compare current config with a preset |

### Credential Vault (`tweek vault`)

| Command | Description |
|---------|-------------|
| `tweek vault store SKILL KEY VALUE` | Store a credential |
| `tweek vault get SKILL KEY` | Retrieve a credential |
| `tweek vault delete SKILL KEY` | Delete a credential |
| `tweek vault migrate-env` | Migrate .env file to vault |

### License Management (`tweek license`)

| Command | Description |
|---------|-------------|
| `tweek license status` | Show license tier and info |
| `tweek license activate KEY` | Activate a license key |
| `tweek license deactivate` | Remove license |

### Security Logs (`tweek logs`)

| Command | Description |
|---------|-------------|
| `tweek logs show` | View recent security events |
| `tweek logs export` | Export events to CSV |
| `tweek logs clear` | Clear old events |
| `tweek logs bundle` | Create diagnostic zip for support |

### HTTP Proxy (`tweek proxy`)

| Command | Description |
|---------|-------------|
| `tweek proxy start` | Start HTTPS interception proxy |
| `tweek proxy stop` | Stop proxy |
| `tweek proxy trust` | Install CA certificate |
| `tweek proxy config` | Show proxy configuration |
| `tweek proxy wrap <command>` | Run command through proxy |
| `tweek proxy setup <client>` | Auto-configure client |

### MCP Integration (`tweek mcp`)

| Command | Description |
|---------|-------------|
| `tweek mcp gateway` | Start MCP gateway server |
| `tweek mcp config` | Show MCP configuration |
| `tweek mcp proxy` | Start MCP proxy server |
| `tweek mcp approve` | View pending approval requests |
| `tweek mcp decide <id>` | Approve or deny a request |
| `tweek mcp setup <client>` | Auto-configure desktop client |

### Plugin Management (`tweek plugins`)

| Command | Description |
|---------|-------------|
| `tweek plugins list` | List installed plugins |
| `tweek plugins info <name>` | Show plugin details |
| `tweek plugins set` | Configure plugin |
| `tweek plugins reset` | Reset plugin config |
| `tweek plugins scan` | Scan with compliance plugins |
| `tweek plugins install <url>` | Install from git repository |
| `tweek plugins update` | Update installed plugins |
| `tweek plugins remove <name>` | Remove a plugin |
| `tweek plugins search <query>` | Search for plugins |
| `tweek plugins lock` | Lock plugin versions |
| `tweek plugins verify` | Verify plugin integrity |
| `tweek plugins registry` | Manage plugin registry |

See [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) for complete documentation with all flags and examples.

---

## Security Features

### Pattern Matching (116+ Patterns)

Tweek ships with a comprehensive pattern library covering six attack categories:

**Credential Theft** — Reading SSH keys, AWS credentials, GCP service accounts, .env files, browser cookies, keychain entries, and more.

**Data Exfiltration** — curl/wget to exfiltration services (transfer.sh, 0x0.st, webhook.site), DNS tunneling, encoded uploads, piping to netcat.

**Prompt Injection** — System prompt overrides, instruction injection, role-play attacks, jailbreak attempts.

**MCP Vulnerabilities** — Known CVEs and attack patterns specific to the Model Context Protocol.

**macOS Specific** — Keychain Access dumps, TCC database reads, security framework abuse.

**AI-Specific** — Model weight theft, training data extraction, API key harvesting from config.

Patterns are updated independently of Tweek:
```bash
tweek update            # Pull latest patterns
tweek update --check    # Check without installing
```

### Log Redaction

All logs are automatically redacted before storage. The redactor removes:
- API keys, AWS credentials, JWT tokens
- GitHub/Slack/OAuth tokens
- Passwords and connection strings
- Private keys and certificates
- Email addresses and credit card numbers
- SSH key paths in commands

This ensures that even if logs are shared for debugging, sensitive data is never exposed.

---

## Credential Vault

Store secrets in your OS keychain instead of .env files:

- **macOS**: Keychain Access
- **Linux**: Secret Service (GNOME Keyring, KWallet, KeePassXC)
- **Windows**: Windows Credential Locker

```bash
# Store a credential
tweek vault store myapp API_KEY "sk-..."

# Retrieve (logged)
tweek vault get myapp API_KEY

# Migrate from .env
tweek vault migrate-env --skill myapp --env-file .env

# Delete
tweek vault delete myapp API_KEY
```

Every vault access is logged as a `VAULT_ACCESS` security event. The MCP gateway exposes `tweek_vault_get` so AI assistants can retrieve credentials without seeing them in plaintext.

See [docs/VAULT.md](docs/VAULT.md) for details.

---

## MCP Integration

Tweek integrates with the Model Context Protocol in two ways:

### MCP Gateway

Exposes Tweek capabilities as MCP tools for direct use by AI assistants:

- `tweek_vault_get` — Retrieve credentials from the vault
- `tweek_status` — Check protection status

### MCP Proxy

Transparent proxy that sits between desktop clients and upstream MCP servers. All tool calls from upstream servers are screened through Tweek's pipeline before reaching the AI.

```yaml
# ~/.tweek/config.yaml
mcp:
  proxy:
    upstreams:
      filesystem:
        command: npx
        args: ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
      github:
        command: npx
        args: ["-y", "@modelcontextprotocol/server-github"]
```

Blocked calls are queued for human approval:
```bash
tweek mcp approve               # View pending requests
tweek mcp decide <id> --approve # Approve
tweek mcp decide <id> --deny    # Deny
```

See [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) for setup guides.

---

## HTTP Proxy

For API-based clients (Cursor, Windsurf, Continue.dev), Tweek provides HTTPS interception using mitmproxy:

```bash
tweek proxy start                  # Start on default port
tweek proxy start --port 9090      # Custom port
tweek proxy trust                  # Install CA certificate
```

The proxy monitors traffic to:
- `api.anthropic.com` (Anthropic/Claude)
- `api.openai.com` (OpenAI/GPT)
- `generativelanguage.googleapis.com` (Google/Gemini)
- `bedrock-runtime.*.amazonaws.com` (AWS Bedrock)

Tool calls in API responses are extracted and screened. Blocked calls have their responses modified to prevent execution.

See [docs/HTTP_PROXY.md](docs/HTTP_PROXY.md) for CA setup and proxy configuration.

---

## Plugin System

Tweek's screening engine is extensible through four plugin categories:

| Category | Purpose | Examples |
|----------|---------|---------|
| **Compliance** | Domain-specific regulation scanning | Government (ITAR/EAR), HIPAA, PCI-DSS, Legal Privilege, SOC2, GDPR |
| **LLM Providers** | API provider detection and tool extraction | Anthropic, OpenAI, Google, Azure OpenAI, AWS Bedrock |
| **Tool Detectors** | IDE/tool-specific behavior | Cursor, Copilot, Windsurf, Continue.dev, Moltbot |
| **Screening** | Security screening methods | Pattern matching, LLM review, Rate limiting, Session analysis |

### Installing Plugins

```bash
# From git repository
tweek plugins install https://github.com/example/tweek-plugin-hipaa

# List installed
tweek plugins list

# Verify integrity
tweek plugins verify
```

### Plugin Scoping

Plugins can be scoped to specific tools, skills, projects, tiers, and directions:
```yaml
plugins:
  my-plugin:
    tools: [Bash, Write]
    skills: [code-review]
    tiers: [risky, dangerous]
    directions: [input, output]
```

### Built-in Compliance Plugins

Tweek includes six compliance plugins (Enterprise tier):
- **Government** — ITAR/EAR classification markings, security clearance levels
- **HIPAA** — Protected Health Information (PHI) detection
- **PCI-DSS** — Payment card data, CVV, magnetic stripe data
- **Legal** — Attorney-client privilege, work product doctrine
- **SOC2** — Access control, audit trail, encryption requirements
- **GDPR** — Personal data, consent records, data subject rights

See [docs/PLUGINS.md](docs/PLUGINS.md) for the plugin development guide.

---

## Logging & Audit

### Event Logging

Every security event is logged to a SQLite database at `~/.tweek/security.db` with automatic redaction:

```bash
# View recent events
tweek logs show
tweek logs show --limit 50 --type blocked

# Statistics
tweek logs show --stats
tweek logs show --stats --days 30

# Export to CSV
tweek logs export --output security_events.csv

# Clear old events
tweek logs clear --days 90
```

### Event Types

| Event Type | Description |
|-----------|-------------|
| `tool_invoked` | Tool call received |
| `pattern_match` | Regex pattern matched |
| `llm_rule_match` | LLM review flagged |
| `escalation` | Tier escalated due to content |
| `allowed` | Execution permitted |
| `blocked` | Execution blocked |
| `user_prompted` | User asked for confirmation |
| `sandbox_preview` | Sandbox preview executed |
| `vault_access` | Credential store/get/delete |
| `config_change` | Configuration modified |
| `license_event` | License activation/deactivation |
| `mcp_approval` | MCP approval queue decision |
| `proxy_event` | HTTP proxy screening |
| `health_check` | Diagnostic results |
| `plugin_event` | Plugin load/failure |

### Correlation IDs

Events from a single screening pass are linked by a `correlation_id`, making it easy to trace the full decision chain for any tool call.

### Structured JSON Logging

Enable NDJSON logging for integration with log aggregation systems (ELK, Splunk, Datadog):

```yaml
# ~/.tweek/config.yaml
logging:
  json_events: true
```

Events are written to `~/.tweek/security_events.jsonl` with automatic 10MB rotation.

### Diagnostic Bundle

Create a zip bundle for support:

```bash
tweek logs bundle                        # Create in current dir
tweek logs bundle -o /tmp/bundle.zip     # Custom output path
tweek logs bundle --days 7               # Last 7 days only
tweek logs bundle --dry-run              # Show what would be collected
```

The bundle includes security database, approval database, proxy logs, JSON event logs, redacted configs, doctor output, and system info. Sensitive files (license keys, certificates, credentials) are never included.

See [docs/LOGGING.md](docs/LOGGING.md) for the complete logging reference.

---

## Platform Support

| Feature | macOS | Linux | Windows |
|---------|-------|-------|---------|
| CLI Hooks | Yes | Yes | Yes |
| Pattern Matching | Yes | Yes | Yes |
| Security Logging | Yes | Yes | Yes |
| Credential Vault | Keychain | Secret Service | Credential Locker |
| Sandbox | sandbox-exec | firejail/bwrap | Not available |
| HTTP Proxy | mitmproxy | mitmproxy | mitmproxy |
| MCP Proxy | Yes | Yes | Yes |

### Requirements

- Python 3.11+
- Claude Code (for CLI hooks)
- Optional: `keyring` (vault), `mitmproxy` (HTTP proxy), `mcp` (MCP integration)

---

## Licensing

| Feature | FREE | PRO ($49 one-time) | ENTERPRISE |
|---------|------|---------------------|------------|
| Pattern matching (116+ patterns) | Yes | Yes | Yes |
| Security logging | Yes | Yes | Yes |
| Credential vault | Yes | Yes | Yes |
| CLI commands | Yes | Yes | Yes |
| Global/project install | Yes | Yes | Yes |
| LLM review (Claude Haiku) | | Yes | Yes |
| Session analysis | | Yes | Yes |
| Rate limiting | | Yes | Yes |
| Advanced logging + CSV export | | Yes | Yes |
| Custom per-tool tiers | | Yes | Yes |
| Priority email support | | Yes | Yes |
| Compliance plugins | | | Yes |
| Custom patterns | | | Yes |
| Pattern allowlisting | | | Yes |
| SSO integration | | | Yes |
| Audit API | | | Yes |
| SLA-backed support | | | Yes |

```bash
# Check current tier
tweek license status

# Activate license
tweek license activate YOUR_LICENSE_KEY

# Deactivate
tweek license deactivate
```

Purchase at [gettweek.com/pricing](https://gettweek.com/pricing).

See [docs/LICENSING.md](docs/LICENSING.md) for feature details.

---

## Troubleshooting

### Quick Diagnostics

```bash
# Run all health checks
tweek doctor

# Check specific components
tweek status
```

`tweek doctor` verifies:
1. Hook installation (global and project)
2. Configuration validity
3. Attack patterns loaded
4. Security database accessible
5. Vault backend available
6. Sandbox availability
7. License status
8. MCP package availability
9. Proxy configuration
10. Plugin integrity

### Common Issues

**Hooks not triggering?**
```bash
tweek doctor              # Check installation
tweek install --force     # Reinstall hooks
```

**Patterns not matching?**
```bash
tweek update --force      # Re-download patterns
tweek config validate     # Check config
```

**Bundle for support:**
```bash
tweek logs bundle -o debug_bundle.zip
```

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) for comprehensive troubleshooting.

---

## Data Locations

All Tweek data lives under `~/.tweek/`:

| Path | Purpose |
|------|---------|
| `~/.tweek/config.yaml` | User configuration |
| `~/.tweek/security.db` | SQLite security event log |
| `~/.tweek/approvals.db` | MCP approval queue |
| `~/.tweek/security_events.jsonl` | NDJSON structured log (opt-in) |
| `~/.tweek/patterns/` | Attack pattern definitions |
| `~/.tweek/license.key` | License key file |
| `~/.tweek/proxy/` | Proxy logs and certificates |
| `~/.tweek/certs/` | CA certificates for HTTPS proxy |
| `~/.tweek/plugins/` | Installed plugins |
| `./.tweek/config.yaml` | Project-level configuration |

---

## Contributing

Contributions are welcome. Please open an issue first to discuss what you would like to change.

---

## Links

- **Website**: [gettweek.com](https://gettweek.com)
- **Issues**: [github.com/gettweek/tweek/issues](https://github.com/gettweek/tweek/issues)
- **Documentation**: [docs/](docs/)

---

## License

Apache 2.0 — See [LICENSE](LICENSE) for details.
]]>