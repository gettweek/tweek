# Tweek

**Defense-in-depth security for AI coding assistants.**

Protect your credentials, code, and system from prompt injection attacks.

## Installation

```bash
# One-liner (recommended)
curl -sSL https://raw.githubusercontent.com/gettweek/tweek/main/scripts/install.sh | bash

# Or via pip (after PyPI publish)
pip install tweek

# Or from GitHub directly
pip install git+https://github.com/gettweek/tweek.git

# Then install hooks
tweek install
```

## What Does Tweek Protect Against?

AI coding assistants like Claude Code can be tricked by malicious content in files, websites, or error messages. Tweek prevents:

- **Credential theft** - SSH keys, API tokens, .env files exfiltrated via curl/wget
- **Data exfiltration** - Source code sent to attacker-controlled servers
- **System compromise** - Reverse shells, malware downloads, config tampering
- **Prompt injection** - Hidden instructions that hijack the AI's behavior

## Quick Start

```bash
# Install Tweek hooks (global - protects all projects)
tweek install

# Or install for just this project
tweek install --scope project

# Check status
tweek status

# View security events
tweek logs show
```

## How It Works

Tweek uses Claude Code's hook system to intercept commands before execution:

```
Command Request
     │
     ▼
┌─────────────────────────────────┐
│ 1. PATTERN MATCHING             │  23 core patterns (FREE)
│    - Credential access          │  116 total patterns (PRO)
│    - Network exfiltration       │
│    - Prompt injection           │
└─────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────┐
│ 2. TIERED RESPONSE              │
│    - safe: allow                │
│    - default: log + allow       │
│    - risky: prompt user         │
│    - dangerous: block           │
└─────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────┐
│ 3. SECURITY LOGGING             │  All events logged for
│    - SQLite database            │  audit and analysis
│    - CSV export                 │
└─────────────────────────────────┘
```

## Configuration

```bash
# Apply a security preset
tweek config preset paranoid    # Maximum security
tweek config preset cautious    # Balanced (default)
tweek config preset trusted     # Minimal prompts

# Configure specific tools
tweek config set --tool Bash --tier dangerous
tweek config set --tool WebFetch --tier risky

# View current configuration
tweek config list
```

## Credential Vault

Store secrets in your system keychain instead of .env files:

```bash
# Migrate from .env
tweek vault migrate-env --skill myapp --env-file .env

# Store manually
tweek vault store myapp API_KEY "sk-..."

# Retrieve (logged)
tweek vault get myapp API_KEY
```

## Commands

| Command | Description |
|---------|-------------|
| `tweek install` | Install hooks (global by default) |
| `tweek install --scope project` | Install for current project only |
| `tweek uninstall` | Remove hooks |
| `tweek update` | Update attack patterns from GitHub |
| `tweek status` | Show protection status |
| `tweek config list` | List security settings |
| `tweek config preset <name>` | Apply paranoid/cautious/trusted |
| `tweek vault store` | Store credential |
| `tweek vault get` | Retrieve credential |
| `tweek logs show` | View recent events |
| `tweek logs stats` | Security statistics |
| `tweek license status` | Check license tier |
| `tweek license activate KEY` | Activate Pro license |

## Pattern Updates

Attack patterns are updated independently of the application:

```bash
# Update patterns (pulls from GitHub)
tweek update

# Check for updates without installing
tweek update --check
```

Patterns are stored in `~/.tweek/patterns/` and can be updated via git pull without upgrading Tweek itself. This allows rapid response to new attack vectors.

## Licensing

Tweek offers two tiers:

| Tier | Price | Patterns | Features |
|------|-------|----------|----------|
| **FREE** | $0 | 23 core patterns | Pattern matching, logging, vault, CLI |
| **PRO** | $49 (one-time) | 116 patterns | + LLM review, session analysis, rate limiting, log export |

### FREE Tier

Essential protection for credential theft and common attacks:
- 23 core patterns covering SSH keys, AWS credentials, .env files
- Basic security logging (SQLite)
- Credential vault (system keychain)
- Global and per-project installation

### PRO Tier

Complete defense-in-depth protection:
- 116 patterns including evasive techniques, MCP CVEs, advanced injection
- LLM semantic review (Claude Haiku) for novel attacks
- Cross-turn session analysis for multi-step attacks
- Rate limiting for resource theft protection
- Advanced logging with CSV export

```bash
# Activate Pro license
tweek license activate YOUR_LICENSE_KEY

# Check status
tweek license status
```

Purchase at [gettweek.com/pricing](https://gettweek.com/pricing)

## Requirements

- Python 3.11+
- Claude Code
- macOS, Linux, or Windows

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.

## Links

- Website: https://gettweek.com
- Issues: https://github.com/gettweek/tweek/issues
