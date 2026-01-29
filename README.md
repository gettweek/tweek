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
│ 1. PATTERN MATCHING             │  100+ regex patterns for
│    - Credential access          │  known attack signatures
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
| `tweek status` | Show protection status |
| `tweek config list` | List security settings |
| `tweek config preset <name>` | Apply paranoid/cautious/trusted |
| `tweek vault store` | Store credential |
| `tweek vault get` | Retrieve credential |
| `tweek logs show` | View recent events |
| `tweek logs stats` | Security statistics |

## Requirements

- Python 3.11+
- Claude Code
- macOS, Linux, or Windows

## License

MIT

## Links

- Website: https://gettweek.com
- Issues: https://github.com/gettweek/tweek/issues
