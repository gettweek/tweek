# Tweek CLI Reference

Complete command reference for the Tweek command-line interface. Tweek provides defense-in-depth security for AI coding assistants.

**Installation:** `pip install tweek`

**Version:** `tweek --version`

---

## Top-Level Commands

### `tweek install`

Install Tweek hooks into Claude Code.

| Option | Default | Description |
|--------|---------|-------------|
| `--scope {global,project}` | `global` | Installation scope: `global` (~/.claude) or `project` (./.claude) |
| `--backup / --no-backup` | `--backup` | Backup existing hooks before installation |
| `--skip-env-scan` | off | Skip scanning for .env files to migrate |
| `--interactive, -i` | off | Walk through interactive configuration prompts |
| `--preset {paranoid,cautious,trusted}` | none | Apply a security preset (skips interactive) |
| `--ai-defaults` | off | Auto-suggest security settings based on detected skills |
| `--with-sandbox` | off | Prompt to install sandbox tool if not available (Linux: firejail) |
| `--force-proxy` | off | Force Tweek proxy to override existing proxy configurations |
| `--skip-proxy-check` | off | Skip checking for existing proxy configurations |

```bash
tweek install                          # Install globally with default settings
tweek install --scope project          # Install for current project only
tweek install --interactive            # Walk through configuration prompts
tweek install --preset paranoid        # Apply paranoid security preset
tweek install --with-sandbox           # Install sandbox tool if needed (Linux)
tweek install --force-proxy            # Override existing proxy configurations
```

During installation, Tweek will:
1. Detect existing proxy configurations (e.g., moltbot) and offer override options
2. Install PreToolUse hooks into Claude Code settings
3. Scan for .env files and offer to migrate credentials to secure vault storage
4. Apply security configuration (preset, interactive, ai-defaults, or default cautious)
5. On Linux, optionally install firejail for command sandboxing

---

### `tweek uninstall`

Remove Tweek hooks from Claude Code.

| Option | Default | Description |
|--------|---------|-------------|
| `--scope {global,project}` | `global` | Uninstall scope |
| `--confirm` | off | Skip confirmation prompt |

```bash
tweek uninstall                        # Remove from global installation
tweek uninstall --scope project        # Remove from current project only
tweek uninstall --confirm              # Skip confirmation prompt
```

The Tweek data directory (`~/.tweek`) is preserved. Remove manually if desired.

---

### `tweek update`

Update attack patterns from GitHub. Patterns are stored in `~/.tweek/patterns/` and cloned from `https://github.com/gettweek/tweek-patterns.git`.

| Option | Default | Description |
|--------|---------|-------------|
| `--check` | off | Check for updates without installing |

```bash
tweek update                           # Download/update attack patterns
tweek update --check                   # Check for updates without installing
```

---

### `tweek doctor`

Run health checks on your Tweek installation. Checks hooks, configuration, patterns, database, vault, sandbox, license, MCP, proxy, and plugin integrity.

| Option | Default | Description |
|--------|---------|-------------|
| `--verbose, -v` | off | Show detailed check information |
| `--json` | off | Output results as JSON for scripting |

```bash
tweek doctor                           # Run all health checks
tweek doctor --verbose                 # Show detailed check information
tweek doctor --json                    # Output results as JSON for scripting
```

---

### `tweek quickstart`

Interactive first-run setup wizard that walks through:

1. Installing hooks (global, project, or both)
2. Choosing a security preset (paranoid, cautious, trusted)
3. Verifying credential vault availability
4. Optional MCP proxy setup

```bash
tweek quickstart                       # Launch interactive setup wizard
```

---

### `tweek status`

Show current Tweek protection status.

---

## Config Commands (`tweek config`)

Manage Tweek security policies. Configuration follows a layered model:
- **default** (built-in) < **user** (`~/.tweek/config.yaml`) < **project** (`.tweek/config.yaml`)

### `tweek config list`

List all tools and skills with their security tiers.

| Option | Default | Description |
|--------|---------|-------------|
| `--tools` | off | Show only tool security tiers |
| `--skills` | off | Show only skill security tiers |
| `--summary` | off | Show tier counts and overrides summary |

```bash
tweek config list                      # List all tools and skills
tweek config list --tools              # Show only tool security tiers
tweek config list --skills             # Show only skill security tiers
tweek config list --summary            # Show tier counts and overrides summary
```

Security tiers: `safe` (no checks) > `default` (regex) > `risky` (+LLM) > `dangerous` (+sandbox)

---

### `tweek config set`

Set security tier for a skill, tool, or the default.

| Option | Default | Description |
|--------|---------|-------------|
| `--skill` | none | Skill name to configure |
| `--tool` | none | Tool name to configure |
| `--tier {safe,default,risky,dangerous}` | required | Security tier to set |
| `--scope {user,project}` | `user` | Config scope |

```bash
tweek config set --tool Bash --tier dangerous
tweek config set --skill web-fetch --tier risky
tweek config set --tier cautious                    # Set default tier for all
tweek config set --tool Edit --tier safe --scope project
```

---

### `tweek config preset`

Apply a configuration preset.

| Argument | Description |
|----------|-------------|
| `{paranoid,cautious,trusted}` | Preset name (required) |

| Option | Default | Description |
|--------|---------|-------------|
| `--scope {user,project}` | `user` | Config scope |

| Preset | Behavior |
|--------|----------|
| `paranoid` | Maximum security, prompt for everything |
| `cautious` | Balanced security (recommended) |
| `trusted` | Minimal prompts, trust AI decisions |

```bash
tweek config preset paranoid
tweek config preset cautious --scope project
```

---

### `tweek config reset`

Reset configuration to defaults.

| Option | Default | Description |
|--------|---------|-------------|
| `--skill` | none | Reset specific skill to default |
| `--tool` | none | Reset specific tool to default |
| `--all` | off | Reset all user configuration |
| `--scope {user,project}` | `user` | Config scope |
| `--confirm` | off | Skip confirmation prompt |

```bash
tweek config reset --tool Bash
tweek config reset --all --confirm
```

---

### `tweek config validate`

Validate configuration for errors, typos, unknown keys, and invalid tier values.

| Option | Default | Description |
|--------|---------|-------------|
| `--scope {user,project,merged}` | `merged` | Which config scope to validate |
| `--json` | off | Output as JSON |

```bash
tweek config validate
tweek config validate --scope project --json
```

---

### `tweek config diff`

Show what would change if a preset were applied.

| Argument | Description |
|----------|-------------|
| `{paranoid,cautious,trusted}` | Preset to compare against (required) |

```bash
tweek config diff paranoid             # Show changes if paranoid preset applied
tweek config diff trusted              # Show changes if trusted preset applied
```

---

## Vault Commands (`tweek vault`)

Manage credentials in secure storage. Backend depends on platform:
- **macOS:** Keychain
- **Linux:** Secret Service (GNOME Keyring, KWallet)

See [VAULT.md](VAULT.md) for architecture details.

### `tweek vault store`

```bash
tweek vault store <SKILL> <KEY> <VALUE>
```

```bash
tweek vault store myskill API_KEY sk-abc123
tweek vault store deploy AWS_SECRET s3cr3t
```

### `tweek vault get`

```bash
tweek vault get <SKILL> <KEY>
```

```bash
tweek vault get myskill API_KEY
```

### `tweek vault delete`

```bash
tweek vault delete <SKILL> <KEY>
```

```bash
tweek vault delete myskill API_KEY
```

### `tweek vault migrate-env`

Migrate credentials from a `.env` file to secure storage.

| Option | Default | Description |
|--------|---------|-------------|
| `--skill` | required | Skill name to store credentials under |
| `--dry-run` | off | Preview without making changes |
| `--env-file` | `.env` | Path to .env file |

```bash
tweek vault migrate-env --skill myapp
tweek vault migrate-env --skill myapp --dry-run
tweek vault migrate-env --skill deploy --env-file .env.production
```

---

## License Commands (`tweek license`)

### `tweek license status`

Show current license status and feature availability. All features are free.

### `tweek license activate`

```bash
tweek license activate YOUR_LICENSE_KEY    # For future Pro/Enterprise tiers
```

### `tweek license deactivate`

| Option | Default | Description |
|--------|---------|-------------|
| `--confirm` | off | Skip confirmation prompt |

```bash
tweek license deactivate
tweek license deactivate --confirm
```

---

## Logs Commands (`tweek logs`)

View and manage security event logs.

### `tweek logs show`

| Option | Default | Description |
|--------|---------|-------------|
| `--limit, -n` | `20` | Number of events to show |
| `--type, -t` | none | Filter by event type |
| `--tool` | none | Filter by tool name |
| `--blocked` | off | Show only blocked/flagged events |
| `--stats` | off | Show security statistics summary |
| `--days, -d` | `7` | Number of days to analyze (with --stats) |

```bash
tweek logs show
tweek logs show -n 50
tweek logs show --type block
tweek logs show --blocked
tweek logs show --stats --days 30
```

### `tweek logs export`

Export security logs to CSV.

| Option | Default | Description |
|--------|---------|-------------|
| `--days, -d` | all | Limit to last N days |
| `--output, -o` | `tweek_security_log.csv` | Output file path |

```bash
tweek logs export
tweek logs export --days 7 -o audit.csv
```

### `tweek logs clear`

| Option | Default | Description |
|--------|---------|-------------|
| `--days, -d` | all | Clear events older than N days |
| `--confirm` | off | Skip confirmation prompt |

```bash
tweek logs clear --days 30
tweek logs clear --confirm
```

### `tweek logs bundle`

Create a diagnostic bundle (zip) for Tweek support. Sensitive data is automatically redacted.

| Option | Default | Description |
|--------|---------|-------------|
| `--output, -o` | auto-timestamped | Output zip file path |
| `--days, -d` | all | Only include events from last N days |
| `--no-redact` | off | Skip redaction (internal debugging) |
| `--dry-run` | off | Show what would be collected |

```bash
tweek logs bundle
tweek logs bundle --dry-run
tweek logs bundle -o /tmp/diag.zip --days 7
```

---

## Proxy Commands (`tweek proxy`)

LLM API security proxy using mitmproxy for HTTPS interception. Requires `pip install tweek[proxy]`.

See [HTTP_PROXY.md](HTTP_PROXY.md) for architecture details.

### `tweek proxy start`

| Option | Default | Description |
|--------|---------|-------------|
| `--port, -p` | `9877` | Port for proxy to listen on |
| `--web-port` | disabled | Port for mitmproxy web interface |
| `--foreground, -f` | off | Run in foreground for debugging |
| `--log-only` | off | Log traffic without blocking |

```bash
tweek proxy start
tweek proxy start --port 8080
tweek proxy start --foreground
tweek proxy start --log-only
```

### `tweek proxy stop`

```bash
tweek proxy stop
```

### `tweek proxy trust`

Install the proxy CA certificate in the system trust store. Required for HTTPS interception.

```bash
tweek proxy trust
```

### `tweek proxy config`

| Option | Default | Description |
|--------|---------|-------------|
| `--enabled` | off | Enable proxy in configuration |
| `--disabled` | off | Disable proxy in configuration |
| `--port, -p` | `9877` | Proxy port |

```bash
tweek proxy config --enabled
tweek proxy config --disabled
tweek proxy config --enabled --port 8080
```

### `tweek proxy wrap`

Generate a wrapper script to route an application through the proxy.

| Argument | Description |
|----------|-------------|
| `APP_NAME` | Name for the wrapper |
| `COMMAND` | The command to wrap |

| Option | Default | Description |
|--------|---------|-------------|
| `--output, -o` | `./run-{app_name}-protected.sh` | Output script path |
| `--port, -p` | `9877` | Proxy port |

```bash
tweek proxy wrap moltbot "npm start"
tweek proxy wrap cursor "/Applications/Cursor.app/Contents/MacOS/Cursor"
tweek proxy wrap myapp "python serve.py" -o run.sh
```

### `tweek proxy setup`

Interactive proxy setup wizard: detect LLM tools, generate/trust CA certificate, configure shell environment variables.

```bash
tweek proxy setup
```

---

## Plugins Commands (`tweek plugins`)

Manage Tweek plugins across four categories: compliance, providers, detectors, screening.

See [PLUGINS.md](PLUGINS.md) for architecture details.

### `tweek plugins list`

| Option | Default | Description |
|--------|---------|-------------|
| `--category, -c` | all | Filter: `compliance`, `providers`, `detectors`, `screening` |
| `--all` | off | Include disabled plugins |

```bash
tweek plugins list
tweek plugins list -c compliance
tweek plugins list --all
```

### `tweek plugins info`

| Argument | Description |
|----------|-------------|
| `PLUGIN_NAME` | Name of the plugin |

| Option | Default | Description |
|--------|---------|-------------|
| `--category, -c` | auto-detected | Plugin category |

```bash
tweek plugins info hipaa
tweek plugins info pii -c compliance
```

### `tweek plugins set`

Configure a plugin: enable/disable, set key-value pairs, or configure scoping.

| Argument | Description |
|----------|-------------|
| `PLUGIN_NAME` | Name of the plugin (required) |
| `KEY` | Configuration key (optional) |
| `VALUE` | Configuration value (optional) |

| Option | Default | Description |
|--------|---------|-------------|
| `--category, -c` | required | Plugin category |
| `--scope {user,project}` | `user` | Config scope |
| `--enabled` | off | Enable the plugin |
| `--disabled` | off | Disable the plugin |
| `--scope-tools` | none | Comma-separated tool names for scoping |
| `--scope-skills` | none | Comma-separated skill names for scoping |
| `--scope-tiers` | none | Comma-separated tiers for scoping |
| `--scope-clear` | off | Clear all scoping (make global) |

```bash
tweek plugins set hipaa --enabled -c compliance
tweek plugins set hipaa --disabled -c compliance
tweek plugins set hipaa threshold 0.8 -c compliance
tweek plugins set hipaa --scope-tools Bash,Edit -c compliance
tweek plugins set hipaa --scope-clear -c compliance
```

### `tweek plugins reset`

Reset a plugin to default configuration.

```bash
tweek plugins reset hipaa -c compliance
```

### `tweek plugins scan`

Run compliance scan on content.

| Argument | Description |
|----------|-------------|
| `CONTENT` | Text to scan (prefix with `@` for file path) |

| Option | Default | Description |
|--------|---------|-------------|
| `--direction, -d {input,output}` | `output` | Scan direction |
| `--plugin, -p` | all enabled | Specific compliance plugin |

```bash
tweek plugins scan "This is TOP SECRET//NOFORN"
tweek plugins scan "Patient MRN: 123456" --plugin hipaa
tweek plugins scan @file.txt
tweek plugins scan "SSN: 123-45-6789" -d input
```

### `tweek plugins install`

Install a plugin from the Tweek registry.

| Option | Default | Description |
|--------|---------|-------------|
| `--version, -v` | latest | Specific version |
| `--from-lockfile` | off | Install all from lockfile |
| `--no-verify` | off | Skip security verification |

```bash
tweek plugins install hipaa-scanner
tweek plugins install hipaa-scanner -v 1.2.0
tweek plugins install _ --from-lockfile
```

### `tweek plugins update`

| Option | Default | Description |
|--------|---------|-------------|
| `--all` | off | Update all installed plugins |
| `--check` | off | Check for updates without installing |
| `--version, -v` | latest | Specific version |
| `--no-verify` | off | Skip security verification |

```bash
tweek plugins update hipaa-scanner
tweek plugins update --all
tweek plugins update --check
```

### `tweek plugins remove`

| Option | Default | Description |
|--------|---------|-------------|
| `--force, -f` | off | Skip confirmation |

```bash
tweek plugins remove hipaa-scanner
tweek plugins remove hipaa-scanner -f
```

### `tweek plugins search`

Search the Tweek plugin registry.

| Option | Default | Description |
|--------|---------|-------------|
| `--category, -c` | all | Filter by category |
| `--tier, -t {free,pro,enterprise}` | all | Filter by license tier |
| `--include-deprecated` | off | Include deprecated plugins |

```bash
tweek plugins search hipaa
tweek plugins search -c compliance
tweek plugins search -t free
```

### `tweek plugins lock`

Generate or update a plugin version lockfile.

| Option | Default | Description |
|--------|---------|-------------|
| `--plugin, -p` | all | Lock a specific plugin |
| `--version, -v` | latest | Lock to specific version |
| `--project` | off | Create project-level lockfile |

```bash
tweek plugins lock
tweek plugins lock -p hipaa -v 1.2.0
```

### `tweek plugins verify`

Verify integrity of installed git plugins.

| Option | Default | Description |
|--------|---------|-------------|
| `--all` | off | Verify all installed plugins |

```bash
tweek plugins verify hipaa-scanner
tweek plugins verify --all
```

### `tweek plugins registry`

Manage the plugin registry cache.

| Option | Default | Description |
|--------|---------|-------------|
| `--refresh` | off | Force refresh the registry cache |
| `--info` | off | Show detailed registry metadata |

```bash
tweek plugins registry
tweek plugins registry --refresh
tweek plugins registry --info
```

---

## Memory Commands (`tweek memory`)

Manage Tweek's agentic memory -- persistent, cross-session learning from past security decisions.

See [MEMORY.md](MEMORY.md) for architecture details.

### `tweek memory status`

Show overall memory statistics: table sizes, last decay run, database file size.

```bash
tweek memory status
```

### `tweek memory patterns`

Show per-pattern confidence adjustments from historical decisions.

| Option | Default | Description |
|--------|---------|-------------|
| `--min-decisions` | `0` | Only show patterns with N+ decisions |
| `--sort {count,approval,name}` | `count` | Sort order |

```bash
tweek memory patterns
tweek memory patterns --min-decisions 5
tweek memory patterns --sort approval
```

### `tweek memory sources`

Show source trustworthiness scores for URLs, files, and domains.

| Option | Default | Description |
|--------|---------|-------------|
| `--suspicious` | off | Only show sources with trust < 0.5 |

```bash
tweek memory sources
tweek memory sources --suspicious
```

### `tweek memory suggestions`

Show pending whitelist suggestions generated from approval patterns.

```bash
tweek memory suggestions
```

Suggestions appear when a pattern has 10+ decisions with 90%+ approval. Use `accept` or `reject` to review.

### `tweek memory accept`

Accept a whitelist suggestion. Writes the pattern to the overrides whitelist.

| Argument | Description |
|----------|-------------|
| `ID` | Suggestion ID (from `tweek memory suggestions`) |

```bash
tweek memory accept 1
tweek memory accept 3
```

### `tweek memory reject`

Reject a whitelist suggestion. Marks it as reviewed without action.

| Argument | Description |
|----------|-------------|
| `ID` | Suggestion ID (from `tweek memory suggestions`) |

```bash
tweek memory reject 2
```

### `tweek memory baseline`

Show workflow baseline for the current project. Displays per-tool invocation counts and denial rates.

```bash
tweek memory baseline
```

### `tweek memory audit`

Show the memory operation audit log.

| Option | Default | Description |
|--------|---------|-------------|
| `--limit, -n` | `50` | Number of entries to show |

```bash
tweek memory audit
tweek memory audit -n 100
```

### `tweek memory clear`

Clear memory data.

| Option | Default | Description |
|--------|---------|-------------|
| `--table {patterns,sources,baselines,whitelists,all}` | `all` | Which table(s) to clear |
| `--confirm` | off | Skip confirmation prompt |

```bash
tweek memory clear --table patterns --confirm
tweek memory clear --table sources
tweek memory clear --confirm                     # Clear all tables
```

### `tweek memory export`

Export all memory data to JSON.

| Option | Default | Description |
|--------|---------|-------------|
| `--output, -o` | stdout | Output file path |

```bash
tweek memory export
tweek memory export -o memory_backup.json
```

### `tweek memory decay`

Manually trigger time decay across all tables. Uses a 30-day half-life.

```bash
tweek memory decay
```

---

## MCP Commands (`tweek mcp`)

MCP Security Gateway for desktop LLM applications. Requires `pip install tweek[mcp]`.

See [MCP_INTEGRATION.md](MCP_INTEGRATION.md) for architecture details.

### `tweek mcp serve`

Start MCP gateway server on stdio transport. Exposes `tweek_vault` and `tweek_status` tools.

```bash
tweek mcp serve
```

### `tweek mcp install`

Install Tweek as MCP server for a desktop client.

| Argument | Description |
|----------|-------------|
| `{claude-desktop,chatgpt,gemini}` | Target client |

```bash
tweek mcp install claude-desktop
tweek mcp install chatgpt
tweek mcp install gemini
```

### `tweek mcp uninstall`

Remove Tweek MCP server from a desktop client.

```bash
tweek mcp uninstall claude-desktop
```

### `tweek mcp proxy`

Start MCP proxy server on stdio transport. Connects to upstream MCP servers and screens all tool calls.

```bash
tweek mcp proxy
```

### `tweek mcp approve`

Start the approval daemon for MCP proxy requests.

| Option | Default | Description |
|--------|---------|-------------|
| `--poll-interval, -p` | `2.0` | Seconds between polls |
| `--list` | off | List pending requests and exit |

```bash
tweek mcp approve
tweek mcp approve --list
tweek mcp approve -p 5
```

### `tweek mcp decide`

Approve or deny a specific approval request.

| Argument | Description |
|----------|-------------|
| `REQUEST_ID` | Full UUID or first 8 characters |
| `{approve,deny}` | Decision |

| Option | Default | Description |
|--------|---------|-------------|
| `--notes, -n` | none | Decision notes |

```bash
tweek mcp decide abc12345 approve
tweek mcp decide abc12345 deny -n "Not authorized"
```

---

## Cross-References

- [MEMORY.md](MEMORY.md) -- Agentic memory system (cross-session learning)
- [MCP_INTEGRATION.md](MCP_INTEGRATION.md) -- MCP gateway and proxy architecture
- [HTTP_PROXY.md](HTTP_PROXY.md) -- HTTP proxy and HTTPS interception
- [VAULT.md](VAULT.md) -- Credential storage architecture
- [PLUGINS.md](PLUGINS.md) -- Plugin system and compliance modules
