# Tweek CLI Reference

Complete command reference for the `tweek` command-line tool.

---

## Installation & Setup

### `tweek install`

Install Tweek hooks into the AI assistant's configuration.

```
tweek install [OPTIONS]
```

| Option | Description |
|--------|-------------|
| *(no flags)* | Install to `./.claude/` — protects current project only (default) |
| `--global` | Install to `~/.claude/` — protects all projects |
| `--interactive` | Walk through configuration prompts (includes scope selection) |
| `--preset [paranoid\|cautious\|trusted]` | Apply a security preset |
| `--ai-defaults` | Auto-configure based on detected skills |
| `--with-sandbox` | Install sandbox tool if needed (Linux: firejail) |
| `--skip-env-scan` | Skip scanning for credential files to migrate |
| `--backup / --no-backup` | Backup existing hooks before installation (default: backup) |

### `tweek uninstall`

Remove Tweek hooks from configuration.

```
tweek uninstall [--global] [--confirm]
```

By default removes from `./.claude/` (current project). Use `--global` to remove from `~/.claude/`.

---

## Project Trust

### `tweek trust`

Exempt a project directory from all screening. This is useful for temporarily pausing Tweek or permanently trusting a known-safe directory.

```
tweek trust [PATH] [OPTIONS]
```

| Option | Description |
|--------|-------------|
| *(no args)* | Trust the current directory |
| `PATH` | Trust a specific directory |
| `--list` | Show all trusted paths |
| `--reason, -r` | Explain why this path is trusted |

Examples:
```
tweek trust                           # Trust current project
tweek trust /path/to/project          # Trust specific directory
tweek trust --list                    # Show all trusted paths
tweek trust . --reason "Safe repo"    # Trust with explanation
```

**Note:** This command is blocked when run by an AI assistant. Trust decisions must be made by a human directly in their terminal.

### `tweek untrust`

Remove trust from a project directory and resume screening.

```
tweek untrust [PATH]
```

Examples:
```
tweek untrust                         # Untrust current project
tweek untrust /path/to/project        # Untrust specific directory
```

---

## Diagnostics

### `tweek status`

Show installation status and active configuration.

```
tweek status
```

### `tweek doctor`

Run health checks on all screening layers.

```
tweek doctor [--verbose] [--json]
```

Checks performed:
- Hook installation
- Configuration validity
- Pattern database loaded
- Security database accessible
- Vault availability
- Sandbox availability
- License status
- Proxy configuration

---

## Logs & Events

### `tweek logs show`

View recent security events.

```
tweek logs show [--limit N] [--type TYPE]
```

Event types: `PATTERN_MATCH`, `BLOCKED`, `ALLOWED`, `USER_PROMPTED`, `RATE_LIMIT`, `SESSION_ANOMALY`, `COMPLIANCE`, and others.

### `tweek logs stats`

Show aggregate statistics.

```
tweek logs stats [--days N]
```

### `tweek logs export`

Export logs to a file.

```
tweek logs export [--days N] [--output FILE]
```

---

## Configuration

### `tweek config preset`

Apply a named security preset.

```
tweek config preset [paranoid|cautious|trusted]
```

| Preset | Behavior |
|--------|----------|
| `paranoid` | Maximum screening — all layers active, lowest thresholds |
| `cautious` | Balanced — recommended for most users (default) |
| `trusted` | Minimal prompts — only blocks critical threats |

### `tweek config list`

Show current security configuration.

```
tweek config list
```

### `tweek config interactive`

Walk through configuration prompts to customize settings.

```
tweek config interactive
```

---

## Pattern Updates

### `tweek update`

Fetch the latest detection patterns.

```
tweek update
```

---

## Audit

### `tweek audit`

Scan a file or directory for security patterns outside of the hook pipeline.

```
tweek audit [PATH] [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--translate / --no-translate` | Enable non-English content translation |
| `--llm-review / --no-llm-review` | Enable LLM semantic analysis |
| `--json` | Output results as JSON |

---

## Skill Management

### `tweek skills chamber`

Manage the skill quarantine area where incoming skills are held for scanning.

```
tweek skills chamber list          # List skills in chamber
tweek skills chamber import PATH   # Import a skill into chamber
tweek skills chamber scan NAME     # Run security scan on a chambered skill
tweek skills chamber approve NAME  # Approve and install a scanned skill
tweek skills chamber reject NAME   # Reject and remove a chambered skill
```

### `tweek skills jail`

Manage skills that failed security scanning.

```
tweek skills jail list             # List jailed skills
tweek skills jail rescan NAME      # Re-scan a jailed skill
tweek skills jail release NAME     # Release from jail (requires approval)
tweek skills jail purge            # Remove all jailed skills
```

### `tweek skills report`

View the security scan report for a skill.

```
tweek skills report NAME
```

### `tweek skills status`

Show status of all known skills (chambered, approved, jailed).

```
tweek skills status
```

---

## Vault (Credential Storage)

### `tweek vault store`

Store a credential in secure storage.

```
tweek vault store SKILL KEY VALUE
```

### `tweek vault get`

Retrieve a credential from secure storage.

```
tweek vault get SKILL KEY
```

### `tweek vault migrate-env`

Migrate credentials from environment files to secure vault storage.

```
tweek vault migrate-env [--dry-run]
```

---

## Plugin Management

### `tweek plugins install`

Install a plugin from the registry.

```
tweek plugins install NAME
```

### `tweek plugins update`

Update an installed plugin.

```
tweek plugins update NAME
```

### `tweek plugins remove`

Remove an installed plugin.

```
tweek plugins remove NAME
```

### `tweek plugins search`

Search the plugin registry.

```
tweek plugins search QUERY
```

---

## Proxy (API Interception)

### `tweek protect`

Set up protection for an AI gateway.

```
tweek protect [openclaw|claude]
```

### `tweek proxy start / stop`

Start or stop the API interception proxy.

```
tweek proxy start
tweek proxy stop
```
