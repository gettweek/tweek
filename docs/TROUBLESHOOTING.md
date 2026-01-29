# Tweek Troubleshooting Guide

Diagnostics, health checks, and common issues.

---

## Overview

Tweek includes a built-in diagnostics engine (`tweek/diagnostics.py`) that
verifies installation, configuration, and runtime dependencies. Run it with:

```bash
tweek doctor
tweek doctor --verbose
tweek doctor --json
```

The `tweek doctor` command runs 10 health checks and reports an overall
status verdict.

---

## Health Checks Explained

### 1. hooks_installed

**Label:** Hook Installation
**What it checks:** Whether Tweek hooks are registered in Claude Code's
`settings.json` at the global (`~/.claude/settings.json`) and/or project
(`./.claude/settings.json`) level. It looks for `PreToolUse` and `PostToolUse`
hook entries whose `command` field contains "tweek".

| Status  | Meaning                                                        |
|---------|----------------------------------------------------------------|
| OK      | Hooks installed globally (and optionally per-project)          |
| WARNING | Hooks installed in project only, not globally                  |
| ERROR   | No hooks installed at either scope                             |

**Fix:**
```bash
tweek install                 # Install globally and in current project
tweek install --scope global  # Install globally only
```

---

### 2. config_valid

**Label:** Configuration
**What it checks:** Loads the configuration via `ConfigManager` and parses
tool and skill definitions. If `validate_config()` is available, it also
checks for structural errors and warnings.

| Status  | Meaning                                                        |
|---------|----------------------------------------------------------------|
| OK      | Config parsed successfully (reports tool/skill counts)         |
| WARNING | Config valid but has warnings                                  |
| ERROR   | Config failed to load or has validation errors                 |

**Fix:**
```bash
tweek config validate         # Show detailed validation output
```

---

### 3. patterns_loaded

**Label:** Attack Patterns
**What it checks:** Looks for `patterns.yaml` at `~/.tweek/patterns/patterns.yaml`
(user-updated) or the bundled location (`tweek/config/patterns.yaml`). Parses the
file and reports the pattern count.

| Status  | Meaning                                                        |
|---------|----------------------------------------------------------------|
| OK      | Patterns loaded (reports count and source)                     |
| WARNING | Patterns file found but contains 0 patterns                   |
| ERROR   | No patterns file found or parse failure                        |

**Fix:**
```bash
tweek update                  # Download latest patterns
tweek update --force          # Force re-download
```

---

### 4. security_db

**Label:** Security Database
**What it checks:** Verifies `~/.tweek/security.db` exists, is a valid SQLite
database, and can be opened. Reports file size and warns if the database is
unusually large (>100 MB).

| Status  | Meaning                                                        |
|---------|----------------------------------------------------------------|
| OK      | Database accessible (reports size)                             |
| OK      | Not yet created (will be created on first event)               |
| WARNING | Database is over 100 MB -- consider cleanup                    |
| ERROR   | Cannot open database (permissions or corruption)               |

**Fix:**
```bash
tweek logs clear --older-than 30d   # Clean up old events
# For corruption:
rm ~/.tweek/security.db             # Delete and let Tweek recreate
```

Check file permissions:
```bash
ls -la ~/.tweek/security.db
```

---

### 5. vault_available

**Label:** Credential Vault
**What it checks:** Queries `tweek.platform.get_capabilities()` for vault
backend availability.

| Status  | Meaning                                                        |
|---------|----------------------------------------------------------------|
| OK      | Vault backend available (reports backend name)                 |
| WARNING | No vault backend detected                                      |

**Platform-specific vault backends:**

| Platform | Backend            | Requirement                           |
|----------|--------------------|---------------------------------------|
| macOS    | macOS Keychain     | Built-in (no extra install)           |
| Linux    | System keyring     | `keyring` package or Secret Service   |
| Windows  | Windows Credential Store | Built-in (limited support)      |

**Fix:** Install system keyring support for your platform if the vault is not
detected.

---

### 6. sandbox_available

**Label:** Sandbox
**What it checks:** Calls `get_sandbox_status()` to determine if a sandbox
backend is available.

| Status  | Meaning                                                        |
|---------|----------------------------------------------------------------|
| OK      | Sandbox tool available (reports tool name)                     |
| WARNING | Linux: firejail not installed                                  |
| SKIPPED | Not available on this platform or module not available          |

**Fix (Linux):**
```bash
sudo apt install firejail     # Debian/Ubuntu
sudo dnf install firejail     # Fedora
sudo pacman -S firejail       # Arch
```

On macOS, `sandbox-exec` is built-in and always available.

---

### 7. license_status

**Label:** License
**What it checks:** Loads the license via `get_license()` and reports the
current tier, email, and expiration status.

| Status  | Meaning                                                        |
|---------|----------------------------------------------------------------|
| OK      | License active (reports tier and email, or "Free tier active") |
| WARNING | License expired or cannot check license                        |

**Fix:**
```bash
tweek license activate <key>  # Activate a new license
tweek license status          # Check current status
```

Renew at: https://gettweek.com/pricing

---

### 8. mcp_available

**Label:** MCP Server
**What it checks:** Attempts to import the `mcp` Python package.

| Status  | Meaning                                                        |
|---------|----------------------------------------------------------------|
| OK      | MCP package installed                                          |
| SKIPPED | MCP package not installed (optional dependency)                |

**Fix:**
```bash
pip install tweek[mcp]
```

MCP support is optional. Without it, Tweek still provides full hook-based
protection.

---

### 9. proxy_config

**Label:** Proxy Config
**What it checks:** Reads the full configuration for `proxy` and `mcp.proxy`
sections. Validates that MCP proxy upstreams have required fields.

| Status  | Meaning                                                        |
|---------|----------------------------------------------------------------|
| OK      | Proxy configured (reports HTTP proxy and/or MCP upstream count)|
| WARNING | Configuration issues detected                                   |
| SKIPPED | No proxy or MCP proxy configured                               |

**Fix:**
```bash
# Check config for proxy settings
tweek config validate
# Edit config
$EDITOR ~/.tweek/config.yaml
```

---

### 10. plugin_integrity

**Label:** Plugin Integrity
**What it checks:** Queries the plugin registry for installed plugins and
checks for load errors.

| Status  | Meaning                                                        |
|---------|----------------------------------------------------------------|
| OK      | All plugins verified (reports enabled/total counts)            |
| OK      | No plugins installed                                           |
| WARNING | Some plugins have load errors (reports names)                  |

**Fix:**
```bash
tweek plugins verify          # Detailed plugin verification
tweek plugins list --all      # List all plugins with status
```

---

## Overall Verdict

After running all 10 checks, `tweek doctor` computes an overall verdict:

| Condition                        | Verdict                                  | Color  |
|----------------------------------|------------------------------------------|--------|
| 0 errors, 0 warnings            | "All systems operational (N/N OK)"       | Green  |
| 0 errors, some warnings         | "Mostly healthy (N OK, M warnings)"      | Yellow |
| 1-2 errors                      | "Issues detected (N OK, M errors, ...)"  | Red    |
| 3+ errors                       | "Multiple issues (M errors, N warnings)" | Red    |

---

## JSON Output

For CI/CD or scripting, use `--json`:

```bash
tweek doctor --json
```

This outputs structured JSON with all check results.

---

## Debug Logging

For detailed troubleshooting, enable verbose output:

```bash
tweek doctor --verbose
```

This adds extra context to check messages (e.g., showing which scopes are
missing for hook installation).

For Python-level debug logging:

```bash
TWEEK_DEBUG=1 tweek doctor
```

---

## Common Issues and Solutions

### Hooks Not Working

**Symptom:** Tweek is installed but AI assistant commands run without screening.

**Cause:** Hooks not registered in Claude Code settings.

**Solution:**
```bash
tweek install --scope global
tweek doctor     # Verify hooks_installed is OK
```

### "No patterns file found"

**Symptom:** `patterns_loaded` check fails.

**Solution:**
```bash
tweek update
tweek update --force    # If patterns exist but are corrupt
```

### Large Security Database

**Symptom:** `security_db` shows warning about large database size.

**Solution:**
```bash
# Export for archival first
tweek logs export --days 90 -o archive.csv

# Then clean up
tweek logs clear --days 30
```

### Permission Denied on security.db

**Symptom:** `security_db` check shows "Cannot open database."

**Solution:**
```bash
# Check permissions
ls -la ~/.tweek/security.db

# Fix permissions
chmod 644 ~/.tweek/security.db

# If corrupted, delete and let Tweek recreate
rm ~/.tweek/security.db
```

### Sandbox Not Available on Linux

**Symptom:** `sandbox_available` shows warning.

**Solution:**
Install firejail for your distribution:
```bash
# Debian/Ubuntu
sudo apt install firejail

# Fedora
sudo dnf install firejail

# Arch
sudo pacman -S firejail
```

Without firejail, Tweek still provides 4 out of 5 defense layers (rate limiting,
pattern matching, LLM review, and session analysis).

### MCP Features Not Working

**Symptom:** `mcp_available` is SKIPPED.

**Solution:**
```bash
pip install tweek[mcp]
```

### License Expired

**Symptom:** `license_status` shows warning about expired license.

**Solution:**
```bash
tweek license status          # Check expiration date
tweek license activate <key>  # Activate renewal key
```

Features will fall back to the FREE tier while the license is expired.

---

## Creating and Submitting Diagnostic Bundles

When contacting support, create a diagnostic bundle:

```bash
tweek logs bundle
```

This creates a zip file (e.g., `tweek_diagnostic_20250615_143022.zip`) containing:

| File                    | Contents                                 |
|-------------------------|------------------------------------------|
| `security.db`           | Security events database                 |
| `approvals.db`          | MCP approval queue database              |
| `proxy.log`             | HTTP proxy log                           |
| `security_events.jsonl` | JSON event log                           |
| `config_user.yaml`      | User config (redacted)                   |
| `config_project.yaml`   | Project config (redacted)                |
| `doctor_output.txt`     | Health check results                     |
| `system_info.json`      | Platform and version info                |
| `manifest.json`         | Bundle metadata                          |

**All sensitive data is automatically redacted** (API keys, passwords, tokens,
credentials) before inclusion. The bundle is safe to share with support.

### Bundle Options

```bash
# Preview what will be collected
tweek logs bundle --dry-run

# Only include last 7 days of events
tweek logs bundle --days 7

# Specify output location
tweek logs bundle -o /tmp/diag.zip
```

### Submitting

Send the zip file to Tweek support or attach it to your GitHub issue.

---

## Platform-Specific Notes

### macOS

- Sandbox (`sandbox-exec`) is always available
- Vault uses macOS Keychain (built-in)
- TCC permissions may affect file access -- ensure Terminal has Full Disk Access
  if needed

### Linux

- Sandbox requires `firejail` or `bubblewrap` (optional)
- Vault requires system keyring support
- SELinux or AppArmor may interfere with firejail -- check system logs

### Windows

- Sandbox is not available
- Vault uses Windows Credential Store (limited support)
- Some patterns may behave differently with Windows paths

---

## Cross-References

- [LOGGING.md](./LOGGING.md) -- Full logging system documentation
- [SANDBOX.md](./SANDBOX.md) -- Sandbox configuration and troubleshooting
- [ATTACK_PATTERNS.md](./ATTACK_PATTERNS.md) -- Pattern library details
- [LICENSING.md](./LICENSING.md) -- License tier information
