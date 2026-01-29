# Tweek Security Logging Documentation

SQLite-based audit logging with automatic redaction, JSON export, and diagnostic bundles.

---

## Overview

Every security-relevant action in Tweek is recorded as a `SecurityEvent` and
persisted to a local SQLite database at `~/.tweek/security.db`. An optional
NDJSON logger writes the same events to `~/.tweek/security_events.jsonl` for
ingestion into external log aggregation systems (ELK, Splunk, Datadog).

All data is automatically redacted for secrets before it is written to any store.

```
tweek/logging/
  __init__.py          # Public API: SecurityLogger, SecurityEvent, EventType
  security_log.py      # Core logger, redactor, SQLite schema
  json_logger.py       # NDJSON event writer with rotation
  bundle.py            # Diagnostic bundle collector
```

---

## SecurityEvent Schema

Every event is represented by the `SecurityEvent` dataclass:

```python
@dataclass
class SecurityEvent:
    event_type: EventType          # Category of event (see below)
    tool_name: str                 # Tool or skill that triggered the event
    command: Optional[str]         # The command being executed
    tier: Optional[str]            # Security tier (safe/default/risky/dangerous)
    pattern_name: Optional[str]    # Name of the matched pattern
    pattern_severity: Optional[str]# critical/high/medium/low
    decision: Optional[str]        # allow, block, ask
    decision_reason: Optional[str] # Why the decision was made
    user_response: Optional[str]   # approved, denied (if user was prompted)
    metadata: Optional[Dict]       # Arbitrary key-value data
    session_id: Optional[str]      # Unique session identifier
    working_directory: Optional[str]
    correlation_id: Optional[str]  # Links related events in a screening pass
    source: Optional[str]          # Origin: "hooks", "mcp", "mcp_proxy", "http_proxy"
```

### Correlation IDs

The `correlation_id` field links multiple events that belong to the same
screening pass. For example, a single `Bash` invocation might generate:

1. `TOOL_INVOKED` (tool call received)
2. `PATTERN_MATCH` (regex pattern hit)
3. `USER_PROMPTED` (user asked for confirmation)
4. `USER_APPROVED` (user said yes)
5. `ALLOWED` (execution permitted)

All five events share the same `correlation_id`, making it possible to
reconstruct the full decision chain.

### Source Field

The `source` field identifies which entry point generated the event:

| Value         | Description                                         |
|---------------|-----------------------------------------------------|
| `hooks`       | Claude Code PreToolUse / PostToolUse hooks           |
| `mcp`         | MCP server screening                                 |
| `mcp_proxy`   | MCP proxy interception                               |
| `http_proxy`  | HTTP MITM proxy screening                            |
| `sandbox`     | Sandbox executor preview/execution                   |
| `cli`         | CLI commands (license activation, config changes)    |
| `diagnostics` | Health check system                                  |

---

## Event Types

All 22 event types defined in `EventType`:

### Core Screening Events

| EventType          | Value              | Description                              |
|--------------------|--------------------|------------------------------------------|
| `TOOL_INVOKED`     | `tool_invoked`     | Tool call received                        |
| `PATTERN_MATCH`    | `pattern_match`    | Regex pattern matched                     |
| `LLM_RULE_MATCH`   | `llm_rule_match`   | LLM rule flagged                          |
| `ESCALATION`       | `escalation`       | Tier escalated due to content             |
| `ALLOWED`          | `allowed`          | Execution permitted                       |
| `BLOCKED`          | `blocked`          | Execution blocked                         |
| `USER_PROMPTED`    | `user_prompted`    | User asked for confirmation               |
| `USER_APPROVED`    | `user_approved`    | User approved after prompt                |
| `USER_DENIED`      | `user_denied`      | User denied after prompt                  |
| `SANDBOX_PREVIEW`  | `sandbox_preview`  | Sandbox preview executed                  |
| `ERROR`            | `error`            | Error during processing                   |

### Vault Events

| EventType          | Value              | Description                              |
|--------------------|--------------------|------------------------------------------|
| `VAULT_ACCESS`     | `vault_access`     | Credential store/get/delete               |
| `VAULT_MIGRATION`  | `vault_migration`  | `.env` migration to vault                 |

### Configuration Events

| EventType          | Value              | Description                              |
|--------------------|--------------------|------------------------------------------|
| `CONFIG_CHANGE`    | `config_change`    | Tier/preset/config modification           |

### License Events

| EventType          | Value              | Description                              |
|--------------------|--------------------|------------------------------------------|
| `LICENSE_EVENT`    | `license_event`    | Activation, deactivation, validation      |

### Advanced Screening Events

| EventType          | Value              | Description                              |
|--------------------|--------------------|------------------------------------------|
| `RATE_LIMIT`       | `rate_limit`       | Rate limit violation                      |
| `SESSION_ANOMALY`  | `session_anomaly`  | Session analysis anomaly detected         |
| `CIRCUIT_BREAKER`  | `circuit_breaker`  | Circuit breaker state transition          |

### Plugin Events

| EventType          | Value              | Description                              |
|--------------------|--------------------|------------------------------------------|
| `PLUGIN_EVENT`     | `plugin_event`     | Plugin load, failure, scan result         |

### MCP Events

| EventType          | Value              | Description                              |
|--------------------|--------------------|------------------------------------------|
| `MCP_APPROVAL`     | `mcp_approval`     | MCP approval queue decision               |

### Proxy Events

| EventType          | Value              | Description                              |
|--------------------|--------------------|------------------------------------------|
| `PROXY_EVENT`      | `proxy_event`      | HTTP proxy request screening              |

### System Events

| EventType          | Value              | Description                              |
|--------------------|--------------------|------------------------------------------|
| `HEALTH_CHECK`     | `health_check`     | Diagnostic check results                  |
| `STARTUP`          | `startup`          | System initialization                     |

---

## Log Redaction

**Class:** `LogRedactor` in `tweek/logging/security_log.py`

All data is redacted **before** writing to SQLite or NDJSON. The redactor
applies pattern-based and key-based redaction to ensure secrets never reach
persistent storage.

### Redaction Patterns (14 categories)

| Name                | Detects                                              | Replacement                     |
|---------------------|------------------------------------------------------|---------------------------------|
| `api_key`           | `api_key=`, `secret_key=`, etc. (16+ char values)   | `\1=***REDACTED***`            |
| `aws_key`           | AWS access key IDs (`AKIA...`, `ASIA...`)            | `***AWS_KEY_REDACTED***`       |
| `aws_secret`        | AWS secret access keys (40 char)                     | `\1=***REDACTED***`            |
| `bearer`            | Bearer tokens (20+ char)                             | `Bearer ***REDACTED***`        |
| `jwt`               | JWT tokens (`eyJ...`)                                | `***JWT_REDACTED***`           |
| `github`            | GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) | `***GITHUB_TOKEN_REDACTED***` |
| `slack`             | Slack tokens (`xoxb-`, `xoxp-`, `xoxa-`, etc.)      | `***SLACK_TOKEN_REDACTED***`   |
| `password`          | Password assignments (8+ char values)                | `\1=***REDACTED***`            |
| `connection_string` | DB connection strings with credentials               | `protocol://user:***REDACTED***@` |
| `private_key`       | PEM private key blocks                               | `***PRIVATE_KEY_REDACTED***`   |
| `base64_secret`     | Base64-encoded secrets (40+ char in sensitive context)| `\1=***REDACTED***`            |
| `email`             | Email addresses                                      | `***EMAIL_REDACTED***`         |
| `credit_card`       | 16-digit card numbers                                | `***CARD_REDACTED***`          |
| `ssh_key_read`      | Commands reading SSH key files                       | `\1 ***SSH_PATH_REDACTED***`   |

### Sensitive Dictionary Keys

When redacting dictionaries, values for these keys are fully replaced with
`***REDACTED***`:

```
password, passwd, pwd, secret, token, api_key, apikey,
access_key, secret_key, private_key, credential, auth,
bearer, jwt, session, cookie, oauth, refresh_token,
client_secret, app_secret, webhook_secret, signing_key,
encryption_key, decryption_key, master_key, root_password
```

### Command-Specific Redaction

Additional patterns applied to command strings:

- `curl -H "Authorization: Bearer ..."` -> header value redacted
- `curl -d '...password=...'` -> secret values redacted
- `export SECRET_KEY=value` -> value redacted
- `TOKEN=value command` -> value redacted

### Redactor API

```python
from tweek.logging.security_log import LogRedactor, get_redactor

redactor = get_redactor()  # Singleton

redactor.redact_string("api_key=sk-abc123def456")
# -> "api_key=***REDACTED***"

redactor.redact_dict({"password": "hunter2", "name": "alice"})
# -> {"password": "***REDACTED***", "name": "alice"}

redactor.redact_command("curl -H 'Authorization: Bearer mytoken123'")
# -> "curl -H 'Authorization: ***REDACTED***'"
```

---

## SQLite Schema

**Database:** `~/.tweek/security.db`

### security_events Table

```sql
CREATE TABLE security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    event_type TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    command TEXT,
    tier TEXT,
    pattern_name TEXT,
    pattern_severity TEXT,
    decision TEXT,
    decision_reason TEXT,
    user_response TEXT,
    session_id TEXT,
    working_directory TEXT,
    metadata_json TEXT,
    correlation_id TEXT,
    source TEXT
);
```

### Indexes

| Index                       | Column(s)       | Purpose                          |
|-----------------------------|-----------------|----------------------------------|
| `idx_events_timestamp`      | `timestamp`     | Time-range queries               |
| `idx_events_type`           | `event_type`    | Filter by event category         |
| `idx_events_tool`           | `tool_name`     | Filter by tool                   |
| `idx_events_decision`       | `decision`      | Filter allow/block/ask           |
| `idx_events_session`        | `session_id`    | Session-level queries            |
| `idx_events_correlation`    | `correlation_id`| Link related events              |
| `idx_events_source`         | `source`        | Filter by entry point            |

### Views

**`event_summary`** -- Aggregated daily counts by type, tool, decision, and source:

```sql
SELECT date(timestamp) as date, event_type, tool_name, decision, source, COUNT(*) as count
FROM security_events
GROUP BY date(timestamp), event_type, tool_name, decision, source;
```

**`recent_blocks`** -- Last 100 blocked or flagged commands:

```sql
SELECT timestamp, tool_name, command, pattern_name, pattern_severity,
       decision_reason, correlation_id, source
FROM security_events
WHERE decision IN ('block', 'ask')
ORDER BY timestamp DESC LIMIT 100;
```

### Schema Migration

When upgrading from older versions, `_migrate_schema` automatically adds
`correlation_id` and `source` columns to existing databases without data loss.

---

## JSON Logger (NDJSON)

**Location:** `tweek/logging/json_logger.py`
**Output:** `~/.tweek/security_events.jsonl`

The JSON logger writes events as newline-delimited JSON (NDJSON), one record per
line. Each record is a self-contained JSON object with an ISO 8601 timestamp.

### Enabling JSON Logging

Add to `~/.tweek/config.yaml`:

```yaml
logging:
  json_events: true
```

### Record Format

```json
{
  "timestamp": "2025-06-15T14:30:22.123456+00:00",
  "event_type": "pattern_match",
  "tool_name": "Bash",
  "command": "curl ***REDACTED***",
  "tier": "dangerous",
  "pattern_name": "curl_post_secrets",
  "pattern_severity": "critical",
  "decision": "block",
  "correlation_id": "abc123",
  "source": "hooks"
}
```

Null/None fields are stripped from the output for cleaner records.

### Log Rotation

| Setting           | Default                            |
|-------------------|------------------------------------|
| Max file size     | 10 MB (`MAX_FILE_SIZE_BYTES`)      |
| Max rotated files | 5 (`MAX_ROTATED_FILES`)            |
| Rotation scheme   | `.jsonl` -> `.jsonl.1` -> `.jsonl.2` ... `.jsonl.5` (oldest deleted) |

### Integration with External Systems

The NDJSON format is directly ingestible by:

| System   | Ingestion Method                                        |
|----------|---------------------------------------------------------|
| **ELK**  | Filebeat with JSON input, or Logstash `json` codec      |
| **Splunk** | Monitor `~/.tweek/security_events.jsonl` as JSON source |
| **Datadog** | Datadog Agent log collection with JSON parsing        |
| **Fluentd** | `in_tail` plugin with `format json`                  |

Example Filebeat configuration:

```yaml
filebeat.inputs:
  - type: log
    paths:
      - ~/.tweek/security_events.jsonl
    json.keys_under_root: true
    json.add_error_key: true
```

---

## CLI Commands

### tweek logs show

Display recent security events in a formatted table.

```bash
tweek logs show                        # Last 20 events
tweek logs show -n 50                  # Last 50 events
tweek logs show --type blocked         # Filter by event type
tweek logs show --tool Bash            # Filter by tool
tweek logs show --blocked              # Only blocked/flagged events
tweek logs show --stats                # Security statistics summary
tweek logs show --stats --days 30      # Stats for the last 30 days
```

The statistics view shows:
- Total events in the period
- Breakdown by decision (allow/block/ask)
- Top triggered patterns with severity
- Events by tool

### tweek logs export

Export events to CSV for external analysis.

```bash
tweek logs export                      # Export all to tweek_security_log.csv
tweek logs export --days 7             # Only last 7 days
tweek logs export -o audit.csv         # Custom output path
tweek logs export --days 30 -o monthly.csv
```

### tweek logs clear

Delete events from the database.

```bash
tweek logs clear                       # Clear all (with confirmation prompt)
tweek logs clear --days 30             # Clear events older than 30 days
tweek logs clear --confirm             # Skip confirmation
```

### tweek logs bundle

Create a diagnostic bundle for support. See the next section for details.

```bash
tweek logs bundle                      # Create bundle in current directory
tweek logs bundle -o /tmp/diag.zip     # Specify output path
tweek logs bundle --days 7             # Only last 7 days of events
tweek logs bundle --dry-run            # Show what would be collected
tweek logs bundle --no-redact          # Internal debugging (skip redaction)
```

---

## Diagnostic Bundle

**Location:** `tweek/logging/bundle.py`

The `BundleCollector` creates a zip file containing all relevant diagnostic data,
with automatic redaction of sensitive information.

### Bundle Contents

| File                    | Contents                                 | Status        |
|-------------------------|------------------------------------------|---------------|
| `security.db`           | SQLite events database (or filtered)     | If exists     |
| `approvals.db`          | MCP approval queue database              | If exists     |
| `proxy.log`             | HTTP proxy log                           | If exists     |
| `security_events.jsonl` | NDJSON event log                         | If exists     |
| `config_user.yaml`      | User config (redacted)                   | If exists     |
| `config_project.yaml`   | Project config (redacted)                | If exists     |
| `doctor_output.txt`     | `tweek doctor` results                   | Generated     |
| `system_info.json`      | Platform, version, capabilities          | Generated     |
| `manifest.json`         | Bundle metadata                          | Generated     |

### Excluded Files

These are **never** included in bundles:

- `license.key` -- License key file
- `credential_registry.json` -- Credential metadata
- `certs/` directory -- CA private keys

### System Info Contents

The `system_info.json` file contains:

```json
{
  "timestamp": "2025-06-15T14:30:00Z",
  "platform": {
    "system": "Darwin",
    "release": "24.3.0",
    "version": "...",
    "machine": "arm64",
    "python_version": "3.12.0"
  },
  "tweek": {
    "version": "0.1.0",
    "license_tier": "pro",
    "capabilities": {
      "sandbox": true,
      "vault_backend": "macos_keychain"
    },
    "mcp_available": true,
    "data_dir_exists": true,
    "data_files": ["security.db", "config.yaml", ...]
  }
}
```

---

## SecurityLogger API

```python
from tweek.logging.security_log import get_logger, SecurityEvent, EventType

logger = get_logger()

# Log an event
row_id = logger.log(SecurityEvent(
    event_type=EventType.TOOL_INVOKED,
    tool_name="Bash",
    command="git status",
    tier="dangerous",
    source="hooks",
))

# Quick log helper
row_id = logger.log_quick(EventType.ALLOWED, "Bash", command="git status")

# Query events
events = logger.get_recent_events(limit=50, event_type=EventType.BLOCKED)
blocked = logger.get_blocked_commands(limit=20)
recent = logger.get_recent(limit=10)  # Returns SecurityEvent objects

# Statistics
stats = logger.get_stats(days=7)

# Maintenance
deleted = logger.delete_events(days=30)
count = logger.export_csv(Path("audit.csv"), days=7)
```

---

## Cross-References

- [SANDBOX.md](./SANDBOX.md) -- Sandbox events and preview logging
- [ATTACK_PATTERNS.md](./ATTACK_PATTERNS.md) -- Patterns that generate PATTERN_MATCH events
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) -- Diagnosing logging issues
- [LICENSING.md](./LICENSING.md) -- `advanced_logging` and `log_export` are PRO features
