# Tweek Overrides Reference

This file documents the full format for `~/.tweek/overrides.yaml` — the human-controlled configuration file for whitelists, pattern toggles, and trust level overrides.

**Important:** This file can only be edited by a human directly. Tweek will block AI-initiated modifications as a security measure. When helping users, provide them the YAML to add — do not attempt to write the file.

---

## Whitelist Rules

Whitelist rules skip all screening for matching targets. When a rule matches, the entire screening pipeline is bypassed — no pattern matching, no LLM review, nothing.

### Rule Types

#### Path-based (files and directories)

```yaml
whitelist:
  # Exempt a specific file for specific tools
  - path: /home/user/project/templates.yaml
    tools: [Read]
    reason: "Known-safe templates file"

  # Exempt an entire directory (prefix match)
  - path: /home/user/trusted-project
    tools: [Read, Grep]
    reason: "Trusted project directory"
```

Path rules support exact file matches and prefix matches (any file inside the directory).

#### URL prefix

```yaml
whitelist:
  - url_prefix: "https://api.example.com/"
    tools: [WebFetch]
    reason: "Internal API endpoint"
```

#### Command prefix

```yaml
whitelist:
  - tool: Bash
    command_prefix: "git status"
    reason: "Git status is always safe"

  - tool: Bash
    command_prefix: "npm test"
    reason: "Running project tests"
```

### Rule Fields

| Field | Required | Description |
|-------|----------|-------------|
| `path` | One of path/url_prefix/command_prefix | File or directory path (supports ~ expansion) |
| `url_prefix` | One of path/url_prefix/command_prefix | URL prefix to match |
| `command_prefix` | One of path/url_prefix/command_prefix | Bash command prefix to match |
| `tools` | No | List of tool names to restrict the rule to (e.g., `[Read, Grep]`). If omitted, applies to all tools. |
| `tool` | No | Single tool name (alternative to `tools` list) |
| `reason` | Yes | Human-readable explanation of why this is whitelisted |

---

## Pattern Toggles

Control which of the 262 detection patterns are active.

### Globally Disable a Pattern

Prevents a pattern from ever triggering:

```yaml
patterns:
  disabled:
    - name: env_command
      reason: "Used frequently in our workflow"
    - name: docker_mount_sensitive
      reason: "Our CI uses Docker volume mounts"
```

### Scope-Disable a Pattern

Disables a pattern only when operating within specific directories:

```yaml
patterns:
  scoped_disables:
    - name: hook_modification
      paths:
        - /home/user/tweek-source
        - /home/user/another-security-tool
      reason: "These repos contain hook management code"
```

### Force-Enable a Pattern

Ensures a pattern stays active even if a broader rule would disable it:

```yaml
patterns:
  force_enabled:
    - credential_theft_critical
    - private_key_access
```

---

## Trust Level Configuration

Override the auto-detected trust mode:

```yaml
trust:
  # Force a specific trust level (overrides auto-detection)
  level: interactive    # or: automated

  # Custom severity threshold
  min_severity: high    # Only prompt on high and critical
                        # Options: critical, high, medium, low
```

You can also set this via environment variable: `TWEEK_TRUST_LEVEL=interactive` or `TWEEK_TRUST_LEVEL=automated`.

---

## Compliance Plugin Allowlists

Per-plugin allowlists for compliance scanning (healthcare, financial, privacy):

```yaml
plugins:
  compliance:
    modules:
      hipaa:
        allowlist:
          - "exact string to ignore"
        allowlist_patterns:
          - "regex_pattern_to_ignore"
        suppressed_patterns:
          - "pattern_name_to_disable"
      pci:
        allowlist:
          - "4111111111111111"   # Test card number
```

---

## Full Example

A complete `~/.tweek/overrides.yaml` combining multiple features:

```yaml
whitelist:
  - path: ~/projects/my-app
    tools: [Read, Grep]
    reason: "Trusted application code"
  - tool: Bash
    command_prefix: "npm test"
    reason: "Running tests"

patterns:
  disabled:
    - name: env_command
      reason: "Standard workflow tool"
  scoped_disables:
    - name: hook_modification
      paths: [~/projects/my-security-tool]
      reason: "Security tool source code"
  force_enabled:
    - credential_theft_critical

trust:
  min_severity: high

plugins:
  compliance:
    modules:
      pci:
        allowlist:
          - "4111111111111111"
```
