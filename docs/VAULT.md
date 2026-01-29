# Tweek Vault

Tweek Vault provides cross-platform secure credential storage, eliminating the need for `.env` files or hardcoded secrets in AI coding assistant workflows.

---

## Architecture Overview

```
+-------------------+       +--------------------+       +-------------------+
|  tweek vault CLI  |       |  MCP Gateway       |       |  Internal APIs    |
|  (store/get/del)  |       |  (tweek_vault tool)|       |  (export_for_     |
+--------+----------+       +--------+-----------+       |   process)        |
         |                           |                   +--------+----------+
         |                           |                            |
         +---------------------------+----------------------------+
                                     |
                          +----------v-----------+
                          | CrossPlatformVault   |
                          | (cross_platform.py)  |
                          +----------+-----------+
                                     |
                          +----------v-----------+
                          |   keyring library    |
                          +----------+-----------+
                                     |
              +----------------------+----------------------+
              |                      |                      |
   +----------v-------+  +----------v--------+  +----------v---------+
   | macOS Keychain    |  | Linux Secret       |  | Windows Credential |
   | (security CLI)    |  | Service (GNOME     |  | Locker             |
   |                   |  | Keyring / KWallet) |  |                    |
   +-------------------+  +-------------------+  +--------------------+
```

---

## Cross-Platform Backends

**Source:** `tweek/vault/cross_platform.py`

The primary vault implementation uses the Python `keyring` library, which provides a unified API for platform-native credential storage.

| Platform | Backend | Service |
|----------|---------|---------|
| macOS | Keychain | GNOME Keyring, KWallet, KeePassXC via `secretstorage` |
| Linux | Secret Service (D-Bus) | GNOME Keyring, KWallet, KeePassXC |
| Windows | Windows Credential Locker | Built-in Windows Credential Manager |

**Dependency:** `pip install keyring`

### Service Name Format

Credentials are stored using the service name format:

```
tweek.{skill}
```

For example, a credential for skill `myapp` with key `API_KEY` is stored as:

- **Service:** `tweek.myapp`
- **Account/Username:** `API_KEY`
- **Password:** *(the secret value)*

This grouping allows multiple credentials per skill while using the OS keychain's native organization.

### Legacy macOS Backend

**Source:** `tweek/vault/keychain.py`

A macOS-specific implementation that calls the `security` CLI directly (no `keyring` dependency):

- **Service prefix:** `com.tweek.{skill}` (note the different prefix)
- **Registry:** Maintains `~/.tweek/credential_registry.json` to track stored keys (since macOS Keychain has no native list operation)
- Uses `security add-generic-password`, `find-generic-password`, `delete-generic-password`
- The `-U` flag enables update-if-exists semantics

The legacy backend is used as a fallback when the `keyring` library is not installed.

---

## API Reference

### `CrossPlatformVault` Class

#### `store(skill, key, value) -> bool`

Store a credential in the vault.

| Parameter | Type | Description |
|-----------|------|-------------|
| `skill` | str | Skill/application namespace |
| `key` | str | Credential key (e.g., `API_KEY`) |
| `value` | str | The secret value |

Returns `True` on success, `False` on failure.

#### `get(skill, key) -> Optional[str]`

Retrieve a credential from the vault.

Returns the secret value, or `None` if not found.

#### `delete(skill, key) -> bool`

Delete a credential from the vault.

Returns `True` if deleted, `False` if not found or error.

#### `list_keys(skill) -> list[str]`

List all credential keys for a skill.

**Note:** The `keyring` library does not provide a native list operation. The cross-platform vault returns an empty list for this method. Use the legacy macOS backend or maintain an external index for full list support.

#### `get_all(skill) -> dict[str, str]`

Get all credentials for a skill as a dictionary. Subject to the same limitation as `list_keys`.

#### `export_for_process(skill, keys) -> dict[str, str]`

Export specific credentials as environment variable key-value pairs. Useful for injecting secrets into subprocess environments.

```python
vault = CrossPlatformVault()
env = vault.export_for_process("myapp", ["API_KEY", "DB_PASSWORD"])
subprocess.run(["python", "serve.py"], env={**os.environ, **env})
```

### `KeychainVault` Class (macOS Legacy)

The macOS-specific backend provides the same core API (`store`, `get`, `delete`) plus additional capabilities:

#### `list_keys(skill) -> list[str]`

Returns keys from the local registry file (`~/.tweek/credential_registry.json`).

#### `list_skills() -> list[str]`

Returns all skill names with stored credentials.

#### `get_all(skill) -> dict[str, str]`

Returns all credentials for a skill by iterating `list_keys` and calling `get` for each.

#### `export_for_process(skill) -> str`

Returns a shell-formatted string of `KEY="value"` pairs suitable for `env -i`.

#### `migrate_from_env(env_path, skill, dry_run=False) -> list[str]`

Migrate credentials from a `.env` file. Returns list of migrated key names.

---

## CLI Usage

### Store a Credential

```bash
tweek vault store <SKILL> <KEY> <VALUE>
```

```bash
tweek vault store myapp API_KEY sk-abc123
tweek vault store deploy AWS_SECRET_ACCESS_KEY s3cr3t
tweek vault store github GH_TOKEN ghp_xxxx
```

### Retrieve a Credential

```bash
tweek vault get <SKILL> <KEY>
```

```bash
tweek vault get myapp API_KEY
# Output: sk-abc123
```

### Delete a Credential

```bash
tweek vault delete <SKILL> <KEY>
```

```bash
tweek vault delete myapp API_KEY
```

---

## .env Migration Workflow

Tweek provides a workflow for migrating plaintext `.env` files to secure vault storage.

### Automatic Migration During Install

When running `tweek install`, Tweek scans for `.env` files and offers to migrate them. Use `--skip-env-scan` to suppress this behavior.

### Manual Migration

```bash
tweek vault migrate-env --skill myapp
tweek vault migrate-env --skill myapp --dry-run
tweek vault migrate-env --skill deploy --env-file .env.production
```

### How Migration Works

**Source:** `tweek/vault/cross_platform.py` (`migrate_env_to_vault` function)

1. Read the `.env` file line by line
2. Skip empty lines and comments (lines starting with `#`)
3. Parse `KEY=value` pairs using regex: `^([A-Z][A-Z0-9_]*)\s*=\s*["']?(.+?)["']?\s*$`
4. Strip surrounding quotes (single or double) from values
5. Store each key-value pair in the vault under the specified skill
6. Return a list of `(key, success)` tuples
7. Log a `VAULT_MIGRATION` security event with counts

The `--dry-run` flag reports which keys would be migrated without actually storing them.

### Supported .env Formats

```bash
# This is a comment (skipped)
API_KEY=sk-abc123
DB_PASSWORD="quoted value"
SECRET='single quoted'
SPACED_KEY = value_with_spaces_trimmed
```

Lines not matching the pattern (lowercase keys, missing values, export statements) are silently skipped.

---

## MCP Gateway Integration

**Source:** `tweek/mcp/server.py`

The `tweek_vault` MCP tool allows desktop LLM clients to retrieve credentials from the vault without reading `.env` files.

### Tool Schema

```json
{
  "name": "tweek_vault",
  "description": "Retrieve a credential from Tweek's secure vault",
  "inputSchema": {
    "type": "object",
    "properties": {
      "skill": { "type": "string", "description": "Skill namespace" },
      "key": { "type": "string", "description": "Credential key name" }
    },
    "required": ["skill", "key"]
  }
}
```

### Response Format

Success:

```json
{"value": "sk-abc123", "skill": "myapp", "key": "API_KEY"}
```

Not found:

```json
{"value": null, "skill": "myapp", "key": "MISSING_KEY"}
```

Blocked by screening:

```json
{"blocked": true, "reason": "Blocked by compliance scan"}
```

Vault unavailable:

```json
{"error": "Vault is not available on this system"}
```

### Screening

All vault access through the MCP gateway passes through Tweek's screening pipeline. The tool name for screening purposes is `tweek_vault`, and the content screened is the skill and key combination.

---

## Security Logging

All vault operations are logged to Tweek's security logger. Events are logged with `event_type=VAULT_ACCESS` and include:

| Metadata Field | Description |
|---------------|-------------|
| `operation` | `store`, `get`, or `delete` |
| `skill` | Skill namespace |
| `key` | Credential key (name only, never the value) |
| `success` | Whether the operation succeeded |
| `error` | Error message if operation failed |

Migration events use `event_type=VAULT_MIGRATION` and include:

| Metadata Field | Description |
|---------------|-------------|
| `source_file` | Path to the `.env` file |
| `skill` | Target skill namespace |
| `dry_run` | Whether this was a dry run |
| `keys_migrated` | Count of successfully migrated keys |
| `keys_failed` | Count of failed migrations |

Security logging never raises exceptions -- all logging errors are silently caught to avoid disrupting vault operations.

---

## Availability Detection

The vault module (`tweek/vault/__init__.py`) uses a fallback chain:

1. Try to import `CrossPlatformVault` (requires `keyring`)
2. If unavailable, set `VAULT_AVAILABLE = False`
3. Fall back to `KeychainVault` on macOS (no dependencies)

Check availability programmatically:

```python
from tweek.vault import VAULT_AVAILABLE, VAULT_TYPE

if VAULT_AVAILABLE:
    from tweek.vault import get_vault
    vault = get_vault()
else:
    print("Vault not available. Install keyring: pip install keyring")
```

The `tweek doctor` command checks vault availability as part of its health checks.

---

## Cross-References

- [CLI_REFERENCE.md](CLI_REFERENCE.md) -- Full CLI reference for `tweek vault` commands
- [MCP_INTEGRATION.md](MCP_INTEGRATION.md) -- MCP gateway `tweek_vault` tool details
- [PLUGINS.md](PLUGINS.md) -- Compliance plugins that screen vault access
