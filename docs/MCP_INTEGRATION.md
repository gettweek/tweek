# Tweek MCP Integration

Tweek integrates with the Model Context Protocol (MCP) to provide security screening for desktop LLM applications. Two modes of operation are available: a **Gateway** that exposes new security tools, and a **Proxy** that transparently wraps upstream MCP servers with screening and human-in-the-loop approval.

**Installation:** `pip install tweek[mcp]`

---

## Architecture Overview

```
                       +-----------------------+
                       |   Desktop LLM Client  |
                       | (Claude / ChatGPT /   |
                       |  Gemini / VS Code)    |
                       +----------+------------+
                                  |
                           stdio transport
                                  |
              +-------------------+-------------------+
              |                                       |
    +---------v----------+              +-------------v-----------+
    | Tweek MCP Gateway  |              |  Tweek MCP Proxy        |
    | (tweek mcp serve)  |              |  (tweek mcp proxy)      |
    |                    |              |                         |
    | Tools:             |              |  Screening Pipeline     |
    |  - tweek_vault     |              |  Approval Queue         |
    |  - tweek_status    |              |  Namespace Merging      |
    +--------------------+              +-----+-------+-----------+
                                              |       |
                                         stdio |       | stdio
                                              |       |
                                  +-----------v-+   +-v-----------+
                                  | Upstream     |   | Upstream     |
                                  | MCP Server A |   | MCP Server B |
                                  +--------------+   +--------------+
```

Built-in desktop client tools (Bash, Read, Write, Edit, etc.) cannot be intercepted via MCP. For those, use CLI hooks (Claude Code) or the HTTP proxy (Cursor, direct API calls).

---

## Gateway Server (`tweek mcp serve`)

The gateway exposes genuinely new capabilities not available as built-in desktop client tools. It runs on stdio transport and is launched by the desktop client as a configured MCP server.

**Source:** `tweek/mcp/server.py`

### Tools Provided

#### `tweek_vault`

Retrieve a credential from Tweek's secure vault (system keychain). Use this instead of reading `.env` files or hardcoding secrets.

**Input Schema:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `skill` | string | yes | Skill namespace for the credential |
| `key` | string | yes | Credential key name |

**Response (JSON):**

```json
{"value": "sk-abc123", "skill": "myapp", "key": "API_KEY"}
```

Or if blocked by screening:

```json
{"blocked": true, "reason": "Blocked by compliance scan"}
```

#### `tweek_status`

Show Tweek security status including active plugins, recent activity, threat summary, and proxy statistics.

**Input Schema:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `detail` | enum: `summary`, `plugins`, `activity`, `threats` | no | Level of detail (default: `summary`) |

**Response (JSON):**

```json
{
  "version": "0.2.0",
  "source": "mcp",
  "mode": "gateway",
  "gateway_requests": 42,
  "gateway_blocked": 3,
  "plugins": {"total": 12, "enabled": 8},
  "recent_activity": [...]
}
```

### Gateway Configuration

Tools can be individually enabled/disabled in `~/.tweek/config.yaml`:

```yaml
mcp:
  gateway:
    tools:
      vault: true     # Enable tweek_vault tool (default: true)
      status: true    # Enable tweek_status tool (default: true)
```

### Gateway Screening Behavior

All tool calls pass through Tweek's screening pipeline (`tweek/mcp/screening.py`). In gateway mode, `should_prompt` decisions are converted to `blocked` since there is no interactive user to confirm.

---

## Proxy Server (`tweek mcp proxy`)

The proxy sits between LLM clients and upstream MCP servers. All tool calls are transparently intercepted, screened through Tweek's defense-in-depth pipeline, and optionally queued for human approval.

**Source:** `tweek/mcp/proxy.py`

### How It Works

1. On startup, the proxy reads upstream server definitions from configuration
2. It connects to each upstream via stdio transport and discovers their tools
3. All discovered tools are merged into a single list with namespace prefixes
4. When the LLM client calls a tool, the proxy:
   a. Resolves the namespaced name to the upstream and original tool name
   b. Runs the screening pipeline on the tool call arguments
   c. If **allowed**: forwards the call to the upstream and returns the result
   d. If **blocked**: returns an error response immediately
   e. If **should_prompt**: queues for human approval, then forwards or denies

### Namespace Format

Proxied tools are namespaced using double-underscore separators:

```
{upstream_name}__{original_tool_name}
```

For example, if upstream `filesystem` provides a tool `read_file`, the proxied tool name is:

```
filesystem__read_file
```

The tool description is also prefixed: `[filesystem] Read a file from the filesystem`.

### Upstream Configuration

Configure upstream MCP servers in `~/.tweek/config.yaml`:

```yaml
mcp:
  proxy:
    approval_timeout: 300     # Seconds to wait for approval (default: 300)
    upstreams:
      filesystem:
        command: "npx"
        args: ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"]
      database:
        command: "npx"
        args: ["-y", "@modelcontextprotocol/server-postgres"]
        env:
          DATABASE_URL: "$DATABASE_URL"
        cwd: "/path/to/project"
    screening_overrides:
      filesystem:
        tier: "risky"         # Override default tier for this upstream
```

Environment variables in `env` values are expanded using `os.path.expandvars`.

### Client Configuration

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "tweek-proxy": {
      "command": "tweek",
      "args": ["mcp", "proxy"]
    }
  }
}
```

**ChatGPT Desktop:** Requires Developer Mode. See `tweek protect chatgpt` for instructions.

**Gemini CLI:** Configured via `~/.gemini/settings.json`. Use `tweek protect gemini` for auto-configuration.

### Auto-Configuration

Use the `tweek protect` command for automatic client configuration:

```bash
tweek protect claude-desktop       # Auto-configures Claude Desktop
tweek protect chatgpt              # Provides Developer Mode instructions
tweek protect gemini               # Auto-configures Gemini CLI
```

---

## Approval Queue (`tweek mcp approve`)

When the screening pipeline flags a tool call as needing confirmation (`should_prompt`), the proxy queues it in an SQLite-backed approval queue. A separate CLI daemon reads pending requests and allows human approve/deny decisions.

**Source:** `tweek/mcp/approval.py`

**Database location:** `~/.tweek/approvals.db`

### Approval Flow

```
Proxy receives tool call
        |
   Screening says "should_prompt"
        |
   Enqueue in approvals.db
        |
   Proxy polls queue (1s interval)
        |
   +----+----+
   |         |
 Approved   Denied/Expired
   |         |
 Forward    Return error
 to upstream
```

### Request Lifecycle

| Status | Description |
|--------|-------------|
| `pending` | Awaiting human decision |
| `approved` | Approved by reviewer |
| `denied` | Denied by reviewer |
| `expired` | Timeout exceeded (auto-denied) |

Default timeout is 300 seconds (5 minutes), configurable via `mcp.proxy.approval_timeout`.

### Running the Approval Daemon

Run in a separate terminal while `tweek mcp proxy` is serving:

```bash
tweek mcp approve                    # Interactive daemon
tweek mcp approve --list             # Show pending requests and exit
tweek mcp approve -p 5               # Poll every 5 seconds
```

### Making Individual Decisions

```bash
tweek mcp decide abc12345 approve
tweek mcp decide abc12345 deny -n "Not authorized"
```

Request IDs support prefix matching -- the first 8 characters are sufficient.

### Database Schema

The `approval_requests` table stores:

| Column | Type | Description |
|--------|------|-------------|
| `id` | TEXT PRIMARY KEY | UUID for the request |
| `timestamp` | TEXT | When the request was created |
| `upstream_server` | TEXT | Upstream MCP server name |
| `tool_name` | TEXT | Original tool name |
| `arguments_json` | TEXT | Redacted tool arguments |
| `screening_reason` | TEXT | Why screening flagged this |
| `screening_findings_json` | TEXT | Detailed findings |
| `risk_level` | TEXT | safe/default/risky/dangerous |
| `status` | TEXT | pending/approved/denied/expired |
| `decided_at` | TEXT | When decision was made |
| `decided_by` | TEXT | Who decided (cli/web/timeout) |
| `decision_notes` | TEXT | Optional notes |
| `timeout_seconds` | INTEGER | Per-request timeout |

The database uses WAL journal mode for concurrent access and includes retry logic for lock contention.

---

## Screening Pipeline (`tweek/mcp/screening.py`)

Shared screening logic used by both the gateway and proxy. The pipeline runs these stages in order:

1. **Tier Resolution** -- Determine the effective security tier for the tool
2. **Compliance Scanning** -- Run all enabled compliance plugins on input content
3. **Safe Tier Bypass** -- Skip further screening if tier is `safe`
4. **Pattern Matching** -- Check content against attack patterns
5. **Screening Plugins** -- Run additional screening plugins (rate limiter, LLM reviewer, session analyzer)

**Return values:**

| Key | Type | Description |
|-----|------|-------------|
| `allowed` | bool | Whether execution is permitted |
| `blocked` | bool | Whether execution is hard-blocked |
| `should_prompt` | bool | Whether human confirmation is needed |
| `reason` | str or None | Explanation of the decision |
| `findings` | list | Detailed findings from screening |

### Output Scanning

The `run_output_scan()` function scans response content for leaked credentials or sensitive data using compliance plugins in `output` direction.

### Error Handling

- If screening modules are unavailable (ImportError): **fail open** with a warning
- If an unexpected error occurs: **fail closed** (block the call)

---

## Cross-References

- [CLI_REFERENCE.md](CLI_REFERENCE.md) -- Full CLI command reference for `tweek mcp` commands
- [HTTP_PROXY.md](HTTP_PROXY.md) -- HTTP proxy for non-MCP applications
- [VAULT.md](VAULT.md) -- Vault architecture used by `tweek_vault` tool
- [PLUGINS.md](PLUGINS.md) -- Compliance and screening plugins used in screening pipeline
