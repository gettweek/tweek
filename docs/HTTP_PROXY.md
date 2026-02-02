# Tweek HTTP Proxy

Tweek includes an HTTPS-intercepting proxy built on mitmproxy that screens LLM API traffic in real time. This provides security coverage for any tool that communicates with LLM APIs over HTTP, including Cursor, Windsurf, Copilot, and direct API calls.

**Installation:** `pip install tweek[proxy]`

---

## Architecture Overview

```
+----------------+       +-----------------+       +--------------------+
|  LLM Client    |  -->  |  Tweek Proxy    |  -->  |  LLM API Provider  |
| (Cursor, etc.) |       | (mitmproxy)     |       | (api.anthropic.com)|
+----------------+       +---------+-------+       +--------------------+
                                   |
                          +--------v--------+
                          | TweekProxyAddon |
                          |  - Intercepts   |
                          |  - Screens      |
                          |  - Blocks/Logs  |
                          +-----------------+
                                   |
                          +--------v--------+
                          | LLMAPIInterceptor|
                          |  - Provider ID   |
                          |  - Tool extract  |
                          |  - Pattern match |
                          +------------------+
```

The proxy operates as a standard HTTP/HTTPS forward proxy. Applications are configured to route traffic through it via `HTTP_PROXY` and `HTTPS_PROXY` environment variables.

---

## Supported LLM Providers

The interceptor (`tweek/proxy/interceptor.py`) identifies providers by hostname:

| Provider | Monitored Hosts | Tool Call Extraction |
|----------|----------------|----------------------|
| Anthropic | `api.anthropic.com` | `content[]` blocks with `type: "tool_use"` |
| OpenAI | `api.openai.com` | `choices[].message.tool_calls[].function` |
| Google | `generativelanguage.googleapis.com` | Supported (host detection) |
| AWS Bedrock | `bedrock-runtime.*.amazonaws.com` | Regional endpoint regex match |

Non-LLM traffic passes through the proxy untouched.

---

## Request Screening

When an outgoing request targets a monitored host, the proxy extracts user messages and checks them for prompt injection patterns using Tweek's PatternMatcher.

Request screening is **advisory only** -- requests are never blocked, only warned. An `X-Tweek-Warning: prompt-injection-suspected` header is added to flagged requests for downstream tracking.

---

## Response Screening

When a response returns from a monitored host, the proxy:

1. Parses the JSON response body
2. Extracts tool calls using provider-specific formats
3. Screens each tool call through the PatternMatcher
4. Decides: allow, warn, or block

### Tool Call Parsing

The interceptor maps tool names to command patterns for pattern matching:

| Tool Name Pattern | Command Reconstruction |
|-------------------|----------------------|
| `bash`, `shell`, `execute`, `run_command` | Uses `command` field directly |
| `read`, `read_file`, `cat` | Constructs `cat {path}` |
| `write`, `write_file` | Constructs `write to {path}` |
| `fetch`, `web_fetch`, `curl`, `http` | Constructs `curl {url}` |
| All other tools | JSON-serializes the entire `input` dict |

### Block Mode

When `block_mode` is enabled (default), dangerous responses are replaced with a 403 error:

```json
{
  "error": {
    "type": "security_blocked",
    "message": "Tweek Security: Blocked dangerous tool calls: bash",
    "blocked_tools": ["bash"],
    "patterns": ["data_exfiltration_curl"]
  }
}
```

### Log-Only Mode

When `log_only` is enabled, all traffic is logged without blocking. Use this for auditing and threat assessment before enabling enforcement.

### Streaming Responses

Responses with `Content-Type: text/event-stream` (SSE streaming) are **skipped** because buffering them would break the user experience. To screen streaming API calls, use MCP hooks or CLI hooks instead.

---

## Proxy Server Management

**Source:** `tweek/proxy/server.py`

### File Locations

| File | Path | Purpose |
|------|------|---------|
| PID file | `~/.tweek/proxy/proxy.pid` | Tracks running proxy process |
| Log file | `~/.tweek/proxy/proxy.log` | Proxy output and error logs |
| CA certificates | `~/.tweek/proxy/certs/` | mitmproxy CA certificate directory |
| CA certificate | `~/.tweek/proxy/certs/mitmproxy-ca-cert.pem` | PEM file for trust installation |

### Default Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| Listen port | `9877` | Proxy listen port |
| Web port | `9878` (disabled) | mitmproxy web interface port |
| Block mode | `true` | Block dangerous responses |
| Log only | `false` | Log without blocking |

### Starting the Proxy

```bash
tweek proxy start                     # Background, default port 9877
tweek proxy start --port 8080         # Custom port
tweek proxy start --foreground        # Foreground (debugging)
tweek proxy start --log-only          # Log without blocking
tweek proxy start --web-port 9878     # Enable mitmproxy web UI
```

The proxy checks for an existing running instance via PID file before starting. If a stale PID file is found (process no longer exists), it is automatically cleaned up.

### Stopping the Proxy

```bash
tweek proxy stop
```

The stop operation:
1. Reads the PID from `~/.tweek/proxy/proxy.pid`
2. Sends `SIGTERM` for graceful shutdown
3. Waits up to 5 seconds
4. Sends `SIGKILL` if the process is still alive
5. Cleans up the PID file

---

## CA Certificate Setup

HTTPS interception requires a trusted Certificate Authority (CA) certificate. The proxy uses mitmproxy's CA generation.

### Installing the CA Certificate

```bash
tweek proxy trust
```

This command:
1. Generates the CA certificate if it does not exist (using mitmproxy's `CertStore`)
2. Installs it in the system trust store

| Platform | Installation Method | Trust Store |
|----------|-------------------|-------------|
| macOS | `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain` | System Keychain |
| Linux | Copies to `/usr/local/share/ca-certificates/tweek-proxy.crt`, runs `update-ca-certificates` | System CA bundle |

Both macOS and Linux installation require `sudo` privileges.

---

## Conflict Detection

During `tweek install`, Tweek detects existing proxy configurations that may conflict:

- Other HTTP proxies already set via environment variables
- Tools like moltbot that manage their own proxy settings

Options for handling conflicts:

| CLI Flag | Behavior |
|----------|----------|
| `--force-proxy` | Override existing proxy configurations |
| `--skip-proxy-check` | Skip proxy conflict detection entirely |

When a conflict is detected and neither flag is specified, Tweek prompts the user to choose.

---

## Environment Variables

To route an application through the proxy, set these environment variables:

```bash
export HTTP_PROXY="http://127.0.0.1:9877"
export HTTPS_PROXY="http://127.0.0.1:9877"
export http_proxy="http://127.0.0.1:9877"
export https_proxy="http://127.0.0.1:9877"
export NODE_TLS_REJECT_UNAUTHORIZED=0    # For Node.js apps with self-signed CA
```

Both upper and lowercase variants are set because different HTTP libraries check different variables.

### Wrapper Scripts

Use `tweek proxy wrap` to generate a shell script that automatically sets environment variables and starts the proxy if needed:

```bash
tweek proxy wrap cursor "/Applications/Cursor.app/Contents/MacOS/Cursor"
tweek proxy wrap myapp "npm start" -o run-protected.sh
```

The generated wrapper:
1. Checks if the Tweek proxy is running; starts it if not
2. Exports all proxy environment variables
3. Runs the target application

### Interactive Setup

```bash
tweek proxy setup
```

The setup wizard:
1. Detects installed LLM tools (via detector plugins)
2. Generates the CA certificate if needed
3. Offers to install the CA in the system trust store
4. Configures shell environment variables

---

## Mitmproxy Addon

**Source:** `tweek/proxy/addon.py`

The `TweekProxyAddon` class implements mitmproxy's addon API:

| Method | Lifecycle | Description |
|--------|-----------|-------------|
| `load(loader)` | Startup | Log configuration summary |
| `request(flow)` | Per-request | Screen outgoing LLM API requests for prompt injection |
| `response(flow)` | Per-response | Screen incoming responses for dangerous tool calls |
| `done()` | Shutdown | Log aggregate statistics |

The `response` handler is decorated with `@concurrent` to allow parallel processing of multiple responses.

### Runtime Statistics

The addon tracks aggregate counters:

| Counter | Description |
|---------|-------------|
| `requests_screened` | Total LLM API requests processed |
| `responses_screened` | Total LLM API responses processed |
| `requests_blocked` | Requests with warnings (not actually blocked) |
| `responses_blocked` | Responses replaced with 403 error |
| `tool_calls_detected` | Total tool calls found in responses |
| `tool_calls_blocked` | Tool calls that matched attack patterns |

Statistics are logged as JSON when the proxy shuts down.

### Configuration via Environment

The addon reads two environment variables set by the proxy server:

| Variable | Values | Default |
|----------|--------|---------|
| `TWEEK_PROXY_BLOCK_MODE` | `0` or `1` | `1` |
| `TWEEK_PROXY_LOG_ONLY` | `0` or `1` | `0` |

---

## Security Logging

All proxy interception events are logged through Tweek's security logger (`tweek/logging/security_log.py`) with event type `PROXY_EVENT`. Logged metadata includes:

- Provider name
- List of blocked tools
- List of matched patterns
- Correlation ID (12-character hex string per screening pass)

---

## Cross-References

- [CLI_REFERENCE.md](CLI_REFERENCE.md) -- Full CLI reference for `tweek proxy` commands
- [MCP_INTEGRATION.md](MCP_INTEGRATION.md) -- MCP-based interception for desktop clients
- [PLUGINS.md](PLUGINS.md) -- LLM provider plugins used for tool call extraction
