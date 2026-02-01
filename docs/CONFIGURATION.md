# Tweek Configuration

## Table of Contents

- [Configuration System Overview](#configuration-system-overview)
- [3-Layer Config Hierarchy](#3-layer-config-hierarchy)
- [Security Tiers](#security-tiers)
- [Presets](#presets)
- [Known Tools and Skills](#known-tools-and-skills)
- [Content-Based Escalations](#content-based-escalations)
- [LLM Review Provider](#llm-review-provider)
- [Plugin Configuration](#plugin-configuration)
- [Directory Activation](#directory-activation)
- [Annotated Config Examples](#annotated-config-examples)
- [Configuration Validation](#configuration-validation)

---

## Configuration System Overview

**Source**: `tweek/config/manager.py`

Tweek uses a layered YAML configuration system where each layer can override the
previous one. The `ConfigManager` class manages loading, merging, validation, and
persistence of configuration across all layers.

### Config File Locations

| Layer | Path | Scope |
|---|---|---|
| Built-in defaults | `tweek/config/tiers.yaml` (bundled) | All users |
| User overrides | `~/.tweek/config.yaml` | Per-user global settings |
| Project overrides | `.tweek/config.yaml` (in project root) | Per-project settings |

---

## 3-Layer Config Hierarchy

Configuration is resolved with project overrides taking highest priority:

```
Built-in defaults (tiers.yaml)
        |
        v
  User overrides (~/.tweek/config.yaml)
        |
        v
  Project overrides (.tweek/config.yaml)    <-- Highest priority
```

### Merge Behavior

The `ConfigManager._get_merged()` method applies layers sequentially:

1. Start with built-in defaults
2. **Update** with user overrides (keys from user config replace built-in keys)
3. **Update** with project overrides (keys from project config replace merged keys)

For `tools` and `skills` dictionaries, this is a shallow merge -- individual tool/skill
tiers are overridden but the complete set is preserved. For `escalations`, user and
project escalations are **appended** to the built-in list.

### Determining Source

Every tool, skill, and plugin configuration tracks its source:

```python
# From ConfigManager.get_tool_config()
if tool_name in self._project.get("tools", {}):
    source = "project"
elif tool_name in self._user.get("tools", {}):
    source = "user"
else:
    source = "default"
```

This allows `tweek config show` to display where each setting came from.

---

## Security Tiers

**Source**: `tweek/config/tiers.yaml`, `tweek/config/manager.py` -> `SecurityTier` enum

Tweek assigns every tool and skill a security tier that determines which screening
layers are activated.

### Tier Definitions

| Tier | Description | Screening Layers | Use Case |
|---|---|---|---|
| **safe** | Trusted, read-only operations | None | `Read`, `Glob`, `Grep` -- no side effects |
| **default** | Standard operations with modification potential | Pattern matching (regex) | `Edit`, `Write`, `NotebookEdit` -- file modifications |
| **risky** | External communication or significant changes | Pattern matching + LLM review | `WebFetch`, `WebSearch` -- network access |
| **dangerous** | System commands, highest scrutiny | Pattern matching + LLM review + Sandbox preview | `Bash` -- arbitrary shell execution |

### Screening Methods Per Tier

```yaml
tiers:
  safe:
    description: "Trusted operations - no screening"
    screening: []

  default:
    description: "Standard operations - regex patterns only"
    screening:
      - regex

  risky:
    description: "Elevated risk - regex + LLM semantic review"
    screening:
      - regex
      - llm

  dangerous:
    description: "High risk - full screening + sandbox preview"
    screening:
      - regex
      - llm
      - sandbox
```

Note: Layer 0 (Compliance) and Layer 1 (Rate Limiting) run regardless of tier.
Layer 4 (Session Analysis) runs for `risky` and `dangerous` when `session_id` exists.

---

## Presets

**Source**: `tweek/config/manager.py` -> `ConfigManager.PRESETS`

Presets provide one-command configuration for common security postures. Apply with:

```bash
tweek config preset paranoid
tweek config preset cautious
tweek config preset trusted
```

### Paranoid Preset

Maximum security. Every operation gets elevated scrutiny. Recommended for high-security
environments or when working with untrusted code.

```yaml
# preset: paranoid
tools:
  Read: default       # Even reads get pattern matching
  Glob: default       # Even globs get pattern matching
  Grep: default       # Even greps get pattern matching
  Edit: risky         # File edits get LLM review
  Write: risky        # File writes get LLM review
  WebFetch: dangerous # Web access gets full pipeline
  WebSearch: dangerous # Web search gets full pipeline
  Bash: dangerous     # Shell commands get full pipeline
default_tier: risky   # Unknown tools get LLM review
```

### Cautious Preset (Recommended)

Balanced security. Matches the built-in defaults with sensible screening for each
tool type.

```yaml
# preset: cautious
tools:
  Read: safe          # Read-only, no screening
  Glob: safe          # Pattern search, no screening
  Grep: safe          # Content search, no screening
  Edit: default       # Pattern matching for edits
  Write: default      # Pattern matching for writes
  WebFetch: risky     # LLM review for web access
  WebSearch: risky    # LLM review for web search
  Bash: dangerous     # Full pipeline for shell commands
default_tier: default # Unknown tools get pattern matching
```

### Trusted Preset

Minimal friction. For trusted environments where the AI assistant is working on
well-understood, low-risk codebases.

```yaml
# preset: trusted
tools:
  Read: safe          # No screening
  Glob: safe          # No screening
  Grep: safe          # No screening
  Edit: safe          # No screening (!)
  Write: safe         # No screening (!)
  WebFetch: default   # Pattern matching only for web
  WebSearch: default  # Pattern matching only for web
  Bash: risky         # LLM review but no sandbox
default_tier: safe    # Unknown tools get no screening
```

### Preset Comparison

| Tool | Paranoid | Cautious | Trusted |
|---|---|---|---|
| Read | default | safe | safe |
| Glob | default | safe | safe |
| Grep | default | safe | safe |
| Edit | risky | default | safe |
| Write | risky | default | safe |
| WebFetch | dangerous | risky | default |
| WebSearch | dangerous | risky | default |
| Bash | dangerous | dangerous | risky |
| **default_tier** | **risky** | **default** | **safe** |

### Previewing Changes

Before applying a preset, preview what would change:

```bash
tweek config diff paranoid
```

This calls `ConfigManager.diff_preset()` which compares current values against the
preset and returns a list of `ConfigChange` objects.

---

## Known Tools and Skills

### Known Tools

**Source**: `tweek/config/manager.py` -> `ConfigManager.KNOWN_TOOLS`

| Tool | Default Tier | Description |
|---|---|---|
| `Read` | safe | Read files -- no side effects |
| `Glob` | safe | Find files by pattern |
| `Grep` | safe | Search file contents |
| `Edit` | default | Modify existing files |
| `Write` | default | Create/overwrite files |
| `NotebookEdit` | default | Edit Jupyter notebooks |
| `WebFetch` | risky | Fetch content from URLs |
| `WebSearch` | risky | Search the web |
| `Bash` | dangerous | Execute shell commands |
| `Task` | default | Spawn subagent tasks |

### Known Skills

**Source**: `tweek/config/manager.py` -> `ConfigManager.KNOWN_SKILLS`

| Skill | Default Tier | Description |
|---|---|---|
| `commit` | default | Git commit operations |
| `review-pr` | safe | Review pull requests (read-only) |
| `explore` | safe | Explore codebase (read-only) |
| `frontend-design` | risky | Generate frontend code |
| `dev-browser` | risky | Browser automation |
| `deploy` | dangerous | Deployment operations |

### Custom Tools and Skills

Any tool or skill not in the known lists receives the `default_tier` setting. You can
assign custom tiers via configuration:

```yaml
# ~/.tweek/config.yaml
tools:
  MyCustomTool: risky

skills:
  my-custom-skill: dangerous
  data-pipeline: risky
```

---

## Content-Based Escalations

**Source**: `tweek/config/tiers.yaml` -> `escalations`, `tweek/hooks/pre_tool_use.py` -> `TierManager.check_escalations()`

Escalation patterns upgrade a tool's effective tier based on the content of the
operation. Escalations can only increase a tier, never decrease it.

### Built-in Escalations

| Pattern | Description | Escalates To |
|---|---|---|
| `\b(prod\|production)\b` | Production environment reference | risky |
| `rm\s+(-rf\|-fr\|--recursive)` | Recursive deletion | dangerous |
| `(DROP\|TRUNCATE\|DELETE FROM)\s+\w+` | Destructive SQL operation | dangerous |
| `(npm publish\|pip upload\|cargo publish)` | Package publishing | dangerous |
| `(kubectl\|gcloud\|aws)\s+(apply\|deploy\|delete)` | Cloud deployment operation | dangerous |
| `sudo\s+` | Elevated privileges | dangerous |

### Custom Escalations

Add custom escalation patterns at user or project level:

```yaml
# ~/.tweek/config.yaml
escalations:
  - pattern: 'docker\s+push'
    description: "Docker image publishing"
    escalate_to: dangerous

  - pattern: 'terraform\s+(apply|destroy)'
    description: "Terraform infrastructure changes"
    escalate_to: dangerous
```

### How Escalation Works

```python
# From TierManager.get_effective_tier()
base_tier = get_base_tier(tool_name, skill_name)  # e.g., "default" for Edit
escalation = check_escalations(content)            # e.g., matches "production"

# Only escalate, never de-escalate
if escalated_priority > base_priority:
    return escalated_tier, escalation  # "risky"
return base_tier, None                 # stays "default"
```

---

## LLM Review Provider

**Source**: `tweek/config/tiers.yaml` -> `llm_review`, `tweek/security/llm_reviewer.py`

The LLM reviewer (Layer 3) supports multiple LLM providers. Configure which provider,
model, and endpoint to use for semantic security analysis.

### Configuration Options

```yaml
# ~/.tweek/config.yaml or .tweek/config.yaml
llm_review:
  enabled: true           # Enable/disable LLM review entirely
  provider: auto          # auto | anthropic | openai | google
  model: auto             # auto = provider default, or explicit model name
  base_url: null          # For OpenAI-compatible endpoints
  api_key_env: null       # Override which env var to read for the API key
  timeout_seconds: 5.0    # Timeout for API calls
```

### Provider Auto-Detection

When `provider: auto` (the default), Tweek checks for API keys in order:

1. `ANTHROPIC_API_KEY` present -> Anthropic, model `claude-3-5-haiku-latest`
2. `OPENAI_API_KEY` present -> OpenAI, model `gpt-4o-mini`
3. `GOOGLE_API_KEY` or `GEMINI_API_KEY` present -> Google, model `gemini-2.0-flash`
4. None found -> LLM reviewer disabled (graceful degradation)

### Provider Examples

**Ollama (local)**
```yaml
llm_review:
  provider: openai
  model: llama3.2
  base_url: http://localhost:11434/v1
```

**LM Studio (local)**
```yaml
llm_review:
  provider: openai
  model: local-model
  base_url: http://localhost:1234/v1
```

**Together AI**
```yaml
llm_review:
  provider: openai
  model: meta-llama/Llama-3.1-8B-Instruct-Turbo
  api_key_env: TOGETHER_API_KEY
  base_url: https://api.together.xyz/v1
```

**Groq**
```yaml
llm_review:
  provider: openai
  model: llama-3.1-8b-instant
  api_key_env: GROQ_API_KEY
  base_url: https://api.groq.com/openai/v1
```

**Google Gemini**
```yaml
llm_review:
  provider: google
  model: gemini-2.0-flash
```

**Explicit Anthropic (same as default)**
```yaml
llm_review:
  provider: anthropic
  model: claude-3-5-haiku-latest
```

### How `base_url` and `api_key_env` Work

The `base_url` parameter redirects the OpenAI SDK to any OpenAI-compatible endpoint.
This covers Ollama, LM Studio, vLLM, Together, Groq, Mistral, DeepSeek, and dozens
of other providers that implement the OpenAI chat completions API.

The `api_key_env` parameter tells Tweek which environment variable to read for the
API key. This is useful when a provider uses a non-standard env var name (e.g.,
`TOGETHER_API_KEY`, `GROQ_API_KEY`).

For local endpoints that don't require authentication (like Ollama), the API key
defaults to a placeholder value -- no env var is needed.

---

## Plugin Configuration

**Source**: `tweek/config/manager.py` -> `ConfigManager.get_plugin_config()`

Plugins are configured under the `plugins` key, organized by category.

### Plugin Categories

| Category | Known Plugins |
|---|---|
| `compliance` | `gov`, `hipaa`, `pci`, `legal`, `soc2`, `gdpr` |
| `screening` | `rate_limiter`, `pattern_matcher`, `llm_reviewer`, `session_analyzer` |
| `providers` | `anthropic`, `openai`, `google`, `bedrock`, `azure_openai` |
| `detectors` | `moltbot`, `cursor`, `continue`, `copilot`, `windsurf` |

### Plugin Configuration Options

Plugins support `enabled`, `scope`, custom settings, allowlists, and action overrides:

```yaml
plugins:
  compliance:
    modules:
      hipaa:
        enabled: true
        scan_direction: both          # input, output, or both
        scope:                        # Scope to specific projects/dirs
          projects: ["healthcare-app"]
          directories: ["~/work/healthcare/"]
        suppressed_patterns:          # Disable specific patterns
          - prescription_info
        allowlist: ["Test Patient"]   # Exact strings to skip (false positives)
        allowlist_patterns:           # Regex patterns to skip
          - "test_mrn_\\d+"
        actions:                      # Override default actions per pattern
          medical_record_number: warn # Downgrade from block to warn
      pci:
        enabled: false                # Disable PCI scanning entirely
```

---

## Directory Activation

**Source**: `tweek/config/allowed_dirs.yaml`, `tweek/hooks/pre_tool_use.py` -> `check_allowed_directory()`

Tweek only activates in explicitly allowed directories. This is a safety feature to
prevent accidental activation in production environments.

### Configuration

```yaml
# tweek/config/allowed_dirs.yaml

# Set to true to enable Tweek globally (production mode)
global_enabled: false

# Directories where Tweek hooks will activate
# Tweek also activates in subdirectories of these paths
allowed_directories:
  - ~/AI/tweek/test-environment
  - ~/projects/sensitive-project
```

### Behavior

- **No config file**: Tweek is DISABLED everywhere (fail-closed default)
- **`global_enabled: true`**: Tweek activates in all directories
- **`allowed_directories` list**: Tweek activates only in listed directories and their subdirectories

The check uses `Path.relative_to()` to determine if the current working directory is
within an allowed path.

---

## Annotated Config Examples

### Minimal User Config

```yaml
# ~/.tweek/config.yaml
# Override only what differs from defaults

tools:
  Bash: risky          # Downgrade Bash from dangerous to risky (skip sandbox)
  WebFetch: default    # Downgrade WebFetch from risky to default (skip LLM)

default_tier: default  # Unknown tools get pattern matching
```

### Security-Focused Project Config

```yaml
# .tweek/config.yaml (in project root)
# Strict settings for a financial services project

tools:
  Bash: dangerous
  Write: risky         # LLM review for all file writes
  Edit: risky          # LLM review for all file edits
  WebFetch: dangerous  # Full pipeline for any web access

skills:
  deploy: dangerous
  commit: risky        # LLM review for git commits

default_tier: risky    # Unknown tools get LLM review

escalations:
  - pattern: 'customer.*data|user.*records'
    description: "Customer data access"
    escalate_to: dangerous

  - pattern: '(SELECT|INSERT|UPDATE).*users'
    description: "User table access"
    escalate_to: risky

plugins:
  compliance:
    modules:
      pci:
        enabled: true
        scan_direction: both
      soc2:
        enabled: true
        scan_direction: both
      gdpr:
        enabled: true
```

### Full Enterprise Config

The security-focused project config above can be extended at the user level
(`~/.tweek/config.yaml`) by adding enterprise compliance plugins, screening modules,
and additional escalation patterns for infrastructure operations (`docker push`,
`terraform apply|destroy`, etc.). See the [Plugin Configuration](#plugin-configuration)
section for complete compliance and screening plugin configuration syntax.

---

## Configuration Validation

**Source**: `tweek/config/manager.py` -> `ConfigManager.validate_config()`

Tweek validates configuration for errors and typos, providing suggestions:

### Checks Performed

| Check | Level | Example |
|---|---|---|
| Unknown top-level keys | error | `tols:` -> "Did you mean 'tools'?" |
| Unknown tool names | warning | `Bahs: risky` -> "Did you mean 'Bash'?" |
| Invalid tier values | error | `Bash: dagerous` -> "Did you mean 'dangerous'?" |
| Unknown skill names | warning | `comit: default` -> "Did you mean 'commit'?" |
| Invalid default_tier | error | `default_tier: unsfe` -> "Valid tiers: safe, default, risky, dangerous" |

### Typo Detection

Tweek uses `difflib.get_close_matches()` with a 0.6 cutoff to suggest corrections
for misspelled keys, tool names, and tier values.

### Valid Top-Level Keys

```python
VALID_TOP_LEVEL_KEYS = {
    "tools", "skills", "default_tier", "escalations",
    "plugins", "mcp", "proxy",
}
```

### Running Validation

```bash
tweek config validate
```

---

## Further Reading

- [PHILOSOPHY.md](PHILOSOPHY.md) - Threat model and design principles
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture and module map
- [DEFENSE_LAYERS.md](DEFENSE_LAYERS.md) - Detailed documentation of each screening layer
