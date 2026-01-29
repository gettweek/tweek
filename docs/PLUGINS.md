# Tweek Plugin System

Tweek uses a modular plugin architecture organized into four categories. Plugins can be built-in (bundled), installed from git repositories, or discovered via Python entry points.

---

## Architecture Overview

```
+------------------------------------------------------------------+
|                        Plugin Registry                            |
|  (tweek/plugins/__init__.py :: PluginRegistry)                    |
|                                                                   |
|  +-------------------+  +-------------------+  +----------------+ |
|  | Compliance        |  | LLM Providers     |  | Tool Detectors | |
|  | gov, hipaa, pci,  |  | anthropic, openai,|  | moltbot,cursor,| |
|  | legal, soc2, gdpr |  | azure, google,    |  | continue,      | |
|  |                   |  | bedrock           |  | copilot,       | |
|  | ENTERPRISE tier   |  | FREE tier         |  | windsurf       | |
|  +-------------------+  +-------------------+  | FREE tier      | |
|                                                 +----------------+ |
|  +-------------------+                                             |
|  | Screening         |  Plugin Sources:                            |
|  | rate_limiter,     |  1. Built-in (bundled)                      |
|  | pattern_matcher,  |  2. Git-installed (~/.tweek/plugins/)       |
|  | llm_reviewer,     |  3. Entry points (installed packages)       |
|  | session_analyzer  |                                             |
|  | FREE/PRO tier     |  Git plugins override builtins of the       |
|  +-------------------+  same name.                                 |
+------------------------------------------------------------------+
```

---

## Plugin Categories

| Category | Entry Point Group | Description | License Tier |
|----------|-------------------|-------------|-------------|
| Compliance | `tweek.compliance` | Domain-specific sensitive data detection | Enterprise |
| LLM Providers | `tweek.llm_providers` | API format parsing and tool call extraction | Free |
| Tool Detectors | `tweek.tool_detectors` | IDE and tool installation detection | Free |
| Screening | `tweek.screening` | Security screening methods for tool invocations | Free / Pro |

---

## Base Classes

**Source:** `tweek/plugins/base.py`

All plugins must inherit from one of the four base classes. Each base class defines the interface and common data structures for its category.

### `CompliancePlugin`

Scans content for domain-specific sensitive information. Supports bidirectional scanning (input and output) with configurable actions per pattern.

```python
class CompliancePlugin(ABC):
    VERSION = "1.0.0"
    REQUIRES_LICENSE = "enterprise"

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def scan_direction(self) -> ScanDirection: ...

    @abstractmethod
    def get_patterns(self) -> List[PatternDefinition]: ...

    def scan(self, content: str, direction: ScanDirection) -> ScanResult: ...
    def configure(self, config: Dict[str, Any]) -> None: ...
```

**Configuration options:**

| Key | Type | Description |
|-----|------|-------------|
| `enabled` | bool | Enable/disable the plugin |
| `scan_direction` | str | `"input"`, `"output"`, or `"both"` |
| `actions` | dict | Map pattern names to actions (allow/warn/block/redact/ask) |
| `allowlist` | list[str] | Exact strings to ignore (false positive suppression) |
| `allowlist_patterns` | list[str] | Regex patterns to ignore |
| `suppressed_patterns` | list[str] | Pattern names to disable |

**Data structures:**

| Class | Fields | Description |
|-------|--------|-------------|
| `PatternDefinition` | name, regex, severity, description, default_action, enabled, tags | Defines a regex pattern to match |
| `Finding` | pattern_name, matched_text, severity, line_number, context, recommended_action | A single match result |
| `ScanResult` | passed, findings, action, message, scan_direction, plugin_name | Aggregated scan result |

**Finding redaction:** The `Finding` class automatically redacts `matched_text` in its `to_dict()` output. Strings longer than 8 characters show the first 2 and last 2 characters with asterisks in between. Raw text is only available via `to_dict(include_raw=True)`.

**Action priority:** When multiple findings are present, the highest-priority action wins: `ALLOW < WARN < ASK < REDACT < BLOCK`.

### `LLMProviderPlugin`

Handles provider-specific API formats for endpoint detection and tool call extraction.

```python
class LLMProviderPlugin(ABC):
    VERSION = "1.0.0"
    REQUIRES_LICENSE = "free"

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def api_hosts(self) -> List[str]: ...

    def matches_endpoint(self, url: str) -> bool: ...

    @abstractmethod
    def extract_tool_calls(self, response: Dict) -> List[ToolCall]: ...

    def extract_content(self, response: Dict) -> str: ...
```

### `ToolDetectorPlugin`

Identifies installed AI coding tools, their configuration paths, and running state.

```python
class ToolDetectorPlugin(ABC):
    VERSION = "1.0.0"
    REQUIRES_LICENSE = "free"

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def detect(self) -> DetectionResult: ...

    def get_conflicts(self) -> List[str]: ...
```

**DetectionResult fields:** `detected`, `tool_name`, `version`, `install_path`, `config_path`, `running`, `port`, `metadata`.

### `ScreeningPlugin`

Analyzes tool invocations for security risks. Used in the screening pipeline for both MCP and HTTP proxy interception.

```python
class ScreeningPlugin(ABC):
    VERSION = "1.0.0"
    REQUIRES_LICENSE = "free"

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def screen(self, tool_name: str, content: str, context: Dict) -> ScreeningResult: ...
```

**ScreeningResult fields:** `allowed`, `plugin_name`, `reason`, `risk_level` (safe/suspicious/dangerous), `confidence`, `should_prompt`, `details`, `findings`.

---

## ReDoS Protection

**Source:** `tweek/plugins/base.py` (`ReDoSProtection` class)

All regex patterns used by compliance plugins pass through ReDoS (Regular Expression Denial of Service) protection:

| Protection Layer | Description |
|-----------------|-------------|
| Pattern validation | Rejects known dangerous patterns (nested quantifiers like `(.*)+`) |
| Length limits | Patterns max 1000 chars; input max 1MB |
| Timeout protection | SIGALRM-based timeout (default 5 seconds) on Unix; no timeout on Windows or non-main threads |
| Match limits | `safe_finditer` returns at most 1000 matches |

Built-in patterns set `validate_redos=False` since they are pre-vetted. External/git plugin patterns are validated by default.

---

## Built-in Compliance Plugins

All compliance plugins require an **Enterprise** license tier.

### Government (`gov`)

**Source:** `tweek/plugins/compliance/gov.py`

Detects US government classification markings and handling caveats.

| Pattern Group | Examples | Severity | Default Action |
|---------------|----------|----------|----------------|
| Top Secret | `TOP SECRET`, `TS/SCI`, `(TS)` | Critical | Block |
| Secret | `SECRET`, `(S)` | Critical | Block |
| Confidential | `CONFIDENTIAL`, `(C)` | High | Warn |
| Handling caveats | `NOFORN`, `ORCON`, `REL TO`, `FVEY`, `WNINTEL` | High-Critical | Warn/Block |
| CUI | `CUI`, `CUI//SPECIFIED`, `FOUO`, `LES` | Medium-High | Warn |
| Classification headers | Banner lines, header/footer lines | High | Warn |
| Special programs | `SAP`, `WAIVED SAP`, `UNACKNOWLEDGED SAP` | Critical | Block |
| NATO | `NATO SECRET`, `COSMIC TOP SECRET` | High | Warn |
| Declassification | `DECLASSIFY ON: 2025-01-15`, `CLASSIFIED BY:` | Medium | Warn |

Custom messaging distinguishes between **output** scanning (hallucinated markings) and **input** scanning (real classified content).

### HIPAA (`hipaa`)

**Source:** `tweek/plugins/compliance/hipaa.py`

Detects Protected Health Information (PHI) based on the 18 HIPAA identifiers: patient IDs, MRNs, medical record references, ICD-10 diagnosis codes, prescription data, healthcare facility identifiers, and insurance information.

### PCI-DSS (`pci`)

**Source:** `tweek/plugins/compliance/pci.py`

Detects payment card industry data including credit/debit card numbers (with Luhn algorithm validation), CVV/CVC codes, bank account and routing numbers, payment tokens, and cardholder data markers.

### Legal (`legal`)

**Source:** `tweek/plugins/compliance/legal.py`

Detects attorney-client privilege markers and confidentiality indicators.

### SOC 2 (`soc2`)

**Source:** `tweek/plugins/compliance/soc2.py`

Detects patterns relevant to SOC 2 security and compliance.

### GDPR (`gdpr`)

**Source:** `tweek/plugins/compliance/gdpr.py`

Detects EU personal data protection patterns covered under GDPR.

---

## Built-in Provider Plugins

| Plugin | Source | API Hosts |
|--------|--------|-----------|
| Anthropic | `tweek/plugins/providers/anthropic.py` | `api.anthropic.com` |
| OpenAI | `tweek/plugins/providers/openai.py` | `api.openai.com` |
| Azure OpenAI | `tweek/plugins/providers/azure_openai.py` | `*.openai.azure.com` |
| Google | `tweek/plugins/providers/google.py` | `generativelanguage.googleapis.com` |
| AWS Bedrock | `tweek/plugins/providers/bedrock.py` | `bedrock-runtime.*.amazonaws.com` |

---

## Built-in Detector Plugins

| Plugin | Source | Tool |
|--------|--------|------|
| moltbot | `tweek/plugins/detectors/moltbot.py` | Claude Code (moltbot) |
| cursor | `tweek/plugins/detectors/cursor.py` | Cursor IDE |
| continue | `tweek/plugins/detectors/continue_dev.py` | Continue.dev |
| copilot | `tweek/plugins/detectors/copilot.py` | GitHub Copilot |
| windsurf | `tweek/plugins/detectors/windsurf.py` | Windsurf |

---

## Built-in Screening Plugins

| Plugin | Source | License | Description |
|--------|--------|---------|-------------|
| `rate_limiter` | `tweek/plugins/screening/rate_limiter.py` | Pro | Rate-limit tool invocations |
| `pattern_matcher` | `tweek/plugins/screening/pattern_matcher.py` | Free | Regex-based attack pattern matching |
| `llm_reviewer` | `tweek/plugins/screening/llm_reviewer.py` | Pro | LLM-based semantic review |
| `session_analyzer` | `tweek/plugins/screening/session_analyzer.py` | Pro | Multi-turn session context analysis |

---

## Plugin Scoping

**Source:** `tweek/plugins/scope.py`

Plugins can be scoped to run only under specific conditions. A plugin without a scope runs globally (default). Scoping uses AND logic across fields and OR logic within a field.

### Scope Dimensions

| Dimension | Config Key | Description | Example |
|-----------|-----------|-------------|---------|
| Tools | `tools` | Only for these tool names | `[Bash, WebFetch, Write]` |
| Skills | `skills` | Only for these skill names | `[email-search, patient-records]` |
| Projects | `projects` | Only under these directories | `["/Users/me/healthcare-app"]` |
| Tiers | `tiers` | Only at these security tiers | `[risky, dangerous]` |
| Directions | `directions` | Only for these scan directions | `[input, output]` |

### Configuration Example

```yaml
plugins:
  compliance:
    hipaa:
      enabled: true
      scope:
        tools: [Bash, WebFetch, Write]
        skills: [patient-records]
        projects: ["/Users/me/healthcare-app"]
        tiers: [risky, dangerous]
```

### CLI Configuration

```bash
tweek plugins set hipaa --scope-tools Bash,Edit -c compliance
tweek plugins set hipaa --scope-skills patient-records -c compliance
tweek plugins set hipaa --scope-tiers risky,dangerous -c compliance
tweek plugins set hipaa --scope-clear -c compliance
```

### Scope Matching Logic

The `PluginScope.matches(context)` method:

1. If `tools` is set and `context.tool_name` is not in the list, return `False`
2. If `skills` is set and `context.skill_name` is not in the list (and skill_name is known), return `False`
3. If `projects` is set and `context.working_dir` does not start with any project path, return `False`
4. If `tiers` is set and `context.tier` is not in the list, return `False`
5. Otherwise, return `True`

---

## Git Plugin Installation

### Discovery Flow

**Source:** `tweek/plugins/git_discovery.py`

```
~/.tweek/plugins/
  +-- tweek-plugin-foo/
  |     +-- tweek_plugin.json      # Manifest (required)
  |     +-- CHECKSUMS.sha256       # Signed checksums
  |     +-- plugin.py              # Plugin code
  |
  +-- tweek-plugin-bar/
        +-- tweek_plugin.json
        +-- plugin.py
```

Discovery steps:

1. Scan `~/.tweek/plugins/*/tweek_plugin.json` for manifests
2. Validate manifest fields and format
3. Check version compatibility (`min_tweek_version`, `max_tweek_version`)
4. Run the 5-layer security pipeline
5. Dynamically import using `importlib` with isolated module namespace `tweek_git_plugins.{name}.{module}`
6. Verify base class inheritance
7. Register in the plugin registry (overriding builtins with the same short name)

### Manifest Format (`tweek_plugin.json`)

```json
{
  "name": "tweek-plugin-cursor-detector",
  "version": "1.2.0",
  "category": "detectors",
  "entry_point": "plugin:CursorDetector",
  "description": "Enhanced Cursor IDE detection",
  "author": "Tweek",
  "requires_license_tier": "free",
  "min_tweek_version": "0.2.0",
  "max_tweek_version": null,
  "tags": ["detector", "cursor"],
  "checksum_signature": "<hmac hex digest>"
}
```

**Required fields:** `name`, `version`, `category`, `entry_point`, `description`

**Valid categories:** `compliance`, `providers`, `detectors`, `screening`

**Valid license tiers:** `free`, `pro`, `enterprise`

**Entry point format:** `module:ClassName` (e.g., `plugin:CursorDetector` imports `CursorDetector` from `plugin.py`)

### Plugin Installer

**Source:** `tweek/plugins/git_installer.py`

The `GitPluginInstaller` class manages the lifecycle of git-installed plugins.

| Operation | Method | Description |
|-----------|--------|-------------|
| Install | `install(name, version, verify)` | Clone from registry, checkout version tag, verify |
| Update | `update(name, version, verify)` | Fetch, checkout new tag, verify (reverts on failure) |
| Remove | `remove(name)` | Delete plugin directory |
| Check updates | `check_updates()` | Compare installed versions against registry |
| List installed | `list_installed()` | List all git plugins with metadata |
| Verify | `verify_plugin(name)` | Run security pipeline on installed plugin |
| Verify all | `verify_all()` | Verify all installed plugins |

Git operations use `subprocess.run` with:
- `capture_output=True` (no terminal access)
- `timeout=30` (prevent hangs)
- No `shell=True` (no injection risk)
- `--depth 1` for shallow clones

---

## Security Verification Pipeline

**Source:** `tweek/plugins/git_security.py`

A 5-layer pipeline validates git plugins before any code is imported:

### Layer 1: Registry Listing

The plugin must exist in the curated Tweek registry with `verified: true`. Unverified plugins are refused.

### Layer 2: Signature Verification

The `CHECKSUMS.sha256` file is signed with an HMAC (SHA-256) using Tweek's signing key. The signature is stored in the manifest as `checksum_signature`. This prevents tampering between the registry and the user's machine.

Signing key: `TWEEK_PLUGIN_SIGNING_KEY` environment variable, or default key.

### Layer 3: Checksum Verification

Every `.py` file in the plugin directory is SHA-256 hashed and compared against `CHECKSUMS.sha256`. Unexpected Python files not listed in checksums are flagged.

### Layer 4: AST Static Analysis

All Python files are parsed into ASTs and scanned for forbidden patterns:

**Forbidden imports:**

| Category | Modules |
|----------|---------|
| Process execution | `subprocess`, `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `ctypes`, `multiprocessing` |
| Network access | `socket`, `urllib`, `http.client`, `http.server`, `requests`, `httpx`, `aiohttp`, `websockets`, `paramiko`, `ftplib`, `smtplib`, `telnetlib` |

**Forbidden function calls:** `eval`, `exec`, `compile`, `__import__`, `os.system`, `os.popen`, `os.remove`, `os.unlink`, `os.rmdir`, `os.removedirs`, `shutil.rmtree`, `shutil.move`

### Layer 5: Base Class Enforcement

After import, the plugin class must inherit from the correct base class for its declared category:

| Category | Required Base Class |
|----------|-------------------|
| `compliance` | `CompliancePlugin` |
| `providers` | `LLMProviderPlugin` |
| `detectors` | `ToolDetectorPlugin` |
| `screening` | `ScreeningPlugin` |

---

## Plugin Registry

**Source:** `tweek/plugins/git_registry.py`

The `PluginRegistryClient` fetches and caches the curated plugin registry from `https://registry.gettweek.com/v1/plugins.json`.

| Feature | Detail |
|---------|--------|
| Cache location | `~/.tweek/registry.json` |
| Cache metadata | `~/.tweek/registry_meta.json` |
| Cache TTL | 1 hour (default) |
| Offline fallback | Uses cached registry when network is unavailable |
| Signature verification | HMAC of the `plugins` array against Tweek's signing key |
| Schema version | Supports schema version `1` |

### Registry Entry Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Plugin name (e.g., `tweek-plugin-cursor-detector`) |
| `category` | string | `compliance`, `providers`, `detectors`, `screening` |
| `repo_url` | string | Git repository URL |
| `latest_version` | string | Latest stable version |
| `requires_license_tier` | string | `free`, `pro`, `enterprise` |
| `verified` | bool | Whether the plugin is approved |
| `deprecated` | bool | Whether the plugin is deprecated |
| `versions` | object | Map of version to `{git_ref, checksums}` |

### CLI Commands

```bash
tweek plugins search hipaa                 # Search by keyword
tweek plugins search -c compliance         # Filter by category
tweek plugins search -t enterprise         # Filter by license tier

tweek plugins install hipaa-scanner        # Install latest version
tweek plugins install hipaa-scanner -v 1.2.0  # Install specific version

tweek plugins update hipaa-scanner         # Update to latest
tweek plugins update --all                 # Update all plugins
tweek plugins update --check               # Check for updates without installing

tweek plugins remove hipaa-scanner         # Remove a plugin
tweek plugins verify hipaa-scanner         # Verify integrity
tweek plugins verify --all                 # Verify all plugins

tweek plugins registry                     # Show registry info
tweek plugins registry --refresh           # Force cache refresh
tweek plugins registry --info              # Detailed registry metadata
```

---

## Plugin Loading Order

The `init_plugins()` function loads plugins in a specific order:

1. **Built-in plugins** -- Registered from bundled subpackages (`compliance`, `providers`, `detectors`, `screening`)
2. **Git-installed plugins** -- Discovered from `~/.tweek/plugins/`, override builtins with the same short name
3. **Entry point plugins** -- Discovered via Python `importlib.metadata.entry_points()` (compatible with Python 3.9+)

Git plugins use a name derivation algorithm to match builtins:

| Full Name | Derived Short Name |
|-----------|--------------------|
| `tweek-plugin-cursor-detector` | `cursor` |
| `tweek-plugin-hipaa` | `hipaa` |
| `tweek-plugin-openai-provider` | `openai` |

Common prefixes (`tweek-plugin-`, `tweek-`) and suffixes (`-detector`, `-provider`, `-plugin`, `-compliance`, `-screening`) are stripped.

---

## License Tier Enforcement

Plugins declare their required license tier via the `REQUIRES_LICENSE` class attribute or `requires_license_tier` manifest field.

| Tier | Hierarchy | Includes |
|------|-----------|----------|
| Free | 0 | Free only |
| Pro | 1 | Free + Pro |
| Enterprise | 2 | Free + Pro + Enterprise |

Higher tiers include all lower tier features. If no license checker is configured, only Free tier plugins are accessible. The license checker is set during `init_plugins()` using the `tweek.licensing` module.

---

## Utility Functions

### `combine_scan_results(results: List[ScanResult]) -> ScanResult`

Merge findings from multiple compliance plugins into a single result. The combined action is the highest-priority action across all results.

### `combine_screening_results(results: List[ScreeningResult]) -> ScreeningResult`

Merge screening decisions. If **any** result blocks, the combined result blocks. Risk levels are aggregated to the highest level (safe < suspicious < dangerous).

---

## Cross-References

- [CLI_REFERENCE.md](CLI_REFERENCE.md) -- Full CLI reference for `tweek plugins` commands
- [MCP_INTEGRATION.md](MCP_INTEGRATION.md) -- Screening pipeline using plugins
- [HTTP_PROXY.md](HTTP_PROXY.md) -- Provider plugins used in HTTP proxy interception
