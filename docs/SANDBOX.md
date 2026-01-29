# Tweek Sandbox Documentation

Cross-platform command sandboxing for speculative execution and skill isolation.

---

## Overview

The Tweek sandbox layer provides isolated execution environments to preview
what commands will do before allowing them to run with full permissions. This is
the fifth and deepest layer in Tweek's defense-in-depth model, activated when a
tool or skill is classified as **dangerous**.

| Platform | Backend               | Status      |
|----------|-----------------------|-------------|
| macOS    | `sandbox-exec` (built-in) | Fully supported |
| Linux    | `firejail` (recommended) or `bubblewrap` | Supported (optional install) |
| Windows  | N/A                   | Not available |

---

## Architecture

```
tweek/sandbox/
  __init__.py            # Platform detection, conditional imports, get_sandbox_status()
  profile_generator.py   # macOS .sb profile generation from skill manifests
  executor.py            # SandboxExecutor: preview and sandboxed execution
  linux.py               # LinuxSandbox: firejail/bubblewrap wrapper
```

The sandbox module is conditionally loaded based on the detected platform
(`tweek.platform.IS_MACOS`, `tweek.platform.IS_LINUX`). On macOS the full
`ProfileGenerator` and `SandboxExecutor` are available. On Linux the
`LinuxSandbox` class is loaded instead. The module-level constants
`SANDBOX_AVAILABLE` and `SANDBOX_TOOL` reflect the runtime state.

---

## macOS: sandbox-exec Profiles

macOS ships with `sandbox-exec`, a kernel-level sandbox that enforces Scheme-like
policy profiles (`.sb` files). Tweek generates these profiles automatically from
skill manifests.

### ProfileGenerator

**Location:** `tweek/sandbox/profile_generator.py`

```python
from tweek.sandbox import ProfileGenerator, SkillManifest

generator = ProfileGenerator()
manifest  = SkillManifest.default("my-skill")
profile   = generator.generate(manifest)
path      = generator.save(manifest)
command   = generator.wrap_command("python3 script.py", "my-skill")
```

**Profiles directory:** `~/.tweek/profiles/`

#### Generated Profile Structure

Every profile starts with a **deny-all** policy and then selectively allows
operations:

```scheme
(version 1)
(deny default)

;; System paths (always allowed)
(allow file-read* (subpath "/usr/lib"))
...

;; Allowed read paths (from manifest)
;; Allowed write paths (from manifest)

;; SECURITY: Always-denied paths
(deny file-read* (subpath "/Users/you/.ssh"))
(deny file-write* (subpath "/Users/you/.ssh"))
...

;; Network access
(deny network*)

;; Process execution
;; No subprocess execution allowed
```

#### Always-Allowed Read Paths

These system paths are always readable regardless of manifest:

| Path                  | Reason                          |
|-----------------------|---------------------------------|
| `/usr/lib`            | Shared libraries                |
| `/usr/local/lib`      | Homebrew/user libraries         |
| `/System/Library`     | System frameworks               |
| `/Library/Frameworks` | Third-party frameworks          |
| `/private/var/db`     | System databases                |
| `/dev/null`           | Null device                     |
| `/dev/random`         | Random number generator         |
| `/dev/urandom`        | Non-blocking random             |

#### Always-Denied Paths

These paths are **always denied** regardless of what the manifest requests:

| Path                                | Contains                   |
|-------------------------------------|----------------------------|
| `~/.ssh`                            | SSH private keys           |
| `~/.gnupg`                          | GPG keys                   |
| `~/.aws/credentials`                | AWS access keys            |
| `~/.config/gcloud/credentials.db`   | Google Cloud credentials   |
| `~/.netrc`                          | Plaintext passwords        |

#### ProfileGenerator API

| Method                | Description                                         |
|-----------------------|-----------------------------------------------------|
| `generate(manifest)`  | Returns `.sb` profile content as a string            |
| `save(manifest)`      | Generates and writes profile to `~/.tweek/profiles/` |
| `get_profile_path(skill_name)` | Returns path to existing profile or `None`  |
| `wrap_command(command, skill_name)` | Wraps a command with `sandbox-exec -f`   |
| `list_profiles()`     | Lists all generated profile names                    |
| `delete_profile(skill_name)` | Deletes a profile                              |

### SkillManifest

The `SkillManifest` dataclass declares what a skill needs access to:

```python
@dataclass
class SkillManifest:
    name: str
    version: str = "1.0"

    # Filesystem permissions
    read_paths: List[str]
    write_paths: List[str]
    deny_paths: List[str]

    # Network permissions
    network_allow: List[str]   # Specific hostnames
    network_deny_all: bool     # Default: True

    # Process permissions
    allow_subprocess: bool     # Default: False
    allow_exec: List[str]      # Specific executables

    # Credentials this skill needs
    credentials: List[str]
```

Manifests can be loaded from YAML files or created programmatically:

```python
# From YAML
manifest = SkillManifest.from_yaml(Path("skill-manifest.yaml"))

# Restrictive default
manifest = SkillManifest.default("my-skill")
```

The default manifest denies: `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube`,
`~/.netrc`, `~/.env`, `**/.env`, `~/.bash_history`, `~/.zsh_history`.

#### Manifest YAML Format

```yaml
name: my-skill
version: "1.0"
permissions:
  filesystem:
    read: ["./", "/usr/lib"]
    write: ["./", "/private/tmp"]
    deny: ["~/.ssh", "~/.aws"]
  network:
    allow: ["api.github.com"]
    deny_all: true
  process:
    subprocess: false
    exec: ["/usr/bin/git"]
credentials:
  - GITHUB_TOKEN
```

---

## Linux: Firejail and Bubblewrap

**Location:** `tweek/sandbox/linux.py`

On Linux, Tweek uses [firejail](https://firejail.wordpress.com/) as the primary
sandbox. If firejail is not available, it falls back to
[bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`), which is
commonly installed alongside Flatpak.

### LinuxSandbox

```python
from tweek.sandbox.linux import LinuxSandbox

sandbox = LinuxSandbox()
print(sandbox.available)  # True if firejail or bwrap found
print(sandbox.tool)       # "firejail" or "bubblewrap" or None
```

### Firejail Restrictions

When using firejail, the following hardening flags are applied:

| Flag                | Effect                              |
|---------------------|-------------------------------------|
| `--noprofile`       | No app-specific profile             |
| `--quiet`           | Reduce output noise                 |
| `--caps.drop=all`   | Drop all Linux capabilities         |
| `--noroot`          | No root privileges                  |
| `--seccomp`         | Enable seccomp-bpf syscall filter   |
| `--private-tmp`     | Isolated `/tmp`                     |
| `--nogroups`        | No supplementary groups             |
| `--net=none`        | Network disabled (unless allowed)   |
| `--read-only=/`     | Read-only root (unless writes allowed) |
| `--timeout=N`       | Execution timeout                   |

### Bubblewrap Restrictions

| Flag               | Effect                               |
|--------------------|--------------------------------------|
| `--ro-bind / /`    | Read-only root                       |
| `--dev /dev`       | Minimal device access                |
| `--proc /proc`     | Process filesystem                   |
| `--tmpfs /tmp`     | Isolated temporary directory         |
| `--unshare-all`    | Unshare all Linux namespaces         |
| `--die-with-parent`| Clean up on parent exit              |
| `--new-session`    | New session                          |
| `--unshare-net`    | Network isolation (unless allowed)   |

### SandboxResult

Both firejail and bubblewrap executions return a `SandboxResult`:

```python
@dataclass
class SandboxResult:
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    blocked_actions: list[str]  # e.g. ["network_blocked", "write_blocked"]
```

### Installation Prompt

On Linux, Tweek can prompt the user to install firejail:

```python
from tweek.sandbox.linux import prompt_install_firejail
prompt_install_firejail(console)
```

This auto-detects the package manager and offers to install firejail. Without it,
Tweek still provides 4/5 defense layers.

---

## Speculative Execution and Preview Mode

**Location:** `tweek/sandbox/executor.py`

The `SandboxExecutor` runs commands in a highly restricted sandbox to observe
what they *try* to do without allowing dangerous side effects.

### SandboxExecutor API

```python
from tweek.sandbox import SandboxExecutor

executor = SandboxExecutor()

# Preview: highly restricted, short timeout, analyze behavior
result = executor.preview_command("curl http://evil.com", skill="my-skill")
if result.suspicious:
    print("Blocked:", result.violations)

# Full execution: skill-specific permissions, longer timeout
result = executor.execute_sandboxed("python3 build.py", skill="build-tool")

# Inspect: get the wrapped command without executing
cmd = executor.get_sandbox_command("python3 script.py", "my-skill")
```

### ExecutionResult

```python
@dataclass
class ExecutionResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False

    # Security analysis
    suspicious: bool = False
    violations: List[str] = []

    # Captured access attempts
    file_reads: List[str] = []
    file_writes: List[str] = []
    network_attempts: List[str] = []
    process_spawns: List[str] = []

    # Denied operations (blocked by sandbox)
    denied_operations: List[str] = []
```

### preview_command vs. execute_sandboxed

| Aspect            | `preview_command`                  | `execute_sandboxed`                |
|-------------------|------------------------------------|------------------------------------|
| Purpose           | Observe behavior before allowing   | Run with appropriate permissions   |
| Default timeout   | 5 seconds                          | 30 seconds                         |
| Profile           | Temporary restrictive profile      | Skill-specific manifest profile    |
| Network           | Denied                             | Per manifest                       |
| Cleanup           | Profile deleted after execution    | Profile persisted                  |
| Use case          | "What would this command do?"      | "Run this in the skill's sandbox"  |

---

## Violation Detection

The `SandboxExecutor` analyzes commands and execution output against three
categories of suspicious behavior:

### 1. Sensitive Path Access

Commands that reference these paths are flagged:

| Pattern            | Example Target                    |
|--------------------|-----------------------------------|
| `\.ssh`            | SSH keys                          |
| `\.aws`            | AWS credentials                   |
| `\.gnupg`          | GPG keys                          |
| `\.netrc`          | Plaintext passwords               |
| `\.env`            | Environment secrets               |
| `credentials`      | Generic credential files          |
| `\.kube/config`    | Kubernetes config                 |
| `\.config/gcloud`  | Google Cloud credentials          |
| `keychain`         | macOS Keychain                    |
| `Cookies`          | Browser cookies                   |
| `Login Data`       | Browser saved passwords           |

### 2. Suspicious Network Hosts

Connections to known paste/exfiltration services:

| Host Pattern       | Service                           |
|--------------------|-----------------------------------|
| `pastebin.com`     | Public paste site                 |
| `hastebin.com`     | Public paste site                 |
| `ghostbin.*`       | Public paste site                 |
| `0x0.st`           | File hosting service              |
| `transfer.sh`      | File transfer service             |
| `file.io`          | Ephemeral file sharing            |
| `webhook.site`     | Webhook testing/capture           |
| `requestbin.*`     | HTTP request capture              |
| `ngrok.io`         | Tunnel service                    |

### 3. Data Exfiltration Patterns

Commands matching these patterns are flagged:

| Pattern                        | Description                              |
|--------------------------------|------------------------------------------|
| `curl.*-d.*\$\(`              | Curl POST with command substitution       |
| `wget.*--post-data`           | Wget sending POST data                    |
| `\| *nc `                     | Piping data to netcat                     |
| `\| *curl`                    | Piping data to curl                       |
| `base64.*\|.*curl`            | Base64 encoding then sending              |

### 4. Sandbox Denial Parsing

The executor parses stderr output from the sandbox for blocked operations:

- `Permission denied` -> `permission_denied`
- `Network is disabled` / `No network` -> `network_blocked`
- `Read-only file system` -> `write_blocked`
- `Operation not permitted` -> `operation_blocked`

---

## Security Event Logging

Both `preview_command` and `execute_sandboxed` log events to the security logger:

- `SANDBOX_PREVIEW` events are logged at the start and (if suspicious) at block time
- `ERROR` events are logged for unexpected failures
- Events include the command, skill name, timeout, and any violations

See [LOGGING.md](./LOGGING.md) for details on the security event system.

---

## Checking Sandbox Status

```python
from tweek.sandbox import get_sandbox_status

status = get_sandbox_status()
# {'available': True, 'tool': 'sandbox-exec', 'platform': 'macos'}
```

The `tweek doctor` command includes a sandbox availability check. See
[TROUBLESHOOTING.md](./TROUBLESHOOTING.md) for details.

---

## Cross-References

- [ATTACK_PATTERNS.md](./ATTACK_PATTERNS.md) -- Patterns that trigger sandbox preview
- [LOGGING.md](./LOGGING.md) -- How sandbox events are logged
- [TROUBLESHOOTING.md](./TROUBLESHOOTING.md) -- Diagnosing sandbox issues
- [LICENSING.md](./LICENSING.md) -- Sandbox is available on all tiers
