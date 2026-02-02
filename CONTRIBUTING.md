# Contributing to Tweek

Thank you for your interest in contributing to Tweek! Every contribution helps make AI coding assistants safer for everyone.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Reporting Security Vulnerabilities](#reporting-security-vulnerabilities)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Code Style](#code-style)
- [Testing](#testing)
- [Writing Plugins](#writing-plugins)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Community](#community)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to:

- Use welcoming and inclusive language
- Respect differing viewpoints and experiences
- Accept constructive criticism gracefully
- Focus on what is best for the community and the security of end users

---

## Reporting Security Vulnerabilities

**Do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in Tweek, please report it responsibly:

1. Email **support@gettweek.com** with the subject line `[SECURITY]`
2. Include a description of the vulnerability and steps to reproduce
3. We will acknowledge receipt within 48 hours
4. We will work with you on a fix and coordinate disclosure

We follow responsible disclosure practices and will credit reporters (unless anonymity is requested).

---

## Getting Started

### Prerequisites

- **uv** (recommended) or **pipx** or **Python 3.9+ with pip**
- **Git**
- **pipx** (recommended) or pip

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/tweek.git
cd tweek
```

---

## Development Setup

### 1. Create a Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows
```

### 2. Install in Development Mode

```bash
# Core + all optional dependencies + dev tools
pip install -e ".[all,dev]"
```

This installs:
- **Core:** click, pyyaml, rich, keyring
- **LLM review:** anthropic SDK
- **MCP proxy:** mcp SDK
- **HTTP proxy:** mitmproxy
- **Dev tools:** pytest, pytest-cov, black, ruff, twine, build

### 3. Verify the Installation

```bash
tweek --version
pytest
```

---

## Making Changes

### Branch Naming

Create a descriptive branch from `main`:

```bash
git checkout -b fix/sandbox-exec-path       # Bug fixes
git checkout -b feature/new-pattern-category # New features
git checkout -b docs/improve-plugin-guide    # Documentation
```

### Commit Messages

Write clear, descriptive commit messages. We follow conventional style:

```
fix: handle edge case in Unicode obfuscation detection
feature: add DMARC pattern to credential theft category
docs: clarify MCP proxy setup for ChatGPT Desktop
test: add coverage for rate limiter circuit breaker
```

- Use the imperative mood ("add" not "added")
- Keep the first line under 72 characters
- Reference issue numbers where applicable: `fix: resolve sandbox timeout (#42)`

### What to Work On

- Browse [open issues](https://github.com/gettweek/tweek/issues) labeled `good first issue` or `help wanted`
- Check the [roadmap](https://github.com/gettweek/tweek/issues?q=label%3Aroadmap) for planned features
- Propose new attack patterns (see [Writing Plugins](#writing-plugins))

---

## Code Style

We use **Black** for formatting and **Ruff** for linting.

```bash
# Format code
black .

# Lint code
ruff check .

# Lint and auto-fix
ruff check --fix .
```

### Style Rules

- **Line length:** 100 characters
- **Target:** Python 3.9+
- **Imports:** Sorted by ruff (isort-compatible)
- **Type hints:** Encouraged for public APIs, not required for internals
- **Docstrings:** Required for public classes and functions. Use Google-style:

```python
def screen_command(command: str, context: ScreeningContext) -> ScreeningResult:
    """Screen a command through all active defense layers.

    Args:
        command: The raw command string to screen.
        context: Current session context including history and anomaly state.

    Returns:
        ScreeningResult with verdict (allow/block/review) and matched patterns.
    """
```

### Pre-commit Check

Before committing, run:

```bash
black . && ruff check . && pytest
```

---

## Testing

All contributions must include tests. We use **pytest** with coverage reporting.

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=tweek --cov-report=term-missing

# Run a specific test file
pytest tests/test_patterns.py

# Run a specific test
pytest tests/test_patterns.py::test_credential_theft_detection -v
```

### Test Organization

Tests live in the `tests/` directory and mirror the source structure:

```
tests/
├── test_cli.py                  # CLI command tests
├── test_patterns.py             # Pattern matching tests
├── test_rate_limiter.py         # Rate limiting tests
├── test_session_analyzer.py     # Session analysis tests
├── test_hooks/                  # Hook integration tests
├── test_sandbox/                # Sandbox preview tests
├── test_vault/                  # Credential vault tests
└── test_plugins/                # Plugin system tests
```

### Writing Tests

- Every new pattern must have at least one test proving it catches the attack
- Every new pattern must have at least one test proving it does NOT false-positive on benign input
- Test both the happy path and edge cases
- Use descriptive test names:

```python
def test_detects_base64_encoded_reverse_shell():
    ...

def test_allows_legitimate_base64_encoding():
    ...
```

### Coverage

We aim for high coverage on security-critical paths. Run `pytest --cov=tweek` to check. Focus coverage on:

- `tweek/screening/` — all screening layers
- `tweek/security/` — pattern matching engine
- `tweek/hooks/` — hook dispatch
- `tweek/sandbox/` — sandbox execution

---

## Writing Plugins

Tweek's plugin architecture supports four extension categories. This is one of the most impactful ways to contribute.

### Plugin Categories

| Category | Entry Point | Example |
|----------|-------------|---------|
| **Compliance** | `tweek.compliance` | HIPAA, PCI, GDPR scanners |
| **Screening** | `tweek.screening` | Custom screening layers |
| **LLM Providers** | `tweek.llm_providers` | New LLM backends |
| **Tool Detectors** | `tweek.tool_detectors` | New AI tool integrations |

### Adding Attack Patterns

The highest-impact contribution is new attack patterns. To add a pattern:

1. Identify the attack vector and category (prompt injection, credential theft, network exfiltration, etc.)
2. Write the regex pattern
3. Add test cases — both true positives and true negatives
4. Add the pattern to the appropriate YAML config in `tweek/config/`
5. Submit a PR with a description of the real-world attack scenario

```yaml
# Example pattern entry
- name: "aws_credential_exfil_via_dns"
  pattern: "dig\\s+.*\\$\\{?AWS"
  severity: "critical"
  category: "credential_theft"
  description: "Detects AWS credential exfiltration via DNS query"
```

### Adding Tool Integrations

To add support for a new AI coding tool:

1. Create a detector in `tweek/plugins/detectors/`
2. Implement the detection interface (process discovery, config location)
3. Add installation/setup logic
4. Write tests
5. Document the integration method (CLI hooks, MCP proxy, or HTTP proxy)

---

## Pull Request Process

### Before Submitting

- [ ] Your code passes `black . && ruff check . && pytest`
- [ ] You've added tests for new functionality
- [ ] You've updated documentation if needed
- [ ] You've written a clear PR description

### PR Description Template

```markdown
## What

Brief description of the change.

## Why

What problem does this solve? Link to issue if applicable.

## How

How does the implementation work? Any design decisions worth noting.

## Testing

How was this tested? What test cases were added?
```

### Review Process

1. **Submit your PR** against the `main` branch
2. **Automated checks** run (tests, linting, formatting)
3. **Maintainer review** — we aim to review PRs within a few days
4. **Address feedback** — push additional commits to the same branch
5. **Merge** — once approved, a maintainer will merge via squash-and-merge

### What We Look For

- **Correctness** — Does the code do what it claims?
- **Security** — Does it introduce any vulnerabilities? (We take this seriously given our mission.)
- **Tests** — Are edge cases covered? Are there false-positive tests for patterns?
- **Simplicity** — Is the solution as simple as it can be?
- **Consistency** — Does it follow existing patterns in the codebase?

---

## Reporting Bugs

Open a [GitHub issue](https://github.com/gettweek/tweek/issues/new) with:

- **Tweek version:** `tweek --version`
- **OS and version:** macOS / Linux / Windows
- **Python version:** `python --version`
- **Steps to reproduce** the bug
- **Expected behavior** vs. **actual behavior**
- **Relevant logs** from `~/.tweek/logs/`

### False Positive Reports

If Tweek blocks a legitimate command, please report it! Include:

- The exact command that was blocked
- The pattern or layer that triggered the block
- Why the command is legitimate in your context

False positive reduction is critical to usability.

---

## Suggesting Features

Open a [GitHub issue](https://github.com/gettweek/tweek/issues/new) with:

- **Problem statement** — What gap or pain point does this address?
- **Proposed solution** — How should it work?
- **Alternatives considered** — What other approaches could work?
- **Impact** — Who benefits and how?

For large features, expect discussion before implementation begins.

---

## Community

- **Website:** [gettweek.com](https://gettweek.com)
- **GitHub Issues:** [github.com/gettweek/tweek/issues](https://github.com/gettweek/tweek/issues)
- **Email:** [support@gettweek.com](mailto:support@gettweek.com)

---

## License

By contributing to Tweek, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
