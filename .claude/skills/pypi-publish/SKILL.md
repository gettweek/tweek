---
name: pypi-publish
description: Build and publish Tweek to PyPI with automated version bumping. Use when user asks to publish, release, bump version, deploy to PyPI, push a new release, or update the package on PyPI.
user-invocable: true
---

# PyPI Publish

## Purpose

Automate the release cycle: version bump, test, build, commit, tag, push to GitHub, and optionally publish to PyPI.

**Use when user asks to:**
- "Publish to PyPI"
- "Release a new version"
- "Bump version and publish"
- "Push a release"
- "Deploy package to PyPI"

---

## CRITICAL: PyPI Publishing Requires Explicit User Instruction

**Do NOT publish to PyPI unless the user explicitly asks you to.** The default workflow is:

1. Bump version, run tests, build, commit, tag, and push to GitHub.
2. **Stop and report.** Tell the user the build is ready and ask if they want to publish to PyPI.
3. Only run the PyPI upload (Step 5) if the user confirms.

Committing and pushing to GitHub is always safe. Publishing to PyPI is a one-way action (you cannot overwrite a published version), so it must always be a deliberate user decision.

---

## Workflow

Follow these steps in order. Stop and report if any step fails.

### Step 1: Determine Version Bump

**Default behavior: always bump patch (point release).** Minor and major bumps only happen when the user explicitly requests them.

**1a.** Run the version helper script to see the current version:

```bash
python3 .claude/skills/pypi-publish/scripts/bump_version.py --type patch
```

This returns JSON with `current` and `next` versions.

**1b.** If the user explicitly specified a bump type (e.g., "release a minor version", "major release"), use that type instead. Otherwise, **always use patch**.

**1c.** Do NOT ask the user to choose between patch/minor/major. Just proceed with patch. The user will tell you if they want something different.

### Step 2: Update Version

Edit **both** files to the new version:

1. `pyproject.toml` — the `version = "x.y.z"` line
2. `tweek/__init__.py` — the `__version__ = "x.y.z"` line

### Step 3: Run Tests

```bash
python3 -m pytest tests/ -x -q
```

If tests fail, stop and report. Do not publish a broken release.

### Step 4: Build

```bash
rm -rf dist/ build/
python3 -m build
```

Verify two files appear in `dist/` (`.whl` and `.tar.gz`).

### Step 5: Git Commit, Tag, and Push

Stage the version files and any other pending changes:

```bash
git add pyproject.toml tweek/__init__.py
```

Commit with the release message format:

```
Release v{version}: {brief description of what changed}
```

Tag the release:

```bash
git tag v{version}
```

Push both the commit and the tag:

```bash
git push origin main && git push origin v{version}
```

### Step 6: Report and Ask About PyPI

**STOP here and report to the user:**
- The new version number
- That the commit and tag have been pushed to GitHub
- The build artifacts are ready in `dist/`
- Ask: **"Ready to publish v{version} to PyPI?"**

**Do NOT proceed to Step 7 unless the user explicitly confirms.**

### Step 7: Publish to PyPI (only when user confirms)

Read the PyPI token from the `.env` file:

```bash
grep PYPI_API_TOKEN .env
```

Then upload:

```bash
TWINE_USERNAME=__token__ TWINE_PASSWORD=<token_value> python3 -m twine upload dist/*
```

**IMPORTANT:** Never print or echo the token. Pass it only via environment variable.

After publishing, tell the user:
- The PyPI URL: `https://pypi.org/project/tweek/{version}/`
- That users can update with `tweek upgrade` or `uv tool upgrade tweek`

---

## Important: Testing Installation

**NEVER use `pip install -e .` to test tweek locally.** The installed binary lives at `~/.local/bin/tweek` and is managed by `uv` (or `pipx`). An editable pip install creates a conflicting package that doesn't update the actual binary.

To test a new release against the installed binary:
1. Publish to PyPI (this skill)
2. Reinstall via: `curl -sSL https://raw.githubusercontent.com/gettweek/tweek/main/scripts/install.sh | bash`
3. Verify with: `tweek --version`

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `twine` not installed | `pip install twine build` |
| Token rejected | Check `.env` has valid `PYPI_API_TOKEN` |
| Version already exists on PyPI | You cannot overwrite — bump again |
| Tests fail | Fix tests before publishing |
| Build fails | Check `pyproject.toml` for syntax errors |
| Installed binary is stale | Do NOT use `pip install -e .` — publish to PyPI and reinstall via curl |

---

## Environment

- **PyPI token location:** `.env` file (`PYPI_API_TOKEN=...`)
- **Version locations:** `pyproject.toml` and `tweek/__init__.py`
- **Build tools required:** `build`, `twine` (in dev dependencies)
