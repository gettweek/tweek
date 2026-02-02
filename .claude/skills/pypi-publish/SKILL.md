---
name: pypi-publish
description: Build and publish Tweek to PyPI with automated version bumping. Use when user asks to publish, release, bump version, deploy to PyPI, push a new release, or update the package on PyPI.
user-invocable: true
---

# PyPI Publish

## Purpose

Automate the full release cycle: version bump, test, build, publish to PyPI, commit, tag, and push.

**Use when user asks to:**
- "Publish to PyPI"
- "Release a new version"
- "Bump version and publish"
- "Push a release"
- "Deploy package to PyPI"

---

## Workflow

Follow these steps in order. Stop and report if any step fails.

### Step 1: Determine Version Bump

**1a.** Run the version helper script to see the current version:

```bash
python3 .claude/skills/pypi-publish/scripts/bump_version.py --type patch
```

This returns JSON with `current` and `next` versions.

**1b.** If the user already specified the bump type (e.g., "release a minor version"), use that directly and skip to Step 2.

**1c.** Otherwise, analyze what changed since the last release to make a recommendation. Get the latest git tag and review commits since then:

```bash
git describe --tags --abbrev=0 2>/dev/null || echo "no-tags"
```

Then review the commit log since that tag:

```bash
git log v{last_version}..HEAD --oneline
```

**1d.** Classify and recommend based on the changes:

| Signal | Recommendation |
|--------|---------------|
| Only bug fixes, style changes, docs, refactors, color fixes, dependency bumps | **patch** |
| New features, new commands, new skills, new plugins, API additions | **minor** |
| Breaking API changes, removed commands, renamed public interfaces, config format changes | **major** |

**1e.** Present the recommendation to the user using `AskUserQuestion`. Show the current version, a 1-2 sentence summary of what changed, and the three options with your recommendation marked. Example:

> Current version: **0.2.1** (3 commits since v0.2.1)
>
> Changes: Added PyPI publish skill, fixed dark mode colors across all CLI output.
>
> - **patch** (0.2.1 → 0.2.2) — bug fixes, small changes **(Recommended)**
> - **minor** (0.2.1 → 0.3.0) — new features, non-breaking
> - **major** (0.2.1 → 1.0.0) — breaking changes

Always wait for the user's response before proceeding.

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

### Step 5: Publish to PyPI

Read the PyPI token from the `.env` file:

```bash
grep PYPI_API_TOKEN .env
```

Then upload:

```bash
TWINE_USERNAME=__token__ TWINE_PASSWORD=<token_value> python3 -m twine upload dist/*
```

**IMPORTANT:** Never print or echo the token. Pass it only via environment variable.

### Step 6: Git Commit, Tag, and Push

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

### Step 7: Report

Tell the user:
- The new version number
- The PyPI URL: `https://pypi.org/project/tweek/{version}/`
- That users can update with `tweek upgrade` or `uv tool upgrade tweek`

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| `twine` not installed | `pip install twine build` |
| Token rejected | Check `.env` has valid `PYPI_API_TOKEN` |
| Version already exists on PyPI | You cannot overwrite — bump again |
| Tests fail | Fix tests before publishing |
| Build fails | Check `pyproject.toml` for syntax errors |

---

## Environment

- **PyPI token location:** `.env` file (`PYPI_API_TOKEN=...`)
- **Version locations:** `pyproject.toml` and `tweek/__init__.py`
- **Build tools required:** `build`, `twine` (in dev dependencies)
