"""
Tweek Configuration Templates

Provides template loading and deployment for self-documenting config files.
Templates are bundled with the package and deployed during installation.
Users get well-commented files with all options visible and sensible defaults.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

TEMPLATES_DIR = Path(__file__).parent / "templates"

# Registry of all user-facing configuration files.
# Used by `tweek config edit` and the install flow.
CONFIG_FILES = [
    {
        "id": "config",
        "name": "Security Settings",
        "template": "config.yaml.template",
        "target_path": "~/.tweek/config.yaml",
        "description": "LLM providers, tool tiers, rate limiting, session analysis",
        "editable": True,
    },
    {
        "id": "env",
        "name": "API Keys",
        "template": "env.template",
        "target_path": "~/.tweek/.env",
        "description": "LLM provider API keys (Google, OpenAI, xAI, Anthropic)",
        "editable": True,
    },
    {
        "id": "overrides",
        "name": "Security Overrides",
        "template": "overrides.yaml.template",
        "target_path": "~/.tweek/overrides.yaml",
        "description": "Whitelists, pattern toggles, trust levels (human-only)",
        "editable": True,
    },
    {
        "id": "hooks",
        "name": "Hook Control",
        "template": "tweek.yaml.template",
        "target_path": ".tweek.yaml",
        "description": "Per-directory enable/disable for pre and post screening",
        "editable": True,
    },
    {
        "id": "soul",
        "name": "Security Policy",
        "template": "soul.md.template",
        "target_path": "~/.tweek/soul.md",
        "description": "Natural-language security philosophy for LLM reviewer (human-only)",
        "editable": True,
    },
    {
        "id": "defaults",
        "name": "Default Reference",
        "template": None,
        "target_path": str(Path(__file__).parent / "tiers.yaml"),
        "description": "Bundled defaults — read-only reference for all options",
        "editable": False,
    },
]


def get_template_content(template_name: str) -> str:
    """Read a template file and return its content."""
    template_path = TEMPLATES_DIR / template_name
    if not template_path.exists():
        raise FileNotFoundError(f"Template not found: {template_path}")
    return template_path.read_text()


def deploy_template(
    template_name: str,
    target_path: Path,
    overwrite: bool = False,
) -> bool:
    """Deploy a template to a target path.

    Returns True if the file was created, False if skipped.
    Does NOT overwrite existing files unless overwrite=True.
    """
    if target_path.exists() and not overwrite:
        return False

    content = get_template_content(template_name)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(content)

    # Set restrictive permissions for sensitive files
    if ".env" in target_path.name:
        target_path.chmod(0o600)

    return True


def resolve_target_path(config_entry: dict, global_scope: bool = True) -> Path:
    """Resolve the target path for a config file entry."""
    path_str = config_entry["target_path"]
    if path_str.startswith("~"):
        return Path(path_str).expanduser()
    if path_str.startswith("."):
        if global_scope:
            return Path.home() / path_str
        return Path.cwd() / path_str
    return Path(path_str)


def deploy_all_templates(global_scope: bool = True) -> list[tuple[str, Path, bool]]:
    """Deploy all templates that don't already exist.

    Returns list of (name, path, created) tuples.
    """
    results = []
    for entry in CONFIG_FILES:
        if entry["template"] is None:
            continue
        target = resolve_target_path(entry, global_scope)
        created = deploy_template(entry["template"], target)
        results.append((entry["name"], target, created))
    return results


def append_active_section(target_path: Path, section_yaml: str) -> None:
    """Append an active (uncommented) config section to a template-based file.

    Used by the install flow to write user-selected LLM provider settings
    below the template comments without destroying them (unlike yaml.dump).
    """
    existing = target_path.read_text() if target_path.exists() else ""
    marker = "# --- Active Configuration (set during install) ---"

    if marker in existing:
        # Replace existing active section
        parts = existing.split(marker)
        existing = parts[0].rstrip()

    target_path.write_text(
        existing.rstrip() + "\n\n" + marker + "\n" + section_yaml + "\n"
    )
