"""
Isolation Chamber Configuration

Defines the IsolationConfig dataclass and loading logic.
Configuration is stored in ~/.tweek/config.yaml under the 'isolation_chamber' key.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Any, Optional

import yaml


# Default allowed file extensions for skills
DEFAULT_ALLOWED_EXTENSIONS = [
    ".md", ".py", ".json", ".yaml", ".yml", ".txt", ".sh", ".toml",
]

# Extensions that should never appear in a skill
DEFAULT_BLOCKED_EXTENSIONS = [
    ".exe", ".dll", ".so", ".dylib", ".bin", ".msi", ".dmg",
    ".com", ".bat", ".cmd", ".scr", ".pif",
]


@dataclass
class IsolationConfig:
    """Configuration for the Skill Isolation Chamber."""

    enabled: bool = True
    mode: str = "auto"  # "auto" or "manual"
    scan_timeout_seconds: float = 30.0
    llm_review_enabled: bool = True
    max_skill_size_bytes: int = 1_048_576  # 1MB
    max_file_count: int = 50
    max_directory_depth: int = 3
    allowed_file_extensions: List[str] = field(
        default_factory=lambda: list(DEFAULT_ALLOWED_EXTENSIONS)
    )
    blocked_file_extensions: List[str] = field(
        default_factory=lambda: list(DEFAULT_BLOCKED_EXTENSIONS)
    )
    trusted_sources: List[str] = field(default_factory=list)

    # Verdict thresholds
    fail_on_critical: bool = True
    fail_on_high_count: int = 3
    review_on_high_count: int = 1

    # Notifications
    notify_on_jail: bool = True

    def validate(self) -> List[str]:
        """Validate configuration values. Returns list of issues."""
        issues = []
        if self.mode not in ("auto", "manual"):
            issues.append(f"Invalid mode '{self.mode}': must be 'auto' or 'manual'")
        if self.scan_timeout_seconds <= 0:
            issues.append("scan_timeout_seconds must be positive")
        if self.max_skill_size_bytes <= 0:
            issues.append("max_skill_size_bytes must be positive")
        if self.fail_on_high_count < 1:
            issues.append("fail_on_high_count must be >= 1")
        if self.review_on_high_count < 1:
            issues.append("review_on_high_count must be >= 1")
        return issues


def load_isolation_config(config_path: Optional[Path] = None) -> IsolationConfig:
    """
    Load isolation chamber configuration from ~/.tweek/config.yaml.

    Falls back to defaults if file is missing or section is absent.

    Args:
        config_path: Override config file path (for testing)

    Returns:
        IsolationConfig with loaded or default values
    """
    if config_path is None:
        config_path = Path.home() / ".tweek" / "config.yaml"

    if not config_path.exists():
        return IsolationConfig()

    try:
        with open(config_path) as f:
            full_config = yaml.safe_load(f) or {}
    except Exception:
        return IsolationConfig()

    section = full_config.get("isolation_chamber", {})
    if not section or not isinstance(section, dict):
        return IsolationConfig()

    return _config_from_dict(section)


def _config_from_dict(data: Dict[str, Any]) -> IsolationConfig:
    """Build IsolationConfig from a dict, ignoring unknown keys."""
    known_fields = {f.name for f in IsolationConfig.__dataclass_fields__.values()}
    filtered = {k: v for k, v in data.items() if k in known_fields}
    return IsolationConfig(**filtered)


def save_isolation_config(
    config: IsolationConfig,
    config_path: Optional[Path] = None,
) -> None:
    """
    Save isolation chamber configuration to ~/.tweek/config.yaml.

    Preserves other sections in the config file.

    Args:
        config: The configuration to save
        config_path: Override config file path (for testing)
    """
    if config_path is None:
        config_path = Path.home() / ".tweek" / "config.yaml"

    config_path.parent.mkdir(parents=True, exist_ok=True)

    # Load existing config to preserve other sections
    full_config = {}
    if config_path.exists():
        try:
            with open(config_path) as f:
                full_config = yaml.safe_load(f) or {}
        except Exception:
            full_config = {}

    # Update just the isolation_chamber section
    section = {}
    for field_name in IsolationConfig.__dataclass_fields__:
        value = getattr(config, field_name)
        default_value = getattr(IsolationConfig(), field_name)
        # Only write non-default values to keep config clean
        if value != default_value:
            section[field_name] = value

    if section:
        full_config["isolation_chamber"] = section
    elif "isolation_chamber" in full_config:
        del full_config["isolation_chamber"]

    with open(config_path, "w") as f:
        yaml.dump(full_config, f, default_flow_style=False, sort_keys=False)
