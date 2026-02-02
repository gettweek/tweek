"""Tweek configuration module."""

from pathlib import Path

from .manager import ConfigManager, SecurityTier, ConfigIssue, ConfigChange, get_config

CONFIG_DIR = Path(__file__).parent
PATTERNS_FILE = CONFIG_DIR / "patterns.yaml"

__all__ = [
    "ConfigManager", "SecurityTier", "ConfigIssue", "ConfigChange",
    "get_config", "CONFIG_DIR", "PATTERNS_FILE",
    "TweekConfig", "PatternsConfig",
]

# Lazy imports for Pydantic models to avoid import cost when not needed
def __getattr__(name):
    if name in ("TweekConfig", "PatternsConfig"):
        from tweek.config.models import TweekConfig, PatternsConfig
        return {"TweekConfig": TweekConfig, "PatternsConfig": PatternsConfig}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
