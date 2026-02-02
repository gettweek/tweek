"""
Pydantic models for Tweek configuration validation.

These models define the schema for tiers.yaml (the main configuration file)
and patterns.yaml (attack pattern definitions). They provide:
- Type-safe configuration loading with automatic validation
- Human-readable error messages for invalid configuration
- JSON Schema export for documentation and IDE support
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ============================================================================
# Enums
# ============================================================================


class SecurityTierValue(str, Enum):
    """Valid security tier values."""
    SAFE = "safe"
    DEFAULT = "default"
    RISKY = "risky"
    DANGEROUS = "dangerous"


class NonEnglishHandling(str, Enum):
    """How non-English content is handled during screening."""
    ESCALATE = "escalate"
    TRANSLATE = "translate"
    BOTH = "both"
    NONE = "none"


class PatternSeverity(str, Enum):
    """Severity levels for attack patterns."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class PatternConfidence(str, Enum):
    """Confidence levels for attack pattern matches."""
    DETERMINISTIC = "deterministic"
    HEURISTIC = "heuristic"
    CONTEXTUAL = "contextual"


# ============================================================================
# Configuration Section Models
# ============================================================================


class LLMReviewLocalConfig(BaseModel):
    """Configuration for local LLM server (Ollama, LM Studio)."""
    enabled: bool = True
    probe_timeout: float = Field(default=2.0, gt=0)
    timeout_seconds: float = Field(default=30.0, gt=0)
    ollama_host: Optional[str] = None
    lm_studio_host: Optional[str] = None
    preferred_models: List[str] = Field(default_factory=list)
    validate_on_first_use: bool = True
    min_validation_score: float = Field(default=0.6, ge=0.0, le=1.0)

    model_config = {"extra": "allow"}


class LLMReviewFallbackConfig(BaseModel):
    """Configuration for LLM fallback chain."""
    enabled: bool = True
    order: List[str] = Field(default_factory=lambda: ["local", "anthropic", "openai"])

    model_config = {"extra": "allow"}


class LLMReviewConfig(BaseModel):
    """Configuration for LLM-based semantic review."""
    enabled: bool = True
    provider: str = "auto"
    model: str = "auto"
    base_url: Optional[str] = None
    api_key_env: Optional[str] = None
    timeout_seconds: float = Field(default=15.0, gt=0)
    local: LLMReviewLocalConfig = Field(default_factory=LLMReviewLocalConfig)
    fallback: LLMReviewFallbackConfig = Field(default_factory=LLMReviewFallbackConfig)

    model_config = {"extra": "allow"}


class RateLimitingConfig(BaseModel):
    """Configuration for request rate limiting."""
    enabled: bool = True
    burst_window_seconds: int = Field(default=10, gt=0)
    burst_threshold: int = Field(default=5, gt=0)
    max_per_minute: int = Field(default=60, gt=0)
    max_dangerous_per_minute: int = Field(default=10, gt=0)
    max_same_command_per_minute: int = Field(default=5, gt=0)

    model_config = {"extra": "allow"}


class SessionAnalysisConfig(BaseModel):
    """Configuration for session-level analysis."""
    enabled: bool = True
    lookback_minutes: int = Field(default=30, gt=0)
    alert_on_risk_score: float = Field(default=0.7, ge=0.0, le=1.0)

    model_config = {"extra": "allow"}


class HeuristicScorerConfig(BaseModel):
    """Configuration for heuristic scoring bridge."""
    enabled: bool = True
    threshold: float = Field(default=0.4, ge=0.0, le=1.0)
    log_all_scores: bool = False

    model_config = {"extra": "allow"}


class LocalModelConfig(BaseModel):
    """Configuration for local ONNX model inference."""
    enabled: bool = True
    model: str = "auto"
    escalate_to_llm: bool = True
    escalate_min_confidence: float = Field(default=0.1, ge=0.0, le=1.0)
    escalate_max_confidence: float = Field(default=0.9, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def check_escalation_bounds(self) -> "LocalModelConfig":
        if self.escalate_min_confidence >= self.escalate_max_confidence:
            raise ValueError(
                f"escalate_min_confidence ({self.escalate_min_confidence}) "
                f"must be less than escalate_max_confidence ({self.escalate_max_confidence})"
            )
        return self

    model_config = {"extra": "allow"}


class TierDefinition(BaseModel):
    """Definition of a security tier."""
    description: str
    screening: List[str] = Field(default_factory=list)


class EscalationRule(BaseModel):
    """A content-based escalation rule."""
    pattern: str
    description: str
    escalate_to: SecurityTierValue

    @field_validator("pattern")
    @classmethod
    def validate_regex(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}") from e
        return v


class SensitiveDirectory(BaseModel):
    """A sensitive directory that triggers path boundary escalation."""
    pattern: str
    escalate_to: SecurityTierValue
    description: str = ""


class PathBoundaryConfig(BaseModel):
    """Configuration for path boundary escalation."""
    enabled: bool = True
    default_escalate_to: SecurityTierValue = SecurityTierValue.RISKY
    sensitive_directories: List[SensitiveDirectory] = Field(default_factory=list)


class OpenClawConfig(BaseModel):
    """Configuration for OpenClaw integration."""
    enabled: bool = False
    gateway_port: int = Field(default=18789, gt=0, le=65535)
    scanner_port: int = Field(default=9878, gt=0, le=65535)
    plugin_installed: bool = False
    preset: str = "cautious"

    model_config = {"extra": "allow"}


# ============================================================================
# Root Configuration Model
# ============================================================================


class TweekConfig(BaseModel):
    """
    Root Pydantic model for Tweek configuration (tiers.yaml / config.yaml).

    Validates the merged configuration from builtin, user, and project layers.
    Uses extra="allow" at the root level to be forward-compatible with new
    config keys added in future versions.
    """
    version: Optional[int] = None

    # Core tool/skill classification
    tools: Dict[str, SecurityTierValue] = Field(default_factory=dict)
    skills: Dict[str, SecurityTierValue] = Field(default_factory=dict)
    default_tier: SecurityTierValue = SecurityTierValue.DEFAULT

    # Tier definitions
    tiers: Dict[str, TierDefinition] = Field(default_factory=dict)

    # Screening configuration
    llm_review: Optional[LLMReviewConfig] = None
    rate_limiting: Optional[RateLimitingConfig] = None
    session_analysis: Optional[SessionAnalysisConfig] = None
    heuristic_scorer: Optional[HeuristicScorerConfig] = None
    local_model: Optional[LocalModelConfig] = None

    # Escalation rules
    escalations: List[EscalationRule] = Field(default_factory=list)

    # Path boundary
    path_boundary: Optional[PathBoundaryConfig] = None

    # Non-English handling
    non_english_handling: NonEnglishHandling = NonEnglishHandling.ESCALATE

    # Integration configs
    proxy: Optional[Dict[str, Any]] = None
    mcp: Optional[Dict[str, Any]] = None
    sandbox: Optional[Dict[str, Any]] = None
    isolation_chamber: Optional[Dict[str, Any]] = None
    plugins: Optional[Dict[str, Any]] = None
    openclaw: Optional[OpenClawConfig] = None

    model_config = {"extra": "allow"}

    @field_validator("tools", mode="before")
    @classmethod
    def coerce_tool_tiers(cls, v: Any) -> Any:
        """Accept string tier values and coerce to SecurityTierValue."""
        if isinstance(v, dict):
            return {k: SecurityTierValue(val) if isinstance(val, str) else val for k, val in v.items()}
        return v

    @field_validator("skills", mode="before")
    @classmethod
    def coerce_skill_tiers(cls, v: Any) -> Any:
        """Accept string tier values and coerce to SecurityTierValue."""
        if isinstance(v, dict):
            return {k: SecurityTierValue(val) if isinstance(val, str) else val for k, val in v.items()}
        return v


# ============================================================================
# Pattern Schema Model
# ============================================================================


class PatternDefinition(BaseModel):
    """A single attack pattern definition from patterns.yaml."""
    id: int
    name: str
    description: str
    regex: str
    severity: PatternSeverity
    confidence: PatternConfidence
    family: Optional[str] = None

    @field_validator("regex")
    @classmethod
    def validate_regex(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"Invalid regex in pattern: {e}") from e
        return v


class PatternsConfig(BaseModel):
    """Root model for patterns.yaml."""
    version: int
    pattern_count: int = 0
    patterns: List[PatternDefinition] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_pattern_count(self) -> "PatternsConfig":
        actual = len(self.patterns)
        if self.pattern_count > 0 and actual != self.pattern_count:
            raise ValueError(
                f"pattern_count ({self.pattern_count}) does not match "
                f"actual number of patterns ({actual})"
            )
        return self

    @model_validator(mode="after")
    def check_unique_ids(self) -> "PatternsConfig":
        ids = [p.id for p in self.patterns]
        if len(ids) != len(set(ids)):
            dupes = [i for i in ids if ids.count(i) > 1]
            raise ValueError(f"Duplicate pattern IDs: {set(dupes)}")
        return self
