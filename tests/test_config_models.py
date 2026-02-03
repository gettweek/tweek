#!/usr/bin/env python3
"""
Tests for Tweek Pydantic configuration models.

Tests coverage of:
- Enum types: SecurityTierValue, NonEnglishHandling, PatternSeverity, PatternConfidence
- Section models: LLMReviewConfig, RateLimitingConfig, SessionAnalysisConfig,
  HeuristicScorerConfig, LocalModelConfig
- Structural models: TierDefinition, EscalationRule, SensitiveDirectory,
  PathBoundaryConfig, OpenClawConfig
- Root models: TweekConfig, PatternDefinition, PatternsConfig
- ConfigManager Pydantic integration: validate_config, _validate_with_pydantic
"""

import sys
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent))

pytestmark = pytest.mark.config

from tweek.config.models import (
    EscalationRule,
    HeuristicScorerConfig,
    LLMReviewConfig,
    LLMReviewFallbackConfig,
    LLMReviewLocalConfig,
    LocalModelConfig,
    NonEnglishHandling,
    OpenClawConfig,
    PathBoundaryConfig,
    PatternConfidence,
    PatternDefinition,
    PatternSeverity,
    PatternsConfig,
    RateLimitingConfig,
    SecurityTierValue,
    SensitiveDirectory,
    SessionAnalysisConfig,
    TierDefinition,
    TweekConfig,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def builtin_config():
    """Load the builtin tiers.yaml as a dict."""
    tiers_path = Path(__file__).parent.parent / "tweek" / "config" / "tiers.yaml"
    with open(tiers_path) as f:
        return yaml.safe_load(f)


@pytest.fixture
def valid_pattern_def():
    """A valid PatternDefinition dict."""
    return {
        "id": 1,
        "name": "test_pattern",
        "description": "A test pattern",
        "regex": r"\btest\b",
        "severity": "high",
        "confidence": "deterministic",
    }


# =============================================================================
# ENUM TESTS
# =============================================================================


class TestSecurityTierValue:
    """Tests for SecurityTierValue enum."""

    def test_all_values(self):
        assert SecurityTierValue.SAFE.value == "safe"
        assert SecurityTierValue.DEFAULT.value == "default"
        assert SecurityTierValue.RISKY.value == "risky"
        assert SecurityTierValue.DANGEROUS.value == "dangerous"

    def test_string_coercion(self):
        """SecurityTierValue is a str enum so it can be constructed from strings."""
        assert SecurityTierValue("safe") == SecurityTierValue.SAFE
        assert SecurityTierValue("default") == SecurityTierValue.DEFAULT
        assert SecurityTierValue("risky") == SecurityTierValue.RISKY
        assert SecurityTierValue("dangerous") == SecurityTierValue.DANGEROUS

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            SecurityTierValue("invalid_tier")

    def test_is_str_subclass(self):
        """SecurityTierValue members are also str instances."""
        assert isinstance(SecurityTierValue.SAFE, str)
        assert SecurityTierValue.RISKY == "risky"

    def test_membership_count(self):
        assert len(SecurityTierValue) == 4


class TestNonEnglishHandling:
    """Tests for NonEnglishHandling enum."""

    def test_all_values(self):
        assert NonEnglishHandling.ESCALATE.value == "escalate"
        assert NonEnglishHandling.TRANSLATE.value == "translate"
        assert NonEnglishHandling.BOTH.value == "both"
        assert NonEnglishHandling.NONE.value == "none"

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            NonEnglishHandling("block")

    def test_membership_count(self):
        assert len(NonEnglishHandling) == 4


class TestPatternSeverity:
    """Tests for PatternSeverity enum."""

    def test_all_values(self):
        assert PatternSeverity.CRITICAL.value == "critical"
        assert PatternSeverity.HIGH.value == "high"
        assert PatternSeverity.MEDIUM.value == "medium"
        assert PatternSeverity.LOW.value == "low"

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            PatternSeverity("extreme")

    def test_membership_count(self):
        assert len(PatternSeverity) == 4


class TestPatternConfidence:
    """Tests for PatternConfidence enum."""

    def test_all_values(self):
        assert PatternConfidence.DETERMINISTIC.value == "deterministic"
        assert PatternConfidence.HEURISTIC.value == "heuristic"
        assert PatternConfidence.CONTEXTUAL.value == "contextual"

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            PatternConfidence("fuzzy")

    def test_membership_count(self):
        assert len(PatternConfidence) == 3


# =============================================================================
# SECTION MODEL TESTS
# =============================================================================


class TestLLMReviewConfig:
    """Tests for LLMReviewConfig and nested sub-configs."""

    def test_defaults(self):
        cfg = LLMReviewConfig()
        assert cfg.enabled is True
        assert cfg.provider == "auto"
        assert cfg.model == "auto"
        assert cfg.base_url is None
        assert cfg.api_key_env is None
        assert cfg.timeout_seconds == 15.0

    def test_custom_values(self):
        cfg = LLMReviewConfig(
            enabled=False,
            provider="openai",
            model="gpt-4",
            base_url="http://localhost:8080",
            api_key_env="MY_KEY",
            timeout_seconds=30.0,
        )
        assert cfg.enabled is False
        assert cfg.provider == "openai"
        assert cfg.model == "gpt-4"
        assert cfg.base_url == "http://localhost:8080"
        assert cfg.api_key_env == "MY_KEY"
        assert cfg.timeout_seconds == 30.0

    def test_nested_local_config_defaults(self):
        cfg = LLMReviewConfig()
        assert cfg.local.enabled is True
        assert cfg.local.probe_timeout == 2.0
        assert cfg.local.timeout_seconds == 30.0
        assert cfg.local.ollama_host is None
        assert cfg.local.lm_studio_host is None
        assert cfg.local.preferred_models == []
        assert cfg.local.validate_on_first_use is True
        assert cfg.local.min_validation_score == 0.6

    def test_nested_local_config_custom(self):
        local = LLMReviewLocalConfig(
            enabled=False,
            probe_timeout=1.0,
            timeout_seconds=10.0,
            ollama_host="http://myhost:11434",
            preferred_models=["llama3", "mistral"],
            min_validation_score=0.8,
        )
        cfg = LLMReviewConfig(local=local)
        assert cfg.local.enabled is False
        assert cfg.local.probe_timeout == 1.0
        assert cfg.local.ollama_host == "http://myhost:11434"
        assert cfg.local.preferred_models == ["llama3", "mistral"]
        assert cfg.local.min_validation_score == 0.8

    def test_nested_fallback_config_defaults(self):
        cfg = LLMReviewConfig()
        assert cfg.fallback.enabled is True
        assert cfg.fallback.order == ["local", "anthropic", "openai"]

    def test_nested_fallback_config_custom(self):
        fb = LLMReviewFallbackConfig(enabled=False, order=["openai", "local"])
        cfg = LLMReviewConfig(fallback=fb)
        assert cfg.fallback.enabled is False
        assert cfg.fallback.order == ["openai", "local"]

    def test_timeout_must_be_positive(self):
        with pytest.raises(ValidationError) as exc_info:
            LLMReviewConfig(timeout_seconds=0)
        errors = exc_info.value.errors()
        assert any("timeout_seconds" in str(e["loc"]) for e in errors)

    def test_timeout_negative_raises(self):
        with pytest.raises(ValidationError):
            LLMReviewConfig(timeout_seconds=-1.0)

    def test_local_probe_timeout_must_be_positive(self):
        with pytest.raises(ValidationError):
            LLMReviewLocalConfig(probe_timeout=0)

    def test_local_min_validation_score_bounds(self):
        # Valid at bounds
        LLMReviewLocalConfig(min_validation_score=0.0)
        LLMReviewLocalConfig(min_validation_score=1.0)
        # Invalid outside bounds
        with pytest.raises(ValidationError):
            LLMReviewLocalConfig(min_validation_score=-0.1)
        with pytest.raises(ValidationError):
            LLMReviewLocalConfig(min_validation_score=1.1)

    def test_extra_fields_allowed(self):
        cfg = LLMReviewConfig(custom_field="hello")
        assert cfg.custom_field == "hello"


class TestRateLimitingConfig:
    """Tests for RateLimitingConfig."""

    def test_defaults(self):
        cfg = RateLimitingConfig()
        assert cfg.enabled is True
        assert cfg.burst_window_seconds == 10
        assert cfg.burst_threshold == 5
        assert cfg.max_per_minute == 60
        assert cfg.max_dangerous_per_minute == 10
        assert cfg.max_same_command_per_minute == 5

    def test_all_fields_must_be_positive(self):
        """Each int field must be > 0."""
        for field_name in [
            "burst_window_seconds",
            "burst_threshold",
            "max_per_minute",
            "max_dangerous_per_minute",
            "max_same_command_per_minute",
        ]:
            with pytest.raises(ValidationError):
                RateLimitingConfig(**{field_name: 0})
            with pytest.raises(ValidationError):
                RateLimitingConfig(**{field_name: -1})

    def test_custom_values(self):
        cfg = RateLimitingConfig(
            enabled=False,
            burst_window_seconds=20,
            burst_threshold=10,
            max_per_minute=120,
            max_dangerous_per_minute=20,
            max_same_command_per_minute=10,
        )
        assert cfg.enabled is False
        assert cfg.burst_window_seconds == 20
        assert cfg.max_per_minute == 120

    def test_boundary_value_one(self):
        """Minimum valid value is 1 for all gt=0 int fields."""
        cfg = RateLimitingConfig(
            burst_window_seconds=1,
            burst_threshold=1,
            max_per_minute=1,
            max_dangerous_per_minute=1,
            max_same_command_per_minute=1,
        )
        assert cfg.burst_window_seconds == 1


class TestSessionAnalysisConfig:
    """Tests for SessionAnalysisConfig."""

    def test_defaults(self):
        cfg = SessionAnalysisConfig()
        assert cfg.enabled is True
        assert cfg.lookback_minutes == 30
        assert cfg.alert_on_risk_score == 0.7

    def test_alert_on_risk_score_bounds(self):
        # Valid at boundaries
        SessionAnalysisConfig(alert_on_risk_score=0.0)
        SessionAnalysisConfig(alert_on_risk_score=1.0)
        # Invalid below
        with pytest.raises(ValidationError):
            SessionAnalysisConfig(alert_on_risk_score=-0.01)
        # Invalid above
        with pytest.raises(ValidationError):
            SessionAnalysisConfig(alert_on_risk_score=1.01)

    def test_lookback_must_be_positive(self):
        with pytest.raises(ValidationError):
            SessionAnalysisConfig(lookback_minutes=0)
        with pytest.raises(ValidationError):
            SessionAnalysisConfig(lookback_minutes=-5)

    def test_custom_values(self):
        cfg = SessionAnalysisConfig(
            enabled=False, lookback_minutes=60, alert_on_risk_score=0.9
        )
        assert cfg.enabled is False
        assert cfg.lookback_minutes == 60
        assert cfg.alert_on_risk_score == 0.9


class TestHeuristicScorerConfig:
    """Tests for HeuristicScorerConfig."""

    def test_defaults(self):
        cfg = HeuristicScorerConfig()
        assert cfg.enabled is True
        assert cfg.threshold == 0.4
        assert cfg.log_all_scores is False

    def test_threshold_bounds(self):
        # Valid at boundaries
        HeuristicScorerConfig(threshold=0.0)
        HeuristicScorerConfig(threshold=1.0)
        # Invalid outside
        with pytest.raises(ValidationError):
            HeuristicScorerConfig(threshold=-0.01)
        with pytest.raises(ValidationError):
            HeuristicScorerConfig(threshold=1.01)

    def test_custom_values(self):
        cfg = HeuristicScorerConfig(enabled=False, threshold=0.8, log_all_scores=True)
        assert cfg.enabled is False
        assert cfg.threshold == 0.8
        assert cfg.log_all_scores is True


class TestLocalModelConfig:
    """Tests for LocalModelConfig with escalation bounds validator."""

    def test_defaults(self):
        cfg = LocalModelConfig()
        assert cfg.enabled is True
        assert cfg.model == "auto"
        assert cfg.escalate_to_llm is True
        assert cfg.escalate_min_confidence == 0.1
        assert cfg.escalate_max_confidence == 0.9

    def test_escalation_bounds_min_must_be_less_than_max(self):
        """escalate_min_confidence must be < escalate_max_confidence."""
        with pytest.raises(ValidationError, match="must be less than"):
            LocalModelConfig(
                escalate_min_confidence=0.9,
                escalate_max_confidence=0.1,
            )

    def test_escalation_bounds_equal_raises(self):
        """Equal min and max should also fail."""
        with pytest.raises(ValidationError, match="must be less than"):
            LocalModelConfig(
                escalate_min_confidence=0.5,
                escalate_max_confidence=0.5,
            )

    def test_valid_escalation_bounds(self):
        cfg = LocalModelConfig(
            escalate_min_confidence=0.2,
            escalate_max_confidence=0.8,
        )
        assert cfg.escalate_min_confidence == 0.2
        assert cfg.escalate_max_confidence == 0.8

    def test_bounds_at_extremes(self):
        cfg = LocalModelConfig(
            escalate_min_confidence=0.0,
            escalate_max_confidence=1.0,
        )
        assert cfg.escalate_min_confidence == 0.0
        assert cfg.escalate_max_confidence == 1.0

    def test_confidence_range_validation(self):
        """Individual fields must be in [0, 1]."""
        with pytest.raises(ValidationError):
            LocalModelConfig(escalate_min_confidence=-0.1)
        with pytest.raises(ValidationError):
            LocalModelConfig(escalate_max_confidence=1.1)

    def test_extra_fields_allowed(self):
        cfg = LocalModelConfig(custom_key="value")
        assert cfg.custom_key == "value"


# =============================================================================
# STRUCTURAL MODEL TESTS
# =============================================================================


class TestTierDefinition:
    """Tests for TierDefinition."""

    def test_with_screening_list(self):
        td = TierDefinition(description="Test tier", screening=["regex", "llm"])
        assert td.description == "Test tier"
        assert td.screening == ["regex", "llm"]

    def test_without_screening_list(self):
        td = TierDefinition(description="Safe tier")
        assert td.description == "Safe tier"
        assert td.screening == []

    def test_empty_screening(self):
        td = TierDefinition(description="Empty", screening=[])
        assert td.screening == []

    def test_requires_description(self):
        with pytest.raises(ValidationError):
            TierDefinition()


class TestEscalationRule:
    """Tests for EscalationRule with regex validation."""

    def test_valid_regex(self):
        rule = EscalationRule(
            pattern=r"\b(prod|production)\b",
            description="Production reference",
            escalate_to=SecurityTierValue.RISKY,
        )
        assert rule.pattern == r"\b(prod|production)\b"
        assert rule.description == "Production reference"
        assert rule.escalate_to == SecurityTierValue.RISKY

    def test_invalid_regex_raises(self):
        with pytest.raises(ValidationError, match="Invalid regex"):
            EscalationRule(
                pattern="[invalid(regex",
                description="Bad regex",
                escalate_to=SecurityTierValue.DANGEROUS,
            )

    def test_all_tier_values(self):
        """escalate_to accepts all SecurityTierValue members."""
        for tier in SecurityTierValue:
            rule = EscalationRule(
                pattern="test",
                description=f"Escalate to {tier.value}",
                escalate_to=tier,
            )
            assert rule.escalate_to == tier

    def test_escalate_to_from_string(self):
        """escalate_to can be set from a string value."""
        rule = EscalationRule(
            pattern="test",
            description="String coercion",
            escalate_to="dangerous",
        )
        assert rule.escalate_to == SecurityTierValue.DANGEROUS

    def test_invalid_tier_value_raises(self):
        with pytest.raises(ValidationError):
            EscalationRule(
                pattern="test",
                description="Bad tier",
                escalate_to="invalid_tier",
            )

    def test_complex_valid_regex(self):
        rule = EscalationRule(
            pattern=r"(kubectl|gcloud|aws)\s+(apply|deploy|delete)",
            description="Cloud ops",
            escalate_to=SecurityTierValue.DANGEROUS,
        )
        assert rule.pattern == r"(kubectl|gcloud|aws)\s+(apply|deploy|delete)"


class TestSensitiveDirectory:
    """Tests for SensitiveDirectory."""

    def test_basic_creation(self):
        sd = SensitiveDirectory(
            pattern=".ssh",
            escalate_to=SecurityTierValue.DANGEROUS,
            description="SSH directory",
        )
        assert sd.pattern == ".ssh"
        assert sd.escalate_to == SecurityTierValue.DANGEROUS
        assert sd.description == "SSH directory"

    def test_default_description(self):
        sd = SensitiveDirectory(
            pattern="/etc/shadow",
            escalate_to=SecurityTierValue.DANGEROUS,
        )
        assert sd.description == ""

    def test_requires_pattern_and_escalate_to(self):
        with pytest.raises(ValidationError):
            SensitiveDirectory(pattern=".kube")
        with pytest.raises(ValidationError):
            SensitiveDirectory(escalate_to=SecurityTierValue.RISKY)


class TestPathBoundaryConfig:
    """Tests for PathBoundaryConfig."""

    def test_defaults(self):
        cfg = PathBoundaryConfig()
        assert cfg.enabled is True
        assert cfg.default_escalate_to == SecurityTierValue.RISKY
        assert cfg.sensitive_directories == []

    def test_with_sensitive_directories(self):
        dirs = [
            SensitiveDirectory(
                pattern=".ssh",
                escalate_to=SecurityTierValue.DANGEROUS,
                description="SSH dir",
            ),
            SensitiveDirectory(
                pattern=".aws",
                escalate_to=SecurityTierValue.DANGEROUS,
                description="AWS dir",
            ),
        ]
        cfg = PathBoundaryConfig(sensitive_directories=dirs)
        assert len(cfg.sensitive_directories) == 2
        assert cfg.sensitive_directories[0].pattern == ".ssh"

    def test_custom_default_escalate_to(self):
        cfg = PathBoundaryConfig(default_escalate_to=SecurityTierValue.DANGEROUS)
        assert cfg.default_escalate_to == SecurityTierValue.DANGEROUS


class TestOpenClawConfig:
    """Tests for OpenClawConfig."""

    def test_defaults(self):
        cfg = OpenClawConfig()
        assert cfg.enabled is False
        assert cfg.gateway_port == 18789
        assert cfg.scanner_port == 9878
        assert cfg.plugin_installed is False
        assert cfg.preset == "cautious"

    def test_port_validation_gateway(self):
        # Valid ports
        OpenClawConfig(gateway_port=1)
        OpenClawConfig(gateway_port=65535)
        # Invalid: 0
        with pytest.raises(ValidationError):
            OpenClawConfig(gateway_port=0)
        # Invalid: above 65535
        with pytest.raises(ValidationError):
            OpenClawConfig(gateway_port=65536)
        # Invalid: negative
        with pytest.raises(ValidationError):
            OpenClawConfig(gateway_port=-1)

    def test_port_validation_scanner(self):
        OpenClawConfig(scanner_port=1)
        OpenClawConfig(scanner_port=65535)
        with pytest.raises(ValidationError):
            OpenClawConfig(scanner_port=0)
        with pytest.raises(ValidationError):
            OpenClawConfig(scanner_port=65536)

    def test_custom_values(self):
        cfg = OpenClawConfig(
            enabled=True,
            gateway_port=9000,
            scanner_port=9001,
            plugin_installed=True,
            preset="paranoid",
        )
        assert cfg.enabled is True
        assert cfg.gateway_port == 9000
        assert cfg.scanner_port == 9001
        assert cfg.plugin_installed is True
        assert cfg.preset == "paranoid"

    def test_extra_fields_rejected(self):
        with pytest.raises(ValidationError):
            OpenClawConfig(extra_key="value")

    def test_preset_validation(self):
        for valid in ("paranoid", "cautious", "balanced", "trusted"):
            cfg = OpenClawConfig(preset=valid)
            assert cfg.preset == valid
        with pytest.raises(ValidationError):
            OpenClawConfig(preset="invalid")

    def test_port_collision_rejected(self):
        with pytest.raises(ValidationError, match="must differ"):
            OpenClawConfig(gateway_port=9000, scanner_port=9000)


# =============================================================================
# ROOT CONFIG MODEL TESTS
# =============================================================================


class TestTweekConfig:
    """Tests for the root TweekConfig model."""

    def test_empty_config_all_defaults(self):
        cfg = TweekConfig()
        assert cfg.version is None
        assert cfg.tools == {}
        assert cfg.skills == {}
        assert cfg.default_tier == SecurityTierValue.DEFAULT
        assert cfg.tiers == {}
        assert cfg.llm_review is None
        assert cfg.rate_limiting is None
        assert cfg.session_analysis is None
        assert cfg.heuristic_scorer is None
        assert cfg.local_model is None
        assert cfg.escalations == []
        assert cfg.path_boundary is None
        assert cfg.non_english_handling == NonEnglishHandling.ESCALATE
        assert cfg.proxy is None
        assert cfg.mcp is None
        assert cfg.sandbox is None
        assert cfg.isolation_chamber is None
        assert cfg.plugins is None
        assert cfg.openclaw is None

    def test_full_config_from_builtin_tiers_yaml(self, builtin_config):
        """The builtin tiers.yaml must validate successfully."""
        cfg = TweekConfig.model_validate(builtin_config)
        assert cfg.version == 2
        assert cfg.default_tier == SecurityTierValue.DEFAULT
        # Check some known tool tiers
        assert cfg.tools["Bash"] == SecurityTierValue.DANGEROUS
        assert cfg.tools["Read"] == SecurityTierValue.DEFAULT
        assert cfg.tools["Glob"] == SecurityTierValue.SAFE
        assert cfg.tools["Write"] == SecurityTierValue.RISKY
        # Check some known skill tiers
        assert cfg.skills["deploy"] == SecurityTierValue.DANGEROUS
        assert cfg.skills["review-pr"] == SecurityTierValue.SAFE
        # Check tier definitions
        assert "safe" in cfg.tiers
        assert "dangerous" in cfg.tiers
        assert cfg.tiers["dangerous"].screening == ["regex", "llm", "sandbox"]
        # Check escalations
        assert len(cfg.escalations) > 0
        # Check non_english_handling
        assert cfg.non_english_handling == NonEnglishHandling.ESCALATE
        # Check llm_review
        assert cfg.llm_review is not None
        assert cfg.llm_review.enabled is True
        # Check rate_limiting
        assert cfg.rate_limiting is not None
        assert cfg.rate_limiting.enabled is True
        # Check session_analysis
        assert cfg.session_analysis is not None
        # Check heuristic_scorer
        assert cfg.heuristic_scorer is not None
        assert cfg.heuristic_scorer.threshold == 0.4
        # Check local_model
        assert cfg.local_model is not None
        assert cfg.local_model.escalate_to_llm is True
        # Check path_boundary
        assert cfg.path_boundary is not None
        assert cfg.path_boundary.enabled is True
        assert len(cfg.path_boundary.sensitive_directories) > 0

    def test_invalid_tool_tier_raises(self):
        """An invalid tier value for a tool should raise ValidationError."""
        with pytest.raises(ValidationError):
            TweekConfig(tools={"Bash": "ultra_dangerous"})

    def test_invalid_escalation_regex_raises(self):
        """An invalid regex in escalations should raise ValidationError."""
        with pytest.raises(ValidationError):
            TweekConfig(
                escalations=[
                    {
                        "pattern": "[invalid(regex",
                        "description": "Bad pattern",
                        "escalate_to": "risky",
                    }
                ]
            )

    def test_extra_keys_allowed(self):
        """Root model uses extra='allow' for forward compatibility."""
        cfg = TweekConfig(future_feature={"enabled": True})
        assert cfg.future_feature == {"enabled": True}

    def test_tool_tier_coercion_from_strings(self):
        """String values in tools dict should be coerced to SecurityTierValue."""
        cfg = TweekConfig(tools={"Bash": "dangerous", "Read": "safe"})
        assert cfg.tools["Bash"] == SecurityTierValue.DANGEROUS
        assert cfg.tools["Read"] == SecurityTierValue.SAFE

    def test_skill_tier_coercion_from_strings(self):
        """String values in skills dict should be coerced to SecurityTierValue."""
        cfg = TweekConfig(skills={"deploy": "dangerous", "review-pr": "safe"})
        assert cfg.skills["deploy"] == SecurityTierValue.DANGEROUS
        assert cfg.skills["review-pr"] == SecurityTierValue.SAFE

    def test_default_tier_from_string(self):
        """default_tier should accept string values."""
        cfg = TweekConfig(default_tier="risky")
        assert cfg.default_tier == SecurityTierValue.RISKY

    def test_invalid_default_tier_raises(self):
        with pytest.raises(ValidationError):
            TweekConfig(default_tier="nonexistent")

    def test_with_all_optional_sections(self):
        """Config with all optional sections set."""
        cfg = TweekConfig(
            version=2,
            llm_review=LLMReviewConfig(),
            rate_limiting=RateLimitingConfig(),
            session_analysis=SessionAnalysisConfig(),
            heuristic_scorer=HeuristicScorerConfig(),
            local_model=LocalModelConfig(),
            path_boundary=PathBoundaryConfig(),
            openclaw=OpenClawConfig(),
        )
        assert cfg.llm_review is not None
        assert cfg.rate_limiting is not None
        assert cfg.session_analysis is not None
        assert cfg.heuristic_scorer is not None
        assert cfg.local_model is not None
        assert cfg.path_boundary is not None
        assert cfg.openclaw is not None

    def test_nested_dict_validation_for_sections(self):
        """Sections can be provided as dicts and will be validated."""
        cfg = TweekConfig(
            llm_review={"enabled": False, "timeout_seconds": 10.0},
            rate_limiting={"burst_threshold": 20},
        )
        assert cfg.llm_review.enabled is False
        assert cfg.llm_review.timeout_seconds == 10.0
        assert cfg.rate_limiting.burst_threshold == 20


# =============================================================================
# PATTERN SCHEMA MODEL TESTS
# =============================================================================


class TestPatternDefinition:
    """Tests for PatternDefinition."""

    def test_valid_pattern(self, valid_pattern_def):
        pd = PatternDefinition(**valid_pattern_def)
        assert pd.id == 1
        assert pd.name == "test_pattern"
        assert pd.description == "A test pattern"
        assert pd.regex == r"\btest\b"
        assert pd.severity == PatternSeverity.HIGH
        assert pd.confidence == PatternConfidence.DETERMINISTIC
        assert pd.family is None

    def test_with_family(self, valid_pattern_def):
        valid_pattern_def["family"] = "exfiltration"
        pd = PatternDefinition(**valid_pattern_def)
        assert pd.family == "exfiltration"

    def test_invalid_regex_raises(self):
        with pytest.raises(ValidationError, match="Invalid regex"):
            PatternDefinition(
                id=1,
                name="bad",
                description="bad pattern",
                regex="[unclosed",
                severity="high",
                confidence="deterministic",
            )

    def test_complex_valid_regex(self):
        pd = PatternDefinition(
            id=99,
            name="complex",
            description="Complex regex",
            regex=r"(?i)(system\s+prompt|instructions).{0,30}(reveal|show)",
            severity="critical",
            confidence="heuristic",
        )
        assert pd.severity == PatternSeverity.CRITICAL
        assert pd.confidence == PatternConfidence.HEURISTIC

    def test_missing_required_fields(self):
        with pytest.raises(ValidationError):
            PatternDefinition(id=1, name="incomplete")

    def test_invalid_severity_raises(self):
        with pytest.raises(ValidationError):
            PatternDefinition(
                id=1,
                name="bad",
                description="desc",
                regex="test",
                severity="extreme",
                confidence="deterministic",
            )

    def test_invalid_confidence_raises(self):
        with pytest.raises(ValidationError):
            PatternDefinition(
                id=1,
                name="bad",
                description="desc",
                regex="test",
                severity="high",
                confidence="guessing",
            )


class TestPatternsConfig:
    """Tests for PatternsConfig with model validators."""

    def test_valid_config(self, valid_pattern_def):
        cfg = PatternsConfig(
            version=1,
            pattern_count=1,
            patterns=[valid_pattern_def],
        )
        assert cfg.version == 1
        assert cfg.pattern_count == 1
        assert len(cfg.patterns) == 1

    def test_pattern_count_mismatch_raises(self, valid_pattern_def):
        with pytest.raises(ValidationError, match="pattern_count.*does not match"):
            PatternsConfig(
                version=1,
                pattern_count=5,
                patterns=[valid_pattern_def],
            )

    def test_pattern_count_zero_skips_count_check(self, valid_pattern_def):
        """pattern_count of 0 means the count check is skipped."""
        p2 = valid_pattern_def.copy()
        p2["id"] = 2
        p2["name"] = "test_pattern_2"
        cfg = PatternsConfig(
            version=1,
            pattern_count=0,
            patterns=[valid_pattern_def, p2],
        )
        # pattern_count=0 skips the count validation
        assert cfg.pattern_count == 0
        assert len(cfg.patterns) == 2

    def test_pattern_count_zero_allows_any_count(self):
        """pattern_count=0 means 'skip the count check'."""
        p1 = {
            "id": 1, "name": "p1", "description": "d", "regex": "a",
            "severity": "high", "confidence": "deterministic",
        }
        p2 = {
            "id": 2, "name": "p2", "description": "d", "regex": "b",
            "severity": "low", "confidence": "heuristic",
        }
        cfg = PatternsConfig(version=1, pattern_count=0, patterns=[p1, p2])
        assert len(cfg.patterns) == 2

    def test_duplicate_ids_raises(self):
        p1 = {
            "id": 1, "name": "p1", "description": "d", "regex": "a",
            "severity": "high", "confidence": "deterministic",
        }
        p2 = {
            "id": 1, "name": "p2", "description": "d", "regex": "b",
            "severity": "low", "confidence": "heuristic",
        }
        with pytest.raises(ValidationError, match="Duplicate pattern IDs"):
            PatternsConfig(version=1, pattern_count=2, patterns=[p1, p2])

    def test_unique_ids_pass(self):
        p1 = {
            "id": 1, "name": "p1", "description": "d", "regex": "a",
            "severity": "high", "confidence": "deterministic",
        }
        p2 = {
            "id": 2, "name": "p2", "description": "d", "regex": "b",
            "severity": "low", "confidence": "heuristic",
        }
        cfg = PatternsConfig(version=1, pattern_count=2, patterns=[p1, p2])
        assert len(cfg.patterns) == 2

    def test_empty_patterns_valid(self):
        cfg = PatternsConfig(version=1, pattern_count=0, patterns=[])
        assert cfg.patterns == []

    def test_requires_version(self):
        with pytest.raises(ValidationError):
            PatternsConfig(pattern_count=0, patterns=[])


# =============================================================================
# CONFIG MANAGER PYDANTIC INTEGRATION TESTS
# =============================================================================


class TestConfigManagerPydanticIntegration:
    """Tests for ConfigManager's Pydantic validation integration."""

    def test_validate_config_no_errors_for_builtin(self, builtin_config):
        """The builtin tiers.yaml should produce no Pydantic validation errors."""
        # Validate directly with TweekConfig
        cfg = TweekConfig.model_validate(builtin_config)
        # If we get here without raising, the builtin config is valid
        assert cfg is not None

    def test_validate_with_pydantic_catches_invalid_tiers(self):
        """_validate_with_pydantic should catch invalid tier values."""
        from tweek.config.manager import ConfigManager, ConfigIssue

        # Create a config dict with an invalid tier
        bad_config = {
            "tools": {"Bash": "ultra_dangerous"},
            "default_tier": "default",
        }

        # Directly call the static-ish validation method
        cm = ConfigManager.__new__(ConfigManager)
        issues = cm._validate_with_pydantic(bad_config)
        assert len(issues) > 0
        assert any("tools" in issue.key for issue in issues)

    def test_validate_with_pydantic_passes_valid_config(self):
        """_validate_with_pydantic should return empty list for valid config."""
        from tweek.config.manager import ConfigManager

        valid_config = {
            "tools": {"Bash": "dangerous", "Read": "safe"},
            "skills": {"deploy": "dangerous"},
            "default_tier": "default",
            "escalations": [],
        }

        cm = ConfigManager.__new__(ConfigManager)
        issues = cm._validate_with_pydantic(valid_config)
        assert issues == []

    def test_validate_with_pydantic_catches_invalid_escalation_regex(self):
        """_validate_with_pydantic should catch invalid regex in escalations."""
        from tweek.config.manager import ConfigManager

        bad_config = {
            "tools": {},
            "default_tier": "default",
            "escalations": [
                {
                    "pattern": "[bad(regex",
                    "description": "broken",
                    "escalate_to": "risky",
                }
            ],
        }

        cm = ConfigManager.__new__(ConfigManager)
        issues = cm._validate_with_pydantic(bad_config)
        assert len(issues) > 0

    def test_validate_with_pydantic_catches_invalid_local_model_bounds(self):
        """_validate_with_pydantic should catch min >= max in local_model."""
        from tweek.config.manager import ConfigManager

        bad_config = {
            "tools": {},
            "default_tier": "default",
            "local_model": {
                "escalate_min_confidence": 0.9,
                "escalate_max_confidence": 0.1,
            },
        }

        cm = ConfigManager.__new__(ConfigManager)
        issues = cm._validate_with_pydantic(bad_config)
        assert len(issues) > 0
        assert any("must be less than" in issue.message for issue in issues)
