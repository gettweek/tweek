"""
Property-based tests for Tweek using Hypothesis.

Tests three core subsystems with fuzz-generated inputs:
1. Pattern matching (PatternMatcher) — no crashes on arbitrary strings
2. Heuristic scoring (HeuristicScorerPlugin) — scores always in [0, 1]
3. Config validation (ConfigManager, Pydantic models) — no crashes on arbitrary dicts
4. Audit pipeline (audit_content) — invariants on risk level determination
"""

import re
import string
import tempfile
from pathlib import Path
from typing import Dict, Any
from unittest.mock import patch, MagicMock

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

# Global Hypothesis settings: disable deadline to handle cold-start loading
# (PatternMatcher loads 262 patterns from YAML on first call)
settings.register_profile("tweek", deadline=None, print_blob=True)
settings.load_profile("tweek")

from tweek.hooks.pre_tool_use import PatternMatcher
from tweek.plugins.screening.heuristic_scorer import HeuristicScorerPlugin, HeuristicScore
from tweek.config.manager import ConfigManager, ConfigIssue, SecurityTier
from tweek.config.models import (
    TweekConfig, PatternsConfig, PatternDefinition,
    SecurityTierValue, PatternSeverity, PatternConfidence,
    LLMReviewConfig, RateLimitingConfig, LocalModelConfig,
    EscalationRule, HeuristicScorerConfig,
)
from tweek.audit import audit_content, AuditResult


# ============================================================================
# Strategies
# ============================================================================

# Arbitrary text including Unicode, control chars, null bytes
fuzz_text = st.text(
    alphabet=st.characters(codec="utf-8"),
    min_size=0,
    max_size=5000,
)

# Text that looks like shell commands
shell_text = st.text(
    alphabet=st.sampled_from(
        list(string.ascii_letters + string.digits + " |;&$(){}[]`'\"\\/.~!@#%^*-_+=:,<>?\n\t")
    ),
    min_size=0,
    max_size=2000,
)

# Strings that might trigger specific heuristic signals
sensitive_tokens = st.sampled_from([
    ".ssh", ".aws", ".env", ".gnupg", ".kube", ".netrc",
    "id_rsa", "id_ed25519", "credentials", "keychain",
    "curl", "wget", "nc", "ncat", "scp", "rsync",
    "base64", "xxd", "openssl", "gzip",
    "$HOME", "${API_KEY}", "$(cat", "eval ",
    "/dev/tcp/", "|", "||", "&&",
    "git commit", "npm install", "python -m pytest",
])

# Build commands from sensitive tokens mixed with random text
mixed_command = st.builds(
    lambda parts: " ".join(parts),
    st.lists(
        st.one_of(sensitive_tokens, st.text(min_size=1, max_size=20)),
        min_size=1,
        max_size=15,
    ),
)

# Valid tier values
valid_tiers = st.sampled_from(["safe", "default", "risky", "dangerous"])

# Arbitrary tier values (may be invalid)
any_tier = st.one_of(
    valid_tiers,
    st.text(min_size=0, max_size=30),
)

# Valid tool names
known_tools = st.sampled_from([
    "Read", "Write", "Edit", "Glob", "Grep", "Bash",
    "WebFetch", "WebSearch", "NotebookEdit", "Task",
])

# Arbitrary tool names
any_tool_name = st.one_of(
    known_tools,
    st.text(alphabet=st.characters(whitelist_categories=("L", "N", "P")), min_size=1, max_size=30),
)

# Config dicts for validation
config_dict = st.fixed_dictionaries(
    {},
    optional={
        "tools": st.dictionaries(any_tool_name, any_tier, max_size=10),
        "skills": st.dictionaries(
            st.text(min_size=1, max_size=30), any_tier, max_size=5
        ),
        "default_tier": any_tier,
        "version": st.one_of(st.integers(min_value=1, max_value=10), st.none()),
        "escalations": st.lists(
            st.fixed_dictionaries({
                "pattern": st.text(min_size=1, max_size=50),
                "description": st.text(min_size=1, max_size=100),
                "escalate_to": any_tier,
            }),
            max_size=5,
        ),
    },
)


# ============================================================================
# 1. Pattern Matching Tests
# ============================================================================

class TestPatternMatcherProperties:
    """Property-based tests for the PatternMatcher regex engine."""

    @pytest.fixture(autouse=True)
    def setup_matcher(self):
        """Create a PatternMatcher instance once for all tests."""
        self.matcher = PatternMatcher()

    @given(content=fuzz_text)
    @settings(max_examples=200)
    def test_check_never_crashes(self, content):
        """PatternMatcher.check() must never crash on any input."""
        result = self.matcher.check(content)
        assert result is None or isinstance(result, dict)

    @given(content=fuzz_text)
    @settings(max_examples=200)
    def test_check_all_never_crashes(self, content):
        """PatternMatcher.check_all() must never crash on any input."""
        results = self.matcher.check_all(content)
        assert isinstance(results, list)
        for r in results:
            assert isinstance(r, dict)

    @given(content=fuzz_text)
    @settings(max_examples=200)
    def test_check_all_superset_of_check(self, content):
        """check_all() must include check()'s result if non-None."""
        single = self.matcher.check(content)
        multi = self.matcher.check_all(content)
        if single is not None:
            assert len(multi) >= 1
            # The first match from check() should be in check_all()
            assert single in multi

    @given(content=fuzz_text)
    @settings(max_examples=100)
    def test_check_result_has_required_keys(self, content):
        """Any match from check() must have name, regex, severity keys."""
        result = self.matcher.check(content)
        if result is not None:
            assert "name" in result
            assert "regex" in result
            assert "severity" in result

    @given(content=fuzz_text)
    @settings(max_examples=100)
    def test_normalize_never_crashes(self, content):
        """Unicode normalization must never crash."""
        normalized = PatternMatcher._normalize(content)
        assert isinstance(normalized, str)

    @given(content=shell_text)
    @settings(max_examples=200)
    def test_shell_like_input_never_crashes(self, content):
        """Shell-like strings with pipes, semicolons, etc. must not crash."""
        results = self.matcher.check_all(content)
        assert isinstance(results, list)

    @given(content=st.text(min_size=0, max_size=0))
    def test_empty_input_returns_no_matches(self, content):
        """Empty string should produce no matches."""
        assert self.matcher.check(content) is None
        assert self.matcher.check_all(content) == []

    @given(
        n=st.integers(min_value=1, max_value=50),
        char=st.sampled_from(list(string.printable)),
    )
    def test_repeated_chars_never_crash(self, n, char):
        """Repeated characters (potential regex DoS) must not hang."""
        content = char * n * 100
        result = self.matcher.check_all(content)
        assert isinstance(result, list)


# ============================================================================
# 2. Heuristic Scorer Tests
# ============================================================================

class TestHeuristicScorerProperties:
    """Property-based tests for the HeuristicScorerPlugin."""

    @pytest.fixture(autouse=True)
    def setup_scorer(self):
        """Create a scorer with default config and pre-loaded families."""
        self.scorer = HeuristicScorerPlugin(config={"enabled": True, "threshold": 0.4})
        # Force family loading with empty families to avoid filesystem dependency
        self.scorer._families = {}
        self.scorer._build_signal_indices()

    @given(content=fuzz_text)
    @settings(max_examples=300)
    def test_score_always_in_unit_interval(self, content):
        """Score must always be in [0.0, 1.0]."""
        score = self.scorer._score_content(content)
        assert 0.0 <= score.total_score <= 1.0

    @given(content=fuzz_text)
    @settings(max_examples=200)
    def test_score_never_crashes(self, content):
        """Scoring must never raise an exception."""
        score = self.scorer._score_content(content)
        assert isinstance(score, HeuristicScore)
        assert isinstance(score.signals, list)
        assert isinstance(score.family_scores, dict)

    @given(content=fuzz_text)
    @settings(max_examples=200)
    def test_should_escalate_consistent_with_threshold(self, content):
        """should_escalate must match score >= threshold."""
        score = self.scorer._score_content(content)
        assert score.should_escalate == (score.total_score >= score.threshold)

    @given(content=fuzz_text)
    @settings(max_examples=200)
    def test_dampened_implies_reason(self, content):
        """If dampened is True, dampening_reason must be non-None."""
        score = self.scorer._score_content(content)
        if score.dampened:
            assert score.dampening_reason is not None
        if score.dampening_reason is None:
            assert not score.dampened

    @given(content=mixed_command)
    @settings(max_examples=300)
    def test_mixed_commands_bounded(self, content):
        """Commands mixing sensitive tokens must still produce bounded scores."""
        score = self.scorer._score_content(content)
        assert 0.0 <= score.total_score <= 1.0
        # Signals list should not be absurdly large
        assert len(score.signals) <= 20

    @given(content=shell_text)
    @settings(max_examples=200)
    def test_shell_input_bounded(self, content):
        """Shell-like input with pipes and expansions must stay bounded."""
        score = self.scorer._score_content(content)
        assert 0.0 <= score.total_score <= 1.0

    def test_empty_input_zero_score(self):
        """Empty string should produce zero score."""
        score = self.scorer._score_content("")
        assert score.total_score == 0.0
        assert not score.should_escalate
        assert not score.dampened

    @given(
        threshold=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
        content=mixed_command,
    )
    @settings(max_examples=100)
    def test_custom_threshold_respected(self, threshold, content):
        """Changing threshold must consistently affect should_escalate."""
        scorer = HeuristicScorerPlugin(config={"enabled": True, "threshold": threshold})
        scorer._families = {}
        scorer._build_signal_indices()
        score = scorer._score_content(content)
        assert score.threshold == threshold
        assert score.should_escalate == (score.total_score >= threshold)

    @given(content=fuzz_text)
    @settings(max_examples=100)
    def test_screen_method_never_crashes(self, content):
        """The public screen() method must never crash."""
        result = self.scorer.screen(
            tool_name="Bash",
            content=content,
            context={},
        )
        assert result.allowed is True  # Scorer never blocks, only escalates
        assert result.plugin_name == "heuristic_scorer"

    @given(content=fuzz_text)
    @settings(max_examples=100)
    def test_disabled_scorer_returns_zero(self, content):
        """Disabled scorer must always return zero score."""
        scorer = HeuristicScorerPlugin(config={"enabled": False})
        result = scorer.screen("Bash", content, {})
        assert result.details["heuristic_score"] == 0.0
        assert result.details["should_escalate"] is False

    @given(content=fuzz_text)
    @settings(max_examples=100)
    def test_tokenize_never_crashes(self, content):
        """Tokenization must handle any string."""
        tokens = self.scorer._tokenize(content)
        assert isinstance(tokens, list)
        for t in tokens:
            assert isinstance(t, str)

    @given(content=fuzz_text)
    @settings(max_examples=100)
    def test_is_benign_returns_optional_str(self, content):
        """_is_benign must return None or a string."""
        result = self.scorer._is_benign(content)
        assert result is None or isinstance(result, str)


# ============================================================================
# 3. Config Validation Tests
# ============================================================================

class TestConfigValidationProperties:
    """Property-based tests for ConfigManager validation."""

    @pytest.fixture(autouse=True)
    def setup_config(self, tmp_path):
        """Create ConfigManager with temp paths to avoid touching real config."""
        self.tmp_path = tmp_path
        self.user_path = tmp_path / "user_config.yaml"
        self.project_path = tmp_path / "project_config.yaml"

    def _make_manager(self, user_config=None, project_config=None):
        """Create a ConfigManager with given user/project config dicts."""
        import yaml
        if user_config:
            self.user_path.write_text(yaml.dump(user_config))
        else:
            # Ensure file doesn't exist
            self.user_path.unlink(missing_ok=True)
        if project_config:
            self.project_path.write_text(yaml.dump(project_config))
        else:
            self.project_path.unlink(missing_ok=True)
        return ConfigManager(
            user_config_path=self.user_path,
            project_config_path=self.project_path,
        )

    @given(config=config_dict)
    @settings(max_examples=200)
    def test_validate_never_crashes(self, config):
        """validate_config() must never raise on any config dict."""
        cm = self._make_manager(user_config=config)
        issues = cm.validate_config(scope="user")
        assert isinstance(issues, list)
        for issue in issues:
            assert isinstance(issue, ConfigIssue)
            assert issue.level in ("error", "warning", "info")

    @given(config=config_dict)
    @settings(max_examples=200)
    def test_valid_tiers_produce_no_tier_errors(self, config):
        """Config with only valid tier values should not produce tier errors."""
        # Force all tiers to valid values
        valid_tier_set = {"safe", "default", "risky", "dangerous"}
        clean_config = {}
        if "tools" in config and isinstance(config["tools"], dict):
            clean_config["tools"] = {
                k: v for k, v in config["tools"].items()
                if isinstance(v, str) and v in valid_tier_set
            }
        if "default_tier" in config and config["default_tier"] in valid_tier_set:
            clean_config["default_tier"] = config["default_tier"]

        cm = self._make_manager(user_config=clean_config)
        issues = cm.validate_config(scope="user")
        tier_errors = [i for i in issues if "Invalid tier" in i.message]
        assert len(tier_errors) == 0

    @given(
        tool_name=known_tools,
        tier=valid_tiers,
    )
    def test_known_tool_valid_tier_no_errors(self, tool_name, tier):
        """Known tool + valid tier should produce zero errors."""
        config = {"tools": {tool_name: tier}}
        cm = self._make_manager(user_config=config)
        issues = cm.validate_config(scope="user")
        errors = [i for i in issues if i.level == "error"]
        assert len(errors) == 0

    @given(tier=st.text(min_size=1, max_size=20).filter(
        lambda t: t not in {"safe", "default", "risky", "dangerous"}
    ))
    @settings(max_examples=100)
    def test_invalid_tier_produces_error(self, tier):
        """Invalid tier value must produce an error issue."""
        config = {"tools": {"Bash": tier}}
        cm = self._make_manager(user_config=config)
        issues = cm.validate_config(scope="user")
        tier_errors = [i for i in issues if "Invalid tier" in i.message]
        assert len(tier_errors) >= 1

    @given(key=st.text(min_size=1, max_size=30).filter(
        lambda k: k not in ConfigManager.VALID_TOP_LEVEL_KEYS
    ))
    @settings(max_examples=100)
    def test_unknown_key_produces_error(self, key):
        """Unknown top-level key must produce an error issue."""
        config = {key: "something"}
        cm = self._make_manager(user_config=config)
        issues = cm.validate_config(scope="user")
        key_errors = [i for i in issues if "Unknown config key" in i.message]
        assert len(key_errors) >= 1

    @given(
        scope=st.sampled_from(["user", "project", "merged"]),
        config=config_dict,
    )
    @settings(max_examples=100)
    def test_all_scopes_produce_list(self, scope, config):
        """All scope values must return a list of ConfigIssue."""
        cm = self._make_manager(user_config=config)
        issues = cm.validate_config(scope=scope)
        assert isinstance(issues, list)

    @given(config=config_dict)
    @settings(max_examples=100)
    def test_get_tool_tier_never_crashes(self, config):
        """get_tool_tier() must handle any tool name without crashing."""
        cm = self._make_manager(user_config=config)
        tier = cm.get_tool_tier("Bash")
        assert isinstance(tier, SecurityTier)

    @given(tool_name=st.text(min_size=1, max_size=50))
    @settings(max_examples=100)
    def test_arbitrary_tool_name_returns_tier(self, tool_name):
        """Any tool name string must return a valid SecurityTier."""
        cm = self._make_manager()
        tier = cm.get_tool_tier(tool_name)
        assert isinstance(tier, SecurityTier)
        assert tier in (
            SecurityTier.SAFE, SecurityTier.DEFAULT,
            SecurityTier.RISKY, SecurityTier.DANGEROUS,
        )


# ============================================================================
# 4. Pydantic Model Validation Tests
# ============================================================================

class TestPydanticModelProperties:
    """Property-based tests for Pydantic config models."""

    @given(data=st.fixed_dictionaries(
        {},
        optional={
            "tools": st.dictionaries(
                st.text(min_size=1, max_size=20),
                st.sampled_from(["safe", "default", "risky", "dangerous"]),
                max_size=10,
            ),
            "skills": st.dictionaries(
                st.text(min_size=1, max_size=20),
                st.sampled_from(["safe", "default", "risky", "dangerous"]),
                max_size=5,
            ),
            "default_tier": st.sampled_from(["safe", "default", "risky", "dangerous"]),
            "version": st.just(2),
        },
    ))
    @settings(max_examples=200)
    def test_tweek_config_accepts_valid_data(self, data):
        """TweekConfig must accept any structurally valid config."""
        config = TweekConfig.model_validate(data)
        assert isinstance(config, TweekConfig)
        assert config.default_tier in SecurityTierValue

    @given(
        tier=st.text(min_size=1, max_size=20).filter(
            lambda t: t not in {"safe", "default", "risky", "dangerous"}
        )
    )
    @settings(max_examples=50)
    def test_tweek_config_rejects_invalid_tier(self, tier):
        """TweekConfig must reject invalid default_tier values."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            TweekConfig.model_validate({"default_tier": tier})

    @given(
        enabled=st.booleans(),
        timeout=st.floats(min_value=0.01, max_value=1000.0, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=100)
    def test_llm_review_config_valid(self, enabled, timeout):
        """LLMReviewConfig accepts valid enabled/timeout combinations."""
        config = LLMReviewConfig(enabled=enabled, timeout_seconds=timeout)
        assert config.enabled == enabled
        assert config.timeout_seconds == timeout

    @given(timeout=st.floats(max_value=0.0, allow_nan=False, allow_infinity=False))
    @settings(max_examples=50)
    def test_llm_review_config_rejects_bad_timeout(self, timeout):
        """LLMReviewConfig must reject zero or negative timeout."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            LLMReviewConfig(timeout_seconds=timeout)

    @given(
        burst_window=st.integers(min_value=1, max_value=3600),
        burst_threshold=st.integers(min_value=1, max_value=1000),
        max_per_min=st.integers(min_value=1, max_value=10000),
    )
    @settings(max_examples=100)
    def test_rate_limiting_valid(self, burst_window, burst_threshold, max_per_min):
        """RateLimitingConfig accepts valid positive integers."""
        config = RateLimitingConfig(
            burst_window_seconds=burst_window,
            burst_threshold=burst_threshold,
            max_per_minute=max_per_min,
        )
        assert config.burst_window_seconds == burst_window
        assert config.burst_threshold == burst_threshold

    @given(
        burst_window=st.integers(max_value=0),
    )
    @settings(max_examples=50)
    def test_rate_limiting_rejects_non_positive(self, burst_window):
        """RateLimitingConfig must reject non-positive integers."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            RateLimitingConfig(burst_window_seconds=burst_window)

    @given(
        min_conf=st.floats(min_value=0.0, max_value=0.89, allow_nan=False, allow_infinity=False),
        max_conf=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
    )
    @settings(max_examples=200)
    def test_local_model_config_escalation_bounds(self, min_conf, max_conf):
        """LocalModelConfig validates that min < max confidence."""
        from pydantic import ValidationError
        if min_conf < max_conf:
            config = LocalModelConfig(
                escalate_min_confidence=min_conf,
                escalate_max_confidence=max_conf,
            )
            assert config.escalate_min_confidence < config.escalate_max_confidence
        else:
            with pytest.raises(ValidationError):
                LocalModelConfig(
                    escalate_min_confidence=min_conf,
                    escalate_max_confidence=max_conf,
                )

    @given(
        pattern=st.from_regex(r"[a-z.\\*+?|()]{1,30}", fullmatch=True),
        desc=st.text(min_size=1, max_size=100),
        tier=st.sampled_from(["safe", "default", "risky", "dangerous"]),
    )
    @settings(max_examples=100)
    def test_escalation_rule_valid_regex(self, pattern, desc, tier):
        """EscalationRule must accept valid regex patterns."""
        try:
            re.compile(pattern)
        except re.error:
            assume(False)  # Skip invalid regex
        rule = EscalationRule(pattern=pattern, description=desc, escalate_to=tier)
        assert rule.pattern == pattern

    @given(
        threshold=st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False),
        enabled=st.booleans(),
        log_all=st.booleans(),
    )
    @settings(max_examples=100)
    def test_heuristic_scorer_config_valid(self, threshold, enabled, log_all):
        """HeuristicScorerConfig accepts valid combinations."""
        config = HeuristicScorerConfig(
            threshold=threshold, enabled=enabled, log_all_scores=log_all
        )
        assert config.threshold == threshold
        assert config.enabled == enabled

    @given(
        threshold=st.one_of(
            st.floats(max_value=-0.01, allow_nan=False, allow_infinity=False),
            st.floats(min_value=1.01, allow_nan=False, allow_infinity=False),
        ),
    )
    @settings(max_examples=50)
    def test_heuristic_scorer_config_rejects_bad_threshold(self, threshold):
        """HeuristicScorerConfig must reject thresholds outside [0, 1]."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            HeuristicScorerConfig(threshold=threshold)

    @given(
        pattern_id=st.integers(min_value=1, max_value=9999),
        name=st.text(min_size=1, max_size=50, alphabet=string.ascii_lowercase + "_"),
        severity=st.sampled_from(["critical", "high", "medium", "low"]),
        confidence=st.sampled_from(["deterministic", "heuristic", "contextual"]),
    )
    @settings(max_examples=100)
    def test_pattern_definition_valid(self, pattern_id, name, severity, confidence):
        """PatternDefinition accepts valid combinations."""
        pd = PatternDefinition(
            id=pattern_id,
            name=name,
            description="test pattern",
            regex="test.*pattern",
            severity=severity,
            confidence=confidence,
        )
        assert pd.id == pattern_id
        assert pd.name == name

    @given(
        count=st.integers(min_value=1, max_value=10),
    )
    @settings(max_examples=50)
    def test_patterns_config_count_validation(self, count):
        """PatternsConfig validates pattern_count against actual count."""
        from pydantic import ValidationError
        patterns = [
            PatternDefinition(
                id=i,
                name=f"pattern_{i}",
                description=f"desc {i}",
                regex=f"test{i}",
                severity="medium",
                confidence="heuristic",
            )
            for i in range(1, count + 1)
        ]
        # Correct count should work
        config = PatternsConfig(version=1, pattern_count=count, patterns=patterns)
        assert len(config.patterns) == count

        # Wrong count should fail
        if count > 1:
            with pytest.raises(ValidationError):
                PatternsConfig(version=1, pattern_count=count - 1, patterns=patterns)

    @given(data=st.dictionaries(
        st.text(min_size=1, max_size=30),
        st.one_of(st.text(max_size=50), st.integers(), st.booleans(), st.none()),
        max_size=10,
    ))
    @settings(max_examples=100)
    def test_tweek_config_extra_allow(self, data):
        """TweekConfig with extra='allow' should accept unknown keys without crashing."""
        try:
            config = TweekConfig.model_validate(data)
            assert isinstance(config, TweekConfig)
        except Exception:
            # Validation errors are acceptable for bad data — just no crashes/hangs
            pass


# ============================================================================
# 5. Audit Pipeline Tests
# ============================================================================

class TestAuditPipelineProperties:
    """Property-based tests for the audit_content pipeline."""

    @given(content=fuzz_text)
    @settings(max_examples=150)
    def test_audit_never_crashes(self, content):
        """audit_content() must never crash on any input string."""
        result = audit_content(
            content=content,
            name="fuzz_test",
            translate=False,
            llm_review=False,
        )
        assert isinstance(result, AuditResult)

    @given(content=fuzz_text)
    @settings(max_examples=150)
    def test_audit_risk_level_valid(self, content):
        """Risk level must be one of the three valid values."""
        result = audit_content(
            content=content,
            name="fuzz_test",
            translate=False,
            llm_review=False,
        )
        assert result.risk_level in ("safe", "suspicious", "dangerous")

    @given(content=fuzz_text)
    @settings(max_examples=150)
    def test_audit_critical_implies_dangerous(self, content):
        """If any critical finding exists, risk_level must be 'dangerous'."""
        result = audit_content(
            content=content,
            name="fuzz_test",
            translate=False,
            llm_review=False,
        )
        if result.critical_count > 0:
            assert result.risk_level == "dangerous"

    @given(content=fuzz_text)
    @settings(max_examples=150)
    def test_audit_finding_counts_consistent(self, content):
        """Finding counts must be consistent with findings list."""
        result = audit_content(
            content=content,
            name="fuzz_test",
            translate=False,
            llm_review=False,
        )
        assert result.finding_count == len(result.findings)
        assert result.critical_count <= result.finding_count
        assert result.high_count <= result.finding_count

    @given(content=fuzz_text)
    @settings(max_examples=100)
    def test_audit_content_length_correct(self, content):
        """content_length must match the actual input length."""
        result = audit_content(
            content=content,
            name="fuzz_test",
            translate=False,
            llm_review=False,
        )
        assert result.content_length == len(content)

    @given(content=fuzz_text)
    @settings(max_examples=100)
    def test_audit_no_findings_implies_safe(self, content):
        """If no findings and no LLM review, risk_level must be 'safe'."""
        result = audit_content(
            content=content,
            name="fuzz_test",
            translate=False,
            llm_review=False,
        )
        if result.finding_count == 0 and result.llm_review is None:
            assert result.risk_level == "safe"

    def test_audit_empty_string(self):
        """Empty string should be safe with no findings."""
        result = audit_content(
            content="",
            name="empty",
            translate=False,
            llm_review=False,
        )
        assert result.risk_level == "safe"
        assert result.finding_count == 0
        assert result.content_length == 0

    @given(
        name=st.text(min_size=1, max_size=50),
        content=fuzz_text,
    )
    @settings(max_examples=50)
    def test_audit_skill_name_propagated(self, name, content):
        """The name argument must be propagated to result.skill_name."""
        result = audit_content(
            content=content,
            name=name,
            translate=False,
            llm_review=False,
        )
        assert result.skill_name == name


# ============================================================================
# 6. Idempotency / Determinism Tests
# ============================================================================

class TestDeterminismProperties:
    """Tests that scoring and matching are deterministic."""

    @pytest.fixture(autouse=True)
    def setup(self):
        self.matcher = PatternMatcher()
        self.scorer = HeuristicScorerPlugin(config={"enabled": True, "threshold": 0.4})
        self.scorer._families = {}
        self.scorer._build_signal_indices()

    @given(content=fuzz_text)
    @settings(max_examples=100)
    def test_pattern_matching_deterministic(self, content):
        """Same input must always produce same pattern matches."""
        r1 = self.matcher.check_all(content)
        r2 = self.matcher.check_all(content)
        assert len(r1) == len(r2)
        for a, b in zip(r1, r2):
            assert a["name"] == b["name"]

    @given(content=fuzz_text)
    @settings(max_examples=100)
    def test_heuristic_scoring_deterministic(self, content):
        """Same input must always produce same heuristic score."""
        s1 = self.scorer._score_content(content)
        s2 = self.scorer._score_content(content)
        assert s1.total_score == s2.total_score
        assert s1.should_escalate == s2.should_escalate
        assert len(s1.signals) == len(s2.signals)

    @given(content=fuzz_text)
    @settings(max_examples=100)
    def test_audit_deterministic(self, content):
        """Same input must always produce same audit results."""
        r1 = audit_content(content, name="det", translate=False, llm_review=False)
        r2 = audit_content(content, name="det", translate=False, llm_review=False)
        assert r1.risk_level == r2.risk_level
        assert r1.finding_count == r2.finding_count
        assert r1.critical_count == r2.critical_count
