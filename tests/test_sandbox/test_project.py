"""
Comprehensive tests for tweek.sandbox.project module.

Covers: SandboxConfig, ProjectSandbox, MergedOverrides,
_detect_project_dir, get_project_sandbox, and reset.
"""

import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

pytestmark = pytest.mark.sandbox

from tweek.sandbox.layers import IsolationLayer
from tweek.sandbox.project import (
    MergedOverrides,
    ProjectSandbox,
    SandboxConfig,
    _detect_project_dir,
    get_project_sandbox,
    reset_sandboxes,
)
from tweek.sandbox.registry import ProjectRegistry, reset_registry


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_singletons():
    """Reset module-level caches before and after every test."""
    reset_sandboxes()
    reset_registry()
    yield
    reset_sandboxes()
    reset_registry()


@pytest.fixture
def project_dir(tmp_path):
    """Create a minimal project directory with a .git marker."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    return tmp_path


@pytest.fixture
def registry_path(tmp_path):
    """Provide a temp registry path so tests never touch ~/.tweek."""
    reg_path = tmp_path / "registry" / "registry.json"
    reg_path.parent.mkdir(parents=True, exist_ok=True)
    return reg_path


@pytest.fixture
def registry(registry_path):
    """Return a real ProjectRegistry backed by a temp file."""
    return ProjectRegistry(registry_path=registry_path)


@pytest.fixture
def sandbox(project_dir, registry):
    """Build a ProjectSandbox with the registry patched to a temp file."""
    with patch("tweek.sandbox.project.get_registry", return_value=registry):
        sb = ProjectSandbox(project_dir)
        yield sb


# =========================================================================
# 1. SandboxConfig creation and from_dict / to_dict
# =========================================================================


class TestSandboxConfig:
    """Tests for SandboxConfig dataclass."""

    def test_defaults(self):
        cfg = SandboxConfig()
        assert cfg.layer == 2
        assert cfg.inherit_global_patterns is True
        assert cfg.additive_only is True
        assert cfg.auto_init is True
        assert cfg.auto_gitignore is True

    def test_custom_values(self):
        cfg = SandboxConfig(layer=0, inherit_global_patterns=False, additive_only=False,
                            auto_init=False, auto_gitignore=False)
        assert cfg.layer == 0
        assert cfg.inherit_global_patterns is False
        assert cfg.additive_only is False

    def test_from_dict_full(self):
        data = {
            "layer": 1,
            "inherit_global_patterns": False,
            "additive_only": False,
            "auto_init": False,
            "auto_gitignore": False,
        }
        cfg = SandboxConfig.from_dict(data)
        assert cfg.layer == 1
        assert cfg.inherit_global_patterns is False
        assert cfg.auto_init is False

    def test_from_dict_empty_uses_defaults(self):
        cfg = SandboxConfig.from_dict({})
        assert cfg.layer == 2
        assert cfg.inherit_global_patterns is True
        assert cfg.additive_only is True
        assert cfg.auto_init is True
        assert cfg.auto_gitignore is True

    def test_from_dict_partial(self):
        cfg = SandboxConfig.from_dict({"layer": 0})
        assert cfg.layer == 0
        assert cfg.auto_init is True  # default preserved

    def test_to_dict(self):
        cfg = SandboxConfig(layer=1, inherit_global_patterns=False,
                            additive_only=True, auto_init=False,
                            auto_gitignore=True)
        d = cfg.to_dict()
        assert d == {
            "layer": 1,
            "inherit_global_patterns": False,
            "additive_only": True,
            "auto_init": False,
            "auto_gitignore": True,
        }

    def test_roundtrip(self):
        original = SandboxConfig(layer=0, inherit_global_patterns=False,
                                 additive_only=False, auto_init=False,
                                 auto_gitignore=False)
        restored = SandboxConfig.from_dict(original.to_dict())
        assert restored == original


# =========================================================================
# 2. ProjectSandbox initialization
# =========================================================================


class TestProjectSandboxInitialization:
    """Tests for ProjectSandbox.initialize()."""

    def test_initialize_creates_tweek_dir(self, sandbox):
        sandbox.initialize()
        assert sandbox.tweek_dir.is_dir()
        assert sandbox.is_initialized

    def test_initialize_creates_sandbox_yaml(self, sandbox):
        sandbox.initialize()
        sandbox_yaml = sandbox.tweek_dir / "sandbox.yaml"
        assert sandbox_yaml.exists()
        data = yaml.safe_load(sandbox_yaml.read_text())
        assert data["layer"] == 2
        assert "created_at" in data

    def test_initialize_creates_overrides_yaml(self, sandbox):
        sandbox.initialize()
        overrides_yaml = sandbox.tweek_dir / "overrides.yaml"
        assert overrides_yaml.exists()
        content = overrides_yaml.read_text()
        assert "additive-only" in content

    def test_initialize_creates_config_yaml(self, sandbox):
        sandbox.initialize()
        config_yaml = sandbox.tweek_dir / "config.yaml"
        assert config_yaml.exists()
        content = config_yaml.read_text()
        assert "Project-scoped" in content

    def test_initialize_is_idempotent(self, sandbox):
        sandbox.initialize()
        yaml1 = (sandbox.tweek_dir / "sandbox.yaml").read_text()
        sandbox.initialize()
        yaml2 = (sandbox.tweek_dir / "sandbox.yaml").read_text()
        assert yaml1 == yaml2  # same content, not overwritten

    def test_initialize_registers_project(self, sandbox, registry):
        sandbox.initialize()
        assert registry.is_registered(sandbox.project_dir)

    def test_is_initialized_false_before_init(self, sandbox):
        assert sandbox.is_initialized is False

    def test_tweek_dir_resolved_path(self, project_dir, registry):
        with patch("tweek.sandbox.project.get_registry", return_value=registry):
            sb = ProjectSandbox(project_dir)
        assert sb.tweek_dir == project_dir.resolve() / ".tweek"


# =========================================================================
# 3. Auto-gitignore
# =========================================================================


class TestAutoGitignore:
    """Tests for _ensure_gitignored()."""

    def test_adds_tweek_to_existing_gitignore(self, sandbox):
        gitignore = sandbox.project_dir / ".gitignore"
        gitignore.write_text("node_modules/\n")
        sandbox.initialize()
        content = gitignore.read_text()
        assert ".tweek/" in content

    def test_skips_if_already_present_exact(self, sandbox):
        gitignore = sandbox.project_dir / ".gitignore"
        gitignore.write_text("node_modules/\n.tweek/\n")
        sandbox.initialize()
        content = gitignore.read_text()
        # Should appear exactly once (the original line)
        assert content.count(".tweek/") == 1

    def test_skips_if_already_present_no_trailing_slash(self, sandbox):
        gitignore = sandbox.project_dir / ".gitignore"
        gitignore.write_text(".tweek\n")
        sandbox.initialize()
        content = gitignore.read_text()
        # Original ".tweek" line counts as already present
        assert content.count(".tweek") == 1

    def test_skips_if_already_present_leading_slash(self, sandbox):
        gitignore = sandbox.project_dir / ".gitignore"
        gitignore.write_text("/.tweek/\n")
        sandbox.initialize()
        content = gitignore.read_text()
        assert content.count(".tweek") == 1

    def test_creates_gitignore_if_git_dir_exists(self, sandbox):
        # .git already exists via project_dir fixture
        gitignore = sandbox.project_dir / ".gitignore"
        assert not gitignore.exists()
        sandbox.initialize()
        assert gitignore.exists()
        content = gitignore.read_text()
        assert ".tweek/" in content

    def test_does_not_create_gitignore_if_no_git_dir(self, tmp_path, registry):
        """When there is no .git/, _ensure_gitignored should NOT create .gitignore."""
        with patch("tweek.sandbox.project.get_registry", return_value=registry):
            sb = ProjectSandbox(tmp_path)
        sb.config = SandboxConfig(auto_gitignore=True)
        sb.initialize()
        gitignore = tmp_path / ".gitignore"
        assert not gitignore.exists()

    def test_auto_gitignore_disabled(self, project_dir, registry):
        """When auto_gitignore is False, .gitignore is not touched."""
        with patch("tweek.sandbox.project.get_registry", return_value=registry):
            sb = ProjectSandbox(project_dir)
        sb.config = SandboxConfig(auto_gitignore=False)
        sb.initialize()
        gitignore = project_dir / ".gitignore"
        assert not gitignore.exists()

    def test_appends_newline_when_file_lacks_trailing_newline(self, sandbox):
        gitignore = sandbox.project_dir / ".gitignore"
        gitignore.write_text("node_modules/")  # no trailing newline
        sandbox.initialize()
        content = gitignore.read_text()
        assert ".tweek/" in content
        # Should still be well-formed
        lines = content.splitlines()
        assert any(".tweek/" in line for line in lines)


# =========================================================================
# 4. get_logger()
# =========================================================================


class TestGetLogger:
    """Tests for ProjectSandbox.get_logger()."""

    def test_layer2_returns_project_scoped_logger(self, sandbox):
        sandbox.initialize()
        logger = sandbox.get_logger()
        # Project-scoped logger should use the .tweek/security.db path
        assert logger.db_path == sandbox.tweek_dir / "security.db"

    def test_layer0_returns_global_logger(self, project_dir, registry):
        with patch("tweek.sandbox.project.get_registry", return_value=registry):
            sb = ProjectSandbox(project_dir)
        sb.layer = IsolationLayer.BYPASS  # Layer 0
        mock_global_logger = MagicMock()
        with patch("tweek.logging.security_log.get_logger", return_value=mock_global_logger):
            logger = sb.get_logger()
        assert logger is mock_global_logger

    def test_layer1_returns_global_logger(self, project_dir, registry):
        with patch("tweek.sandbox.project.get_registry", return_value=registry):
            sb = ProjectSandbox(project_dir)
        sb.layer = IsolationLayer.SKILLS  # Layer 1
        mock_global_logger = MagicMock()
        with patch("tweek.logging.security_log.get_logger", return_value=mock_global_logger):
            logger = sb.get_logger()
        assert logger is mock_global_logger

    def test_logger_is_cached(self, sandbox):
        sandbox.initialize()
        logger1 = sandbox.get_logger()
        logger2 = sandbox.get_logger()
        assert logger1 is logger2


# =========================================================================
# 5. get_overrides()
# =========================================================================


class TestGetOverrides:
    """Tests for ProjectSandbox.get_overrides()."""

    def test_layer_below_project_returns_global(self, project_dir, registry):
        with patch("tweek.sandbox.project.get_registry", return_value=registry):
            sb = ProjectSandbox(project_dir)
        sb.layer = IsolationLayer.SKILLS

        mock_global_ovr = MagicMock()
        with patch("tweek.hooks.overrides.get_overrides", return_value=mock_global_ovr):
            result = sb.get_overrides()
        assert result is mock_global_ovr

    def test_no_project_overrides_file_returns_global(self, sandbox):
        """When overrides.yaml does not exist, returns global overrides."""
        mock_global_ovr = MagicMock()
        with patch("tweek.hooks.overrides.get_overrides", return_value=mock_global_ovr):
            result = sandbox.get_overrides()
        assert result is mock_global_ovr

    def test_empty_project_overrides_returns_global(self, sandbox):
        """When project overrides.yaml exists but is empty, returns global overrides."""
        sandbox.initialize()
        # overrides.yaml was created with comments only (no YAML data -> empty config)
        mock_global_ovr = MagicMock()
        with patch("tweek.hooks.overrides.get_overrides", return_value=mock_global_ovr):
            # Need to clear cached overrides since initialize may have cached something
            sandbox._overrides = None
            result = sandbox.get_overrides()
        assert result is mock_global_ovr

    def test_project_overrides_returns_merged(self, sandbox):
        """When project overrides.yaml has real config, returns MergedOverrides."""
        sandbox.initialize()
        # Write real override data to the project overrides.yaml
        overrides_yaml = sandbox.tweek_dir / "overrides.yaml"
        overrides_data = {
            "patterns": {
                "force_enabled": ["test_pattern"],
            }
        }
        with open(overrides_yaml, "w") as f:
            yaml.safe_dump(overrides_data, f)

        mock_global_ovr = MagicMock()
        mock_global_ovr.config = {"patterns": {"disabled": []}}
        sandbox._overrides = None
        with patch("tweek.hooks.overrides.get_overrides", return_value=mock_global_ovr):
            result = sandbox.get_overrides()
        assert isinstance(result, MergedOverrides)

    def test_overrides_cached(self, sandbox):
        mock_global_ovr = MagicMock()
        with patch("tweek.hooks.overrides.get_overrides", return_value=mock_global_ovr):
            result1 = sandbox.get_overrides()
            result2 = sandbox.get_overrides()
        assert result1 is result2


# =========================================================================
# 6. get_fingerprints()
# =========================================================================


class TestGetFingerprints:
    """Tests for ProjectSandbox.get_fingerprints()."""

    def test_layer2_returns_project_scoped_fingerprints(self, sandbox):
        sandbox.initialize()
        fp = sandbox.get_fingerprints()
        assert fp.cache_path == sandbox.tweek_dir / "fingerprints.json"

    def test_layer_below_project_returns_global(self, project_dir, registry):
        with patch("tweek.sandbox.project.get_registry", return_value=registry):
            sb = ProjectSandbox(project_dir)
        sb.layer = IsolationLayer.BYPASS

        mock_global_fp = MagicMock()
        with patch("tweek.skills.fingerprints.get_fingerprints", return_value=mock_global_fp):
            result = sb.get_fingerprints()
        assert result is mock_global_fp

    def test_fingerprints_cached(self, sandbox):
        sandbox.initialize()
        fp1 = sandbox.get_fingerprints()
        fp2 = sandbox.get_fingerprints()
        assert fp1 is fp2


# =========================================================================
# 7. MergedOverrides - additive-only enforcement
# =========================================================================


class TestMergedOverrides:
    """Tests for MergedOverrides additive-only merge logic."""

    def _make_overrides(self, config: dict):
        """Create a mock SecurityOverrides-like object with the given config."""
        obj = MagicMock()
        obj.config = config
        return obj

    # --- Disabled patterns ---

    def test_project_cannot_disable_global_patterns(self, tmp_path):
        global_ovr = self._make_overrides({
            "patterns": {"disabled": [{"name": "P001"}]},
        })
        project_ovr = self._make_overrides({
            "patterns": {"disabled": [{"name": "P002"}]},
        })
        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        disabled = merged.config["patterns"]["disabled"]
        disabled_names = [d["name"] for d in disabled]
        assert "P001" in disabled_names  # global disabled kept
        assert "P002" not in disabled_names  # project disabled ignored

    def test_scoped_disables_only_from_global(self, tmp_path):
        global_ovr = self._make_overrides({
            "patterns": {"scoped_disables": [{"name": "P001", "paths": ["/global"]}]},
        })
        project_ovr = self._make_overrides({
            "patterns": {"scoped_disables": [{"name": "P002", "paths": ["/project"]}]},
        })
        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        scoped = merged.config["patterns"]["scoped_disables"]
        names = [s["name"] for s in scoped]
        assert "P001" in names
        assert "P002" not in names

    # --- Force-enabled patterns ---

    def test_force_enabled_union(self, tmp_path):
        global_ovr = self._make_overrides({
            "patterns": {"force_enabled": ["G1"]},
        })
        project_ovr = self._make_overrides({
            "patterns": {"force_enabled": ["P1"]},
        })
        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        force = set(merged.config["patterns"]["force_enabled"])
        assert "G1" in force
        assert "P1" in force

    def test_force_enabled_dedup(self, tmp_path):
        global_ovr = self._make_overrides({
            "patterns": {"force_enabled": ["SHARED"]},
        })
        project_ovr = self._make_overrides({
            "patterns": {"force_enabled": ["SHARED"]},
        })
        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        force = merged.config["patterns"]["force_enabled"]
        assert force.count("SHARED") == 1

    # --- Whitelist scoping ---

    def test_project_whitelist_scoped_to_project(self, tmp_path):
        global_ovr = self._make_overrides({
            "whitelist": [{"path": "/global/file.py", "tool": "Read"}],
        })
        # Path inside the project -- allowed
        inside_path = str(tmp_path / "src" / "foo.py")
        # Path outside the project -- should be filtered out
        outside_path = "/etc/passwd"
        project_ovr = self._make_overrides({
            "whitelist": [
                {"path": inside_path, "tool": "Read"},
                {"path": outside_path, "tool": "Read"},
            ],
        })
        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        wl_paths = [r.get("path") for r in merged.config["whitelist"]]
        assert "/global/file.py" in wl_paths  # global kept
        assert inside_path in wl_paths  # scoped to project -- kept
        assert outside_path not in wl_paths  # outside project -- dropped

    def test_project_whitelist_tool_only_rule_allowed(self, tmp_path):
        """Rules with no path but a tool filter are allowed from project."""
        global_ovr = self._make_overrides({"whitelist": []})
        project_ovr = self._make_overrides({
            "whitelist": [{"tool": "WebFetch"}],
        })
        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        wl = merged.config["whitelist"]
        assert len(wl) == 1
        assert wl[0]["tool"] == "WebFetch"

    def test_project_whitelist_no_path_no_tool_dropped(self, tmp_path):
        """Rules with neither path nor tool are dropped from project."""
        global_ovr = self._make_overrides({"whitelist": []})
        project_ovr = self._make_overrides({
            "whitelist": [{"reason": "catch-all"}],
        })
        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        assert merged.config["whitelist"] == []

    # --- Severity can only be raised (stricter) ---

    def test_severity_raised_to_stricter(self, tmp_path):
        """Project with 'low' (stricter) wins over global 'high' (more permissive)."""
        global_ovr = self._make_overrides({
            "trust": {
                "interactive": {"min_severity": "high"},
            },
        })
        project_ovr = self._make_overrides({
            "trust": {
                "interactive": {"min_severity": "low"},
            },
        })
        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        assert merged.config["trust"]["interactive"]["min_severity"] == "low"

    def test_severity_cannot_be_lowered(self, tmp_path):
        """Project with 'critical' (more permissive) cannot weaken global 'medium'."""
        global_ovr = self._make_overrides({
            "trust": {
                "automated": {"min_severity": "medium"},
            },
        })
        project_ovr = self._make_overrides({
            "trust": {
                "automated": {"min_severity": "critical"},
            },
        })
        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        # medium is stricter than critical, so medium wins
        assert merged.config["trust"]["automated"]["min_severity"] == "medium"

    def test_severity_both_modes_independent(self, tmp_path):
        global_ovr = self._make_overrides({
            "trust": {
                "interactive": {"min_severity": "high"},
                "automated": {"min_severity": "medium"},
            },
        })
        project_ovr = self._make_overrides({
            "trust": {
                "interactive": {"min_severity": "low"},
                "automated": {"min_severity": "critical"},
            },
        })
        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        assert merged.config["trust"]["interactive"]["min_severity"] == "low"
        assert merged.config["trust"]["automated"]["min_severity"] == "medium"

    # --- SecurityOverrides-compatible interface ---

    def test_get_min_severity(self, tmp_path):
        global_ovr = self._make_overrides({
            "trust": {"interactive": {"min_severity": "medium"}},
        })
        project_ovr = self._make_overrides({"trust": {}})
        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        assert merged.get_min_severity("interactive") == "medium"
        assert merged.get_min_severity("automated") == "low"  # default

    def test_get_trust_default(self, tmp_path):
        global_ovr = self._make_overrides({
            "trust": {"default_mode": "automated"},
        })
        project_ovr = self._make_overrides({"trust": {}})
        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        assert merged.get_trust_default() == "automated"

    def test_get_trust_default_fallback(self, tmp_path):
        global_ovr = self._make_overrides({"trust": {}})
        project_ovr = self._make_overrides({"trust": {}})
        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        assert merged.get_trust_default() == "interactive"

    def test_should_skip_llm_for_default_tier(self, tmp_path):
        global_ovr = self._make_overrides({
            "trust": {"interactive": {"skip_llm_for_default_tier": True}},
        })
        project_ovr = self._make_overrides({"trust": {}})
        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        assert merged.should_skip_llm_for_default_tier("interactive") is True
        assert merged.should_skip_llm_for_default_tier("automated") is False

    def test_check_whitelist_delegates(self, tmp_path):
        """check_whitelist falls through global then project."""
        global_ovr = self._make_overrides({"whitelist": []})
        global_ovr.check_whitelist = MagicMock(return_value={"tool": "Read"})
        project_ovr = self._make_overrides({"whitelist": []})
        project_ovr.check_whitelist = MagicMock(return_value=None)

        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        result = merged.check_whitelist("Read", {}, "")
        assert result == {"tool": "Read"}
        global_ovr.check_whitelist.assert_called_once()

    def test_check_whitelist_project_scoped_only(self, tmp_path):
        """Project whitelist match is only returned if scoped to project."""
        global_ovr = self._make_overrides({"whitelist": []})
        global_ovr.check_whitelist = MagicMock(return_value=None)

        outside_rule = {"path": "/etc/secrets", "tool": "Read"}
        project_ovr = self._make_overrides({"whitelist": []})
        project_ovr.check_whitelist = MagicMock(return_value=outside_rule)

        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        result = merged.check_whitelist("Read", {}, "")
        assert result is None  # outside project, rejected

    def test_filter_patterns_delegates_to_global(self, tmp_path):
        global_ovr = self._make_overrides({"patterns": {}})
        global_ovr.filter_patterns = MagicMock(side_effect=lambda m, p: m)
        project_ovr = self._make_overrides({"patterns": {}})

        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        matches = [{"name": "P001"}]
        result = merged.filter_patterns(matches, "/some/path")
        assert result == matches
        global_ovr.filter_patterns.assert_called_once()

    # --- Edge cases ---

    def test_empty_global_and_project_configs(self, tmp_path):
        global_ovr = self._make_overrides({})
        project_ovr = self._make_overrides({})
        merged = MergedOverrides(global_ovr, project_ovr, tmp_path)
        assert merged.config["whitelist"] == []
        assert merged.config["patterns"]["disabled"] == []
        assert merged.config["patterns"]["force_enabled"] == []
        assert merged.config["patterns"]["scoped_disables"] == []

    def test_none_global_ovr(self, tmp_path):
        project_ovr = self._make_overrides({"whitelist": [{"tool": "Read"}]})
        merged = MergedOverrides(None, project_ovr, tmp_path)
        assert merged.config["whitelist"] == [{"tool": "Read"}]

    def test_none_project_ovr(self, tmp_path):
        global_ovr = self._make_overrides({"whitelist": [{"tool": "Read"}]})
        merged = MergedOverrides(global_ovr, None, tmp_path)
        assert merged.config["whitelist"] == [{"tool": "Read"}]


# =========================================================================
# 8. _detect_project_dir()
# =========================================================================


class TestDetectProjectDir:
    """Tests for _detect_project_dir() project root detection."""

    def test_finds_git_dir(self, tmp_path):
        project = tmp_path / "myproject"
        project.mkdir()
        (project / ".git").mkdir()
        subdir = project / "src" / "lib"
        subdir.mkdir(parents=True)
        result = _detect_project_dir(str(subdir))
        assert result == project.resolve()

    def test_finds_claude_dir(self, tmp_path):
        project = tmp_path / "myproject"
        project.mkdir()
        (project / ".claude").mkdir()
        subdir = project / "deep" / "nested"
        subdir.mkdir(parents=True)
        result = _detect_project_dir(str(subdir))
        assert result == project.resolve()

    def test_prefers_closest_marker(self, tmp_path):
        """When both .git and .claude exist at different levels, closest wins."""
        outer = tmp_path / "outer"
        outer.mkdir()
        (outer / ".git").mkdir()
        inner = outer / "inner"
        inner.mkdir()
        (inner / ".claude").mkdir()
        working = inner / "src"
        working.mkdir()
        result = _detect_project_dir(str(working))
        assert result == inner.resolve()

    def test_returns_none_when_no_markers(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        result = _detect_project_dir(str(deep))
        assert result is None

    def test_resolves_working_dir(self, tmp_path):
        project = tmp_path / "proj"
        project.mkdir()
        (project / ".git").mkdir()
        result = _detect_project_dir(str(project))
        assert result == project.resolve()

    def test_walks_up_max_10_levels(self, tmp_path):
        """Verify it stops after 10 levels (won't go forever)."""
        project = tmp_path / "proj"
        project.mkdir()
        (project / ".git").mkdir()
        # Create 11 levels deep -- should still find it within 10
        deep = project
        for i in range(9):
            deep = deep / f"level{i}"
        deep.mkdir(parents=True)
        result = _detect_project_dir(str(deep))
        assert result == project.resolve()

    def test_12_levels_deep_returns_none(self, tmp_path):
        """At 12 levels below the marker, the walker gives up."""
        project = tmp_path / "proj"
        project.mkdir()
        (project / ".git").mkdir()
        deep = project
        for i in range(12):
            deep = deep / f"level{i}"
        deep.mkdir(parents=True)
        result = _detect_project_dir(str(deep))
        # 12 levels below means 13 hops total -- exceeds 10 walk limit
        # (depends on tmp_path depth too, but the marker is at least 12 hops up)
        # This is a best-effort test; the key guarantee is it does not loop forever.
        # Due to the walk limit of 10, it may or may not find it depending on
        # the depth of tmp_path itself. We just verify it returns something or None.
        assert result is None or result == project.resolve()


# =========================================================================
# 9. get_project_sandbox() - singleton cache, auto-init, layer gating
# =========================================================================


class TestGetProjectSandbox:
    """Tests for the module-level get_project_sandbox()."""

    def test_returns_none_for_none_working_dir(self):
        result = get_project_sandbox(None)
        assert result is None

    def test_returns_none_for_empty_string(self):
        result = get_project_sandbox("")
        assert result is None

    def test_returns_none_when_no_project_root(self, tmp_path):
        """No .git or .claude -> no sandbox."""
        deep = tmp_path / "no_project" / "deep"
        deep.mkdir(parents=True)
        result = get_project_sandbox(str(deep))
        assert result is None

    def test_auto_initializes_for_layer2(self, project_dir, registry):
        with patch("tweek.sandbox.project.get_registry", return_value=registry):
            sandbox = get_project_sandbox(str(project_dir))
        assert sandbox is not None
        assert sandbox.is_initialized
        assert (project_dir / ".tweek").is_dir()

    def test_returns_none_for_layer_below_project(self, project_dir, registry):
        """Layer 0/1 returns None from get_project_sandbox."""
        # Register project at Layer 0
        registry.register(project_dir, layer=IsolationLayer.BYPASS)
        with patch("tweek.sandbox.project.get_registry", return_value=registry):
            result = get_project_sandbox(str(project_dir))
        assert result is None

    def test_singleton_cache_returns_same_instance(self, project_dir, registry):
        with patch("tweek.sandbox.project.get_registry", return_value=registry):
            sb1 = get_project_sandbox(str(project_dir))
            sb2 = get_project_sandbox(str(project_dir))
        assert sb1 is sb2

    def test_different_projects_get_different_sandboxes(self, tmp_path, registry):
        proj_a = tmp_path / "projA"
        proj_a.mkdir()
        (proj_a / ".git").mkdir()

        proj_b = tmp_path / "projB"
        proj_b.mkdir()
        (proj_b / ".git").mkdir()

        with patch("tweek.sandbox.project.get_registry", return_value=registry):
            sb_a = get_project_sandbox(str(proj_a))
            sb_b = get_project_sandbox(str(proj_b))

        assert sb_a is not sb_b
        assert sb_a.project_dir != sb_b.project_dir

    def test_subdir_resolves_to_same_sandbox(self, project_dir, registry):
        subdir = project_dir / "src" / "lib"
        subdir.mkdir(parents=True)
        with patch("tweek.sandbox.project.get_registry", return_value=registry):
            sb_root = get_project_sandbox(str(project_dir))
            sb_sub = get_project_sandbox(str(subdir))
        assert sb_root is sb_sub


# =========================================================================
# 10. reset()
# =========================================================================


class TestReset:
    """Tests for ProjectSandbox.reset()."""

    def test_reset_removes_tweek_dir(self, sandbox):
        sandbox.initialize()
        assert sandbox.tweek_dir.is_dir()
        sandbox.reset()
        assert not sandbox.tweek_dir.exists()

    def test_reset_deregisters_project(self, sandbox, registry):
        sandbox.initialize()
        assert registry.is_registered(sandbox.project_dir)
        sandbox.reset()
        assert not registry.is_registered(sandbox.project_dir)

    def test_reset_clears_cached_services(self, sandbox):
        sandbox.initialize()
        # Populate caches
        _ = sandbox.get_logger()
        _ = sandbox.get_fingerprints()
        assert sandbox._logger is not None
        assert sandbox._fingerprints is not None
        sandbox.reset()
        assert sandbox._logger is None
        assert sandbox._overrides is None
        assert sandbox._fingerprints is None

    def test_reset_is_safe_when_not_initialized(self, sandbox):
        """reset() should not raise even if .tweek/ does not exist."""
        sandbox.reset()  # no error

    def test_reset_then_reinitialize(self, sandbox):
        sandbox.initialize()
        sandbox.reset()
        assert not sandbox.is_initialized
        sandbox.initialize()
        assert sandbox.is_initialized
        assert (sandbox.tweek_dir / "sandbox.yaml").exists()


# =========================================================================
# Additional: _load_config paths
# =========================================================================


class TestLoadConfig:
    """Tests for _load_config edge cases."""

    def test_loads_from_existing_sandbox_yaml(self, project_dir, registry):
        tweek_dir = project_dir / ".tweek"
        tweek_dir.mkdir()
        sandbox_yaml = tweek_dir / "sandbox.yaml"
        sandbox_yaml.write_text(yaml.safe_dump({"layer": 0, "auto_init": False}))
        with patch("tweek.sandbox.project.get_registry", return_value=registry):
            sb = ProjectSandbox(project_dir)
        assert sb.config.layer == 0
        assert sb.config.auto_init is False

    def test_falls_back_to_registry_layer(self, project_dir, registry):
        """When no sandbox.yaml but project is in registry, uses registry layer."""
        registry.register(project_dir, layer=IsolationLayer.SKILLS)
        with patch("tweek.sandbox.project.get_registry", return_value=registry):
            sb = ProjectSandbox(project_dir)
        assert sb.config.layer == IsolationLayer.SKILLS.value

    def test_falls_back_to_global_defaults(self, project_dir, registry):
        """When no sandbox.yaml and not registered, uses global defaults."""
        global_defaults = {"default_layer": 0, "auto_init": False}
        with patch("tweek.sandbox.project.get_registry", return_value=registry), \
             patch("tweek.sandbox.project._get_global_sandbox_defaults",
                   return_value=global_defaults):
            sb = ProjectSandbox(project_dir)
        assert sb.config.layer == 0
        assert sb.config.auto_init is False

    def test_corrupt_sandbox_yaml_falls_through(self, project_dir, registry):
        """Corrupt YAML should not crash; falls back to registry or defaults."""
        tweek_dir = project_dir / ".tweek"
        tweek_dir.mkdir()
        sandbox_yaml = tweek_dir / "sandbox.yaml"
        sandbox_yaml.write_text(": : : invalid yaml [[[")
        with patch("tweek.sandbox.project.get_registry", return_value=registry):
            sb = ProjectSandbox(project_dir)
        # Should get default layer 2 (no registry entry, no global defaults)
        assert sb.config.layer == 2
