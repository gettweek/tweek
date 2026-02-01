#!/usr/bin/env python3
"""
Tests for Tweek configuration manager.

Tests coverage of:
- Tool and skill tier configuration
- Presets (paranoid, cautious, trusted)
- Config persistence (user and project scope)
- Config merging and priority
"""

import pytest
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

pytestmark = pytest.mark.config

from tweek.config.manager import ConfigManager, SecurityTier, ToolConfig, SkillConfig


class TestSecurityTier:
    """Tests for SecurityTier enum."""

    def test_tier_values(self):
        """Test security tier enum values."""
        assert SecurityTier.SAFE.value == "safe"
        assert SecurityTier.DEFAULT.value == "default"
        assert SecurityTier.RISKY.value == "risky"
        assert SecurityTier.DANGEROUS.value == "dangerous"

    def test_from_string(self):
        """Test creating tier from string."""
        assert SecurityTier.from_string("safe") == SecurityTier.SAFE
        assert SecurityTier.from_string("default") == SecurityTier.DEFAULT
        assert SecurityTier.from_string("risky") == SecurityTier.RISKY
        assert SecurityTier.from_string("dangerous") == SecurityTier.DANGEROUS

    def test_from_string_invalid(self):
        """Test from_string with invalid value."""
        assert SecurityTier.from_string("invalid") == SecurityTier.DEFAULT

    def test_tier_ordering(self):
        """Test tier ordering for comparison."""
        tiers = [SecurityTier.SAFE, SecurityTier.DEFAULT, SecurityTier.RISKY, SecurityTier.DANGEROUS]
        # Each tier should have increasing security level
        assert tiers == sorted(tiers, key=lambda t: ["safe", "default", "risky", "dangerous"].index(t.value))


class TestToolConfig:
    """Tests for ToolConfig dataclass."""

    def test_create_tool_config(self):
        """Test creating tool config."""
        config = ToolConfig(
            name="Bash",
            tier=SecurityTier.DANGEROUS,
            source="default",
            description="Shell commands"
        )

        assert config.name == "Bash"
        assert config.tier == SecurityTier.DANGEROUS
        assert config.source == "default"


class TestConfigManagerInit:
    """Tests for ConfigManager initialization."""

    @pytest.fixture
    def config_manager(self, tmp_path):
        """Create ConfigManager with temp paths."""
        (tmp_path / ".tweek").mkdir(exist_ok=True)
        manager = ConfigManager(
            user_config_path=tmp_path / ".tweek" / "config.yaml",
            project_config_path=tmp_path / ".tweek" / "project_config.yaml"
        )
        yield manager

    def test_loads_default_tiers(self, config_manager):
        """Test that default tiers are loaded."""
        # Should have some default tools configured
        tools = config_manager.list_tools()
        tool_names = [t.name for t in tools]

        # Common tools should be configured
        assert "Bash" in tool_names or len(tools) > 0

    def test_default_tier(self, config_manager):
        """Test getting default tier."""
        tier = config_manager.get_default_tier()
        assert isinstance(tier, SecurityTier)


class TestToolConfiguration:
    """Tests for tool tier configuration."""

    @pytest.fixture
    def config_manager(self, tmp_path):
        """Create ConfigManager with temp paths."""
        (tmp_path / ".tweek").mkdir(exist_ok=True)
        # Pass explicit paths to avoid class-level Path.home() evaluation
        manager = ConfigManager(
            user_config_path=tmp_path / ".tweek" / "config.yaml",
            project_config_path=tmp_path / ".tweek" / "project_config.yaml"
        )
        yield manager

    def test_get_tool_tier_default(self, config_manager):
        """Test getting tier for unknown tool returns default."""
        tier = config_manager.get_tool_tier("UnknownTool")
        assert tier == config_manager.get_default_tier()

    def test_set_tool_tier(self, config_manager):
        """Test setting tool tier."""
        config_manager.set_tool_tier("TestTool", SecurityTier.DANGEROUS)

        tier = config_manager.get_tool_tier("TestTool")
        assert tier == SecurityTier.DANGEROUS

    def test_set_tool_tier_user_scope(self, config_manager):
        """Test setting tool tier in user scope."""
        config_manager.set_tool_tier("TestTool", SecurityTier.RISKY, scope="user")

        # Should be persisted to user config
        user_config = config_manager.export_config("user")
        assert "TestTool" in user_config.get("tools", {})

    def test_reset_tool(self, config_manager):
        """Test resetting tool to default."""
        # First set a custom tier
        config_manager.set_tool_tier("TestTool", SecurityTier.DANGEROUS, scope="user")

        # Then reset
        result = config_manager.reset_tool("TestTool", scope="user")

        assert result is True
        # Should fall back to default
        tier = config_manager.get_tool_tier("TestTool")
        assert tier == config_manager.get_default_tier()


class TestSkillConfiguration:
    """Tests for skill tier configuration."""

    @pytest.fixture
    def config_manager(self, tmp_path):
        """Create ConfigManager with temp paths."""
        (tmp_path / ".tweek").mkdir(exist_ok=True)
        # Pass explicit paths to avoid class-level Path.home() evaluation
        manager = ConfigManager(
            user_config_path=tmp_path / ".tweek" / "config.yaml",
            project_config_path=tmp_path / ".tweek" / "project_config.yaml"
        )
        yield manager

    def test_get_skill_tier_default(self, config_manager):
        """Test getting tier for unknown skill returns default."""
        tier = config_manager.get_skill_tier("unknown-skill")
        assert tier == config_manager.get_default_tier()

    def test_set_skill_tier(self, config_manager):
        """Test setting skill tier."""
        config_manager.set_skill_tier("my-skill", SecurityTier.SAFE)

        tier = config_manager.get_skill_tier("my-skill")
        assert tier == SecurityTier.SAFE

    def test_reset_skill(self, config_manager):
        """Test resetting skill to default."""
        config_manager.set_skill_tier("my-skill", SecurityTier.RISKY, scope="user")

        result = config_manager.reset_skill("my-skill", scope="user")

        assert result is True


class TestPresets:
    """Tests for configuration presets."""

    @pytest.fixture
    def config_manager(self, tmp_path):
        """Create ConfigManager with temp paths."""
        (tmp_path / ".tweek").mkdir(exist_ok=True)
        manager = ConfigManager(
            user_config_path=tmp_path / ".tweek" / "config.yaml",
            project_config_path=tmp_path / ".tweek" / "project_config.yaml"
        )
        yield manager

    def test_apply_paranoid_preset(self, config_manager):
        """Test applying paranoid preset."""
        config_manager.apply_preset("paranoid")

        # Paranoid should make Bash dangerous
        bash_tier = config_manager.get_tool_tier("Bash")
        assert bash_tier == SecurityTier.DANGEROUS

    def test_apply_cautious_preset(self, config_manager):
        """Test applying cautious preset."""
        config_manager.apply_preset("cautious")

        # Cautious is balanced - check it doesn't error
        tier = config_manager.get_default_tier()
        assert isinstance(tier, SecurityTier)

    def test_apply_trusted_preset(self, config_manager):
        """Test applying trusted preset."""
        config_manager.apply_preset("trusted")

        # Trusted should be more permissive
        tier = config_manager.get_default_tier()
        assert isinstance(tier, SecurityTier)

    def test_apply_invalid_preset(self, config_manager):
        """Test applying invalid preset."""
        with pytest.raises((ValueError, KeyError)):
            config_manager.apply_preset("invalid_preset")


class TestConfigPersistence:
    """Tests for config persistence."""

    @pytest.fixture
    def config_manager(self, tmp_path):
        """Create ConfigManager with temp paths."""
        (tmp_path / ".tweek").mkdir(exist_ok=True)
        manager = ConfigManager(
            user_config_path=tmp_path / ".tweek" / "config.yaml",
            project_config_path=tmp_path / ".tweek" / "project_config.yaml"
        )
        yield manager, tmp_path

    def test_export_config_user(self, config_manager):
        """Test exporting user config."""
        manager, tmp_path = config_manager

        # Set some config
        manager.set_tool_tier("TestTool", SecurityTier.RISKY, scope="user")

        # Export
        config = manager.export_config("user")

        assert "tools" in config or "TestTool" in str(config)

    def test_config_file_created(self, config_manager):
        """Test that config file is created on save."""
        manager, tmp_path = config_manager

        manager.set_tool_tier("TestTool", SecurityTier.DANGEROUS, scope="user")

        # Check file exists
        config_file = tmp_path / ".tweek" / "config.yaml"
        assert config_file.exists()

    def test_config_roundtrip(self, config_manager):
        """Test config survives save/load cycle."""
        manager, tmp_path = config_manager

        # Set config
        manager.set_tool_tier("RoundtripTool", SecurityTier.RISKY, scope="user")
        manager.set_skill_tier("roundtrip-skill", SecurityTier.SAFE, scope="user")

        # Create new manager (simulates reload) with same paths
        new_manager = ConfigManager(
            user_config_path=tmp_path / ".tweek" / "config.yaml",
            project_config_path=tmp_path / ".tweek" / "project_config.yaml"
        )

        # Check config persisted
        assert new_manager.get_tool_tier("RoundtripTool") == SecurityTier.RISKY
        assert new_manager.get_skill_tier("roundtrip-skill") == SecurityTier.SAFE


class TestConfigMerging:
    """Tests for config merging (default < user < project)."""

    @pytest.fixture
    def config_manager(self, tmp_path):
        """Create ConfigManager with temp paths."""
        (tmp_path / ".tweek").mkdir(exist_ok=True)
        manager = ConfigManager(
            user_config_path=tmp_path / ".tweek" / "config.yaml",
            project_config_path=tmp_path / ".tweek" / "project_config.yaml"
        )
        yield manager, tmp_path

    def test_user_overrides_default(self, config_manager):
        """Test user config overrides default."""
        manager, tmp_path = config_manager

        # Get default tier for Bash (likely dangerous)
        # Then override in user config
        manager.set_tool_tier("Bash", SecurityTier.SAFE, scope="user")

        # User config should take precedence
        tier = manager.get_tool_tier("Bash")
        assert tier == SecurityTier.SAFE

    def test_project_overrides_user(self, config_manager):
        """Test project config overrides user."""
        manager, tmp_path = config_manager

        # Set user config
        manager.set_tool_tier("TestTool", SecurityTier.SAFE, scope="user")

        # Set project config (higher priority)
        manager.set_tool_tier("TestTool", SecurityTier.DANGEROUS, scope="project")

        # Project should win
        tier = manager.get_tool_tier("TestTool")
        assert tier == SecurityTier.DANGEROUS


class TestListFunctions:
    """Tests for listing tools and skills."""

    @pytest.fixture
    def config_manager(self, tmp_path):
        """Create ConfigManager with temp paths."""
        (tmp_path / ".tweek").mkdir(exist_ok=True)
        manager = ConfigManager(
            user_config_path=tmp_path / ".tweek" / "config.yaml",
            project_config_path=tmp_path / ".tweek" / "project_config.yaml"
        )
        yield manager

    def test_list_tools(self, config_manager):
        """Test listing all tools."""
        tools = config_manager.list_tools()

        assert isinstance(tools, list)
        for tool in tools:
            assert isinstance(tool, ToolConfig)
            assert tool.name is not None
            assert isinstance(tool.tier, SecurityTier)

    def test_list_skills(self, config_manager):
        """Test listing all skills."""
        # Add some skills first
        config_manager.set_skill_tier("skill1", SecurityTier.SAFE)
        config_manager.set_skill_tier("skill2", SecurityTier.RISKY)

        skills = config_manager.list_skills()

        assert isinstance(skills, list)
        skill_names = [s.name for s in skills]
        assert "skill1" in skill_names
        assert "skill2" in skill_names

    def test_get_unknown_skills(self, config_manager):
        """Test finding skills not in config."""
        # Set up some known skills
        config_manager.set_skill_tier("known-skill", SecurityTier.SAFE)

        # Check for unknown
        detected = ["known-skill", "unknown-skill-1", "unknown-skill-2"]
        unknown = config_manager.get_unknown_skills(detected)

        assert "unknown-skill-1" in unknown
        assert "unknown-skill-2" in unknown
        assert "known-skill" not in unknown


class TestResetAll:
    """Tests for resetting all config."""

    @pytest.fixture
    def config_manager(self, tmp_path):
        """Create ConfigManager with temp paths."""
        (tmp_path / ".tweek").mkdir(exist_ok=True)
        manager = ConfigManager(
            user_config_path=tmp_path / ".tweek" / "config.yaml",
            project_config_path=tmp_path / ".tweek" / "project_config.yaml"
        )
        yield manager, tmp_path

    def test_reset_all_user(self, config_manager):
        """Test resetting all user config."""
        manager, tmp_path = config_manager

        # Set some config
        manager.set_tool_tier("Tool1", SecurityTier.DANGEROUS, scope="user")
        manager.set_skill_tier("skill1", SecurityTier.RISKY, scope="user")

        # Reset all
        manager.reset_all(scope="user")

        # Check reset
        user_config = manager.export_config("user")
        assert user_config.get("tools", {}) == {}
        assert user_config.get("skills", {}) == {}
