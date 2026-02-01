"""Tests for the sandbox profile generator."""

import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tweek.sandbox.profile_generator import ProfileGenerator, SkillManifest

pytestmark = pytest.mark.sandbox


class TestSkillManifest:
    """Tests for SkillManifest."""

    def test_default_manifest(self):
        """Should create restrictive default manifest."""
        manifest = SkillManifest.default("test")

        assert manifest.name == "test"
        assert "./" in manifest.read_paths
        assert "./" in manifest.write_paths
        assert "~/.ssh" in manifest.deny_paths
        assert manifest.network_deny_all is True

    def test_from_yaml(self, tmp_path):
        """Should parse YAML manifest."""
        manifest_content = """
name: my-skill
version: "2.0"

permissions:
  filesystem:
    read:
      - ./data
      - /usr/lib
    write:
      - ./output
    deny:
      - ~/.aws
  network:
    allow:
      - api.example.com
    deny_all: true
  process:
    subprocess: false

credentials:
  - API_KEY
  - SECRET_TOKEN
"""
        manifest_path = tmp_path / "manifest.yaml"
        manifest_path.write_text(manifest_content)

        manifest = SkillManifest.from_yaml(manifest_path)

        assert manifest.name == "my-skill"
        assert manifest.version == "2.0"
        assert "./data" in manifest.read_paths
        assert "./output" in manifest.write_paths
        assert "~/.aws" in manifest.deny_paths
        assert "api.example.com" in manifest.network_allow
        assert manifest.network_deny_all is True
        assert "API_KEY" in manifest.credentials

    def test_from_yaml_missing_file(self, tmp_path):
        """Should raise error for missing file."""
        with pytest.raises(FileNotFoundError):
            SkillManifest.from_yaml(tmp_path / "nonexistent.yaml")


class TestProfileGenerator:
    """Tests for ProfileGenerator."""

    @pytest.fixture
    def generator(self, tmp_path):
        """Create generator with temp profiles dir."""
        return ProfileGenerator(profiles_dir=tmp_path / "profiles")

    @pytest.fixture
    def manifest(self):
        """Create test manifest."""
        return SkillManifest(
            name="test-skill",
            version="1.0",
            read_paths=["./", "/opt/data"],
            write_paths=["./output"],
            deny_paths=["~/.secrets"],
            network_allow=["api.example.com"],
            network_deny_all=True,
        )

    def test_generate_basic(self, generator, manifest):
        """Should generate valid profile."""
        profile = generator.generate(manifest)

        assert "(version 1)" in profile
        assert "(deny default)" in profile
        assert "test-skill" in profile

    def test_generate_includes_read_paths(self, generator, manifest):
        """Should include read paths."""
        profile = generator.generate(manifest)

        assert '(allow file-read*' in profile
        assert '/opt/data' in profile

    def test_generate_includes_write_paths(self, generator, manifest):
        """Should include write paths."""
        profile = generator.generate(manifest)

        assert '(allow file-write*' in profile

    def test_generate_includes_deny_paths(self, generator, manifest):
        """Should include deny paths."""
        profile = generator.generate(manifest)

        assert '(deny file-read*' in profile
        # Should deny SSH always
        assert '.ssh' in profile

    def test_generate_network_rules(self, generator, manifest):
        """Should include network rules."""
        profile = generator.generate(manifest)

        assert 'api.example.com' in profile
        assert '(allow network-outbound' in profile

    def test_always_denies_sensitive_paths(self, generator):
        """Should always deny sensitive paths regardless of manifest."""
        manifest = SkillManifest(
            name="permissive",
            read_paths=["/"],  # Try to allow everything
        )
        profile = generator.generate(manifest)

        # These should ALWAYS be denied
        assert '.ssh' in profile
        assert '(deny file-read*' in profile

    def test_save_creates_file(self, generator, manifest):
        """Should save profile to disk."""
        profile_path = generator.save(manifest)

        assert profile_path.exists()
        assert profile_path.suffix == ".sb"
        assert "test-skill" in profile_path.name

    def test_get_profile_path(self, generator, manifest):
        """Should find existing profile."""
        generator.save(manifest)

        path = generator.get_profile_path("test-skill")
        assert path is not None
        assert path.exists()

    def test_get_profile_path_missing(self, generator):
        """Should return None for missing profile."""
        path = generator.get_profile_path("nonexistent")
        assert path is None

    def test_wrap_command(self, generator, manifest):
        """Should wrap command with sandbox-exec."""
        generator.save(manifest)

        wrapped = generator.wrap_command("python3 script.py", "test-skill")

        assert "sandbox-exec" in wrapped
        assert "test-skill.sb" in wrapped
        assert "python3 script.py" in wrapped

    def test_wrap_command_generates_default(self, generator):
        """Should generate default profile if missing."""
        wrapped = generator.wrap_command(
            "python3 script.py",
            "new-skill",
            generate_if_missing=True
        )

        assert "sandbox-exec" in wrapped
        assert "new-skill.sb" in wrapped

        # Profile should now exist
        path = generator.get_profile_path("new-skill")
        assert path is not None

    def test_wrap_command_no_generate(self, generator):
        """Should return original command if no profile and not generating."""
        wrapped = generator.wrap_command(
            "python3 script.py",
            "missing-skill",
            generate_if_missing=False
        )

        assert wrapped == "python3 script.py"
        assert "sandbox-exec" not in wrapped

    def test_list_profiles(self, generator, manifest):
        """Should list all profiles."""
        generator.save(manifest)

        manifest2 = SkillManifest(name="other-skill")
        generator.save(manifest2)

        profiles = generator.list_profiles()

        assert "test-skill" in profiles
        assert "other-skill" in profiles

    def test_delete_profile(self, generator, manifest):
        """Should delete profile."""
        generator.save(manifest)
        assert generator.get_profile_path("test-skill") is not None

        result = generator.delete_profile("test-skill")

        assert result is True
        assert generator.get_profile_path("test-skill") is None

    def test_delete_profile_missing(self, generator):
        """Should return False for missing profile."""
        result = generator.delete_profile("nonexistent")
        assert result is False


class TestProfileContent:
    """Tests for generated profile content validity."""

    @pytest.fixture
    def generator(self, tmp_path):
        return ProfileGenerator(profiles_dir=tmp_path / "profiles")

    def test_profile_starts_with_version(self, generator):
        """Profile should start with version declaration."""
        manifest = SkillManifest.default("test")
        profile = generator.generate(manifest)

        # Find version line (after comments)
        lines = [l for l in profile.split("\n") if l and not l.startswith(";")]
        assert lines[0] == "(version 1)"

    def test_profile_has_deny_default(self, generator):
        """Profile should have deny-default policy."""
        manifest = SkillManifest.default("test")
        profile = generator.generate(manifest)

        assert "(deny default)" in profile

    def test_network_deny_all(self, generator):
        """Should deny all network if specified."""
        manifest = SkillManifest(
            name="no-network",
            network_deny_all=True,
            network_allow=[],
        )
        profile = generator.generate(manifest)

        assert "(deny network*)" in profile
