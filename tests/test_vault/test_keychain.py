"""Tests for the Keychain vault."""

import pytest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tweek.vault.keychain import KeychainVault, VaultError


class TestKeychainVault:
    """Tests for KeychainVault."""

    @pytest.fixture
    def vault(self):
        """Create a vault instance."""
        return KeychainVault()

    @pytest.fixture
    def test_skill(self):
        """Test skill name (use unique name to avoid conflicts)."""
        return "tweek-test-skill"

    @pytest.fixture(autouse=True)
    def cleanup(self, vault, test_skill):
        """Clean up test credentials after each test."""
        yield
        # Delete any test credentials
        for key in vault.list_keys(test_skill):
            vault.delete(test_skill, key)

    def test_store_and_get(self, vault, test_skill):
        """Should store and retrieve a credential."""
        vault.store(test_skill, "TEST_KEY", "test_value_123")
        value = vault.get(test_skill, "TEST_KEY")
        assert value == "test_value_123"

    def test_get_nonexistent(self, vault, test_skill):
        """Should return None for nonexistent credential."""
        value = vault.get(test_skill, "NONEXISTENT_KEY")
        assert value is None

    def test_delete(self, vault, test_skill):
        """Should delete a credential."""
        vault.store(test_skill, "DELETE_ME", "value")
        assert vault.get(test_skill, "DELETE_ME") == "value"

        result = vault.delete(test_skill, "DELETE_ME")
        assert result is True
        assert vault.get(test_skill, "DELETE_ME") is None

    def test_delete_nonexistent(self, vault, test_skill):
        """Should return False for deleting nonexistent credential."""
        result = vault.delete(test_skill, "NONEXISTENT")
        assert result is False

    def test_list_keys(self, vault, test_skill):
        """Should list all keys for a skill."""
        vault.store(test_skill, "KEY1", "value1")
        vault.store(test_skill, "KEY2", "value2")

        keys = vault.list_keys(test_skill)
        assert "KEY1" in keys
        assert "KEY2" in keys

    def test_list_skills(self, vault, test_skill):
        """Should list all skills with credentials."""
        vault.store(test_skill, "KEY", "value")

        skills = vault.list_skills()
        assert test_skill in skills

    def test_get_all(self, vault, test_skill):
        """Should get all credentials for a skill."""
        vault.store(test_skill, "KEY1", "value1")
        vault.store(test_skill, "KEY2", "value2")

        creds = vault.get_all(test_skill)
        assert creds == {"KEY1": "value1", "KEY2": "value2"}

    def test_overwrite_existing(self, vault, test_skill):
        """Should overwrite existing credential."""
        vault.store(test_skill, "OVERWRITE", "original")
        vault.store(test_skill, "OVERWRITE", "updated")

        value = vault.get(test_skill, "OVERWRITE")
        assert value == "updated"

    def test_special_characters(self, vault, test_skill):
        """Should handle special characters in values."""
        special_value = 'secret"with$pecial&chars!'
        vault.store(test_skill, "SPECIAL", special_value)

        value = vault.get(test_skill, "SPECIAL")
        assert value == special_value

    def test_export_for_process(self, vault, test_skill):
        """Should return dict of credentials for subprocess env injection."""
        vault.store(test_skill, "API_KEY", "sk-123")
        vault.store(test_skill, "SECRET", "abc")

        env_dict = vault.export_for_process(test_skill)
        assert isinstance(env_dict, dict)
        assert env_dict["API_KEY"] == "sk-123"
        assert env_dict["SECRET"] == "abc"

    def test_service_name_format(self, vault):
        """Should use correct service name format."""
        service = vault._service_name("my-skill")
        assert service == "com.tweek.my-skill"


class TestEnvMigration:
    """Tests for .env file migration."""

    @pytest.fixture
    def vault(self):
        return KeychainVault()

    @pytest.fixture
    def test_skill(self):
        return "tweek-migration-test"

    @pytest.fixture
    def env_file(self, tmp_path):
        """Create a test .env file."""
        env_content = """
# Comment line
API_KEY=sk-test-123
SECRET_TOKEN="quoted-value"
EMPTY=
DATABASE_URL=postgres://user:pass@localhost/db

# Another comment
DEBUG=true
"""
        env_path = tmp_path / ".env"
        env_path.write_text(env_content)
        return env_path

    @pytest.fixture(autouse=True)
    def cleanup(self, vault, test_skill):
        yield
        for key in vault.list_keys(test_skill):
            vault.delete(test_skill, key)

    def test_migrate_dry_run(self, vault, test_skill, env_file):
        """Should report what would be migrated without storing."""
        migrated = vault.migrate_from_env(env_file, test_skill, dry_run=True)

        assert "API_KEY" in migrated
        assert "SECRET_TOKEN" in migrated
        assert "DATABASE_URL" in migrated
        assert "DEBUG" in migrated
        # EMPTY should be skipped
        assert "EMPTY" not in migrated

        # Nothing should actually be stored
        assert vault.get(test_skill, "API_KEY") is None

    def test_migrate_actual(self, vault, test_skill, env_file):
        """Should migrate credentials to vault."""
        migrated = vault.migrate_from_env(env_file, test_skill, dry_run=False)

        assert len(migrated) >= 4
        assert vault.get(test_skill, "API_KEY") == "sk-test-123"
        assert vault.get(test_skill, "SECRET_TOKEN") == "quoted-value"
        assert vault.get(test_skill, "DATABASE_URL") == "postgres://user:pass@localhost/db"

    def test_migrate_nonexistent_file(self, vault, test_skill, tmp_path):
        """Should raise error for nonexistent file."""
        with pytest.raises(VaultError):
            vault.migrate_from_env(tmp_path / "nonexistent.env", test_skill)
