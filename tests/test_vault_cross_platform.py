"""Tests for the cross-platform vault (tweek.vault.cross_platform).

Covers:
- StoredCredential dataclass
- CrossPlatformVault init, validation, service name, logging
- store / get / delete / list_keys / get_all / export_for_process
- migrate_env_to_vault() function
- get_vault() factory function

All keyring operations are mocked — the real system keyring is never touched.
"""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, call

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

pytestmark = pytest.mark.security


# ---------------------------------------------------------------------------
# Helpers — provide a fake PasswordDeleteError when keyring is not installed
# ---------------------------------------------------------------------------

try:
    from keyring.errors import PasswordDeleteError
except ImportError:
    class PasswordDeleteError(Exception):
        """Stand-in for keyring.errors.PasswordDeleteError in test env."""


# ---------------------------------------------------------------------------
# 1. TestStoredCredential
# ---------------------------------------------------------------------------

class TestStoredCredential:
    """Validate the StoredCredential dataclass."""

    def test_create_stored_credential(self):
        from tweek.vault.cross_platform import StoredCredential

        cred = StoredCredential(skill="my-skill", key="API_KEY", value="secret123")
        assert cred.skill == "my-skill"
        assert cred.key == "API_KEY"
        assert cred.value == "secret123"

    def test_stored_credential_equality(self):
        from tweek.vault.cross_platform import StoredCredential

        a = StoredCredential(skill="s", key="k", value="v")
        b = StoredCredential(skill="s", key="k", value="v")
        assert a == b

    def test_stored_credential_different_values(self):
        from tweek.vault.cross_platform import StoredCredential

        a = StoredCredential(skill="s", key="k", value="v1")
        b = StoredCredential(skill="s", key="k", value="v2")
        assert a != b


# ---------------------------------------------------------------------------
# 2. TestCrossPlatformVaultInit
# ---------------------------------------------------------------------------

class TestCrossPlatformVaultInit:
    """Test CrossPlatformVault.__init__."""

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_init_success(self, mock_backend):
        from tweek.vault.cross_platform import CrossPlatformVault

        vault = CrossPlatformVault()
        assert vault.backend_name == "macOS Keychain"
        mock_backend.assert_called_once()

    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", False)
    def test_init_keyring_not_available(self):
        from tweek.vault.cross_platform import CrossPlatformVault

        with pytest.raises(RuntimeError, match="keyring library not installed"):
            CrossPlatformVault()

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="Secret Service (GNOME Keyring/KWallet)")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_init_linux_backend(self, mock_backend):
        from tweek.vault.cross_platform import CrossPlatformVault

        vault = CrossPlatformVault()
        assert vault.backend_name == "Secret Service (GNOME Keyring/KWallet)"


# ---------------------------------------------------------------------------
# 3. TestValidateName
# ---------------------------------------------------------------------------

class TestValidateName:
    """Test CrossPlatformVault._validate_name static method."""

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_valid_alphanumeric(self, _backend):
        from tweek.vault.cross_platform import CrossPlatformVault

        # Should not raise
        CrossPlatformVault._validate_name("my-skill_01", "skill")

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_valid_single_char(self, _backend):
        from tweek.vault.cross_platform import CrossPlatformVault

        CrossPlatformVault._validate_name("a")

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_empty_string_raises(self, _backend):
        from tweek.vault.cross_platform import CrossPlatformVault

        with pytest.raises(ValueError, match="Invalid vault"):
            CrossPlatformVault._validate_name("", "skill")

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_special_chars_raise(self, _backend):
        from tweek.vault.cross_platform import CrossPlatformVault

        with pytest.raises(ValueError, match="Invalid vault"):
            CrossPlatformVault._validate_name("skill.name", "skill")

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_spaces_raise(self, _backend):
        from tweek.vault.cross_platform import CrossPlatformVault

        with pytest.raises(ValueError, match="Invalid vault"):
            CrossPlatformVault._validate_name("my skill", "skill")

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_too_long_raises(self, _backend):
        from tweek.vault.cross_platform import CrossPlatformVault

        long_name = "a" * 65  # max 64
        with pytest.raises(ValueError, match="Invalid vault"):
            CrossPlatformVault._validate_name(long_name)

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_max_length_valid(self, _backend):
        from tweek.vault.cross_platform import CrossPlatformVault

        name_64 = "a" * 64
        CrossPlatformVault._validate_name(name_64)  # should not raise

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_none_raises(self, _backend):
        from tweek.vault.cross_platform import CrossPlatformVault

        with pytest.raises((ValueError, TypeError)):
            CrossPlatformVault._validate_name(None, "skill")

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_slash_raises(self, _backend):
        from tweek.vault.cross_platform import CrossPlatformVault

        with pytest.raises(ValueError, match="Invalid vault"):
            CrossPlatformVault._validate_name("path/traversal", "key")


# ---------------------------------------------------------------------------
# 4. TestServiceName
# ---------------------------------------------------------------------------

class TestServiceName:
    """Test CrossPlatformVault._service_name."""

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_service_name_format(self, _backend):
        from tweek.vault.cross_platform import CrossPlatformVault

        vault = CrossPlatformVault()
        assert vault._service_name("my-skill") == "tweek.my-skill"

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_service_name_validates_skill(self, _backend):
        from tweek.vault.cross_platform import CrossPlatformVault

        vault = CrossPlatformVault()
        with pytest.raises(ValueError, match="Invalid vault skill"):
            vault._service_name("bad skill name!")

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_service_name_uses_prefix(self, _backend):
        from tweek.vault.cross_platform import CrossPlatformVault, SERVICE_PREFIX

        vault = CrossPlatformVault()
        result = vault._service_name("test")
        assert result.startswith(SERVICE_PREFIX + ".")


# ---------------------------------------------------------------------------
# Shared fixture: mocked vault ready for store/get/delete tests
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_vault():
    """Return a CrossPlatformVault with keyring fully mocked."""
    with patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True), \
         patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain"):
        from tweek.vault.cross_platform import CrossPlatformVault
        vault = CrossPlatformVault()
    return vault


# ---------------------------------------------------------------------------
# 5. TestStore
# ---------------------------------------------------------------------------

class TestStore:
    """Test CrossPlatformVault.store."""

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.set_password")
    def test_store_success(self, mock_set, mock_log, mock_vault):
        result = mock_vault.store("myskill", "API_KEY", "secret123")

        assert result is True
        mock_set.assert_called_once_with("tweek.myskill", "API_KEY", "secret123")
        mock_log.assert_called_once_with("store", "myskill", "API_KEY", success=True)

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.set_password", side_effect=Exception("backend locked"))
    def test_store_keyring_exception(self, mock_set, mock_log, mock_vault, capsys):
        result = mock_vault.store("myskill", "API_KEY", "secret123")

        assert result is False
        mock_log.assert_called_once_with(
            "store", "myskill", "API_KEY", success=False, error="backend locked"
        )
        captured = capsys.readouterr()
        assert "Failed to store credential" in captured.out

    @patch("keyring.set_password")
    def test_store_invalid_skill_name(self, mock_set, mock_vault, capsys):
        """Invalid skill name is caught by the try/except, returns False."""
        result = mock_vault.store("bad skill!", "KEY", "val")
        assert result is False
        mock_set.assert_not_called()
        captured = capsys.readouterr()
        assert "Failed to store credential" in captured.out

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.set_password")
    def test_store_returns_true(self, mock_set, mock_log, mock_vault):
        assert mock_vault.store("skill", "K", "V") is True


# ---------------------------------------------------------------------------
# 6. TestGet
# ---------------------------------------------------------------------------

class TestGet:
    """Test CrossPlatformVault.get."""

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.get_password", return_value="the-secret")
    def test_get_success(self, mock_get, mock_log, mock_vault):
        result = mock_vault.get("myskill", "API_KEY")

        assert result == "the-secret"
        mock_get.assert_called_once_with("tweek.myskill", "API_KEY")
        mock_log.assert_called_once_with("get", "myskill", "API_KEY", success=True)

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.get_password", return_value=None)
    def test_get_not_found(self, mock_get, mock_log, mock_vault):
        result = mock_vault.get("myskill", "MISSING")

        assert result is None
        mock_log.assert_called_once_with("get", "myskill", "MISSING", success=False)

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.get_password", side_effect=Exception("backend error"))
    def test_get_keyring_exception(self, mock_get, mock_log, mock_vault):
        result = mock_vault.get("myskill", "KEY")

        assert result is None
        mock_log.assert_called_once_with(
            "get", "myskill", "KEY", success=False, error="backend error"
        )

    @patch("keyring.get_password")
    def test_get_invalid_skill_name(self, mock_get, mock_vault):
        """Invalid skill name is caught by try/except, returns None."""
        result = mock_vault.get("bad name!", "KEY")
        assert result is None
        mock_get.assert_not_called()


# ---------------------------------------------------------------------------
# 7. TestDelete
# ---------------------------------------------------------------------------

class TestDelete:
    """Test CrossPlatformVault.delete."""

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.delete_password")
    def test_delete_success(self, mock_del, mock_log, mock_vault):
        result = mock_vault.delete("myskill", "API_KEY")

        assert result is True
        mock_del.assert_called_once_with("tweek.myskill", "API_KEY")
        mock_log.assert_called_once_with("delete", "myskill", "API_KEY", success=True)

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.delete_password", side_effect=PasswordDeleteError("not found"))
    def test_delete_not_found(self, mock_del, mock_log, mock_vault):
        # Ensure PasswordDeleteError is accessible in the module namespace
        with patch("tweek.vault.cross_platform.PasswordDeleteError", PasswordDeleteError):
            result = mock_vault.delete("myskill", "MISSING")

        assert result is False
        mock_log.assert_called_once_with(
            "delete", "myskill", "MISSING", success=False, error="not found"
        )

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.delete_password", side_effect=RuntimeError("backend crash"))
    def test_delete_other_exception(self, mock_del, mock_log, mock_vault):
        result = mock_vault.delete("myskill", "KEY")

        assert result is False
        mock_log.assert_called_once_with(
            "delete", "myskill", "KEY", success=False, error="backend crash"
        )

    @patch("keyring.delete_password")
    def test_delete_invalid_skill(self, mock_del, mock_vault):
        """Invalid skill name is caught by try/except, returns False."""
        result = mock_vault.delete("invalid skill!", "KEY")
        assert result is False
        mock_del.assert_not_called()


# ---------------------------------------------------------------------------
# 8. TestListKeysAndGetAll
# ---------------------------------------------------------------------------

class TestListKeysAndGetAll:
    """Test the stub list_keys and get_all methods."""

    def test_list_keys_returns_empty(self, mock_vault):
        result = mock_vault.list_keys("any-skill")
        assert result == []
        assert isinstance(result, list)

    def test_get_all_returns_empty(self, mock_vault):
        result = mock_vault.get_all("any-skill")
        assert result == {}
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# 9. TestExportForProcess
# ---------------------------------------------------------------------------

class TestExportForProcess:
    """Test CrossPlatformVault.export_for_process."""

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.get_password")
    def test_export_multiple_keys(self, mock_get, mock_log, mock_vault):
        mock_get.side_effect = lambda svc, key: {
            "API_KEY": "sk-123",
            "SECRET": "abc",
        }.get(key)

        result = mock_vault.export_for_process("myskill", ["API_KEY", "SECRET"])

        assert result == {"API_KEY": "sk-123", "SECRET": "abc"}

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.get_password")
    def test_export_filters_missing(self, mock_get, mock_log, mock_vault):
        mock_get.side_effect = lambda svc, key: {
            "API_KEY": "sk-123",
        }.get(key)

        result = mock_vault.export_for_process("myskill", ["API_KEY", "MISSING_KEY"])

        assert result == {"API_KEY": "sk-123"}
        assert "MISSING_KEY" not in result

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.get_password", return_value=None)
    def test_export_empty_list(self, mock_get, mock_log, mock_vault):
        result = mock_vault.export_for_process("myskill", [])
        assert result == {}

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.get_password", return_value=None)
    def test_export_all_missing(self, mock_get, mock_log, mock_vault):
        result = mock_vault.export_for_process("myskill", ["A", "B", "C"])
        assert result == {}


# ---------------------------------------------------------------------------
# 10. TestLogVaultEvent
# ---------------------------------------------------------------------------

class TestLogVaultEvent:
    """Test CrossPlatformVault._log_vault_event."""

    def test_log_vault_event_success_no_error(self, mock_vault):
        """Logging with success=True and no error string."""
        mock_logger = MagicMock()
        mock_module = MagicMock()
        mock_module.get_logger.return_value = mock_logger
        with patch.dict("sys.modules", {"tweek.logging.security_log": mock_module}):
            # Force re-import inside the method
            mock_vault._log_vault_event("store", "skill", "key", success=True)
        mock_logger.log.assert_called_once()

    def test_log_vault_event_never_raises(self, mock_vault):
        """_log_vault_event should silently swallow all exceptions."""
        # Patch the import inside the method to raise
        with patch.dict("sys.modules", {"tweek.logging.security_log": None}):
            # Should not raise
            mock_vault._log_vault_event("store", "skill", "key", success=True)

    def test_log_vault_event_with_error_string(self, mock_vault):
        """_log_vault_event with error kwarg populates metadata['error']."""
        mock_logger = MagicMock()
        mock_module = MagicMock()
        mock_module.get_logger.return_value = mock_logger
        with patch.dict("sys.modules", {"tweek.logging.security_log": mock_module}):
            mock_vault._log_vault_event(
                "get", "skill", "key", success=False, error="some error"
            )
        mock_logger.log.assert_called_once()

    def test_log_vault_event_import_fails(self, mock_vault):
        """If the security_log import fails, no exception propagates."""
        with patch.dict("sys.modules", {"tweek.logging.security_log": None}):
            mock_vault._log_vault_event(
                "delete", "skill", "key", success=False, error="import failed"
            )


# ---------------------------------------------------------------------------
# 11. TestMigrateEnvToVault
# ---------------------------------------------------------------------------

class TestMigrateEnvToVault:
    """Test the migrate_env_to_vault() function."""

    @pytest.fixture
    def vault_for_migration(self):
        """Return a mocked CrossPlatformVault for migration tests."""
        with patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True), \
             patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain"):
            from tweek.vault.cross_platform import CrossPlatformVault
            vault = CrossPlatformVault()
        return vault

    def test_file_not_found(self, tmp_path, vault_for_migration):
        from tweek.vault.cross_platform import migrate_env_to_vault

        result = migrate_env_to_vault(
            tmp_path / "nonexistent.env", "myskill", vault_for_migration
        )
        assert result == []

    def test_dry_run(self, tmp_path, vault_for_migration):
        from tweek.vault.cross_platform import migrate_env_to_vault

        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=sk-test-123\nSECRET_TOKEN=abc\n")

        result = migrate_env_to_vault(env_file, "myskill", vault_for_migration, dry_run=True)

        assert len(result) == 2
        assert ("API_KEY", True) in result
        assert ("SECRET_TOKEN", True) in result

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.set_password")
    def test_real_migration(self, mock_set, mock_log, tmp_path, vault_for_migration):
        from tweek.vault.cross_platform import migrate_env_to_vault

        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=sk-test-123\nDB_URL=postgres://localhost/db\n")

        result = migrate_env_to_vault(env_file, "myskill", vault_for_migration)

        assert len(result) == 2
        assert all(success for _, success in result)
        assert mock_set.call_count == 2

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.set_password")
    def test_quoted_values(self, mock_set, mock_log, tmp_path, vault_for_migration):
        from tweek.vault.cross_platform import migrate_env_to_vault

        env_file = tmp_path / ".env"
        env_file.write_text('MY_KEY="quoted-value"\nOTHER=\'single-quoted\'\n')

        result = migrate_env_to_vault(env_file, "myskill", vault_for_migration)

        assert len(result) == 2
        # Verify the stored values had quotes stripped
        stored_values = [c.args[2] for c in mock_set.call_args_list]
        assert "quoted-value" in stored_values
        assert "single-quoted" in stored_values

    def test_comments_and_empty_lines(self, tmp_path, vault_for_migration):
        from tweek.vault.cross_platform import migrate_env_to_vault

        env_file = tmp_path / ".env"
        env_file.write_text("# This is a comment\n\n   \n# Another comment\nAPI_KEY=value\n")

        result = migrate_env_to_vault(env_file, "myskill", vault_for_migration, dry_run=True)

        assert len(result) == 1
        assert result[0][0] == "API_KEY"

    def test_malformed_lines_skipped(self, tmp_path, vault_for_migration):
        from tweek.vault.cross_platform import migrate_env_to_vault

        env_file = tmp_path / ".env"
        env_file.write_text(
            "API_KEY=valid\n"
            "not_a_valid_line\n"      # lowercase key, no match
            "=no_key\n"               # missing key
            "GOOD_KEY=another\n"
        )

        result = migrate_env_to_vault(env_file, "myskill", vault_for_migration, dry_run=True)

        keys = [k for k, _ in result]
        assert "API_KEY" in keys
        assert "GOOD_KEY" in keys
        # Malformed lines should be skipped
        assert len(result) == 2

    @patch("tweek.vault.cross_platform.CrossPlatformVault._log_vault_event")
    @patch("keyring.set_password")
    def test_partial_failures(self, mock_set, mock_log, tmp_path, vault_for_migration):
        from tweek.vault.cross_platform import migrate_env_to_vault

        # First call succeeds, second fails
        mock_set.side_effect = [None, Exception("backend error")]

        env_file = tmp_path / ".env"
        env_file.write_text("GOOD_KEY=value1\nBAD_KEY=value2\n")

        result = migrate_env_to_vault(env_file, "myskill", vault_for_migration)

        assert len(result) == 2
        keys_success = {k: s for k, s in result}
        assert keys_success["GOOD_KEY"] is True
        assert keys_success["BAD_KEY"] is False

    def test_migration_logs_event(self, tmp_path, vault_for_migration):
        """Migration should attempt to log a vault migration event."""
        from tweek.vault.cross_platform import migrate_env_to_vault

        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=value\n")

        mock_logger = MagicMock()
        mock_security_log = MagicMock()
        mock_security_log.get_logger.return_value = mock_logger
        mock_security_log.SecurityEvent = MagicMock()
        mock_security_log.EventType = MagicMock()

        with patch.dict("sys.modules", {"tweek.logging.security_log": mock_security_log}):
            migrate_env_to_vault(env_file, "myskill", vault_for_migration, dry_run=True)

        # Logger.log should have been called once for the migration event
        mock_logger.log.assert_called_once()

    def test_migration_log_failure_suppressed(self, tmp_path, vault_for_migration):
        """If the security logger throws, migration should still succeed."""
        from tweek.vault.cross_platform import migrate_env_to_vault

        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=value\n")

        # Make the logging import raise
        with patch.dict("sys.modules", {"tweek.logging.security_log": None}):
            result = migrate_env_to_vault(
                env_file, "myskill", vault_for_migration, dry_run=True
            )

        assert len(result) == 1

    def test_empty_env_file(self, tmp_path, vault_for_migration):
        from tweek.vault.cross_platform import migrate_env_to_vault

        env_file = tmp_path / ".env"
        env_file.write_text("")

        result = migrate_env_to_vault(env_file, "myskill", vault_for_migration, dry_run=True)
        assert result == []

    def test_env_file_only_comments(self, tmp_path, vault_for_migration):
        from tweek.vault.cross_platform import migrate_env_to_vault

        env_file = tmp_path / ".env"
        env_file.write_text("# comment1\n# comment2\n")

        result = migrate_env_to_vault(env_file, "myskill", vault_for_migration, dry_run=True)
        assert result == []


# ---------------------------------------------------------------------------
# 12. TestGetVault
# ---------------------------------------------------------------------------

class TestGetVault:
    """Test the get_vault() factory function."""

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_returns_vault_instance(self, _backend):
        from tweek.vault.cross_platform import get_vault, CrossPlatformVault

        vault = get_vault()
        assert isinstance(vault, CrossPlatformVault)

    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", False)
    def test_keyring_not_available_raises(self):
        from tweek.vault.cross_platform import get_vault

        with pytest.raises(RuntimeError, match="keyring library not installed"):
            get_vault()

    @patch("tweek.vault.cross_platform.get_vault_backend", return_value="macOS Keychain")
    @patch("tweek.vault.cross_platform.KEYRING_AVAILABLE", True)
    def test_returns_new_instance_each_call(self, _backend):
        from tweek.vault.cross_platform import get_vault

        v1 = get_vault()
        v2 = get_vault()
        assert v1 is not v2
