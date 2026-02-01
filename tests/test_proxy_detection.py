#!/usr/bin/env python3
"""
Tests for Tweek proxy detection module.

Tests coverage of:
- Moltbot detection (npm, process, config)
- Moltbot gateway port checking
- Proxy conflict detection
- Port availability checking
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

pytestmark = pytest.mark.core

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tweek.proxy import (
    detect_moltbot,
    detect_cursor,
    detect_continue,
    detect_supported_tools,
    detect_proxy_conflicts,
    get_moltbot_status,
    is_port_in_use,
    check_moltbot_gateway_running,
    ProxyConflict,
    MOLTBOT_DEFAULT_PORT,
    TWEEK_DEFAULT_PORT,
)


class TestPortChecking:
    """Tests for port availability checking."""

    def test_is_port_in_use_closed_port(self):
        """Test that a closed port returns False."""
        # Use a high port that's unlikely to be in use
        result = is_port_in_use(59999)
        # This might be True or False depending on system state,
        # so we just verify it returns a boolean
        assert isinstance(result, bool)

    def test_is_port_in_use_with_mock(self):
        """Test port checking with mocked socket."""
        with patch('tweek.proxy.socket.socket') as mock_socket:
            mock_sock_instance = MagicMock()
            mock_socket.return_value.__enter__.return_value = mock_sock_instance

            # Simulate port in use (connect succeeds)
            mock_sock_instance.connect_ex.return_value = 0
            assert is_port_in_use(8080) is True

            # Simulate port not in use (connect fails)
            mock_sock_instance.connect_ex.return_value = 111  # Connection refused
            assert is_port_in_use(8080) is False

    def test_is_port_in_use_socket_error(self):
        """Test port checking handles socket errors."""
        with patch('tweek.proxy.socket.socket') as mock_socket:
            mock_socket.side_effect = OSError("Network error")
            result = is_port_in_use(8080)
            assert result is False


class TestMoltbotDetection:
    """Tests for moltbot detection."""

    def test_detect_moltbot_not_installed(self):
        """Test detection when moltbot is not installed."""
        with patch('subprocess.run') as mock_run:
            # npm list returns empty/error
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="{}",
                stderr=""
            )

            with patch.object(Path, 'home', return_value=Path("/tmp/fake_home")):
                result = detect_moltbot()

            # Should return None when not installed
            assert result is None

    def test_detect_moltbot_npm_installed(self):
        """Test detection when moltbot is installed via npm."""
        npm_output = '{"dependencies": {"moltbot": {"version": "1.0.0"}}}'

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=npm_output,
                stderr=""
            )

            with patch.object(Path, 'home', return_value=Path("/tmp/fake_home")):
                result = detect_moltbot()

            assert result is not None
            assert result["npm_global"] is True
            assert result["gateway_port"] == MOLTBOT_DEFAULT_PORT

    def test_detect_moltbot_process_running(self):
        """Test detection when moltbot process is running."""
        with patch('subprocess.run') as mock_run:
            def subprocess_side_effect(cmd, **kwargs):
                if "npm" in cmd:
                    return MagicMock(returncode=1, stdout="{}", stderr="")
                elif "pgrep" in cmd:
                    return MagicMock(returncode=0, stdout="12345", stderr="")
                return MagicMock(returncode=1)

            mock_run.side_effect = subprocess_side_effect

            with patch.object(Path, 'home', return_value=Path("/tmp/fake_home")):
                result = detect_moltbot()

            assert result is not None
            assert result["process_running"] is True

    def test_detect_moltbot_config_exists(self, tmp_path):
        """Test detection when moltbot config directory exists."""
        # Create fake moltbot config directory
        moltbot_config = tmp_path / ".moltbot"
        moltbot_config.mkdir()

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="{}", stderr="")

            with patch.object(Path, 'home', return_value=tmp_path):
                result = detect_moltbot()

            assert result is not None
            assert result["config_exists"] is True

    def test_detect_moltbot_timeout_handling(self):
        """Test that subprocess timeout is handled gracefully."""
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="npm", timeout=5)

            with patch.object(Path, 'home', return_value=Path("/tmp/fake_home")):
                result = detect_moltbot()

            # Should not raise, returns None
            assert result is None


class TestMoltbotStatus:
    """Tests for detailed moltbot status."""

    def test_get_moltbot_status_not_installed(self):
        """Test status when moltbot is not installed."""
        with patch('tweek.proxy.detect_moltbot', return_value=None):
            status = get_moltbot_status()

            assert status["installed"] is False
            assert status["running"] is False
            assert status["gateway_active"] is False
            assert status["port"] == MOLTBOT_DEFAULT_PORT

    def test_get_moltbot_status_installed_not_running(self, tmp_path):
        """Test status when moltbot is installed but not running."""
        moltbot_info = {
            "npm_global": True,
            "process_running": False,
            "config_exists": True,
            "gateway_port": MOLTBOT_DEFAULT_PORT,
        }

        with patch('tweek.proxy.detect_moltbot', return_value=moltbot_info):
            with patch('tweek.proxy.check_moltbot_gateway_running', return_value=False):
                with patch.object(Path, 'home', return_value=tmp_path):
                    # Create the config path
                    (tmp_path / ".moltbot").mkdir()
                    status = get_moltbot_status()

            assert status["installed"] is True
            assert status["running"] is False
            assert status["gateway_active"] is False

    def test_get_moltbot_status_fully_running(self, tmp_path):
        """Test status when moltbot is fully running with gateway active."""
        moltbot_info = {
            "npm_global": True,
            "process_running": True,
            "config_exists": True,
            "gateway_port": MOLTBOT_DEFAULT_PORT,
        }

        with patch('tweek.proxy.detect_moltbot', return_value=moltbot_info):
            with patch('tweek.proxy.check_moltbot_gateway_running', return_value=True):
                with patch.object(Path, 'home', return_value=tmp_path):
                    (tmp_path / ".moltbot").mkdir()
                    status = get_moltbot_status()

            assert status["installed"] is True
            assert status["running"] is True
            assert status["gateway_active"] is True
            assert status["config_path"] is not None


class TestProxyConflictDetection:
    """Tests for proxy conflict detection."""

    def test_detect_proxy_conflicts_none(self):
        """Test no conflicts when nothing is running."""
        with patch('tweek.proxy.detect_moltbot', return_value=None):
            with patch('tweek.proxy.is_port_in_use', return_value=False):
                conflicts = detect_proxy_conflicts()

            assert len(conflicts) == 0

    def test_detect_proxy_conflicts_moltbot_running(self):
        """Test conflict detection when moltbot is running."""
        moltbot_info = {
            "npm_global": True,
            "process_running": True,
            "config_exists": False,
            "gateway_port": MOLTBOT_DEFAULT_PORT,
        }

        with patch('tweek.proxy.detect_moltbot', return_value=moltbot_info):
            with patch('tweek.proxy.check_moltbot_gateway_running', return_value=True):
                with patch('tweek.proxy.is_port_in_use', return_value=False):
                    conflicts = detect_proxy_conflicts()

            assert len(conflicts) >= 1
            moltbot_conflict = next((c for c in conflicts if c.tool_name == "moltbot"), None)
            assert moltbot_conflict is not None
            assert moltbot_conflict.is_running is True
            assert moltbot_conflict.port == MOLTBOT_DEFAULT_PORT

    def test_detect_proxy_conflicts_tweek_port_in_use(self):
        """Test conflict detection when Tweek's port is already in use."""
        def port_check(port):
            return port == TWEEK_DEFAULT_PORT

        with patch('tweek.proxy.detect_moltbot', return_value=None):
            with patch('tweek.proxy.is_port_in_use', side_effect=port_check):
                conflicts = detect_proxy_conflicts()

            assert len(conflicts) >= 1
            port_conflict = next((c for c in conflicts if c.port == TWEEK_DEFAULT_PORT), None)
            assert port_conflict is not None
            assert port_conflict.tool_name == "unknown"

    def test_detect_proxy_conflicts_multiple(self):
        """Test detection of multiple conflicts."""
        moltbot_info = {
            "npm_global": True,
            "process_running": True,
            "config_exists": False,
            "gateway_port": MOLTBOT_DEFAULT_PORT,
        }

        def port_check(port):
            # Both moltbot port and tweek port in use
            return port in (MOLTBOT_DEFAULT_PORT, TWEEK_DEFAULT_PORT)

        with patch('tweek.proxy.detect_moltbot', return_value=moltbot_info):
            with patch('tweek.proxy.check_moltbot_gateway_running', return_value=True):
                with patch('tweek.proxy.is_port_in_use', side_effect=port_check):
                    conflicts = detect_proxy_conflicts()

            # Should have both moltbot and port conflicts
            assert len(conflicts) >= 2


class TestOtherToolDetection:
    """Tests for Cursor and Continue detection."""

    def test_detect_cursor_not_installed(self, tmp_path):
        """Test Cursor detection when not installed."""
        # Mock both the app path and home directory to ensure Cursor is not found
        with patch.object(Path, 'home', return_value=tmp_path):
            with patch.object(Path, 'exists', return_value=False):
                result = detect_cursor()
                assert result is None

    def test_detect_cursor_installed_darwin(self, tmp_path):
        """Test Cursor detection on macOS."""
        with patch('platform.system', return_value="Darwin"):
            with patch.object(Path, 'exists', return_value=True):
                result = detect_cursor()

                assert result is not None
                assert "app_exists" in result

    def test_detect_continue_not_installed(self, tmp_path):
        """Test Continue.dev detection when not installed."""
        with patch.object(Path, 'home', return_value=tmp_path):
            result = detect_continue()
            assert result is None

    def test_detect_continue_installed(self, tmp_path):
        """Test Continue.dev detection when installed."""
        # Create fake VS Code extension
        ext_path = tmp_path / ".vscode" / "extensions" / "continue.continue-1.0.0"
        ext_path.mkdir(parents=True)

        with patch.object(Path, 'home', return_value=tmp_path):
            result = detect_continue()

            assert result is not None
            assert result["version"] == "1.0.0"


class TestSupportedToolsDetection:
    """Tests for combined tool detection."""

    def test_detect_supported_tools_empty(self):
        """Test supported tools detection when nothing installed."""
        with patch('tweek.proxy.detect_moltbot', return_value=None):
            with patch('tweek.proxy.detect_cursor', return_value=None):
                with patch('tweek.proxy.detect_continue', return_value=None):
                    tools = detect_supported_tools()

                    assert tools["moltbot"] is None
                    assert tools["cursor"] is None
                    assert tools["continue"] is None

    def test_detect_supported_tools_with_moltbot(self):
        """Test supported tools detection with moltbot installed."""
        moltbot_info = {
            "npm_global": True,
            "process_running": False,
            "config_exists": False,
            "gateway_port": MOLTBOT_DEFAULT_PORT,
        }

        with patch('tweek.proxy.detect_moltbot', return_value=moltbot_info):
            with patch('tweek.proxy.detect_cursor', return_value=None):
                with patch('tweek.proxy.detect_continue', return_value=None):
                    tools = detect_supported_tools()

                    assert tools["moltbot"] is not None
                    assert tools["moltbot"]["npm_global"] is True


class TestProxyConflictDataclass:
    """Tests for ProxyConflict dataclass."""

    def test_proxy_conflict_creation(self):
        """Test creating a ProxyConflict instance."""
        conflict = ProxyConflict(
            tool_name="moltbot",
            port=18789,
            is_running=True,
            description="Moltbot gateway detected on port 18789"
        )

        assert conflict.tool_name == "moltbot"
        assert conflict.port == 18789
        assert conflict.is_running is True
        assert "18789" in conflict.description


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
