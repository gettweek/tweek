"""Tests for the proxy server lifecycle management."""
import os
import signal
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from tweek.proxy.server import (
    is_proxy_running,
    start_proxy,
    stop_proxy,
    get_proxy_info,
    get_proxy_env_vars,
    generate_wrapper_script,
    get_addon_script_path,
    DEFAULT_PORT,
)


@pytest.mark.plugins
class TestIsProxyRunning:
    """Tests for proxy running status detection."""

    def test_no_pid_file(self, tmp_path):
        pid_file = tmp_path / "proxy.pid"
        with patch("tweek.proxy.server.PID_FILE", pid_file):
            running, pid = is_proxy_running()
            assert running is False
            assert pid is None

    def test_valid_pid_file_process_running(self, tmp_path):
        pid_file = tmp_path / "proxy.pid"
        pid_file.write_text(str(os.getpid()))  # Current process is always running
        with patch("tweek.proxy.server.PID_FILE", pid_file):
            running, pid = is_proxy_running()
            assert running is True
            assert pid == os.getpid()

    def test_stale_pid_file_process_gone(self, tmp_path):
        pid_file = tmp_path / "proxy.pid"
        pid_file.write_text("999999999")  # Likely nonexistent PID
        with patch("tweek.proxy.server.PID_FILE", pid_file):
            running, pid = is_proxy_running()
            assert running is False
            assert pid is None
            # Stale PID file should be cleaned up
            assert not pid_file.exists()

    def test_invalid_pid_file_content(self, tmp_path):
        pid_file = tmp_path / "proxy.pid"
        pid_file.write_text("not_a_number")
        with patch("tweek.proxy.server.PID_FILE", pid_file):
            running, pid = is_proxy_running()
            assert running is False
            assert pid is None


@pytest.mark.plugins
class TestStartProxy:
    """Tests for starting the proxy."""

    def test_already_running(self, tmp_path):
        pid_file = tmp_path / "proxy.pid"
        pid_file.write_text(str(os.getpid()))
        with patch("tweek.proxy.server.PID_FILE", pid_file):
            success, msg = start_proxy()
            assert success is False
            assert "already running" in msg

    def test_mitmproxy_not_installed(self, tmp_path):
        pid_file = tmp_path / "proxy.pid"
        with patch("tweek.proxy.server.PID_FILE", pid_file), \
             patch("builtins.__import__", side_effect=ImportError("No module named 'mitmproxy'")):
            success, msg = start_proxy()
            assert success is False
            assert "mitmproxy not installed" in msg


@pytest.mark.plugins
class TestStopProxy:
    """Tests for stopping the proxy."""

    def test_not_running(self, tmp_path):
        pid_file = tmp_path / "proxy.pid"
        with patch("tweek.proxy.server.PID_FILE", pid_file):
            success, msg = stop_proxy()
            assert success is False
            assert "not running" in msg

    def test_stop_running_process(self, tmp_path):
        pid_file = tmp_path / "proxy.pid"
        pid_file.write_text("12345")

        with patch("tweek.proxy.server.PID_FILE", pid_file), \
             patch("os.kill") as mock_kill:
            # First call (SIGTERM) succeeds, second call (check if alive) raises ProcessLookupError
            mock_kill.side_effect = [None, ProcessLookupError]
            success, msg = stop_proxy()
            assert success is True
            assert "stopped" in msg.lower()
            mock_kill.assert_any_call(12345, signal.SIGTERM)

    def test_stop_already_dead_process(self, tmp_path):
        pid_file = tmp_path / "proxy.pid"
        pid_file.write_text("12345")

        with patch("tweek.proxy.server.PID_FILE", pid_file), \
             patch("tweek.proxy.server.is_proxy_running", return_value=(True, 12345)), \
             patch("os.kill", side_effect=ProcessLookupError):
            success, msg = stop_proxy()
            assert success is True
            assert "already stopped" in msg.lower()

    def test_stop_permission_denied(self, tmp_path):
        pid_file = tmp_path / "proxy.pid"
        pid_file.write_text("12345")

        with patch("tweek.proxy.server.PID_FILE", pid_file), \
             patch("tweek.proxy.server.is_proxy_running", return_value=(True, 12345)), \
             patch("os.kill", side_effect=PermissionError):
            success, msg = stop_proxy()
            assert success is False
            assert "Permission denied" in msg


@pytest.mark.plugins
class TestGetProxyInfo:
    """Tests for proxy info retrieval."""

    def test_info_when_not_running(self, tmp_path):
        pid_file = tmp_path / "proxy.pid"
        ca_dir = tmp_path / "certs"
        ca_dir.mkdir()

        with patch("tweek.proxy.server.PID_FILE", pid_file), \
             patch("tweek.proxy.server.LOG_FILE", tmp_path / "proxy.log"), \
             patch("tweek.proxy.server.CA_DIR", ca_dir):
            info = get_proxy_info()
            assert info["running"] is False
            assert info["pid"] is None
            assert info["default_port"] == DEFAULT_PORT
            assert info["ca_cert_exists"] is False

    def test_info_with_ca_cert(self, tmp_path):
        pid_file = tmp_path / "proxy.pid"
        ca_dir = tmp_path / "certs"
        ca_dir.mkdir()
        (ca_dir / "mitmproxy-ca-cert.pem").write_text("CERT")

        with patch("tweek.proxy.server.PID_FILE", pid_file), \
             patch("tweek.proxy.server.LOG_FILE", tmp_path / "proxy.log"), \
             patch("tweek.proxy.server.CA_DIR", ca_dir):
            info = get_proxy_info()
            assert info["ca_cert_exists"] is True


@pytest.mark.plugins
class TestGetProxyEnvVars:
    """Tests for proxy environment variable generation."""

    def test_default_port(self):
        env = get_proxy_env_vars()
        assert env["HTTP_PROXY"] == f"http://127.0.0.1:{DEFAULT_PORT}"
        assert env["HTTPS_PROXY"] == f"http://127.0.0.1:{DEFAULT_PORT}"
        assert env["http_proxy"] == f"http://127.0.0.1:{DEFAULT_PORT}"
        assert env["https_proxy"] == f"http://127.0.0.1:{DEFAULT_PORT}"
        assert "NODE_EXTRA_CA_CERTS" in env

    def test_custom_port(self):
        env = get_proxy_env_vars(port=8080)
        assert env["HTTP_PROXY"] == "http://127.0.0.1:8080"

    def test_node_ca_certs_path(self):
        env = get_proxy_env_vars()
        assert "tweek" in env["NODE_EXTRA_CA_CERTS"]
        assert "proxy" in env["NODE_EXTRA_CA_CERTS"]


@pytest.mark.plugins
class TestGenerateWrapperScript:
    """Tests for wrapper script generation."""

    def test_script_contains_command(self):
        script = generate_wrapper_script("npm start")
        assert "npm start" in script

    def test_script_contains_proxy_vars(self):
        script = generate_wrapper_script("python app.py")
        assert "HTTP_PROXY" in script
        assert "HTTPS_PROXY" in script
        assert "NODE_EXTRA_CA_CERTS" in script

    def test_script_is_bash(self):
        script = generate_wrapper_script("node server.js")
        assert script.startswith("#!/bin/bash")

    def test_custom_port(self):
        script = generate_wrapper_script("app", port=8080)
        assert "8080" in script

    def test_write_to_file(self, tmp_path):
        output = tmp_path / "wrapper.sh"
        script = generate_wrapper_script("my-app", output_path=output)
        assert output.exists()
        assert output.read_text() == script
        # Check executable permission
        assert output.stat().st_mode & 0o755


@pytest.mark.plugins
class TestGetAddonScriptPath:
    """Tests for addon script path resolution."""

    def test_returns_path(self):
        path = get_addon_script_path()
        assert isinstance(path, Path)
        assert path.name == "addon.py"
        assert "proxy" in str(path)
