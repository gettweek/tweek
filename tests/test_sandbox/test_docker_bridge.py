"""Tests for the Docker bridge integration."""

import subprocess
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tweek.sandbox.docker_bridge import DockerBridge, TWEEK_HOME

pytestmark = pytest.mark.sandbox


class TestIsDockerAvailable:
    """Tests for DockerBridge.is_docker_available()."""

    def test_returns_true_when_docker_info_succeeds(self):
        """Should return True when 'docker info' exits with code 0."""
        bridge = DockerBridge()
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("tweek.sandbox.docker_bridge.subprocess.run", return_value=mock_result) as mock_run:
            assert bridge.is_docker_available() is True

        mock_run.assert_called_once_with(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=5,
        )

    def test_returns_false_when_docker_info_fails(self):
        """Should return False when 'docker info' exits with non-zero code."""
        bridge = DockerBridge()
        mock_result = MagicMock()
        mock_result.returncode = 1

        with patch("tweek.sandbox.docker_bridge.subprocess.run", return_value=mock_result):
            assert bridge.is_docker_available() is False

    def test_returns_false_when_docker_not_found(self):
        """Should return False when docker binary is not on PATH."""
        bridge = DockerBridge()

        with patch(
            "tweek.sandbox.docker_bridge.subprocess.run",
            side_effect=FileNotFoundError("No such file or directory: 'docker'"),
        ):
            assert bridge.is_docker_available() is False

    def test_returns_false_on_timeout(self):
        """Should return False when docker info times out."""
        bridge = DockerBridge()

        with patch(
            "tweek.sandbox.docker_bridge.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="docker info", timeout=5),
        ):
            assert bridge.is_docker_available() is False


class TestGetDockerVersion:
    """Tests for DockerBridge.get_docker_version()."""

    def test_returns_version_string_on_success(self):
        """Should return the stripped version string from docker."""
        bridge = DockerBridge()
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "24.0.7\n"

        with patch("tweek.sandbox.docker_bridge.subprocess.run", return_value=mock_result) as mock_run:
            version = bridge.get_docker_version()

        assert version == "24.0.7"
        mock_run.assert_called_once_with(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )

    def test_returns_none_on_nonzero_exit(self):
        """Should return None when docker version command fails."""
        bridge = DockerBridge()
        mock_result = MagicMock()
        mock_result.returncode = 1

        with patch("tweek.sandbox.docker_bridge.subprocess.run", return_value=mock_result):
            assert bridge.get_docker_version() is None

    def test_returns_none_when_docker_not_found(self):
        """Should return None when docker binary is not installed."""
        bridge = DockerBridge()

        with patch(
            "tweek.sandbox.docker_bridge.subprocess.run",
            side_effect=FileNotFoundError,
        ):
            assert bridge.get_docker_version() is None

    def test_returns_none_on_timeout(self):
        """Should return None when docker version times out."""
        bridge = DockerBridge()

        with patch(
            "tweek.sandbox.docker_bridge.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="docker version", timeout=5),
        ):
            assert bridge.get_docker_version() is None


class TestInit:
    """Tests for DockerBridge.init()."""

    def test_creates_tweek_directory(self, tmp_path):
        """Should create .tweek/ directory if it does not exist."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        tweek_dir = project_dir / ".tweek"
        assert not tweek_dir.exists()

        bridge.init(project_dir)

        assert tweek_dir.exists()
        assert tweek_dir.is_dir()

    def test_creates_tweek_directory_idempotent(self, tmp_path):
        """Should succeed even if .tweek/ directory already exists."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()
        (project_dir / ".tweek").mkdir()

        # Should not raise
        compose_path = bridge.init(project_dir)
        assert compose_path.exists()

    def test_returns_compose_file_path(self, tmp_path):
        """Should return the path to the generated docker-compose.yaml."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        compose_path = bridge.init(project_dir)

        expected = project_dir / ".tweek" / "docker-compose.yaml"
        assert compose_path == expected
        assert compose_path.exists()

    def test_compose_file_contains_service_definition(self, tmp_path):
        """Generated compose should define a tweek-sandbox service."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        compose_path = bridge.init(project_dir)
        content = compose_path.read_text()

        assert "services:" in content
        assert "tweek-sandbox:" in content

    def test_compose_file_uses_python_slim_image(self, tmp_path):
        """Generated compose should use python:3.12-slim image."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        compose_path = bridge.init(project_dir)
        content = compose_path.read_text()

        assert "image: python:3.12-slim" in content

    def test_compose_file_mounts_project_dir_rw(self, tmp_path):
        """Generated compose should mount project directory read-write at /workspace."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        compose_path = bridge.init(project_dir)
        content = compose_path.read_text()

        resolved = str(project_dir.resolve())
        assert f"{resolved}:/workspace:rw" in content

    def test_compose_file_mounts_tweek_config_ro(self, tmp_path):
        """Generated compose should mount global Tweek config read-only."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        compose_path = bridge.init(project_dir)
        content = compose_path.read_text()

        tweek_home_str = str(TWEEK_HOME)
        assert f"{tweek_home_str}:/home/tweek/.tweek-global:ro" in content

    def test_compose_file_disables_network(self, tmp_path):
        """Generated compose should set network_mode to none for security."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        compose_path = bridge.init(project_dir)
        content = compose_path.read_text()

        assert 'network_mode: "none"' in content

    def test_compose_file_sets_environment_variables(self, tmp_path):
        """Generated compose should set required environment variables."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        compose_path = bridge.init(project_dir)
        content = compose_path.read_text()

        assert "TWEEK_SANDBOX_LAYER=2" in content
        assert "TWEEK_GLOBAL_CONFIG=/home/tweek/.tweek-global" in content
        assert "HOME=/home/tweek" in content

    def test_compose_file_sets_working_dir(self, tmp_path):
        """Generated compose should set working_dir to /workspace."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        compose_path = bridge.init(project_dir)
        content = compose_path.read_text()

        assert "working_dir: /workspace" in content

    def test_compose_file_enables_interactive_tty(self, tmp_path):
        """Generated compose should enable stdin_open and tty for interactive use."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        compose_path = bridge.init(project_dir)
        content = compose_path.read_text()

        assert "stdin_open: true" in content
        assert "tty: true" in content

    def test_compose_file_installs_tweek_in_command(self, tmp_path):
        """Generated compose command should pip install tweek."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        compose_path = bridge.init(project_dir)
        content = compose_path.read_text()

        assert "pip install -q tweek" in content

    def test_init_resolves_relative_paths(self, tmp_path):
        """Should resolve relative project paths to absolute in compose file."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        # Pass the path as-is (tmp_path fixture already provides absolute,
        # but the code calls .resolve() which normalizes symlinks etc.)
        compose_path = bridge.init(project_dir)
        content = compose_path.read_text()

        resolved = str(project_dir.resolve())
        assert resolved in content

    def test_init_overwrites_existing_compose(self, tmp_path):
        """Should overwrite an existing docker-compose.yaml on re-init."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        # Create an initial compose file
        bridge.init(project_dir)

        # Overwrite with stale content
        compose_path = project_dir / ".tweek" / "docker-compose.yaml"
        compose_path.write_text("stale content")

        # Re-init should overwrite
        bridge.init(project_dir)
        content = compose_path.read_text()

        assert "stale content" not in content
        assert "tweek-sandbox:" in content


class TestRun:
    """Tests for DockerBridge.run()."""

    def test_calls_docker_compose_run(self, tmp_path):
        """Should invoke docker compose run with correct arguments."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        # Pre-create compose file so init is not triggered
        bridge.init(project_dir)

        compose_path = project_dir / ".tweek" / "docker-compose.yaml"
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("tweek.sandbox.docker_bridge.subprocess.run", return_value=mock_result) as mock_run:
            exit_code = bridge.run(project_dir)

        assert exit_code == 0
        mock_run.assert_called_once_with(
            ["docker", "compose", "-f", str(compose_path), "run", "--rm", "tweek-sandbox"],
            cwd=str(project_dir.resolve()),
        )

    def test_auto_generates_compose_if_missing(self, tmp_path):
        """Should call init() to generate compose file when it does not exist."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        compose_path = project_dir / ".tweek" / "docker-compose.yaml"
        assert not compose_path.exists()

        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("tweek.sandbox.docker_bridge.subprocess.run", return_value=mock_result):
            bridge.run(project_dir)

        # init() should have created the compose file
        assert compose_path.exists()
        content = compose_path.read_text()
        assert "tweek-sandbox:" in content

    def test_returns_container_exit_code(self, tmp_path):
        """Should return the exit code from the docker compose run process."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()
        bridge.init(project_dir)

        mock_result = MagicMock()
        mock_result.returncode = 42

        with patch("tweek.sandbox.docker_bridge.subprocess.run", return_value=mock_result):
            assert bridge.run(project_dir) == 42


class TestStop:
    """Tests for DockerBridge.stop()."""

    def test_calls_docker_compose_down(self, tmp_path):
        """Should invoke docker compose down when compose file exists."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        # Create the compose file
        bridge.init(project_dir)
        compose_path = project_dir / ".tweek" / "docker-compose.yaml"

        with patch("tweek.sandbox.docker_bridge.subprocess.run") as mock_run:
            bridge.stop(project_dir)

        mock_run.assert_called_once_with(
            ["docker", "compose", "-f", str(compose_path), "down"],
            capture_output=True,
        )

    def test_does_nothing_when_no_compose_file(self, tmp_path):
        """Should not call docker compose when no compose file exists."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        with patch("tweek.sandbox.docker_bridge.subprocess.run") as mock_run:
            bridge.stop(project_dir)

        mock_run.assert_not_called()


class TestSuggestDocker:
    """Tests for DockerBridge.suggest_docker()."""

    def test_returns_suggestion_when_docker_available_no_config(self, tmp_path):
        """Should return suggestion string when Docker is available but not configured."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        with patch.object(bridge, "is_docker_available", return_value=True):
            result = bridge.suggest_docker(project_dir)

        assert result is not None
        assert "Docker detected" in result
        assert "tweek sandbox docker init" in result

    def test_returns_none_when_docker_not_available(self, tmp_path):
        """Should return None when Docker is not installed or not running."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        with patch.object(bridge, "is_docker_available", return_value=False):
            result = bridge.suggest_docker(project_dir)

        assert result is None

    def test_returns_none_when_already_configured(self, tmp_path):
        """Should return None when docker-compose.yaml already exists."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        # Create the compose file via init
        bridge.init(project_dir)

        with patch.object(bridge, "is_docker_available", return_value=True):
            result = bridge.suggest_docker(project_dir)

        assert result is None

    def test_returns_none_when_docker_not_available_and_configured(self, tmp_path):
        """Should return None when Docker is not available even if configured."""
        bridge = DockerBridge()
        project_dir = tmp_path / "my-project"
        project_dir.mkdir()

        bridge.init(project_dir)

        with patch.object(bridge, "is_docker_available", return_value=False):
            result = bridge.suggest_docker(project_dir)

        assert result is None
