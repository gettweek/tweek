"""
Proxy Server Management - Start, stop, and manage the Tweek proxy.

This module handles the lifecycle of the mitmproxy-based security proxy.
"""

from __future__ import annotations

import os
import sys
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional
import logging

logger = logging.getLogger("tweek.proxy")

# Default configuration
DEFAULT_PORT = 9877
DEFAULT_WEB_PORT = 9878  # mitmproxy web interface
PID_FILE = Path.home() / ".tweek" / "proxy" / "proxy.pid"
LOG_FILE = Path.home() / ".tweek" / "proxy" / "proxy.log"
CA_DIR = Path.home() / ".tweek" / "proxy" / "certs"


def ensure_directories():
    """Ensure proxy directories exist."""
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    CA_DIR.mkdir(parents=True, exist_ok=True)


def get_addon_script_path() -> Path:
    """Get the path to the mitmproxy addon script."""
    return Path(__file__).parent / "addon.py"


def is_proxy_running() -> tuple[bool, Optional[int]]:
    """Check if the proxy is running and return its PID."""
    if not PID_FILE.exists():
        return False, None

    try:
        pid = int(PID_FILE.read_text().strip())

        # Check if process exists
        os.kill(pid, 0)
        return True, pid
    except (ValueError, ProcessLookupError, PermissionError):
        # Clean up stale PID file
        PID_FILE.unlink(missing_ok=True)
        return False, None


def start_proxy(
    port: int = DEFAULT_PORT,
    web_port: Optional[int] = None,
    block_mode: bool = True,
    log_only: bool = False,
    foreground: bool = False,
) -> tuple[bool, str]:
    """
    Start the Tweek proxy server.

    Args:
        port: Port for the proxy to listen on
        web_port: Port for mitmproxy web interface (None to disable)
        block_mode: If True, block dangerous responses
        log_only: If True, log only without blocking
        foreground: If True, run in foreground (for debugging)

    Returns:
        Tuple of (success, message)
    """
    # Check if already running
    running, pid = is_proxy_running()
    if running:
        return False, f"Proxy already running (PID {pid})"

    # Check for mitmproxy
    try:
        import mitmproxy
    except ImportError:
        return False, "mitmproxy not installed. Run: pip install tweek[proxy]"

    ensure_directories()

    # Build mitmproxy command
    addon_path = get_addon_script_path()

    cmd = [
        sys.executable, "-m", "mitmproxy.tools.main",
        "--mode", "regular",
        "--listen-port", str(port),
        "--set", f"confdir={CA_DIR}",
        "--scripts", str(addon_path),
        "--quiet",  # Reduce noise
    ]

    if web_port:
        cmd.extend(["--web-port", str(web_port)])
    else:
        cmd.append("--no-web-open-browser")

    # Set environment for addon configuration
    env = os.environ.copy()
    env["TWEEK_PROXY_BLOCK_MODE"] = "1" if block_mode else "0"
    env["TWEEK_PROXY_LOG_ONLY"] = "1" if log_only else "0"

    if foreground:
        # Run in foreground for debugging
        try:
            subprocess.run(cmd, env=env)
            return True, "Proxy stopped"
        except KeyboardInterrupt:
            return True, "Proxy stopped by user"
    else:
        # Run in background
        with open(LOG_FILE, "a") as log:
            process = subprocess.Popen(
                cmd,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )

        # Save PID
        PID_FILE.write_text(str(process.pid))

        # Wait a moment to check if it started successfully
        time.sleep(1)

        running, _ = is_proxy_running()
        if running:
            return True, f"Proxy started on port {port} (PID {process.pid})"
        else:
            return False, f"Proxy failed to start. Check {LOG_FILE} for details"


def stop_proxy() -> tuple[bool, str]:
    """
    Stop the Tweek proxy server.

    Returns:
        Tuple of (success, message)
    """
    running, pid = is_proxy_running()

    if not running:
        return False, "Proxy is not running"

    try:
        os.kill(pid, signal.SIGTERM)

        # Wait for graceful shutdown
        for _ in range(10):
            time.sleep(0.5)
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
        else:
            # Force kill if still running
            os.kill(pid, signal.SIGKILL)

        PID_FILE.unlink(missing_ok=True)
        return True, f"Proxy stopped (PID {pid})"

    except ProcessLookupError:
        PID_FILE.unlink(missing_ok=True)
        return True, "Proxy was already stopped"
    except PermissionError:
        return False, f"Permission denied stopping PID {pid}"


def get_proxy_info() -> dict:
    """Get detailed proxy status information."""
    running, pid = is_proxy_running()

    info = {
        "running": running,
        "pid": pid,
        "pid_file": str(PID_FILE),
        "log_file": str(LOG_FILE),
        "ca_dir": str(CA_DIR),
        "ca_cert": str(CA_DIR / "mitmproxy-ca-cert.pem"),
        "default_port": DEFAULT_PORT,
    }

    # Check if CA cert exists
    ca_cert = CA_DIR / "mitmproxy-ca-cert.pem"
    info["ca_cert_exists"] = ca_cert.exists()

    return info


def install_ca_certificate() -> tuple[bool, str]:
    """
    Install the Tweek proxy CA certificate in the system trust store.

    Returns:
        Tuple of (success, message)
    """
    import platform

    ca_cert = CA_DIR / "mitmproxy-ca-cert.pem"

    if not ca_cert.exists():
        # Generate CA cert by starting proxy briefly
        ensure_directories()
        try:
            import mitmproxy
            from mitmproxy.certs import CertStore

            # This will generate the CA if it doesn't exist
            store = CertStore.from_store(str(CA_DIR), "mitmproxy", 2048)
            # CA is now generated
        except Exception as e:
            return False, f"Failed to generate CA certificate: {e}"

    if not ca_cert.exists():
        return False, "CA certificate not found. Start the proxy first to generate it."

    system = platform.system()

    if system == "Darwin":
        # macOS: Add to System Keychain
        cmd = [
            "sudo", "security", "add-trusted-cert",
            "-d", "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain",
            str(ca_cert)
        ]
        try:
            subprocess.run(cmd, check=True)
            return True, "CA certificate installed in macOS System Keychain"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to install CA certificate: {e}"

    elif system == "Linux":
        # Linux: Copy to /usr/local/share/ca-certificates
        dest = Path("/usr/local/share/ca-certificates/tweek-proxy.crt")
        try:
            subprocess.run(["sudo", "cp", str(ca_cert), str(dest)], check=True)
            subprocess.run(["sudo", "update-ca-certificates"], check=True)
            return True, "CA certificate installed in system trust store"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to install CA certificate: {e}"

    else:
        return False, f"Automatic CA installation not supported on {system}. Please install manually: {ca_cert}"


def get_proxy_env_vars(port: int = DEFAULT_PORT) -> dict[str, str]:
    """
    Get environment variables to configure applications to use the proxy.

    Returns:
        Dictionary of environment variables
    """
    proxy_url = f"http://127.0.0.1:{port}"

    return {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        # For Node.js: use CA cert bundle instead of disabling TLS validation
        # NODE_TLS_REJECT_UNAUTHORIZED=0 would disable ALL TLS checks (insecure)
        # NODE_EXTRA_CA_CERTS adds our CA to the trust store without disabling validation
        "NODE_EXTRA_CA_CERTS": str(Path.home() / ".tweek" / "proxy" / "tweek-ca.pem"),
    }


def generate_wrapper_script(
    app_command: str,
    port: int = DEFAULT_PORT,
    output_path: Optional[Path] = None,
) -> str:
    """
    Generate a wrapper script to run an application through the Tweek proxy.

    Args:
        app_command: The command to wrap (e.g., "npm start")
        port: Proxy port
        output_path: If provided, write script to this path

    Returns:
        The wrapper script content
    """
    env_vars = get_proxy_env_vars(port)

    script = f"""#!/bin/bash
# Tweek Proxy Wrapper Script
# This script runs an application through the Tweek security proxy.

# Ensure Tweek proxy is running
if ! pgrep -f "tweek.*proxy" > /dev/null; then
    echo "Starting Tweek proxy..."
    tweek proxy start
    sleep 2
fi

# Set proxy environment variables
{chr(10).join(f'export {k}="{v}"' for k, v in env_vars.items())}

# Run the application
{app_command}
"""

    if output_path:
        output_path.write_text(script)
        output_path.chmod(0o755)

    return script
