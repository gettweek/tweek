"""CLI commands for the Tweek LLM security proxy.

Provides the ``proxy`` Click group and its subcommands:
start, stop, trust, config, wrap, setup.

These were extracted from the monolithic cli.py to improve
maintainability.  The group is registered on the main CLI
entry-point via ``main.add_command(proxy)``.
"""

import os
from pathlib import Path

import click

from tweek.cli_helpers import console, print_error, print_success, print_warning, spinner


# ------------------------------------------------------------------
# Proxy command group
# ------------------------------------------------------------------

@click.group()
def proxy():
    """LLM API security proxy for universal protection.

    The proxy intercepts LLM API traffic and screens for dangerous tool calls.
    Works with any application that calls Anthropic, OpenAI, or other LLM APIs.

    \b
    Install dependencies: pip install tweek[proxy]
    Quick start:
        tweek proxy start       # Start the proxy
        tweek proxy trust       # Install CA certificate
        tweek proxy wrap openclaw "npm start"  # Wrap an app
    """
    pass


# ------------------------------------------------------------------
# tweek proxy start
# ------------------------------------------------------------------

@proxy.command(
    "start",
    epilog="""\b
Examples:
  tweek proxy start                      Start proxy on default port (9877)
  tweek proxy start --port 8080          Start proxy on custom port
  tweek proxy start --foreground         Run in foreground for debugging
  tweek proxy start --log-only           Log traffic without blocking
""",
)
@click.option("--port", "-p", default=9877, help="Port for proxy to listen on")
@click.option("--web-port", type=int, help="Port for web interface (disabled by default)")
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground (for debugging)")
@click.option("--log-only", is_flag=True, help="Log only, don't block dangerous requests")
def proxy_start(port: int, web_port: int, foreground: bool, log_only: bool):
    """Start the Tweek LLM security proxy."""
    from tweek.proxy import PROXY_AVAILABLE, PROXY_MISSING_DEPS

    if not PROXY_AVAILABLE:
        console.print("[red]\u2717[/red] Proxy dependencies not installed.")
        console.print("  [white]Hint: Install with: pip install tweek[proxy][/white]")
        console.print("  [white]This adds mitmproxy for HTTP(S) interception.[/white]")
        return

    from tweek.proxy.server import start_proxy

    console.print(f"[cyan]Starting Tweek proxy on port {port}...[/cyan]")

    success, message = start_proxy(
        port=port,
        web_port=web_port,
        log_only=log_only,
        foreground=foreground,
    )

    if success:
        console.print(f"[green]\u2713[/green] {message}")
        console.print()
        console.print("[bold]To use the proxy:[/bold]")
        console.print(f"  export HTTPS_PROXY=http://127.0.0.1:{port}")
        console.print(f"  export HTTP_PROXY=http://127.0.0.1:{port}")
        console.print()
        console.print("[white]Or use 'tweek proxy wrap' to create a wrapper script[/white]")
    else:
        console.print(f"[red]\u2717[/red] {message}")


# ------------------------------------------------------------------
# tweek proxy stop
# ------------------------------------------------------------------

@proxy.command(
    "stop",
    epilog="""\b
Examples:
  tweek proxy stop                       Stop the running proxy server
""",
)
def proxy_stop():
    """Stop the Tweek LLM security proxy."""
    from tweek.proxy import PROXY_AVAILABLE

    if not PROXY_AVAILABLE:
        console.print("[red]\u2717[/red] Proxy dependencies not installed.")
        return

    from tweek.proxy.server import stop_proxy

    success, message = stop_proxy()

    if success:
        console.print(f"[green]\u2713[/green] {message}")
    else:
        console.print(f"[yellow]![/yellow] {message}")


# ------------------------------------------------------------------
# tweek proxy trust
# ------------------------------------------------------------------

@proxy.command(
    "trust",
    epilog="""\b
Examples:
  tweek proxy trust                      Install CA certificate for HTTPS interception
""",
)
def proxy_trust():
    """Install the proxy CA certificate in system trust store.

    This is required for HTTPS interception to work. The certificate
    is generated locally and only used for local proxy traffic.
    """
    from tweek.proxy import PROXY_AVAILABLE

    if not PROXY_AVAILABLE:
        console.print("[red]\u2717[/red] Proxy dependencies not installed.")
        console.print("[white]Run: pip install tweek\\[proxy][/white]")
        return

    from tweek.proxy.server import get_proxy_info, install_ca_certificate

    info = get_proxy_info()

    console.print("[bold]Tweek Proxy Certificate Installation[/bold]")
    console.print()
    console.print("This will install a local CA certificate to enable HTTPS interception.")
    console.print("The certificate is generated on YOUR machine and never transmitted.")
    console.print()
    console.print(f"[white]Certificate location: {info['ca_cert']}[/white]")
    console.print()

    if not click.confirm("Install certificate? (requires admin password)"):
        console.print("[white]Cancelled[/white]")
        return

    success, message = install_ca_certificate()

    if success:
        console.print(f"[green]\u2713[/green] {message}")
    else:
        console.print(f"[red]\u2717[/red] {message}")


# ------------------------------------------------------------------
# tweek proxy config
# ------------------------------------------------------------------

@proxy.command(
    "config",
    epilog="""\b
Examples:
  tweek proxy config --enabled           Enable proxy in configuration
  tweek proxy config --disabled          Disable proxy in configuration
  tweek proxy config --enabled --port 8080   Enable proxy on custom port
""",
)
@click.option("--enabled", "set_enabled", is_flag=True, help="Enable proxy in configuration")
@click.option("--disabled", "set_disabled", is_flag=True, help="Disable proxy in configuration")
@click.option("--port", "-p", default=9877, help="Port for proxy")
def proxy_config(set_enabled, set_disabled, port):
    """Configure proxy settings."""
    if not set_enabled and not set_disabled:
        console.print("[red]Specify --enabled or --disabled[/red]")
        return

    import yaml

    config_path = Path.home() / ".tweek" / "config.yaml"
    config_path.parent.mkdir(parents=True, exist_ok=True)

    config = {}
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f) or {}
        except Exception:
            pass

    if set_enabled:
        config["proxy"] = {
            "enabled": True,
            "port": port,
            "block_mode": True,
            "log_only": False,
        }

        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)

        console.print(f"[green]\u2713[/green] Proxy mode enabled (port {port})")
        console.print("[white]Run 'tweek proxy start' to start the proxy[/white]")

    elif set_disabled:
        if "proxy" in config:
            config["proxy"]["enabled"] = False

            with open(config_path, "w") as f:
                yaml.dump(config, f, default_flow_style=False)

        console.print("[green]\u2713[/green] Proxy mode disabled")


# ------------------------------------------------------------------
# tweek proxy wrap
# ------------------------------------------------------------------

@proxy.command(
    "wrap",
    epilog="""\b
Examples:
  tweek proxy wrap openclaw "npm start"                     Wrap a Node.js app
  tweek proxy wrap cursor "/Applications/Cursor.app/Contents/MacOS/Cursor"
  tweek proxy wrap myapp "python serve.py" -o run.sh       Custom output path
  tweek proxy wrap myapp "npm start" --port 8080           Use custom proxy port
""",
)
@click.argument("app_name")
@click.argument("command")
@click.option("--output", "-o", help="Output script path (default: ./run-{app_name}-protected.sh)")
@click.option("--port", "-p", default=9877, help="Proxy port")
def proxy_wrap(app_name: str, command: str, output: str, port: int):
    """Generate a wrapper script to run an app through the proxy."""
    from tweek.proxy.server import generate_wrapper_script

    if output:
        output_path = Path(output)
    else:
        output_path = Path(f"./run-{app_name}-protected.sh")

    script = generate_wrapper_script(command, port=port, output_path=output_path)

    console.print(f"[green]\u2713[/green] Created wrapper script: {output_path}")
    console.print()
    console.print("[bold]Usage:[/bold]")
    console.print(f"  chmod +x {output_path}")
    console.print(f"  ./{output_path.name}")
    console.print()
    console.print("[white]The script will:[/white]")
    console.print("[white]  1. Start Tweek proxy if not running[/white]")
    console.print("[white]  2. Set proxy environment variables[/white]")
    console.print(f"[white]  3. Run: {command}[/white]")


# ------------------------------------------------------------------
# tweek proxy setup
# ------------------------------------------------------------------

@proxy.command(
    "setup",
    epilog="""\b
Examples:
  tweek proxy setup                      Launch interactive proxy setup wizard
""",
)
def proxy_setup():
    """Interactive setup wizard for the HTTP proxy.

    Walks through:
      1. Detecting LLM tools to protect
      2. Generating and trusting CA certificate
      3. Configuring shell environment variables
    """
    console.print()
    console.print("[bold]HTTP Proxy Setup[/bold]")
    console.print("\u2500" * 30)
    console.print()

    # Check dependencies
    try:
        from tweek.proxy import PROXY_AVAILABLE, PROXY_MISSING_DEPS
    except ImportError:
        print_error(
            "Proxy module not available",
            fix_hint="Install with: pip install tweek[proxy]",
        )
        return

    if not PROXY_AVAILABLE:
        print_error(
            "Proxy dependencies not installed",
            fix_hint="Install with: pip install tweek[proxy]",
        )
        return

    # Step 1: Detect tools
    console.print("[bold cyan]Step 1/3: Detect LLM Tools[/bold cyan]")
    try:
        from tweek.proxy import detect_supported_tools

        with spinner("Scanning for LLM tools"):
            tools = detect_supported_tools()

        detected = [(name, info) for name, info in tools.items() if info]
        if detected:
            for name, info in detected:
                print_success(f"Found {name.capitalize()}")
        else:
            print_warning("No LLM tools detected. You can still set up the proxy manually.")
    except Exception as e:
        print_warning(f"Could not detect tools: {e}")
    console.print()

    # Step 2: CA Certificate
    console.print("[bold cyan]Step 2/3: CA Certificate[/bold cyan]")
    setup_cert = click.confirm("Generate and trust Tweek CA certificate?", default=True)
    if setup_cert:
        try:
            from tweek.proxy.cert import generate_ca, trust_ca

            with spinner("Generating CA certificate"):
                generate_ca()
            print_success("CA certificate generated")

            with spinner("Installing to system trust store"):
                trust_ca()
            print_success("Certificate trusted")
        except ImportError:
            print_warning("Certificate module not available. Run: tweek proxy trust")
        except Exception as e:
            print_warning(f"Could not set up certificate: {e}")
            console.print("  [white]You can do this later with: tweek proxy trust[/white]")
    else:
        console.print("  [white]Skipped. Run 'tweek proxy trust' later.[/white]")
    console.print()

    # Step 3: Shell environment
    console.print("[bold cyan]Step 3/3: Environment Variables[/bold cyan]")
    port = click.prompt("Proxy port", default=9877, type=int)

    shell_rc = _detect_shell_rc()
    if shell_rc:
        console.print(f"  Detected shell config: {shell_rc}")
        console.print(f"  Will add:")
        console.print(f"    export HTTP_PROXY=http://127.0.0.1:{port}")
        console.print(f"    export HTTPS_PROXY=http://127.0.0.1:{port}")
        console.print()

        apply_env = click.confirm(f"Add to {shell_rc}?", default=True)
        if apply_env:
            try:
                rc_path = Path(shell_rc).expanduser()
                with open(rc_path, "a") as f:
                    f.write(f"\n# Tweek proxy environment\n")
                    f.write(f"export HTTP_PROXY=http://127.0.0.1:{port}\n")
                    f.write(f"export HTTPS_PROXY=http://127.0.0.1:{port}\n")
                print_success(f"Added to {shell_rc}")
                console.print(f"  [white]Restart your shell or run: source {shell_rc}[/white]")
            except Exception as e:
                print_warning(f"Could not write to {shell_rc}: {e}")
        else:
            console.print("  [white]Skipped. Set HTTP_PROXY and HTTPS_PROXY manually.[/white]")
    else:
        console.print("  [white]Could not detect shell config file.[/white]")
        console.print(f"  Add these to your shell profile:")
        console.print(f"    export HTTP_PROXY=http://127.0.0.1:{port}")
        console.print(f"    export HTTPS_PROXY=http://127.0.0.1:{port}")

    console.print()
    console.print("[bold green]Proxy configured![/bold green]")
    console.print("  Start with: [cyan]tweek proxy start[/cyan]")
    console.print()


# ------------------------------------------------------------------
# Helper (only used by proxy_setup)
# ------------------------------------------------------------------

def _detect_shell_rc() -> str:
    """Detect the user's shell config file."""
    shell = os.environ.get("SHELL", "")
    home = Path.home()

    if "zsh" in shell:
        return "~/.zshrc"
    elif "bash" in shell:
        if (home / ".bash_profile").exists():
            return "~/.bash_profile"
        return "~/.bashrc"
    elif "fish" in shell:
        return "~/.config/fish/config.fish"
    return ""
