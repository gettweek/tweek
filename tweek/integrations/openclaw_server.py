#!/usr/bin/env python3
"""
Tweek OpenClaw Scanning Server

HTTP server exposing Tweek's security scanning pipeline for the OpenClaw
Gateway plugin. Runs on localhost and provides endpoints for skill scanning,
tool screening, output scanning, and fingerprint management.

Endpoints:
    POST /scan               - Run 7-layer SkillScanner on a skill directory
    POST /screen             - Screen a tool call (pre-execution)
    POST /output             - Scan tool output (post-execution)
    POST /fingerprint/check  - Check if skill is known/approved
    POST /fingerprint/register - Register approved skill hash
    GET  /health             - Server health + scanner status
    GET  /report/<skill>     - Retrieve scan report

Usage:
    python -m tweek.integrations.openclaw_server [--port 9878]
"""

import json
import os
import secrets
import signal
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

# Default port for the OpenClaw scanning server
DEFAULT_PORT = 9878

# Maximum request body size (10 MB)
MAX_REQUEST_SIZE = 10 * 1024 * 1024

# Token file for bearer auth
TOKEN_FILE = Path.home() / ".tweek" / ".scanner_token"

# PID file for process management
PID_FILE = Path.home() / ".tweek" / ".scanner.pid"

# Allowed base directory for skill scanning
OPENCLAW_SKILLS_BASE = Path.home() / ".openclaw" / "workspace" / "skills"

# Rate limit settings per endpoint (max requests per 60-second window)
RATE_LIMITS = {
    "/scan": 5,
    "/screen": 60,
    "/output": 60,
    "/fingerprint/check": 30,
    "/fingerprint/register": 10,
}

# Pre-resolved event type names to avoid dynamic attribute lookups
_EVENT_TYPES = {}


def _init_event_types():
    """Cache EventType enum values at startup."""
    global _EVENT_TYPES
    try:
        from tweek.logging.security_log import EventType
        _EVENT_TYPES = {e.name: e for e in EventType}
    except Exception:
        _EVENT_TYPES = {}


def _load_or_create_token() -> str:
    """Load existing auth token or create a new one.

    Returns:
        The bearer token string.
    """
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)

    if TOKEN_FILE.exists():
        token = TOKEN_FILE.read_text().strip()
        if token:
            return token

    token = secrets.token_urlsafe(32)
    TOKEN_FILE.write_text(token)
    TOKEN_FILE.chmod(0o600)
    return token


def _get_logger():
    """Get the security logger, returning None if unavailable."""
    try:
        from tweek.logging.security_log import get_logger
        return get_logger()
    except Exception:
        return None


class _RateTracker:
    """Simple per-endpoint rate limiter using sliding window counters."""

    def __init__(self, limits: Dict[str, int]):
        self._limits = limits
        self._windows: Dict[str, list] = {}

    def check(self, endpoint: str) -> bool:
        """Return True if request is allowed, False if rate-limited."""
        limit = self._limits.get(endpoint)
        if limit is None:
            return True

        now = time.monotonic()
        window = self._windows.setdefault(endpoint, [])

        # Purge entries older than 60 seconds
        cutoff = now - 60.0
        self._windows[endpoint] = [t for t in window if t > cutoff]
        window = self._windows[endpoint]

        if len(window) >= limit:
            return False

        window.append(now)
        return True

    def retry_after(self, endpoint: str) -> int:
        """Seconds until the oldest entry in the window expires."""
        window = self._windows.get(endpoint, [])
        if not window:
            return 0
        oldest = min(window)
        remaining = 60.0 - (time.monotonic() - oldest)
        return max(1, int(remaining))


def _scan_skill(skill_dir: str) -> Dict[str, Any]:
    """
    Run the 7-layer SkillScanner on a skill directory.

    Args:
        skill_dir: Path to the directory containing SKILL.md

    Returns:
        Scan report as a JSON-serializable dict
    """
    from tweek.skills.scanner import SkillScanner

    scanner = SkillScanner()
    report = scanner.scan(Path(skill_dir))

    return {
        "verdict": report.verdict,
        "risk_level": report.risk_level,
        "skill_name": report.skill_name,
        "layers_passed": report.layers_passed,
        "layers_total": report.layers_total,
        "findings": [
            {
                "layer": f.layer,
                "severity": f.severity,
                "description": f.description,
                "matched_text": f.matched_text if hasattr(f, "matched_text") else "",
            }
            for f in report.findings
        ],
        "severity_counts": {
            "critical": report.critical_count,
            "high": report.high_count,
            "medium": report.medium_count,
            "low": report.low_count,
        },
        "report_path": str(report.report_path) if report.report_path else None,
    }


def _screen_tool(tool: str, input_data: Dict, tier: str = "default") -> Dict[str, Any]:
    """
    Screen a tool call through Tweek's pattern matcher and LLM reviewer.

    Args:
        tool: Tool name (e.g., "bash", "file_write", "web_fetch")
        input_data: Tool input parameters
        tier: Security tier ("safe", "default", "risky", "dangerous")

    Returns:
        Screening decision dict
    """
    from tweek.hooks.pre_tool_use import process_hook

    logger = _get_logger()

    hook_input = {
        "tool_name": tool,
        "tool_input": input_data,
    }

    try:
        result = process_hook(hook_input, logger)
        decision = result.get("hookSpecificOutput", {}).get("permissionDecision", "allow")
        reason = result.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")

        # Log the screening decision
        if logger:
            evt = _EVENT_TYPES.get("ALLOWED") if decision == "allow" else _EVENT_TYPES.get("USER_PROMPTED")
            if evt:
                logger.log_quick(
                    evt,
                    tool,
                    command=json.dumps(input_data)[:500],
                    decision=decision,
                    decision_reason=reason[:200],
                    source="openclaw_server",
                )

        return {
            "decision": decision,
            "reason": reason,
            "tool": tool,
            "tier": tier,
        }
    except Exception as e:
        # Fail-closed: default to "ask" on errors, not "allow"
        if logger:
            evt = _EVENT_TYPES.get("ERROR")
            if evt:
                logger.log_quick(
                    evt,
                    tool,
                    command=json.dumps(input_data)[:200],
                    decision="ask",
                    decision_reason=f"Screening error: {e}",
                    source="openclaw_server",
                )
        return {
            "decision": "ask",
            "reason": f"Screening error: {e}. Manual review recommended.",
            "tool": tool,
            "tier": tier,
            "error": str(e),
            "degraded": True,
        }


def _scan_output(content: str, tool_name: str = "unknown_openclaw_tool") -> Dict[str, Any]:
    """
    Scan tool output for credential leakage and exfiltration attempts.

    Args:
        content: Tool output text to scan
        tool_name: The actual tool that produced the output

    Returns:
        Scanning result dict
    """
    from tweek.hooks.post_tool_use import process_hook

    input_data = {
        "tool_name": tool_name,
        "tool_input": {"file_path": f"/openclaw/{tool_name}/output"},
        "tool_response": content,
    }

    try:
        result = process_hook(input_data)
        if result.get("decision") == "block":
            return {
                "blocked": True,
                "reason": result.get("reason", ""),
            }
    except Exception as e:
        return {"blocked": False, "error": f"Output scanning error: {e}"}

    return {"blocked": False}


def _check_fingerprint(skill_path: str) -> Dict[str, Any]:
    """
    Check if a skill is known/approved via fingerprint.

    Args:
        skill_path: Absolute path to the SKILL.md file

    Returns:
        Fingerprint status dict
    """
    from tweek.skills.fingerprints import get_fingerprints

    fps = get_fingerprints()
    known = fps.is_known(Path(skill_path))

    return {
        "known": known,
        "path": skill_path,
    }


def _register_fingerprint(
    skill_path: str, verdict: str, report_path: Optional[str] = None
) -> Dict[str, Any]:
    """
    Register a skill's fingerprint after approval.

    Args:
        skill_path: Absolute path to the SKILL.md file
        verdict: Scan verdict ("pass", "manual_review", "fail")
        report_path: Optional path to the scan report

    Returns:
        Registration result dict
    """
    from tweek.skills.fingerprints import get_fingerprints

    fps = get_fingerprints()
    fps.register(Path(skill_path), verdict=verdict, report_path=report_path)

    return {
        "registered": True,
        "path": skill_path,
        "verdict": verdict,
    }


def _get_report(skill_name: str) -> Dict[str, Any]:
    """
    Retrieve the most recent scan report for a skill.

    Args:
        skill_name: Name of the skill (must not contain path separators)

    Returns:
        Report dict or error
    """
    from tweek.skills import REPORTS_DIR

    # Find the most recent report for this skill
    reports = sorted(
        REPORTS_DIR.glob(f"{skill_name}-*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not reports:
        return {"error": f"No report found for skill: {skill_name}"}

    try:
        with open(reports[0]) as f:
            report_data = json.load(f)
        report_data["report_path"] = str(reports[0])
        return report_data
    except (json.JSONDecodeError, IOError) as e:
        return {"error": f"Failed to read report: {e}"}


def _validate_skill_path(path_str: str) -> Optional[str]:
    """Validate that a skill path resolves under the allowed base directory.

    Returns None if valid, or an error message string if invalid.
    """
    try:
        resolved = Path(path_str).resolve()
    except (ValueError, OSError) as e:
        return f"Invalid path: {e}"

    # Must be under the OpenClaw skills directory
    try:
        resolved.relative_to(OPENCLAW_SKILLS_BASE.resolve())
    except ValueError:
        return f"Path must be under {OPENCLAW_SKILLS_BASE}"

    return None


def _sanitize_skill_name(name: str) -> Optional[str]:
    """Validate a skill name for use in report lookups.

    Returns None if valid, or an error message string if invalid.
    """
    if not name:
        return "Missing skill name"
    if "/" in name or "\\" in name or ".." in name or "\x00" in name:
        return "Invalid characters in skill name"
    return None


class OpenClawScanHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the OpenClaw scanning server."""

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            # Health endpoint is exempt from auth
            self._respond(200, {
                "status": "ok",
                "service": "tweek-openclaw-scanner",
                "port": self.server.server_address[1],
            })
        elif parsed.path.startswith("/report/"):
            if not self._check_auth():
                return

            raw_name = parsed.path[len("/report/"):]
            error = _sanitize_skill_name(raw_name)
            if error:
                self._respond(400, {"error": error})
                return

            result = _get_report(raw_name)
            status = 200 if "error" not in result else 404
            self._respond(status, result)
        else:
            self._respond(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)

        if not self._check_auth():
            return

        # Rate limiting (skip if rate_tracker not configured, e.g. in tests)
        rate_tracker = getattr(self.server, "rate_tracker", None)
        if rate_tracker and not rate_tracker.check(parsed.path):
            retry = rate_tracker.retry_after(parsed.path)
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", str(retry))
            self.end_headers()
            body = json.dumps({"error": "Rate limit exceeded", "retry_after": retry})
            self.wfile.write(body.encode())
            return

        data = self._read_json()
        if data is None:
            return  # Error already sent

        if parsed.path == "/scan":
            self._handle_scan(data)
        elif parsed.path == "/screen":
            self._handle_screen(data)
        elif parsed.path == "/output":
            self._handle_output(data)
        elif parsed.path == "/fingerprint/check":
            self._handle_fingerprint_check(data)
        elif parsed.path == "/fingerprint/register":
            self._handle_fingerprint_register(data)
        else:
            self._respond(404, {"error": "Not found"})

    def _handle_scan(self, data: Dict):
        skill_dir = data.get("skill_dir", "")
        if not skill_dir:
            self._respond(400, {"error": "Missing 'skill_dir' field"})
            return

        # Validate path is under allowed directory
        path_error = _validate_skill_path(skill_dir)
        if path_error:
            self._respond(403, {"error": path_error})
            return

        if not Path(skill_dir).exists():
            self._respond(400, {"error": f"Directory not found: {skill_dir}"})
            return

        # Check skill guard before scanning
        try:
            from tweek.skills.guard import get_skill_guard_reason
            guard_reason = get_skill_guard_reason("Read", {"file_path": skill_dir})
            if guard_reason:
                self._respond(403, {"error": guard_reason})
                return
        except ImportError:
            pass

        result = _scan_skill(skill_dir)
        self._respond(200, result)

    def _handle_screen(self, data: Dict):
        tool = data.get("tool", "")
        input_data = data.get("input", {})
        tier = data.get("tier", "default")
        if not tool:
            self._respond(400, {"error": "Missing 'tool' field"})
            return
        result = _screen_tool(tool, input_data, tier)
        self._respond(200, result)

    def _handle_output(self, data: Dict):
        content = data.get("content", "")
        tool_name = data.get("tool_name", "unknown_openclaw_tool")
        if not content:
            self._respond(400, {"error": "Missing 'content' field"})
            return
        result = _scan_output(content, tool_name=tool_name)
        self._respond(200, result)

    def _handle_fingerprint_check(self, data: Dict):
        path = data.get("path", "")
        if not path:
            self._respond(400, {"error": "Missing 'path' field"})
            return
        result = _check_fingerprint(path)
        self._respond(200, result)

    def _handle_fingerprint_register(self, data: Dict):
        path = data.get("path", "")
        verdict = data.get("verdict", "")
        if not path or not verdict:
            self._respond(400, {"error": "Missing 'path' or 'verdict' field"})
            return

        # Check skill guard -- don't register fingerprints for protected paths
        try:
            from tweek.skills.guard import is_chamber_protected_path
            if is_chamber_protected_path(path):
                self._respond(403, {
                    "error": "Cannot register fingerprint for protected path"
                })
                return
        except ImportError:
            pass

        report_path = data.get("report_path")
        result = _register_fingerprint(path, verdict, report_path)
        self._respond(200, result)

    def _check_auth(self) -> bool:
        """Verify bearer token. Returns True if authenticated, sends 401 otherwise."""
        expected = self.server.auth_token if hasattr(self.server, "auth_token") else None
        if not expected:
            return True  # No token configured (dev/test mode)

        auth_header = self.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            self._respond(401, {"error": "Missing or invalid Authorization header"})
            return False

        token = auth_header[len("Bearer "):]
        if not secrets.compare_digest(token, expected):
            self._respond(401, {"error": "Invalid token"})
            return False

        return True

    def _read_json(self) -> Optional[Dict]:
        """Read and parse JSON from request body with size limit."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self._respond(400, {"error": "Invalid Content-Length"})
            return None

        if content_length > MAX_REQUEST_SIZE:
            self._respond(413, {
                "error": f"Request too large (max {MAX_REQUEST_SIZE // (1024 * 1024)} MB)"
            })
            return None

        try:
            body = self.rfile.read(content_length)
            return json.loads(body)
        except (json.JSONDecodeError, ValueError) as e:
            self._respond(400, {"error": f"Invalid JSON: {e}"})
            return None

    def _respond(self, status: int, data: dict):
        """Send a JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "http://127.0.0.1")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        """Custom log format for the scanning server."""
        sys.stderr.write(
            f"[Tweek Scanner] {self.address_string()} - {format % args}\n"
        )


def run_server(port: int = DEFAULT_PORT):
    """Start the OpenClaw scanning server."""
    # Load .env if available
    try:
        from tweek.utils.env import load_env
        load_env()
    except ImportError:
        # Manual fallback
        env_path = Path.home() / ".tweek" / ".env"
        if not env_path.exists():
            env_path = Path(__file__).parent.parent.parent / ".env"
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip("'\""))

    # Initialize event types for logging
    _init_event_types()

    # Load or generate auth token
    auth_token = _load_or_create_token()

    # Write PID file
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))

    # Bind to loopback only -- never expose to the network
    server = HTTPServer(("127.0.0.1", port), OpenClawScanHandler)
    server.auth_token = auth_token
    server.rate_tracker = _RateTracker(RATE_LIMITS)

    # SIGTERM handler for graceful shutdown
    def _handle_signal(signum, frame):
        sys.stderr.write(f"\n[Tweek Scanner] Received signal {signum}, shutting down.\n")
        server.shutdown()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    print(f"Tweek OpenClaw Scanning Server running on http://127.0.0.1:{port}")
    print(f"  Auth token stored in: {TOKEN_FILE}")
    print(f"  PID file: {PID_FILE}")
    print(f"  POST /scan               - Scan a skill directory (7-layer)")
    print(f"  POST /screen             - Screen a tool call")
    print(f"  POST /output             - Scan tool output")
    print(f"  POST /fingerprint/check  - Check skill fingerprint")
    print(f"  POST /fingerprint/register - Register approved skill")
    print(f"  GET  /health             - Health check")
    print(f"  GET  /report/<skill>     - Retrieve scan report")
    print(f"Press Ctrl+C to stop.")

    try:
        server.serve_forever()
    finally:
        # Clean up PID file on exit
        try:
            PID_FILE.unlink(missing_ok=True)
        except OSError:
            pass
        print("\nShutting down.")


def _main():
    import argparse
    parser = argparse.ArgumentParser(description="Tweek OpenClaw Scanning Server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"Port to listen on (default: {DEFAULT_PORT})")
    args = parser.parse_args()
    run_server(args.port)


# Entry point
_entry = "_" + "main" + "_"
if __name__ == _entry:
    _main()
