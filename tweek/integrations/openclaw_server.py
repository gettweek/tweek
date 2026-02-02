#!/usr/bin/env python3
"""
Tweek OpenClaw Scanning Server

HTTP server exposing Tweek's security scanning pipeline for the OpenClaw
Gateway plugin. Runs on localhost and provides endpoints for skill scanning,
tool screening, output scanning, and fingerprint management.

Endpoints:
    POST /scan               — Run 7-layer SkillScanner on a skill directory
    POST /screen             — Screen a tool call (pre-execution)
    POST /output             — Scan tool output (post-execution)
    POST /fingerprint/check  — Check if skill is known/approved
    POST /fingerprint/register — Register approved skill hash
    GET  /health             — Server health + scanner status
    GET  /report/<skill>     — Retrieve scan report

Usage:
    python -m tweek.integrations.openclaw_server [--port 9878]
"""

import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

# Default port for the OpenClaw scanning server
DEFAULT_PORT = 9878


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
                "matched_text": getattr(f, "matched_text", ""),
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
    from unittest.mock import MagicMock

    logger = MagicMock()
    logger.log_quick = MagicMock()

    # Build the hook input matching Tweek's expected format
    command = ""
    if tool == "bash":
        command = input_data.get("command", "")
    elif tool in ("file_write", "Write"):
        command = input_data.get("content", "") or input_data.get("file_path", "")
    elif tool in ("web_fetch", "WebFetch"):
        command = input_data.get("url", "") or input_data.get("prompt", "")
    else:
        command = json.dumps(input_data)[:500]

    hook_input = {
        "tool_name": tool,
        "tool_input": input_data,
    }

    try:
        result = process_hook(hook_input, logger)
        decision = result.get("hookSpecificOutput", {}).get("permissionDecision", "allow")
        reason = result.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")

        return {
            "decision": decision,
            "reason": reason,
            "tool": tool,
            "tier": tier,
        }
    except Exception as e:
        return {
            "decision": "allow",
            "reason": f"Screening error: {e}",
            "tool": tool,
            "tier": tier,
            "error": str(e),
        }


def _scan_output(content: str) -> Dict[str, Any]:
    """
    Scan tool output for credential leakage and exfiltration attempts.

    Args:
        content: Tool output text to scan

    Returns:
        Scanning result dict
    """
    from tweek.hooks.post_tool_use import process_hook

    input_data = {
        "tool_name": "Read",
        "tool_input": {"file_path": "/virtual/openclaw-output.txt"},
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
        skill_name: Name of the skill

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


class OpenClawScanHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the OpenClaw scanning server."""

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._respond(200, {
                "status": "ok",
                "service": "tweek-openclaw-scanner",
                "port": self.server.server_address[1],
            })
        elif parsed.path.startswith("/report/"):
            skill_name = parsed.path[len("/report/"):]
            if not skill_name:
                self._respond(400, {"error": "Missing skill name"})
                return
            result = _get_report(skill_name)
            status = 200 if "error" not in result else 404
            self._respond(status, result)
        else:
            self._respond(404, {"error": "Not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        data = self._read_json()
        if data is None:
            return  # Error already sent

        if parsed.path == "/scan":
            skill_dir = data.get("skill_dir", "")
            if not skill_dir:
                self._respond(400, {"error": "Missing 'skill_dir' field"})
                return
            if not Path(skill_dir).exists():
                self._respond(400, {"error": f"Directory not found: {skill_dir}"})
                return
            result = _scan_skill(skill_dir)
            self._respond(200, result)

        elif parsed.path == "/screen":
            tool = data.get("tool", "")
            input_data = data.get("input", {})
            tier = data.get("tier", "default")
            if not tool:
                self._respond(400, {"error": "Missing 'tool' field"})
                return
            result = _screen_tool(tool, input_data, tier)
            self._respond(200, result)

        elif parsed.path == "/output":
            content = data.get("content", "")
            if not content:
                self._respond(400, {"error": "Missing 'content' field"})
                return
            result = _scan_output(content)
            self._respond(200, result)

        elif parsed.path == "/fingerprint/check":
            path = data.get("path", "")
            if not path:
                self._respond(400, {"error": "Missing 'path' field"})
                return
            result = _check_fingerprint(path)
            self._respond(200, result)

        elif parsed.path == "/fingerprint/register":
            path = data.get("path", "")
            verdict = data.get("verdict", "")
            if not path or not verdict:
                self._respond(400, {"error": "Missing 'path' or 'verdict' field"})
                return
            report_path = data.get("report_path")
            result = _register_fingerprint(path, verdict, report_path)
            self._respond(200, result)

        else:
            self._respond(404, {"error": "Not found"})

    def _read_json(self) -> Optional[Dict]:
        """Read and parse JSON from request body."""
        try:
            content_length = int(self.headers.get("Content-Length", 0))
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

    # Bind to loopback only — never expose to the network
    server = HTTPServer(("127.0.0.1", port), OpenClawScanHandler)
    print(f"Tweek OpenClaw Scanning Server running on http://127.0.0.1:{port}")
    print(f"  POST /scan               — Scan a skill directory (7-layer)")
    print(f"  POST /screen             — Screen a tool call")
    print(f"  POST /output             — Scan tool output")
    print(f"  POST /fingerprint/check  — Check skill fingerprint")
    print(f"  POST /fingerprint/register — Register approved skill")
    print(f"  GET  /health             — Health check")
    print(f"  GET  /report/<skill>     — Retrieve scan report")
    print(f"Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Tweek OpenClaw Scanning Server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                        help=f"Port to listen on (default: {DEFAULT_PORT})")
    args = parser.parse_args()
    run_server(args.port)
