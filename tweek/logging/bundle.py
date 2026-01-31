#!/usr/bin/env python3
"""
Tweek Diagnostic Bundle Collector

Collects logs, configs, and system info into a zip file for support.
Sensitive data is redacted before inclusion.

Usage:
    tweek logs bundle                        # Create bundle in current dir
    tweek logs bundle -o /tmp/bundle.zip     # Specify output path
    tweek logs bundle --days 7               # Only last 7 days of events
    tweek logs bundle --dry-run              # Show what would be collected
"""

import json
import platform
import shutil
import sqlite3
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

TWEEK_DIR = Path.home() / ".tweek"


class BundleCollector:
    """
    Collects diagnostic data into a zip bundle for support.

    Automatically redacts sensitive data (API keys, secrets, credentials)
    before including any file in the bundle.
    """

    # Files that are NEVER included
    EXCLUDED_FILES = {
        "license.key",
        "credential_registry.json",
    }

    # Directories that are NEVER included
    EXCLUDED_DIRS = {
        "certs",  # CA private keys
    }

    def __init__(self, redact: bool = True, days: Optional[int] = None):
        self.redact = redact
        self.days = days
        self._redactor = None
        self._collected: List[Dict[str, Any]] = []

    def _get_redactor(self):
        """Lazy-load the redactor."""
        if self._redactor is None:
            from tweek.logging.security_log import LogRedactor
            self._redactor = LogRedactor(enabled=self.redact)
        return self._redactor

    def collect_security_db(self) -> Optional[Path]:
        """Copy the security events database."""
        db_path = TWEEK_DIR / "security.db"
        if not db_path.exists():
            self._collected.append({"file": "security.db", "status": "not found"})
            return None

        self._collected.append({
            "file": "security.db",
            "status": "included",
            "size": db_path.stat().st_size,
        })
        return db_path

    def collect_approvals_db(self) -> Optional[Path]:
        """Copy the MCP approvals database."""
        db_path = TWEEK_DIR / "approvals.db"
        if not db_path.exists():
            self._collected.append({"file": "approvals.db", "status": "not found"})
            return None

        self._collected.append({
            "file": "approvals.db",
            "status": "included",
            "size": db_path.stat().st_size,
        })
        return db_path

    def collect_proxy_log(self) -> Optional[Path]:
        """Copy the HTTP proxy log."""
        log_path = TWEEK_DIR / "proxy" / "proxy.log"
        if not log_path.exists():
            self._collected.append({"file": "proxy/proxy.log", "status": "not found"})
            return None

        self._collected.append({
            "file": "proxy/proxy.log",
            "status": "included",
            "size": log_path.stat().st_size,
        })
        return log_path

    def collect_json_log(self) -> Optional[Path]:
        """Copy the JSON event log."""
        log_path = TWEEK_DIR / "security_events.jsonl"
        if not log_path.exists():
            self._collected.append({"file": "security_events.jsonl", "status": "not found"})
            return None

        self._collected.append({
            "file": "security_events.jsonl",
            "status": "included",
            "size": log_path.stat().st_size,
        })
        return log_path

    def collect_config(self, scope: str = "user") -> Optional[str]:
        """Collect and redact a config file.

        Returns redacted YAML content as string, or None if not found.
        """
        if scope == "user":
            config_path = TWEEK_DIR / "config.yaml"
            bundle_name = "config_user.yaml"
        else:
            config_path = Path.cwd() / ".tweek" / "config.yaml"
            bundle_name = "config_project.yaml"

        if not config_path.exists():
            self._collected.append({"file": bundle_name, "status": "not found"})
            return None

        content = config_path.read_text()
        if self.redact:
            redactor = self._get_redactor()
            content = redactor.redact_string(content)

        self._collected.append({
            "file": bundle_name,
            "status": "included (redacted)" if self.redact else "included",
        })
        return content

    def collect_doctor_output(self) -> str:
        """Run tweek doctor programmatically and capture output."""
        try:
            from tweek.diagnostics import run_health_checks, get_health_verdict

            checks = run_health_checks()
            verdict = get_health_verdict(checks)

            lines = [
                f"Tweek Doctor Report",
                f"Generated: {datetime.utcnow().isoformat()}Z",
                f"Overall: {verdict}",
                "",
            ]
            for check in checks:
                status = check.status.value if hasattr(check.status, "value") else str(check.status)
                lines.append(f"[{status:>7}] {check.name}: {check.message}")
                if check.fix_hint:
                    lines.append(f"          Fix: {check.fix_hint}")

            self._collected.append({"file": "doctor_output.txt", "status": "generated"})
            return "\n".join(lines)

        except Exception as e:
            self._collected.append({"file": "doctor_output.txt", "status": f"error: {e}"})
            return f"Failed to run doctor: {e}"

    def collect_system_info(self) -> Dict[str, Any]:
        """Collect platform and version information."""
        info = {
            "timestamp": datetime.now(tz=None).isoformat() + "Z",
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "python_version": platform.python_version(),
            },
            "tweek": {},
        }

        # Tweek version
        try:
            from tweek import __version__
            info["tweek"]["version"] = __version__
        except (ImportError, AttributeError):
            info["tweek"]["version"] = "unknown"

        # License tier (not the key)
        try:
            from tweek.licensing import get_license
            license_mgr = get_license()
            info["tweek"]["license_tier"] = license_mgr.tier.value
        except Exception:
            info["tweek"]["license_tier"] = "unknown"

        # Platform capabilities
        try:
            from tweek.platform import get_capabilities
            caps = get_capabilities()
            info["tweek"]["capabilities"] = {
                "sandbox": caps.sandbox_available,
                "vault_backend": caps.vault_backend,
            }
        except Exception:
            pass

        # MCP availability
        try:
            from mcp.server import Server
            info["tweek"]["mcp_available"] = True
        except ImportError:
            info["tweek"]["mcp_available"] = False

        # Data directory stats
        try:
            if TWEEK_DIR.exists():
                info["tweek"]["data_dir_exists"] = True
                files = list(TWEEK_DIR.iterdir())
                info["tweek"]["data_files"] = [
                    f.name for f in files
                    if f.name not in self.EXCLUDED_FILES
                    and f.name not in self.EXCLUDED_DIRS
                ]
        except Exception:
            pass

        self._collected.append({"file": "system_info.json", "status": "generated"})
        return info

    def create_bundle(self, output_path: Path) -> Path:
        """
        Create the diagnostic bundle zip file.

        Args:
            output_path: Path for the output zip file

        Returns:
            Path to the created zip file
        """
        self._collected = []

        with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # Security database
            db_path = self.collect_security_db()
            if db_path:
                if self.days:
                    # Export only recent events to a temp copy
                    self._add_filtered_db(zf, db_path, "security.db")
                else:
                    zf.write(db_path, "security.db")

            # Approvals database
            approvals_path = self.collect_approvals_db()
            if approvals_path:
                zf.write(approvals_path, "approvals.db")

            # Proxy log
            proxy_log = self.collect_proxy_log()
            if proxy_log:
                zf.write(proxy_log, "proxy.log")

            # JSON event log
            json_log = self.collect_json_log()
            if json_log:
                zf.write(json_log, "security_events.jsonl")

            # Configs (redacted)
            for scope, name in [("user", "config_user.yaml"), ("project", "config_project.yaml")]:
                content = self.collect_config(scope)
                if content:
                    zf.writestr(name, content)

            # Doctor output
            doctor = self.collect_doctor_output()
            zf.writestr("doctor_output.txt", doctor)

            # System info
            sys_info = self.collect_system_info()
            zf.writestr("system_info.json", json.dumps(sys_info, indent=2))

            # Manifest
            manifest = {
                "bundle_version": "1.0",
                "created_at": datetime.now(tz=None).isoformat() + "Z",
                "redacted": self.redact,
                "days_filter": self.days,
                "files": self._collected,
            }
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        return output_path

    def get_dry_run_report(self) -> List[Dict[str, Any]]:
        """Generate a dry-run report showing what would be collected."""
        self._collected = []

        self.collect_security_db()
        self.collect_approvals_db()
        self.collect_proxy_log()
        self.collect_json_log()
        self.collect_config("user")
        self.collect_config("project")
        self._collected.append({"file": "doctor_output.txt", "status": "will generate"})
        self._collected.append({"file": "system_info.json", "status": "will generate"})
        self._collected.append({"file": "manifest.json", "status": "will generate"})

        return self._collected

    def _add_filtered_db(self, zf: zipfile.ZipFile, db_path: Path, archive_name: str):
        """Add a filtered copy of the security database (only recent events)."""
        import tempfile
        tmp_db = Path(tempfile.mktemp(suffix=".db"))
        try:
            # Create a new DB with only recent events
            src = sqlite3.connect(str(db_path))
            dst = sqlite3.connect(str(tmp_db))

            # Copy schema
            for row in src.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='security_events'"
            ):
                if row[0]:
                    dst.execute(row[0])

            # Copy filtered data
            days_filter = f"-{self.days} days"
            rows = src.execute(
                "SELECT * FROM security_events WHERE timestamp > datetime('now', ?)",
                (days_filter,),
            ).fetchall()

            if rows:
                placeholders = ",".join("?" * len(rows[0]))
                for row in rows:
                    dst.execute(
                        f"INSERT INTO security_events VALUES ({placeholders})",
                        tuple(row),
                    )

            dst.commit()
            src.close()
            dst.close()

            zf.write(tmp_db, archive_name)
        finally:
            if tmp_db.exists():
                tmp_db.unlink()
