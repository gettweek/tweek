"""
Tweek Skill Isolation Chamber — Lifecycle Manager

Manages the full skill lifecycle: accept → scan → approve/jail → install.
Skills enter the chamber as inert files and only become active after passing
the 7-layer security scan.
"""

import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from tweek.skills import (
    CHAMBER_DIR,
    CLAUDE_GLOBAL_SKILLS,
    JAIL_DIR,
    REPORTS_DIR,
    ensure_directories,
    get_claude_project_skills,
)
from tweek.skills.config import IsolationConfig, load_isolation_config
from tweek.skills.scanner import SkillScanner, SkillScanReport


class SkillIsolationChamber:
    """
    Manages the skill isolation chamber lifecycle.

    Skills flow: accept → scan → approve/jail → install
    """

    def __init__(self, config: Optional[IsolationConfig] = None):
        self.config = config or load_isolation_config()
        self.scanner = SkillScanner(config=self.config)
        ensure_directories()

    # =========================================================================
    # Accept: Place a skill in the chamber
    # =========================================================================

    def accept_skill(
        self, source_path: Path, skill_name: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Accept a skill into the isolation chamber.

        Copies the skill directory to ~/.tweek/skills/chamber/<name>/.
        Does NOT activate it — the skill is inert until approved.

        Args:
            source_path: Path to the skill directory or SKILL.md file
            skill_name: Override skill name (defaults to directory name)

        Returns:
            (success, message)
        """
        source = Path(source_path).resolve()

        # Handle both directory and file paths
        if source.is_file() and source.name == "SKILL.md":
            source = source.parent
        elif not source.is_dir():
            return False, f"Source path does not exist or is not a directory: {source}"

        if not (source / "SKILL.md").exists():
            return False, f"No SKILL.md found in {source}"

        name = skill_name or source.name
        target = CHAMBER_DIR / name

        if target.exists():
            return False, (
                f"Skill '{name}' already in chamber. "
                f"Remove it first or use a different name."
            )

        try:
            shutil.copytree(source, target)
            # Set restrictive permissions
            target.chmod(0o700)
            self._log_event("skill_chamber_intake", name, {
                "source": str(source),
                "target": str(target),
            })
            return True, f"Skill '{name}' placed in isolation chamber."
        except Exception as e:
            return False, f"Failed to copy skill to chamber: {e}"

    # =========================================================================
    # Scan: Run the 7-layer security pipeline
    # =========================================================================

    def scan_skill(self, skill_name: str) -> Tuple[SkillScanReport, str]:
        """
        Scan a skill in the chamber using the 7-layer pipeline.

        Args:
            skill_name: Name of the skill in the chamber

        Returns:
            (report, message)
        """
        skill_dir = CHAMBER_DIR / skill_name
        if not skill_dir.exists():
            empty_report = SkillScanReport(skill_name=skill_name, verdict="fail")
            return empty_report, f"Skill '{skill_name}' not found in chamber."

        report = self.scanner.scan(skill_dir)

        # Save report
        self._save_report(report)

        self._log_event("skill_scan_complete", skill_name, {
            "verdict": report.verdict,
            "risk_level": report.risk_level,
            "critical": report.critical_count,
            "high": report.high_count,
            "duration_ms": report.scan_duration_ms,
        })

        return report, self._format_verdict_message(report)

    # =========================================================================
    # Accept and Scan: Combined operation
    # =========================================================================

    def accept_and_scan(
        self,
        source_path: Path,
        skill_name: Optional[str] = None,
        target: str = "global",
    ) -> Tuple[SkillScanReport, str]:
        """
        Accept a skill into the chamber and immediately scan it.

        In auto mode, also installs if the scan passes.

        Args:
            source_path: Path to the skill directory
            skill_name: Override name
            target: "global" or "project"

        Returns:
            (report, message)
        """
        source = Path(source_path).resolve()
        if source.is_file() and source.name == "SKILL.md":
            source = source.parent

        name = skill_name or source.name

        # Accept
        ok, msg = self.accept_skill(source, name)
        if not ok:
            return SkillScanReport(skill_name=name, verdict="fail"), msg

        # Scan
        report, scan_msg = self.scan_skill(name)

        # Auto-install if configured and passed
        if report.verdict == "pass" and self.config.mode == "auto":
            ok, install_msg = self.approve_skill(name, target=target)
            if ok:
                return report, f"{scan_msg}\n{install_msg}"
            else:
                return report, f"{scan_msg}\nAuto-install failed: {install_msg}"

        # Auto-jail if failed
        if report.verdict == "fail":
            self.jail_skill(name, report)
            return report, f"{scan_msg}\nQuarantined to jail."

        return report, scan_msg

    # =========================================================================
    # Approve: Move from chamber to Claude's skill directory
    # =========================================================================

    def approve_skill(
        self, skill_name: str, target: str = "global"
    ) -> Tuple[bool, str]:
        """
        Approve a skill and install it to Claude's skill directory.

        Args:
            skill_name: Name of the skill in the chamber
            target: "global" (~/.claude/skills/) or "project" (./.claude/skills/)

        Returns:
            (success, message)
        """
        skill_dir = CHAMBER_DIR / skill_name
        if not skill_dir.exists():
            return False, f"Skill '{skill_name}' not found in chamber."

        if target == "project":
            install_dir = get_claude_project_skills() / skill_name
        else:
            install_dir = CLAUDE_GLOBAL_SKILLS / skill_name

        try:
            install_dir.parent.mkdir(parents=True, exist_ok=True)

            # Atomic-ish: copy first, then remove from chamber
            if install_dir.exists():
                shutil.rmtree(install_dir)
            shutil.copytree(skill_dir, install_dir)
            shutil.rmtree(skill_dir)

            self._log_event("skill_approved", skill_name, {
                "install_path": str(install_dir),
                "target": target,
            })

            return True, f"Skill '{skill_name}' installed to {install_dir}"

        except Exception as e:
            return False, f"Failed to install skill: {e}"

    # =========================================================================
    # Jail: Quarantine a failed skill
    # =========================================================================

    def jail_skill(
        self,
        skill_name: str,
        report: Optional[SkillScanReport] = None,
    ) -> Tuple[bool, str]:
        """
        Move a skill from the chamber to the jail.

        Args:
            skill_name: Name of the skill
            report: Optional scan report to embed in jail

        Returns:
            (success, message)
        """
        skill_dir = CHAMBER_DIR / skill_name
        if not skill_dir.exists():
            return False, f"Skill '{skill_name}' not found in chamber."

        jail_target = JAIL_DIR / skill_name

        try:
            if jail_target.exists():
                shutil.rmtree(jail_target)

            shutil.move(str(skill_dir), str(jail_target))

            # Embed scan report in jail
            if report:
                report_path = jail_target / "scan-report.json"
                report_path.write_text(report.to_json())

            self._log_event("skill_jailed", skill_name, {
                "verdict": report.verdict if report else "unknown",
                "risk_level": report.risk_level if report else "unknown",
            })

            if self.config.notify_on_jail:
                print(
                    f"TWEEK SECURITY: Skill '{skill_name}' FAILED security scan. "
                    f"Quarantined to jail.",
                    file=sys.stderr,
                )

            return True, f"Skill '{skill_name}' quarantined to jail."

        except Exception as e:
            return False, f"Failed to jail skill: {e}"

    # =========================================================================
    # Release: Re-scan and potentially release from jail
    # =========================================================================

    def release_from_jail(
        self, skill_name: str, force: bool = False
    ) -> Tuple[bool, str]:
        """
        Re-scan a jailed skill and release if it now passes.

        Args:
            skill_name: Name of the jailed skill
            force: Force release without re-scanning (dangerous)

        Returns:
            (success, message)
        """
        jail_path = JAIL_DIR / skill_name
        if not jail_path.exists():
            return False, f"Skill '{skill_name}' not found in jail."

        if force:
            # Move back to chamber for manual approval
            target = CHAMBER_DIR / skill_name
            if target.exists():
                shutil.rmtree(target)
            shutil.move(str(jail_path), str(target))
            return True, (
                f"Skill '{skill_name}' force-released to chamber. "
                f"Use 'tweek skills chamber approve {skill_name}' to install."
            )

        # Move to chamber for re-scan
        chamber_path = CHAMBER_DIR / skill_name
        if chamber_path.exists():
            shutil.rmtree(chamber_path)
        shutil.copytree(jail_path, chamber_path)

        # Re-scan
        report, msg = self.scan_skill(skill_name)

        if report.verdict == "pass":
            shutil.rmtree(jail_path)
            return True, f"Skill '{skill_name}' now passes. {msg}"
        elif report.verdict == "manual_review":
            shutil.rmtree(jail_path)
            return True, f"Skill '{skill_name}' needs manual review. {msg}"
        else:
            # Still fails — remove from chamber, keep in jail
            shutil.rmtree(chamber_path)
            return False, f"Skill '{skill_name}' still fails. {msg}"

    # =========================================================================
    # List and Query
    # =========================================================================

    def list_chamber(self) -> List[Dict[str, str]]:
        """List skills currently in the isolation chamber."""
        if not CHAMBER_DIR.exists():
            return []
        return [
            {
                "name": d.name,
                "path": str(d),
                "has_skill_md": (d / "SKILL.md").exists(),
            }
            for d in sorted(CHAMBER_DIR.iterdir())
            if d.is_dir()
        ]

    def list_jail(self) -> List[Dict[str, str]]:
        """List skills currently in the jail."""
        if not JAIL_DIR.exists():
            return []
        results = []
        for d in sorted(JAIL_DIR.iterdir()):
            if not d.is_dir():
                continue
            info = {"name": d.name, "path": str(d)}
            report_path = d / "scan-report.json"
            if report_path.exists():
                try:
                    report_data = json.loads(report_path.read_text())
                    info["verdict"] = report_data.get("verdict", "unknown")
                    info["risk_level"] = report_data.get("risk_level", "unknown")
                    info["critical"] = report_data.get("summary", {}).get("critical", 0)
                    info["high"] = report_data.get("summary", {}).get("high", 0)
                except (json.JSONDecodeError, IOError):
                    pass
            results.append(info)
        return results

    def get_report(self, skill_name: str) -> Optional[Dict]:
        """Get the latest scan report for a skill."""
        # Check jail first (has embedded report)
        jail_report = JAIL_DIR / skill_name / "scan-report.json"
        if jail_report.exists():
            try:
                return json.loads(jail_report.read_text())
            except (json.JSONDecodeError, IOError):
                pass

        # Check reports directory
        if REPORTS_DIR.exists():
            reports = sorted(
                REPORTS_DIR.glob(f"{skill_name}-*.json"),
                reverse=True,
            )
            if reports:
                try:
                    return json.loads(reports[0].read_text())
                except (json.JSONDecodeError, IOError):
                    pass

        return None

    def purge_jail(self) -> Tuple[int, str]:
        """Delete all jailed skills."""
        if not JAIL_DIR.exists():
            return 0, "Jail is empty."

        count = 0
        for d in JAIL_DIR.iterdir():
            if d.is_dir():
                shutil.rmtree(d)
                count += 1

        return count, f"Purged {count} skill(s) from jail."

    # =========================================================================
    # Internal Helpers
    # =========================================================================

    def _save_report(self, report: SkillScanReport) -> Path:
        """Save a scan report to the reports directory."""
        ensure_directories()
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        filename = f"{report.skill_name}-{ts}.json"
        report_path = REPORTS_DIR / filename
        report_path.write_text(report.to_json())
        return report_path

    def _format_verdict_message(self, report: SkillScanReport) -> str:
        """Format a human-readable verdict message."""
        lines = [f"Skill scan: {report.skill_name}"]
        lines.append(f"Verdict: {report.verdict.upper()}")
        lines.append(f"Risk: {report.risk_level}")
        lines.append(
            f"Findings: {report.critical_count} critical, {report.high_count} high, "
            f"{report.medium_count} medium, {report.low_count} low"
        )
        lines.append(f"Duration: {report.scan_duration_ms}ms")

        if report.verdict == "pass":
            if self.config.mode == "auto":
                lines.append("Action: Auto-installing.")
            else:
                lines.append(
                    f"Action: Awaiting approval. "
                    f"Run 'tweek skills chamber approve {report.skill_name}'"
                )
        elif report.verdict == "fail":
            lines.append("Action: Quarantined to jail.")
        elif report.verdict == "manual_review":
            lines.append(
                f"Action: Manual review required. "
                f"Run 'tweek skills chamber approve {report.skill_name}' or "
                f"'tweek skills chamber reject {report.skill_name}'"
            )

        return "\n".join(lines)

    def _log_event(self, event_type: str, skill_name: str, details: Dict) -> None:
        """Log a security event for the isolation chamber."""
        try:
            from tweek.logging.security_log import get_security_logger, EventType

            logger = get_security_logger()
            # Use the closest matching event type, or fall back to generic
            try:
                et = EventType(event_type)
            except ValueError:
                et = EventType.TOOL_INVOKED

            logger.log_quick(
                et,
                "SkillIsolation",
                skill_name=skill_name,
                source="skill_isolation",
                **details,
            )
        except (ImportError, Exception):
            # Logging is best-effort — don't break the chamber if logger fails
            pass
