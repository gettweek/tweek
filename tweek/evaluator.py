"""
Tweek Skill Evaluator — Plan Mode Security Evaluation

Orchestrates skill evaluation by combining the 7-layer SkillScanner pipeline
with permission manifest extraction, cross-validation, and behavioral signal
detection. Produces an EvaluationReport with a synthesized recommendation.

This module powers:
- `tweek evaluate <source>` CLI command
- `.claude/agents/skill-evaluator.md` plan-mode agent (reads saved reports)
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from tweek.skills.config import IsolationConfig
from tweek.skills.scanner import SkillScanner, SkillScanReport


# =============================================================================
# Dataclasses
# =============================================================================


@dataclass
class PermissionManifest:
    """Permissions declared in a skill's SKILL.md frontmatter."""

    tools_requested: List[str] = field(default_factory=list)
    permission_mode: Optional[str] = None  # "plan", "full", or None
    network_access: bool = False
    file_write_access: bool = False
    bash_access: bool = False
    raw_frontmatter: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_tools(
        cls,
        tools: List[str],
        permission_mode: Optional[str] = None,
        raw_frontmatter: Optional[Dict[str, Any]] = None,
    ) -> PermissionManifest:
        """Create a manifest with access flags inferred from tool names."""
        tools_lower = [t.lower() for t in tools]
        return cls(
            tools_requested=tools,
            permission_mode=permission_mode,
            network_access=any(
                t in tools_lower for t in ("webfetch", "websearch", "web_fetch", "web_search")
            ),
            file_write_access=any(
                t in tools_lower for t in ("write", "edit", "notebookedit", "notebook_edit")
            ),
            bash_access="bash" in tools_lower,
            raw_frontmatter=raw_frontmatter or {},
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tools_requested": self.tools_requested,
            "permission_mode": self.permission_mode,
            "network_access": self.network_access,
            "file_write_access": self.file_write_access,
            "bash_access": self.bash_access,
        }


@dataclass
class BehavioralSignal:
    """A behavioral observation from skill content analysis."""

    signal_type: str  # e.g. "scope_creep", "capability_mismatch"
    severity: str  # "info", "warning", "danger"
    description: str
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_type": self.signal_type,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
        }


@dataclass
class EvaluationReport:
    """Complete evaluation report wrapping scan + permission + behavioral analysis."""

    schema_version: int = 1
    skill_name: str = ""
    skill_path: str = ""
    timestamp: str = ""
    evaluation_duration_ms: int = 0

    # Wrapped scan report
    scan_report: Optional[SkillScanReport] = None

    # Permission analysis
    permissions: Optional[PermissionManifest] = None
    permission_issues: List[str] = field(default_factory=list)

    # Behavioral analysis
    behavioral_signals: List[BehavioralSignal] = field(default_factory=list)

    # Synthesized verdict
    recommendation: str = "pending"  # "approve", "reject", "review"
    recommendation_reasons: List[str] = field(default_factory=list)
    risk_summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "skill_name": self.skill_name,
            "skill_path": self.skill_path,
            "timestamp": self.timestamp,
            "evaluation_duration_ms": self.evaluation_duration_ms,
            "scan_report": self.scan_report.to_dict() if self.scan_report else None,
            "permissions": self.permissions.to_dict() if self.permissions else None,
            "permission_issues": self.permission_issues,
            "behavioral_signals": [s.to_dict() for s in self.behavioral_signals],
            "recommendation": self.recommendation,
            "recommendation_reasons": self.recommendation_reasons,
            "risk_summary": self.risk_summary,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# =============================================================================
# Frontmatter Extraction
# =============================================================================

_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?\n)---\s*\n", re.DOTALL)


def extract_frontmatter(skill_md_content: str) -> Dict[str, Any]:
    """Parse YAML frontmatter from SKILL.md content.

    Returns the parsed dict, or empty dict if no frontmatter found or parse error.
    """
    match = _FRONTMATTER_RE.match(skill_md_content)
    if not match:
        return {}
    try:
        parsed = yaml.safe_load(match.group(1))
        return parsed if isinstance(parsed, dict) else {}
    except yaml.YAMLError:
        return {}


# =============================================================================
# Behavioral Detection Patterns
# =============================================================================

_WRITE_INDICATORS = re.compile(
    r"\b(write|edit|create|modify|overwrite|append|mkdir|touch|>"
    r"|cat\s*>|echo\s*>|tee\s)"
    , re.IGNORECASE,
)

_BASH_INDICATORS = re.compile(
    r"\b(bash|shell|terminal|command|exec|subprocess|os\.system|os\.popen"
    r"|shutil\.|chmod|chown|rm\s|kill\s|pkill|sudo)\b"
    , re.IGNORECASE,
)

_NETWORK_INDICATORS = re.compile(
    r"\b(curl|wget|fetch|http|https|requests\.|urllib|httpx"
    r"|socket|api\s*call|endpoint|webhook)\b"
    , re.IGNORECASE,
)

_TRUST_ESCALATION = re.compile(
    r"(this\s+(is\s+a\s+)?trusted|pre.?authorized|already\s+approved"
    r"|safe\s+to\s+run|bypass\s+security|skip\s+(confirmation|review|screening)"
    r"|disable\s+(tweek|security|screening|hook)"
    r"|no\s+need\s+to\s+(check|verify|confirm))"
    , re.IGNORECASE,
)


# =============================================================================
# SkillEvaluator
# =============================================================================


class SkillEvaluator:
    """Orchestrates skill evaluation: scan + permission extraction + behavioral analysis."""

    def __init__(self, config: Optional[IsolationConfig] = None):
        self.config = config or IsolationConfig()
        self.scanner = SkillScanner(config=self.config)

    def evaluate(self, source: str) -> EvaluationReport:
        """Full evaluation pipeline.

        Args:
            source: Path to skill directory or SKILL.md file.

        Returns:
            EvaluationReport with scan results, permissions, behavioral signals,
            and a synthesized recommendation.
        """
        start_time = time.monotonic()
        source_path = Path(source).resolve()

        # Determine skill directory
        if source_path.is_file():
            skill_dir = source_path.parent
            skill_name = skill_dir.name
        elif source_path.is_dir():
            skill_dir = source_path
            skill_name = skill_dir.name
        else:
            raise FileNotFoundError(f"Source not found: {source}")

        report = EvaluationReport(
            skill_name=skill_name,
            skill_path=str(skill_dir),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Phase 1: Run the 7-layer scanner
        scan_report = self.scanner.scan(skill_dir)
        report.scan_report = scan_report

        # Phase 2: Extract permission manifest from SKILL.md
        skill_md_path = skill_dir / "SKILL.md"
        skill_md_content = ""
        if skill_md_path.exists():
            try:
                skill_md_content = skill_md_path.read_text(encoding="utf-8")
            except (IOError, UnicodeDecodeError):
                pass

        report.permissions = self._extract_permissions(skill_md_content)

        # Phase 3: Cross-validate permissions against scan findings
        report.permission_issues = self._validate_permissions(
            report.permissions, scan_report, skill_dir
        )

        # Phase 4: Behavioral signal detection
        report.behavioral_signals = self._analyze_behavior(
            skill_dir, report.permissions, scan_report
        )

        # Phase 5: Synthesize recommendation
        rec, reasons, summary = self._synthesize_recommendation(
            scan_report, report.permission_issues, report.behavioral_signals
        )
        report.recommendation = rec
        report.recommendation_reasons = reasons
        report.risk_summary = summary

        report.evaluation_duration_ms = int(
            (time.monotonic() - start_time) * 1000
        )
        return report

    def _extract_permissions(self, skill_md_content: str) -> PermissionManifest:
        """Parse YAML frontmatter and build a PermissionManifest."""
        frontmatter = extract_frontmatter(skill_md_content)
        if not frontmatter:
            return PermissionManifest(raw_frontmatter={})

        # Extract tools list from various possible field names
        tools_raw = (
            frontmatter.get("tools")
            or frontmatter.get("allowed-tools")
            or frontmatter.get("allowedTools")
            or frontmatter.get("allowed_tools")
            or []
        )
        if isinstance(tools_raw, str):
            tools_raw = [tools_raw]
        if not isinstance(tools_raw, list):
            tools_raw = []
        tools = [str(t) for t in tools_raw]

        # Extract permission mode
        perm_mode = (
            frontmatter.get("permissionMode")
            or frontmatter.get("permission_mode")
            or frontmatter.get("permission-mode")
        )
        if perm_mode and not isinstance(perm_mode, str):
            perm_mode = None

        return PermissionManifest.from_tools(
            tools=tools,
            permission_mode=perm_mode,
            raw_frontmatter=frontmatter,
        )

    def _validate_permissions(
        self,
        permissions: PermissionManifest,
        scan_report: SkillScanReport,
        skill_dir: Path,
    ) -> List[str]:
        """Cross-validate declared permissions against actual content."""
        issues: List[str] = []

        # Collect all text content for analysis
        all_content = self._read_all_text(skill_dir)

        # Check for undeclared Bash usage
        if not permissions.bash_access and _BASH_INDICATORS.search(all_content):
            issues.append(
                "Skill content references shell/bash operations but does not "
                "declare Bash in its tools list"
            )

        # Check for undeclared network access
        if not permissions.network_access and _NETWORK_INDICATORS.search(all_content):
            issues.append(
                "Skill content references network operations (URLs, HTTP, fetch) "
                "but does not declare network tools"
            )

        # Check for undeclared write access
        if not permissions.file_write_access and _WRITE_INDICATORS.search(all_content):
            issues.append(
                "Skill content references file write operations but does not "
                "declare Write/Edit in its tools list"
            )

        # Check plan mode contradiction
        if permissions.permission_mode == "plan":
            if permissions.bash_access:
                issues.append(
                    "Declares permissionMode: plan but requests Bash access "
                    "(Bash is denied in plan mode)"
                )
            if permissions.file_write_access:
                issues.append(
                    "Declares permissionMode: plan but requests Write/Edit access "
                    "(writes are denied in plan mode)"
                )
            # Check content for write/bash references even without declaration
            if _BASH_INDICATORS.search(all_content):
                issues.append(
                    "Declares permissionMode: plan but content references "
                    "shell/bash operations"
                )

        return issues

    def _analyze_behavior(
        self,
        skill_dir: Path,
        permissions: PermissionManifest,
        scan_report: SkillScanReport,
    ) -> List[BehavioralSignal]:
        """Detect behavioral signals beyond pattern matching."""
        signals: List[BehavioralSignal] = []
        all_content = self._read_all_text(skill_dir)

        # --- Trust escalation ---
        match = _TRUST_ESCALATION.search(all_content)
        if match:
            signals.append(BehavioralSignal(
                signal_type="trust_escalation",
                severity="danger",
                description=(
                    "Skill contains language attempting to establish trust or "
                    "bypass security screening"
                ),
                evidence=match.group()[:120],
            ))

        # --- Capability mismatch (plan mode + write/bash content) ---
        if permissions.permission_mode == "plan":
            if _WRITE_INDICATORS.search(all_content) or _BASH_INDICATORS.search(all_content):
                signals.append(BehavioralSignal(
                    signal_type="capability_mismatch",
                    severity="danger",
                    description=(
                        "Declares plan mode (read-only) but content references "
                        "write or shell operations"
                    ),
                    evidence="permissionMode: plan + write/bash references",
                ))

        # --- Progressive disclosure ---
        # SKILL.md is clean but bundled scripts have findings
        skill_md_findings = 0
        bundled_findings = 0
        for layer_data in scan_report.layers.values():
            for finding in layer_data.get("findings", []):
                if isinstance(finding, dict):
                    f_file = finding.get("file", "")
                    if f_file == "SKILL.md" or f_file.endswith("/SKILL.md"):
                        skill_md_findings += 1
                    else:
                        bundled_findings += 1

        if bundled_findings > 0 and skill_md_findings == 0:
            signals.append(BehavioralSignal(
                signal_type="progressive_disclosure",
                severity="warning",
                description=(
                    f"SKILL.md is clean but {bundled_findings} finding(s) detected "
                    f"in bundled files"
                ),
                evidence=f"{bundled_findings} findings in non-SKILL.md files",
            ))

        # --- Excessive files ---
        file_count = len(scan_report.files_scanned)
        if file_count > 10:
            signals.append(BehavioralSignal(
                signal_type="excessive_files",
                severity="info",
                description=(
                    f"Skill contains {file_count} files, which is unusually "
                    f"large for a skill"
                ),
                evidence=f"{file_count} files scanned",
            ))

        # --- Scope creep ---
        # Narrow description but many files or large content
        description = permissions.raw_frontmatter.get("description", "")
        if description and len(description) < 80 and (
            file_count > 5 or scan_report.total_content_bytes > 50000
        ):
            signals.append(BehavioralSignal(
                signal_type="scope_creep",
                severity="warning",
                description=(
                    "Skill has a brief description but contains substantial "
                    f"content ({file_count} files, "
                    f"{scan_report.total_content_bytes:,} bytes)"
                ),
                evidence=f'description: "{description[:60]}"',
            ))

        # --- Undeclared network ---
        if not permissions.network_access and _NETWORK_INDICATORS.search(all_content):
            # Only add if not already covered by permission_issues (avoid dupe)
            if not any(s.signal_type == "undeclared_network" for s in signals):
                signals.append(BehavioralSignal(
                    signal_type="undeclared_network",
                    severity="warning",
                    description=(
                        "Content references network operations without declaring "
                        "network tools"
                    ),
                    evidence="Network indicators found in content",
                ))

        return signals

    def _synthesize_recommendation(
        self,
        scan_report: SkillScanReport,
        permission_issues: List[str],
        behavioral_signals: List[BehavioralSignal],
    ) -> Tuple[str, List[str], str]:
        """Combine all analysis into a final recommendation.

        Returns:
            (recommendation, reasons, risk_summary)
        """
        reasons: List[str] = []

        # Check for reject conditions
        has_reject = False

        if scan_report.verdict == "fail":
            has_reject = True
            reasons.append(f"Security scan failed (risk: {scan_report.risk_level})")

        for signal in behavioral_signals:
            if signal.severity == "danger":
                has_reject = True
                reasons.append(f"Danger signal: {signal.description}")

        if has_reject:
            summary = self._build_summary("reject", scan_report, behavioral_signals)
            return "reject", reasons, summary

        # Check for review conditions
        has_review = False

        if scan_report.verdict == "manual_review":
            has_review = True
            reasons.append("Security scan requires manual review")

        for signal in behavioral_signals:
            if signal.severity == "warning":
                has_review = True
                reasons.append(f"Warning: {signal.description}")

        if permission_issues:
            has_review = True
            for issue in permission_issues:
                reasons.append(f"Permission issue: {issue}")

        if has_review:
            summary = self._build_summary("review", scan_report, behavioral_signals)
            return "review", reasons, summary

        # All clear
        reasons.append("Security scan passed with no issues")
        summary = self._build_summary("approve", scan_report, behavioral_signals)
        return "approve", reasons, summary

    def _build_summary(
        self,
        recommendation: str,
        scan_report: SkillScanReport,
        signals: List[BehavioralSignal],
    ) -> str:
        """Build a one-line risk summary."""
        if recommendation == "reject":
            danger_count = sum(1 for s in signals if s.severity == "danger")
            parts = []
            if scan_report.verdict == "fail":
                parts.append(f"scan {scan_report.risk_level}")
            if danger_count:
                parts.append(f"{danger_count} danger signal(s)")
            return f"REJECT: {', '.join(parts)}" if parts else "REJECT: failed evaluation"

        if recommendation == "review":
            warning_count = sum(1 for s in signals if s.severity == "warning")
            return (
                f"REVIEW: {warning_count} warning(s), "
                f"{scan_report.high_count} high-severity finding(s)"
            )

        return (
            f"APPROVE: scan passed, "
            f"{len(scan_report.files_scanned)} file(s) analyzed"
        )

    @staticmethod
    def _read_all_text(skill_dir: Path) -> str:
        """Read all text file content from a skill directory into one string."""
        text_exts = {
            ".md", ".py", ".sh", ".json", ".yaml", ".yml",
            ".txt", ".toml", ".cfg", ".ini", ".js", ".ts",
        }
        parts: List[str] = []
        try:
            for item in skill_dir.rglob("*"):
                if item.is_file() and item.suffix.lower() in text_exts:
                    try:
                        parts.append(item.read_text(encoding="utf-8"))
                    except (IOError, UnicodeDecodeError):
                        continue
        except OSError:
            pass
        return "\n".join(parts)
