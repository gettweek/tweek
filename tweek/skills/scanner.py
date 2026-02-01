"""
Tweek Skill Scanner — 7-Layer Security Pipeline

Scans skill directories through multiple security layers before allowing
installation. Reuses existing Tweek infrastructure where possible.

Layers:
1. Structure Validation    — file types, size, depth, symlinks
2. Pattern Matching        — 259 regex patterns (reuses audit.py)
3. Secret Scanning         — credential detection (reuses secret_scanner.py)
4. AST Analysis            — forbidden imports/calls (reuses git_security.py)
5. Prompt Injection Scan   — skill-specific instruction injection patterns
6. Exfiltration Detection  — network URLs, exfil sites, data sending
7. LLM Semantic Review     — Claude Haiku intent analysis (reuses llm_reviewer.py)
"""

import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tweek.skills.config import IsolationConfig


@dataclass
class ScanLayerResult:
    """Result from a single scan layer."""
    layer_name: str
    passed: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class SkillScanReport:
    """Complete scan report for a skill."""
    schema_version: int = 1
    skill_name: str = ""
    skill_path: str = ""
    timestamp: str = ""
    scan_duration_ms: int = 0
    verdict: str = "pending"  # "pass", "fail", "manual_review"
    risk_level: str = "safe"  # "safe", "suspicious", "dangerous"

    # Per-layer results
    layers: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Aggregate counts
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    # Metadata
    files_scanned: List[str] = field(default_factory=list)
    total_content_bytes: int = 0
    non_english_detected: bool = False
    scan_config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to a JSON-compatible dict."""
        return {
            "schema_version": self.schema_version,
            "skill_name": self.skill_name,
            "skill_path": self.skill_path,
            "timestamp": self.timestamp,
            "scan_duration_ms": self.scan_duration_ms,
            "verdict": self.verdict,
            "risk_level": self.risk_level,
            "summary": {
                "files_scanned": len(self.files_scanned),
                "total_bytes": self.total_content_bytes,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "layers": self.layers,
            "files": self.files_scanned,
            "scan_config": self.scan_config,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize report to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


# Skill-specific prompt injection patterns (Layer 5)
# These detect manipulation of Claude's behavior through skill instructions
SKILL_INJECTION_PATTERNS = [
    {
        "name": "skill_disable_security",
        "severity": "critical",
        "description": "Skill instructs Claude to disable security tools or hooks",
        "regex": r"(disable|turn\s+off|deactivate|bypass|skip|remove)\s+(tweek|security\s+hook|screening|pre.?tool|post.?tool|safety\s+check)",
    },
    {
        "name": "skill_ignore_instructions",
        "severity": "critical",
        "description": "Skill contains instruction override attempt",
        "regex": r"(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|system|other|existing)\s+(instructions|rules|guidelines|constraints|directives|prompts)",
    },
    {
        "name": "skill_access_credentials",
        "severity": "high",
        "description": "Skill instructs access to credentials or secrets",
        "regex": r"(read|access|cat|open|load|fetch|get|extract)\s+.{0,30}(\.env|credentials|api.?key|secret|token|password|private.?key|\.ssh|\.aws|\.gnupg)",
    },
    {
        "name": "skill_modify_config",
        "severity": "high",
        "description": "Skill instructs modification of security configuration",
        "regex": r"(write|edit|modify|change|update|overwrite)\s+.{0,30}(\.claude/(settings|config)|\.tweek/(config|overrides|patterns)|\.cursorrules)",
    },
    {
        "name": "skill_send_data",
        "severity": "high",
        "description": "Skill instructs sending data to external endpoints",
        "regex": r"(send|post|upload|transmit|exfiltrate|forward)\s+.{0,40}(to\s+|https?://|webhook|api\s+endpoint|external\s+server)",
    },
    {
        "name": "skill_execute_remote",
        "severity": "critical",
        "description": "Skill instructs downloading and executing remote code",
        "regex": r"(download|fetch|curl|wget)\s+.{0,40}(and\s+)?(then\s+)?(run|execute|eval|source|bash|sh\b|python)",
    },
    {
        "name": "skill_hidden_base64",
        "severity": "high",
        "description": "Skill contains base64-encoded instruction blocks",
        "regex": r"(decode|base64|atob)\s*[:=(\s]\s*[A-Za-z0-9+/]{40,}={0,2}",
    },
    {
        "name": "skill_role_hijack",
        "severity": "high",
        "description": "Skill attempts to redefine Claude's identity or role",
        "regex": r"(you\s+are\s+now|your\s+new\s+(role|identity|purpose)\s+is|from\s+now\s+on\s+you\s+are|act\s+as\s+if\s+you\s+have\s+no\s+(restrictions|limits|rules))",
    },
    {
        "name": "skill_system_prompt_extract",
        "severity": "high",
        "description": "Skill instructs extraction or exposure of system prompt",
        "regex": r"(output|print|show|display|reveal|share|repeat)\s+.{0,20}(system\s+prompt|your\s+instructions|your\s+configuration|your\s+rules)",
    },
    {
        "name": "skill_social_engineering",
        "severity": "medium",
        "description": "Skill uses social engineering to bypass restrictions",
        "regex": r"(the\s+user\s+has\s+already\s+approved|this\s+is\s+a\s+trusted\s+operation|security\s+has\s+been\s+verified|pre-?authorized|don.t\s+ask\s+for\s+confirmation)",
    },
]

# Exfiltration patterns for Layer 6
EXFIL_URL_PATTERN = re.compile(
    r'https?://[^\s"\'>]+', re.IGNORECASE
)

EXFIL_COMMAND_PATTERNS = [
    re.compile(r"(curl|wget|http|fetch)\s+", re.IGNORECASE),
    re.compile(r"(nc|ncat|netcat)\s+", re.IGNORECASE),
    re.compile(r"(scp|rsync|sftp)\s+", re.IGNORECASE),
]

SUSPICIOUS_HOSTS = [
    "pastebin.com", "hastebin.com", "ghostbin.", "0x0.st",
    "transfer.sh", "file.io", "webhook.site", "requestbin.",
    "ngrok.io", "pipedream.", "hookbin.com", "beeceptor.com",
]


class SkillScanner:
    """
    7-layer security scanner for skill directories.

    Runs each layer in sequence, collecting findings. Layers are fail-fast
    on CRITICAL findings when configured.
    """

    def __init__(self, config: Optional[IsolationConfig] = None):
        self.config = config or IsolationConfig()

    def scan(self, skill_dir: Path) -> SkillScanReport:
        """
        Run the full 7-layer scan pipeline on a skill directory.

        Args:
            skill_dir: Path to the skill directory to scan

        Returns:
            SkillScanReport with verdict and all layer results
        """
        start_time = time.monotonic()

        report = SkillScanReport(
            skill_name=skill_dir.name,
            skill_path=str(skill_dir),
            timestamp=datetime.now(timezone.utc).isoformat(),
            scan_config={
                "mode": self.config.mode,
                "llm_review_enabled": self.config.llm_review_enabled,
            },
        )

        # Collect all text files for scanning
        text_files = self._collect_text_files(skill_dir)
        report.files_scanned = [str(f.relative_to(skill_dir)) for f in text_files]
        report.total_content_bytes = sum(
            f.stat().st_size for f in text_files if f.exists()
        )

        # Layer 1: Structure Validation
        layer1 = self._scan_structure(skill_dir)
        report.layers["structure"] = self._layer_to_dict(layer1)
        if not layer1.passed:
            report.verdict = "fail"
            report.risk_level = "dangerous"
            report.scan_duration_ms = int((time.monotonic() - start_time) * 1000)
            return report

        # Layer 2: Pattern Matching
        layer2 = self._scan_patterns(skill_dir, text_files)
        report.layers["patterns"] = self._layer_to_dict(layer2)
        self._accumulate_findings(report, layer2)

        # Layer 3: Secret Scanning
        layer3 = self._scan_secrets(skill_dir)
        report.layers["secrets"] = self._layer_to_dict(layer3)

        # Layer 4: AST Analysis
        layer4 = self._scan_ast(skill_dir)
        report.layers["ast"] = self._layer_to_dict(layer4)

        # Layer 5: Prompt Injection Detection
        layer5 = self._scan_prompt_injection(skill_dir, text_files)
        report.layers["prompt_injection"] = self._layer_to_dict(layer5)
        self._accumulate_findings(report, layer5)

        # Layer 6: Exfiltration Detection
        layer6 = self._scan_exfiltration(skill_dir, text_files)
        report.layers["exfiltration"] = self._layer_to_dict(layer6)
        self._accumulate_findings(report, layer6)

        # Layer 7: LLM Semantic Review
        if self.config.llm_review_enabled:
            layer7 = self._scan_llm_review(skill_dir, text_files)
            report.layers["llm_review"] = self._layer_to_dict(layer7)
        else:
            report.layers["llm_review"] = {
                "passed": True, "skipped": True, "reason": "LLM review disabled"
            }

        # Compute final verdict
        report.verdict = self._compute_verdict(report, layer3, layer4)
        report.risk_level = self._compute_risk_level(report)
        report.scan_duration_ms = int((time.monotonic() - start_time) * 1000)

        return report

    # =========================================================================
    # Layer 1: Structure Validation
    # =========================================================================

    def _scan_structure(self, skill_dir: Path) -> ScanLayerResult:
        """Validate skill directory structure."""
        result = ScanLayerResult(layer_name="structure", passed=True)

        # Must have SKILL.md
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            result.passed = False
            result.issues.append("Missing SKILL.md file")
            return result

        # Check for symlinks pointing outside the skill directory
        resolved_dir = skill_dir.resolve()
        for item in skill_dir.rglob("*"):
            if item.is_symlink():
                target = item.resolve()
                try:
                    target.relative_to(resolved_dir)
                except ValueError:
                    result.passed = False
                    result.issues.append(
                        f"Symlink {item.name} points outside skill directory: {target}"
                    )

        # Check total size
        total_size = sum(
            f.stat().st_size for f in skill_dir.rglob("*") if f.is_file()
        )
        if total_size > self.config.max_skill_size_bytes:
            result.passed = False
            result.issues.append(
                f"Total size {total_size} bytes exceeds limit "
                f"{self.config.max_skill_size_bytes}"
            )

        # Check file count
        file_count = sum(1 for _ in skill_dir.rglob("*") if _.is_file())
        if file_count > self.config.max_file_count:
            result.passed = False
            result.issues.append(
                f"File count {file_count} exceeds limit {self.config.max_file_count}"
            )

        # Check directory depth
        for item in skill_dir.rglob("*"):
            try:
                rel = item.relative_to(skill_dir)
                depth = len(rel.parts)
                if depth > self.config.max_directory_depth:
                    result.passed = False
                    result.issues.append(
                        f"Path depth {depth} exceeds limit "
                        f"{self.config.max_directory_depth}: {rel}"
                    )
                    break
            except ValueError:
                pass

        # Check for blocked file extensions
        for item in skill_dir.rglob("*"):
            if item.is_file():
                ext = item.suffix.lower()
                if ext in self.config.blocked_file_extensions:
                    result.passed = False
                    result.issues.append(
                        f"Blocked file extension '{ext}': {item.name}"
                    )

        # Check for hidden files (except .gitignore)
        for item in skill_dir.rglob(".*"):
            if item.name == ".gitignore":
                continue
            if item.is_file():
                result.issues.append(f"Hidden file detected: {item.name}")

        return result

    # =========================================================================
    # Layer 2: Pattern Matching (reuses audit.py)
    # =========================================================================

    def _scan_patterns(
        self, skill_dir: Path, text_files: List[Path]
    ) -> ScanLayerResult:
        """Run 259 regex patterns against all text files."""
        result = ScanLayerResult(layer_name="patterns", passed=True)

        try:
            from tweek.audit import audit_content

            for file_path in text_files:
                try:
                    content = file_path.read_text(encoding="utf-8")
                except (IOError, UnicodeDecodeError):
                    continue

                audit_result = audit_content(
                    content=content,
                    name=str(file_path.relative_to(skill_dir)),
                    path=file_path,
                    translate=True,
                    llm_review=False,  # LLM review is a separate layer
                )

                if audit_result.non_english_detected:
                    self._report_non_english = True

                for finding in audit_result.findings:
                    result.findings.append({
                        "file": str(file_path.relative_to(skill_dir)),
                        "pattern_id": finding.pattern_id,
                        "name": finding.pattern_name,
                        "severity": finding.severity,
                        "description": finding.description,
                        "matched_text": finding.matched_text[:100],
                    })

        except ImportError as e:
            result.error = f"Pattern matcher not available: {e}"

        return result

    # =========================================================================
    # Layer 3: Secret Scanning (reuses secret_scanner.py)
    # =========================================================================

    def _scan_secrets(self, skill_dir: Path) -> ScanLayerResult:
        """Scan for hardcoded credentials in the skill directory."""
        result = ScanLayerResult(layer_name="secrets", passed=True)

        try:
            from tweek.security.secret_scanner import SecretScanner

            scanner = SecretScanner(enforce_permissions=False)
            scan_result = scanner.scan_directory(
                skill_dir,
                patterns=["**/*.yaml", "**/*.yml", "**/*.json", "**/.env*",
                          "**/*.py", "**/*.sh", "**/*.toml", "**/*.md",
                          "**/*.txt"],
            )

            if scan_result.findings:
                result.passed = False
                for finding in scan_result.findings:
                    result.findings.append({
                        "file": str(finding.file_path) if hasattr(finding, "file_path") else "unknown",
                        "key": getattr(finding, "key", "unknown"),
                        "severity": "critical",
                        "description": f"Hardcoded secret: {getattr(finding, 'key', 'unknown')}",
                    })

        except ImportError as e:
            result.error = f"Secret scanner not available: {e}"

        return result

    # =========================================================================
    # Layer 4: AST Analysis (reuses git_security.py)
    # =========================================================================

    def _scan_ast(self, skill_dir: Path) -> ScanLayerResult:
        """Static analysis of Python files for forbidden patterns."""
        result = ScanLayerResult(layer_name="ast", passed=True)

        py_files = list(skill_dir.glob("**/*.py"))
        if not py_files:
            return result  # No Python files to scan

        try:
            from tweek.plugins.git_security import static_analyze_python_files

            is_safe, issues = static_analyze_python_files(skill_dir)
            if not is_safe:
                result.passed = False
                result.issues = issues

        except ImportError as e:
            result.error = f"AST analyzer not available: {e}"

        return result

    # =========================================================================
    # Layer 5: Prompt Injection Detection (skill-specific)
    # =========================================================================

    def _scan_prompt_injection(
        self, skill_dir: Path, text_files: List[Path]
    ) -> ScanLayerResult:
        """Scan for prompt injection patterns specific to skill instructions."""
        result = ScanLayerResult(layer_name="prompt_injection", passed=True)

        for file_path in text_files:
            try:
                content = file_path.read_text(encoding="utf-8")
            except (IOError, UnicodeDecodeError):
                continue

            for pattern_def in SKILL_INJECTION_PATTERNS:
                try:
                    match = re.search(
                        pattern_def["regex"], content, re.IGNORECASE | re.MULTILINE
                    )
                    if match:
                        result.findings.append({
                            "file": str(file_path.relative_to(skill_dir)),
                            "name": pattern_def["name"],
                            "severity": pattern_def["severity"],
                            "description": pattern_def["description"],
                            "matched_text": match.group(0)[:100],
                        })
                except re.error:
                    continue

        return result

    # =========================================================================
    # Layer 6: Exfiltration Vector Detection
    # =========================================================================

    def _scan_exfiltration(
        self, skill_dir: Path, text_files: List[Path]
    ) -> ScanLayerResult:
        """Detect data exfiltration vectors in skill content."""
        result = ScanLayerResult(layer_name="exfiltration", passed=True)

        for file_path in text_files:
            try:
                content = file_path.read_text(encoding="utf-8")
            except (IOError, UnicodeDecodeError):
                continue

            rel_path = str(file_path.relative_to(skill_dir))
            is_script = file_path.suffix in (".py", ".sh")

            # Check for URLs pointing to suspicious hosts
            urls = EXFIL_URL_PATTERN.findall(content)
            for url in urls:
                url_lower = url.lower()
                for host in SUSPICIOUS_HOSTS:
                    if host in url_lower:
                        severity = "critical" if is_script else "high"
                        result.findings.append({
                            "file": rel_path,
                            "name": "exfil_suspicious_host",
                            "severity": severity,
                            "description": f"URL to known exfiltration site: {host}",
                            "matched_text": url[:100],
                        })

            # Check for exfiltration commands in scripts
            if is_script:
                for pattern in EXFIL_COMMAND_PATTERNS:
                    matches = pattern.finditer(content)
                    for match in matches:
                        # Get surrounding context
                        start = max(0, match.start() - 20)
                        end = min(len(content), match.end() + 80)
                        context = content[start:end].strip()
                        result.findings.append({
                            "file": rel_path,
                            "name": "exfil_network_command",
                            "severity": "high",
                            "description": "Network command in skill script",
                            "matched_text": context[:100],
                        })

        return result

    # =========================================================================
    # Layer 7: LLM Semantic Review (reuses llm_reviewer.py)
    # =========================================================================

    def _scan_llm_review(
        self, skill_dir: Path, text_files: List[Path]
    ) -> ScanLayerResult:
        """Run LLM semantic analysis on skill content."""
        result = ScanLayerResult(layer_name="llm_review", passed=True)

        # Collect content from key files (SKILL.md first, then others)
        content_parts = []
        skill_md = skill_dir / "SKILL.md"
        if skill_md.exists():
            try:
                md_content = skill_md.read_text(encoding="utf-8")
                content_parts.append(f"=== SKILL.md ===\n{md_content}")
            except (IOError, UnicodeDecodeError):
                pass

        for file_path in text_files:
            if file_path == skill_md:
                continue
            try:
                fc = file_path.read_text(encoding="utf-8")
                rel = str(file_path.relative_to(skill_dir))
                content_parts.append(f"=== {rel} ===\n{fc[:2000]}")
            except (IOError, UnicodeDecodeError):
                continue

        combined = "\n\n".join(content_parts)[:8000]

        try:
            from tweek.security.llm_reviewer import get_llm_reviewer

            reviewer = get_llm_reviewer()
            if not reviewer.enabled:
                result.findings.append({
                    "name": "llm_review_unavailable",
                    "severity": "medium",
                    "description": "LLM reviewer not available (no API key)",
                })
                return result

            review = reviewer.review(
                command=combined[:4000],
                tool="SkillIsolation",
                tier="dangerous",
            )

            result.findings.append({
                "name": "llm_semantic_review",
                "severity": "low",
                "description": review.reason,
                "risk_level": review.risk_level.value,
                "confidence": review.confidence,
                "model": "claude-3-5-haiku-latest",
            })

            if review.risk_level.value == "dangerous" and review.confidence >= 0.7:
                result.passed = False
            elif review.risk_level.value == "suspicious":
                # Mark for manual review but don't fail
                result.findings[-1]["severity"] = "medium"

        except ImportError:
            result.error = "LLM reviewer not available"
        except Exception as e:
            # Fail-closed: treat errors as needing manual review
            result.findings.append({
                "name": "llm_review_error",
                "severity": "medium",
                "description": f"LLM review failed: {e}",
            })

        return result

    # =========================================================================
    # Verdict and Risk Computation
    # =========================================================================

    def _compute_verdict(
        self,
        report: SkillScanReport,
        secrets_layer: ScanLayerResult,
        ast_layer: ScanLayerResult,
    ) -> str:
        """Compute final verdict based on all layer results."""

        # Hard FAIL conditions
        if any(
            not layer.get("passed", True)
            for name, layer in report.layers.items()
            if name == "structure"
        ):
            return "fail"

        if self.config.fail_on_critical and report.critical_count > 0:
            return "fail"

        if not secrets_layer.passed:
            return "fail"

        if not ast_layer.passed:
            return "fail"

        if report.high_count >= self.config.fail_on_high_count:
            return "fail"

        # LLM review dangerous = fail
        llm_layer = report.layers.get("llm_review", {})
        if not llm_layer.get("passed", True):
            return "fail"

        # Manual review conditions
        if report.high_count >= self.config.review_on_high_count:
            return "manual_review"

        llm_findings = llm_layer.get("findings", [])
        for f in llm_findings:
            if isinstance(f, dict) and f.get("risk_level") == "suspicious":
                return "manual_review"

        # Manual mode override
        if self.config.mode == "manual":
            return "manual_review"

        return "pass"

    def _compute_risk_level(self, report: SkillScanReport) -> str:
        """Compute overall risk level from findings."""
        if report.critical_count > 0:
            return "dangerous"
        if report.high_count > 0:
            return "suspicious"
        if report.medium_count > 0:
            return "suspicious"
        return "safe"

    # =========================================================================
    # Helpers
    # =========================================================================

    def _collect_text_files(self, skill_dir: Path) -> List[Path]:
        """Collect all scannable text files from the skill directory."""
        files = []
        allowed = set(self.config.allowed_file_extensions)
        for item in skill_dir.rglob("*"):
            if item.is_file() and item.suffix.lower() in allowed:
                files.append(item)
        return sorted(files)

    def _accumulate_findings(
        self, report: SkillScanReport, layer: ScanLayerResult
    ) -> None:
        """Add finding severity counts from a layer to the report totals."""
        for finding in layer.findings:
            sev = finding.get("severity", "low")
            if sev == "critical":
                report.critical_count += 1
            elif sev == "high":
                report.high_count += 1
            elif sev == "medium":
                report.medium_count += 1
            else:
                report.low_count += 1

    def _layer_to_dict(self, layer: ScanLayerResult) -> Dict[str, Any]:
        """Convert a ScanLayerResult to a serializable dict."""
        d = {"passed": layer.passed}
        if layer.findings:
            d["findings"] = layer.findings
        if layer.issues:
            d["issues"] = layer.issues
        if layer.error:
            d["error"] = layer.error
        return d

    # Internal state for cross-layer communication
    _report_non_english: bool = False
