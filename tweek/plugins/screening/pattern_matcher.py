#!/usr/bin/env python3
"""
Tweek Pattern Matcher Screening Plugin

Regex-based pattern matching for known attack vectors:
- Credential access patterns
- Data exfiltration patterns
- Prompt injection patterns
- Privilege escalation patterns

FREE feature - available to all users.
"""

import re
from pathlib import Path
from typing import Optional, Dict, Any, List

import yaml

from tweek.plugins.base import (
    ScreeningPlugin,
    ScreeningResult,
    Finding,
    Severity,
    ActionType,
)


class PatternMatcherPlugin(ScreeningPlugin):
    """
    Pattern matcher screening plugin.

    Matches content against known attack patterns using regex.
    Patterns are loaded from YAML configuration files.

    FREE feature - all patterns available to all users.
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Regex-based pattern matching for known attack vectors"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["screening", "pattern-matching", "regex"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._patterns: Optional[List[Dict]] = None
        self._compiled: Dict[str, re.Pattern] = {}

    @property
    def name(self) -> str:
        return "pattern_matcher"

    def _load_patterns(self) -> List[Dict]:
        """Load patterns from configuration files."""
        if self._patterns is not None:
            return self._patterns

        self._patterns = []

        # Try user patterns first
        user_patterns = Path.home() / ".tweek" / "patterns" / "patterns.yaml"
        bundled_patterns = Path(__file__).parent.parent.parent / "config" / "patterns.yaml"

        patterns_path = None
        if self._config.get("patterns_path"):
            patterns_path = Path(self._config["patterns_path"])
        elif user_patterns.exists():
            patterns_path = user_patterns
        elif bundled_patterns.exists():
            patterns_path = bundled_patterns

        if patterns_path and patterns_path.exists():
            try:
                # Verify signature for bundled patterns
                if patterns_path == bundled_patterns:
                    self._verify_bundled_signature(patterns_path)

                with open(patterns_path) as f:
                    data = yaml.safe_load(f) or {}
                    self._patterns = data.get("patterns", [])
            except (yaml.YAMLError, IOError):
                pass

        return self._patterns

    def _verify_bundled_signature(self, patterns_path: Path) -> None:
        """Verify the cryptographic signature of bundled patterns.

        Logs a security event if verification fails but does not block
        pattern loading (graceful degradation).
        """
        try:
            from tweek.security.pattern_signer import verify_patterns_file

            result = verify_patterns_file(patterns_path)

            if result["sig_found"] and not result["verified"]:
                # Signature exists but is invalid — possible tampering
                try:
                    from tweek.logging.security_log import (
                        EventType,
                        SecurityEvent,
                        get_logger,
                    )
                    get_logger().log(SecurityEvent(
                        event_type=EventType.FILE_INTEGRITY_VIOLATION,
                        tool_name="pattern_matcher",
                        decision="alert",
                        decision_reason=f"Pattern signature invalid: {result['reason']}",
                        metadata={
                            "file": str(patterns_path),
                            "reason": result["reason"],
                            "key_id": result.get("key_id"),
                        },
                        source="pattern_matcher",
                    ))
                except Exception:
                    pass

            # Store verification result for diagnostics
            self._signature_status = result
        except Exception:
            self._signature_status = {
                "verified": False,
                "reason": "verification_error",
                "key_id": None,
                "sig_found": False,
            }

    def _get_compiled(self, pattern: str) -> Optional[re.Pattern]:
        """Get or compile a regex pattern."""
        if pattern not in self._compiled:
            try:
                self._compiled[pattern] = re.compile(pattern, re.IGNORECASE)
            except re.error:
                self._compiled[pattern] = None
        return self._compiled[pattern]

    def screen(
        self,
        tool_name: str,
        content: str,
        context: Dict[str, Any]
    ) -> ScreeningResult:
        """
        Screen content against known attack patterns.

        Args:
            tool_name: Name of the tool being invoked
            content: Command or content to screen
            context: Additional context (unused for pattern matching)

        Returns:
            ScreeningResult with pattern match findings
        """
        patterns = self._load_patterns()
        findings = []

        for pattern_def in patterns:
            regex = pattern_def.get("regex", "")
            if not regex:
                continue

            compiled = self._get_compiled(regex)
            if compiled is None:
                continue

            match = compiled.search(content)
            if match:
                severity_map = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                }

                action_map = {
                    "block": ActionType.BLOCK,
                    "warn": ActionType.WARN,
                    "ask": ActionType.ASK,
                    "allow": ActionType.ALLOW,
                }

                severity = severity_map.get(
                    pattern_def.get("severity", "medium"),
                    Severity.MEDIUM
                )

                action = action_map.get(
                    pattern_def.get("action", "ask"),
                    ActionType.ASK
                )

                findings.append(Finding(
                    pattern_name=pattern_def.get("name", "unknown"),
                    matched_text=match.group()[:100],  # Truncate
                    severity=severity,
                    description=pattern_def.get("description", ""),
                    context=self._get_context(content, match.start()),
                    recommended_action=action,
                    metadata={
                        "pattern_id": pattern_def.get("id"),
                        "category": pattern_def.get("category"),
                        "tags": pattern_def.get("tags", []),
                    }
                ))

        if not findings:
            return ScreeningResult(
                allowed=True,
                plugin_name=self.name,
                risk_level="safe",
            )

        # Determine overall action
        action_priority = [
            ActionType.ALLOW,
            ActionType.WARN,
            ActionType.ASK,
            ActionType.REDACT,
            ActionType.BLOCK,
        ]

        max_action = ActionType.ALLOW
        max_severity = Severity.LOW

        for finding in findings:
            if action_priority.index(finding.recommended_action) > action_priority.index(max_action):
                max_action = finding.recommended_action
            if list(Severity).index(finding.severity) > list(Severity).index(max_severity):
                max_severity = finding.severity

        # Determine risk level
        risk_level = "safe"
        if max_severity in (Severity.HIGH, Severity.CRITICAL):
            risk_level = "dangerous"
        elif max_severity == Severity.MEDIUM:
            risk_level = "suspicious"

        # Should prompt if action is ASK or BLOCK
        should_prompt = max_action in (ActionType.ASK, ActionType.BLOCK)

        return ScreeningResult(
            allowed=max_action not in (ActionType.BLOCK,),
            plugin_name=self.name,
            reason=f"Matched {len(findings)} pattern(s): {', '.join(f.pattern_name for f in findings[:3])}",
            risk_level=risk_level,
            should_prompt=should_prompt,
            findings=findings,
            details={
                "pattern_count": len(findings),
                "max_severity": max_severity.value,
            }
        )

    def _get_context(self, content: str, position: int, chars: int = 40) -> str:
        """Get surrounding context for a match."""
        start = max(0, position - chars)
        end = min(len(content), position + chars)

        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(content) else ""

        return f"{prefix}{content[start:end]}{suffix}"

    def check(self, content: str) -> Optional[Dict]:
        """
        Simple check returning first matching pattern.

        For compatibility with existing code.
        """
        patterns = self._load_patterns()

        for pattern_def in patterns:
            regex = pattern_def.get("regex", "")
            if not regex:
                continue

            compiled = self._get_compiled(regex)
            if compiled and compiled.search(content):
                return pattern_def

        return None

    def check_all(self, content: str) -> List[Dict]:
        """
        Check content against all patterns, returning all matches.

        For compatibility with existing code.
        """
        patterns = self._load_patterns()
        matches = []

        for pattern_def in patterns:
            regex = pattern_def.get("regex", "")
            if not regex:
                continue

            compiled = self._get_compiled(regex)
            if compiled and compiled.search(content):
                matches.append(pattern_def)

        return matches

    def get_pattern_count(self) -> int:
        """Get total number of loaded patterns."""
        return len(self._load_patterns())

    def get_patterns_by_category(self) -> Dict[str, List[Dict]]:
        """Get patterns grouped by category."""
        patterns = self._load_patterns()
        by_category: Dict[str, List[Dict]] = {}

        for pattern in patterns:
            category = pattern.get("category", "uncategorized")
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(pattern)

        return by_category
