"""
Tweek YARA Scanner — Optional YARA-based pattern matching layer.

Provides industry-standard malware classification patterns for skill scanning.
YARA rules ship with Tweek in tweek/rules/yara/ and cover patterns that are
difficult to express as individual regexes: multi-condition logic, threshold-based
detection, and structured exclusions.

YARA rules sourced from Cisco AI Defense skill-scanner (Apache 2.0).
See THIRD-PARTY-NOTICES.md for attribution.

This module is optional — if yara-python is not installed, the scanner
gracefully reports itself as unavailable and all scan calls return empty results.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Attempt to import yara — optional dependency
try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

# Default rules directory (shipped with Tweek)
_DEFAULT_RULES_DIR = Path(__file__).parent.parent / "rules" / "yara"

# Map YARA meta severity strings to Tweek severity levels
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "low",
}


class YaraScanner:
    """YARA-based pattern scanner for skill content.

    Compiles all .yara files from the rules directory into a single ruleset
    and scans text content against them.

    If yara-python is not installed, all operations are no-ops.
    """

    def __init__(self, rules_dir: Optional[Path] = None):
        """Initialize the YARA scanner.

        Args:
            rules_dir: Directory containing .yara rule files.
                       Defaults to tweek/rules/yara/.
        """
        self._rules = None
        self._rule_count = 0

        if not YARA_AVAILABLE:
            return

        rules_dir = rules_dir or _DEFAULT_RULES_DIR

        if not rules_dir.is_dir():
            logger.warning("YARA rules directory not found: %s", rules_dir)
            return

        # Collect all .yara files
        sources: Dict[str, str] = {}
        for rule_file in sorted(rules_dir.glob("*.yara")):
            try:
                sources[rule_file.stem] = rule_file.read_text(encoding="utf-8")
            except (IOError, UnicodeDecodeError) as e:
                logger.warning("Failed to read YARA rule %s: %s", rule_file, e)

        if not sources:
            logger.warning("No YARA rule files found in %s", rules_dir)
            return

        # Compile all rules into a single namespace-separated ruleset
        try:
            self._rules = yara.compile(sources=sources)
            self._rule_count = len(sources)
            logger.debug("Compiled %d YARA rule files", self._rule_count)
        except yara.SyntaxError as e:
            logger.error("YARA compilation error: %s", e)
        except yara.Error as e:
            logger.error("YARA error: %s", e)

    @property
    def available(self) -> bool:
        """True if yara-python is installed and rules compiled successfully."""
        return self._rules is not None

    @property
    def rule_count(self) -> int:
        """Number of YARA rule files loaded."""
        return self._rule_count

    def scan_content(
        self, content: str, filename: str = ""
    ) -> List[Dict[str, Any]]:
        """Scan text content against all loaded YARA rules.

        Args:
            content: Text content to scan.
            filename: Source filename (for reporting).

        Returns:
            List of finding dicts with keys:
                - rule: YARA rule name
                - severity: Tweek severity level
                - description: Rule description from meta
                - category: Threat type from meta
                - matched_strings: List of (identifier, matched_text) tuples
                - file: Source filename
        """
        if not self._rules:
            return []

        try:
            matches = self._rules.match(data=content.encode("utf-8"))
        except yara.Error as e:
            logger.warning("YARA scan error on %s: %s", filename, e)
            return []

        findings = []
        for match in matches:
            meta = match.meta or {}

            # Extract matched strings with readable text
            matched_strings = []
            for string_match in match.strings:
                for instance in string_match.instances:
                    try:
                        text = instance.matched_data.decode("utf-8", errors="replace")
                        matched_strings.append((string_match.identifier, text[:200]))
                    except (AttributeError, TypeError):
                        matched_strings.append((string_match.identifier, ""))

            # Map severity from YARA meta
            raw_severity = str(meta.get("severity", "medium")).lower()
            severity = _SEVERITY_MAP.get(raw_severity, "medium")

            findings.append({
                "rule": match.rule,
                "severity": severity,
                "description": meta.get("description", match.rule),
                "category": meta.get("threat_type", meta.get("classification", "unknown")),
                "matched_strings": matched_strings,
                "file": filename,
            })

        return findings
