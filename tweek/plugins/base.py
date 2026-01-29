#!/usr/bin/env python3
"""
Tweek Plugin Base Classes

Abstract base classes defining the interface for each plugin type:
- CompliancePlugin: Domain compliance (Gov, HIPAA, PCI, Legal)
- LLMProviderPlugin: LLM API provider detection and parsing
- ToolDetectorPlugin: Tool/IDE detection
- ScreeningPlugin: Security screening methods

All plugins should inherit from one of these base classes.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any, Tuple
import re
import signal
import threading


# =============================================================================
# REDOS PROTECTION
# =============================================================================

class RegexError(Exception):
    """Exception raised for regex-related errors."""
    pass


class RegexTimeoutError(RegexError):
    """Exception raised when regex execution times out (potential ReDoS)."""
    pass


class ReDoSProtection:
    """
    Protection against Regular Expression Denial of Service (ReDoS) attacks.

    ReDoS occurs when a crafted regex pattern causes exponential backtracking,
    consuming excessive CPU and potentially hanging the application.

    This class provides:
    1. Pattern validation to detect known dangerous patterns
    2. Timeout-based protection for regex execution
    3. Length limits on input strings
    """

    # Maximum allowed pattern length
    MAX_PATTERN_LENGTH = 1000

    # Maximum input length for scanning (per call)
    MAX_INPUT_LENGTH = 1_000_000  # 1MB

    # Timeout for regex operations (seconds)
    DEFAULT_TIMEOUT = 5.0

    # Dangerous pattern indicators (simple heuristics)
    # These are common patterns that can cause exponential backtracking
    DANGEROUS_PATTERNS = [
        # Nested quantifiers
        r'\(\.\*\)\+',           # (.*)+
        r'\(\.\+\)\+',           # (.+)+
        r'\(\.\*\)\*',           # (.*)*
        r'\(\.\+\)\*',           # (.+)*
        # Overlapping alternation with quantifiers
        r'\([^)]*\|[^)]*\)\+',   # (a|a)+
        r'\([^)]*\|[^)]*\)\*',   # (a|a)*
    ]

    @classmethod
    def validate_pattern(cls, pattern: str) -> Tuple[bool, Optional[str]]:
        """
        Validate a regex pattern for potential ReDoS vulnerabilities.

        Args:
            pattern: The regex pattern to validate

        Returns:
            Tuple of (is_safe, error_message)
            If is_safe is True, error_message is None
        """
        # Check length
        if len(pattern) > cls.MAX_PATTERN_LENGTH:
            return False, f"Pattern too long ({len(pattern)} > {cls.MAX_PATTERN_LENGTH})"

        # Check for dangerous patterns
        for dangerous in cls.DANGEROUS_PATTERNS:
            try:
                if re.search(dangerous, pattern):
                    return False, f"Pattern contains potentially dangerous construct"
            except re.error:
                continue

        # Try to compile the pattern
        try:
            re.compile(pattern)
        except re.error as e:
            return False, f"Invalid regex: {e}"

        return True, None

    @classmethod
    def safe_compile(
        cls,
        pattern: str,
        flags: int = 0,
        validate: bool = True
    ) -> re.Pattern:
        """
        Safely compile a regex pattern with ReDoS validation.

        Args:
            pattern: The regex pattern to compile
            flags: Regex flags (re.IGNORECASE, etc.)
            validate: Whether to validate for ReDoS (default True)

        Returns:
            Compiled regex pattern

        Raises:
            RegexError: If pattern is invalid or potentially dangerous
        """
        if validate:
            is_safe, error = cls.validate_pattern(pattern)
            if not is_safe:
                raise RegexError(f"Unsafe regex pattern: {error}")

        try:
            return re.compile(pattern, flags)
        except re.error as e:
            raise RegexError(f"Failed to compile regex: {e}")

    @classmethod
    def safe_search(
        cls,
        pattern: re.Pattern,
        text: str,
        timeout: float = None
    ) -> Optional[re.Match]:
        """
        Safely execute regex search with timeout protection.

        Note: Timeout protection only works on Unix-like systems (uses SIGALRM).
        On Windows, this falls back to no timeout.

        Args:
            pattern: Compiled regex pattern
            text: Text to search
            timeout: Timeout in seconds (default: DEFAULT_TIMEOUT)

        Returns:
            Match object or None

        Raises:
            RegexTimeoutError: If regex execution times out
        """
        if timeout is None:
            timeout = cls.DEFAULT_TIMEOUT

        # Truncate input if too long
        if len(text) > cls.MAX_INPUT_LENGTH:
            text = text[:cls.MAX_INPUT_LENGTH]

        # On Windows or in threaded context, just run without timeout
        if not hasattr(signal, 'SIGALRM') or threading.current_thread() is not threading.main_thread():
            return pattern.search(text)

        def timeout_handler(signum, frame):
            raise RegexTimeoutError(f"Regex execution timed out after {timeout}s")

        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, timeout)

        try:
            return pattern.search(text)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)

    @classmethod
    def safe_finditer(
        cls,
        pattern: re.Pattern,
        text: str,
        timeout: float = None,
        max_matches: int = 1000
    ) -> List[re.Match]:
        """
        Safely execute regex finditer with timeout and match limit.

        Args:
            pattern: Compiled regex pattern
            text: Text to search
            timeout: Timeout in seconds
            max_matches: Maximum number of matches to return

        Returns:
            List of match objects

        Raises:
            RegexTimeoutError: If regex execution times out
        """
        if timeout is None:
            timeout = cls.DEFAULT_TIMEOUT

        # Truncate input if too long
        if len(text) > cls.MAX_INPUT_LENGTH:
            text = text[:cls.MAX_INPUT_LENGTH]

        matches = []

        # On Windows or in threaded context, just run without timeout
        if not hasattr(signal, 'SIGALRM') or threading.current_thread() is not threading.main_thread():
            for i, match in enumerate(pattern.finditer(text)):
                if i >= max_matches:
                    break
                matches.append(match)
            return matches

        def timeout_handler(signum, frame):
            raise RegexTimeoutError(f"Regex execution timed out after {timeout}s")

        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, timeout)

        try:
            for i, match in enumerate(pattern.finditer(text)):
                if i >= max_matches:
                    break
                matches.append(match)
            return matches
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)


class ScanDirection(Enum):
    """Direction of content scanning."""
    INPUT = "input"       # Scanning incoming data (user input, tool results)
    OUTPUT = "output"     # Scanning LLM outputs (before displaying to user)
    BOTH = "both"         # Bidirectional scanning


class ActionType(Enum):
    """Actions that can be taken on findings."""
    ALLOW = "allow"       # Allow content through unchanged
    WARN = "warn"         # Allow but warn user
    BLOCK = "block"       # Block content entirely
    REDACT = "redact"     # Redact matched content and allow
    ASK = "ask"           # Prompt user for decision


class Severity(Enum):
    """Severity levels for findings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    """
    A single finding from a compliance or security scan.

    Represents a specific match or issue detected in content.
    Security: matched_text is stored internally for redaction processing,
    but is redacted in to_dict() and redacted_text property to prevent
    accidental exposure of sensitive data in logs/exports.
    """
    pattern_name: str
    matched_text: str
    severity: Severity
    description: Optional[str] = None
    line_number: Optional[int] = None
    column: Optional[int] = None
    context: Optional[str] = None
    recommended_action: ActionType = ActionType.WARN
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def redacted_text(self) -> str:
        """
        Get redacted version of matched text.

        Preserves first and last chars, masks middle with asterisks.
        For very short strings (<=4 chars), masks entirely.
        """
        return self._redact_text(self.matched_text)

    @property
    def redacted_context(self) -> Optional[str]:
        """Get context with matched text redacted."""
        if self.context is None:
            return None
        return self.context.replace(self.matched_text, self.redacted_text)

    @staticmethod
    def _redact_text(text: str) -> str:
        """
        Redact sensitive text while preserving some structure.

        - For strings <=4 chars: mask entirely with asterisks
        - For longer strings: show first 2 and last 2 chars, mask middle
        """
        if len(text) <= 4:
            return "*" * len(text)
        elif len(text) <= 8:
            return text[0] + "*" * (len(text) - 2) + text[-1]
        else:
            return text[:2] + "*" * (len(text) - 4) + text[-2:]

    def to_dict(self, include_raw: bool = False) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization.

        Args:
            include_raw: If True, include raw matched_text (SECURITY: only use
                        for internal processing, never for logs/exports)

        Returns:
            Dictionary with finding details (matched_text redacted by default)
        """
        result = {
            "pattern_name": self.pattern_name,
            "matched_text": self.matched_text if include_raw else self.redacted_text,
            "severity": self.severity.value,
            "description": self.description,
            "line_number": self.line_number,
            "column": self.column,
            "context": self.context if include_raw else self.redacted_context,
            "recommended_action": self.recommended_action.value,
            "metadata": self.metadata,
        }
        if not include_raw:
            result["text_length"] = len(self.matched_text)
        return result


@dataclass
class ScanResult:
    """
    Result of a compliance/security scan.

    Aggregates all findings and determines overall action.
    """
    passed: bool
    findings: List[Finding] = field(default_factory=list)
    action: ActionType = ActionType.ALLOW
    message: Optional[str] = None
    scan_direction: Optional[ScanDirection] = None
    plugin_name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def has_critical(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)

    @property
    def has_high(self) -> bool:
        return any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in self.findings)

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return max(self.findings, key=lambda f: severity_order.index(f.severity)).severity

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "passed": self.passed,
            "findings": [f.to_dict() for f in self.findings],
            "action": self.action.value,
            "message": self.message,
            "scan_direction": self.scan_direction.value if self.scan_direction else None,
            "plugin_name": self.plugin_name,
            "finding_count": self.finding_count,
            "max_severity": self.max_severity.value if self.max_severity else None,
            "metadata": self.metadata,
        }


@dataclass
class PatternDefinition:
    """Definition of a pattern to match against."""
    name: str
    regex: str
    severity: Severity
    description: str
    default_action: ActionType = ActionType.WARN
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Whether to validate pattern for ReDoS (disable for trusted built-in patterns)
    validate_redos: bool = False

    _compiled: Optional[re.Pattern] = field(default=None, repr=False)
    _compile_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def compile(self, validate: bool = None) -> re.Pattern:
        """
        Compile and cache the regex pattern.

        Thread-safe using double-checked locking pattern.

        Args:
            validate: Override ReDoS validation (default: use self.validate_redos)

        Returns:
            Compiled regex pattern

        Raises:
            RegexError: If pattern is invalid or fails ReDoS validation
        """
        # Fast path: already compiled
        if self._compiled is not None:
            return self._compiled

        # Slow path: acquire lock and compile
        with self._compile_lock:
            # Double-check after acquiring lock
            if self._compiled is None:
                should_validate = validate if validate is not None else self.validate_redos
                self._compiled = ReDoSProtection.safe_compile(
                    self.regex,
                    flags=re.IGNORECASE | re.MULTILINE,
                    validate=should_validate
                )
        return self._compiled


# =============================================================================
# COMPLIANCE PLUGIN BASE
# =============================================================================

class CompliancePlugin(ABC):
    """
    Base class for domain compliance plugins.

    Compliance plugins scan content for domain-specific sensitive information:
    - Gov: Classification markings, CUI, FOUO
    - HIPAA: PHI, medical records, patient data
    - PCI: Credit cards, CVVs, bank accounts
    - Legal: Attorney-client privilege markers

    Supports bidirectional scanning:
    - OUTPUT: Detect hallucinated sensitive content in LLM responses
    - INPUT: Detect real sensitive content in incoming data
    """

    # Class-level metadata (override in subclasses)
    VERSION = "1.0.0"
    DESCRIPTION = "Base compliance plugin"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "enterprise"
    TAGS = ["compliance"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the compliance plugin.

        Args:
            config: Optional configuration dictionary with:
                - enabled: bool
                - scan_direction: "input", "output", or "both"
                - actions: Dict mapping pattern names to actions
                - allowlist: List of exact strings to ignore (false positive suppression)
                - allowlist_patterns: List of regex patterns to ignore
                - suppressed_patterns: List of pattern names to disable
        """
        self._config = config or {}
        self._action_overrides: Dict[str, ActionType] = {}
        self._allowlist: List[str] = []
        self._allowlist_patterns: List[re.Pattern] = []
        self._suppressed_patterns: set = set()

        # Load action overrides from config
        actions = self._config.get("actions", {})
        for pattern_name, action_str in actions.items():
            try:
                self._action_overrides[pattern_name] = ActionType(action_str)
            except ValueError:
                pass

        # Load allowlist (exact string matches to ignore)
        self._allowlist = self._config.get("allowlist", [])

        # Load allowlist patterns (regex patterns to ignore)
        for pattern_str in self._config.get("allowlist_patterns", []):
            try:
                self._allowlist_patterns.append(re.compile(pattern_str, re.IGNORECASE))
            except re.error:
                pass  # Skip invalid patterns

        # Load suppressed pattern names
        self._suppressed_patterns = set(self._config.get("suppressed_patterns", []))

    @property
    @abstractmethod
    def name(self) -> str:
        """Plugin name (e.g., 'gov', 'hipaa')."""
        pass

    @property
    @abstractmethod
    def scan_direction(self) -> ScanDirection:
        """Which direction this plugin scans by default."""
        pass

    @abstractmethod
    def get_patterns(self) -> List[PatternDefinition]:
        """
        Return patterns this plugin checks for.

        Returns:
            List of PatternDefinition objects
        """
        pass

    def scan(self, content: str, direction: ScanDirection) -> ScanResult:
        """
        Scan content for compliance issues.

        Args:
            content: Text content to scan
            direction: Whether this is input or output scanning

        Returns:
            ScanResult with findings and recommended action
        """
        # Check if we should scan this direction
        if self.scan_direction != ScanDirection.BOTH:
            if self.scan_direction != direction:
                return ScanResult(
                    passed=True,
                    plugin_name=self.name,
                    scan_direction=direction
                )

        findings = []

        for pattern in self.get_patterns():
            if not pattern.enabled:
                continue

            # Check if pattern is suppressed
            if pattern.name in self._suppressed_patterns:
                continue

            try:
                compiled = pattern.compile()
                for match in compiled.finditer(content):
                    matched_text = match.group()

                    # Check if match is in allowlist (exact match)
                    if matched_text in self._allowlist:
                        continue

                    # Check if match is suppressed by allowlist pattern
                    if self._is_allowlisted(matched_text):
                        continue

                    # Get line number
                    line_num = content[:match.start()].count('\n') + 1

                    # Get context (surrounding text)
                    context = self._get_context(content, match.start(), match.end())

                    # Determine action (check for override)
                    action = self._action_overrides.get(
                        pattern.name,
                        pattern.default_action
                    )

                    findings.append(Finding(
                        pattern_name=pattern.name,
                        matched_text=matched_text,
                        severity=pattern.severity,
                        description=pattern.description,
                        line_number=line_num,
                        context=context,
                        recommended_action=action,
                        metadata={"pattern_tags": pattern.tags}
                    ))
            except re.error as e:
                # Invalid regex - skip
                continue

        # Determine overall action (highest severity wins)
        action = self._determine_action(findings)

        # Generate message
        message = self._format_message(findings, direction)

        return ScanResult(
            passed=len(findings) == 0,
            findings=findings,
            action=action,
            message=message,
            scan_direction=direction,
            plugin_name=self.name
        )

    def _get_context(
        self,
        content: str,
        start: int,
        end: int,
        context_chars: int = 50
    ) -> str:
        """Get surrounding context for a match."""
        ctx_start = max(0, start - context_chars)
        ctx_end = min(len(content), end + context_chars)

        prefix = "..." if ctx_start > 0 else ""
        suffix = "..." if ctx_end < len(content) else ""

        return f"{prefix}{content[ctx_start:ctx_end]}{suffix}"

    def _is_allowlisted(self, text: str) -> bool:
        """
        Check if text matches any allowlist pattern.

        Args:
            text: The matched text to check

        Returns:
            True if text should be suppressed (matches allowlist)
        """
        for pattern in self._allowlist_patterns:
            if pattern.search(text):
                return True
        return False

    def _determine_action(self, findings: List[Finding]) -> ActionType:
        """Determine overall action based on findings."""
        if not findings:
            return ActionType.ALLOW

        # Priority: BLOCK > REDACT > ASK > WARN > ALLOW
        action_priority = [
            ActionType.ALLOW,
            ActionType.WARN,
            ActionType.ASK,
            ActionType.REDACT,
            ActionType.BLOCK,
        ]

        max_action = ActionType.ALLOW
        for finding in findings:
            if action_priority.index(finding.recommended_action) > action_priority.index(max_action):
                max_action = finding.recommended_action

        return max_action

    def _format_message(
        self,
        findings: List[Finding],
        direction: ScanDirection
    ) -> Optional[str]:
        """Format a user-facing message about findings."""
        if not findings:
            return None

        if direction == ScanDirection.OUTPUT:
            prefix = "LLM output contains"
            suffix = "These may be hallucinated and should be verified."
        else:
            prefix = "Input data contains"
            suffix = "Verify proper handling procedures."

        # Group by severity
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        high = [f for f in findings if f.severity == Severity.HIGH]

        lines = [f"{prefix} {len(findings)} potential compliance issue(s):"]

        if critical:
            lines.append(f"  CRITICAL: {len(critical)} finding(s)")
        if high:
            lines.append(f"  HIGH: {len(high)} finding(s)")

        lines.append(suffix)

        return "\n".join(lines)

    def configure(self, config: Dict[str, Any]) -> None:
        """Update plugin configuration."""
        self._config.update(config)

        # Reload action overrides
        actions = self._config.get("actions", {})
        for pattern_name, action_str in actions.items():
            try:
                self._action_overrides[pattern_name] = ActionType(action_str)
            except ValueError:
                pass

        # Reload allowlist settings
        self._allowlist = self._config.get("allowlist", [])

        self._allowlist_patterns = []
        for pattern_str in self._config.get("allowlist_patterns", []):
            try:
                self._allowlist_patterns.append(re.compile(pattern_str, re.IGNORECASE))
            except re.error:
                pass

        self._suppressed_patterns = set(self._config.get("suppressed_patterns", []))


# =============================================================================
# LLM PROVIDER PLUGIN BASE
# =============================================================================

@dataclass
class ToolCall:
    """Represents a tool call extracted from an LLM response."""
    id: str
    name: str
    input: Dict[str, Any]
    provider: str
    raw: Optional[Dict[str, Any]] = None


class LLMProviderPlugin(ABC):
    """
    Base class for LLM provider plugins.

    Provider plugins handle provider-specific API formats:
    - Endpoint detection
    - Tool call extraction from responses
    - Request/response parsing
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Base LLM provider plugin"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["provider"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or {}

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name (e.g., 'anthropic', 'openai')."""
        pass

    @property
    @abstractmethod
    def api_hosts(self) -> List[str]:
        """List of API hostnames for this provider."""
        pass

    def matches_endpoint(self, url: str) -> bool:
        """
        Check if URL matches this provider's API.

        Args:
            url: URL or hostname to check

        Returns:
            True if this provider handles the URL
        """
        # Extract hostname from URL
        if "://" in url:
            host = url.split("://")[1].split("/")[0]
        else:
            host = url.split("/")[0]

        # Remove port if present
        host = host.split(":")[0]

        return host in self.api_hosts

    @abstractmethod
    def extract_tool_calls(self, response: Dict[str, Any]) -> List[ToolCall]:
        """
        Extract tool calls from provider-specific response format.

        Args:
            response: Parsed JSON response from the API

        Returns:
            List of ToolCall objects
        """
        pass

    def extract_content(self, response: Dict[str, Any]) -> str:
        """
        Extract text content from provider-specific response.

        Args:
            response: Parsed JSON response from the API

        Returns:
            Text content from the response
        """
        # Default implementation - override for provider-specific format
        return ""

    def configure(self, config: Dict[str, Any]) -> None:
        """Update plugin configuration."""
        self._config.update(config)


# =============================================================================
# TOOL DETECTOR PLUGIN BASE
# =============================================================================

@dataclass
class DetectionResult:
    """Result of tool detection."""
    detected: bool
    tool_name: str
    version: Optional[str] = None
    install_path: Optional[str] = None
    config_path: Optional[str] = None
    running: bool = False
    port: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ToolDetectorPlugin(ABC):
    """
    Base class for tool detector plugins.

    Detector plugins identify installed LLM tools/IDEs:
    - Installation detection
    - Running process detection
    - Configuration location
    - Conflict detection
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Base tool detector plugin"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["detector"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or {}

    @property
    @abstractmethod
    def name(self) -> str:
        """Tool name (e.g., 'moltbot', 'cursor')."""
        pass

    @abstractmethod
    def detect(self) -> DetectionResult:
        """
        Detect if tool is installed/running.

        Returns:
            DetectionResult with detection information
        """
        pass

    def get_conflicts(self) -> List[str]:
        """
        Get list of potential conflicts with this tool.

        Returns:
            List of conflict descriptions
        """
        return []

    def configure(self, config: Dict[str, Any]) -> None:
        """Update plugin configuration."""
        self._config.update(config)


# =============================================================================
# SCREENING PLUGIN BASE
# =============================================================================

@dataclass
class ScreeningResult:
    """Result of a security screening check."""
    allowed: bool
    plugin_name: str
    reason: Optional[str] = None
    risk_level: Optional[str] = None  # "safe", "suspicious", "dangerous"
    confidence: float = 1.0
    should_prompt: bool = False
    details: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "plugin_name": self.plugin_name,
            "reason": self.reason,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "should_prompt": self.should_prompt,
            "details": self.details,
            "findings": [f.to_dict() for f in self.findings],
        }


class ScreeningPlugin(ABC):
    """
    Base class for screening method plugins.

    Screening plugins analyze tool invocations for security risks:
    - Rate limiting
    - Pattern matching
    - LLM-based review
    - Session analysis
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Base screening plugin"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["screening"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or {}

    @property
    @abstractmethod
    def name(self) -> str:
        """Screening method name (e.g., 'rate_limiter', 'pattern_matcher')."""
        pass

    @abstractmethod
    def screen(
        self,
        tool_name: str,
        content: str,
        context: Dict[str, Any]
    ) -> ScreeningResult:
        """
        Screen a tool invocation for security risks.

        Args:
            tool_name: Name of the tool being invoked
            content: Command or content to screen
            context: Additional context (session_id, tool_input, tier, etc.)

        Returns:
            ScreeningResult with screening decision
        """
        pass

    def configure(self, config: Dict[str, Any]) -> None:
        """Update plugin configuration."""
        self._config.update(config)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def combine_scan_results(results: List[ScanResult]) -> ScanResult:
    """
    Combine multiple scan results into a single result.

    Args:
        results: List of ScanResult objects

    Returns:
        Combined ScanResult with all findings
    """
    if not results:
        return ScanResult(passed=True)

    all_findings = []
    messages = []

    for result in results:
        all_findings.extend(result.findings)
        if result.message:
            messages.append(result.message)

    # Determine combined action
    action_priority = [
        ActionType.ALLOW,
        ActionType.WARN,
        ActionType.ASK,
        ActionType.REDACT,
        ActionType.BLOCK,
    ]

    max_action = ActionType.ALLOW
    for result in results:
        if action_priority.index(result.action) > action_priority.index(max_action):
            max_action = result.action

    return ScanResult(
        passed=len(all_findings) == 0,
        findings=all_findings,
        action=max_action,
        message="\n\n".join(messages) if messages else None,
        metadata={"combined_from": [r.plugin_name for r in results if r.plugin_name]}
    )


def combine_screening_results(results: List[ScreeningResult]) -> ScreeningResult:
    """
    Combine multiple screening results into a single result.

    Args:
        results: List of ScreeningResult objects

    Returns:
        Combined ScreeningResult
    """
    if not results:
        return ScreeningResult(allowed=True, plugin_name="combined")

    # If any result blocks, the combined result blocks
    allowed = all(r.allowed for r in results)
    should_prompt = any(r.should_prompt for r in results)

    # Collect all findings
    all_findings = []
    for result in results:
        all_findings.extend(result.findings)

    # Determine highest risk level
    risk_order = {"safe": 0, "suspicious": 1, "dangerous": 2}
    max_risk = "safe"
    for result in results:
        if result.risk_level and risk_order.get(result.risk_level, 0) > risk_order.get(max_risk, 0):
            max_risk = result.risk_level

    # Combine reasons
    reasons = [r.reason for r in results if r.reason and not r.allowed]

    return ScreeningResult(
        allowed=allowed,
        plugin_name="combined",
        reason="; ".join(reasons) if reasons else None,
        risk_level=max_risk,
        should_prompt=should_prompt,
        details={"from_plugins": [r.plugin_name for r in results]},
        findings=all_findings
    )


# Public API
__all__ = [
    # Enums
    "ScanDirection",
    "ActionType",
    "Severity",
    # Exceptions
    "RegexError",
    "RegexTimeoutError",
    # Data classes
    "Finding",
    "ScanResult",
    "PatternDefinition",
    "ToolCall",
    "DetectionResult",
    "ScreeningResult",
    # Base classes
    "CompliancePlugin",
    "LLMProviderPlugin",
    "ToolDetectorPlugin",
    "ScreeningPlugin",
    # Utilities
    "ReDoSProtection",
    "combine_scan_results",
    "combine_screening_results",
]
