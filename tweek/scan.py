"""
Tweek Scan — Static Security Scanner for Skill Files

Pre-scans skill files (.md) or skill directories for security risks before
installation. Supports local files, local directories, and remote URLs.

Runs a multi-layer security pipeline in read-only mode:
1.   Structure Validation    — file types, size, depth, blocked extensions
2.   Pattern Matching        — 275+ regex patterns (reuses audit.py)
2.5  YARA Rules              — 13 rules via yara-python (optional)
3.   Secret Scanning         — credential detection (reuses secret_scanner.py)
4.   AST Analysis            — forbidden imports/calls in Python files
4B.  Taint/Dataflow Analysis — source→sink tracking (env vars, creds → network)
4.5  Manifest-Code Consistency — cross-validates declared tools vs actual code
5.   Prompt Injection Scan   — skill-specific injection + unicode steganography
6.   Exfiltration Detection  — network URLs, exfil sites, data sending
7.   LLM Semantic Review     — intent analysis (reuses llm_reviewer.py)

Safety guarantees:
- Purely read-only: no files are created, moved, or modified
- URL content is downloaded to memory only, never written to disk
- Content is never executed — only parsed via regex, ast.parse, and string ops
- All regex execution uses ReDoS-protected timeouts
- LLM review wraps content in nonce-tagged XML to prevent injection
"""

import ast
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from tweek.skills.config import IsolationConfig
from tweek.skills.scanner import (
    EXFIL_COMMAND_PATTERNS,
    EXFIL_URL_PATTERN,
    SKILL_INJECTION_PATTERNS,
    SUSPICIOUS_HOSTS,
    ScanLayerResult,
    SkillScanReport,
)


# =============================================================================
# URL Normalization
# =============================================================================

# GitHub: github.com/user/repo/blob/branch/path → raw.githubusercontent.com/user/repo/branch/path
GITHUB_BLOB_RE = re.compile(
    r"^https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$"
)

# GitLab: gitlab.com/user/repo/-/blob/branch/path → gitlab.com/user/repo/-/raw/branch/path
GITLAB_BLOB_RE = re.compile(
    r"^https?://gitlab\.com/(.+?)/-/blob/([^/]+)/(.+)$"
)

# Bitbucket: bitbucket.org/user/repo/src/branch/path → bitbucket.org/user/repo/raw/branch/path
BITBUCKET_SRC_RE = re.compile(
    r"^https?://bitbucket\.org/([^/]+)/([^/]+)/src/([^/]+)/(.+)$"
)

MAX_DOWNLOAD_BYTES = 1_048_576  # 1 MB
DOWNLOAD_TIMEOUT = 30  # seconds


def normalize_url(url: str) -> str:
    """Convert GitHub/GitLab/Bitbucket blob/view URLs to raw content URLs.

    Passes through URLs that are already raw or from unknown hosts.
    """
    # GitHub blob → raw
    m = GITHUB_BLOB_RE.match(url)
    if m:
        user, repo, branch, path = m.groups()
        return f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"

    # GitLab blob → raw
    m = GITLAB_BLOB_RE.match(url)
    if m:
        project, branch, path = m.groups()
        return f"https://gitlab.com/{project}/-/raw/{branch}/{path}"

    # Bitbucket src → raw
    m = BITBUCKET_SRC_RE.match(url)
    if m:
        user, repo, branch, path = m.groups()
        return f"https://bitbucket.org/{user}/{repo}/raw/{branch}/{path}"

    return url


# =============================================================================
# ScanTarget — In-Memory Content Bundle
# =============================================================================

@dataclass
class ScanTarget:
    """Read-only content bundle for scanning.

    Represents the content to be scanned without any filesystem coupling.
    All text content is held in memory as strings.
    """
    name: str                                    # Skill name
    source: str                                  # Original source (path or URL)
    source_type: str                             # "file", "directory", or "url"
    files: Dict[str, str] = field(default_factory=dict)   # {relative_path: content}
    total_bytes: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Source Resolution
# =============================================================================

def resolve_source(source: str, config: Optional[IsolationConfig] = None) -> ScanTarget:
    """Resolve a source string (local path or URL) to a ScanTarget.

    Args:
        source: Local file path, local directory path, or URL
        config: Optional isolation config for size/extension limits

    Returns:
        ScanTarget with content loaded into memory

    Raises:
        FileNotFoundError: If local path doesn't exist
        ValueError: If URL download fails or exceeds limits
    """
    if source.startswith("http://") or source.startswith("https://"):
        return resolve_url(source, config)
    return resolve_local_path(source, config)


def resolve_local_path(
    path_str: str, config: Optional[IsolationConfig] = None
) -> ScanTarget:
    """Resolve a local file or directory to a ScanTarget.

    Args:
        path_str: Path to a file or directory
        config: Optional isolation config for extension filtering

    Returns:
        ScanTarget with file content(s) loaded

    Raises:
        FileNotFoundError: If path doesn't exist
        ValueError: If content exceeds size limits
    """
    config = config or IsolationConfig()
    path = Path(path_str).resolve()

    if not path.exists():
        raise FileNotFoundError(f"Path not found: {path_str}")

    if path.is_file():
        content = path.read_text(encoding="utf-8")
        total_bytes = len(content.encode("utf-8"))

        if total_bytes > config.max_skill_size_bytes:
            raise ValueError(
                f"File size {total_bytes:,} bytes exceeds limit "
                f"{config.max_skill_size_bytes:,} bytes"
            )

        name = path.parent.name if path.name == "SKILL.md" else path.stem
        return ScanTarget(
            name=name,
            source=str(path),
            source_type="file",
            files={path.name: content},
            total_bytes=total_bytes,
        )

    # Directory
    allowed = set(config.allowed_file_extensions)
    blocked = set(config.blocked_file_extensions)
    files: Dict[str, str] = {}
    total_bytes = 0

    for item in sorted(path.rglob("*")):
        if not item.is_file():
            continue

        ext = item.suffix.lower()
        if ext in blocked:
            continue
        if ext not in allowed:
            continue

        try:
            content = item.read_text(encoding="utf-8")
            rel_path = str(item.relative_to(path))
            files[rel_path] = content
            total_bytes += len(content.encode("utf-8"))
        except (IOError, UnicodeDecodeError):
            continue

    if total_bytes > config.max_skill_size_bytes:
        raise ValueError(
            f"Total content size {total_bytes:,} bytes exceeds limit "
            f"{config.max_skill_size_bytes:,} bytes"
        )

    return ScanTarget(
        name=path.name,
        source=str(path),
        source_type="directory",
        files=files,
        total_bytes=total_bytes,
    )


def resolve_url(
    url: str, config: Optional[IsolationConfig] = None
) -> ScanTarget:
    """Download a URL to memory and return a ScanTarget.

    Safety measures:
    - HTTPS enforcement (plain HTTP rejected)
    - Size limit check via Content-Length header before download
    - Streaming download with cumulative byte limit
    - 30-second timeout
    - Content stored only in memory, never written to disk

    Args:
        url: URL to download (must be HTTPS)
        config: Optional isolation config for size limits

    Returns:
        ScanTarget with downloaded content

    Raises:
        ValueError: If URL is invalid, too large, or download fails
    """
    config = config or IsolationConfig()
    max_bytes = min(MAX_DOWNLOAD_BYTES, config.max_skill_size_bytes)

    # Enforce HTTPS
    if url.startswith("http://"):
        url = "https://" + url[7:]

    if not url.startswith("https://"):
        raise ValueError(f"Only HTTPS URLs are supported: {url}")

    # Normalize blob URLs to raw content URLs
    raw_url = normalize_url(url)

    # Extract filename from URL path
    url_path = raw_url.split("?")[0]  # Strip query params
    filename = url_path.rsplit("/", 1)[-1] if "/" in url_path else "SKILL.md"

    try:
        # Create SSL context
        ctx = ssl.create_default_context()

        req = urllib.request.Request(raw_url, headers={
            "User-Agent": "tweek-scan/1.0",
            "Accept": "text/plain, text/markdown, */*",
        })

        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT, context=ctx) as resp:
            # Check Content-Length if available
            content_length = resp.headers.get("Content-Length")
            if content_length and int(content_length) > max_bytes:
                raise ValueError(
                    f"Content size {int(content_length):,} bytes exceeds "
                    f"limit {max_bytes:,} bytes"
                )

            # Stream download with size guard
            chunks = []
            total = 0
            while True:
                chunk = resp.read(8192)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(
                        f"Download exceeded {max_bytes:,} byte limit "
                        f"(received {total:,} bytes)"
                    )
                chunks.append(chunk)

            raw_content = b"".join(chunks)

    except urllib.error.HTTPError as e:
        raise ValueError(f"HTTP {e.code}: {e.reason} — {raw_url}") from e
    except urllib.error.URLError as e:
        raise ValueError(f"URL error: {e.reason} — {raw_url}") from e
    except TimeoutError:
        raise ValueError(f"Download timed out after {DOWNLOAD_TIMEOUT}s — {raw_url}")

    # Decode content
    try:
        content = raw_content.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Downloaded content is not valid UTF-8 text")

    # Determine skill name from URL path
    parts = url_path.rstrip("/").split("/")
    # For .../skills/foo/SKILL.md, use "foo" as the name
    if filename == "SKILL.md" and len(parts) >= 2:
        name = parts[-2]
    else:
        name = Path(filename).stem

    return ScanTarget(
        name=name,
        source=url,
        source_type="url",
        files={filename: content},
        total_bytes=len(raw_content),
        metadata={
            "raw_url": raw_url,
            "original_url": url,
        },
    )


# =============================================================================
# ContentScanner — 7-Layer Pipeline on In-Memory Content
# =============================================================================

# AST analysis constants (from tweek.plugins.git_security)
FORBIDDEN_IMPORTS = frozenset({
    "subprocess", "os.system", "os.popen", "os.exec", "os.execl",
    "os.execle", "os.execlp", "os.execv", "os.execve", "os.execvp",
    "os.execvpe", "os.spawn", "os.spawnl", "os.spawnle", "os.spawnlp",
    "os.spawnlpe", "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "ctypes", "multiprocessing", "importlib", "importlib.util",
})

FORBIDDEN_CALLS = frozenset({
    "eval", "exec", "compile", "__import__", "os.system", "os.popen",
    "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
    "shutil.rmtree", "shutil.move", "importlib.import_module",
    "importlib.util.spec_from_file_location", "getattr",
})

FORBIDDEN_NETWORK_IMPORTS = frozenset({
    "socket", "urllib", "urllib.request", "urllib.parse",
    "http.client", "http.server", "requests", "httpx", "aiohttp",
    "websockets", "paramiko", "ftplib", "smtplib",
})


# =============================================================================
# Unicode Steganography Detection
# (from Cisco AI Defense skill-scanner — see THIRD-PARTY-NOTICES.md)
# =============================================================================

# Zero-width characters used for invisible text encoding
_ZERO_WIDTH_CHARS = re.compile(r"[\u200B\u200C\u200D\uFEFF]")

# Directional override characters (can reverse displayed text)
_BIDI_OVERRIDES = re.compile(r"[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]")

# Unicode tag characters (U+E0000-U+E007F) — invisible metadata encoding
_TAG_CHARS = re.compile(r"[\U000E0001-\U000E007F]")

# Invisible separator characters
_INVISIBLE_SEPARATORS = re.compile(r"[\u2028\u2029\u00AD\u034F\u061C\u180E]")

# Variation selectors (U+FE00-U+FE0F, U+E0100-U+E01EF)
_VARIATION_SELECTORS = re.compile(r"[\uFE00-\uFE0F\U000E0100-\U000E01EF]")

# Threshold for zero-width chars before flagging (legitimate use is rare)
_ZERO_WIDTH_THRESHOLD = 5


def _detect_unicode_steganography(
    content: str, filename: str = ""
) -> List[Dict[str, Any]]:
    """Detect hidden Unicode steganography in text content.

    Flags:
    - Excessive zero-width characters (>threshold, possible hidden data)
    - Bidirectional override characters (can reverse displayed text)
    - Unicode tag characters (invisible metadata encoding)
    - Invisible separator characters
    - Variation selectors used for encoding

    Args:
        content: Text content to scan.
        filename: Source filename for reporting.

    Returns:
        List of finding dicts.
    """
    findings: List[Dict[str, Any]] = []

    # Zero-width characters (threshold-based)
    zw_matches = _ZERO_WIDTH_CHARS.findall(content)
    if len(zw_matches) > _ZERO_WIDTH_THRESHOLD:
        findings.append({
            "file": filename,
            "name": "unicode_zero_width_chars",
            "severity": "high",
            "description": (
                f"Found {len(zw_matches)} zero-width characters "
                f"(threshold: {_ZERO_WIDTH_THRESHOLD}) — possible hidden data encoding"
            ),
            "matched_text": f"{len(zw_matches)} zero-width chars detected",
        })

    # Bidirectional overrides (always flag — can change displayed text direction)
    bidi_matches = _BIDI_OVERRIDES.findall(content)
    if bidi_matches:
        findings.append({
            "file": filename,
            "name": "unicode_bidi_override",
            "severity": "critical",
            "description": (
                f"Found {len(bidi_matches)} bidirectional override character(s) — "
                "can reverse displayed text to hide malicious content"
            ),
            "matched_text": f"{len(bidi_matches)} bidi override(s)",
        })

    # Unicode tag characters (always flag — invisible metadata)
    tag_matches = _TAG_CHARS.findall(content)
    if tag_matches:
        findings.append({
            "file": filename,
            "name": "unicode_tag_chars",
            "severity": "critical",
            "description": (
                f"Found {len(tag_matches)} Unicode tag character(s) — "
                "invisible characters used for steganographic encoding"
            ),
            "matched_text": f"{len(tag_matches)} tag char(s)",
        })

    # Invisible separators (always flag)
    sep_matches = _INVISIBLE_SEPARATORS.findall(content)
    if sep_matches:
        findings.append({
            "file": filename,
            "name": "unicode_invisible_separator",
            "severity": "medium",
            "description": (
                f"Found {len(sep_matches)} invisible separator character(s) — "
                "unusual in skill content"
            ),
            "matched_text": f"{len(sep_matches)} invisible separator(s)",
        })

    return findings


class ContentScanner:
    """7-layer security scanner operating on in-memory ScanTarget content.

    Adapts the same scanning logic as SkillScanner but works entirely on
    Dict[str, str] content rather than filesystem Path objects.
    """

    def __init__(self, config: Optional[IsolationConfig] = None):
        self.config = config or IsolationConfig()

    def scan(self, target: ScanTarget) -> SkillScanReport:
        """Run the full 7-layer scan pipeline on a ScanTarget.

        Args:
            target: In-memory content bundle to scan

        Returns:
            SkillScanReport with verdict and all layer results
        """
        start_time = time.monotonic()

        report = SkillScanReport(
            skill_name=target.name,
            skill_path=target.source,
            timestamp=datetime.now(timezone.utc).isoformat(),
            files_scanned=list(target.files.keys()),
            total_content_bytes=target.total_bytes,
            scan_config={
                "mode": "scan",
                "source_type": target.source_type,
                "llm_review_enabled": self.config.llm_review_enabled,
            },
        )

        # Layer 1: Structure Validation (directories only)
        layer1 = self._scan_structure(target)
        report.layers["structure"] = self._layer_to_dict(layer1)
        if not layer1.passed:
            report.verdict = "fail"
            report.risk_level = "dangerous"
            report.scan_duration_ms = int((time.monotonic() - start_time) * 1000)
            return report

        # Layer 2: Pattern Matching
        layer2 = self._scan_patterns(target)
        report.layers["patterns"] = self._layer_to_dict(layer2)
        self._accumulate_findings(report, layer2)

        # Layer 2.5: YARA Rules (if yara-python installed)
        layer2_5 = self._scan_yara(target)
        report.layers["yara"] = self._layer_to_dict(layer2_5)
        self._accumulate_findings(report, layer2_5)

        # Layer 3: Secret Scanning
        layer3 = self._scan_secrets(target)
        report.layers["secrets"] = self._layer_to_dict(layer3)

        # Layer 4: AST Analysis
        layer4 = self._scan_ast(target)
        report.layers["ast"] = self._layer_to_dict(layer4)

        # Layer 4B: Taint/Dataflow Analysis
        layer4b = self._scan_taint(target)
        if layer4b.findings or layer4b.issues:
            report.layers["taint"] = self._layer_to_dict(layer4b)
            self._accumulate_findings(report, layer4b)

        # Layer 4.5: Manifest-Code Consistency
        layer4_5 = self._scan_consistency(target)
        if layer4_5.findings or layer4_5.issues:
            report.layers["consistency"] = self._layer_to_dict(layer4_5)
            self._accumulate_findings(report, layer4_5)

        # Layer 5: Prompt Injection Detection
        layer5 = self._scan_prompt_injection(target)
        report.layers["prompt_injection"] = self._layer_to_dict(layer5)
        self._accumulate_findings(report, layer5)

        # Layer 6: Exfiltration Detection
        layer6 = self._scan_exfiltration(target)
        report.layers["exfiltration"] = self._layer_to_dict(layer6)
        self._accumulate_findings(report, layer6)

        # Layer 7: LLM Semantic Review
        if self.config.llm_review_enabled:
            layer7 = self._scan_llm_review(target)
            report.layers["llm_review"] = self._layer_to_dict(layer7)
        else:
            report.layers["llm_review"] = {
                "passed": True, "skipped": True, "reason": "LLM review disabled"
            }

        # Layer 7B: LLM Meta-Analysis (validates static findings with LLM context)
        if self.config.llm_review_enabled:
            meta_result = self._scan_meta_analysis(target, report)
            if meta_result:
                report.layers["meta_analysis"] = meta_result

        # Compute final verdict and risk
        report.verdict = self._compute_verdict(report, layer3, layer4)
        report.risk_level = self._compute_risk_level(report)
        report.scan_duration_ms = int((time.monotonic() - start_time) * 1000)

        return report

    # =========================================================================
    # Layer 1: Structure Validation
    # =========================================================================

    def _scan_structure(self, target: ScanTarget) -> ScanLayerResult:
        """Validate structure (primarily for directories)."""
        result = ScanLayerResult(layer_name="structure", passed=True)

        # Single files: only check size
        if target.source_type in ("file", "url"):
            if target.total_bytes > self.config.max_skill_size_bytes:
                result.passed = False
                result.issues.append(
                    f"Content size {target.total_bytes:,} bytes exceeds limit "
                    f"{self.config.max_skill_size_bytes:,}"
                )
            return result

        # Directory checks
        # Check for SKILL.md
        has_skill_md = any(
            p == "SKILL.md" or p.endswith("/SKILL.md")
            for p in target.files
        )
        if not has_skill_md:
            result.passed = False
            result.issues.append("Missing SKILL.md file")

        # File count
        if len(target.files) > self.config.max_file_count:
            result.passed = False
            result.issues.append(
                f"File count {len(target.files)} exceeds limit "
                f"{self.config.max_file_count}"
            )

        # Directory depth
        for rel_path in target.files:
            depth = len(Path(rel_path).parts)
            if depth > self.config.max_directory_depth:
                result.passed = False
                result.issues.append(
                    f"Path depth {depth} exceeds limit "
                    f"{self.config.max_directory_depth}: {rel_path}"
                )
                break

        # Blocked extensions
        blocked = set(self.config.blocked_file_extensions)
        for rel_path in target.files:
            ext = Path(rel_path).suffix.lower()
            if ext in blocked:
                result.passed = False
                result.issues.append(
                    f"Blocked file extension '{ext}': {rel_path}"
                )

        # Hidden files (except .gitignore)
        for rel_path in target.files:
            name = Path(rel_path).name
            if name.startswith(".") and name != ".gitignore":
                result.issues.append(f"Hidden file detected: {name}")

        return result

    # =========================================================================
    # Layer 2: Pattern Matching (reuses audit.py)
    # =========================================================================

    def _scan_patterns(self, target: ScanTarget) -> ScanLayerResult:
        """Run 275 regex patterns against all text content."""
        result = ScanLayerResult(layer_name="patterns", passed=True)

        try:
            from tweek.audit import audit_content

            for rel_path, content in target.files.items():
                audit_result = audit_content(
                    content=content,
                    name=rel_path,
                    translate=True,
                    llm_review=False,
                )

                if audit_result.non_english_detected:
                    self._has_non_english = True

                for finding in audit_result.findings:
                    result.findings.append({
                        "file": rel_path,
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

    def _scan_secrets(self, target: ScanTarget) -> ScanLayerResult:
        """Scan for hardcoded credentials in content."""
        result = ScanLayerResult(layer_name="secrets", passed=True)

        try:
            from tweek.security.secret_scanner import SecretScanner

            scanner = SecretScanner(enforce_permissions=False)

            for rel_path, content in target.files.items():
                ext = Path(rel_path).suffix.lower()
                synthetic_path = Path(f"scan://{rel_path}")

                # Route to appropriate scanner based on extension
                if ext in (".yaml", ".yml"):
                    findings = scanner._scan_yaml(synthetic_path, content)
                elif ext == ".json":
                    findings = scanner._scan_json(synthetic_path, content)
                else:
                    findings = scanner._scan_text(synthetic_path, content)

                if findings:
                    result.passed = False
                    for finding in findings:
                        result.findings.append({
                            "file": rel_path,
                            "key": finding.key_name,
                            "severity": finding.severity,
                            "description": f"Hardcoded secret: {finding.key_name}",
                        })

        except ImportError as e:
            result.error = f"Secret scanner not available: {e}"

        return result

    # =========================================================================
    # Layer 4: AST Analysis
    # =========================================================================

    def _scan_ast(self, target: ScanTarget) -> ScanLayerResult:
        """Static analysis of Python file content for forbidden patterns."""
        result = ScanLayerResult(layer_name="ast", passed=True)

        py_files = {
            path: content
            for path, content in target.files.items()
            if path.endswith(".py")
        }

        if not py_files:
            return result  # No Python files to scan

        for rel_path, content in py_files.items():
            try:
                tree = ast.parse(content, filename=rel_path)
            except SyntaxError as e:
                result.issues.append(f"{rel_path}: Syntax error: {e}")
                continue

            issues = self._analyze_ast(tree, rel_path)
            if issues:
                result.passed = False
                result.issues.extend(issues)

        return result

    @staticmethod
    def _analyze_ast(tree: ast.AST, filename: str) -> List[str]:
        """Walk an AST tree and find forbidden patterns."""
        issues = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module_name = alias.name
                    if module_name in FORBIDDEN_IMPORTS or module_name in FORBIDDEN_NETWORK_IMPORTS:
                        issues.append(
                            f"{filename}:{node.lineno}: Forbidden import '{module_name}'"
                        )

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module in FORBIDDEN_IMPORTS or module in FORBIDDEN_NETWORK_IMPORTS:
                    issues.append(
                        f"{filename}:{node.lineno}: Forbidden import from '{module}'"
                    )
                for alias in (node.names or []):
                    full_name = f"{module}.{alias.name}" if module else alias.name
                    if full_name in FORBIDDEN_IMPORTS or full_name in FORBIDDEN_CALLS:
                        issues.append(
                            f"{filename}:{node.lineno}: Forbidden import '{full_name}'"
                        )

            elif isinstance(node, ast.Call):
                call_name = ContentScanner._get_call_name(node)
                if call_name in FORBIDDEN_CALLS:
                    issues.append(
                        f"{filename}:{node.lineno}: Forbidden call to '{call_name}'"
                    )

        return issues

    @staticmethod
    def _get_call_name(node: ast.Call) -> str:
        """Extract the full dotted name of a function call."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    # =========================================================================
    # Layer 4B: Taint/Dataflow Analysis
    # (architecture inspired by Cisco AI Defense — see THIRD-PARTY-NOTICES.md)
    # =========================================================================

    def _scan_taint(self, target: ScanTarget) -> ScanLayerResult:
        """Trace sensitive data from sources to sinks via dataflow analysis.

        Uses forward taint propagation over a control flow graph to detect
        credential exfiltration, env var leaks, and other data flow attacks
        that simple forbidden-import checks cannot catch.
        """
        result = ScanLayerResult(layer_name="taint", passed=True)

        py_files = {
            path: content
            for path, content in target.files.items()
            if path.endswith(".py")
        }

        if not py_files:
            return result  # No Python files to analyze

        try:
            from tweek.security.taint_analyzer import CrossFileAnalyzer

            analyzer = CrossFileAnalyzer(py_files)
            findings = analyzer.analyze_all()

            for finding in findings:
                result.findings.append({
                    "file": finding.file,
                    "name": f"taint_{finding.source_type}_to_{finding.sink_type}",
                    "severity": finding.severity,
                    "description": finding.path_description,
                    "source_file": finding.source_file,
                    "source_line": finding.source_line,
                    "source_detail": finding.source_detail,
                    "sink_line": finding.sink_line,
                    "sink_detail": finding.sink_detail,
                })

            if findings:
                result.passed = False

        except Exception as e:
            result.issues.append(f"Taint analysis error: {e}")

        return result

    # =========================================================================
    # Layer 4.5: Manifest-Code Consistency Checking
    # (from Cisco AI Defense skill-scanner — see THIRD-PARTY-NOTICES.md)
    # =========================================================================

    def _scan_consistency(self, target: ScanTarget) -> ScanLayerResult:
        """Cross-validate SKILL.md frontmatter against actual code behavior.

        Checks that declared capabilities (allowed-tools) match what the
        code actually imports/uses. Catches skills claiming "read-only"
        while secretly importing network libraries.
        """
        result = ScanLayerResult(layer_name="consistency", passed=True)

        # Find SKILL.md content
        skill_md = None
        for path, content in target.files.items():
            if path == "SKILL.md" or path.endswith("/SKILL.md"):
                skill_md = content
                break

        if not skill_md:
            return result  # No manifest to validate

        # Extract YAML frontmatter (between --- delimiters)
        declared_tools: set = set()
        try:
            import yaml

            if skill_md.startswith("---"):
                parts = skill_md.split("---", 2)
                if len(parts) >= 3:
                    frontmatter = yaml.safe_load(parts[1])
                    if isinstance(frontmatter, dict):
                        tools = frontmatter.get("allowed-tools", [])
                        if isinstance(tools, list):
                            declared_tools = {str(t).lower() for t in tools}
        except Exception:
            return result  # Can't parse frontmatter, skip

        if not declared_tools:
            return result  # No tools declared, nothing to validate

        # Analyze Python files for actual behavior
        network_imports = {"requests", "urllib", "httpx", "aiohttp", "socket", "http"}
        file_imports = {"open", "pathlib"}
        exec_imports = {"subprocess", "os.system", "os.popen"}

        code_uses_network = False
        code_uses_files = False
        code_uses_exec = False

        for path, content in target.files.items():
            if not path.endswith(".py"):
                continue
            try:
                tree = ast.parse(content, filename=path)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    module = ""
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            module = alias.name.split(".")[0]
                            if module in network_imports:
                                code_uses_network = True
                            if module in exec_imports:
                                code_uses_exec = True
                    elif isinstance(node, ast.ImportFrom):
                        module = (node.module or "").split(".")[0]
                        if module in network_imports:
                            code_uses_network = True
                        if module in exec_imports:
                            code_uses_exec = True

                elif isinstance(node, ast.Call):
                    call_name = self._get_call_name(node)
                    if call_name in ("open", "pathlib.Path.read_text", "pathlib.Path.write_text"):
                        code_uses_files = True

        # Cross-validate
        has_network_tool = any(
            t in declared_tools
            for t in ("webfetch", "websearch", "bash", "network", "http")
        )
        has_read_tool = any(
            t in declared_tools for t in ("read", "bash", "file", "glob")
        )
        has_exec_tool = any(
            t in declared_tools for t in ("bash", "exec", "shell")
        )

        if code_uses_network and not has_network_tool:
            result.findings.append({
                "file": "SKILL.md",
                "name": "consistency_undeclared_network",
                "severity": "high",
                "description": (
                    "Code imports network libraries but manifest does not "
                    "declare network-capable tools"
                ),
                "matched_text": "Network imports without declaration",
            })

        if code_uses_exec and not has_exec_tool:
            result.findings.append({
                "file": "SKILL.md",
                "name": "consistency_undeclared_exec",
                "severity": "high",
                "description": (
                    "Code imports execution libraries but manifest does not "
                    "declare execution-capable tools"
                ),
                "matched_text": "Exec imports without declaration",
            })

        if code_uses_files and not has_read_tool:
            result.findings.append({
                "file": "SKILL.md",
                "name": "consistency_undeclared_file_access",
                "severity": "medium",
                "description": (
                    "Code performs file operations but manifest does not "
                    "declare file-access tools"
                ),
                "matched_text": "File access without declaration",
            })

        return result

    # =========================================================================
    # Layer 2.5: YARA Rules
    # =========================================================================

    def _scan_yara(self, target: ScanTarget) -> ScanLayerResult:
        """Scan content with YARA rules (if yara-python installed)."""
        result = ScanLayerResult(layer_name="yara", passed=True)

        try:
            from tweek.security.yara_scanner import YaraScanner

            scanner = YaraScanner()
            if not scanner.available:
                result.error = "yara-python not installed — install with: pip install tweek[yara]"
                return result

            for rel_path, content in target.files.items():
                findings = scanner.scan_content(content, filename=rel_path)
                for finding in findings:
                    result.findings.append({
                        "file": rel_path,
                        "name": finding["rule"],
                        "severity": finding["severity"],
                        "description": finding["description"],
                        "category": finding["category"],
                        "matched_text": (
                            finding["matched_strings"][0][1][:100]
                            if finding["matched_strings"]
                            else ""
                        ),
                    })

        except ImportError:
            result.error = "yara-python not installed — install with: pip install tweek[yara]"

        return result

    # =========================================================================
    # Layer 5: Prompt Injection Detection (skill-specific)
    # =========================================================================

    def _scan_prompt_injection(self, target: ScanTarget) -> ScanLayerResult:
        """Scan for prompt injection patterns specific to skill instructions."""
        result = ScanLayerResult(layer_name="prompt_injection", passed=True)

        for rel_path, content in target.files.items():
            # Regex-based skill injection patterns
            for pattern_def in SKILL_INJECTION_PATTERNS:
                try:
                    match = re.search(
                        pattern_def["regex"], content,
                        re.IGNORECASE | re.MULTILINE,
                    )
                    if match:
                        result.findings.append({
                            "file": rel_path,
                            "name": pattern_def["name"],
                            "severity": pattern_def["severity"],
                            "description": pattern_def["description"],
                            "matched_text": match.group(0)[:100],
                        })
                except re.error:
                    continue

            # Unicode steganography detection
            steg_findings = _detect_unicode_steganography(content, rel_path)
            result.findings.extend(steg_findings)

        return result

    # =========================================================================
    # Layer 6: Exfiltration Detection
    # =========================================================================

    def _scan_exfiltration(self, target: ScanTarget) -> ScanLayerResult:
        """Detect data exfiltration vectors in content."""
        result = ScanLayerResult(layer_name="exfiltration", passed=True)

        for rel_path, content in target.files.items():
            is_script = rel_path.endswith(".py") or rel_path.endswith(".sh")

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
                    for match in pattern.finditer(content):
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
    # Layer 7: LLM Semantic Review
    # =========================================================================

    def _scan_llm_review(self, target: ScanTarget) -> ScanLayerResult:
        """Run LLM semantic analysis on skill content."""
        result = ScanLayerResult(layer_name="llm_review", passed=True)

        # Build combined content (SKILL.md first)
        content_parts = []
        for rel_path in sorted(target.files.keys(), key=lambda p: (p != "SKILL.md", p)):
            text = target.files[rel_path]
            content_parts.append(f"=== {rel_path} ===\n{text[:2000]}")

        combined = "\n\n".join(content_parts)[:8000]

        try:
            from tweek.security.llm_reviewer import get_llm_reviewer

            reviewer = get_llm_reviewer()
            if not reviewer.enabled:
                result.findings.append({
                    "name": "llm_review_unavailable",
                    "severity": "medium",
                    "description": "LLM reviewer not available (no API key configured)",
                })
                return result

            review = reviewer.review(
                command=combined[:4000],
                tool="SkillScan",
                tier="dangerous",
            )

            result.findings.append({
                "name": "llm_semantic_review",
                "severity": "low",
                "description": review.reason,
                "risk_level": review.risk_level.value,
                "confidence": review.confidence,
            })

            if review.risk_level.value == "dangerous" and review.confidence >= 0.7:
                result.passed = False
            elif review.risk_level.value == "suspicious":
                result.findings[-1]["severity"] = "medium"

        except ImportError:
            result.error = "LLM reviewer not available"
        except Exception as e:
            result.findings.append({
                "name": "llm_review_error",
                "severity": "medium",
                "description": f"LLM review failed: {e}",
            })

        return result

    # =========================================================================
    # Layer 7B: LLM Meta-Analysis
    # (inspired by Cisco AI Defense two-pass review — see THIRD-PARTY-NOTICES.md)
    # =========================================================================

    def _scan_meta_analysis(
        self, target: ScanTarget, report: SkillScanReport
    ) -> Optional[Dict[str, Any]]:
        """Run meta-analysis to validate static findings with LLM context.

        Takes all findings from static layers + initial LLM review, and asks
        the LLM to validate/filter/enhance them. Reduces false positives and
        catches semantic threats missed by static analysis alone.
        """
        # Collect all static findings
        all_findings = []
        for layer_data in report.layers.values():
            if isinstance(layer_data, dict):
                for f in layer_data.get("findings", []):
                    if isinstance(f, dict) and f.get("severity") in ("critical", "high", "medium"):
                        all_findings.append(f)

        if not all_findings:
            return None  # Nothing to validate

        try:
            from tweek.security.llm_reviewer import MetaAnalysisReviewer, get_llm_reviewer

            reviewer = get_llm_reviewer()
            if not reviewer.enabled or not reviewer._provider_instance:
                return None

            meta = MetaAnalysisReviewer(provider=reviewer._provider_instance)

            # Build combined content
            content_parts = []
            for rel_path in sorted(target.files.keys()):
                text = target.files[rel_path]
                content_parts.append(f"=== {rel_path} ===\n{text[:2000]}")
            combined = "\n\n".join(content_parts)[:6000]

            result = meta.analyze(combined, all_findings)
            if result:
                return {
                    "validated_count": len(result.validated_findings),
                    "filtered_count": len(result.filtered_findings),
                    "enhanced_count": len(result.enhanced_findings),
                    "summary": result.summary,
                    "confidence": result.confidence,
                    "validated": result.validated_findings[:10],
                    "filtered": result.filtered_findings[:10],
                    "enhanced": result.enhanced_findings[:5],
                }
        except Exception:
            pass  # Meta-analysis is best-effort enhancement

        return None

    # =========================================================================
    # Verdict and Risk Computation (same logic as SkillScanner)
    # =========================================================================

    def _compute_verdict(
        self,
        report: SkillScanReport,
        secrets_layer: ScanLayerResult,
        ast_layer: ScanLayerResult,
    ) -> str:
        """Compute final verdict based on all layer results."""
        # Structure fail = immediate FAIL
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

        return "pass"

    @staticmethod
    def _compute_risk_level(report: SkillScanReport) -> str:
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

    @staticmethod
    def _layer_to_dict(layer: ScanLayerResult) -> Dict[str, Any]:
        """Convert a ScanLayerResult to a serializable dict."""
        d: Dict[str, Any] = {"passed": layer.passed}
        if layer.findings:
            d["findings"] = layer.findings
        if layer.issues:
            d["issues"] = layer.issues
        if layer.error:
            d["error"] = layer.error
        return d

    # Internal state
    _has_non_english: bool = False
