#!/usr/bin/env python3
"""
Tweek Secret Scanner

Scans configuration files for hardcoded secrets and credentials.
Enforces environment-variable-only secrets policy.

Based on moltbot's secret-guard security hardening initiative.
"""

import os
import re
import stat
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
import json
import yaml


class SecretType(Enum):
    """Types of secrets that can be detected."""
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    PRIVATE_KEY = "private_key"
    CONNECTION_STRING = "connection_string"
    AWS_CREDENTIAL = "aws_credential"
    OAUTH_SECRET = "oauth_secret"
    WEBHOOK_SECRET = "webhook_secret"
    ENCRYPTION_KEY = "encryption_key"
    CERTIFICATE = "certificate"


@dataclass
class SecretFinding:
    """A detected secret in a configuration file."""
    file_path: Path
    secret_type: SecretType
    key_name: str
    line_number: Optional[int] = None
    context: Optional[str] = None  # Redacted preview
    severity: str = "high"
    recommendation: str = ""

    def __post_init__(self):
        if not self.recommendation:
            env_var = self._suggest_env_var()
            self.recommendation = f"Move to environment variable: {env_var}"

    def _suggest_env_var(self) -> str:
        """Suggest an environment variable name."""
        # Convert key name to UPPER_SNAKE_CASE
        name = re.sub(r'[^a-zA-Z0-9]', '_', self.key_name)
        name = re.sub(r'_+', '_', name).strip('_').upper()
        return f"TWEEK_{name}"


@dataclass
class ScanResult:
    """Result of scanning for secrets."""
    findings: List[SecretFinding] = field(default_factory=list)
    files_scanned: int = 0
    files_with_secrets: int = 0
    permissions_fixed: List[Path] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return len(self.findings) == 0

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "critical" for f in self.findings)


class SecretScanner:
    """
    Scanner for detecting hardcoded secrets in configuration files.

    Checks for:
    - API keys and tokens
    - Passwords and secrets
    - Private keys and certificates
    - Connection strings
    - AWS/cloud credentials
    """

    # Patterns for detecting secrets (key patterns)
    SECRET_KEY_PATTERNS = [
        # API Keys
        (r'(?i)(api[_-]?key|apikey)', SecretType.API_KEY),
        (r'(?i)(secret[_-]?key|secretkey)', SecretType.API_KEY),
        (r'(?i)(access[_-]?key|accesskey)', SecretType.API_KEY),

        # Passwords
        (r'(?i)(password|passwd|pwd)', SecretType.PASSWORD),
        (r'(?i)(secret)', SecretType.PASSWORD),

        # Tokens
        (r'(?i)(token|auth[_-]?token|bearer)', SecretType.TOKEN),
        (r'(?i)(jwt|refresh[_-]?token)', SecretType.TOKEN),

        # Private Keys
        (r'(?i)(private[_-]?key|priv[_-]?key)', SecretType.PRIVATE_KEY),
        (r'(?i)(ssh[_-]?key|rsa[_-]?key)', SecretType.PRIVATE_KEY),

        # Connection Strings
        (r'(?i)(connection[_-]?string|conn[_-]?str)', SecretType.CONNECTION_STRING),
        (r'(?i)(database[_-]?url|db[_-]?url)', SecretType.CONNECTION_STRING),
        (r'(?i)(mongodb|postgres|mysql|redis).*url', SecretType.CONNECTION_STRING),

        # AWS
        (r'(?i)(aws[_-]?secret)', SecretType.AWS_CREDENTIAL),
        (r'(?i)(aws[_-]?access[_-]?key[_-]?id)', SecretType.AWS_CREDENTIAL),

        # OAuth
        (r'(?i)(client[_-]?secret|oauth[_-]?secret)', SecretType.OAUTH_SECRET),
        (r'(?i)(app[_-]?secret)', SecretType.OAUTH_SECRET),

        # Webhooks
        (r'(?i)(webhook[_-]?secret|signing[_-]?secret)', SecretType.WEBHOOK_SECRET),

        # Encryption
        (r'(?i)(encryption[_-]?key|encrypt[_-]?key)', SecretType.ENCRYPTION_KEY),
        (r'(?i)(aes[_-]?key|cipher[_-]?key)', SecretType.ENCRYPTION_KEY),
    ]

    # Patterns for detecting secret values (value patterns)
    SECRET_VALUE_PATTERNS = [
        # AWS Access Key ID (starts with AKIA, ABIA, ACCA, ASIA)
        (r'(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}', SecretType.AWS_CREDENTIAL, "critical"),

        # AWS Secret Access Key (40 char base64-ish)
        (r'(?i)aws.*[\'"][A-Za-z0-9/+=]{40}[\'"]', SecretType.AWS_CREDENTIAL, "critical"),

        # Private key markers
        (r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', SecretType.PRIVATE_KEY, "critical"),

        # JWT tokens
        (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', SecretType.TOKEN, "high"),

        # GitHub tokens
        (r'gh[pousr]_[A-Za-z0-9_]{36,}', SecretType.TOKEN, "critical"),

        # Generic API key patterns (long alphanumeric strings)
        (r'(?i)(?:api[_-]?key|token|secret)[\'"\s:=]+[\'"]?[A-Za-z0-9_-]{32,}[\'"]?', SecretType.API_KEY, "high"),

        # Slack tokens
        (r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*', SecretType.TOKEN, "critical"),

        # Stripe keys (live and test)
        (r'sk_live_[A-Za-z0-9]{24,}', SecretType.API_KEY, "critical"),
        (r'pk_live_[A-Za-z0-9]{24,}', SecretType.API_KEY, "high"),
        (r'rk_live_[A-Za-z0-9]{24,}', SecretType.API_KEY, "critical"),

        # SendGrid API key
        (r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}', SecretType.API_KEY, "critical"),

        # Anthropic API key
        (r'sk-ant-[A-Za-z0-9_-]{36,}', SecretType.API_KEY, "critical"),

        # OpenAI API key
        (r'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}', SecretType.API_KEY, "critical"),

        # npm token
        (r'npm_[A-Za-z0-9]{36,}', SecretType.TOKEN, "critical"),

        # PyPI token
        (r'pypi-[A-Za-z0-9_-]{50,}', SecretType.TOKEN, "critical"),

        # Azure subscription key / connection string
        (r'(?i)DefaultEndpointProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{60,}', SecretType.CONNECTION_STRING, "critical"),

        # Google API key
        (r'AIza[A-Za-z0-9_-]{35}', SecretType.API_KEY, "high"),

        # Google OAuth client secret
        (r'GOCSPX-[A-Za-z0-9_-]{28}', SecretType.OAUTH_SECRET, "critical"),

        # Twilio API key
        (r'SK[a-f0-9]{32}', SecretType.API_KEY, "high"),

        # Mailchimp API key
        (r'[a-f0-9]{32}-us[0-9]{1,2}', SecretType.API_KEY, "high"),

        # Discord bot token
        (r'[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}', SecretType.TOKEN, "critical"),

        # Heroku API key
        (r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', SecretType.API_KEY, "medium"),

        # Generic high-entropy strings that look like secrets
        (r'[\'"][A-Za-z0-9+/]{40,}={0,2}[\'"]', SecretType.API_KEY, "medium"),
    ]

    # Files that should have restricted permissions (chmod 600)
    SENSITIVE_FILES = [
        "oauth.json",
        "auth-profiles.json",
        "credentials.json",
        "secrets.yaml",
        "secrets.json",
        ".env",
        "license.key",
    ]

    # Environment variable reference patterns (these are OK)
    ENV_VAR_PATTERNS = [
        r'\$\{[A-Z_][A-Z0-9_]*\}',     # ${VAR_NAME}
        r'\$[A-Z_][A-Z0-9_]*',          # $VAR_NAME
        r'env\([\'"]?[A-Z_][A-Z0-9_]*[\'"]?\)',  # env("VAR")
        r'os\.environ\[[\'"][A-Z_][A-Z0-9_]*[\'"]\]',  # os.environ["VAR"]
        r'process\.env\.[A-Z_][A-Z0-9_]*',  # process.env.VAR
    ]

    def __init__(self, enforce_permissions: bool = True):
        """
        Initialize the secret scanner.

        Args:
            enforce_permissions: If True, fix permissions on sensitive files
        """
        self.enforce_permissions = enforce_permissions

    def scan_file(self, file_path: Path) -> List[SecretFinding]:
        """
        Scan a single file for hardcoded secrets.

        Args:
            file_path: Path to the file to scan

        Returns:
            List of secret findings
        """
        findings = []

        if not file_path.exists():
            return findings

        try:
            content = file_path.read_text()
        except Exception:
            return findings

        # Determine file type
        suffix = file_path.suffix.lower()

        if suffix in ('.yaml', '.yml'):
            findings.extend(self._scan_yaml(file_path, content))
        elif suffix == '.json':
            findings.extend(self._scan_json(file_path, content))
        else:
            # Generic text scan
            findings.extend(self._scan_text(file_path, content))

        return findings

    def _scan_yaml(self, file_path: Path, content: str) -> List[SecretFinding]:
        """Scan YAML content for secrets."""
        findings = []

        try:
            data = yaml.safe_load(content)
            if data:
                findings.extend(self._scan_dict(file_path, data, []))
        except yaml.YAMLError:
            pass

        # Also do text-based scanning for value patterns
        findings.extend(self._scan_value_patterns(file_path, content))

        return findings

    def _scan_json(self, file_path: Path, content: str) -> List[SecretFinding]:
        """Scan JSON content for secrets."""
        findings = []

        try:
            data = json.loads(content)
            if isinstance(data, dict):
                findings.extend(self._scan_dict(file_path, data, []))
        except json.JSONDecodeError:
            pass

        # Also do text-based scanning for value patterns
        findings.extend(self._scan_value_patterns(file_path, content))

        return findings

    def _scan_text(self, file_path: Path, content: str) -> List[SecretFinding]:
        """Scan plain text content for secrets."""
        return self._scan_value_patterns(file_path, content)

    def _scan_dict(
        self,
        file_path: Path,
        data: Dict[str, Any],
        path: List[str]
    ) -> List[SecretFinding]:
        """Recursively scan a dictionary for secret keys."""
        findings = []

        for key, value in data.items():
            current_path = path + [key]
            key_path = ".".join(current_path)

            # Check if key matches secret patterns
            for pattern, secret_type in self.SECRET_KEY_PATTERNS:
                if re.search(pattern, key):
                    # Check if value looks like an actual secret (not env var ref)
                    if self._is_hardcoded_secret(value):
                        findings.append(SecretFinding(
                            file_path=file_path,
                            secret_type=secret_type,
                            key_name=key_path,
                            context=self._redact_value(value),
                            severity="high",
                        ))
                    break

            # Recurse into nested dicts
            if isinstance(value, dict):
                findings.extend(self._scan_dict(file_path, value, current_path))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        findings.extend(
                            self._scan_dict(file_path, item, current_path + [f"[{i}]"])
                        )

        return findings

    def _scan_value_patterns(self, file_path: Path, content: str) -> List[SecretFinding]:
        """Scan content for secret value patterns."""
        findings = []
        lines = content.split('\n')

        for pattern, secret_type, severity in self.SECRET_VALUE_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    # Check it's not an env var reference
                    if not self._is_env_var_reference(line):
                        findings.append(SecretFinding(
                            file_path=file_path,
                            secret_type=secret_type,
                            key_name=f"line_{line_num}",
                            line_number=line_num,
                            context=self._redact_line(line),
                            severity=severity,
                        ))

        return findings

    def _is_hardcoded_secret(self, value: Any) -> bool:
        """Check if a value appears to be a hardcoded secret."""
        if value is None:
            return False

        if not isinstance(value, str):
            return False

        # Empty or very short values are not secrets
        if len(value) < 8:
            return False

        # Check if it's an environment variable reference
        if self._is_env_var_reference(value):
            return False

        # Check for obvious placeholder values
        placeholders = [
            'your_', 'xxx', 'changeme', 'placeholder', 'example',
            '<', '>', 'TODO', 'FIXME', 'INSERT', 'REPLACE'
        ]
        value_lower = value.lower()
        if any(p in value_lower for p in placeholders):
            return False

        return True

    def _is_env_var_reference(self, value: str) -> bool:
        """Check if value is an environment variable reference."""
        for pattern in self.ENV_VAR_PATTERNS:
            if re.search(pattern, value):
                return True
        return False

    def _redact_value(self, value: Any) -> str:
        """Redact a secret value for safe display.

        Only shows first 4 characters (provider prefix) — never reveals suffix
        to minimize information leakage.
        """
        if not isinstance(value, str):
            return "<redacted>"

        if len(value) <= 8:
            return "*" * len(value)

        # Show first 4 chars only (identifies provider without revealing key material)
        return f"{value[:4]}{'*' * (len(value) - 4)}"

    def _redact_line(self, line: str) -> str:
        """Redact sensitive parts of a line."""
        # Redact anything that looks like a secret value
        redacted = re.sub(
            r'([\'"])[A-Za-z0-9+/=_-]{16,}([\'"])',
            r'\1***REDACTED***\2',
            line
        )
        return redacted[:100] + "..." if len(redacted) > 100 else redacted

    def fix_permissions(self, file_path: Path) -> bool:
        """
        Fix permissions on a sensitive file to 600 (owner read/write only).

        Args:
            file_path: Path to the file

        Returns:
            True if permissions were changed
        """
        if not file_path.exists():
            return False

        try:
            current_mode = file_path.stat().st_mode
            desired_mode = stat.S_IRUSR | stat.S_IWUSR  # 600

            if (current_mode & 0o777) != desired_mode:
                file_path.chmod(desired_mode)
                return True
        except OSError:
            pass

        return False

    def scan_directory(
        self,
        directory: Path,
        patterns: Optional[List[str]] = None
    ) -> ScanResult:
        """
        Scan a directory for configuration files with secrets.

        Args:
            directory: Directory to scan
            patterns: Glob patterns for files to scan (default: *.yaml, *.yml, *.json)

        Returns:
            ScanResult with all findings
        """
        result = ScanResult()

        if patterns is None:
            patterns = ["**/*.yaml", "**/*.yml", "**/*.json", "**/.env*"]

        files_to_scan = set()
        for pattern in patterns:
            files_to_scan.update(directory.glob(pattern))

        for file_path in files_to_scan:
            if file_path.is_file():
                result.files_scanned += 1

                findings = self.scan_file(file_path)
                if findings:
                    result.files_with_secrets += 1
                    result.findings.extend(findings)

                # Check and fix permissions on sensitive files
                if self.enforce_permissions:
                    if file_path.name in self.SENSITIVE_FILES:
                        if self.fix_permissions(file_path):
                            result.permissions_fixed.append(file_path)

        return result

    def scan_tweek_config(self) -> ScanResult:
        """
        Scan Tweek's configuration directory for secrets.

        Returns:
            ScanResult with all findings
        """
        tweek_dir = Path.home() / ".tweek"

        if not tweek_dir.exists():
            return ScanResult()

        return self.scan_directory(tweek_dir)


def scan_for_secrets(path: Optional[Path] = None) -> ScanResult:
    """
    Convenience function to scan for secrets.

    Args:
        path: Path to scan (default: ~/.tweek)

    Returns:
        ScanResult with findings
    """
    scanner = SecretScanner()

    if path is None:
        return scanner.scan_tweek_config()
    elif path.is_file():
        findings = scanner.scan_file(path)
        return ScanResult(
            findings=findings,
            files_scanned=1,
            files_with_secrets=1 if findings else 0
        )
    else:
        return scanner.scan_directory(path)


def enforce_env_only_secrets(
    config_path: Optional[Path] = None,
    raise_on_secrets: bool = True
) -> Tuple[bool, ScanResult]:
    """
    Enforce that secrets come from environment variables only.

    Args:
        config_path: Path to scan (default: ~/.tweek)
        raise_on_secrets: If True, raise exception when secrets found

    Returns:
        (is_clean, result) tuple

    Raises:
        ValueError: If secrets are found and raise_on_secrets is True
    """
    result = scan_for_secrets(config_path)

    if not result.is_clean and raise_on_secrets:
        secret_list = "\n".join(
            f"  - {f.file_path}:{f.line_number or '?'} ({f.secret_type.value})"
            for f in result.findings[:10]
        )
        raise ValueError(
            f"Hardcoded secrets detected in configuration files:\n{secret_list}\n\n"
            f"Secrets must come from environment variables. "
            f"See recommendations in scan results."
        )

    return result.is_clean, result
