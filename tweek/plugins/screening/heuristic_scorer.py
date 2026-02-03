"""
Tweek Heuristic Scorer Screening Plugin

Lightweight signal-based scoring for confidence-gated LLM escalation.
Runs between Layer 2 (regex) and Layer 3 (LLM) to detect novel attack
variants that don't match any of the 262 regex patterns but exhibit
suspicious characteristics.

Scoring signals (all local, no network, no LLM):
- Sensitive path tokens (from pattern family definitions)
- Exfiltration verbs
- Encoding/obfuscation tools
- Shell expansion/eval constructs
- Pipe chain complexity
- Combination bonuses (multiplicative)
- Known-benign dampening

FREE feature - available to all users.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any, List, Set, Tuple
import re
import yaml

from tweek.plugins.base import (
    ScreeningPlugin,
    ScreeningResult,
    Finding,
    Severity,
    ActionType,
)


@dataclass
class HeuristicScore:
    """Result of heuristic scoring."""

    total_score: float
    signals: List[Dict[str, Any]]
    family_scores: Dict[str, float]
    threshold: float = 0.4
    dampened: bool = False
    dampening_reason: Optional[str] = None

    @property
    def should_escalate(self) -> bool:
        return self.total_score >= self.threshold


# Pre-compiled benign command patterns
_BENIGN_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"^git\s+(commit|push|pull|fetch|clone|checkout|branch|merge|log|diff|status|add|stash|rebase|tag|remote|init)\b",
        r"^npm\s+(install|test|run|build|start|ci|audit|outdated|ls|init)\b",
        r"^yarn\s+(install|add|remove|build|test|start|dev)\b",
        r"^pip3?\s+(install|list|show|freeze|check)\b",
        r"^python[23]?\s+(-m\s+)?(pytest|unittest|pip|venv|http\.server|json\.tool)\b",
        r"^(ls|pwd|cd|echo|mkdir|touch|date|which|type|man|help)\b",
        r"^cargo\s+(build|test|run|check|fmt|clippy|doc|bench)\b",
        r"^make(\s+|$)",
        r"^docker\s+(build|run|compose|ps|images|logs|stop|start)\b",
        r"^go\s+(build|test|run|mod|fmt|vet|generate)\b",
        r"^rustc\b",
        r"^gcc\b|^g\+\+\b|^clang\b",
        r"^cat\s+\S+\.(py|js|ts|rs|go|java|c|cpp|h|rb|sh|md|txt|json|yaml|yml|toml|cfg|ini|html|css|xml|sql)\b",
        r"^(ruff|black|prettier|eslint|flake8|mypy|pylint)\b",
    ]
]

# Command chaining operators -- presence means a "benign" prefix does not
# guarantee the entire command is benign (Finding F7 fix).
_CHAIN_OPERATORS_RE = re.compile(r"\s*(?:&&|\|\||;)\s*")

# Shell expansion patterns
_SHELL_EXPANSION_RE = re.compile(r"\$\(|\$\{|`[^`]+`|\beval\s|\bexec\s|\bsource\s")

# Redirect to external patterns
_REDIRECT_EXTERNAL_RE = re.compile(r"/dev/tcp/|/dev/udp/|>\s*&\d|>\(\s*(curl|wget|nc|ncat)\b")

# Env var with secret name
_SECRET_ENV_RE = re.compile(
    r"\$\{?(API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE_KEY|AUTH|"
    r"AWS_SECRET|GITHUB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|"
    r"DATABASE_URL|DB_PASSWORD|STRIPE_KEY|SENDGRID|TWILIO)[A-Z_]*\}?",
    re.IGNORECASE,
)


class HeuristicScorerPlugin(ScreeningPlugin):
    """
    Heuristic scorer screening plugin.

    Uses cheap local signals to score commands for suspicious
    characteristics. When the score exceeds a threshold, recommends
    LLM escalation regardless of the tool's base tier.

    FREE feature - available to all users.
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Lightweight heuristic scoring for confidence-gated LLM escalation"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["screening", "heuristic", "escalation"]

    # --- Signal weights ---
    WEIGHT_SENSITIVE_PATH = 0.25
    WEIGHT_EXFIL_VERB = 0.20
    WEIGHT_ENCODING_TOOL = 0.10
    WEIGHT_SHELL_EXPANSION = 0.15
    WEIGHT_PIPE_COMPLEXITY = 0.05  # per pipe beyond first
    WEIGHT_REDIRECT_EXTERNAL = 0.20
    WEIGHT_SECRET_ENV_VAR = 0.15
    WEIGHT_EXFIL_TARGET = 0.30

    # Combination bonuses (multiplicative)
    COMBO_EXFIL_PLUS_SENSITIVE = 1.5
    COMBO_ENCODING_PLUS_EXFIL = 1.3
    COMBO_EXPANSION_PLUS_EXFIL = 1.4

    # Known-benign dampening factor
    BENIGN_DAMPENING = 0.8  # score *= (1 - 0.8) = 0.2

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._families: Optional[Dict] = None
        self._sensitive_paths: Optional[Set[str]] = None
        self._exfil_verbs: Optional[Set[str]] = None
        self._exfil_targets: Optional[Set[str]] = None
        self._encoding_tools: Optional[Set[str]] = None
        self._threshold: float = self._config.get("threshold", 0.4)
        self._enabled: bool = self._config.get("enabled", True)
        self._log_all: bool = self._config.get("log_all_scores", False)

    @property
    def name(self) -> str:
        return "heuristic_scorer"

    def _load_families(self) -> Dict:
        """Load family definitions from YAML and build signal indices."""
        if self._families is not None:
            return self._families

        # Try config path, then user path, then bundled
        bundled = Path(__file__).parent.parent.parent / "config" / "families.yaml"
        user_path = Path.home() / ".tweek" / "patterns" / "families.yaml"

        path = None
        if self._config.get("families_path"):
            path = Path(self._config["families_path"])
        elif user_path.exists():
            path = user_path
        elif bundled.exists():
            path = bundled

        if path and path.exists():
            try:
                with open(path) as f:
                    data = yaml.safe_load(f) or {}
                    self._families = data.get("families", {})
            except (yaml.YAMLError, OSError):
                self._families = {}
        else:
            self._families = {}

        self._build_signal_indices()
        return self._families

    def _build_signal_indices(self):
        """Build lookup sets from all family heuristic_signals."""
        self._sensitive_paths = set()
        self._exfil_verbs = set()
        self._exfil_targets = set()
        self._encoding_tools = set()

        for family_def in (self._families or {}).values():
            signals = family_def.get("heuristic_signals", {})

            # Sensitive paths from credential_theft, persistence, etc.
            for key in ("sensitive_paths", "persistence_paths", "priv_paths"):
                for token in signals.get(key, []):
                    self._sensitive_paths.add(token.lower())

            # Exfil verbs
            for token in signals.get("exfil_verbs", []):
                self._exfil_verbs.add(token.lower())

            # Exfil targets
            for token in signals.get("exfil_targets", []):
                self._exfil_targets.add(token.lower())

            # Encoding tools
            for token in signals.get("encoding_tools", []):
                self._encoding_tools.add(token.lower())

        # Add some baseline signals if families didn't provide any
        if not self._sensitive_paths:
            self._sensitive_paths = {
                ".ssh", ".aws", ".env", ".gnupg", ".kube", ".netrc",
                "id_rsa", "id_ed25519", "credentials", "keychain",
            }
        if not self._exfil_verbs:
            self._exfil_verbs = {
                "curl", "wget", "nc", "ncat", "netcat", "socat",
                "scp", "rsync", "ftp",
            }
        if not self._encoding_tools:
            self._encoding_tools = {"base64", "xxd", "openssl", "gzip"}

    def _tokenize(self, content: str) -> List[str]:
        """Split content into tokens for signal matching."""
        # Split on whitespace, pipes, semicolons, ampersands, parentheses
        return re.split(r"[\s|;&()]+", content.lower())

    def _is_benign(self, content: str) -> Optional[str]:
        """Check if content matches a known-benign pattern.

        Returns None (not benign) if command chaining operators are detected,
        since a benign prefix (e.g. 'git commit') does not make the entire
        chained command benign (e.g. 'git commit && curl evil.com').
        """
        stripped = content.strip()
        if _CHAIN_OPERATORS_RE.search(stripped):
            return None
        for pattern in _BENIGN_PATTERNS:
            if pattern.match(stripped):
                return pattern.pattern
        return None

    def _score_content(self, content: str) -> HeuristicScore:
        """Score content against heuristic signals."""
        self._load_families()

        content_lower = content.lower()
        tokens = self._tokenize(content)
        token_set = set(tokens)

        signals: List[Dict[str, Any]] = []
        family_scores: Dict[str, float] = {}
        score = 0.0

        # Track which signal categories fired (for combination bonuses)
        has_sensitive_path = False
        has_exfil_verb = False
        has_encoding_tool = False
        has_shell_expansion = False

        # 1. Sensitive path scan
        matched_paths = set()
        for path_token in self._sensitive_paths:
            if path_token in content_lower and path_token not in matched_paths:
                matched_paths.add(path_token)
                has_sensitive_path = True
        if matched_paths:
            score += self.WEIGHT_SENSITIVE_PATH
            signals.append({
                "name": "sensitive_path",
                "weight": self.WEIGHT_SENSITIVE_PATH,
                "matched": list(matched_paths)[:5],
            })

        # 2. Exfiltration verb scan
        matched_verbs = token_set & self._exfil_verbs
        if matched_verbs:
            score += self.WEIGHT_EXFIL_VERB
            has_exfil_verb = True
            signals.append({
                "name": "exfil_verb",
                "weight": self.WEIGHT_EXFIL_VERB,
                "matched": list(matched_verbs)[:5],
            })

        # 3. Exfil target scan
        matched_targets = set()
        for target in self._exfil_targets:
            if target in content_lower:
                matched_targets.add(target)
        if matched_targets:
            score += self.WEIGHT_EXFIL_TARGET
            has_exfil_verb = True  # treat target as exfil signal too
            signals.append({
                "name": "exfil_target",
                "weight": self.WEIGHT_EXFIL_TARGET,
                "matched": list(matched_targets)[:5],
            })

        # 4. Encoding tool scan
        matched_encoding = token_set & self._encoding_tools
        if matched_encoding:
            score += self.WEIGHT_ENCODING_TOOL
            has_encoding_tool = True
            signals.append({
                "name": "encoding_tool",
                "weight": self.WEIGHT_ENCODING_TOOL,
                "matched": list(matched_encoding),
            })

        # 5. Shell expansion scan
        expansion_match = _SHELL_EXPANSION_RE.search(content)
        if expansion_match:
            score += self.WEIGHT_SHELL_EXPANSION
            has_shell_expansion = True
            signals.append({
                "name": "shell_expansion",
                "weight": self.WEIGHT_SHELL_EXPANSION,
                "matched": [expansion_match.group()[:30]],
            })

        # 6. Pipe chain complexity
        pipe_count = content.count("|")
        if pipe_count > 1:
            pipe_score = self.WEIGHT_PIPE_COMPLEXITY * (pipe_count - 1)
            score += pipe_score
            signals.append({
                "name": "pipe_complexity",
                "weight": pipe_score,
                "matched": [f"{pipe_count} pipes"],
            })

        # 7. Redirect to external
        if _REDIRECT_EXTERNAL_RE.search(content):
            score += self.WEIGHT_REDIRECT_EXTERNAL
            signals.append({
                "name": "redirect_external",
                "weight": self.WEIGHT_REDIRECT_EXTERNAL,
                "matched": ["external redirect"],
            })

        # 8. Secret env var access
        env_match = _SECRET_ENV_RE.search(content)
        if env_match:
            score += self.WEIGHT_SECRET_ENV_VAR
            signals.append({
                "name": "secret_env_var",
                "weight": self.WEIGHT_SECRET_ENV_VAR,
                "matched": [env_match.group()[:30]],
            })

        # 9. Combination bonuses (multiplicative)
        if has_exfil_verb and has_sensitive_path:
            score *= self.COMBO_EXFIL_PLUS_SENSITIVE
            signals.append({
                "name": "combo_exfil_sensitive",
                "weight": self.COMBO_EXFIL_PLUS_SENSITIVE,
                "matched": ["multiplicative"],
            })
        if has_encoding_tool and has_exfil_verb:
            score *= self.COMBO_ENCODING_PLUS_EXFIL
            signals.append({
                "name": "combo_encoding_exfil",
                "weight": self.COMBO_ENCODING_PLUS_EXFIL,
                "matched": ["multiplicative"],
            })
        if has_shell_expansion and has_exfil_verb:
            score *= self.COMBO_EXPANSION_PLUS_EXFIL
            signals.append({
                "name": "combo_expansion_exfil",
                "weight": self.COMBO_EXPANSION_PLUS_EXFIL,
                "matched": ["multiplicative"],
            })

        # 10. Per-family sub-scores
        for family_name, family_def in (self._families or {}).items():
            fam_signals = family_def.get("heuristic_signals", {})
            fam_score = 0.0
            all_family_tokens = set()
            for token_list in fam_signals.values():
                if isinstance(token_list, list):
                    for t in token_list:
                        all_family_tokens.add(t.lower())

            hits = 0
            for ft in all_family_tokens:
                if ft in content_lower:
                    hits += 1
            if all_family_tokens:
                fam_score = hits / len(all_family_tokens)
            family_scores[family_name] = round(fam_score, 3)

        # 11. Known-benign dampening
        dampened = False
        dampening_reason = None
        benign_match = self._is_benign(content)
        if benign_match and score > 0:
            score *= (1.0 - self.BENIGN_DAMPENING)
            dampened = True
            dampening_reason = f"Benign pattern: {benign_match[:50]}"
            signals.append({
                "name": "benign_dampening",
                "weight": -(self.BENIGN_DAMPENING),
                "matched": [dampening_reason],
            })

        # 12. Clamp
        score = max(0.0, min(1.0, score))

        return HeuristicScore(
            total_score=round(score, 4),
            signals=signals,
            family_scores=family_scores,
            threshold=self._threshold,
            dampened=dampened,
            dampening_reason=dampening_reason,
        )

    def screen(
        self,
        tool_name: str,
        content: str,
        context: Dict[str, Any],
    ) -> ScreeningResult:
        """
        Score content and return escalation recommendation.

        Unlike other screening plugins, this does not make a final
        allow/block decision. It returns a score and an escalation
        recommendation in the details dict.
        """
        if not self._enabled:
            return ScreeningResult(
                allowed=True,
                plugin_name=self.name,
                reason="Heuristic scorer disabled",
                risk_level="safe",
                confidence=0.0,
                details={"heuristic_score": 0.0, "should_escalate": False},
                findings=[],
            )

        score = self._score_content(content)

        if score.total_score < self._threshold:
            return ScreeningResult(
                allowed=True,
                plugin_name=self.name,
                risk_level="safe",
                confidence=score.total_score,
                details={
                    "heuristic_score": score.total_score,
                    "threshold": self._threshold,
                    "should_escalate": False,
                    "signals": score.signals,
                    "family_scores": score.family_scores,
                },
                findings=[],
            )

        # Score exceeds threshold — recommend LLM escalation
        top_families = sorted(
            score.family_scores.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:3]

        top_family_name = top_families[0][0] if top_families else "unknown"

        return ScreeningResult(
            allowed=True,  # Scorer does not block; it escalates
            plugin_name=self.name,
            reason=f"Heuristic score {score.total_score:.2f} exceeds threshold {self._threshold}",
            risk_level="suspicious",
            confidence=score.total_score,
            should_prompt=False,  # Don't prompt user directly; escalate to LLM
            details={
                "heuristic_score": score.total_score,
                "threshold": self._threshold,
                "should_escalate": True,
                "top_families": top_families,
                "signals": score.signals,
                "family_scores": score.family_scores,
            },
            findings=[
                Finding(
                    pattern_name="heuristic_escalation",
                    matched_text=content[:100],
                    severity=Severity.MEDIUM,
                    description=f"Near-miss heuristic: resembles {top_family_name} attack family",
                    recommended_action=ActionType.WARN,
                    metadata={
                        "score": score.total_score,
                        "families": dict(top_families),
                    },
                )
            ],
        )
