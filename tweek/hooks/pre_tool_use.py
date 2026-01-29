#!/usr/bin/env python3
"""
Tweek Pre-Tool-Use Hook for Claude Code

This hook intercepts tool calls before execution and applies tiered security screening.

Security Layers (Defense in Depth):
1. Rate Limiting - Detect resource theft and burst attacks
2. Pattern Matching - Regex patterns for known attack vectors
3. LLM Review - Semantic analysis for risky/dangerous tiers
4. Session Analysis - Cross-turn anomaly detection
5. Sandbox Preview - Speculative execution (dangerous tier only)

Tiers:
  - safe: No screening (trusted operations)
  - default: Regex pattern matching only
  - risky: Regex + LLM rules
  - dangerous: Regex + LLM + Sandbox preview

Input (stdin): JSON with tool_name and tool_input
Output (stdout): JSON with decision (allow/block/ask) and optional message

Claude Code Hook Protocol:
- Empty response or {}: proceed with tool execution
- "permissionDecision": "ask" - prompt user for confirmation
- "permissionDecision": "deny" - block execution
"""

import json
import os
import re
import sys
from pathlib import Path
from typing import Optional, Dict, List, Any

import yaml

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from tweek.logging.security_log import (
    SecurityLogger, SecurityEvent, EventType, get_logger
)


class TierManager:
    """Manages security tier classification and escalation."""

    def __init__(self, config_path: Optional[Path] = None):
        if config_path is None:
            config_path = Path(__file__).parent.parent / "config" / "tiers.yaml"

        self.config = self._load_config(config_path)
        self.tools = self.config.get("tools", {})
        self.skills = self.config.get("skills", {})
        self.escalations = self.config.get("escalations", [])
        self.default_tier = self.config.get("default_tier", "default")
        self.tiers = self.config.get("tiers", {})

    def _load_config(self, path: Path) -> dict:
        """Load tier configuration from YAML."""
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def get_base_tier(self, tool_name: str, skill_name: Optional[str] = None) -> str:
        """Get the base tier for a tool or skill."""
        # Skills override tools if specified
        if skill_name and skill_name in self.skills:
            return self.skills[skill_name]

        if tool_name in self.tools:
            return self.tools[tool_name]

        return self.default_tier

    def check_escalations(self, content: str) -> Optional[Dict]:
        """Check if content triggers any escalation patterns.

        Returns the highest-priority escalation match, or None.
        """
        tier_priority = {"safe": 0, "default": 1, "risky": 2, "dangerous": 3}
        highest_match = None
        highest_priority = -1

        for escalation in self.escalations:
            pattern = escalation.get("pattern", "")
            try:
                if re.search(pattern, content, re.IGNORECASE):
                    target_tier = escalation.get("escalate_to", "default")
                    priority = tier_priority.get(target_tier, 1)
                    if priority > highest_priority:
                        highest_priority = priority
                        highest_match = escalation
            except re.error:
                continue

        return highest_match

    def get_effective_tier(
        self,
        tool_name: str,
        content: str,
        skill_name: Optional[str] = None
    ) -> tuple[str, Optional[Dict]]:
        """Get the effective tier after checking escalations.

        Returns (tier, escalation_match) where escalation_match is None
        if no escalation occurred.
        """
        base_tier = self.get_base_tier(tool_name, skill_name)
        escalation = self.check_escalations(content)

        if escalation is None:
            return base_tier, None

        tier_priority = {"safe": 0, "default": 1, "risky": 2, "dangerous": 3}
        base_priority = tier_priority.get(base_tier, 1)
        escalated_tier = escalation.get("escalate_to", "default")
        escalated_priority = tier_priority.get(escalated_tier, 1)

        # Only escalate, never de-escalate
        if escalated_priority > base_priority:
            return escalated_tier, escalation

        return base_tier, None

    def get_screening_methods(self, tier: str) -> List[str]:
        """Get the screening methods for a tier."""
        tier_config = self.tiers.get(tier, {})
        return tier_config.get("screening", [])


class PatternMatcher:
    """Matches commands against hostile patterns."""

    # Default max pattern ID for free tier
    FREE_TIER_MAX_ID = 23

    def __init__(self, patterns_path: Optional[Path] = None):
        # Try user patterns first (~/.tweek/patterns/), fall back to bundled
        user_patterns = Path.home() / ".tweek" / "patterns" / "patterns.yaml"
        bundled_patterns = Path(__file__).parent.parent / "config" / "patterns.yaml"

        if patterns_path is not None:
            self.patterns = self._load_patterns(patterns_path)
        elif user_patterns.exists():
            self.patterns = self._load_patterns(user_patterns)
        else:
            self.patterns = self._load_patterns(bundled_patterns)

    def _load_patterns(self, path: Path) -> List[dict]:
        """Load patterns from YAML config, filtered by license tier.

        Patterns are numbered sequentially:
        - FREE tier: Patterns with id <= 23
        - PRO tier: All patterns (1-116+)
        """
        if not path.exists():
            return []

        with open(path) as f:
            config = yaml.safe_load(f) or {}

        all_patterns = config.get("patterns", [])
        free_tier_max = config.get("free_tier_max", self.FREE_TIER_MAX_ID)

        # Check license tier
        try:
            from tweek.licensing import get_license
            is_pro = get_license().is_pro
        except Exception:
            is_pro = False

        if is_pro:
            # Pro users get all patterns
            return all_patterns
        else:
            # Free users only get patterns where id <= free_tier_max
            return [p for p in all_patterns if p.get("id", 999) <= free_tier_max]

    def check(self, content: str) -> Optional[dict]:
        """Check content against all patterns.

        Returns the first matching pattern, or None.
        """
        for pattern in self.patterns:
            try:
                if re.search(pattern.get("regex", ""), content, re.IGNORECASE):
                    return pattern
            except re.error:
                continue
        return None

    def check_all(self, content: str) -> List[dict]:
        """Check content against all patterns, returning all matches."""
        matches = []
        for pattern in self.patterns:
            try:
                if re.search(pattern.get("regex", ""), content, re.IGNORECASE):
                    matches.append(pattern)
            except re.error:
                continue
        return matches


def format_prompt_message(
    pattern: Optional[dict],
    escalation: Optional[dict],
    command: str,
    tier: str,
    rate_limit_msg: Optional[str] = None,
    llm_msg: Optional[str] = None,
    session_msg: Optional[str] = None
) -> str:
    """Format the message shown to user when prompting for confirmation."""
    severity_icons = {
        "critical": "",
        "high": " ",
        "medium": "",
        "low": "",
    }

    lines = []

    # Header with tier info
    tier_icons = {"safe": "", "default": "", "risky": "", "dangerous": ""}
    lines.append(f"{tier_icons.get(tier, '')} TWEEK SECURITY CHECK")
    lines.append("" * 45)

    # Rate limit info if applicable
    if rate_limit_msg:
        lines.append(rate_limit_msg)
        lines.append("")

    # Session analysis if applicable
    if session_msg:
        lines.append(session_msg)
        lines.append("")

    # Escalation info if applicable
    if escalation:
        lines.append(f"  Escalated to {tier.upper()} tier")
        lines.append(f"   Reason: {escalation.get('description', 'Content-based escalation')}")
        lines.append("")

    # Pattern match info
    if pattern:
        icon = severity_icons.get(pattern.get("severity", "medium"), "")
        lines.append(f"{icon} Pattern Match: {pattern.get('name', 'unknown')}")
        if pattern.get("id"):
            lines.append(f"   ID: {pattern.get('id')}")
        lines.append(f"   Severity: {pattern.get('severity', 'unknown').upper()}")
        lines.append(f"   {pattern.get('description', 'Suspicious command detected')}")
        lines.append("")

    # LLM review if applicable
    if llm_msg:
        lines.append(llm_msg)
        lines.append("")

    # Command preview
    display_cmd = command if len(command) < 60 else command[:57] + "..."
    lines.append(f"Command: {display_cmd}")
    lines.append("" * 45)
    lines.append("Allow this command?")

    return "\n".join(lines)


def process_hook(input_data: dict, logger: SecurityLogger) -> dict:
    """Main hook logic with tiered security screening.

    Security Layers:
    1. Rate Limiting - Detect resource theft
    2. Pattern Matching - Known attack vectors
    3. LLM Review - Semantic analysis
    4. Session Analysis - Cross-turn anomalies
    5. Sandbox Preview - Speculative execution

    Args:
        input_data: Dict with tool_name, tool_input from Claude Code
        logger: Security logger instance

    Returns:
        Dict with hookSpecificOutput for Claude Code hook protocol
    """
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})
    session_id = input_data.get("session_id")
    working_dir = input_data.get("cwd")

    # Extract content to analyze (command for Bash, path for Read, etc.)
    if tool_name == "Bash":
        content = tool_input.get("command", "")
    elif tool_name in ("Read", "Write", "Edit"):
        content = tool_input.get("file_path", "")
    elif tool_name == "WebFetch":
        content = tool_input.get("url", "")
    else:
        content = json.dumps(tool_input)

    if not content:
        return {}

    # Initialize managers
    tier_mgr = TierManager()
    pattern_matcher = PatternMatcher()

    # Determine effective tier
    effective_tier, escalation = tier_mgr.get_effective_tier(tool_name, content)
    screening_methods = tier_mgr.get_screening_methods(effective_tier)

    # Log tool invocation
    logger.log_quick(
        EventType.TOOL_INVOKED,
        tool_name,
        command=content if tool_name == "Bash" else None,
        tier=effective_tier,
        session_id=session_id,
        working_directory=working_dir,
        metadata={"tool_input": tool_input}
    )

    # Log escalation if it occurred
    if escalation:
        logger.log_quick(
            EventType.ESCALATION,
            tool_name,
            command=content if tool_name == "Bash" else None,
            tier=effective_tier,
            decision_reason=escalation.get("description"),
            session_id=session_id,
            metadata={"escalation": escalation}
        )

    # =========================================================================
    # LAYER 1: Rate Limiting
    # =========================================================================
    rate_limit_msg = None
    try:
        from tweek.security.rate_limiter import get_rate_limiter

        rate_limiter = get_rate_limiter()
        rate_result = rate_limiter.check(
            tool_name=tool_name,
            command=content if tool_name == "Bash" else None,
            session_id=session_id,
            tier=effective_tier
        )

        if not rate_result.allowed:
            rate_limit_msg = rate_limiter.format_violation_message(rate_result)
            logger.log_quick(
                EventType.PATTERN_MATCH,
                tool_name,
                command=content if tool_name == "Bash" else None,
                tier=effective_tier,
                pattern_name="rate_limit",
                pattern_severity="high",
                decision="ask",
                decision_reason=f"Rate limit violations: {rate_result.violations}",
                session_id=session_id,
                metadata={"rate_limit": rate_result.details}
            )

            # Rate limit alone triggers prompt
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": format_prompt_message(
                        None, None, content, effective_tier,
                        rate_limit_msg=rate_limit_msg
                    ),
                }
            }
    except ImportError:
        pass  # Rate limiter not available
    except Exception as e:
        logger.log_quick(
            EventType.ERROR,
            tool_name,
            decision_reason=f"Rate limiter error: {e}",
            session_id=session_id
        )

    # Safe tier - no further screening
    if not screening_methods:
        logger.log_quick(
            EventType.ALLOWED,
            tool_name,
            tier=effective_tier,
            decision="allow",
            decision_reason="Safe tier - no screening required",
            session_id=session_id
        )
        return {}

    # =========================================================================
    # LAYER 2: Pattern Matching
    # =========================================================================
    pattern_match = None
    if "regex" in screening_methods:
        pattern_match = pattern_matcher.check(content)

        if pattern_match:
            logger.log_quick(
                EventType.PATTERN_MATCH,
                tool_name,
                command=content if tool_name == "Bash" else None,
                tier=effective_tier,
                pattern_name=pattern_match.get("name"),
                pattern_severity=pattern_match.get("severity"),
                session_id=session_id,
                metadata={"pattern": pattern_match}
            )

    # =========================================================================
    # LAYER 3: LLM Review (for risky/dangerous tiers)
    # =========================================================================
    llm_msg = None
    llm_triggered = False
    if "llm" in screening_methods and tool_name == "Bash":
        try:
            from tweek.security.llm_reviewer import get_llm_reviewer

            llm_reviewer = get_llm_reviewer()
            llm_result = llm_reviewer.review(
                command=content,
                tool=tool_name,
                tier=effective_tier,
                tool_input=tool_input,
                session_context=f"session:{session_id}" if session_id else None
            )

            if llm_result.should_prompt:
                llm_triggered = True
                llm_msg = llm_reviewer.format_review_message(llm_result)
                logger.log_quick(
                    EventType.LLM_RULE_MATCH,
                    tool_name,
                    command=content,
                    tier=effective_tier,
                    pattern_name="llm_review",
                    pattern_severity=llm_result.risk_level.value,
                    decision="ask",
                    decision_reason=llm_result.reason,
                    session_id=session_id,
                    metadata={
                        "llm_risk": llm_result.risk_level.value,
                        "llm_confidence": llm_result.confidence,
                        "llm_reason": llm_result.reason
                    }
                )
        except ImportError:
            pass  # LLM reviewer not available
        except Exception as e:
            logger.log_quick(
                EventType.ERROR,
                tool_name,
                decision_reason=f"LLM reviewer error: {e}",
                session_id=session_id
            )

    # =========================================================================
    # LAYER 4: Session Analysis (cross-turn anomaly detection)
    # =========================================================================
    session_msg = None
    session_triggered = False
    if session_id and effective_tier in ("risky", "dangerous"):
        try:
            from tweek.security.session_analyzer import get_session_analyzer

            session_analyzer = get_session_analyzer()
            session_result = session_analyzer.analyze(session_id)

            if session_result.is_suspicious:
                session_triggered = True
                session_msg = session_analyzer.format_analysis_message(session_result)
                logger.log_quick(
                    EventType.PATTERN_MATCH,
                    tool_name,
                    command=content if tool_name == "Bash" else None,
                    tier=effective_tier,
                    pattern_name="session_anomaly",
                    pattern_severity="high" if session_result.is_high_risk else "medium",
                    decision="ask",
                    decision_reason=f"Session anomalies: {session_result.anomalies}",
                    session_id=session_id,
                    metadata={
                        "risk_score": session_result.risk_score,
                        "anomalies": [a.value for a in session_result.anomalies]
                    }
                )
        except ImportError:
            pass  # Session analyzer not available
        except Exception as e:
            logger.log_quick(
                EventType.ERROR,
                tool_name,
                decision_reason=f"Session analyzer error: {e}",
                session_id=session_id
            )

    # =========================================================================
    # LAYER 5: Sandbox Preview (dangerous tier, Bash only)
    # =========================================================================
    sandbox_triggered = False
    sandbox_msg = None
    if "sandbox" in screening_methods and tool_name == "Bash":
        try:
            from tweek.sandbox.executor import SandboxExecutor

            executor = SandboxExecutor()
            preview = executor.preview_command(content, skill="hook-preview", timeout=3.0)

            if preview.suspicious:
                sandbox_triggered = True
                logger.log_quick(
                    EventType.SANDBOX_PREVIEW,
                    tool_name,
                    command=content,
                    tier=effective_tier,
                    pattern_name="sandbox_preview",
                    pattern_severity="high",
                    decision="ask",
                    decision_reason="Sandbox preview detected suspicious behavior",
                    session_id=session_id,
                    metadata={"violations": preview.violations, "denied_ops": preview.denied_operations}
                )

                violation_text = "\n".join(f"  * {v}" for v in preview.violations)
                sandbox_msg = (
                    f" SANDBOX PREVIEW\n"
                    f"Speculative execution detected suspicious behavior:\n\n"
                    f"{violation_text}"
                )
        except ImportError:
            pass  # Sandbox not available
        except Exception as e:
            logger.log_quick(
                EventType.ERROR,
                tool_name,
                command=content,
                tier=effective_tier,
                decision_reason=f"Sandbox preview error: {e}",
                session_id=session_id
            )

    # =========================================================================
    # Decision: Prompt if any layer triggered
    # =========================================================================
    if pattern_match or llm_triggered or session_triggered or sandbox_triggered:
        logger.log_quick(
            EventType.USER_PROMPTED,
            tool_name,
            command=content if tool_name == "Bash" else None,
            tier=effective_tier,
            pattern_name=pattern_match.get("name") if pattern_match else "multi_layer",
            pattern_severity=pattern_match.get("severity") if pattern_match else "high",
            decision="ask",
            decision_reason="Security check triggered",
            session_id=session_id,
            metadata={
                "pattern_triggered": pattern_match is not None,
                "llm_triggered": llm_triggered,
                "session_triggered": session_triggered,
                "sandbox_triggered": sandbox_triggered
            }
        )

        # Combine all messages
        final_msg = format_prompt_message(
            pattern_match, escalation, content, effective_tier,
            rate_limit_msg=rate_limit_msg,
            llm_msg=llm_msg,
            session_msg=session_msg
        )

        # Add sandbox message if applicable
        if sandbox_msg:
            final_msg += f"\n\n{sandbox_msg}"

        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "permissionDecisionReason": final_msg,
            }
        }

    # No issues found - allow
    logger.log_quick(
        EventType.ALLOWED,
        tool_name,
        command=content if tool_name == "Bash" else None,
        tier=effective_tier,
        decision="allow",
        decision_reason="Passed all screening layers",
        session_id=session_id
    )

    return {}


def check_allowed_directory() -> bool:
    """
    Check if current working directory is in the allowed list.

    This is a SAFETY CHECK to prevent Tweek from accidentally
    running in production or other directories.

    Returns:
        True if Tweek should activate, False to pass through
    """
    config_path = Path(__file__).parent.parent / "config" / "allowed_dirs.yaml"

    if not config_path.exists():
        # No config = disabled everywhere (safe default)
        return False

    try:
        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
    except Exception:
        return False

    # Check if globally enabled (production mode)
    if config.get("global_enabled", False):
        return True

    # Check allowed directories
    allowed_dirs = config.get("allowed_directories", [])
    cwd = Path.cwd().resolve()

    for allowed in allowed_dirs:
        allowed_path = Path(allowed).expanduser().resolve()
        try:
            # Check if cwd is the allowed dir or a subdirectory
            cwd.relative_to(allowed_path)
            return True
        except ValueError:
            continue

    return False


def main():
    """Entry point for the hook."""
    # SAFETY CHECK: Only activate in allowed directories
    if not check_allowed_directory():
        # Not in allowed directory - pass through without screening
        print("{}")
        return

    logger = get_logger()

    try:
        # Read JSON from stdin
        input_text = sys.stdin.read()
        if not input_text.strip():
            print("{}")
            return

        input_data = json.loads(input_text)
        result = process_hook(input_data, logger)

        # Output JSON result
        print(json.dumps(result))

    except json.JSONDecodeError as e:
        # Invalid JSON - fail open (allow) but log
        logger.log_quick(
            EventType.ERROR,
            "unknown",
            decision="allow",
            decision_reason=f"JSON decode error: {e}"
        )
        print("{}")

    except Exception as e:
        # Any error - fail closed (block for safety)
        logger.log_quick(
            EventType.ERROR,
            "unknown",
            decision="deny",
            decision_reason=f"Hook error: {e}"
        )
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f" TWEEK ERROR: {e}\nBlocking for safety.",
            }
        }))


if __name__ == "__main__":
    main()
