#!/usr/bin/env python3
"""
Tweek MCP Screening - Shared screening logic for MCP gateway and proxy.

Extracts the screening pipeline from TweekMCPServer so it can be reused
by both the MCP gateway (which converts should_prompt -> blocked) and
the MCP proxy (which queues should_prompt for human approval).
"""

import logging
from typing import Any, Dict

from tweek.screening.context import ScreeningContext

logger = logging.getLogger(__name__)


def run_mcp_screening(context: ScreeningContext) -> Dict[str, Any]:
    """
    Run the shared screening pipeline on a tool call.

    Returns dict with:
        allowed: bool       - Whether execution is permitted
        blocked: bool       - Whether execution is hard-blocked
        should_prompt: bool - Whether human confirmation is needed
        reason: Optional[str]
        findings: List[Dict]
    """
    try:
        from tweek.hooks.pre_tool_use import (
            TierManager,
            PatternMatcher,
            run_compliance_scans,
            run_screening_plugins,
        )
        from tweek.logging.security_log import get_logger as get_sec_logger

        sec_logger = get_sec_logger()

        # Resolve tier
        tier_mgr = TierManager()
        effective_tier, escalation = tier_mgr.get_effective_tier(
            context.tool_name, context.content
        )
        context.tier = effective_tier

        # Run compliance scans on input
        should_block, compliance_msg, compliance_findings = run_compliance_scans(
            content=context.content,
            direction="input",
            logger=sec_logger,
            session_id=context.session_id,
            tool_name=context.tool_name,
        )

        if should_block:
            return {
                "allowed": False,
                "blocked": True,
                "should_prompt": False,
                "reason": compliance_msg or "Blocked by compliance scan",
                "findings": compliance_findings,
            }

        # Skip further screening for safe tier
        if effective_tier == "safe":
            return {
                "allowed": True,
                "blocked": False,
                "should_prompt": False,
                "reason": None,
                "findings": [],
            }

        # Pattern matching
        pattern_matcher = PatternMatcher()
        match = pattern_matcher.check(context.content)

        if match:
            pattern_name = match.get("pattern", match.get("name", "unknown"))
            return {
                "allowed": False,
                "blocked": True,
                "should_prompt": False,
                "reason": f"Blocked by pattern match: {pattern_name}",
                "findings": [match],
            }

        # Run screening plugins
        legacy_context = context.to_legacy_dict()
        allowed, should_prompt, screen_msg, screen_findings = run_screening_plugins(
            tool_name=context.tool_name,
            content=context.content,
            context=legacy_context,
            logger=sec_logger,
        )

        if not allowed:
            return {
                "allowed": False,
                "blocked": True,
                "should_prompt": False,
                "reason": screen_msg or "Blocked by screening plugin",
                "findings": screen_findings,
            }

        if should_prompt:
            return {
                "allowed": True,
                "blocked": False,
                "should_prompt": True,
                "reason": screen_msg or "Requires user confirmation",
                "findings": screen_findings,
            }

        return {
            "allowed": True,
            "blocked": False,
            "should_prompt": False,
            "reason": None,
            "findings": [],
        }

    except ImportError as e:
        logger.warning(f"Screening modules not available: {e}")
        # Fail open with warning if screening not available
        return {
            "allowed": True,
            "blocked": False,
            "should_prompt": False,
            "reason": f"Warning: screening unavailable ({e})",
            "findings": [],
        }
    except Exception as e:
        logger.error(f"Screening error: {e}")
        # Fail closed on unexpected errors
        return {
            "allowed": False,
            "blocked": True,
            "should_prompt": False,
            "reason": f"Screening error: {e}",
            "findings": [],
        }


def run_output_scan(content: str) -> Dict[str, Any]:
    """
    Scan output content for leaked credentials or sensitive data.

    Returns dict with:
        blocked: bool
        reason: Optional[str]
        findings: List[Dict]
    """
    try:
        from tweek.hooks.pre_tool_use import run_compliance_scans
        from tweek.logging.security_log import get_logger as get_sec_logger

        sec_logger = get_sec_logger()
        should_block, msg, findings = run_compliance_scans(
            content=content,
            direction="output",
            logger=sec_logger,
            tool_name="mcp_output_scan",
        )

        if should_block:
            return {"blocked": True, "reason": msg, "findings": findings}

    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"Output scan error: {e}")

    return {"blocked": False}
