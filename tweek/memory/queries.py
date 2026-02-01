"""
Tweek Memory Query Functions

Hook entry points for reading and writing memory during PreToolUse
and PostToolUse screening. All functions are best-effort and fail
silently to avoid blocking security screening.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from tweek.memory.safety import MIN_CONFIDENCE_SCORE
from tweek.memory.schemas import PatternDecisionEntry
from tweek.memory.store import (
    MemoryStore,
    content_hash,
    get_memory_store,
    hash_project,
    normalize_path_prefix,
)


def memory_read_for_pattern(
    pattern_name: str,
    pattern_severity: str,
    pattern_confidence: str,
    tool_name: str,
    path_prefix: Optional[str] = None,
    project_hash: Optional[str] = None,
    current_decision: str = "ask",
) -> Optional[Dict[str, Any]]:
    """Read memory for a pattern match to get confidence adjustment.

    Called from PreToolUse after pattern matching, before enforcement resolution.

    Returns a dict with 'adjusted_decision' key if memory suggests a change,
    or None if no adjustment suggested.
    """
    try:
        store = get_memory_store()
        normalized_prefix = normalize_path_prefix(path_prefix) if path_prefix else None

        adjustment = store.get_confidence_adjustment(
            pattern_name=pattern_name,
            path_prefix=normalized_prefix,
            current_decision=current_decision,
            original_severity=pattern_severity,
            original_confidence=pattern_confidence,
        )

        if adjustment is None:
            return None

        if (
            adjustment.adjusted_decision
            and adjustment.confidence_score >= MIN_CONFIDENCE_SCORE
        ):
            return {
                "adjusted_decision": adjustment.adjusted_decision,
                "confidence_score": adjustment.confidence_score,
                "approval_ratio": adjustment.approval_ratio,
                "total_decisions": adjustment.total_decisions,
                "pattern_name": pattern_name,
            }

        return None
    except Exception:
        return None


def memory_write_after_decision(
    pattern_name: str,
    pattern_id: Optional[int],
    original_severity: str,
    original_confidence: str,
    decision: str,
    user_response: Optional[str],
    tool_name: str,
    content: str,
    path_prefix: Optional[str] = None,
    project_hash: Optional[str] = None,
) -> None:
    """Write a pattern decision to memory.

    Called from PreToolUse after the decision is made (in all branches:
    deny, ask, log, and allow).
    """
    try:
        store = get_memory_store()
        normalized_prefix = normalize_path_prefix(path_prefix) if path_prefix else None
        c_hash = content_hash(content) if content else None

        entry = PatternDecisionEntry(
            pattern_name=pattern_name,
            pattern_id=pattern_id,
            original_severity=original_severity,
            original_confidence=original_confidence,
            decision=decision,
            user_response=user_response,
            tool_name=tool_name,
            content_hash=c_hash,
            path_prefix=normalized_prefix,
            project_hash=project_hash,
        )

        store.record_decision(entry)
    except Exception:
        pass  # Memory is best-effort


def memory_read_source_trust(
    source_type: str,
    source_key: str,
) -> Optional[Dict[str, Any]]:
    """Read source trust information.

    Called from PostToolUse before screen_content().

    Returns a dict with trust information if available.
    """
    try:
        store = get_memory_store()
        entry = store.get_source_trust(source_type, source_key)

        if entry is None:
            return None

        return {
            "source_type": entry.source_type,
            "source_key": entry.source_key,
            "trust_score": entry.trust_score,
            "total_scans": entry.total_scans,
            "injection_detections": entry.injection_detections,
            "last_injection": entry.last_injection,
        }
    except Exception:
        return None


def memory_write_source_scan(
    source_type: str,
    source_key: str,
    had_injection: bool,
) -> None:
    """Record a source scan result in memory.

    Called from PostToolUse after screen_content() completes.
    """
    try:
        store = get_memory_store()
        store.record_source_scan(source_type, source_key, had_injection)

        # Also record domain-level trust for URLs
        if source_type == "url":
            try:
                from urllib.parse import urlparse
                domain = urlparse(source_key).hostname
                if domain:
                    store.record_source_scan("domain", domain, had_injection)
            except Exception:
                pass
    except Exception:
        pass  # Memory is best-effort


def memory_update_workflow(
    project_hash: str,
    tool_name: str,
    was_denied: bool = False,
) -> None:
    """Update workflow baseline for a project.

    Called from PreToolUse at the end of processing.
    """
    try:
        store = get_memory_store()
        hour = datetime.utcnow().hour
        store.update_workflow(
            project_hash=project_hash,
            tool_name=tool_name,
            hour_of_day=hour,
            was_denied=was_denied,
        )
    except Exception:
        pass  # Memory is best-effort


def memory_get_workflow_baseline(
    project_hash: str,
) -> Optional[Dict[str, Any]]:
    """Get workflow baseline for cross-session comparison.

    Called from session_analyzer to compare current behavior against baselines.
    """
    try:
        store = get_memory_store()
        baselines = store.get_workflow_baseline(project_hash)

        if not baselines:
            return None

        # Aggregate into a summary
        tool_counts = {}
        total_invocations = 0
        total_denials = 0

        for b in baselines:
            if b.tool_name not in tool_counts:
                tool_counts[b.tool_name] = {"invocations": 0, "denials": 0}
            tool_counts[b.tool_name]["invocations"] += b.invocation_count
            tool_counts[b.tool_name]["denials"] += b.denied_count
            total_invocations += b.invocation_count
            total_denials += b.denied_count

        return {
            "project_hash": project_hash,
            "tool_counts": tool_counts,
            "total_invocations": total_invocations,
            "total_denials": total_denials,
            "denial_ratio": total_denials / max(total_invocations, 1),
        }
    except Exception:
        return None
