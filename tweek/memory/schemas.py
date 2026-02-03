"""
Tweek Memory Data Schemas

Dataclasses for structured memory entries and query results.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PatternDecisionEntry:
    """A single pattern decision record."""

    pattern_name: str
    pattern_id: Optional[int]
    original_severity: str
    original_confidence: str
    decision: str  # deny/ask/log/allow
    user_response: Optional[str]  # approved/denied/null
    tool_name: str
    content_hash: Optional[str]
    path_prefix: Optional[str]
    project_hash: Optional[str]
    timestamp: Optional[str] = None
    decay_weight: float = 1.0


@dataclass
class ConfidenceAdjustment:
    """Result of a memory confidence query for a pattern."""

    pattern_name: str
    path_prefix: Optional[str]
    total_decisions: int
    weighted_approvals: float
    weighted_denials: float
    approval_ratio: float
    last_decision: Optional[str]
    adjusted_decision: Optional[str] = None  # suggested decision override
    confidence_score: float = 0.0  # 0.0-1.0 how confident the suggestion is
    scope: Optional[str] = None  # which scope matched: exact/tool_project/path


@dataclass
class SourceTrustEntry:
    """Trust score for a URL, file, or domain."""

    source_type: str  # url/file/domain
    source_key: str
    total_scans: int = 0
    injection_detections: int = 0
    trust_score: float = 0.5  # 0.0=bad, 1.0=good
    last_clean_scan: Optional[str] = None
    last_injection: Optional[str] = None


@dataclass
class WorkflowBaseline:
    """Baseline tool usage pattern for a project."""

    project_hash: str
    tool_name: str
    hour_of_day: Optional[int]
    invocation_count: int = 0
    denied_count: int = 0


@dataclass
class LearnedWhitelistSuggestion:
    """A suggested whitelist entry derived from approval patterns."""

    id: int
    pattern_name: str
    tool_name: Optional[str]
    path_prefix: Optional[str]
    approval_count: int = 0
    denial_count: int = 0
    confidence: float = 0.0
    suggested_at: Optional[str] = None
    human_reviewed: int = 0  # 0=pending, 1=accepted, -1=rejected
