#!/usr/bin/env python3
"""
Tweek Screening Plugins

Screening plugins provide security analysis methods:
- RateLimiter: Detect burst patterns and abuse
- PatternMatcher: Regex-based pattern matching
- HeuristicScorer: Signal-based scoring for confidence-gated LLM escalation
- LLMReviewer: Semantic analysis using LLM
- SessionAnalyzer: Cross-turn anomaly detection

License tiers:
- FREE: PatternMatcher (basic patterns), HeuristicScorer
- PRO: RateLimiter, LLMReviewer, SessionAnalyzer
"""

from tweek.plugins.screening.rate_limiter import RateLimiterPlugin
from tweek.plugins.screening.pattern_matcher import PatternMatcherPlugin
from tweek.plugins.screening.heuristic_scorer import HeuristicScorerPlugin
from tweek.plugins.screening.llm_reviewer import LLMReviewerPlugin
from tweek.plugins.screening.session_analyzer import SessionAnalyzerPlugin

try:
    from tweek.plugins.screening.local_model_reviewer import LocalModelReviewerPlugin
except ImportError:
    LocalModelReviewerPlugin = None  # type: ignore[assignment,misc]

__all__ = [
    "RateLimiterPlugin",
    "PatternMatcherPlugin",
    "HeuristicScorerPlugin",
    "LLMReviewerPlugin",
    "LocalModelReviewerPlugin",
    "SessionAnalyzerPlugin",
]
