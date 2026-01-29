"""
Mitmproxy Addon - The actual proxy implementation.

This module provides the mitmproxy addon that intercepts LLM API traffic
and applies Tweek's security screening.

Requires: pip install tweek[proxy]
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

# Guard import - only available with [proxy] extra
try:
    from mitmproxy import http, ctx
    from mitmproxy.script import concurrent
    MITMPROXY_AVAILABLE = True
except ImportError:
    MITMPROXY_AVAILABLE = False
    # Stub for type checking
    class http:
        class HTTPFlow:
            pass
    ctx = None
    def concurrent(f):
        return f

from .interceptor import LLMAPIInterceptor, LLMProvider

logger = logging.getLogger("tweek.proxy")


class TweekProxyAddon:
    """
    Mitmproxy addon for Tweek LLM security screening.

    This addon intercepts HTTPS traffic to LLM APIs and screens
    both requests (for prompt injection) and responses (for dangerous tool calls).
    """

    def __init__(
        self,
        pattern_matcher=None,
        security_logger=None,
        block_mode: bool = True,
        log_only: bool = False,
    ):
        """
        Initialize the Tweek proxy addon.

        Args:
            pattern_matcher: PatternMatcher instance for screening
            security_logger: SecurityLogger for audit logging
            block_mode: If True, block dangerous responses. If False, just log.
            log_only: If True, log all traffic without blocking.
        """
        self.interceptor = LLMAPIInterceptor(
            pattern_matcher=pattern_matcher,
            security_logger=security_logger,
        )
        self.block_mode = block_mode
        self.log_only = log_only
        self.stats = {
            "requests_screened": 0,
            "responses_screened": 0,
            "requests_blocked": 0,
            "responses_blocked": 0,
            "tool_calls_detected": 0,
            "tool_calls_blocked": 0,
        }

    def load(self, loader):
        """Called when the addon is loaded."""
        if ctx:
            ctx.log.info("Tweek LLM Security Proxy loaded")
            ctx.log.info(f"Block mode: {self.block_mode}")
            ctx.log.info(f"Log only: {self.log_only}")

    def request(self, flow: http.HTTPFlow):
        """Handle outgoing requests to LLM APIs."""
        host = flow.request.host

        if not self.interceptor.should_intercept(host):
            return

        self.stats["requests_screened"] += 1
        provider = self.interceptor.identify_provider(host)

        # Screen the request for prompt injection
        if flow.request.content:
            result = self.interceptor.screen_request(flow.request.content, provider)

            if result.warnings:
                # Log warnings but don't block requests
                logger.warning(
                    f"Prompt injection warning: {result.warnings} "
                    f"(provider={provider.value}, path={flow.request.path})"
                )

                # Add header to track warning
                flow.request.headers["X-Tweek-Warning"] = "prompt-injection-suspected"

    @concurrent
    def response(self, flow: http.HTTPFlow):
        """Handle incoming responses from LLM APIs."""
        host = flow.request.host

        if not self.interceptor.should_intercept(host):
            return

        # Skip streaming responses - we can't buffer them without breaking UX
        content_type = flow.response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            logger.debug(f"Skipping streaming response from {host}")
            return

        self.stats["responses_screened"] += 1
        provider = self.interceptor.identify_provider(host)

        if not flow.response.content:
            return

        # Screen the response for dangerous tool calls
        result = self.interceptor.screen_response(flow.response.content, provider)

        if result.blocked_tools:
            self.stats["tool_calls_detected"] += len(result.blocked_tools)

        if not result.allowed:
            self.stats["responses_blocked"] += 1
            self.stats["tool_calls_blocked"] += len(result.blocked_tools)

            logger.warning(
                f"BLOCKED: {result.reason} "
                f"(provider={provider.value}, patterns={result.matched_patterns})"
            )

            if self.block_mode and not self.log_only:
                # Replace response with error
                flow.response = http.Response.make(
                    403,
                    json.dumps({
                        "error": {
                            "type": "security_blocked",
                            "message": f"Tweek Security: {result.reason}",
                            "blocked_tools": result.blocked_tools,
                            "patterns": result.matched_patterns,
                        }
                    }),
                    {"Content-Type": "application/json"},
                )

        elif result.warnings:
            logger.info(f"Warnings for response: {result.warnings}")

    def done(self):
        """Called when the proxy shuts down."""
        logger.info(f"Tweek Proxy Stats: {json.dumps(self.stats, indent=2)}")


def create_addon(
    pattern_matcher=None,
    security_logger=None,
    block_mode: bool = True,
    log_only: bool = False,
) -> TweekProxyAddon:
    """
    Factory function to create a configured Tweek proxy addon.

    This is the entry point used by mitmproxy when loading the script.
    """
    return TweekProxyAddon(
        pattern_matcher=pattern_matcher,
        security_logger=security_logger,
        block_mode=block_mode,
        log_only=log_only,
    )


# For direct script loading by mitmproxy
addons = []


def configure_and_load():
    """
    Configure and load the addon with Tweek's pattern matcher.

    Called when loading as a mitmproxy script.
    """
    global addons

    # Try to load Tweek's pattern matcher
    pattern_matcher = None
    security_logger = None

    try:
        from tweek.hooks.patterns import PatternMatcher
        pattern_matcher = PatternMatcher()
    except ImportError:
        logger.warning("Could not load PatternMatcher, running in pass-through mode")

    try:
        from tweek.logging.security_log import SecurityLogger
        security_logger = SecurityLogger()
    except ImportError:
        logger.warning("Could not load SecurityLogger")

    addon = create_addon(
        pattern_matcher=pattern_matcher,
        security_logger=security_logger,
    )

    addons = [addon]
    return addons


# Auto-configure when loaded as script
if MITMPROXY_AVAILABLE:
    configure_and_load()
