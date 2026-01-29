"""
LLM API Interceptor - Screens requests and responses to LLM APIs.

This module provides the core interception logic for the Tweek proxy,
analyzing LLM API traffic for security threats.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum


class LLMProvider(Enum):
    """Supported LLM API providers."""
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GOOGLE = "google"
    BEDROCK = "bedrock"
    UNKNOWN = "unknown"


@dataclass
class InterceptionResult:
    """Result of screening an LLM API request or response."""
    allowed: bool
    provider: LLMProvider
    reason: Optional[str] = None
    blocked_tools: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    matched_patterns: list[str] = field(default_factory=list)


@dataclass
class ToolCall:
    """Represents a tool call extracted from an LLM response."""
    id: str
    name: str
    input: dict[str, Any]
    provider: LLMProvider


class LLMAPIInterceptor:
    """
    Intercepts and screens LLM API traffic.

    Analyzes both requests (prompts) and responses (tool calls)
    for security threats using Tweek's pattern matching engine.
    """

    # API endpoints to monitor
    MONITORED_HOSTS = {
        "api.anthropic.com": LLMProvider.ANTHROPIC,
        "api.openai.com": LLMProvider.OPENAI,
        "generativelanguage.googleapis.com": LLMProvider.GOOGLE,
    }

    # Bedrock uses regional endpoints
    BEDROCK_PATTERN = re.compile(r"bedrock-runtime\.[\w-]+\.amazonaws\.com")

    def __init__(self, pattern_matcher=None, security_logger=None):
        """
        Initialize the interceptor.

        Args:
            pattern_matcher: Tweek PatternMatcher instance for screening
            security_logger: SecurityLogger for audit logging
        """
        self.pattern_matcher = pattern_matcher
        self.security_logger = security_logger

    def identify_provider(self, host: str) -> LLMProvider:
        """Identify the LLM provider from the request host."""
        if host in self.MONITORED_HOSTS:
            return self.MONITORED_HOSTS[host]

        if self.BEDROCK_PATTERN.match(host):
            return LLMProvider.BEDROCK

        return LLMProvider.UNKNOWN

    def should_intercept(self, host: str) -> bool:
        """Check if this host should be intercepted."""
        return self.identify_provider(host) != LLMProvider.UNKNOWN

    def extract_tool_calls_anthropic(self, response: dict) -> list[ToolCall]:
        """Extract tool calls from Anthropic API response."""
        tool_calls = []

        content = response.get("content", [])
        for block in content:
            if block.get("type") == "tool_use":
                tool_calls.append(ToolCall(
                    id=block.get("id", ""),
                    name=block.get("name", ""),
                    input=block.get("input", {}),
                    provider=LLMProvider.ANTHROPIC,
                ))

        return tool_calls

    def extract_tool_calls_openai(self, response: dict) -> list[ToolCall]:
        """Extract tool calls from OpenAI API response."""
        tool_calls = []

        choices = response.get("choices", [])
        for choice in choices:
            message = choice.get("message", {})
            for tc in message.get("tool_calls", []):
                func = tc.get("function", {})
                try:
                    args = json.loads(func.get("arguments", "{}"))
                except json.JSONDecodeError:
                    args = {"_raw": func.get("arguments", "")}

                tool_calls.append(ToolCall(
                    id=tc.get("id", ""),
                    name=func.get("name", ""),
                    input=args,
                    provider=LLMProvider.OPENAI,
                ))

        return tool_calls

    def extract_tool_calls(self, response: dict, provider: LLMProvider) -> list[ToolCall]:
        """Extract tool calls from an LLM API response."""
        if provider == LLMProvider.ANTHROPIC:
            return self.extract_tool_calls_anthropic(response)
        elif provider == LLMProvider.OPENAI:
            return self.extract_tool_calls_openai(response)
        else:
            return []

    def screen_tool_call(self, tool_call: ToolCall) -> InterceptionResult:
        """Screen a single tool call for security threats."""
        if not self.pattern_matcher:
            return InterceptionResult(allowed=True, provider=tool_call.provider)

        # Build command string for pattern matching
        # Handle common tool patterns
        command = ""
        tool_name = tool_call.name.lower()

        if tool_name in ("bash", "shell", "execute", "run_command"):
            command = tool_call.input.get("command", "")
        elif tool_name in ("read", "read_file", "cat"):
            command = f"cat {tool_call.input.get('path', tool_call.input.get('file_path', ''))}"
        elif tool_name in ("write", "write_file"):
            path = tool_call.input.get('path', tool_call.input.get('file_path', ''))
            command = f"write to {path}"
        elif tool_name in ("fetch", "web_fetch", "curl", "http"):
            url = tool_call.input.get('url', '')
            command = f"curl {url}"
        else:
            # Generic: serialize input for pattern matching
            command = json.dumps(tool_call.input)

        # Run through pattern matcher
        matches = self.pattern_matcher.match(command)

        if matches:
            # Log the blocked attempt
            if self.security_logger:
                self.security_logger.log_event(
                    event_type="proxy_block",
                    tool=tool_call.name,
                    command=command[:500],  # Truncate for logging
                    patterns=matches,
                )

            return InterceptionResult(
                allowed=False,
                provider=tool_call.provider,
                reason=f"Blocked by patterns: {', '.join(matches)}",
                blocked_tools=[tool_call.name],
                matched_patterns=matches,
            )

        return InterceptionResult(allowed=True, provider=tool_call.provider)

    def screen_response(self, response_body: bytes, provider: LLMProvider) -> InterceptionResult:
        """
        Screen an LLM API response for dangerous tool calls.

        Args:
            response_body: Raw response body bytes
            provider: The LLM provider

        Returns:
            InterceptionResult with screening decision
        """
        try:
            response = json.loads(response_body)
        except json.JSONDecodeError:
            # Can't parse, allow through
            return InterceptionResult(allowed=True, provider=provider)

        tool_calls = self.extract_tool_calls(response, provider)

        if not tool_calls:
            return InterceptionResult(allowed=True, provider=provider)

        # Screen each tool call
        blocked_tools = []
        all_patterns = []
        all_warnings = []

        for tc in tool_calls:
            result = self.screen_tool_call(tc)
            if not result.allowed:
                blocked_tools.extend(result.blocked_tools)
                all_patterns.extend(result.matched_patterns)
            all_warnings.extend(result.warnings)

        if blocked_tools:
            return InterceptionResult(
                allowed=False,
                provider=provider,
                reason=f"Blocked dangerous tool calls: {', '.join(blocked_tools)}",
                blocked_tools=blocked_tools,
                matched_patterns=all_patterns,
                warnings=all_warnings,
            )

        return InterceptionResult(
            allowed=True,
            provider=provider,
            warnings=all_warnings,
        )

    def screen_request(self, request_body: bytes, provider: LLMProvider) -> InterceptionResult:
        """
        Screen an LLM API request for prompt injection attempts.

        Args:
            request_body: Raw request body bytes
            provider: The LLM provider

        Returns:
            InterceptionResult with screening decision
        """
        if not self.pattern_matcher:
            return InterceptionResult(allowed=True, provider=provider)

        try:
            request = json.loads(request_body)
        except json.JSONDecodeError:
            return InterceptionResult(allowed=True, provider=provider)

        # Extract user messages for screening
        messages = []

        if provider == LLMProvider.ANTHROPIC:
            messages = request.get("messages", [])
        elif provider == LLMProvider.OPENAI:
            messages = request.get("messages", [])

        # Screen each user message
        warnings = []

        for msg in messages:
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    # Check for prompt injection patterns
                    # Note: This is advisory only, we don't block requests
                    matches = self.pattern_matcher.match_prompt_injection(content)
                    if matches:
                        warnings.append(f"Potential prompt injection: {matches}")

        return InterceptionResult(
            allowed=True,  # Requests are allowed, just warned
            provider=provider,
            warnings=warnings,
        )
