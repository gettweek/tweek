"""
LLM API Interceptor - Screens requests and responses to LLM APIs.

This module provides the core interception logic for the Tweek proxy,
analyzing LLM API traffic for security threats.
"""
from __future__ import annotations

import json
import re
import uuid
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

    def _new_correlation_id(self) -> str:
        """Generate a new correlation ID for a screening pass."""
        return uuid.uuid4().hex[:12]

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

    # ------------------------------------------------------------------
    # SSE (Server-Sent Events) streaming support
    # ------------------------------------------------------------------

    @staticmethod
    def parse_sse_events(body: bytes) -> list[dict]:
        """Parse a buffered SSE body into a list of JSON data payloads.

        Each SSE event is separated by a blank line.  We extract the
        ``data:`` field from each event and attempt to JSON-parse it.
        Non-JSON ``data: [DONE]`` sentinels are silently skipped.
        """
        text = body.decode("utf-8", errors="replace")
        events: list[dict] = []

        for block in text.split("\n\n"):
            for line in block.splitlines():
                if line.startswith("data:"):
                    payload = line[len("data:"):].strip()
                    if not payload or payload == "[DONE]":
                        continue
                    try:
                        events.append(json.loads(payload))
                    except json.JSONDecodeError:
                        continue
        return events

    def extract_tool_calls_anthropic_sse(self, events: list[dict]) -> list[ToolCall]:
        """Reassemble tool calls from Anthropic streaming events.

        Anthropic streams tool calls as:
          content_block_start  → type=tool_use, name, id
          content_block_delta  → input_json_delta with partial_json
          content_block_stop
        """
        # Track in-flight tool blocks by index
        pending: dict[int, dict] = {}  # index → {id, name, json_parts}

        tool_calls: list[ToolCall] = []

        for ev in events:
            ev_type = ev.get("type", "")

            if ev_type == "content_block_start":
                block = ev.get("content_block", {})
                if block.get("type") == "tool_use":
                    idx = ev.get("index", 0)
                    pending[idx] = {
                        "id": block.get("id", ""),
                        "name": block.get("name", ""),
                        "json_parts": [],
                    }

            elif ev_type == "content_block_delta":
                idx = ev.get("index", 0)
                delta = ev.get("delta", {})
                if delta.get("type") == "input_json_delta" and idx in pending:
                    pending[idx]["json_parts"].append(delta.get("partial_json", ""))

            elif ev_type == "content_block_stop":
                idx = ev.get("index", 0)
                if idx in pending:
                    info = pending.pop(idx)
                    raw_json = "".join(info["json_parts"])
                    try:
                        tool_input = json.loads(raw_json) if raw_json else {}
                    except json.JSONDecodeError:
                        tool_input = {"_raw": raw_json}
                    tool_calls.append(ToolCall(
                        id=info["id"],
                        name=info["name"],
                        input=tool_input,
                        provider=LLMProvider.ANTHROPIC,
                    ))

        # Flush any pending blocks that never got a stop event
        for info in pending.values():
            raw_json = "".join(info["json_parts"])
            try:
                tool_input = json.loads(raw_json) if raw_json else {}
            except json.JSONDecodeError:
                tool_input = {"_raw": raw_json}
            tool_calls.append(ToolCall(
                id=info["id"],
                name=info["name"],
                input=tool_input,
                provider=LLMProvider.ANTHROPIC,
            ))

        return tool_calls

    def extract_tool_calls_openai_sse(self, events: list[dict]) -> list[ToolCall]:
        """Reassemble tool calls from OpenAI Chat Completions streaming events.

        OpenAI streams tool calls as delta chunks inside choices[].delta.tool_calls[].
        The first chunk for each tool_call index carries the id and function.name.
        Subsequent chunks carry function.arguments fragments.
        """
        # Track in-flight tool calls by (choice_index, tool_call_index)
        pending: dict[tuple[int, int], dict] = {}

        for ev in events:
            for choice in ev.get("choices", []):
                delta = choice.get("delta", {})
                for tc in delta.get("tool_calls", []):
                    tc_idx = tc.get("index", 0)
                    key = (choice.get("index", 0), tc_idx)
                    func = tc.get("function", {})

                    if key not in pending:
                        pending[key] = {
                            "id": tc.get("id", ""),
                            "name": func.get("name", ""),
                            "arg_parts": [],
                        }
                    else:
                        # Update name/id if present (first chunk)
                        if tc.get("id"):
                            pending[key]["id"] = tc["id"]
                        if func.get("name"):
                            pending[key]["name"] = func["name"]

                    if func.get("arguments"):
                        pending[key]["arg_parts"].append(func["arguments"])

        tool_calls: list[ToolCall] = []
        for info in pending.values():
            raw_args = "".join(info["arg_parts"])
            try:
                tool_input = json.loads(raw_args) if raw_args else {}
            except json.JSONDecodeError:
                tool_input = {"_raw": raw_args}
            tool_calls.append(ToolCall(
                id=info["id"],
                name=info["name"],
                input=tool_input,
                provider=LLMProvider.OPENAI,
            ))

        return tool_calls

    def extract_tool_calls_sse(
        self, body: bytes, provider: LLMProvider
    ) -> list[ToolCall]:
        """Extract tool calls from a buffered SSE response body."""
        events = self.parse_sse_events(body)
        if not events:
            return []

        if provider == LLMProvider.ANTHROPIC:
            return self.extract_tool_calls_anthropic_sse(events)
        elif provider == LLMProvider.OPENAI:
            return self.extract_tool_calls_openai_sse(events)
        else:
            return []

    def screen_tool_call(self, tool_call: ToolCall) -> InterceptionResult:
        """Screen a single tool call for security threats."""
        if not self.pattern_matcher:
            return InterceptionResult(allowed=True, provider=tool_call.provider)

        # Normalize tool name and dispatch by capability
        from tweek.tools.registry import normalize as _normalize_tool, get_registry
        canonical = _normalize_tool(tool_call.name)
        capability = get_registry().get_capability(canonical)

        command = ""
        if capability == "shell_execution":
            command = tool_call.input.get("command", "")
        elif capability == "file_read":
            command = f"cat {tool_call.input.get('path', tool_call.input.get('file_path', ''))}"
        elif capability == "file_write":
            path = tool_call.input.get('path', tool_call.input.get('file_path', ''))
            command = f"write to {path}"
        elif capability == "web_fetch":
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

    def screen_response(
        self,
        response_body: bytes,
        provider: LLMProvider,
        is_sse: bool = False,
    ) -> InterceptionResult:
        """
        Screen an LLM API response for dangerous tool calls.

        Args:
            response_body: Raw response body bytes
            provider: The LLM provider
            is_sse: If True, parse body as SSE event stream instead of JSON.

        Returns:
            InterceptionResult with screening decision
        """
        correlation_id = self._new_correlation_id()

        if is_sse:
            tool_calls = self.extract_tool_calls_sse(response_body, provider)
        else:
            try:
                response = json.loads(response_body)
            except json.JSONDecodeError:
                # Not valid JSON — try SSE as fallback
                tool_calls = self.extract_tool_calls_sse(response_body, provider)
            else:
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
            self._log_proxy_event(
                "block", blocked_tools, all_patterns, provider, correlation_id
            )
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

    def _log_proxy_event(
        self,
        decision: str,
        blocked_tools: list,
        matched_patterns: list,
        provider: LLMProvider,
        correlation_id: str,
    ):
        """Log a proxy screening event to the security logger."""
        try:
            from tweek.logging.security_log import get_logger, SecurityEvent, EventType
            get_logger().log(SecurityEvent(
                event_type=EventType.PROXY_EVENT,
                tool_name="http_proxy",
                decision=decision,
                decision_reason=f"Blocked tools: {', '.join(blocked_tools)}" if blocked_tools else None,
                metadata={
                    "provider": provider.value,
                    "blocked_tools": blocked_tools,
                    "matched_patterns": matched_patterns,
                },
                correlation_id=correlation_id,
                source="http_proxy",
            ))
        except Exception:
            pass

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
