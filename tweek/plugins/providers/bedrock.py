#!/usr/bin/env python3
"""
Tweek AWS Bedrock Provider Plugin

Handles AWS Bedrock API format:
- Endpoint: bedrock-runtime.{region}.amazonaws.com
- Supports multiple underlying models (Claude, Titan, etc.)
- Converse API and InvokeModel API
"""

import re
from typing import Optional, List, Dict, Any
from tweek.plugins.base import LLMProviderPlugin, ToolCall


class BedrockProvider(LLMProviderPlugin):
    """
    AWS Bedrock API provider plugin.

    Supports:
    - Converse API (unified format)
    - InvokeModel API (model-specific formats)
    - Multiple model families (Anthropic, Amazon, Meta, etc.)
    """

    VERSION = "1.0.0"
    DESCRIPTION = "AWS Bedrock API provider"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["provider", "bedrock", "aws"]

    # Bedrock endpoint pattern
    ENDPOINT_PATTERN = re.compile(r"bedrock-runtime\.[\w-]+\.amazonaws\.com")

    @property
    def name(self) -> str:
        return "bedrock"

    @property
    def api_hosts(self) -> List[str]:
        # Bedrock uses regional endpoints
        # Return empty list - we use matches_endpoint for pattern matching
        return []

    def matches_endpoint(self, url: str) -> bool:
        """
        Check if URL matches Bedrock's regional endpoint pattern.
        """
        # Extract hostname
        if "://" in url:
            host = url.split("://")[1].split("/")[0]
        else:
            host = url.split("/")[0]

        host = host.split(":")[0]

        return bool(self.ENDPOINT_PATTERN.match(host))

    def extract_tool_calls(self, response: Dict[str, Any]) -> List[ToolCall]:
        """
        Extract tool calls from Bedrock API response.

        Supports both Converse API and model-specific formats.
        """
        tool_calls = []

        # Try Converse API format first
        tool_calls.extend(self._extract_converse_tool_calls(response))

        # Try Anthropic format (Claude on Bedrock)
        if not tool_calls:
            tool_calls.extend(self._extract_anthropic_tool_calls(response))

        return tool_calls

    def _extract_converse_tool_calls(
        self,
        response: Dict[str, Any]
    ) -> List[ToolCall]:
        """
        Extract tool calls from Converse API format.

        Converse API format:
        {
            "output": {
                "message": {
                    "content": [
                        {
                            "toolUse": {
                                "toolUseId": "xxx",
                                "name": "tool_name",
                                "input": {...}
                            }
                        }
                    ]
                }
            }
        }
        """
        tool_calls = []

        output = response.get("output", {})
        if not isinstance(output, dict):
            return tool_calls

        message = output.get("message", {})
        if not isinstance(message, dict):
            return tool_calls

        content = message.get("content", [])
        if not isinstance(content, list):
            return tool_calls

        for block in content:
            if not isinstance(block, dict):
                continue

            tool_use = block.get("toolUse")
            if isinstance(tool_use, dict):
                tool_calls.append(ToolCall(
                    id=tool_use.get("toolUseId", ""),
                    name=tool_use.get("name", ""),
                    input=tool_use.get("input", {}),
                    provider=self.name,
                    raw=tool_use,
                ))

        return tool_calls

    def _extract_anthropic_tool_calls(
        self,
        response: Dict[str, Any]
    ) -> List[ToolCall]:
        """
        Extract tool calls from Anthropic format (Claude on Bedrock).

        Uses the same format as Anthropic API.
        """
        tool_calls = []

        content = response.get("content", [])
        if not isinstance(content, list):
            return tool_calls

        for block in content:
            if not isinstance(block, dict):
                continue

            if block.get("type") == "tool_use":
                tool_calls.append(ToolCall(
                    id=block.get("id", ""),
                    name=block.get("name", ""),
                    input=block.get("input", {}),
                    provider=self.name,
                    raw=block,
                ))

        return tool_calls

    def extract_content(self, response: Dict[str, Any]) -> str:
        """
        Extract text content from Bedrock API response.
        """
        # Try Converse API format
        output = response.get("output", {})
        if isinstance(output, dict):
            message = output.get("message", {})
            if isinstance(message, dict):
                content = message.get("content", [])
                if isinstance(content, list):
                    text_parts = []
                    for block in content:
                        if isinstance(block, dict) and "text" in block:
                            text_parts.append(block["text"])
                    if text_parts:
                        return "\n".join(text_parts)

        # Try Anthropic format
        content = response.get("content", [])
        if isinstance(content, list):
            text_parts = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text_parts.append(block.get("text", ""))
            if text_parts:
                return "\n".join(text_parts)

        # Try Titan format
        results = response.get("results", [])
        if isinstance(results, list) and results:
            return results[0].get("outputText", "")

        return ""

    def extract_messages(self, request: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract messages from Bedrock API request.
        """
        # Converse API uses 'messages'
        messages = request.get("messages", [])
        if messages:
            return messages

        # InvokeModel with Anthropic format
        anthropic_messages = request.get("messages", [])
        if anthropic_messages:
            return anthropic_messages

        # InvokeModel with Titan format (prompt field)
        prompt = request.get("inputText") or request.get("prompt")
        if prompt:
            return [{"role": "user", "content": prompt}]

        return []

    def get_system_prompt(self, request: Dict[str, Any]) -> Optional[str]:
        """Extract system prompt from request."""
        # Converse API
        system = request.get("system")
        if isinstance(system, list):
            text_parts = []
            for block in system:
                if isinstance(block, dict) and "text" in block:
                    text_parts.append(block["text"])
            return "\n".join(text_parts) if text_parts else None
        elif isinstance(system, str):
            return system

        # Anthropic format on Bedrock
        anthropic_system = request.get("system")
        if isinstance(anthropic_system, str):
            return anthropic_system

        return None

    def get_model_id(self, request: Dict[str, Any]) -> Optional[str]:
        """
        Get the model ID from the request.

        For Bedrock, this is typically in the URL path, but may also
        be in the request body for some APIs.
        """
        return request.get("modelId")

    def is_streaming_response(self, response: Dict[str, Any]) -> bool:
        """Check if response is a streaming event."""
        # Bedrock streaming uses event types
        return "contentBlockDelta" in response or "contentBlockStart" in response
