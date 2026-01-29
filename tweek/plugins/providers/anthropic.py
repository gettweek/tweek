#!/usr/bin/env python3
"""
Tweek Anthropic Provider Plugin

Handles Anthropic Claude API format:
- Endpoint: api.anthropic.com
- Tool calls in content blocks with type="tool_use"
- Messages API format
"""

from typing import Optional, List, Dict, Any
from tweek.plugins.base import LLMProviderPlugin, ToolCall


class AnthropicProvider(LLMProviderPlugin):
    """
    Anthropic Claude API provider plugin.

    Supports:
    - Messages API (v1)
    - Tool use blocks
    - Streaming responses
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Anthropic Claude API provider"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["provider", "anthropic", "claude"]

    @property
    def name(self) -> str:
        return "anthropic"

    @property
    def api_hosts(self) -> List[str]:
        return [
            "api.anthropic.com",
        ]

    def extract_tool_calls(self, response: Dict[str, Any]) -> List[ToolCall]:
        """
        Extract tool calls from Anthropic API response.

        Anthropic format:
        {
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_xxx",
                    "name": "tool_name",
                    "input": {...}
                }
            ]
        }
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
        Extract text content from Anthropic API response.

        Concatenates all text blocks from the content array.
        """
        content = response.get("content", [])
        if not isinstance(content, list):
            return ""

        text_parts = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif isinstance(block, str):
                text_parts.append(block)

        return "\n".join(text_parts)

    def extract_messages(self, request: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract messages from Anthropic API request.

        Returns list of message dicts with role and content.
        """
        return request.get("messages", [])

    def get_system_prompt(self, request: Dict[str, Any]) -> Optional[str]:
        """Extract system prompt from request."""
        system = request.get("system")
        if isinstance(system, str):
            return system
        elif isinstance(system, list):
            # System can be array of content blocks
            parts = []
            for block in system:
                if isinstance(block, dict) and block.get("type") == "text":
                    parts.append(block.get("text", ""))
                elif isinstance(block, str):
                    parts.append(block)
            return "\n".join(parts)
        return None

    def is_streaming_response(self, response: Dict[str, Any]) -> bool:
        """Check if response is a streaming event."""
        return response.get("type") in (
            "message_start",
            "content_block_start",
            "content_block_delta",
            "content_block_stop",
            "message_delta",
            "message_stop",
        )

    def extract_streaming_tool_call(
        self,
        events: List[Dict[str, Any]]
    ) -> List[ToolCall]:
        """
        Extract tool calls from streaming events.

        Reassembles tool_use blocks from streaming deltas.
        """
        tool_calls = []
        current_tools: Dict[int, Dict[str, Any]] = {}

        for event in events:
            event_type = event.get("type")

            if event_type == "content_block_start":
                index = event.get("index", 0)
                block = event.get("content_block", {})
                if block.get("type") == "tool_use":
                    current_tools[index] = {
                        "id": block.get("id", ""),
                        "name": block.get("name", ""),
                        "input_json": "",
                    }

            elif event_type == "content_block_delta":
                index = event.get("index", 0)
                delta = event.get("delta", {})
                if delta.get("type") == "input_json_delta":
                    if index in current_tools:
                        current_tools[index]["input_json"] += delta.get("partial_json", "")

            elif event_type == "content_block_stop":
                index = event.get("index", 0)
                if index in current_tools:
                    tool_data = current_tools.pop(index)
                    try:
                        import json
                        input_dict = json.loads(tool_data["input_json"]) if tool_data["input_json"] else {}
                    except (json.JSONDecodeError, TypeError):
                        input_dict = {"_raw": tool_data["input_json"]}

                    tool_calls.append(ToolCall(
                        id=tool_data["id"],
                        name=tool_data["name"],
                        input=input_dict,
                        provider=self.name,
                    ))

        return tool_calls
