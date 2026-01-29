#!/usr/bin/env python3
"""
Tweek Azure OpenAI Provider Plugin

Handles Azure OpenAI API format:
- Endpoint: *.openai.azure.com
- Same tool call format as OpenAI (Azure uses OpenAI-compatible API)
- Supports custom deployment names
"""

import json
from typing import Optional, List, Dict, Any
from tweek.plugins.base import LLMProviderPlugin, ToolCall


class AzureOpenAIProvider(LLMProviderPlugin):
    """
    Azure OpenAI API provider plugin.

    Azure OpenAI uses the same API format as OpenAI but with:
    - Different endpoint structure (*.openai.azure.com)
    - Deployment-based model selection
    - Different API versioning scheme

    Supports:
    - Chat Completions API
    - Function calling (legacy)
    - Tool use (current)
    - Streaming responses
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Azure OpenAI API provider"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["provider", "azure", "openai", "enterprise"]

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        # Allow custom Azure endpoints via config
        self._custom_hosts = config.get("custom_hosts", []) if config else []

    @property
    def name(self) -> str:
        return "azure_openai"

    @property
    def api_hosts(self) -> List[str]:
        # Azure OpenAI endpoints follow pattern: *.openai.azure.com
        # Include common patterns plus any custom hosts
        default_hosts = [
            "openai.azure.com",  # Will match via matches_endpoint logic
        ]
        return default_hosts + self._custom_hosts

    def matches_endpoint(self, url: str) -> bool:
        """
        Check if URL matches Azure OpenAI API.

        Azure OpenAI uses endpoints like:
        - https://{resource-name}.openai.azure.com/...
        - https://{custom-domain}/openai/...
        """
        # Extract hostname from URL
        if "://" in url:
            host = url.split("://")[1].split("/")[0]
        else:
            host = url.split("/")[0]

        # Remove port if present
        host = host.split(":")[0]

        # Check for Azure OpenAI pattern (*.openai.azure.com)
        if host.endswith(".openai.azure.com"):
            return True

        # Check for /openai/ path pattern (Azure uses this)
        if "/openai/" in url:
            # Likely an Azure endpoint with custom domain
            return True

        # Check custom hosts
        return host in self._custom_hosts

    def extract_tool_calls(self, response: Dict[str, Any]) -> List[ToolCall]:
        """
        Extract tool calls from Azure OpenAI API response.

        Azure OpenAI uses the same format as OpenAI:
        {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "id": "call_xxx",
                                "type": "function",
                                "function": {
                                    "name": "tool_name",
                                    "arguments": "{...}"
                                }
                            }
                        ]
                    }
                }
            ]
        }
        """
        tool_calls = []

        choices = response.get("choices", [])
        if not isinstance(choices, list):
            return tool_calls

        for choice in choices:
            if not isinstance(choice, dict):
                continue

            message = choice.get("message", {})
            if not isinstance(message, dict):
                continue

            # Handle tool_calls (current format)
            for tc in message.get("tool_calls", []):
                if not isinstance(tc, dict):
                    continue

                func = tc.get("function", {})
                if not isinstance(func, dict):
                    continue

                # Parse arguments JSON
                args_str = func.get("arguments", "{}")
                try:
                    args = json.loads(args_str) if isinstance(args_str, str) else args_str
                except json.JSONDecodeError:
                    args = {"_raw": args_str}

                tool_calls.append(ToolCall(
                    id=tc.get("id", ""),
                    name=func.get("name", ""),
                    input=args if isinstance(args, dict) else {"_value": args},
                    provider=self.name,
                    raw=tc,
                ))

            # Handle function_call (legacy format)
            function_call = message.get("function_call")
            if isinstance(function_call, dict):
                args_str = function_call.get("arguments", "{}")
                try:
                    args = json.loads(args_str) if isinstance(args_str, str) else args_str
                except json.JSONDecodeError:
                    args = {"_raw": args_str}

                tool_calls.append(ToolCall(
                    id="function_call",
                    name=function_call.get("name", ""),
                    input=args if isinstance(args, dict) else {"_value": args},
                    provider=self.name,
                    raw=function_call,
                ))

        return tool_calls

    def extract_content(self, response: Dict[str, Any]) -> str:
        """
        Extract text content from Azure OpenAI API response.
        """
        choices = response.get("choices", [])
        if not isinstance(choices, list) or not choices:
            return ""

        content_parts = []
        for choice in choices:
            if not isinstance(choice, dict):
                continue

            message = choice.get("message", {})
            if isinstance(message, dict):
                content = message.get("content")
                if isinstance(content, str):
                    content_parts.append(content)

        return "\n".join(content_parts)

    def extract_messages(self, request: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract messages from Azure OpenAI API request.
        """
        return request.get("messages", [])

    def get_system_prompt(self, request: Dict[str, Any]) -> Optional[str]:
        """Extract system prompt from request."""
        messages = request.get("messages", [])
        for msg in messages:
            if isinstance(msg, dict) and msg.get("role") == "system":
                content = msg.get("content")
                if isinstance(content, str):
                    return content
                elif isinstance(content, list):
                    # Handle content array format
                    parts = []
                    for part in content:
                        if isinstance(part, dict) and part.get("type") == "text":
                            parts.append(part.get("text", ""))
                    return "\n".join(parts)
        return None

    def get_deployment_name(self, url: str) -> Optional[str]:
        """
        Extract deployment name from Azure OpenAI URL.

        Azure URLs follow pattern:
        https://{resource}.openai.azure.com/openai/deployments/{deployment}/chat/completions
        """
        try:
            parts = url.split("/")
            if "deployments" in parts:
                idx = parts.index("deployments")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
        except Exception:
            pass
        return None

    def is_streaming_response(self, response: Dict[str, Any]) -> bool:
        """Check if response is a streaming chunk."""
        # Streaming responses have 'object': 'chat.completion.chunk'
        return response.get("object") == "chat.completion.chunk"

    def extract_streaming_tool_calls(
        self,
        chunks: List[Dict[str, Any]]
    ) -> List[ToolCall]:
        """
        Extract tool calls from streaming chunks.

        Reassembles tool calls from delta chunks.
        """
        tool_calls: Dict[int, Dict[str, Any]] = {}

        for chunk in chunks:
            choices = chunk.get("choices", [])
            for choice in choices:
                if not isinstance(choice, dict):
                    continue

                delta = choice.get("delta", {})
                if not isinstance(delta, dict):
                    continue

                for tc in delta.get("tool_calls", []):
                    if not isinstance(tc, dict):
                        continue

                    index = tc.get("index", 0)

                    if index not in tool_calls:
                        tool_calls[index] = {
                            "id": tc.get("id", ""),
                            "name": "",
                            "arguments": "",
                        }

                    func = tc.get("function", {})
                    if isinstance(func, dict):
                        if func.get("name"):
                            tool_calls[index]["name"] = func["name"]
                        if func.get("arguments"):
                            tool_calls[index]["arguments"] += func["arguments"]

        # Convert to ToolCall objects
        result = []
        for index in sorted(tool_calls.keys()):
            tc_data = tool_calls[index]
            try:
                args = json.loads(tc_data["arguments"]) if tc_data["arguments"] else {}
            except json.JSONDecodeError:
                args = {"_raw": tc_data["arguments"]}

            result.append(ToolCall(
                id=tc_data["id"],
                name=tc_data["name"],
                input=args,
                provider=self.name,
            ))

        return result
