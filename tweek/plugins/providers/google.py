#!/usr/bin/env python3
"""
Tweek Google Gemini Provider Plugin

Handles Google Gemini API format:
- Endpoint: generativelanguage.googleapis.com
- Tool calls in functionCall parts
- GenerateContent API format
"""

from typing import Optional, List, Dict, Any
from tweek.plugins.base import LLMProviderPlugin, ToolCall


class GoogleProvider(LLMProviderPlugin):
    """
    Google Gemini API provider plugin.

    Supports:
    - GenerateContent API
    - Function calling
    - Multi-turn conversations
    """

    VERSION = "1.0.0"
    DESCRIPTION = "Google Gemini API provider"
    AUTHOR = "Tweek"
    REQUIRES_LICENSE = "free"
    TAGS = ["provider", "google", "gemini"]

    @property
    def name(self) -> str:
        return "google"

    @property
    def api_hosts(self) -> List[str]:
        return [
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com",  # Vertex AI
        ]

    def extract_tool_calls(self, response: Dict[str, Any]) -> List[ToolCall]:
        """
        Extract tool calls from Gemini API response.

        Gemini format:
        {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "functionCall": {
                                    "name": "tool_name",
                                    "args": {...}
                                }
                            }
                        ]
                    }
                }
            ]
        }
        """
        tool_calls = []

        candidates = response.get("candidates", [])
        if not isinstance(candidates, list):
            return tool_calls

        for idx, candidate in enumerate(candidates):
            if not isinstance(candidate, dict):
                continue

            content = candidate.get("content", {})
            if not isinstance(content, dict):
                continue

            parts = content.get("parts", [])
            if not isinstance(parts, list):
                continue

            for part_idx, part in enumerate(parts):
                if not isinstance(part, dict):
                    continue

                function_call = part.get("functionCall")
                if isinstance(function_call, dict):
                    tool_calls.append(ToolCall(
                        id=f"gemini_{idx}_{part_idx}",
                        name=function_call.get("name", ""),
                        input=function_call.get("args", {}),
                        provider=self.name,
                        raw=function_call,
                    ))

        return tool_calls

    def extract_content(self, response: Dict[str, Any]) -> str:
        """
        Extract text content from Gemini API response.
        """
        candidates = response.get("candidates", [])
        if not isinstance(candidates, list):
            return ""

        text_parts = []
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue

            content = candidate.get("content", {})
            if not isinstance(content, dict):
                continue

            parts = content.get("parts", [])
            if not isinstance(parts, list):
                continue

            for part in parts:
                if isinstance(part, dict) and "text" in part:
                    text_parts.append(part["text"])

        return "\n".join(text_parts)

    def extract_messages(self, request: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract messages from Gemini API request.

        Gemini uses 'contents' instead of 'messages'.
        """
        contents = request.get("contents", [])
        if not isinstance(contents, list):
            return []

        # Convert Gemini format to standard format
        messages = []
        for content in contents:
            if not isinstance(content, dict):
                continue

            role = content.get("role", "user")
            parts = content.get("parts", [])

            text_parts = []
            for part in parts:
                if isinstance(part, dict) and "text" in part:
                    text_parts.append(part["text"])
                elif isinstance(part, str):
                    text_parts.append(part)

            if text_parts:
                messages.append({
                    "role": role,
                    "content": "\n".join(text_parts)
                })

        return messages

    def get_system_prompt(self, request: Dict[str, Any]) -> Optional[str]:
        """Extract system instruction from request."""
        # Gemini uses systemInstruction
        system = request.get("systemInstruction")
        if isinstance(system, dict):
            parts = system.get("parts", [])
            text_parts = []
            for part in parts:
                if isinstance(part, dict) and "text" in part:
                    text_parts.append(part["text"])
            return "\n".join(text_parts) if text_parts else None
        elif isinstance(system, str):
            return system
        return None

    def is_streaming_response(self, response: Dict[str, Any]) -> bool:
        """Check if response is a streaming chunk."""
        # Gemini streaming sends candidates with partial content
        # and includes a 'usageMetadata' only in final chunk
        return "candidates" in response and "usageMetadata" not in response

    def extract_function_declarations(
        self,
        request: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Extract function declarations from request.

        Returns the tool definitions from the request.
        """
        tools = request.get("tools", [])
        declarations = []

        for tool in tools:
            if isinstance(tool, dict):
                func_decls = tool.get("functionDeclarations", [])
                declarations.extend(func_decls)

        return declarations
