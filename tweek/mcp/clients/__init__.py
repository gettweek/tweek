#!/usr/bin/env python3
"""
MCP Client Auto-Configuration

Handles installing and uninstalling Tweek as an MCP server
for various desktop LLM clients.
"""

from tweek.mcp.clients.claude_desktop import ClaudeDesktopClient
from tweek.mcp.clients.chatgpt import ChatGPTClient
from tweek.mcp.clients.gemini import GeminiClient

SUPPORTED_CLIENTS = {
    "claude-desktop": ClaudeDesktopClient,
    "chatgpt": ChatGPTClient,
    "gemini": GeminiClient,
}


def get_client(name: str):
    """Get a client configuration handler by name."""
    client_class = SUPPORTED_CLIENTS.get(name)
    if client_class is None:
        raise ValueError(
            f"Unknown client: {name}. "
            f"Supported: {', '.join(SUPPORTED_CLIENTS.keys())}"
        )
    return client_class()


__all__ = [
    "ClaudeDesktopClient",
    "ChatGPTClient",
    "GeminiClient",
    "SUPPORTED_CLIENTS",
    "get_client",
]
