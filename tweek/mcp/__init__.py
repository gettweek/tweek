#!/usr/bin/env python3
"""
Tweek MCP Security Proxy

MCP (Model Context Protocol) integration for desktop LLM applications:
- Claude Desktop
- ChatGPT Desktop
- Gemini CLI
- VS Code (Continue.dev)

Transparently wraps upstream MCP servers with security screening and
human-in-the-loop approval. Also provides built-in tweek_vault and
tweek_status tools alongside proxied upstream tools.

Use: tweek mcp proxy

Built-in desktop client tools (Bash, Read, Write, etc.) cannot be
intercepted via MCP — use CLI hooks for Claude Code, or the HTTP
proxy for Cursor/direct API calls.
"""

__all__ = ["create_proxy"]
