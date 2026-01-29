#!/usr/bin/env python3
"""
Tweek MCP Security Gateway

MCP (Model Context Protocol) server that provides security-screened tools
to desktop LLM applications:
- Claude Desktop
- ChatGPT Desktop
- Gemini CLI
- VS Code (Continue.dev)

All tool calls route through Tweek's shared screening engine, providing
the same defense-in-depth protection as CLI hooks and the HTTP proxy.
"""

__all__ = ["create_server"]
