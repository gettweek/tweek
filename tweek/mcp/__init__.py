#!/usr/bin/env python3
"""
Tweek MCP Security Gateway & Proxy

MCP (Model Context Protocol) integration for desktop LLM applications:
- Claude Desktop
- ChatGPT Desktop
- Gemini CLI
- VS Code (Continue.dev)

Two modes of operation:
- **Proxy** (recommended): Transparently wraps upstream MCP servers with
  security screening and human-in-the-loop approval. Tools keep their
  original names. Use: tweek mcp proxy
- **Gateway**: Exposes tweek_vault and tweek_status as new MCP tools for
  capabilities not available as built-in desktop client tools.
  Use: tweek mcp serve

Built-in desktop client tools (Bash, Read, Write, etc.) cannot be
intercepted via MCP — use CLI hooks for Claude Code, or the HTTP
proxy for Cursor/direct API calls.
"""

__all__ = ["create_server", "create_proxy"]
