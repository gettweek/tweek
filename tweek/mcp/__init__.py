#!/usr/bin/env python3
"""
Tweek MCP Security Gateway & Proxy

MCP (Model Context Protocol) server and proxy for security-screened
tool access from desktop LLM applications:
- Claude Desktop
- ChatGPT Desktop
- Gemini CLI
- VS Code (Continue.dev)

Two modes of operation:
- **Gateway**: Exposes 6 pre-screened tools directly (tweek mcp serve)
- **Proxy**: Transparently proxies upstream MCP servers with screening
  and human-in-the-loop approval (tweek mcp proxy)

All tool calls route through Tweek's shared screening engine, providing
the same defense-in-depth protection as CLI hooks and the HTTP proxy.
"""

__all__ = ["create_server", "create_proxy"]
