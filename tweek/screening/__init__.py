#!/usr/bin/env python3
"""
Tweek Screening Engine

Shared screening context and pipeline used by all interception layers:
- CLI Hooks (Claude Code)
- MCP Gateway (Claude Desktop, ChatGPT Desktop, Gemini CLI)
- HTTP Proxy (Cursor, Continue.dev, direct API calls)
"""

from tweek.screening.context import ScreeningContext

__all__ = ["ScreeningContext"]
