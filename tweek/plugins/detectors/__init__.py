#!/usr/bin/env python3
"""
Tweek Tool Detector Plugins

Detector plugins identify installed LLM tools and IDEs:
- Moltbot: AI coding assistant
- Cursor: AI-powered IDE
- Continue.dev: VS Code AI extension
- Copilot: GitHub Copilot
- Windsurf: Codeium AI IDE

Detection helps:
- Identify proxy conflicts
- Configure appropriate protection
- Suggest integration options
"""

from tweek.plugins.detectors.moltbot import MoltbotDetector
from tweek.plugins.detectors.cursor import CursorDetector
from tweek.plugins.detectors.continue_dev import ContinueDetector
from tweek.plugins.detectors.copilot import CopilotDetector
from tweek.plugins.detectors.windsurf import WindsurfDetector

__all__ = [
    "MoltbotDetector",
    "CursorDetector",
    "ContinueDetector",
    "CopilotDetector",
    "WindsurfDetector",
]
