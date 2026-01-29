#!/usr/bin/env python3
"""
Tweek LLM Provider Plugins

Provider plugins handle API-specific formats for different LLM providers:
- Anthropic (Claude)
- OpenAI (GPT)
- Azure OpenAI (GPT on Azure)
- Google (Gemini)
- AWS Bedrock

Each provider plugin knows how to:
- Identify API endpoints
- Extract tool calls from responses
- Parse request/response formats
"""

from tweek.plugins.providers.anthropic import AnthropicProvider
from tweek.plugins.providers.openai import OpenAIProvider
from tweek.plugins.providers.azure_openai import AzureOpenAIProvider
from tweek.plugins.providers.google import GoogleProvider
from tweek.plugins.providers.bedrock import BedrockProvider

__all__ = [
    "AnthropicProvider",
    "OpenAIProvider",
    "AzureOpenAIProvider",
    "GoogleProvider",
    "BedrockProvider",
]
