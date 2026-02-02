"""
Tests for LLM provider plugins.

Tests all 5 provider plugins:
- AnthropicProvider
- OpenAIProvider
- AzureOpenAIProvider
- GoogleProvider
- BedrockProvider

Covers: extract_tool_calls, extract_content, extract_messages,
        extract_streaming_tool_call(s), is_streaming_response,
        matches_endpoint, and provider-specific methods.
"""

import pytest
from tweek.plugins.base import ToolCall
from tweek.plugins.providers.anthropic import AnthropicProvider
from tweek.plugins.providers.openai import OpenAIProvider
from tweek.plugins.providers.azure_openai import AzureOpenAIProvider
from tweek.plugins.providers.google import GoogleProvider
from tweek.plugins.providers.bedrock import BedrockProvider

pytestmark = pytest.mark.plugins


# =============================================================================
# ANTHROPIC PROVIDER TESTS
# =============================================================================

class TestAnthropicProvider:
    """Tests for Anthropic Claude API provider plugin."""

    @pytest.fixture
    def provider(self):
        return AnthropicProvider()

    # --- Metadata ---

    def test_provider_name(self, provider):
        """Test provider name is 'anthropic'."""
        assert provider.name == "anthropic"

    def test_api_hosts(self, provider):
        """Test API hosts include api.anthropic.com."""
        assert "api.anthropic.com" in provider.api_hosts

    def test_matches_endpoint_valid(self, provider):
        """Test matching a valid Anthropic endpoint URL."""
        assert provider.matches_endpoint("https://api.anthropic.com/v1/messages") is True

    def test_matches_endpoint_invalid(self, provider):
        """Test non-matching endpoint URL."""
        assert provider.matches_endpoint("https://api.openai.com/v1/chat/completions") is False

    def test_matches_endpoint_hostname_only(self, provider):
        """Test matching with bare hostname."""
        assert provider.matches_endpoint("api.anthropic.com") is True

    def test_matches_endpoint_with_port(self, provider):
        """Test matching URL with port strips the port."""
        assert provider.matches_endpoint("https://api.anthropic.com:443/v1/messages") is True

    # --- extract_tool_calls ---

    def test_extract_tool_calls_single(self, provider):
        """Test extracting a single tool_use block."""
        response = {
            "id": "msg_01ABC",
            "type": "message",
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_01XYZ",
                    "name": "bash",
                    "input": {"command": "ls -la"}
                }
            ],
            "model": "claude-sonnet-4-20250514",
            "stop_reason": "tool_use",
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].id == "toolu_01XYZ"
        assert calls[0].name == "bash"
        assert calls[0].input == {"command": "ls -la"}
        assert calls[0].provider == "anthropic"
        assert calls[0].raw is not None

    def test_extract_tool_calls_multiple(self, provider):
        """Test extracting multiple tool_use blocks."""
        response = {
            "content": [
                {
                    "type": "text",
                    "text": "I will run two commands."
                },
                {
                    "type": "tool_use",
                    "id": "toolu_01A",
                    "name": "bash",
                    "input": {"command": "pwd"}
                },
                {
                    "type": "tool_use",
                    "id": "toolu_01B",
                    "name": "read_file",
                    "input": {"path": "/tmp/test.py"}
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 2
        assert calls[0].name == "bash"
        assert calls[1].name == "read_file"

    def test_extract_tool_calls_no_tool_use(self, provider):
        """Test response with only text blocks returns no tool calls."""
        response = {
            "content": [
                {"type": "text", "text": "Hello, world!"}
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert calls == []

    def test_extract_tool_calls_empty_content(self, provider):
        """Test response with empty content list."""
        response = {"content": []}
        calls = provider.extract_tool_calls(response)
        assert calls == []

    def test_extract_tool_calls_missing_content(self, provider):
        """Test response with no content key."""
        response = {"id": "msg_01ABC", "type": "message"}
        calls = provider.extract_tool_calls(response)
        assert calls == []

    def test_extract_tool_calls_content_not_list(self, provider):
        """Test response where content is not a list."""
        response = {"content": "just a string"}
        calls = provider.extract_tool_calls(response)
        assert calls == []

    def test_extract_tool_calls_non_dict_block(self, provider):
        """Test content blocks that are not dicts are skipped."""
        response = {
            "content": [
                "a bare string",
                42,
                {"type": "tool_use", "id": "toolu_01C", "name": "bash", "input": {}}
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].name == "bash"

    def test_extract_tool_calls_missing_fields(self, provider):
        """Test tool_use block with missing id/name/input defaults gracefully."""
        response = {
            "content": [
                {"type": "tool_use"}
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].id == ""
        assert calls[0].name == ""
        assert calls[0].input == {}

    # --- extract_content ---

    def test_extract_content_text_block(self, provider):
        """Test extracting text from text blocks."""
        response = {
            "content": [
                {"type": "text", "text": "Hello, world!"}
            ]
        }
        assert provider.extract_content(response) == "Hello, world!"

    def test_extract_content_multiple_text_blocks(self, provider):
        """Test concatenation of multiple text blocks."""
        response = {
            "content": [
                {"type": "text", "text": "Line one"},
                {"type": "text", "text": "Line two"},
            ]
        }
        assert provider.extract_content(response) == "Line one\nLine two"

    def test_extract_content_mixed_blocks(self, provider):
        """Test that tool_use blocks are excluded from content."""
        response = {
            "content": [
                {"type": "text", "text": "I will use a tool."},
                {"type": "tool_use", "id": "toolu_01A", "name": "bash", "input": {}},
            ]
        }
        assert provider.extract_content(response) == "I will use a tool."

    def test_extract_content_string_blocks(self, provider):
        """Test that bare string content blocks are included."""
        response = {
            "content": ["bare string content"]
        }
        assert provider.extract_content(response) == "bare string content"

    def test_extract_content_empty(self, provider):
        """Test empty content list returns empty string."""
        response = {"content": []}
        assert provider.extract_content(response) == ""

    def test_extract_content_missing_key(self, provider):
        """Test missing content key returns empty string."""
        response = {}
        assert provider.extract_content(response) == ""

    def test_extract_content_not_list(self, provider):
        """Test content that is not a list returns empty string."""
        response = {"content": "not a list"}
        assert provider.extract_content(response) == ""

    # --- extract_messages ---

    def test_extract_messages(self, provider):
        """Test extracting messages from request."""
        request = {
            "model": "claude-sonnet-4-20250514",
            "messages": [
                {"role": "user", "content": "Hello"},
                {"role": "assistant", "content": "Hi!"},
            ]
        }
        messages = provider.extract_messages(request)
        assert len(messages) == 2
        assert messages[0]["role"] == "user"
        assert messages[1]["role"] == "assistant"

    def test_extract_messages_empty(self, provider):
        """Test request with no messages."""
        request = {"model": "claude-sonnet-4-20250514"}
        assert provider.extract_messages(request) == []

    # --- get_system_prompt ---

    def test_get_system_prompt_string(self, provider):
        """Test extracting system prompt as a string."""
        request = {
            "system": "You are a helpful assistant.",
            "messages": []
        }
        assert provider.get_system_prompt(request) == "You are a helpful assistant."

    def test_get_system_prompt_list(self, provider):
        """Test extracting system prompt as content block list."""
        request = {
            "system": [
                {"type": "text", "text": "You are a helpful assistant."},
                {"type": "text", "text": "Always be concise."},
            ],
            "messages": []
        }
        assert provider.get_system_prompt(request) == "You are a helpful assistant.\nAlways be concise."

    def test_get_system_prompt_list_with_strings(self, provider):
        """Test system prompt list with bare strings."""
        request = {
            "system": ["You are helpful."],
            "messages": []
        }
        assert provider.get_system_prompt(request) == "You are helpful."

    def test_get_system_prompt_missing(self, provider):
        """Test request with no system prompt."""
        request = {"messages": []}
        assert provider.get_system_prompt(request) is None

    # --- is_streaming_response ---

    def test_is_streaming_response_message_start(self, provider):
        """Test message_start streaming event."""
        event = {"type": "message_start", "message": {"id": "msg_01A"}}
        assert provider.is_streaming_response(event) is True

    def test_is_streaming_response_content_block_start(self, provider):
        """Test content_block_start streaming event."""
        event = {"type": "content_block_start", "index": 0}
        assert provider.is_streaming_response(event) is True

    def test_is_streaming_response_content_block_delta(self, provider):
        """Test content_block_delta streaming event."""
        event = {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta"}}
        assert provider.is_streaming_response(event) is True

    def test_is_streaming_response_content_block_stop(self, provider):
        """Test content_block_stop streaming event."""
        event = {"type": "content_block_stop", "index": 0}
        assert provider.is_streaming_response(event) is True

    def test_is_streaming_response_message_delta(self, provider):
        """Test message_delta streaming event."""
        event = {"type": "message_delta", "delta": {"stop_reason": "end_turn"}}
        assert provider.is_streaming_response(event) is True

    def test_is_streaming_response_message_stop(self, provider):
        """Test message_stop streaming event."""
        event = {"type": "message_stop"}
        assert provider.is_streaming_response(event) is True

    def test_is_streaming_response_non_streaming(self, provider):
        """Test non-streaming response returns False."""
        response = {"type": "message", "content": []}
        assert provider.is_streaming_response(response) is False

    def test_is_streaming_response_no_type(self, provider):
        """Test response with no type field."""
        response = {"content": []}
        assert provider.is_streaming_response(response) is False

    # --- extract_streaming_tool_call ---

    def test_extract_streaming_tool_call_complete(self, provider):
        """Test reassembling a tool call from streaming events."""
        events = [
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "toolu_01STREAM",
                    "name": "bash",
                }
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {
                    "type": "input_json_delta",
                    "partial_json": '{"comma'
                }
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {
                    "type": "input_json_delta",
                    "partial_json": 'nd": "ls"}'
                }
            },
            {
                "type": "content_block_stop",
                "index": 0,
            }
        ]
        calls = provider.extract_streaming_tool_call(events)
        assert len(calls) == 1
        assert calls[0].id == "toolu_01STREAM"
        assert calls[0].name == "bash"
        assert calls[0].input == {"command": "ls"}
        assert calls[0].provider == "anthropic"

    def test_extract_streaming_tool_call_multiple(self, provider):
        """Test reassembling multiple tool calls from streaming events."""
        events = [
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "tool_use", "id": "toolu_A", "name": "bash"}
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": '{"command": "pwd"}'}
            },
            {
                "type": "content_block_stop",
                "index": 0,
            },
            {
                "type": "content_block_start",
                "index": 1,
                "content_block": {"type": "tool_use", "id": "toolu_B", "name": "read_file"}
            },
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": '{"path": "/tmp/x"}'}
            },
            {
                "type": "content_block_stop",
                "index": 1,
            },
        ]
        calls = provider.extract_streaming_tool_call(events)
        assert len(calls) == 2
        assert calls[0].name == "bash"
        assert calls[1].name == "read_file"

    def test_extract_streaming_tool_call_malformed_json(self, provider):
        """Test streaming tool call with malformed JSON falls back to _raw."""
        events = [
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "tool_use", "id": "toolu_BAD", "name": "bash"}
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": '{"broken: json'}
            },
            {
                "type": "content_block_stop",
                "index": 0,
            },
        ]
        calls = provider.extract_streaming_tool_call(events)
        assert len(calls) == 1
        assert "_raw" in calls[0].input
        assert calls[0].input["_raw"] == '{"broken: json'

    def test_extract_streaming_tool_call_empty_input(self, provider):
        """Test streaming tool call with no input JSON produces empty dict."""
        events = [
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "tool_use", "id": "toolu_EMPTY", "name": "noop"}
            },
            {
                "type": "content_block_stop",
                "index": 0,
            },
        ]
        calls = provider.extract_streaming_tool_call(events)
        assert len(calls) == 1
        assert calls[0].input == {}

    def test_extract_streaming_tool_call_text_blocks_ignored(self, provider):
        """Test that text streaming events are ignored by tool call extraction."""
        events = [
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""}
            },
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "Hello"}
            },
            {
                "type": "content_block_stop",
                "index": 0,
            },
        ]
        calls = provider.extract_streaming_tool_call(events)
        assert calls == []

    def test_extract_streaming_tool_call_empty_events(self, provider):
        """Test empty events list returns no tool calls."""
        calls = provider.extract_streaming_tool_call([])
        assert calls == []


# =============================================================================
# OPENAI PROVIDER TESTS
# =============================================================================

class TestOpenAIProvider:
    """Tests for OpenAI GPT API provider plugin."""

    @pytest.fixture
    def provider(self):
        return OpenAIProvider()

    # --- Metadata ---

    def test_provider_name(self, provider):
        """Test provider name is 'openai'."""
        assert provider.name == "openai"

    def test_api_hosts(self, provider):
        """Test API hosts include api.openai.com."""
        assert "api.openai.com" in provider.api_hosts

    def test_matches_endpoint_valid(self, provider):
        """Test matching a valid OpenAI endpoint URL."""
        assert provider.matches_endpoint("https://api.openai.com/v1/chat/completions") is True

    def test_matches_endpoint_invalid(self, provider):
        """Test non-matching endpoint URL."""
        assert provider.matches_endpoint("https://api.anthropic.com/v1/messages") is False

    # --- extract_tool_calls ---

    def test_extract_tool_calls_single(self, provider):
        """Test extracting a single tool call from OpenAI format."""
        response = {
            "id": "chatcmpl-ABC123",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_abc123",
                                "type": "function",
                                "function": {
                                    "name": "get_weather",
                                    "arguments": '{"location": "San Francisco", "unit": "celsius"}'
                                }
                            }
                        ]
                    },
                    "finish_reason": "tool_calls"
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].id == "call_abc123"
        assert calls[0].name == "get_weather"
        assert calls[0].input == {"location": "San Francisco", "unit": "celsius"}
        assert calls[0].provider == "openai"
        assert calls[0].raw is not None

    def test_extract_tool_calls_multiple(self, provider):
        """Test extracting multiple tool calls."""
        response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_001",
                                "type": "function",
                                "function": {
                                    "name": "read_file",
                                    "arguments": '{"path": "/tmp/a.txt"}'
                                }
                            },
                            {
                                "id": "call_002",
                                "type": "function",
                                "function": {
                                    "name": "write_file",
                                    "arguments": '{"path": "/tmp/b.txt", "content": "hello"}'
                                }
                            }
                        ]
                    }
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 2
        assert calls[0].name == "read_file"
        assert calls[1].name == "write_file"
        assert calls[1].input["content"] == "hello"

    def test_extract_tool_calls_legacy_function_call(self, provider):
        """Test extracting legacy function_call format."""
        response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "function_call": {
                            "name": "get_weather",
                            "arguments": '{"location": "NYC"}'
                        }
                    }
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].id == "function_call"
        assert calls[0].name == "get_weather"
        assert calls[0].input == {"location": "NYC"}

    def test_extract_tool_calls_malformed_arguments_json(self, provider):
        """Test tool call with invalid JSON arguments falls back to _raw."""
        response = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "id": "call_bad",
                                "type": "function",
                                "function": {
                                    "name": "some_tool",
                                    "arguments": "{not valid json"
                                }
                            }
                        ]
                    }
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].input == {"_raw": "{not valid json"}

    def test_extract_tool_calls_arguments_already_dict(self, provider):
        """Test tool call where arguments is already a dict (not JSON string)."""
        response = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "id": "call_dict",
                                "type": "function",
                                "function": {
                                    "name": "my_tool",
                                    "arguments": {"key": "value"}
                                }
                            }
                        ]
                    }
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].input == {"key": "value"}

    def test_extract_tool_calls_empty_choices(self, provider):
        """Test response with empty choices list."""
        response = {"choices": []}
        assert provider.extract_tool_calls(response) == []

    def test_extract_tool_calls_no_choices(self, provider):
        """Test response with no choices key."""
        response = {"id": "chatcmpl-ABC"}
        assert provider.extract_tool_calls(response) == []

    def test_extract_tool_calls_choices_not_list(self, provider):
        """Test response where choices is not a list."""
        response = {"choices": "not a list"}
        assert provider.extract_tool_calls(response) == []

    def test_extract_tool_calls_non_dict_choice(self, provider):
        """Test non-dict choice entries are skipped."""
        response = {"choices": ["not a dict"]}
        assert provider.extract_tool_calls(response) == []

    def test_extract_tool_calls_message_not_dict(self, provider):
        """Test choice with non-dict message is skipped."""
        response = {"choices": [{"message": "not a dict"}]}
        assert provider.extract_tool_calls(response) == []

    def test_extract_tool_calls_function_not_dict(self, provider):
        """Test tool_call with non-dict function is skipped."""
        response = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "id": "call_x",
                                "type": "function",
                                "function": "not_a_dict"
                            }
                        ]
                    }
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert calls == []

    def test_extract_tool_calls_non_dict_tool_call_entry(self, provider):
        """Test non-dict entries in tool_calls array are skipped."""
        response = {
            "choices": [
                {
                    "message": {
                        "tool_calls": ["not a dict"]
                    }
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert calls == []

    def test_extract_tool_calls_missing_tool_calls_key(self, provider):
        """Test message with no tool_calls key and no function_call."""
        response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Just text"
                    }
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert calls == []

    # --- extract_content ---

    def test_extract_content(self, provider):
        """Test extracting text content."""
        response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Hello, I am GPT."
                    }
                }
            ]
        }
        assert provider.extract_content(response) == "Hello, I am GPT."

    def test_extract_content_multiple_choices(self, provider):
        """Test extracting content from multiple choices."""
        response = {
            "choices": [
                {"message": {"content": "Response A"}},
                {"message": {"content": "Response B"}},
            ]
        }
        assert provider.extract_content(response) == "Response A\nResponse B"

    def test_extract_content_null_content(self, provider):
        """Test response with null content (tool call response)."""
        response = {
            "choices": [
                {"message": {"role": "assistant", "content": None}}
            ]
        }
        assert provider.extract_content(response) == ""

    def test_extract_content_empty_choices(self, provider):
        """Test empty choices returns empty string."""
        response = {"choices": []}
        assert provider.extract_content(response) == ""

    def test_extract_content_no_choices(self, provider):
        """Test missing choices returns empty string."""
        response = {}
        assert provider.extract_content(response) == ""

    def test_extract_content_choices_not_list(self, provider):
        """Test choices not a list returns empty string."""
        response = {"choices": "not a list"}
        assert provider.extract_content(response) == ""

    # --- extract_messages ---

    def test_extract_messages(self, provider):
        """Test extracting messages from request."""
        request = {
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Hello"},
            ]
        }
        messages = provider.extract_messages(request)
        assert len(messages) == 2
        assert messages[0]["role"] == "system"

    def test_extract_messages_empty(self, provider):
        """Test request with no messages."""
        request = {"model": "gpt-4o"}
        assert provider.extract_messages(request) == []

    # --- get_system_prompt ---

    def test_get_system_prompt_string(self, provider):
        """Test extracting system prompt from messages."""
        request = {
            "messages": [
                {"role": "system", "content": "You are a coding assistant."},
                {"role": "user", "content": "Help me"},
            ]
        }
        assert provider.get_system_prompt(request) == "You are a coding assistant."

    def test_get_system_prompt_content_array(self, provider):
        """Test system prompt with content array format."""
        request = {
            "messages": [
                {
                    "role": "system",
                    "content": [
                        {"type": "text", "text": "Part one."},
                        {"type": "text", "text": "Part two."},
                    ]
                }
            ]
        }
        assert provider.get_system_prompt(request) == "Part one.\nPart two."

    def test_get_system_prompt_no_system_message(self, provider):
        """Test request with no system message returns None."""
        request = {
            "messages": [
                {"role": "user", "content": "Hello"},
            ]
        }
        assert provider.get_system_prompt(request) is None

    def test_get_system_prompt_no_messages(self, provider):
        """Test request with no messages key returns None."""
        request = {}
        assert provider.get_system_prompt(request) is None

    # --- is_streaming_response ---

    def test_is_streaming_response_chunk(self, provider):
        """Test streaming chunk detection."""
        chunk = {
            "id": "chatcmpl-ABC",
            "object": "chat.completion.chunk",
            "choices": [{"delta": {"content": "Hi"}}]
        }
        assert provider.is_streaming_response(chunk) is True

    def test_is_streaming_response_non_streaming(self, provider):
        """Test non-streaming response detection."""
        response = {
            "id": "chatcmpl-ABC",
            "object": "chat.completion",
            "choices": [{"message": {"content": "Hi"}}]
        }
        assert provider.is_streaming_response(response) is False

    def test_is_streaming_response_no_object(self, provider):
        """Test response with no object field."""
        response = {"choices": []}
        assert provider.is_streaming_response(response) is False

    # --- extract_streaming_tool_calls ---

    def test_extract_streaming_tool_calls_complete(self, provider):
        """Test reassembling tool calls from streaming chunks."""
        chunks = [
            {
                "object": "chat.completion.chunk",
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_stream1",
                                    "type": "function",
                                    "function": {
                                        "name": "get_weather",
                                        "arguments": '{"loc'
                                    }
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "object": "chat.completion.chunk",
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "function": {
                                        "arguments": 'ation": "SF"}'
                                    }
                                }
                            ]
                        }
                    }
                ]
            },
        ]
        calls = provider.extract_streaming_tool_calls(chunks)
        assert len(calls) == 1
        assert calls[0].id == "call_stream1"
        assert calls[0].name == "get_weather"
        assert calls[0].input == {"location": "SF"}
        assert calls[0].provider == "openai"

    def test_extract_streaming_tool_calls_multiple(self, provider):
        """Test reassembling multiple tool calls from streaming chunks."""
        chunks = [
            {
                "object": "chat.completion.chunk",
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_A",
                                    "function": {"name": "tool_a", "arguments": '{"x": 1}'}
                                },
                                {
                                    "index": 1,
                                    "id": "call_B",
                                    "function": {"name": "tool_b", "arguments": '{"y": 2}'}
                                }
                            ]
                        }
                    }
                ]
            },
        ]
        calls = provider.extract_streaming_tool_calls(chunks)
        assert len(calls) == 2
        assert calls[0].name == "tool_a"
        assert calls[0].input == {"x": 1}
        assert calls[1].name == "tool_b"
        assert calls[1].input == {"y": 2}

    def test_extract_streaming_tool_calls_malformed_json(self, provider):
        """Test streaming tool call with malformed JSON."""
        chunks = [
            {
                "object": "chat.completion.chunk",
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_bad",
                                    "function": {
                                        "name": "bad_tool",
                                        "arguments": '{broken'
                                    }
                                }
                            ]
                        }
                    }
                ]
            },
        ]
        calls = provider.extract_streaming_tool_calls(chunks)
        assert len(calls) == 1
        assert calls[0].input == {"_raw": "{broken"}

    def test_extract_streaming_tool_calls_empty_arguments(self, provider):
        """Test streaming tool call with empty arguments."""
        chunks = [
            {
                "object": "chat.completion.chunk",
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_empty",
                                    "function": {"name": "noop"}
                                }
                            ]
                        }
                    }
                ]
            },
        ]
        calls = provider.extract_streaming_tool_calls(chunks)
        assert len(calls) == 1
        assert calls[0].input == {}

    def test_extract_streaming_tool_calls_empty_chunks(self, provider):
        """Test empty chunks list returns no tool calls."""
        assert provider.extract_streaming_tool_calls([]) == []

    def test_extract_streaming_tool_calls_non_dict_entries(self, provider):
        """Test non-dict entries in delta.tool_calls are skipped."""
        chunks = [
            {
                "choices": [
                    {
                        "delta": {
                            "tool_calls": ["not a dict"]
                        }
                    }
                ]
            },
        ]
        calls = provider.extract_streaming_tool_calls(chunks)
        assert calls == []


# =============================================================================
# AZURE OPENAI PROVIDER TESTS
# =============================================================================

class TestAzureOpenAIProvider:
    """Tests for Azure OpenAI API provider plugin."""

    @pytest.fixture
    def provider(self):
        return AzureOpenAIProvider()

    @pytest.fixture
    def provider_with_custom_hosts(self):
        return AzureOpenAIProvider(config={"custom_hosts": ["my-custom-host.example.com"]})

    # --- Metadata ---

    def test_provider_name(self, provider):
        """Test provider name is 'azure_openai'."""
        assert provider.name == "azure_openai"

    def test_api_hosts(self, provider):
        """Test API hosts include openai.azure.com."""
        assert "openai.azure.com" in provider.api_hosts

    # --- matches_endpoint ---

    def test_matches_endpoint_standard_azure(self, provider):
        """Test matching standard Azure OpenAI endpoint."""
        url = "https://my-resource.openai.azure.com/openai/deployments/gpt-4/chat/completions?api-version=2024-02-01"
        assert provider.matches_endpoint(url) is True

    def test_matches_endpoint_different_resource(self, provider):
        """Test matching a different Azure resource name."""
        url = "https://contoso-prod.openai.azure.com/openai/deployments/gpt-35-turbo/chat/completions"
        assert provider.matches_endpoint(url) is True

    def test_matches_endpoint_openai_path_pattern(self, provider):
        """Test matching /openai/ path pattern for custom domains."""
        url = "https://custom-domain.example.com/openai/deployments/model/chat/completions"
        assert provider.matches_endpoint(url) is True

    def test_matches_endpoint_non_azure(self, provider):
        """Test non-Azure endpoint does not match."""
        url = "https://api.openai.com/v1/chat/completions"
        assert provider.matches_endpoint(url) is False

    def test_matches_endpoint_custom_host(self, provider_with_custom_hosts):
        """Test matching custom host from config."""
        url = "https://my-custom-host.example.com/v1/chat"
        assert provider_with_custom_hosts.matches_endpoint(url) is True

    def test_matches_endpoint_bare_hostname(self, provider):
        """Test matching bare hostname without protocol."""
        url = "myresource.openai.azure.com"
        assert provider.matches_endpoint(url) is True

    def test_matches_endpoint_non_matching(self, provider):
        """Test completely unrelated URL does not match."""
        url = "https://example.com/api/v1/data"
        assert provider.matches_endpoint(url) is False

    # --- extract_tool_calls (same format as OpenAI) ---

    def test_extract_tool_calls_single(self, provider):
        """Test extracting a single tool call (OpenAI-compatible format)."""
        response = {
            "id": "chatcmpl-AZ123",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_az001",
                                "type": "function",
                                "function": {
                                    "name": "search_documents",
                                    "arguments": '{"query": "revenue Q4"}'
                                }
                            }
                        ]
                    },
                    "finish_reason": "tool_calls"
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].id == "call_az001"
        assert calls[0].name == "search_documents"
        assert calls[0].input == {"query": "revenue Q4"}
        assert calls[0].provider == "azure_openai"

    def test_extract_tool_calls_legacy_function_call(self, provider):
        """Test extracting legacy function_call format."""
        response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "function_call": {
                            "name": "get_data",
                            "arguments": '{"id": 42}'
                        }
                    }
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].id == "function_call"
        assert calls[0].name == "get_data"
        assert calls[0].provider == "azure_openai"

    def test_extract_tool_calls_malformed_json(self, provider):
        """Test malformed JSON arguments produce _raw fallback."""
        response = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "id": "call_bad",
                                "type": "function",
                                "function": {
                                    "name": "tool",
                                    "arguments": "not json at all"
                                }
                            }
                        ]
                    }
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].input == {"_raw": "not json at all"}

    def test_extract_tool_calls_empty(self, provider):
        """Test empty response."""
        response = {"choices": []}
        assert provider.extract_tool_calls(response) == []

    def test_extract_tool_calls_choices_not_list(self, provider):
        """Test choices not a list."""
        response = {"choices": "invalid"}
        assert provider.extract_tool_calls(response) == []

    # --- extract_content ---

    def test_extract_content(self, provider):
        """Test extracting text content."""
        response = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "Azure OpenAI response."
                    }
                }
            ]
        }
        assert provider.extract_content(response) == "Azure OpenAI response."

    def test_extract_content_empty(self, provider):
        """Test empty choices."""
        assert provider.extract_content({"choices": []}) == ""

    def test_extract_content_no_choices(self, provider):
        """Test missing choices key."""
        assert provider.extract_content({}) == ""

    # --- extract_messages ---

    def test_extract_messages(self, provider):
        """Test extracting messages from Azure OpenAI request."""
        request = {
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "What is Azure?"},
            ]
        }
        messages = provider.extract_messages(request)
        assert len(messages) == 2

    # --- get_system_prompt ---

    def test_get_system_prompt(self, provider):
        """Test extracting system prompt."""
        request = {
            "messages": [
                {"role": "system", "content": "Enterprise assistant."},
                {"role": "user", "content": "Hello"},
            ]
        }
        assert provider.get_system_prompt(request) == "Enterprise assistant."

    def test_get_system_prompt_content_array(self, provider):
        """Test system prompt with content array format."""
        request = {
            "messages": [
                {
                    "role": "system",
                    "content": [
                        {"type": "text", "text": "Part A"},
                        {"type": "text", "text": "Part B"},
                    ]
                }
            ]
        }
        assert provider.get_system_prompt(request) == "Part A\nPart B"

    def test_get_system_prompt_missing(self, provider):
        """Test no system prompt returns None."""
        request = {"messages": [{"role": "user", "content": "Hi"}]}
        assert provider.get_system_prompt(request) is None

    # --- get_deployment_name ---

    def test_get_deployment_name(self, provider):
        """Test extracting deployment name from Azure URL."""
        url = "https://myresource.openai.azure.com/openai/deployments/gpt-4o/chat/completions"
        assert provider.get_deployment_name(url) == "gpt-4o"

    def test_get_deployment_name_different_model(self, provider):
        """Test extracting different deployment name."""
        url = "https://prod.openai.azure.com/openai/deployments/gpt-35-turbo-16k/chat/completions"
        assert provider.get_deployment_name(url) == "gpt-35-turbo-16k"

    def test_get_deployment_name_no_deployments(self, provider):
        """Test URL without deployments path returns None."""
        url = "https://myresource.openai.azure.com/openai/chat/completions"
        assert provider.get_deployment_name(url) is None

    def test_get_deployment_name_empty_url(self, provider):
        """Test empty URL returns None."""
        assert provider.get_deployment_name("") is None

    # --- is_streaming_response ---

    def test_is_streaming_response_chunk(self, provider):
        """Test streaming chunk detection."""
        chunk = {"object": "chat.completion.chunk", "choices": []}
        assert provider.is_streaming_response(chunk) is True

    def test_is_streaming_response_non_streaming(self, provider):
        """Test non-streaming response."""
        response = {"object": "chat.completion", "choices": []}
        assert provider.is_streaming_response(response) is False

    # --- extract_streaming_tool_calls ---

    def test_extract_streaming_tool_calls(self, provider):
        """Test reassembling tool calls from streaming chunks."""
        chunks = [
            {
                "object": "chat.completion.chunk",
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_az_stream",
                                    "function": {
                                        "name": "azure_tool",
                                        "arguments": '{"key":'
                                    }
                                }
                            ]
                        }
                    }
                ]
            },
            {
                "object": "chat.completion.chunk",
                "choices": [
                    {
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "function": {
                                        "arguments": ' "value"}'
                                    }
                                }
                            ]
                        }
                    }
                ]
            },
        ]
        calls = provider.extract_streaming_tool_calls(chunks)
        assert len(calls) == 1
        assert calls[0].name == "azure_tool"
        assert calls[0].input == {"key": "value"}
        assert calls[0].provider == "azure_openai"

    def test_extract_streaming_tool_calls_empty(self, provider):
        """Test empty chunks list."""
        assert provider.extract_streaming_tool_calls([]) == []


# =============================================================================
# GOOGLE PROVIDER TESTS
# =============================================================================

class TestGoogleProvider:
    """Tests for Google Gemini API provider plugin."""

    @pytest.fixture
    def provider(self):
        return GoogleProvider()

    # --- Metadata ---

    def test_provider_name(self, provider):
        """Test provider name is 'google'."""
        assert provider.name == "google"

    def test_api_hosts(self, provider):
        """Test API hosts include Gemini and Vertex AI endpoints."""
        hosts = provider.api_hosts
        assert "generativelanguage.googleapis.com" in hosts
        assert "aiplatform.googleapis.com" in hosts

    def test_matches_endpoint_gemini(self, provider):
        """Test matching Gemini API endpoint."""
        url = "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent"
        assert provider.matches_endpoint(url) is True

    def test_matches_endpoint_vertex(self, provider):
        """Test matching Vertex AI endpoint."""
        url = "https://aiplatform.googleapis.com/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-pro:generateContent"
        assert provider.matches_endpoint(url) is True

    def test_matches_endpoint_invalid(self, provider):
        """Test non-matching endpoint."""
        assert provider.matches_endpoint("https://api.openai.com/v1/chat/completions") is False

    # --- extract_tool_calls ---

    def test_extract_tool_calls_single(self, provider):
        """Test extracting a single function call from Gemini format."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "functionCall": {
                                    "name": "get_weather",
                                    "args": {"location": "Tokyo", "unit": "celsius"}
                                }
                            }
                        ],
                        "role": "model"
                    },
                    "finishReason": "STOP"
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].id == "gemini_0_0"
        assert calls[0].name == "get_weather"
        assert calls[0].input == {"location": "Tokyo", "unit": "celsius"}
        assert calls[0].provider == "google"
        assert calls[0].raw is not None

    def test_extract_tool_calls_multiple_parts(self, provider):
        """Test extracting multiple function calls from multiple parts."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "functionCall": {
                                    "name": "search",
                                    "args": {"query": "AI news"}
                                }
                            },
                            {
                                "functionCall": {
                                    "name": "get_calendar",
                                    "args": {"date": "2024-01-15"}
                                }
                            }
                        ],
                        "role": "model"
                    }
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 2
        assert calls[0].name == "search"
        assert calls[0].id == "gemini_0_0"
        assert calls[1].name == "get_calendar"
        assert calls[1].id == "gemini_0_1"

    def test_extract_tool_calls_mixed_parts(self, provider):
        """Test that text parts are excluded, only functionCall parts extracted."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": "Let me check the weather."},
                            {
                                "functionCall": {
                                    "name": "get_weather",
                                    "args": {"location": "London"}
                                }
                            }
                        ],
                        "role": "model"
                    }
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].name == "get_weather"

    def test_extract_tool_calls_no_function_call(self, provider):
        """Test response with only text parts returns no tool calls."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": "Hello, how can I help?"}
                        ],
                        "role": "model"
                    }
                }
            ]
        }
        assert provider.extract_tool_calls(response) == []

    def test_extract_tool_calls_empty_candidates(self, provider):
        """Test empty candidates list."""
        response = {"candidates": []}
        assert provider.extract_tool_calls(response) == []

    def test_extract_tool_calls_no_candidates(self, provider):
        """Test missing candidates key."""
        response = {}
        assert provider.extract_tool_calls(response) == []

    def test_extract_tool_calls_candidates_not_list(self, provider):
        """Test candidates not a list."""
        response = {"candidates": "not a list"}
        assert provider.extract_tool_calls(response) == []

    def test_extract_tool_calls_non_dict_candidate(self, provider):
        """Test non-dict candidate entries are skipped."""
        response = {"candidates": ["not a dict"]}
        assert provider.extract_tool_calls(response) == []

    def test_extract_tool_calls_content_not_dict(self, provider):
        """Test candidate with non-dict content is skipped."""
        response = {"candidates": [{"content": "not a dict"}]}
        assert provider.extract_tool_calls(response) == []

    def test_extract_tool_calls_parts_not_list(self, provider):
        """Test content with non-list parts is skipped."""
        response = {"candidates": [{"content": {"parts": "not a list"}}]}
        assert provider.extract_tool_calls(response) == []

    def test_extract_tool_calls_non_dict_part(self, provider):
        """Test non-dict part entries are skipped."""
        response = {"candidates": [{"content": {"parts": ["not a dict"]}}]}
        assert provider.extract_tool_calls(response) == []

    def test_extract_tool_calls_missing_args(self, provider):
        """Test functionCall with missing args defaults to empty dict."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"functionCall": {"name": "no_args_tool"}}
                        ]
                    }
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].name == "no_args_tool"
        assert calls[0].input == {}

    # --- extract_content ---

    def test_extract_content(self, provider):
        """Test extracting text content from Gemini response."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": "Hello from Gemini!"}
                        ],
                        "role": "model"
                    }
                }
            ]
        }
        assert provider.extract_content(response) == "Hello from Gemini!"

    def test_extract_content_multiple_parts(self, provider):
        """Test extracting content from multiple text parts."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": "First part."},
                            {"text": "Second part."},
                        ]
                    }
                }
            ]
        }
        assert provider.extract_content(response) == "First part.\nSecond part."

    def test_extract_content_mixed_with_function_call(self, provider):
        """Test that functionCall parts are excluded from content."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {"text": "Calling a function."},
                            {"functionCall": {"name": "tool", "args": {}}}
                        ]
                    }
                }
            ]
        }
        assert provider.extract_content(response) == "Calling a function."

    def test_extract_content_empty(self, provider):
        """Test empty response returns empty string."""
        assert provider.extract_content({"candidates": []}) == ""
        assert provider.extract_content({}) == ""

    def test_extract_content_candidates_not_list(self, provider):
        """Test candidates not a list returns empty string."""
        assert provider.extract_content({"candidates": "invalid"}) == ""

    # --- extract_messages ---

    def test_extract_messages(self, provider):
        """Test extracting messages from Gemini request (contents format)."""
        request = {
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": "What is the weather in Tokyo?"}]
                },
                {
                    "role": "model",
                    "parts": [{"text": "Let me check."}]
                }
            ]
        }
        messages = provider.extract_messages(request)
        assert len(messages) == 2
        assert messages[0]["role"] == "user"
        assert messages[0]["content"] == "What is the weather in Tokyo?"
        assert messages[1]["role"] == "model"

    def test_extract_messages_string_parts(self, provider):
        """Test messages with string parts instead of dicts."""
        request = {
            "contents": [
                {
                    "role": "user",
                    "parts": ["Hello world"]
                }
            ]
        }
        messages = provider.extract_messages(request)
        assert len(messages) == 1
        assert messages[0]["content"] == "Hello world"

    def test_extract_messages_default_role(self, provider):
        """Test content without role defaults to 'user'."""
        request = {
            "contents": [
                {"parts": [{"text": "Question?"}]}
            ]
        }
        messages = provider.extract_messages(request)
        assert len(messages) == 1
        assert messages[0]["role"] == "user"

    def test_extract_messages_empty(self, provider):
        """Test request with no contents."""
        assert provider.extract_messages({}) == []

    def test_extract_messages_contents_not_list(self, provider):
        """Test contents not a list returns empty."""
        assert provider.extract_messages({"contents": "not a list"}) == []

    def test_extract_messages_non_dict_content(self, provider):
        """Test non-dict entries in contents are skipped."""
        request = {"contents": ["not a dict"]}
        assert provider.extract_messages(request) == []

    def test_extract_messages_no_text_parts(self, provider):
        """Test content with only functionCall parts is excluded from messages."""
        request = {
            "contents": [
                {
                    "role": "model",
                    "parts": [{"functionCall": {"name": "tool", "args": {}}}]
                }
            ]
        }
        messages = provider.extract_messages(request)
        assert messages == []

    # --- get_system_prompt ---

    def test_get_system_prompt_dict(self, provider):
        """Test extracting systemInstruction as dict with parts."""
        request = {
            "systemInstruction": {
                "parts": [
                    {"text": "You are a helpful assistant."},
                    {"text": "Be concise."},
                ]
            },
            "contents": []
        }
        assert provider.get_system_prompt(request) == "You are a helpful assistant.\nBe concise."

    def test_get_system_prompt_string(self, provider):
        """Test extracting systemInstruction as a string."""
        request = {
            "systemInstruction": "You are a coding assistant.",
            "contents": []
        }
        assert provider.get_system_prompt(request) == "You are a coding assistant."

    def test_get_system_prompt_missing(self, provider):
        """Test request without systemInstruction returns None."""
        request = {"contents": []}
        assert provider.get_system_prompt(request) is None

    def test_get_system_prompt_empty_parts(self, provider):
        """Test systemInstruction with empty parts returns None."""
        request = {
            "systemInstruction": {"parts": []},
            "contents": []
        }
        assert provider.get_system_prompt(request) is None

    # --- is_streaming_response ---

    def test_is_streaming_response_partial(self, provider):
        """Test streaming response (candidates present, no usageMetadata)."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": "partial content"}],
                        "role": "model"
                    }
                }
            ]
        }
        assert provider.is_streaming_response(response) is True

    def test_is_streaming_response_final_chunk(self, provider):
        """Test final chunk with usageMetadata is not considered streaming."""
        response = {
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": "final content"}],
                        "role": "model"
                    },
                    "finishReason": "STOP"
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 20,
                "totalTokenCount": 30
            }
        }
        assert provider.is_streaming_response(response) is False

    def test_is_streaming_response_no_candidates(self, provider):
        """Test response without candidates is not streaming."""
        response = {"error": {"code": 400, "message": "Bad request"}}
        assert provider.is_streaming_response(response) is False

    # --- extract_function_declarations ---

    def test_extract_function_declarations(self, provider):
        """Test extracting function declarations from request."""
        request = {
            "tools": [
                {
                    "functionDeclarations": [
                        {
                            "name": "get_weather",
                            "description": "Get weather for a location",
                            "parameters": {
                                "type": "OBJECT",
                                "properties": {
                                    "location": {"type": "STRING"}
                                }
                            }
                        },
                        {
                            "name": "search",
                            "description": "Search the web",
                            "parameters": {
                                "type": "OBJECT",
                                "properties": {
                                    "query": {"type": "STRING"}
                                }
                            }
                        }
                    ]
                }
            ],
            "contents": []
        }
        declarations = provider.extract_function_declarations(request)
        assert len(declarations) == 2
        assert declarations[0]["name"] == "get_weather"
        assert declarations[1]["name"] == "search"

    def test_extract_function_declarations_empty(self, provider):
        """Test request with no tools."""
        request = {"contents": []}
        assert provider.extract_function_declarations(request) == []

    def test_extract_function_declarations_multiple_tool_groups(self, provider):
        """Test multiple tool groups."""
        request = {
            "tools": [
                {"functionDeclarations": [{"name": "tool_a"}]},
                {"functionDeclarations": [{"name": "tool_b"}]},
            ]
        }
        declarations = provider.extract_function_declarations(request)
        assert len(declarations) == 2

    def test_extract_function_declarations_non_dict_tool(self, provider):
        """Test non-dict tool entries are skipped."""
        request = {"tools": ["not a dict"]}
        assert provider.extract_function_declarations(request) == []


# =============================================================================
# BEDROCK PROVIDER TESTS
# =============================================================================

class TestBedrockProvider:
    """Tests for AWS Bedrock API provider plugin."""

    @pytest.fixture
    def provider(self):
        return BedrockProvider()

    # --- Metadata ---

    def test_provider_name(self, provider):
        """Test provider name is 'bedrock'."""
        assert provider.name == "bedrock"

    def test_api_hosts_empty(self, provider):
        """Test API hosts is empty (uses pattern matching instead)."""
        assert provider.api_hosts == []

    # --- matches_endpoint ---

    def test_matches_endpoint_us_east_1(self, provider):
        """Test matching US East 1 endpoint."""
        url = "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-v2/invoke"
        assert provider.matches_endpoint(url) is True

    def test_matches_endpoint_eu_west_1(self, provider):
        """Test matching EU West 1 endpoint."""
        url = "https://bedrock-runtime.eu-west-1.amazonaws.com/model/amazon.titan-text-express-v1/invoke"
        assert provider.matches_endpoint(url) is True

    def test_matches_endpoint_ap_northeast(self, provider):
        """Test matching AP Northeast endpoint."""
        url = "https://bedrock-runtime.ap-northeast-1.amazonaws.com/model/anthropic.claude-3-sonnet/converse"
        assert provider.matches_endpoint(url) is True

    def test_matches_endpoint_bare_hostname(self, provider):
        """Test matching bare hostname without protocol."""
        assert provider.matches_endpoint("bedrock-runtime.us-west-2.amazonaws.com") is True

    def test_matches_endpoint_with_port(self, provider):
        """Test matching endpoint with port number."""
        url = "https://bedrock-runtime.us-east-1.amazonaws.com:443/model/invoke"
        assert provider.matches_endpoint(url) is True

    def test_matches_endpoint_non_bedrock(self, provider):
        """Test non-Bedrock AWS endpoint does not match."""
        url = "https://lambda.us-east-1.amazonaws.com/invoke"
        assert provider.matches_endpoint(url) is False

    def test_matches_endpoint_openai(self, provider):
        """Test OpenAI endpoint does not match."""
        url = "https://api.openai.com/v1/chat/completions"
        assert provider.matches_endpoint(url) is False

    def test_matches_endpoint_non_aws(self, provider):
        """Test completely unrelated URL does not match."""
        url = "https://example.com/api"
        assert provider.matches_endpoint(url) is False

    # --- extract_tool_calls (Converse API) ---

    def test_extract_tool_calls_converse_api(self, provider):
        """Test extracting tool calls from Converse API format."""
        response = {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "toolUse": {
                                "toolUseId": "tooluse_ABC123",
                                "name": "get_weather",
                                "input": {"location": "Seattle", "unit": "fahrenheit"}
                            }
                        }
                    ]
                }
            },
            "stopReason": "tool_use",
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].id == "tooluse_ABC123"
        assert calls[0].name == "get_weather"
        assert calls[0].input == {"location": "Seattle", "unit": "fahrenheit"}
        assert calls[0].provider == "bedrock"
        assert calls[0].raw is not None

    def test_extract_tool_calls_converse_multiple(self, provider):
        """Test extracting multiple tool calls from Converse API."""
        response = {
            "output": {
                "message": {
                    "content": [
                        {
                            "text": "Let me help with that."
                        },
                        {
                            "toolUse": {
                                "toolUseId": "tooluse_001",
                                "name": "read_file",
                                "input": {"path": "/tmp/data.csv"}
                            }
                        },
                        {
                            "toolUse": {
                                "toolUseId": "tooluse_002",
                                "name": "write_file",
                                "input": {"path": "/tmp/out.csv", "content": "data"}
                            }
                        }
                    ]
                }
            }
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 2
        assert calls[0].name == "read_file"
        assert calls[1].name == "write_file"

    def test_extract_tool_calls_converse_empty(self, provider):
        """Test Converse API response with no tool use blocks."""
        response = {
            "output": {
                "message": {
                    "content": [
                        {"text": "Just a text response."}
                    ]
                }
            }
        }
        calls = provider.extract_tool_calls(response)
        assert calls == []

    # --- extract_tool_calls (Anthropic format on Bedrock) ---

    def test_extract_tool_calls_anthropic_on_bedrock(self, provider):
        """Test extracting tool calls from Anthropic format (Claude on Bedrock)."""
        response = {
            "content": [
                {
                    "type": "text",
                    "text": "I will check that."
                },
                {
                    "type": "tool_use",
                    "id": "toolu_bedrock_01",
                    "name": "bash",
                    "input": {"command": "date"}
                }
            ],
            "stop_reason": "tool_use"
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].id == "toolu_bedrock_01"
        assert calls[0].name == "bash"
        assert calls[0].input == {"command": "date"}
        assert calls[0].provider == "bedrock"

    def test_extract_tool_calls_converse_takes_priority(self, provider):
        """Test that Converse API format is tried first; if found, Anthropic format is skipped."""
        response = {
            "output": {
                "message": {
                    "content": [
                        {
                            "toolUse": {
                                "toolUseId": "converse_tool",
                                "name": "converse_tool_name",
                                "input": {}
                            }
                        }
                    ]
                }
            },
            "content": [
                {
                    "type": "tool_use",
                    "id": "anthropic_tool",
                    "name": "anthropic_tool_name",
                    "input": {}
                }
            ]
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].name == "converse_tool_name"

    def test_extract_tool_calls_empty_response(self, provider):
        """Test completely empty response."""
        response = {}
        calls = provider.extract_tool_calls(response)
        assert calls == []

    def test_extract_tool_calls_output_not_dict(self, provider):
        """Test output not a dict is handled."""
        response = {"output": "not a dict"}
        calls = provider.extract_tool_calls(response)
        assert calls == []

    def test_extract_tool_calls_content_not_list(self, provider):
        """Test content not a list in both formats is handled."""
        response = {"output": {"message": {"content": "not a list"}}}
        calls = provider.extract_tool_calls(response)
        assert calls == []

    def test_extract_tool_calls_non_dict_block(self, provider):
        """Test non-dict blocks in content are skipped."""
        response = {
            "output": {
                "message": {
                    "content": ["not a dict", 42]
                }
            }
        }
        calls = provider.extract_tool_calls(response)
        assert calls == []

    def test_extract_tool_calls_missing_tool_use_fields(self, provider):
        """Test toolUse block with missing fields defaults gracefully."""
        response = {
            "output": {
                "message": {
                    "content": [
                        {"toolUse": {}}
                    ]
                }
            }
        }
        calls = provider.extract_tool_calls(response)
        assert len(calls) == 1
        assert calls[0].id == ""
        assert calls[0].name == ""
        assert calls[0].input == {}

    # --- extract_content ---

    def test_extract_content_converse(self, provider):
        """Test extracting text content from Converse API format."""
        response = {
            "output": {
                "message": {
                    "content": [
                        {"text": "Hello from Bedrock Converse!"}
                    ]
                }
            }
        }
        assert provider.extract_content(response) == "Hello from Bedrock Converse!"

    def test_extract_content_converse_multiple(self, provider):
        """Test extracting multiple text blocks from Converse API."""
        response = {
            "output": {
                "message": {
                    "content": [
                        {"text": "Line one."},
                        {"text": "Line two."},
                    ]
                }
            }
        }
        assert provider.extract_content(response) == "Line one.\nLine two."

    def test_extract_content_converse_mixed(self, provider):
        """Test that toolUse blocks are excluded from Converse content."""
        response = {
            "output": {
                "message": {
                    "content": [
                        {"text": "Some text."},
                        {"toolUse": {"toolUseId": "x", "name": "tool", "input": {}}}
                    ]
                }
            }
        }
        assert provider.extract_content(response) == "Some text."

    def test_extract_content_anthropic(self, provider):
        """Test extracting text content from Anthropic format on Bedrock."""
        response = {
            "content": [
                {"type": "text", "text": "Hello from Claude on Bedrock!"},
            ]
        }
        assert provider.extract_content(response) == "Hello from Claude on Bedrock!"

    def test_extract_content_anthropic_multiple(self, provider):
        """Test multiple text blocks in Anthropic format."""
        response = {
            "content": [
                {"type": "text", "text": "Part A"},
                {"type": "text", "text": "Part B"},
            ]
        }
        assert provider.extract_content(response) == "Part A\nPart B"

    def test_extract_content_titan(self, provider):
        """Test extracting text content from Amazon Titan format."""
        response = {
            "results": [
                {"outputText": "Hello from Titan!"}
            ]
        }
        assert provider.extract_content(response) == "Hello from Titan!"

    def test_extract_content_titan_empty_results(self, provider):
        """Test Titan format with empty results."""
        response = {"results": []}
        assert provider.extract_content(response) == ""

    def test_extract_content_empty(self, provider):
        """Test empty response returns empty string."""
        assert provider.extract_content({}) == ""

    def test_extract_content_converse_priority(self, provider):
        """Test Converse format takes priority over Anthropic format."""
        response = {
            "output": {
                "message": {
                    "content": [
                        {"text": "From Converse"}
                    ]
                }
            },
            "content": [
                {"type": "text", "text": "From Anthropic"}
            ]
        }
        assert provider.extract_content(response) == "From Converse"

    # --- extract_messages ---

    def test_extract_messages_converse(self, provider):
        """Test extracting messages from Converse API request."""
        request = {
            "messages": [
                {"role": "user", "content": [{"text": "Hello"}]},
                {"role": "assistant", "content": [{"text": "Hi!"}]},
            ]
        }
        messages = provider.extract_messages(request)
        assert len(messages) == 2
        assert messages[0]["role"] == "user"

    def test_extract_messages_titan_input_text(self, provider):
        """Test extracting messages from Titan format (inputText)."""
        request = {
            "inputText": "What is the capital of France?"
        }
        messages = provider.extract_messages(request)
        assert len(messages) == 1
        assert messages[0]["role"] == "user"
        assert messages[0]["content"] == "What is the capital of France?"

    def test_extract_messages_prompt_field(self, provider):
        """Test extracting messages from prompt field."""
        request = {
            "prompt": "Tell me a joke."
        }
        messages = provider.extract_messages(request)
        assert len(messages) == 1
        assert messages[0]["content"] == "Tell me a joke."

    def test_extract_messages_empty(self, provider):
        """Test empty request returns empty list."""
        assert provider.extract_messages({}) == []

    # --- get_system_prompt ---

    def test_get_system_prompt_converse_list(self, provider):
        """Test extracting system prompt from Converse API format (list)."""
        request = {
            "system": [
                {"text": "You are a helpful assistant."},
                {"text": "Be concise."},
            ],
            "messages": []
        }
        assert provider.get_system_prompt(request) == "You are a helpful assistant.\nBe concise."

    def test_get_system_prompt_string(self, provider):
        """Test extracting system prompt as a string."""
        request = {
            "system": "You are a coding expert.",
            "messages": []
        }
        assert provider.get_system_prompt(request) == "You are a coding expert."

    def test_get_system_prompt_missing(self, provider):
        """Test no system prompt returns None."""
        request = {"messages": []}
        assert provider.get_system_prompt(request) is None

    def test_get_system_prompt_empty_list(self, provider):
        """Test empty system list returns None."""
        request = {"system": [], "messages": []}
        assert provider.get_system_prompt(request) is None

    # --- get_model_id ---

    def test_get_model_id(self, provider):
        """Test extracting model ID from request."""
        request = {"modelId": "anthropic.claude-3-sonnet-20240229-v1:0"}
        assert provider.get_model_id(request) == "anthropic.claude-3-sonnet-20240229-v1:0"

    def test_get_model_id_missing(self, provider):
        """Test missing model ID returns None."""
        assert provider.get_model_id({}) is None

    # --- is_streaming_response ---

    def test_is_streaming_response_content_block_delta(self, provider):
        """Test contentBlockDelta streaming event."""
        event = {
            "contentBlockDelta": {
                "delta": {"text": "streaming text"},
                "contentBlockIndex": 0
            }
        }
        assert provider.is_streaming_response(event) is True

    def test_is_streaming_response_content_block_start(self, provider):
        """Test contentBlockStart streaming event."""
        event = {
            "contentBlockStart": {
                "start": {"text": ""},
                "contentBlockIndex": 0
            }
        }
        assert provider.is_streaming_response(event) is True

    def test_is_streaming_response_non_streaming(self, provider):
        """Test non-streaming response returns False."""
        response = {
            "output": {
                "message": {"content": [{"text": "Complete."}]}
            }
        }
        assert provider.is_streaming_response(response) is False

    def test_is_streaming_response_empty(self, provider):
        """Test empty response returns False."""
        assert provider.is_streaming_response({}) is False


# =============================================================================
# CROSS-PROVIDER TESTS
# =============================================================================

class TestProviderDetection:
    """Tests for provider detection via matches_endpoint across all providers."""

    @pytest.fixture
    def all_providers(self):
        return [
            AnthropicProvider(),
            OpenAIProvider(),
            AzureOpenAIProvider(),
            GoogleProvider(),
            BedrockProvider(),
        ]

    def test_anthropic_url_only_matches_anthropic(self, all_providers):
        """Test that Anthropic URL only matches Anthropic provider."""
        url = "https://api.anthropic.com/v1/messages"
        matches = [p.name for p in all_providers if p.matches_endpoint(url)]
        assert matches == ["anthropic"]

    def test_openai_url_only_matches_openai(self, all_providers):
        """Test that OpenAI URL only matches OpenAI provider."""
        url = "https://api.openai.com/v1/chat/completions"
        matches = [p.name for p in all_providers if p.matches_endpoint(url)]
        assert matches == ["openai"]

    def test_azure_url_matches_azure(self, all_providers):
        """Test that Azure OpenAI URL matches Azure provider."""
        url = "https://myresource.openai.azure.com/openai/deployments/gpt-4/chat/completions"
        matches = [p.name for p in all_providers if p.matches_endpoint(url)]
        assert "azure_openai" in matches

    def test_gemini_url_only_matches_google(self, all_providers):
        """Test that Gemini URL only matches Google provider."""
        url = "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent"
        matches = [p.name for p in all_providers if p.matches_endpoint(url)]
        assert matches == ["google"]

    def test_bedrock_url_only_matches_bedrock(self, all_providers):
        """Test that Bedrock URL only matches Bedrock provider."""
        url = "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-v2/invoke"
        matches = [p.name for p in all_providers if p.matches_endpoint(url)]
        assert matches == ["bedrock"]

    def test_unknown_url_matches_nothing(self, all_providers):
        """Test that an unknown URL matches no provider (except Azure /openai/ path)."""
        url = "https://example.com/api/v1/chat"
        matches = [p.name for p in all_providers if p.matches_endpoint(url)]
        assert matches == []

    def test_all_provider_names_unique(self, all_providers):
        """Test that all provider names are unique."""
        names = [p.name for p in all_providers]
        assert len(names) == len(set(names))


class TestToolCallDataclass:
    """Tests for the ToolCall dataclass itself."""

    def test_tool_call_creation(self):
        """Test creating a ToolCall with all fields."""
        tc = ToolCall(
            id="test_id",
            name="test_tool",
            input={"key": "value"},
            provider="test_provider",
            raw={"original": "data"},
        )
        assert tc.id == "test_id"
        assert tc.name == "test_tool"
        assert tc.input == {"key": "value"}
        assert tc.provider == "test_provider"
        assert tc.raw == {"original": "data"}

    def test_tool_call_default_raw(self):
        """Test that raw defaults to None."""
        tc = ToolCall(
            id="id",
            name="name",
            input={},
            provider="provider",
        )
        assert tc.raw is None

    def test_tool_call_equality(self):
        """Test that two ToolCalls with same fields are equal."""
        tc1 = ToolCall(id="a", name="b", input={"x": 1}, provider="p")
        tc2 = ToolCall(id="a", name="b", input={"x": 1}, provider="p")
        assert tc1 == tc2

    def test_tool_call_inequality(self):
        """Test that ToolCalls with different fields are not equal."""
        tc1 = ToolCall(id="a", name="b", input={}, provider="p")
        tc2 = ToolCall(id="a", name="c", input={}, provider="p")
        assert tc1 != tc2


class TestProviderConfiguration:
    """Tests for provider configuration and lifecycle."""

    def test_provider_default_config(self):
        """Test provider initializes with empty config by default."""
        provider = AnthropicProvider()
        assert provider._config == {}

    def test_provider_custom_config(self):
        """Test provider accepts custom config."""
        config = {"timeout": 30, "retry": 3}
        provider = OpenAIProvider(config=config)
        assert provider._config == config

    def test_provider_configure_updates(self):
        """Test configure method updates config."""
        provider = GoogleProvider()
        provider.configure({"max_tokens": 1000})
        assert provider._config["max_tokens"] == 1000

    def test_provider_configure_merges(self):
        """Test configure merges with existing config."""
        provider = BedrockProvider(config={"region": "us-east-1"})
        provider.configure({"model": "claude-3"})
        assert provider._config["region"] == "us-east-1"
        assert provider._config["model"] == "claude-3"

    def test_azure_provider_custom_hosts(self):
        """Test Azure provider accepts custom hosts via config."""
        provider = AzureOpenAIProvider(config={
            "custom_hosts": ["custom-ai.corp.example.com"]
        })
        assert "custom-ai.corp.example.com" in provider.api_hosts
        assert provider.matches_endpoint("https://custom-ai.corp.example.com/v1/chat") is True

    def test_azure_provider_no_config(self):
        """Test Azure provider works with no config."""
        provider = AzureOpenAIProvider()
        assert provider._custom_hosts == []

    def test_provider_class_metadata(self):
        """Test that all providers have expected class-level metadata."""
        providers = [
            AnthropicProvider(),
            OpenAIProvider(),
            AzureOpenAIProvider(),
            GoogleProvider(),
            BedrockProvider(),
        ]
        for p in providers:
            assert hasattr(p, "VERSION")
            assert hasattr(p, "DESCRIPTION")
            assert hasattr(p, "AUTHOR")
            assert hasattr(p, "REQUIRES_LICENSE")
            assert hasattr(p, "TAGS")
            assert "provider" in p.TAGS
            assert p.REQUIRES_LICENSE == "free"
            assert p.AUTHOR == "Tweek"
