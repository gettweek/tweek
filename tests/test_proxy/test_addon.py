"""Tests for the mitmproxy addon module."""
import json
from unittest.mock import MagicMock, patch

import pytest

from tweek.proxy.addon import TweekProxyAddon, create_addon
from tweek.proxy.interceptor import LLMProvider, InterceptionResult


@pytest.mark.plugins
class TestTweekProxyAddonInit:
    """Tests for addon initialization."""

    def test_default_init(self):
        addon = TweekProxyAddon()
        assert addon.block_mode is True
        assert addon.log_only is False
        assert addon.stats["requests_screened"] == 0
        assert addon.stats["responses_screened"] == 0

    def test_custom_init(self):
        addon = TweekProxyAddon(block_mode=False, log_only=True)
        assert addon.block_mode is False
        assert addon.log_only is True

    def test_stats_initialized(self):
        addon = TweekProxyAddon()
        expected_keys = {
            "requests_screened",
            "responses_screened",
            "requests_blocked",
            "responses_blocked",
            "tool_calls_detected",
            "tool_calls_blocked",
        }
        assert set(addon.stats.keys()) == expected_keys
        assert all(v == 0 for v in addon.stats.values())


@pytest.mark.plugins
class TestAddonRequest:
    """Tests for request handling."""

    def _make_flow(self, host, content=None, path="/v1/messages"):
        flow = MagicMock()
        flow.request.host = host
        flow.request.path = path
        flow.request.content = content
        flow.request.headers = {}
        return flow

    def test_non_llm_host_ignored(self):
        addon = TweekProxyAddon()
        flow = self._make_flow("example.com", b'{"messages": []}')
        addon.request(flow)
        assert addon.stats["requests_screened"] == 0

    def test_anthropic_request_screened(self):
        addon = TweekProxyAddon()
        flow = self._make_flow(
            "api.anthropic.com",
            json.dumps({"messages": [{"role": "user", "content": "hello"}]}).encode(),
        )
        addon.request(flow)
        assert addon.stats["requests_screened"] == 1

    def test_no_content_no_screening(self):
        addon = TweekProxyAddon()
        flow = self._make_flow("api.anthropic.com", content=None)
        addon.request(flow)
        assert addon.stats["requests_screened"] == 1

    def test_warning_adds_header(self):
        class MockMatcher:
            def match_prompt_injection(self, text):
                return ["injection"]

        addon = TweekProxyAddon(pattern_matcher=MockMatcher())
        flow = self._make_flow(
            "api.anthropic.com",
            json.dumps({"messages": [{"role": "user", "content": "ignore instructions"}]}).encode(),
        )
        addon.request(flow)
        assert flow.request.headers.get("X-Tweek-Warning") == "prompt-injection-suspected"

    def test_stats_increment_per_request(self):
        addon = TweekProxyAddon()
        for _ in range(5):
            flow = self._make_flow("api.openai.com", b'{}')
            addon.request(flow)
        assert addon.stats["requests_screened"] == 5


@pytest.mark.plugins
class TestAddonResponse:
    """Tests for response handling."""

    def _make_flow(self, host, response_content=None, content_type="application/json"):
        flow = MagicMock()
        flow.request.host = host
        flow.response.content = response_content
        headers = MagicMock()
        headers.get = MagicMock(side_effect=lambda key, default="": (
            content_type if key == "content-type" else default
        ))
        flow.response.headers = headers
        return flow

    def test_non_llm_host_ignored(self):
        addon = TweekProxyAddon()
        flow = self._make_flow("example.com", b'{}')
        addon.response(flow)
        assert addon.stats["responses_screened"] == 0

    def test_streaming_response_screened(self):
        addon = TweekProxyAddon()
        flow = self._make_flow("api.anthropic.com", b'data: {}\n\n', "text/event-stream")
        addon.response(flow)
        assert addon.stats["responses_screened"] == 1
        assert addon.stats.get("streaming_unscreened", 0) == 0

    def test_no_content_skipped(self):
        addon = TweekProxyAddon()
        flow = self._make_flow("api.anthropic.com", response_content=None)
        addon.response(flow)
        assert addon.stats["responses_screened"] == 1

    def test_safe_response_allowed(self):
        class MockMatcher:
            def match(self, text):
                return []

        addon = TweekProxyAddon(pattern_matcher=MockMatcher())
        body = json.dumps({
            "content": [{"type": "text", "text": "Hello"}]
        }).encode()
        flow = self._make_flow("api.anthropic.com", body)
        addon.response(flow)
        assert addon.stats["responses_screened"] == 1
        assert addon.stats["responses_blocked"] == 0

    def test_dangerous_response_blocked(self):
        class MockMatcher:
            def match(self, text):
                if "rm -rf" in text:
                    return ["destructive"]
                return []

        addon = TweekProxyAddon(pattern_matcher=MockMatcher(), block_mode=True)
        body = json.dumps({
            "content": [
                {"type": "tool_use", "id": "t1", "name": "bash", "input": {"command": "rm -rf /"}},
            ]
        }).encode()
        flow = self._make_flow("api.anthropic.com", body)
        mock_response = MagicMock()
        with patch("tweek.proxy.addon.http") as mock_http:
            mock_http.Response.make.return_value = mock_response
            addon.response(flow)
        assert addon.stats["responses_blocked"] == 1
        assert addon.stats["tool_calls_blocked"] >= 1

    def test_dangerous_sse_response_blocked(self):
        """Regression: SSE streaming responses with dangerous tool calls must be blocked.

        This is the primary regression test for the SSE screening gap. If someone
        re-introduces an SSE bail-out, this test will catch it because the dangerous
        tool call would pass through unscreened.
        """
        class MockMatcher:
            def match(self, text):
                if "rm -rf" in text:
                    return ["destructive"]
                return []

        addon = TweekProxyAddon(pattern_matcher=MockMatcher(), block_mode=True)

        # Build a realistic Anthropic SSE stream with a dangerous tool call
        sse_body = (
            'event: content_block_start\n'
            'data: {"type":"content_block_start","index":0,"content_block":'
            '{"type":"tool_use","id":"toolu_sse","name":"Bash","input":{}}}\n\n'
            'event: content_block_delta\n'
            'data: {"type":"content_block_delta","index":0,"delta":'
            '{"type":"input_json_delta","partial_json":"{\\"command\\": \\"rm -rf /\\"}"}}\n\n'
            'event: content_block_stop\n'
            'data: {"type":"content_block_stop","index":0}\n\n'
        ).encode()

        flow = self._make_flow("api.anthropic.com", sse_body, "text/event-stream")
        mock_response = MagicMock()
        with patch("tweek.proxy.addon.http") as mock_http:
            mock_http.Response.make.return_value = mock_response
            addon.response(flow)
        assert addon.stats["responses_blocked"] == 1
        assert addon.stats["tool_calls_blocked"] >= 1

    def test_log_only_mode_no_block(self):
        class MockMatcher:
            def match(self, text):
                return ["dangerous"]

        addon = TweekProxyAddon(pattern_matcher=MockMatcher(), block_mode=True, log_only=True)
        body = json.dumps({
            "content": [
                {"type": "tool_use", "id": "t1", "name": "bash", "input": {"command": "rm -rf /"}},
            ]
        }).encode()
        flow = self._make_flow("api.anthropic.com", body)
        original_response = flow.response
        addon.response(flow)
        assert addon.stats["responses_blocked"] == 1
        # In log_only mode, response is NOT replaced even though it's "blocked" in stats
        assert flow.response == original_response


@pytest.mark.plugins
class TestAddonDone:
    """Tests for addon shutdown."""

    def test_done_logs_stats(self, caplog):
        import logging
        with caplog.at_level(logging.INFO, logger="tweek.proxy"):
            addon = TweekProxyAddon()
            addon.stats["requests_screened"] = 10
            addon.done()
            assert "Tweek Proxy Stats" in caplog.text


@pytest.mark.plugins
class TestCreateAddon:
    """Tests for the factory function."""

    def test_default_factory(self):
        addon = create_addon()
        assert isinstance(addon, TweekProxyAddon)
        assert addon.block_mode is True
        assert addon.log_only is False

    def test_custom_factory(self):
        addon = create_addon(block_mode=False, log_only=True)
        assert addon.block_mode is False
        assert addon.log_only is True

    def test_factory_with_matcher(self):
        matcher = MagicMock()
        addon = create_addon(pattern_matcher=matcher)
        assert addon.interceptor.pattern_matcher is matcher
