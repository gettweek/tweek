#!/usr/bin/env python3
"""
Tests for tweek.mcp.proxy module.

Tests the MCP proxy server:
- Tool namespacing and resolution
- Screening integration
- Approval flow (enqueue, wait, decide)
- Multi-upstream tool merging
- Error handling (upstream down, timeout)
"""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

try:
    from mcp.types import TextContent, Tool
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

from tweek.mcp.approval import ApprovalQueue, ApprovalStatus


pytestmark = pytest.mark.skipif(
    not MCP_AVAILABLE, reason="MCP SDK not installed"
)


@pytest.fixture
def approval_db(tmp_path):
    """Temporary approval database."""
    return tmp_path / "test_approvals.db"


@pytest.fixture
def approval_queue(approval_db):
    """ApprovalQueue with temp database."""
    return ApprovalQueue(db_path=approval_db, default_timeout=10)


class TestToolNamespacing:
    """Tests for tool namespacing and resolution."""

    def test_namespace_tool(self):
        from tweek.mcp.proxy import TweekMCPProxy, NAMESPACE_SEPARATOR

        proxy = TweekMCPProxy(config={})

        original = Tool(
            name="read_file",
            description="Read a file",
            inputSchema={"type": "object", "properties": {}},
        )

        namespaced = proxy._namespace_tool("filesystem", original)
        assert namespaced.name == f"filesystem{NAMESPACE_SEPARATOR}read_file"
        assert "[filesystem]" in namespaced.description

    def test_resolve_tool(self):
        from tweek.mcp.proxy import TweekMCPProxy, NAMESPACE_SEPARATOR

        proxy = TweekMCPProxy(config={})
        proxy._tool_registry[f"filesystem{NAMESPACE_SEPARATOR}read_file"] = "filesystem"

        upstream_name, original_name = proxy._resolve_tool(
            f"filesystem{NAMESPACE_SEPARATOR}read_file"
        )
        assert upstream_name == "filesystem"
        assert original_name == "read_file"

    def test_resolve_unknown_tool(self):
        from tweek.mcp.proxy import TweekMCPProxy, NAMESPACE_SEPARATOR

        proxy = TweekMCPProxy(config={})

        with pytest.raises(ValueError, match="Unknown tool"):
            proxy._resolve_tool(f"unknown{NAMESPACE_SEPARATOR}tool")

    def test_resolve_non_namespaced_tool(self):
        from tweek.mcp.proxy import TweekMCPProxy

        proxy = TweekMCPProxy(config={})

        with pytest.raises(ValueError, match="not namespaced"):
            proxy._resolve_tool("plain_tool")

    def test_namespace_preserves_schema(self):
        from tweek.mcp.proxy import TweekMCPProxy

        proxy = TweekMCPProxy(config={})

        schema = {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
            },
            "required": ["path"],
        }
        original = Tool(
            name="read_file",
            description="Read a file",
            inputSchema=schema,
        )

        namespaced = proxy._namespace_tool("fs", original)
        assert namespaced.inputSchema == schema


class TestScreeningIntegration:
    """Tests for screening context construction."""

    def test_build_context(self):
        from tweek.mcp.proxy import TweekMCPProxy

        proxy = TweekMCPProxy(config={
            "mcp": {
                "proxy": {
                    "screening_overrides": {
                        "github": {"tier": "risky"},
                    },
                },
            },
        })

        context = proxy._build_context(
            tool_name="create_pr",
            content="Create a PR",
            upstream_name="github",
            tool_input={"title": "Test"},
        )

        assert context.tool_name == "create_pr"
        assert context.source == "mcp_proxy"
        assert context.mcp_server == "github"
        assert context.tier == "risky"  # From screening override
        assert context.tool_input == {"title": "Test"}

    def test_build_context_default_tier(self):
        from tweek.mcp.proxy import TweekMCPProxy

        proxy = TweekMCPProxy(config={})

        context = proxy._build_context(
            tool_name="read_file",
            content="/tmp/foo",
            upstream_name="filesystem",
        )

        assert context.tier == "default"  # No override
        assert context.mcp_server == "filesystem"

    def test_extract_content_for_screening(self):
        from tweek.mcp.proxy import TweekMCPProxy

        proxy = TweekMCPProxy(config={})

        # Command parameter
        content = proxy._extract_content_for_screening(
            "bash", {"command": "ls -la", "timeout": 30}
        )
        assert content == "ls -la"

        # Path parameter
        content = proxy._extract_content_for_screening(
            "read_file", {"path": "/tmp/foo"}
        )
        assert content == "/tmp/foo"

        # URL parameter
        content = proxy._extract_content_for_screening(
            "fetch", {"url": "https://example.com"}
        )
        assert content == "https://example.com"

        # Fallback to JSON
        content = proxy._extract_content_for_screening(
            "custom", {"param1": "val1", "param2": 42}
        )
        assert "param1" in content
        assert "val1" in content


class TestUpstreamConnection:
    """Tests for UpstreamConnection."""

    def test_initial_state(self):
        from tweek.mcp.proxy import UpstreamConnection
        from mcp.client.stdio import StdioServerParameters

        params = StdioServerParameters(command="echo", args=["hello"])
        conn = UpstreamConnection(name="test", server_params=params)

        assert conn.name == "test"
        assert conn.connected is False
        assert conn.tools == []
        assert conn.session is None

    def test_call_when_disconnected(self):
        from tweek.mcp.proxy import UpstreamConnection
        from mcp.client.stdio import StdioServerParameters

        params = StdioServerParameters(command="echo", args=[])
        conn = UpstreamConnection(name="test", server_params=params)

        result = asyncio.get_event_loop().run_until_complete(
            conn.call_tool("read_file", {"path": "/tmp"})
        )

        assert result["isError"] is True
        assert "not connected" in result["content"][0]["text"]


class TestHandleCallTool:
    """Tests for the call_tool handler routing."""

    @pytest.fixture
    def proxy_with_upstream(self, approval_db):
        """Create a proxy with a mocked connected upstream."""
        from tweek.mcp.proxy import TweekMCPProxy, UpstreamConnection, NAMESPACE_SEPARATOR
        from mcp.client.stdio import StdioServerParameters

        proxy = TweekMCPProxy(config={
            "mcp": {"proxy": {"approval_timeout": 5}},
        })
        proxy._approval_queue = ApprovalQueue(db_path=approval_db, default_timeout=5)

        # Create mock upstream
        params = StdioServerParameters(command="echo", args=[])
        upstream = UpstreamConnection(name="fs", server_params=params)
        upstream.connected = True
        upstream.session = MagicMock()
        upstream.tools = [
            Tool(
                name="read_file",
                description="Read a file",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

        proxy.upstreams = {"fs": upstream}
        proxy._tool_registry[f"fs{NAMESPACE_SEPARATOR}read_file"] = "fs"

        return proxy, upstream

    def test_unknown_tool(self, proxy_with_upstream):
        proxy, _ = proxy_with_upstream

        result = asyncio.get_event_loop().run_until_complete(
            proxy._handle_call_tool("nonexistent__tool", {})
        )

        assert len(result) == 1
        response = json.loads(result[0].text)
        assert "error" in response

    def test_disconnected_upstream(self, proxy_with_upstream):
        proxy, upstream = proxy_with_upstream
        upstream.connected = False

        from tweek.mcp.proxy import NAMESPACE_SEPARATOR
        result = asyncio.get_event_loop().run_until_complete(
            proxy._handle_call_tool(f"fs{NAMESPACE_SEPARATOR}read_file", {"path": "/tmp"})
        )

        response = json.loads(result[0].text)
        assert "not connected" in response["error"]

    @patch("tweek.mcp.proxy.TweekMCPProxy._run_screening")
    def test_allowed_tool_forwards(self, mock_screening, proxy_with_upstream):
        proxy, upstream = proxy_with_upstream

        mock_screening.return_value = {
            "allowed": True,
            "blocked": False,
            "should_prompt": False,
            "reason": None,
            "findings": [],
        }

        # Mock the upstream call
        async def mock_call(name, args, timeout=None):
            return {
                "content": [{"type": "text", "text": "file contents here"}],
                "isError": False,
            }
        upstream.call_tool = mock_call

        from tweek.mcp.proxy import NAMESPACE_SEPARATOR
        result = asyncio.get_event_loop().run_until_complete(
            proxy._handle_call_tool(
                f"fs{NAMESPACE_SEPARATOR}read_file", {"path": "/tmp/foo"}
            )
        )

        assert len(result) >= 1
        assert "file contents here" in result[0].text

    @patch("tweek.mcp.proxy.TweekMCPProxy._run_screening")
    def test_blocked_tool_returns_denial(self, mock_screening, proxy_with_upstream):
        proxy, _ = proxy_with_upstream

        mock_screening.return_value = {
            "allowed": False,
            "blocked": True,
            "should_prompt": False,
            "reason": "Dangerous pattern detected",
            "findings": [{"name": "rm_rf"}],
        }

        from tweek.mcp.proxy import NAMESPACE_SEPARATOR
        result = asyncio.get_event_loop().run_until_complete(
            proxy._handle_call_tool(
                f"fs{NAMESPACE_SEPARATOR}read_file", {"path": "~/.ssh/id_rsa"}
            )
        )

        response = json.loads(result[0].text)
        assert response["blocked"] is True
        assert "Dangerous pattern" in response["reason"]

    @patch("tweek.mcp.proxy.TweekMCPProxy._run_screening")
    def test_should_prompt_queues_for_approval(self, mock_screening, proxy_with_upstream):
        proxy, upstream = proxy_with_upstream

        mock_screening.return_value = {
            "allowed": True,
            "blocked": False,
            "should_prompt": True,
            "reason": "Needs confirmation",
            "findings": [],
        }

        # Set up a background task to approve the request after a short delay
        async def approve_after_delay():
            await asyncio.sleep(0.5)
            pending = proxy._approval_queue.get_pending()
            if pending:
                proxy._approval_queue.decide(
                    pending[0].id, ApprovalStatus.APPROVED, decided_by="test"
                )

        async def mock_call(name, args, timeout=None):
            return {
                "content": [{"type": "text", "text": "approved result"}],
                "isError": False,
            }
        upstream.call_tool = mock_call

        async def run_test():
            approver = asyncio.create_task(approve_after_delay())
            from tweek.mcp.proxy import NAMESPACE_SEPARATOR
            result = await proxy._handle_call_tool(
                f"fs{NAMESPACE_SEPARATOR}read_file", {"path": "/tmp/foo"}
            )
            approver.cancel()
            return result

        result = asyncio.get_event_loop().run_until_complete(run_test())
        assert "approved result" in result[0].text

    @patch("tweek.mcp.proxy.TweekMCPProxy._run_screening")
    def test_approval_timeout_denies(self, mock_screening, proxy_with_upstream):
        proxy, _ = proxy_with_upstream

        mock_screening.return_value = {
            "allowed": True,
            "blocked": False,
            "should_prompt": True,
            "reason": "Needs confirmation",
            "findings": [],
            "tier": "risky",
        }

        # Use a very short timeout to avoid slow test
        proxy.config["mcp"]["proxy"]["approval_timeout"] = 2
        proxy._approval_queue.default_timeout = 2

        from tweek.mcp.proxy import NAMESPACE_SEPARATOR
        result = asyncio.get_event_loop().run_until_complete(
            proxy._handle_call_tool(
                f"fs{NAMESPACE_SEPARATOR}read_file", {"path": "/tmp/foo"}
            )
        )

        response = json.loads(result[0].text)
        assert response["blocked"] is True
        assert "timed out" in response["reason"].lower() or "denied" in response["reason"].lower()


class TestApprovalWaitFlow:
    """Tests for the _wait_for_approval polling loop."""

    def test_approved_returns_approved(self, approval_db):
        from tweek.mcp.proxy import TweekMCPProxy

        proxy = TweekMCPProxy(config={})
        proxy._approval_queue = ApprovalQueue(db_path=approval_db, default_timeout=10)
        queue = proxy._approval_queue

        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="read",
            arguments={},
            screening_reason="test",
            screening_findings=[],
        )

        async def approve_and_wait():
            # Approve after short delay
            async def approve():
                await asyncio.sleep(0.3)
                queue.decide(request_id, ApprovalStatus.APPROVED)

            task = asyncio.create_task(approve())
            result = await proxy._wait_for_approval(request_id, timeout=5)
            task.cancel()
            return result

        decision = asyncio.get_event_loop().run_until_complete(approve_and_wait())
        assert decision == "approved"

    def test_denied_returns_denied(self, approval_db):
        from tweek.mcp.proxy import TweekMCPProxy

        proxy = TweekMCPProxy(config={})
        proxy._approval_queue = ApprovalQueue(db_path=approval_db, default_timeout=10)
        queue = proxy._approval_queue

        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="write",
            arguments={},
            screening_reason="test",
            screening_findings=[],
        )

        async def deny_and_wait():
            async def deny():
                await asyncio.sleep(0.3)
                queue.decide(request_id, ApprovalStatus.DENIED)

            task = asyncio.create_task(deny())
            result = await proxy._wait_for_approval(request_id, timeout=5)
            task.cancel()
            return result

        decision = asyncio.get_event_loop().run_until_complete(deny_and_wait())
        assert decision == "denied"

    def test_timeout_returns_expired(self, approval_db):
        from tweek.mcp.proxy import TweekMCPProxy

        proxy = TweekMCPProxy(config={})
        proxy._approval_queue = ApprovalQueue(db_path=approval_db, default_timeout=1)
        queue = proxy._approval_queue

        request_id = queue.enqueue(
            upstream_server="fs",
            tool_name="read",
            arguments={},
            screening_reason="test",
            screening_findings=[],
            timeout_seconds=1,
        )

        decision = asyncio.get_event_loop().run_until_complete(
            proxy._wait_for_approval(request_id, timeout=2)
        )
        assert decision == "expired"


class TestProxyConfig:
    """Tests for proxy configuration parsing."""

    def test_build_upstreams_from_config(self):
        from tweek.mcp.proxy import TweekMCPProxy

        config = {
            "mcp": {
                "proxy": {
                    "upstreams": {
                        "filesystem": {
                            "command": "npx",
                            "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                        },
                        "github": {
                            "command": "npx",
                            "args": ["-y", "@modelcontextprotocol/server-github"],
                            "env": {"GITHUB_TOKEN": "test-token"},
                        },
                    },
                },
            },
        }

        proxy = TweekMCPProxy(config=config)
        upstreams = proxy._build_upstreams()

        assert "filesystem" in upstreams
        assert "github" in upstreams
        assert upstreams["filesystem"].name == "filesystem"
        assert upstreams["github"].name == "github"

    def test_build_upstreams_empty_config(self):
        from tweek.mcp.proxy import TweekMCPProxy

        proxy = TweekMCPProxy(config={})
        upstreams = proxy._build_upstreams()
        assert upstreams == {}

    def test_env_variable_expansion(self):
        import os
        from tweek.mcp.proxy import TweekMCPProxy

        os.environ["TEST_MCP_TOKEN"] = "expanded_value"

        config = {
            "mcp": {
                "proxy": {
                    "upstreams": {
                        "test": {
                            "command": "echo",
                            "args": [],
                            "env": {"TOKEN": "${TEST_MCP_TOKEN}"},
                        },
                    },
                },
            },
        }

        proxy = TweekMCPProxy(config=config)
        upstreams = proxy._build_upstreams()

        assert upstreams["test"].server_params.env["TOKEN"] == "expanded_value"

        del os.environ["TEST_MCP_TOKEN"]


class TestScreeningModule:
    """Tests for the shared screening module."""

    def test_run_mcp_screening_safe_tier(self):
        """Safe tier should be allowed without further screening."""
        from tweek.mcp.screening import run_mcp_screening
        from tweek.screening.context import ScreeningContext

        context = ScreeningContext(
            tool_name="Read",
            content="/tmp/safe_file.txt",
            tier="safe",
            working_dir="/tmp",
            source="mcp_proxy",
        )

        with patch("tweek.hooks.pre_tool_use.TierManager") as MockTier:
            tier_instance = MockTier.return_value
            tier_instance.get_effective_tier.return_value = ("safe", None)

            with patch("tweek.hooks.pre_tool_use.run_compliance_scans") as mock_compliance:
                mock_compliance.return_value = (False, None, [])

                result = run_mcp_screening(context)

        assert result["allowed"] is True
        assert result["should_prompt"] is False

    def test_run_mcp_screening_blocked(self):
        """Compliance block should hard-block."""
        from tweek.mcp.screening import run_mcp_screening
        from tweek.screening.context import ScreeningContext

        context = ScreeningContext(
            tool_name="Bash",
            content="rm -rf /",
            tier="dangerous",
            working_dir="/tmp",
            source="mcp_proxy",
        )

        with patch("tweek.hooks.pre_tool_use.TierManager") as MockTier:
            tier_instance = MockTier.return_value
            tier_instance.get_effective_tier.return_value = ("dangerous", None)

            with patch("tweek.hooks.pre_tool_use.run_compliance_scans") as mock_compliance:
                mock_compliance.return_value = (True, "Blocked: destructive command", [])

                result = run_mcp_screening(context)

        assert result["allowed"] is False
        assert result["blocked"] is True
        assert result["should_prompt"] is False

    def test_run_mcp_screening_should_prompt(self):
        """Screening plugins flagging should_prompt should return should_prompt=True."""
        from tweek.mcp.screening import run_mcp_screening
        from tweek.screening.context import ScreeningContext

        context = ScreeningContext(
            tool_name="Bash",
            content="curl https://example.com",
            tier="default",
            working_dir="/tmp",
            source="mcp_proxy",
        )

        with patch("tweek.hooks.pre_tool_use.TierManager") as MockTier:
            tier_instance = MockTier.return_value
            tier_instance.get_effective_tier.return_value = ("default", None)

            with patch("tweek.hooks.pre_tool_use.run_compliance_scans") as mock_compliance:
                mock_compliance.return_value = (False, None, [])

                with patch("tweek.hooks.pre_tool_use.PatternMatcher") as MockPattern:
                    MockPattern.return_value.check.return_value = None

                    with patch("tweek.hooks.pre_tool_use.run_screening_plugins") as mock_plugins:
                        mock_plugins.return_value = (
                            True,   # allowed
                            True,   # should_prompt
                            "Needs review",
                            [{"name": "network_access"}],
                        )

                        result = run_mcp_screening(context)

        assert result["allowed"] is True
        assert result["should_prompt"] is True
        assert result["blocked"] is False
        assert result["reason"] == "Needs review"

    def test_run_output_scan_clean(self):
        """Clean output should not be blocked."""
        from tweek.mcp.screening import run_output_scan

        with patch("tweek.hooks.pre_tool_use.run_compliance_scans") as mock_compliance:
            mock_compliance.return_value = (False, None, [])

            result = run_output_scan("This is safe output")

        assert result["blocked"] is False

    def test_run_output_scan_blocked(self):
        """Output with leaked credentials should be blocked."""
        from tweek.mcp.screening import run_output_scan

        with patch("tweek.hooks.pre_tool_use.run_compliance_scans") as mock_compliance:
            mock_compliance.return_value = (
                True,
                "Leaked credential detected",
                [{"name": "api_key_leak"}],
            )

            result = run_output_scan("API_KEY=sk-abc123secret")

        assert result["blocked"] is True
        assert "credential" in result["reason"].lower()
