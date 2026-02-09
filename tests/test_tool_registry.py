"""
Tests for tweek.tools.registry — Cross-client tool name normalization.

Covers:
  - Canonical name passthrough (fast path)
  - Alias normalization for OpenClaw, Gemini CLI, Anthropic API
  - Case-insensitive matching
  - Unknown tool passthrough
  - Capability lookup
  - Alias retrieval
  - No duplicate aliases across capabilities
  - Singleton behavior
  - Integration with provenance, local_reviewer, and config manager
"""

import pytest

from tweek.tools.registry import (
    TOOL_CAPABILITIES,
    ToolCapability,
    ToolRegistry,
    get_registry,
    normalize,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def registry():
    """Fresh registry instance (not singleton)."""
    return ToolRegistry()


# ============================================================================
# Canonical Name Passthrough (fast path — no .lower() call)
# ============================================================================

@pytest.mark.parametrize("canonical", [
    "Bash", "Read", "Write", "Edit", "Glob", "Grep",
    "WebFetch", "WebSearch", "NotebookEdit", "Task", "Skill",
])
def test_canonical_passthrough(registry, canonical):
    """Canonical PascalCase names return unchanged (fast path)."""
    assert registry.normalize(canonical) == canonical


# ============================================================================
# OpenClaw Aliases
# ============================================================================

@pytest.mark.parametrize("alias,expected", [
    ("exec", "Bash"),
    ("read", "Read"),
    ("edit", "Edit"),
    ("write", "Write"),
    ("web_fetch", "WebFetch"),
    ("web_search", "WebSearch"),
])
def test_openclaw_aliases(registry, alias, expected):
    """OpenClaw snake_case tool names normalize correctly."""
    assert registry.normalize(alias) == expected


# ============================================================================
# Gemini CLI Aliases
# ============================================================================

@pytest.mark.parametrize("alias,expected", [
    ("run_shell_command", "Bash"),
    ("read_file", "Read"),
    ("write_file", "Write"),
    ("replace", "Edit"),
    ("grep_search", "Grep"),
    ("google_web_search", "WebSearch"),
    ("find_files", "Glob"),
])
def test_gemini_cli_aliases(registry, alias, expected):
    """Gemini CLI descriptive tool names normalize correctly."""
    assert registry.normalize(alias) == expected


# ============================================================================
# Anthropic API / Generic Aliases
# ============================================================================

@pytest.mark.parametrize("alias,expected", [
    ("bash", "Bash"),
    ("shell", "Bash"),
    ("cat", "Read"),
    ("curl", "WebFetch"),
    ("http", "WebFetch"),
    ("fetch", "WebFetch"),
    ("rg", "Grep"),
    ("ripgrep", "Grep"),
    ("sed", "Edit"),
    ("terminal", "Bash"),
    ("view_file", "Read"),
    ("create_file", "Write"),
    ("save_file", "Write"),
    ("edit_file", "Edit"),
    ("patch_file", "Edit"),
    ("url_fetch", "WebFetch"),
    ("browser", "WebFetch"),
    ("search_web", "WebSearch"),
    ("websearch", "WebSearch"),
    ("webfetch", "WebFetch"),
    ("notebookedit", "NotebookEdit"),
    ("notebook_edit", "NotebookEdit"),
    ("edit_notebook", "NotebookEdit"),
    ("task", "Task"),
    ("spawn_task", "Task"),
    ("subagent", "Task"),
    ("delegate", "Task"),
    ("skill", "Skill"),
    ("invoke_skill", "Skill"),
    ("use_skill", "Skill"),
])
def test_api_and_generic_aliases(registry, alias, expected):
    """Generic and API-level aliases normalize correctly."""
    assert registry.normalize(alias) == expected


# ============================================================================
# Case Insensitivity
# ============================================================================

@pytest.mark.parametrize("tool_name,expected", [
    ("BASH", "Bash"),
    ("RUN_SHELL_COMMAND", "Bash"),
    ("Read_File", "Read"),
    ("EXEC", "Bash"),
    ("Curl", "WebFetch"),
    ("GREP_SEARCH", "Grep"),
    ("GOOGLE_WEB_SEARCH", "WebSearch"),
    ("WebFetch", "WebFetch"),  # already canonical — fast path
])
def test_case_insensitive(registry, tool_name, expected):
    """Alias matching is case-insensitive."""
    assert registry.normalize(tool_name) == expected


# ============================================================================
# Unknown Tool Passthrough
# ============================================================================

@pytest.mark.parametrize("tool_name", [
    "MyCustomTool",
    "unknown_tool",
    "FooBar",
    "",
    "a_really_obscure_tool_name",
])
def test_unknown_passthrough(registry, tool_name):
    """Unknown tool names pass through unchanged."""
    assert registry.normalize(tool_name) == tool_name


# ============================================================================
# Capability Lookup
# ============================================================================

@pytest.mark.parametrize("tool_name,expected_cap", [
    ("Bash", "shell_execution"),
    ("exec", "shell_execution"),
    ("run_shell_command", "shell_execution"),
    ("Read", "file_read"),
    ("read_file", "file_read"),
    ("Write", "file_write"),
    ("Edit", "file_edit"),
    ("replace", "file_edit"),
    ("Glob", "file_search"),
    ("Grep", "content_search"),
    ("grep_search", "content_search"),
    ("WebFetch", "web_fetch"),
    ("curl", "web_fetch"),
    ("WebSearch", "web_search"),
    ("google_web_search", "web_search"),
    ("NotebookEdit", "notebook_edit"),
    ("Task", "subagent"),
    ("Skill", "skill_invoke"),
])
def test_get_capability(registry, tool_name, expected_cap):
    """Capability lookup works for both canonical and alias names."""
    assert registry.get_capability(tool_name) == expected_cap


def test_get_capability_unknown(registry):
    """Unknown tool returns None for capability."""
    assert registry.get_capability("MyCustomTool") is None


# ============================================================================
# Alias Retrieval
# ============================================================================

def test_get_aliases_bash(registry):
    """Bash aliases include expected multi-client names."""
    aliases = registry.get_aliases("Bash")
    assert "exec" in aliases
    assert "run_shell_command" in aliases
    assert "shell" in aliases
    assert "terminal" in aliases


def test_get_aliases_read(registry):
    """Read aliases include expected names."""
    aliases = registry.get_aliases("Read")
    assert "read_file" in aliases
    assert "cat" in aliases
    assert "read" in aliases


def test_get_aliases_webfetch(registry):
    """WebFetch aliases include expected names."""
    aliases = registry.get_aliases("WebFetch")
    assert "curl" in aliases
    assert "fetch" in aliases
    assert "web_fetch" in aliases


def test_get_aliases_unknown(registry):
    """Unknown canonical name returns empty tuple."""
    assert registry.get_aliases("FooTool") == ()


# ============================================================================
# is_known
# ============================================================================

@pytest.mark.parametrize("tool_name,expected", [
    ("Bash", True),
    ("exec", True),
    ("EXEC", True),
    ("run_shell_command", True),
    ("Read", True),
    ("cat", True),
    ("MyCustomTool", False),
    ("", False),
])
def test_is_known(registry, tool_name, expected):
    """is_known correctly identifies registered tools."""
    assert registry.is_known(tool_name) is expected


# ============================================================================
# canonical_for_capability
# ============================================================================

@pytest.mark.parametrize("capability,expected", [
    ("shell_execution", "Bash"),
    ("file_read", "Read"),
    ("file_write", "Write"),
    ("file_edit", "Edit"),
    ("file_search", "Glob"),
    ("content_search", "Grep"),
    ("web_fetch", "WebFetch"),
    ("web_search", "WebSearch"),
    ("notebook_edit", "NotebookEdit"),
    ("subagent", "Task"),
    ("skill_invoke", "Skill"),
])
def test_canonical_for_capability(registry, capability, expected):
    """Capability string resolves to correct canonical name."""
    assert registry.canonical_for_capability(capability) == expected


def test_canonical_for_unknown_capability(registry):
    """Unknown capability returns None."""
    assert registry.canonical_for_capability("teleport") is None


# ============================================================================
# No Duplicate Aliases
# ============================================================================

def test_no_duplicate_aliases():
    """No alias maps to more than one canonical name."""
    seen = {}
    for cap in TOOL_CAPABILITIES:
        for alias in cap.aliases:
            key = alias.lower()
            if key in seen:
                # This is only a problem if the alias maps to a DIFFERENT canonical
                assert seen[key] == cap.canonical, (
                    f"Alias '{alias}' maps to both '{seen[key]}' and '{cap.canonical}'"
                )
            seen[key] = cap.canonical


def test_canonical_names_not_duplicated_across_capabilities():
    """Each canonical name appears in exactly one capability."""
    canonicals = [cap.canonical for cap in TOOL_CAPABILITIES]
    assert len(canonicals) == len(set(canonicals)), "Duplicate canonical names found"


# ============================================================================
# Singleton
# ============================================================================

def test_singleton():
    """get_registry() returns the same instance."""
    reg1 = get_registry()
    reg2 = get_registry()
    assert reg1 is reg2


def test_module_level_normalize():
    """Module-level normalize() function works correctly."""
    assert normalize("Bash") == "Bash"
    assert normalize("exec") == "Bash"
    assert normalize("run_shell_command") == "Bash"
    assert normalize("unknown") == "unknown"


# ============================================================================
# canonical_names() set
# ============================================================================

def test_canonical_names_complete(registry):
    """All 11 canonical names are present."""
    names = registry.canonical_names()
    expected = {"Bash", "Read", "Write", "Edit", "Glob", "Grep",
                "WebFetch", "WebSearch", "NotebookEdit", "Task", "Skill"}
    assert names == expected


# ============================================================================
# Integration: provenance module uses registry-derived constants
# ============================================================================

def test_provenance_external_source_tools():
    """provenance.EXTERNAL_SOURCE_TOOLS is derived from registry."""
    from tweek.memory.provenance import EXTERNAL_SOURCE_TOOLS
    assert "Read" in EXTERNAL_SOURCE_TOOLS
    assert "WebFetch" in EXTERNAL_SOURCE_TOOLS
    assert "WebSearch" in EXTERNAL_SOURCE_TOOLS
    assert "Grep" in EXTERNAL_SOURCE_TOOLS
    # Shell execution is NOT an external source
    assert "Bash" not in EXTERNAL_SOURCE_TOOLS


def test_provenance_action_tools():
    """provenance.ACTION_TOOLS is derived from registry."""
    from tweek.memory.provenance import ACTION_TOOLS
    assert "Bash" in ACTION_TOOLS
    assert "Write" in ACTION_TOOLS
    assert "Edit" in ACTION_TOOLS
    assert "NotebookEdit" in ACTION_TOOLS
    # Read is NOT an action tool
    assert "Read" not in ACTION_TOOLS


# ============================================================================
# Integration: config manager alias-aware validation
# ============================================================================

def test_config_validates_alias_as_warning(tmp_path):
    """Config manager flags aliases with suggestion to use canonical name."""
    from tweek.config.manager import ConfigManager

    user_cfg = tmp_path / "user.yaml"
    user_cfg.write_text("tools:\n  exec: dangerous\n")

    mgr = ConfigManager(
        user_config_path=user_cfg,
        project_config_path=tmp_path / "project.yaml",
    )
    issues = mgr.validate_config(scope="user")

    # Should find the alias warning
    alias_issues = [i for i in issues if "alias" in i.message.lower()]
    assert len(alias_issues) >= 1
    assert "Bash" in alias_issues[0].suggestion


def test_config_validates_canonical_tools_no_warning(tmp_path):
    """Config manager does not flag canonical tool names."""
    from tweek.config.manager import ConfigManager

    user_cfg = tmp_path / "user.yaml"
    user_cfg.write_text("tools:\n  Bash: dangerous\n  Read: safe\n")

    mgr = ConfigManager(
        user_config_path=user_cfg,
        project_config_path=tmp_path / "project.yaml",
    )
    issues = mgr.validate_config(scope="user")

    tool_issues = [i for i in issues if i.key.startswith("tools.")]
    assert len(tool_issues) == 0


# ============================================================================
# Edge: ToolCapability construction
# ============================================================================

def test_tool_capability_slots():
    """ToolCapability uses __slots__ for memory efficiency."""
    tc = ToolCapability(
        canonical="Test",
        capability="test_cap",
        aliases=("t1", "t2"),
        description="A test",
    )
    assert tc.canonical == "Test"
    assert tc.capability == "test_cap"
    assert tc.aliases == ("t1", "t2")
    assert tc.description == "A test"


def test_custom_registry():
    """A custom registry with custom capabilities works."""
    custom = ToolCapability(
        canonical="MyTool",
        capability="my_capability",
        aliases=("my_tool", "mt"),
    )
    reg = ToolRegistry(capabilities=(custom,))
    assert reg.normalize("my_tool") == "MyTool"
    assert reg.normalize("mt") == "MyTool"
    assert reg.normalize("MyTool") == "MyTool"
    assert reg.normalize("Bash") == "Bash"  # unknown, passthrough
    assert reg.get_capability("MyTool") == "my_capability"
    assert reg.canonical_names() == frozenset({"MyTool"})
