"""Tests for install/uninstall resilience.

Covers self-healing hook wrappers, standalone uninstall script,
scope-aware install/uninstall, and .tweek.yaml cleanup.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


def _make_hook_entry(cmd_str):
    """Build a single hook entry dict."""
    return {"type": "command", "command": cmd_str}


def _make_settings_with_hooks(path, hook_cmds):
    """Write a settings.json with given hook commands.

    Args:
        path: Path to settings.json
        hook_cmds: dict mapping hook_type to list of (matcher, command) tuples
    """
    hooks = {}
    for hook_type, entries in hook_cmds.items():
        hooks[hook_type] = []
        for matcher, cmds in entries:
            hooks[hook_type].append({
                "matcher": matcher,
                "hooks": [_make_hook_entry(c) for c in cmds],
            })
    path.write_text(json.dumps({"hooks": hooks}, indent=2))
    return path


@pytest.fixture
def tmp_tweek_dir(tmp_path):
    tweek_dir = tmp_path / ".tweek"
    tweek_dir.mkdir()
    return tweek_dir


@pytest.fixture
def tmp_claude_dir(tmp_path):
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    return claude_dir


@pytest.fixture
def settings_with_tweek(tmp_claude_dir):
    """settings.json containing only tweek hooks."""
    sf = tmp_claude_dir / "settings.json"
    return _make_settings_with_hooks(sf, {
        "PreToolUse": [
            ("Bash|Write", ["/usr/bin/python3 /home/.tweek/hooks/pre_tool_use.py"]),
        ],
        "PostToolUse": [
            ("Read|Bash", ["/usr/bin/python3 /home/.tweek/hooks/post_tool_use.py"]),
        ],
    })


@pytest.fixture
def settings_with_mixed(tmp_claude_dir):
    """settings.json with tweek + non-tweek hooks."""
    sf = tmp_claude_dir / "settings.json"
    return _make_settings_with_hooks(sf, {
        "PreToolUse": [
            ("Bash", [
                "/usr/bin/python3 /home/.tweek/hooks/pre_tool_use.py",
                "/usr/bin/other-tool check",
            ]),
        ],
        "PostToolUse": [
            ("Read", ["some-other-hook"]),
        ],
    })


# ── Wrapper deployment ──

@pytest.mark.cli
class TestDeployHookWrappers:

    def test_wrappers_can_be_copied(self, tmp_tweek_dir):
        hooks_dir = tmp_tweek_dir / "hooks"
        hooks_dir.mkdir()
        src_dir = Path(__file__).resolve().parent.parent / "tweek" / "hooks"
        for w in ("wrapper_pre_tool_use.py", "wrapper_post_tool_use.py"):
            shutil.copy2(src_dir / w, hooks_dir / w.replace("wrapper_", ""))
        assert (hooks_dir / "pre_tool_use.py").exists()
        assert (hooks_dir / "post_tool_use.py").exists()

    def test_wrapper_contains_self_heal(self):
        src_dir = Path(__file__).resolve().parent.parent / "tweek" / "hooks"
        for w in ("wrapper_pre_tool_use.py", "wrapper_post_tool_use.py"):
            content = (src_dir / w).read_text()
            assert "def _self_heal" in content
            assert "def _remove_tweek_hooks_from_file" in content

    def test_wrapper_no_tweek_imports_at_module_level(self):
        src_dir = Path(__file__).resolve().parent.parent / "tweek" / "hooks"
        for w in ("wrapper_pre_tool_use.py", "wrapper_post_tool_use.py"):
            lines = (src_dir / w).read_text().split("\n")
            in_func = False
            for line in lines:
                s = line.strip()
                if s.startswith("def ") or s.startswith("class "):
                    in_func = True
                if not in_func and s.startswith("from tweek"):
                    pytest.fail(f"{w}: module-level tweek import: {s}")

    def test_wrapper_stdlib_only_at_module_level(self):
        src_dir = Path(__file__).resolve().parent.parent / "tweek" / "hooks"
        ok = {"json", "sys", "pathlib", "__future__"}
        for w in ("wrapper_pre_tool_use.py", "wrapper_post_tool_use.py"):
            lines = (src_dir / w).read_text().split("\n")
            in_func = False
            for line in lines:
                s = line.strip()
                if s.startswith("def ") or s.startswith("class "):
                    in_func = True
                if not in_func and (s.startswith("import ") or s.startswith("from ")):
                    mod = s.split()[1].split(".")[0]
                    assert mod in ok, f"{w}: non-stdlib '{mod}' at module level"


# ── Self-healing removal ──

@pytest.mark.cli
class TestSelfHealRemoval:

    def test_removes_all_tweek_hooks(self, settings_with_tweek):
        from tweek.hooks.wrapper_pre_tool_use import _remove_tweek_hooks_from_file
        _remove_tweek_hooks_from_file(settings_with_tweek)
        data = json.loads(settings_with_tweek.read_text())
        assert "hooks" not in data or not data.get("hooks")

    def test_preserves_non_tweek_hooks(self, settings_with_mixed):
        from tweek.hooks.wrapper_pre_tool_use import _remove_tweek_hooks_from_file
        _remove_tweek_hooks_from_file(settings_with_mixed)
        data = json.loads(settings_with_mixed.read_text())
        hooks = data.get("hooks", {})
        pre = hooks.get("PreToolUse", [])
        assert len(pre) == 1
        assert "other-tool" in pre[0]["hooks"][0]["command"]
        post = hooks.get("PostToolUse", [])
        assert len(post) == 1
        assert "some-other-hook" in post[0]["hooks"][0]["command"]

    def test_handles_missing_file(self, tmp_path):
        from tweek.hooks.wrapper_pre_tool_use import _remove_tweek_hooks_from_file
        _remove_tweek_hooks_from_file(tmp_path / "nope.json")

    def test_handles_bad_json(self, tmp_claude_dir):
        from tweek.hooks.wrapper_pre_tool_use import _remove_tweek_hooks_from_file
        sf = tmp_claude_dir / "settings.json"
        sf.write_text("{bad json")
        _remove_tweek_hooks_from_file(sf)

    def test_handles_empty_hooks(self, tmp_claude_dir):
        from tweek.hooks.wrapper_pre_tool_use import _remove_tweek_hooks_from_file
        sf = tmp_claude_dir / "settings.json"
        sf.write_text(json.dumps({"hooks": {}}))
        _remove_tweek_hooks_from_file(sf)
        assert json.loads(sf.read_text()) == {"hooks": {}}

    def test_self_heal_prints_empty_json(self, capsys):
        from tweek.hooks.wrapper_pre_tool_use import _self_heal
        with patch("tweek.hooks.wrapper_pre_tool_use._remove_tweek_hooks_from_file"):
            _self_heal()
        assert capsys.readouterr().out.strip() == "{}"

    def test_self_heal_cleans_multiple_locations(self):
        from tweek.hooks.wrapper_pre_tool_use import _self_heal
        calls = []
        with patch(
            "tweek.hooks.wrapper_pre_tool_use._remove_tweek_hooks_from_file",
            side_effect=lambda p: calls.append(str(p)),
        ):
            _self_heal()
        assert len(calls) >= 2


# ── Wrapper delegation ──

@pytest.mark.cli
class TestWrapperDelegation:

    def test_delegates_when_available(self):
        from tweek.hooks import wrapper_pre_tool_use
        mock_main = MagicMock()
        with patch("tweek.hooks.wrapper_pre_tool_use._self_heal") as heal:
            with patch("tweek.hooks.pre_tool_use.main", mock_main):
                wrapper_pre_tool_use.main()
                mock_main.assert_called_once()
                heal.assert_not_called()

    def test_fails_open_on_exception(self, capsys):
        from tweek.hooks import wrapper_pre_tool_use
        with patch("tweek.hooks.pre_tool_use.main", side_effect=RuntimeError("x")):
            wrapper_pre_tool_use.main()
        assert capsys.readouterr().out.strip() == "{}"


# ── Post-tool-use wrapper ──

@pytest.mark.cli
class TestPostWrapper:

    def test_removes_hooks(self, settings_with_tweek):
        from tweek.hooks.wrapper_post_tool_use import _remove_tweek_hooks_from_file
        _remove_tweek_hooks_from_file(settings_with_tweek)
        data = json.loads(settings_with_tweek.read_text())
        assert "hooks" not in data or not data.get("hooks")

    def test_self_heal_prints_empty(self, capsys):
        from tweek.hooks.wrapper_post_tool_use import _self_heal
        with patch("tweek.hooks.wrapper_post_tool_use._remove_tweek_hooks_from_file"):
            _self_heal()
        assert capsys.readouterr().out.strip() == "{}"


# ── Standalone uninstall script ──

@pytest.mark.cli
class TestUninstallScript:

    def test_exists(self):
        src = Path(__file__).resolve().parent.parent / "tweek" / "scripts" / "uninstall.sh"
        assert src.exists()

    def test_executable(self):
        src = Path(__file__).resolve().parent.parent / "tweek" / "scripts" / "uninstall.sh"
        assert os.access(src, os.X_OK)

    def test_bash_shebang(self):
        src = Path(__file__).resolve().parent.parent / "tweek" / "scripts" / "uninstall.sh"
        assert "bash" in src.read_text().split("\n")[0]

    def test_syntax_valid(self):
        src = Path(__file__).resolve().parent.parent / "tweek" / "scripts" / "uninstall.sh"
        r = subprocess.run(["bash", "-n", str(src)], capture_output=True, text=True)
        assert r.returncode == 0, f"Syntax error: {r.stderr}"

    def test_has_key_functions(self):
        src = Path(__file__).resolve().parent.parent / "tweek" / "scripts" / "uninstall.sh"
        content = src.read_text()
        for fn in ("remove_hooks_from_settings", "collect_settings_files",
                    "remove_tweek_yaml_files", "remove_skill_dirs", "remove_package"):
            assert fn in content, f"Missing: {fn}"


# ── .tweek.yaml removal ──

@pytest.mark.cli
class TestRemoveTweekYaml:

    def test_removes_global(self, tmp_path):
        from tweek.cli_uninstall import _remove_tweek_yaml_files
        yaml_f = tmp_path / ".tweek.yaml"
        yaml_f.write_text("hooks:\n  pre_tool_use: true\n")
        td = tmp_path / ".tweek"
        td.mkdir()
        with patch("tweek.cli_uninstall.Path") as MP:
            rp = Path
            def pf(a):
                if a == "~/.tweek.yaml":
                    m = MagicMock(); m.expanduser.return_value = yaml_f; return m
                return rp(a)
            MP.side_effect = pf; MP.cwd.return_value = tmp_path / "x"
            removed = _remove_tweek_yaml_files(td)
        assert not yaml_f.exists()
        assert len(removed) >= 1

    def test_removes_project_from_scopes(self, tmp_path):
        from tweek.cli_uninstall import _remove_tweek_yaml_files
        proj = tmp_path / "proj"
        proj.mkdir()
        cd = proj / ".claude"; cd.mkdir()
        yf = proj / ".tweek.yaml"
        yf.write_text("hooks:\n  pre_tool_use: true\n")
        td = tmp_path / ".tweek"; td.mkdir()
        sf = td / "installed_scopes.json"
        sf.write_text(json.dumps([str(cd)]))
        with patch("tweek.cli_uninstall.Path") as MP:
            rp = Path
            def pf(a):
                if a == "~/.tweek.yaml":
                    m = MagicMock(); m.expanduser.return_value = tmp_path / "no.y"; return m
                return rp(a)
            MP.side_effect = pf; MP.cwd.return_value = tmp_path / "x"
            removed = _remove_tweek_yaml_files(td)
        assert not yf.exists()

    def test_handles_no_scopes(self, tmp_path):
        from tweek.cli_uninstall import _remove_tweek_yaml_files
        td = tmp_path / ".tweek"; td.mkdir()
        with patch("tweek.cli_uninstall.Path") as MP:
            rp = Path
            def pf(a):
                if a == "~/.tweek.yaml":
                    m = MagicMock(); m.expanduser.return_value = tmp_path / "no.y"; return m
                return rp(a)
            MP.side_effect = pf; MP.cwd.return_value = tmp_path
            assert _remove_tweek_yaml_files(td) == []


# ── Scope-aware install ──

@pytest.mark.cli
class TestScopeAware:

    def test_shared_hooks_dir(self):
        from tweek.cli_install import _TWEEK_HOOKS_DIR
        assert str(_TWEEK_HOOKS_DIR).endswith(".tweek/hooks")

    def test_wrapper_templates_exist(self):
        d = Path(__file__).resolve().parent.parent / "tweek" / "hooks"
        assert (d / "wrapper_pre_tool_use.py").exists()
        assert (d / "wrapper_post_tool_use.py").exists()


# ── Uninstall data dir ──

@pytest.mark.cli
class TestUninstallDataDir:

    def test_removes_hooks_dir(self, tmp_tweek_dir):
        from tweek.cli_uninstall import _remove_tweek_data_dir
        hd = tmp_tweek_dir / "hooks"; hd.mkdir()
        (hd / "pre_tool_use.py").write_text("# w")
        removed = _remove_tweek_data_dir(tmp_tweek_dir)
        assert not hd.exists()
        assert "self-healing hook wrappers" in removed

    def test_removes_uninstall_sh(self, tmp_tweek_dir):
        from tweek.cli_uninstall import _remove_tweek_data_dir
        (tmp_tweek_dir / "uninstall.sh").write_text("#!/bin/bash\n")
        removed = _remove_tweek_data_dir(tmp_tweek_dir)
        assert "standalone uninstall script" in removed

    def test_removes_scopes_json(self, tmp_tweek_dir):
        from tweek.cli_uninstall import _remove_tweek_data_dir
        (tmp_tweek_dir / "installed_scopes.json").write_text("[]")
        removed = _remove_tweek_data_dir(tmp_tweek_dir)
        assert "installation scope tracking" in removed

    def test_removes_directory_itself(self, tmp_tweek_dir):
        from tweek.cli_uninstall import _remove_tweek_data_dir
        removed = _remove_tweek_data_dir(tmp_tweek_dir)
        assert not tmp_tweek_dir.exists()
