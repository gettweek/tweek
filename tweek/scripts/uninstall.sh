#!/usr/bin/env bash
# =============================================================================
# Tweek Standalone Uninstall Script
#
# Deployed to ~/.tweek/uninstall.sh at install time.
# This script requires NO Python package -- it can clean up orphaned Tweek
# state even after `pip uninstall tweek` has already run.
#
# Usage:
#   ~/.tweek/uninstall.sh           Interactive full removal
#   ~/.tweek/uninstall.sh --force   Remove everything without prompts
# =============================================================================
set -euo pipefail

TWEEK_DIR="$HOME/.tweek"
GLOBAL_CLAUDE_DIR="$HOME/.claude"
SCOPES_FILE="$TWEEK_DIR/installed_scopes.json"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log_ok()   { printf "  [OK] %s\n" "$1"; }
log_skip() { printf "  [-]  %s\n" "$1"; }
log_warn() { printf "  [!]  %s\n" "$1"; }

# Remove tweek hook entries from a settings.json file using Python's json
# module. Falls back to a warning if Python is unavailable.
remove_hooks_from_settings() {
    local settings_file="$1"
    if [[ ! -f "$settings_file" ]]; then
        return 0
    fi

    # Check if file contains tweek references at all
    if ! grep -qi "tweek" "$settings_file" 2>/dev/null; then
        return 0
    fi

    # Try Python-based removal (preserves JSON structure)
    if command -v python3 &>/dev/null; then
        python3 << PYEOF
import json, sys
try:
    with open('$settings_file') as f:
        settings = json.load(f)
except Exception:
    sys.exit(0)

hooks = settings.get('hooks', {})
if not hooks:
    sys.exit(0)

changed = False
for hook_type in list(hooks.keys()):
    original = hooks[hook_type]
    filtered = []
    for hc in original:
        inner = [h for h in hc.get('hooks', [])
                 if 'tweek' not in h.get('command', '').lower()]
        if inner:
            hc['hooks'] = inner
            filtered.append(hc)
    if len(filtered) != len(original):
        changed = True
    if filtered:
        hooks[hook_type] = filtered
    else:
        del hooks[hook_type]

if not changed:
    sys.exit(0)

if not hooks:
    settings.pop('hooks', None)

with open('$settings_file', 'w') as f:
    json.dump(settings, f, indent=2)
PYEOF
        return 0
    fi

    log_warn "Python not available. Please manually edit $settings_file"
    log_warn "Remove entries containing 'tweek' from the hooks section."
    return 1
}

# ---------------------------------------------------------------------------
# Collect all settings.json files to clean
# ---------------------------------------------------------------------------

collect_settings_files() {
    local files=()

    # Global
    if [[ -f "$GLOBAL_CLAUDE_DIR/settings.json" ]]; then
        files+=("$GLOBAL_CLAUDE_DIR/settings.json")
    fi

    # Current project
    local cwd_settings
    cwd_settings="$(pwd)/.claude/settings.json"
    if [[ -f "$cwd_settings" ]]; then
        files+=("$cwd_settings")
    fi

    # Recorded project scopes from install-time tracking
    if [[ -f "$SCOPES_FILE" ]] && command -v python3 &>/dev/null; then
        local scopes
        scopes=$(python3 -c "
import json, sys
try:
    data = json.loads(open('$SCOPES_FILE').read()) or []
    for s in data:
        print(s + '/settings.json')
except Exception:
    pass
" 2>/dev/null)
        while IFS= read -r scope_settings; do
            if [[ -n "$scope_settings" && -f "$scope_settings" ]]; then
                # Deduplicate
                local already=false
                for f in "${files[@]+"${files[@]}"}"; do
                    if [[ "$(realpath "$f" 2>/dev/null)" == "$(realpath "$scope_settings" 2>/dev/null)" ]]; then
                        already=true
                        break
                    fi
                done
                if [[ "$already" == false ]]; then
                    files+=("$scope_settings")
                fi
            fi
        done <<< "$scopes"
    fi

    echo "${files[@]+"${files[@]}"}"
}

# ---------------------------------------------------------------------------
# Remove .tweek.yaml control files
# ---------------------------------------------------------------------------

remove_tweek_yaml_files() {
    # Global
    if [[ -f "$HOME/.tweek.yaml" ]]; then
        rm -f "$HOME/.tweek.yaml"
        log_ok "Removed ~/.tweek.yaml"
    fi

    # Recorded project scopes
    if [[ -f "$SCOPES_FILE" ]] && command -v python3 &>/dev/null; then
        local scopes
        scopes=$(python3 -c "
import json, os, sys
try:
    data = json.loads(open('$SCOPES_FILE').read()) or []
    for s in data:
        parent = os.path.dirname(s)
        yaml_path = os.path.join(parent, '.tweek.yaml')
        if os.path.exists(yaml_path):
            print(yaml_path)
except Exception:
    pass
" 2>/dev/null)
        while IFS= read -r yaml_file; do
            if [[ -n "$yaml_file" && -f "$yaml_file" ]]; then
                rm -f "$yaml_file"
                log_ok "Removed $yaml_file"
            fi
        done <<< "$scopes"
    fi
}

# ---------------------------------------------------------------------------
# Remove skill directories
# ---------------------------------------------------------------------------

remove_skill_dirs() {
    # Global
    local global_skill="$GLOBAL_CLAUDE_DIR/skills/tweek"
    if [[ -d "$global_skill" ]]; then
        rm -r "$global_skill"
        log_ok "Removed global skill directory"
    fi

    # Current project
    local project_skill
    project_skill="$(pwd)/.claude/skills/tweek"
    if [[ -d "$project_skill" ]]; then
        rm -r "$project_skill"
        log_ok "Removed project skill directory"
    fi

    # Recorded project scopes
    if [[ -f "$SCOPES_FILE" ]] && command -v python3 &>/dev/null; then
        local scopes
        scopes=$(python3 -c "
import json, sys
try:
    data = json.loads(open('$SCOPES_FILE').read()) or []
    for s in data:
        print(s)
except Exception:
    pass
" 2>/dev/null)
        while IFS= read -r scope_dir; do
            if [[ -n "$scope_dir" && -d "$scope_dir/skills/tweek" ]]; then
                rm -r "$scope_dir/skills/tweek"
                log_ok "Removed skill directory at $scope_dir"
            fi
        done <<< "$scopes"
    fi
}

# ---------------------------------------------------------------------------
# Remove MCP integrations
# ---------------------------------------------------------------------------

remove_mcp_integrations() {
    local configs=(
        "$HOME/Library/Application Support/Claude/claude_desktop_config.json"
        "$HOME/Library/Application Support/com.openai.chat/config.json"
    )

    for config_path in "${configs[@]}"; do
        if [[ ! -f "$config_path" ]]; then
            continue
        fi
        if ! grep -qi "tweek" "$config_path" 2>/dev/null; then
            continue
        fi
        if command -v python3 &>/dev/null; then
            python3 << PYEOF
import json
try:
    with open('$config_path') as f:
        config = json.load(f)
    servers = config.get('mcpServers', {})
    tweek_keys = [k for k in servers if 'tweek' in k.lower()]
    if tweek_keys:
        for k in tweek_keys:
            del servers[k]
        with open('$config_path', 'w') as f:
            json.dump(config, f, indent=2)
except Exception:
    pass
PYEOF
            log_ok "Removed MCP integration from $(basename "$(dirname "$config_path")")"
        fi
    done
}

# ---------------------------------------------------------------------------
# Remove tweek pip/pipx/uv package
# ---------------------------------------------------------------------------

remove_package() {
    local found=()

    # Check pipx
    if command -v pipx &>/dev/null; then
        if pipx list 2>/dev/null | grep -q "tweek"; then
            found+=("pipx uninstall tweek")
        fi
    fi

    # Check uv
    if command -v uv &>/dev/null; then
        if uv tool list 2>/dev/null | grep -q "tweek"; then
            found+=("uv tool uninstall tweek")
        fi
    fi

    # Check pip
    if command -v python3 &>/dev/null; then
        if python3 -m pip show tweek &>/dev/null 2>&1; then
            found+=("python3 -m pip uninstall tweek -y")
        fi
    fi

    if [[ ${#found[@]} -eq 0 ]]; then
        log_skip "No tweek package installations found"
        return 0
    fi

    for cmd in "${found[@]}"; do
        printf "  Running: %s\n" "$cmd"
        if eval "$cmd" &>/dev/null 2>&1; then
            log_ok "Package removed ($cmd)"
        else
            log_warn "Could not remove via: $cmd"
        fi
    done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    local force=false
    if [[ "${1:-}" == "--force" || "${1:-}" == "-f" ]]; then
        force=true
    fi

    echo ""
    printf "Tweek Standalone Uninstall\n"
    echo ""

    if [[ "$force" != true ]]; then
        echo "This will remove ALL Tweek data from your system:"
        echo "  - Hooks from all settings.json files"
        echo "  - Skill directories"
        echo "  - .tweek.yaml control files"
        echo "  - ~/.tweek/ data directory"
        echo "  - MCP integrations"
        echo "  - The tweek Python package"
        echo ""
        printf "Type 'yes' to confirm: "
        read -r response
        if [[ "$response" != "yes" ]]; then
            echo "Cancelled."
            exit 0
        fi
        echo ""
    fi

    # 1. Remove hooks from all settings.json files
    printf "Hooks:\n"
    local settings_files
    settings_files=$(collect_settings_files)
    if [[ -n "$settings_files" ]]; then
        for sf in $settings_files; do
            if remove_hooks_from_settings "$sf"; then
                log_ok "Cleaned hooks from $sf"
            else
                log_warn "Could not clean $sf"
            fi
        done
    else
        log_skip "No settings.json files found"
    fi
    echo ""

    # 2. Remove skill directories
    printf "Skills:\n"
    remove_skill_dirs
    echo ""

    # 3. Remove .tweek.yaml control files
    printf "Control files:\n"
    remove_tweek_yaml_files
    echo ""

    # 4. Remove MCP integrations
    printf "MCP integrations:\n"
    remove_mcp_integrations
    echo ""

    # 5. Remove package
    printf "Package:\n"
    remove_package
    echo ""

    # 6. Remove ~/.tweek/ data directory (last -- we need scopes_file above)
    printf "Data directory:\n"
    if [[ -d "$TWEEK_DIR" ]]; then
        rm -r "$TWEEK_DIR"
        log_ok "Removed ~/.tweek/"
    else
        log_skip "~/.tweek/ not found"
    fi
    echo ""

    printf "Tweek has been fully removed.\n"
    echo ""
}

main "$@"
