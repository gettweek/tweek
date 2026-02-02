#!/bin/bash
# Tweek Installer
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/gettweek/tweek/main/scripts/install.sh | bash
#
# Options (via environment variables):
#   TWEEK_SKIP_HOOKS=1        Skip hook installation
#   TWEEK_PRESET=paranoid     Set security preset (paranoid, cautious, trusted)
#   TWEEK_PREFER=uv|pipx|pip  Force a specific install method
#   TWEEK_UV_URL=<url>        Override uv installer URL (for mirrors/proxies)

set -euo pipefail

# Colors (disabled if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    DIM='\033[2m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' DIM='' BOLD='' NC=''
fi

# Detect if running interactively or piped
INTERACTIVE=false
if [ -t 0 ]; then
    INTERACTIVE=true
fi

# Global state
PYTHON=""
UV_CMD=""
TWEEK_CMD=""
INSTALL_METHOD=""

info()  { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}!${NC} $*"; }
fail()  { echo -e "${RED}✗${NC} $*"; exit 1; }
step()  { echo -e "${CYAN}→${NC} $*"; }

# ── Banner ──────────────────────────────────────────────────────
echo -e "${CYAN}"
cat << 'BANNER'

  ████████╗██╗    ██╗███████╗███████╗██╗  ██╗
  ╚══██╔══╝██║    ██║██╔════╝██╔════╝██║ ██╔╝
     ██║   ██║ █╗ ██║█████╗  █████╗  █████╔╝
     ██║   ██║███╗██║██╔══╝  ██╔══╝  ██╔═██╗
     ██║   ╚███╔███╔╝███████╗███████╗██║  ██╗
     ╚═╝    ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝

  GAH! Defense-in-depth security for AI coding assistants.
  Free and open source. https://github.com/gettweek/tweek

BANNER
echo -e "${NC}"

# ═══════════════════════════════════════════════════════════════
# Detection helpers
# ═══════════════════════════════════════════════════════════════

# ── Detect uv (standalone Python package manager) ─────────────
check_uv() {
    local uv_cmd=""

    for cmd in uv "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do
        if command -v "$cmd" &>/dev/null || [ -x "$cmd" ]; then
            uv_cmd="$cmd"
            break
        fi
    done

    [ -z "$uv_cmd" ] && return 1

    # Validate version: uv tool install requires >= 0.4.0
    local uv_ver
    uv_ver=$("$uv_cmd" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "0.0.0")
    local uv_major uv_minor
    uv_major=$(echo "$uv_ver" | cut -d. -f1)
    uv_minor=$(echo "$uv_ver" | cut -d. -f2)

    if [ "${uv_major:-0}" -eq 0 ] && [ "${uv_minor:-0}" -lt 4 ]; then
        warn "uv $uv_ver found but too old (need >= 0.4.0)"
        return 1
    fi

    UV_CMD="$uv_cmd"
    return 0
}

# ── Detect Python 3.9+ ────────────────────────────────────────
check_python() {
    local py=""
    local ver=""

    for cmd in python3.13 python3.12 python3.11 python3.10 python3.9 python3 python; do
        if command -v "$cmd" &>/dev/null; then
            ver=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)
            local major minor
            major=$(echo "$ver" | cut -d. -f1)
            minor=$(echo "$ver" | cut -d. -f2)
            if [ "${major:-0}" -ge 3 ] && [ "${minor:-0}" -ge 9 ]; then
                py="$cmd"
                break
            fi
        fi
    done

    if [ -z "$py" ]; then
        return 1
    fi

    info "Python $ver found ($py)"
    PYTHON="$py"
    return 0
}

# ═══════════════════════════════════════════════════════════════
# Install methods (tried in priority order)
# ═══════════════════════════════════════════════════════════════

# ── Method 1: uv tool install (fastest, isolated, no Python needed) ──
try_uv() {
    check_uv || return 1

    info "Using uv (recommended)"

    if "$UV_CMD" tool list 2>/dev/null | grep -q "^tweek "; then
        step "Upgrading existing installation..."
        "$UV_CMD" tool upgrade tweek 2>/dev/null || "$UV_CMD" tool install --force tweek || return 1
    else
        "$UV_CMD" tool install tweek 2>/dev/null || "$UV_CMD" tool install --force tweek || return 1
    fi

    INSTALL_METHOD="uv"
    return 0
}

# ── Method 2: pipx install (isolated, requires Python) ───────
try_pipx() {
    command -v pipx &>/dev/null || return 1

    info "Using pipx"
    if pipx list 2>/dev/null | grep -q "tweek"; then
        step "Upgrading existing installation..."
        pipx upgrade tweek 2>/dev/null || pipx install --force tweek || return 1
    else
        pipx install tweek 2>/dev/null || pipx install --force tweek || return 1
    fi
    INSTALL_METHOD="pipx"
    return 0
}

# ── Method 3: pip install --user (requires Python + pip >= 22) ──
try_pip() {
    check_python || return 1

    # Check pip version — macOS system Python ships pip 21 which
    # cannot reliably resolve modern packages
    local pip_ver
    pip_ver=$("$PYTHON" -m pip --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 || echo "0.0")
    local pip_major
    pip_major=$(echo "$pip_ver" | cut -d. -f1)

    if [ "${pip_major:-0}" -lt 22 ]; then
        warn "pip $pip_ver is too old to install packages reliably"
        return 1
    fi

    warn "Using $PYTHON -m pip (consider installing uv: https://docs.astral.sh/uv/)"
    "$PYTHON" -m pip install --user tweek || return 1
    INSTALL_METHOD="pip"
    return 0
}

# ── Method 4: Bootstrap uv then install ──────────────────────
bootstrap_uv() {
    local uv_install_url="${TWEEK_UV_URL:-https://astral.sh/uv/install.sh}"

    echo ""
    step "No suitable package manager found."
    echo ""
    echo -e "  Tweek can install ${BOLD}uv${NC} — a fast Python package manager"
    echo -e "  that requires ${BOLD}no dependencies${NC} and ${BOLD}no sudo${NC}."
    echo -e "  ${DIM}https://docs.astral.sh/uv/${NC}"
    echo ""

    if [ "$INTERACTIVE" = true ]; then
        echo -ne "${CYAN}→${NC} Install uv to ~/.local/bin? ${DIM}[Y/n]${NC} "
        read -r reply </dev/tty
        if [[ "$reply" =~ ^[Nn]$ ]]; then
            return 1
        fi
    else
        step "Installing uv (standalone binary, no sudo)..."
    fi

    # Verify we can download
    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        warn "Neither curl nor wget found. Cannot download uv."
        return 1
    fi

    # Download and run the uv installer.
    # The || true prevents set -euo pipefail from aborting the script
    # if the download or installer fails — we handle the error below.
    local exit_code=0
    if command -v curl &>/dev/null; then
        curl -LsSf "$uv_install_url" | sh 2>&1 || exit_code=$?
    else
        wget -qO- "$uv_install_url" | sh 2>&1 || exit_code=$?
    fi

    if [ $exit_code -ne 0 ]; then
        warn "uv installation failed (exit code $exit_code)"
        echo -e "  ${DIM}Check your network connection or try manually:${NC}"
        echo -e "  ${DIM}curl -LsSf $uv_install_url | sh${NC}"
        return 1
    fi

    # Make uv available in this session
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

    if ! command -v uv &>/dev/null; then
        warn "uv installed but not found on PATH"
        echo -e "  ${DIM}Try opening a new terminal and re-running the installer${NC}"
        return 1
    fi

    info "uv installed successfully"
    UV_CMD="uv"

    # Install tweek via uv (uv downloads Python automatically if needed)
    echo ""
    step "Installing Tweek via uv..."
    "$UV_CMD" tool install tweek || {
        warn "uv tool install tweek failed"
        return 1
    }

    INSTALL_METHOD="uv"
    return 0
}

# ── Method 5: Homebrew (macOS) or manual instructions (last resort) ──
fallback_homebrew_or_manual() {
    echo ""
    warn "Could not install via uv, pipx, or pip."
    echo ""

    if [ "$(uname -s)" = "Darwin" ]; then
        if command -v brew &>/dev/null; then
            if [ "$INTERACTIVE" = true ]; then
                echo -ne "${CYAN}→${NC} Install Python 3.12 via Homebrew? ${DIM}[Y/n]${NC} "
                read -r reply </dev/tty
                if [[ ! "$reply" =~ ^[Nn]$ ]]; then
                    step "Installing Python 3.12 via Homebrew..."
                    brew install python@3.12
                    brew link --overwrite python@3.12 2>/dev/null || true

                    # Retry with pipx or pip
                    check_python || fail "Python installed but not on PATH. Try: brew link python@3.12"
                    step "Installing pipx..."
                    brew install pipx 2>/dev/null || true
                    try_pipx && return 0
                    try_pip && return 0
                    fail "Python installed but tweek installation failed"
                else
                    echo ""
                    echo "  To install manually:"
                    echo "    brew install python@3.12 pipx"
                    echo "    pipx install tweek"
                    exit 1
                fi
            else
                echo "  Install via Homebrew:"
                echo "    brew install python@3.12 pipx"
                echo "    pipx install tweek"
                exit 1
            fi
        else
            echo "  Install one of:"
            echo "    1. uv (recommended, no sudo): curl -LsSf https://astral.sh/uv/install.sh | sh"
            echo "    2. Homebrew: https://brew.sh → brew install python@3.12 pipx"
            echo "    3. python.org: https://www.python.org/downloads/"
            exit 1
        fi
    elif [ "$(uname -s)" = "Linux" ]; then
        echo "  Install one of:"
        echo "    1. uv (recommended, no sudo): curl -LsSf https://astral.sh/uv/install.sh | sh"
        if command -v apt &>/dev/null; then
            echo "    2. Python: sudo apt update && sudo apt install python3.12 python3.12-venv pipx"
        elif command -v dnf &>/dev/null; then
            echo "    2. Python: sudo dnf install python3.12 pipx"
        elif command -v pacman &>/dev/null; then
            echo "    2. Python: sudo pacman -S python python-pipx"
        else
            echo "    2. Python 3.9+ via your package manager"
        fi
        echo "    3. pyenv: https://github.com/pyenv/pyenv"
        exit 1
    else
        echo "  Install one of:"
        echo "    1. uv: https://docs.astral.sh/uv/"
        echo "    2. Python 3.9+: https://www.python.org/downloads/"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════
# Orchestrator: tries each method in priority order
# ═══════════════════════════════════════════════════════════════

install_tweek_package() {
    echo ""

    # If tweek is already installed and working, skip package installation.
    # This handles the re-install-after-uninstall case where uninstall only
    # removed hooks/skills but the pipx/uv package is still present.
    if command -v tweek &>/dev/null; then
        local existing_ver
        existing_ver=$(tweek --version 2>/dev/null || echo "")
        if [ -n "$existing_ver" ]; then
            info "Tweek $existing_ver is already installed"
            step "Skipping package installation (already present)"
            echo -e "  ${DIM}To upgrade: pipx upgrade tweek  or  uv tool upgrade tweek${NC}"
            INSTALL_METHOD="existing"
            return 0
        fi
    fi

    step "Installing Tweek..."
    echo ""

    # Respect explicit preference
    case "${TWEEK_PREFER:-}" in
        uv)
            try_uv && return
            fail "TWEEK_PREFER=uv set but uv is not available. Install: https://docs.astral.sh/uv/"
            ;;
        pipx)
            try_pipx && return
            fail "TWEEK_PREFER=pipx set but pipx is not available."
            ;;
        pip)
            try_pip && return
            fail "TWEEK_PREFER=pip set but pip install failed."
            ;;
    esac

    # Auto-detect: try each method in priority order
    try_uv && return
    try_pipx && return
    try_pip && return

    # Nothing on the system works. Bootstrap uv (downloads a single binary).
    bootstrap_uv && return

    # uv bootstrap failed (offline, proxy, user declined). Last resort.
    fallback_homebrew_or_manual
}

# ── Verify tweek is in PATH ────────────────────────────────────
verify_install() {
    echo ""

    if command -v tweek &>/dev/null; then
        local ver
        ver=$(tweek --version 2>/dev/null || echo "unknown")
        info "Tweek $ver installed"
        TWEEK_CMD="tweek"
        return
    fi

    # Check common locations including uv tool bin
    local uv_bin_dir=""
    uv_bin_dir=$(uv tool dir --bin 2>/dev/null || true)

    for path in \
        "$HOME/.local/bin/tweek" \
        "$HOME/.local/pipx/venvs/tweek/bin/tweek" \
        "${uv_bin_dir:+$uv_bin_dir/tweek}"; do
        if [ -n "$path" ] && [ -x "$path" ]; then
            info "Tweek installed at $path"
            TWEEK_CMD="$path"

            warn "Add to PATH for easier access:"
            echo ""
            if [ -f "$HOME/.zshrc" ]; then
                echo -e "  ${DIM}echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc && source ~/.zshrc${NC}"
            else
                echo -e "  ${DIM}echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc${NC}"
            fi
            echo ""
            return
        fi
    done

    fail "Installation succeeded but 'tweek' not found in PATH"
}

# ── Install hooks into Claude Code ──────────────────────────────
setup_hooks() {
    if [ "${TWEEK_SKIP_HOOKS:-}" = "1" ]; then
        echo ""
        warn "Skipping hook installation (TWEEK_SKIP_HOOKS=1)"
        echo -e "  ${DIM}Run 'tweek install' later to activate protection${NC}"
        return
    fi

    # Check if Claude Code is installed
    if ! command -v claude &>/dev/null; then
        echo ""
        warn "Claude Code not detected on this system"
        echo -e "  ${DIM}Install Claude Code first, then run 'tweek install' to add hooks${NC}"
        echo -e "  ${DIM}https://docs.anthropic.com/en/docs/claude-code${NC}"
        return
    fi

    info "Claude Code detected"
    echo ""

    if [ "$INTERACTIVE" = true ]; then
        # Interactive: ask the user
        echo -ne "${CYAN}→${NC} Install Claude Code hooks now? ${DIM}[Y/n]${NC} "
        read -r reply </dev/tty
        if [[ "$reply" =~ ^[Nn]$ ]]; then
            echo ""
            echo -e "  ${DIM}Run 'tweek install' later to activate protection${NC}"
            return
        fi
    else
        # Non-interactive (piped from curl): auto-install
        step "Installing Claude Code hooks..."
    fi

    echo ""

    if [ -n "${TWEEK_PRESET:-}" ]; then
        $TWEEK_CMD install --preset "$TWEEK_PRESET" --non-interactive 2>/dev/null || $TWEEK_CMD install 2>/dev/null || true
    else
        $TWEEK_CMD install --non-interactive 2>/dev/null || $TWEEK_CMD install 2>/dev/null || true
    fi
}

# ── Detect Moltbot and offer protection ─────────────────────────
setup_moltbot() {
    if ! command -v moltbot &>/dev/null; then
        return
    fi

    echo ""
    info "Moltbot detected on this system"
    echo ""

    if [ "$INTERACTIVE" = true ]; then
        echo -e "${CYAN}Tweek can protect Moltbot tool calls. Choose a method:${NC}"
        echo ""
        echo -e "  ${CYAN}1.${NC} Protect via ${BOLD}tweek-security${NC} MoltHub skill"
        echo -e "     ${DIM}Screens tool calls through Tweek as a MoltHub skill${NC}"
        echo -e "  ${CYAN}2.${NC} Protect via ${BOLD}tweek protect moltbot${NC}"
        echo -e "     ${DIM}Wraps the Moltbot gateway with Tweek's proxy${NC}"
        echo -e "  ${CYAN}3.${NC} Skip for now"
        echo -e "     ${DIM}You can set up Moltbot protection later${NC}"
        echo ""
        echo -ne "${CYAN}→${NC} Select ${DIM}[1/2/3]${NC} (default: 3): "
        read -r choice </dev/tty

        case "${choice:-3}" in
            1)
                echo ""
                echo -e "  ${GREEN}✓${NC} To add Moltbot protection via the skill, run:"
                echo -e "    ${BOLD}moltbot protect tweek-security${NC}"
                ;;
            2)
                echo ""
                step "Configuring Moltbot proxy protection..."
                $TWEEK_CMD protect moltbot 2>/dev/null || true
                ;;
            *)
                echo ""
                echo -e "  ${DIM}Skipped. Run 'tweek protect moltbot' or add the${NC}"
                echo -e "  ${DIM}tweek-security skill later to protect Moltbot.${NC}"
                ;;
        esac
    else
        # Non-interactive: inform and skip
        echo -e "  ${DIM}Run 'tweek protect moltbot' or add the tweek-security${NC}"
        echo -e "  ${DIM}skill to protect Moltbot tool calls.${NC}"
    fi
}

# ── Run doctor check ────────────────────────────────────────────
run_doctor() {
    echo ""
    $TWEEK_CMD doctor 2>/dev/null || true
}

# ── Final output ────────────────────────────────────────────────
finish() {
    echo ""
    echo -e "${GREEN}${BOLD}Done!${NC} Your AI coding sessions are now protected."
    echo ""
    echo -e "  ${BOLD}Quick commands:${NC}"
    echo -e "  ${DIM}tweek doctor${NC}      Verify protection status"
    echo -e "  ${DIM}tweek status${NC}      Show current configuration"
    echo -e "  ${DIM}tweek logs show${NC}   View security events"
    echo -e "  ${DIM}tweek --help${NC}      See all commands"
    echo ""
    echo -e "  ${DIM}GitHub:  https://github.com/gettweek/tweek${NC}"
    echo -e "  ${DIM}Issues:  https://github.com/gettweek/tweek/issues${NC}"
    echo ""
}

# ── Main ────────────────────────────────────────────────────────
main() {
    install_tweek_package
    verify_install
    setup_hooks
    setup_moltbot
    run_doctor
    finish
}

main "$@"
