#!/bin/bash
# Tweek Installer
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/gettweek/tweek/main/scripts/install.sh | bash
#
# Options (via environment variables):
#   TWEEK_SKIP_HOOKS=1    Skip hook installation
#   TWEEK_PRESET=paranoid Set security preset (paranoid, cautious, trusted)

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

# ── Check Python 3.9+ ──────────────────────────────────────────
check_python() {
    local py=""
    local ver=""

    for cmd in python3 python; do
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
        echo -e "${RED}✗${NC} Python 3.9+ required (found: ${ver:-none})"
        echo ""

        # On macOS, offer to install via Homebrew
        if [ "$(uname -s)" = "Darwin" ]; then
            if command -v brew &>/dev/null; then
                if [ "$INTERACTIVE" = true ]; then
                    echo -ne "${CYAN}→${NC} Install Python 3.12 via Homebrew? ${DIM}[Y/n]${NC} "
                    read -r reply </dev/tty
                    if [[ ! "$reply" =~ ^[Nn]$ ]]; then
                        step "Installing Python 3.12 via Homebrew..."
                        brew install python@3.12
                        brew link --overwrite python@3.12 2>/dev/null || true
                        # Retry detection after install
                        for cmd in python3 python; do
                            if command -v "$cmd" &>/dev/null; then
                                ver=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)
                                major=$(echo "$ver" | cut -d. -f1)
                                minor=$(echo "$ver" | cut -d. -f2)
                                if [ "${major:-0}" -ge 3 ] && [ "${minor:-0}" -ge 9 ]; then
                                    py="$cmd"
                                    break
                                fi
                            fi
                        done
                        if [ -z "$py" ]; then
                            echo ""
                            warn "Python installed but not on PATH. Try:"
                            echo "  brew link python@3.12"
                            echo "  Then re-run this installer."
                            exit 1
                        fi
                    else
                        echo ""
                        echo "  To install manually:"
                        echo "    brew install python@3.12"
                        echo "    brew link python@3.12"
                        echo ""
                        echo "  Or visit: https://www.python.org/downloads/"
                        exit 1
                    fi
                else
                    echo "  Install Python 3.12 via Homebrew:"
                    echo "    brew install python@3.12"
                    echo "    brew link python@3.12"
                    echo ""
                    echo "  Then re-run this installer."
                    exit 1
                fi
            else
                # Homebrew not installed — offer to install it without admin
                if [ "$INTERACTIVE" = true ] && command -v git &>/dev/null; then
                    echo -e "  Homebrew is not installed. It can be installed ${BOLD}without admin access${NC}"
                    echo -e "  to ${DIM}~/.homebrew${NC}, then used to install Python."
                    echo ""
                    echo -ne "${CYAN}→${NC} Install Homebrew to ~/.homebrew (no sudo required)? ${DIM}[Y/n]${NC} "
                    read -r reply </dev/tty
                    if [[ ! "$reply" =~ ^[Nn]$ ]]; then
                        local brew_prefix="$HOME/.homebrew"
                        if [ -d "$brew_prefix" ] && [ -x "$brew_prefix/bin/brew" ]; then
                            info "Existing Homebrew found at $brew_prefix"
                        else
                            [ -d "$brew_prefix" ] && rm -rf "$brew_prefix"
                            step "Cloning Homebrew into $brew_prefix..."
                            git clone --depth=1 https://github.com/Homebrew/brew "$brew_prefix"
                        fi

                        # Make brew available in this session
                        eval "$("$brew_prefix/bin/brew" shellenv)"

                        # Persist to shell profile
                        local shell_rc=""
                        if [ -f "$HOME/.zshrc" ]; then
                            shell_rc="$HOME/.zshrc"
                        elif [ -f "$HOME/.bashrc" ]; then
                            shell_rc="$HOME/.bashrc"
                        elif [ -f "$HOME/.bash_profile" ]; then
                            shell_rc="$HOME/.bash_profile"
                        fi

                        if [ -n "$shell_rc" ]; then
                            if ! grep -q '.homebrew/bin/brew shellenv' "$shell_rc" 2>/dev/null; then
                                echo '' >> "$shell_rc"
                                echo '# Homebrew (user-local install)' >> "$shell_rc"
                                echo "eval \"\$($brew_prefix/bin/brew shellenv)\"" >> "$shell_rc"
                                info "Added Homebrew to $shell_rc"
                            fi
                        else
                            warn "Could not detect shell profile. Add this to your shell config:"
                            echo "  eval \"\$($brew_prefix/bin/brew shellenv)\""
                        fi

                        info "Homebrew installed to $brew_prefix"
                        echo ""

                        # Now install Python via the fresh Homebrew
                        step "Installing Python 3.12 via Homebrew..."
                        brew install python@3.12
                        brew link --overwrite python@3.12 2>/dev/null || true

                        # Retry detection
                        for cmd in python3 python; do
                            if command -v "$cmd" &>/dev/null; then
                                ver=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)
                                major=$(echo "$ver" | cut -d. -f1)
                                minor=$(echo "$ver" | cut -d. -f2)
                                if [ "${major:-0}" -ge 3 ] && [ "${minor:-0}" -ge 9 ]; then
                                    py="$cmd"
                                    break
                                fi
                            fi
                        done

                        if [ -z "$py" ]; then
                            echo ""
                            warn "Python installed but not detected on PATH."
                            echo "  Open a new terminal and re-run this installer."
                            exit 1
                        fi
                    else
                        echo ""
                        echo "  Install Python manually via one of:"
                        echo "    1. python.org: https://www.python.org/downloads/"
                        echo "    2. pyenv: https://github.com/pyenv/pyenv#installation"
                        exit 1
                    fi
                else
                    echo "  Install Python via one of:"
                    echo "    1. Homebrew: https://brew.sh"
                    echo "       Then: brew install python@3.12"
                    echo "    2. python.org: https://www.python.org/downloads/"
                    echo "    3. pyenv: https://github.com/pyenv/pyenv#installation"
                    exit 1
                fi
            fi
        elif [ "$(uname -s)" = "Linux" ]; then
            echo "  Install Python 3.9+:"
            if command -v apt &>/dev/null; then
                echo "    sudo apt update && sudo apt install python3.12 python3.12-venv"
            elif command -v dnf &>/dev/null; then
                echo "    sudo dnf install python3.12"
            elif command -v pacman &>/dev/null; then
                echo "    sudo pacman -S python"
            else
                echo "    Install python3.12 via your package manager"
            fi
            echo "  Or use pyenv: https://github.com/pyenv/pyenv#installation"
            exit 1
        else
            echo "  Download Python 3.9+: https://www.python.org/downloads/"
            exit 1
        fi
    fi

    info "Python $ver found ($py)"
    PYTHON="$py"
}

# ── Install via pipx (preferred) or pip ─────────────────────────
install_tweek() {
    echo ""
    step "Installing Tweek..."
    echo ""

    # Prefer pipx > pip
    if command -v pipx &>/dev/null; then
        info "Using pipx (recommended)"
        if pipx list 2>/dev/null | grep -q "tweek"; then
            step "Upgrading existing installation..."
            pipx upgrade tweek 2>/dev/null || pipx install --force tweek
        else
            pipx install tweek
        fi
        INSTALL_METHOD="pipx"
        return
    fi

    # Fall back to pip
    if command -v pip3 &>/dev/null; then
        warn "pipx not found, using pip3 (consider: brew install pipx)"
        pip3 install --user tweek
        INSTALL_METHOD="pip"
        return
    fi

    if command -v pip &>/dev/null; then
        warn "pipx not found, using pip"
        pip install --user tweek
        INSTALL_METHOD="pip"
        return
    fi

    fail "No package manager found. Install pipx or pip first."
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

    # Check common locations
    for path in "$HOME/.local/bin/tweek" "$HOME/.local/pipx/venvs/tweek/bin/tweek"; do
        if [ -x "$path" ]; then
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
    check_python
    install_tweek
    verify_install
    setup_hooks
    setup_moltbot
    run_doctor
    finish
}

main "$@"
