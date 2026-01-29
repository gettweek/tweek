#!/bin/bash
# Tweek Installer
# Usage: curl -sSL https://raw.githubusercontent.com/gettweek/tweek/main/scripts/install.sh | bash

set -e

TWEEK_VERSION="${TWEEK_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
cat << 'EOF'
 ████████╗██╗    ██╗███████╗███████╗██╗  ██╗
 ╚══██╔══╝██║    ██║██╔════╝██╔════╝██║ ██╔╝
    ██║   ██║ █╗ ██║█████╗  █████╗  █████╔╝
    ██║   ██║███╗██║██╔══╝  ██╔══╝  ██╔═██╗
    ██║   ╚███╔███╔╝███████╗███████╗██║  ██╗
    ╚═╝    ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝
EOF
echo -e "${NC}"
echo "Security for AI Coding Assistants"
echo ""

# Check for Python 3.11+
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 11 ]; then
            echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION found"
            return 0
        fi
    fi

    echo -e "${RED}✗${NC} Python 3.11+ required but not found"
    echo ""
    echo "Install Python 3.11+ first:"
    echo "  macOS:  brew install python@3.11"
    echo "  Ubuntu: sudo apt install python3.11"
    echo "  Other:  https://www.python.org/downloads/"
    exit 1
}

# Check for pip
check_pip() {
    if command -v pip3 &> /dev/null; then
        echo -e "${GREEN}✓${NC} pip found"
        return 0
    elif command -v pip &> /dev/null; then
        echo -e "${GREEN}✓${NC} pip found"
        return 0
    fi

    echo -e "${RED}✗${NC} pip not found"
    echo "Install pip: python3 -m ensurepip --upgrade"
    exit 1
}

# Install Tweek
install_tweek() {
    echo ""
    echo -e "${CYAN}Installing Tweek...${NC}"

    # Try PyPI first, fall back to git if not published yet
    if pip3 install --user tweek 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Installed from PyPI"
    else
        echo -e "${YELLOW}Not on PyPI yet, installing from GitHub...${NC}"
        pip3 install --user "git+https://github.com/gettweek/tweek.git"
    fi

    echo ""
    echo -e "${GREEN}✓${NC} Tweek installed successfully!"
}

# Verify installation
verify_install() {
    if command -v tweek &> /dev/null; then
        echo ""
        tweek --version
        return 0
    fi

    # Check if it's in user bin but not in PATH
    if [ -f "$HOME/.local/bin/tweek" ]; then
        echo ""
        echo -e "${YELLOW}Note:${NC} Add ~/.local/bin to your PATH:"
        echo ""
        echo '  echo '\''export PATH="$HOME/.local/bin:$PATH"'\'' >> ~/.bashrc'
        echo '  # or for zsh:'
        echo '  echo '\''export PATH="$HOME/.local/bin:$PATH"'\'' >> ~/.zshrc'
        echo ""
    fi
}

# Setup hooks
setup_hooks() {
    echo ""
    echo -e "${CYAN}Setting up Claude Code hooks...${NC}"
    echo ""

    read -p "Install Tweek hooks now? [Y/n] " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
        if command -v tweek &> /dev/null; then
            tweek install
        else
            "$HOME/.local/bin/tweek" install
        fi
    else
        echo ""
        echo "Run 'tweek install' later to set up hooks."
    fi
}

# Main
main() {
    echo "Checking requirements..."
    echo ""

    check_python
    check_pip
    install_tweek
    verify_install
    setup_hooks

    echo ""
    echo -e "${GREEN}Done!${NC} Your Claude Code sessions are now protected."
    echo ""
    echo "Commands:"
    echo "  tweek status     - Check protection status"
    echo "  tweek logs show  - View security events"
    echo "  tweek --help     - See all commands"
    echo ""
}

main
