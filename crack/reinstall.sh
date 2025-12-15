#!/bin/bash
# Reinstall CRACK in development mode
# Supports: pip, uv, and handles Kali/Debian externally-managed Python

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }

cd "$(dirname "$0")"

# Detect package manager
if command -v uv &>/dev/null; then
    PKG_MGR="uv"
    INSTALL_CMD="uv pip install -e ."
    UNINSTALL_CMD="uv pip uninstall crack -y"
elif [ -n "$VIRTUAL_ENV" ]; then
    PKG_MGR="pip (venv)"
    INSTALL_CMD="python3 -m pip install -e ."
    UNINSTALL_CMD="python3 -m pip uninstall crack -y"
else
    PKG_MGR="pip (system)"
    INSTALL_CMD="python3 -m pip install -e . --break-system-packages"
    UNINSTALL_CMD="python3 -m pip uninstall crack -y --break-system-packages"
fi

info "Using: $PKG_MGR"

# Uninstall existing
info "Uninstalling crack..."
$UNINSTALL_CMD 2>/dev/null || true

# Install in dev mode
info "Installing crack in development mode..."
$INSTALL_CMD

# Verify
if command -v crack &>/dev/null; then
    info "Success! CRACK installed at: $(which crack)"
    crack --version 2>/dev/null || true
else
    warn "Installed but 'crack' not in PATH. Try: source ~/.bashrc"
fi
