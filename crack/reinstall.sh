#!/bin/bash
# Reinstall script for CRACK toolkit
# Handles clean uninstall and reinstall with proper dependencies

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo -e "${GREEN}${BOLD}════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  CRACK Toolkit Reinstall Script${NC}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════${NC}\n"

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo -e "${YELLOW}[1/5] Uninstalling existing installation...${NC}"
pip uninstall -y crack-toolkit 2>/dev/null || true
echo -e "${GREEN}  ✓ Uninstall complete${NC}"

echo -e "\n${YELLOW}[2/5] Cleaning build artifacts...${NC}"
rm -rf "$SCRIPT_DIR/build" 2>/dev/null || true
rm -rf "$SCRIPT_DIR/dist" 2>/dev/null || true
rm -rf "$SCRIPT_DIR"/*.egg-info 2>/dev/null || true
rm -rf "$SCRIPT_DIR/crack_toolkit.egg-info" 2>/dev/null || true
find "$SCRIPT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$SCRIPT_DIR" -type f -name "*.pyc" -delete 2>/dev/null || true
echo -e "${GREEN}  ✓ Build artifacts cleaned${NC}"

echo -e "\n${YELLOW}[3/5] Installing in editable mode...${NC}"
cd "$SCRIPT_DIR"
pip install -e . --break-system-packages
echo -e "${GREEN}  ✓ Installation complete${NC}"

echo -e "\n${YELLOW}[4/5] Installing pywal16 for 250+ theme support...${NC}"
pip install --break-system-packages pywal16 2>/dev/null || echo -e "${YELLOW}  ⚠ Pywal16 install skipped (optional)${NC}"
if python3 -c "import pywal" 2>/dev/null; then
    echo -e "${GREEN}  ✓ Pywal16 installed - 256 themes available${NC}"
else
    echo -e "${YELLOW}  → Running with 6 built-in themes${NC}"
fi

echo -e "\n${YELLOW}[5/6] Verifying installation...${NC}"
if command -v crack &> /dev/null; then
    echo -e "${GREEN}  ✓ crack command found${NC}"

    # Test core module imports
    if python3 -c "from crack.track import cli; from crack.reference import HybridCommandRegistry" 2>/dev/null; then
        echo -e "${GREEN}  ✓ Core modules working${NC}"
    else
        echo -e "${RED}  ✗ Module import failed${NC}"
        exit 1
    fi

    # Test track command
    if crack track --help &>/dev/null; then
        echo -e "${GREEN}  ✓ Track module working${NC}"
    else
        echo -e "${RED}  ✗ Track module failed${NC}"
        exit 1
    fi
else
    echo -e "${RED}  ✗ Installation failed - crack command not found${NC}"
    exit 1
fi

echo -e "\n${YELLOW}[6/6] Installation Summary${NC}"
echo -e "\n${GREEN}${BOLD}Installation successful!${NC}"
echo -e "Version: $(crack --version 2>/dev/null | grep -o 'v[0-9.]*' || echo 'v1.0.0')"

echo -e "\n${CYAN}${BOLD}═══════════ PRIMARY TOOLS ═══════════${NC}"
echo -e "\n${CYAN}▶ CRACK Track${NC} - Enumeration Tracking & Task Management"
echo -e "  ${GREEN}crack track <target>${NC}                    # TUI interface (DEFAULT)"
echo -e "  ${GREEN}crack track -i <target>${NC}                 # Terminal interactive mode"
echo -e "  ${GREEN}crack track <target> --import scan.xml${NC}  # Import nmap results"
echo -e "  ${GREEN}crack track <target> --export report.md${NC} # Export OSCP writeup"

echo -e "\n${CYAN}▶ Reference System${NC} - 70+ OSCP Commands"
echo -e "  ${GREEN}crack reference --fill bash-reverse-shell${NC}  # Auto-fill LHOST/LPORT"
echo -e "  ${GREEN}crack reference --category post-exploit${NC}    # List privesc commands"
echo -e "  ${GREEN}crack reference --tag QUICK_WIN${NC}            # Find quick wins"
echo -e "  ${GREEN}crack reference --config auto${NC}              # Auto-detect settings"

echo -e "\n${CYAN}▶ Session Management${NC} - Reverse Shell Handler"
echo -e "  ${GREEN}crack session start tcp --port 4444${NC}        # TCP listener"
echo -e "  ${GREEN}crack session start http --port 8080${NC}       # HTTP beacon"
echo -e "  ${GREEN}crack session upgrade <id> --method auto${NC}   # TTY upgrade"

echo -e "\n${CYAN}${BOLD}═══════════ WEB TOOLS ═══════════${NC}"
echo -e "  ${GREEN}crack html-enum <url>${NC}                      # HTML enumeration"
echo -e "  ${GREEN}crack param-discover <url>${NC}                 # Parameter discovery"
echo -e "  ${GREEN}crack sqli-scan <url>${NC}                      # SQL injection scanner"

echo -e "\n${CYAN}${BOLD}═══════════ NETWORK TOOLS ═══════════${NC}"
echo -e "  ${GREEN}crack port-scan <target> --full${NC}            # Two-stage port scan"
echo -e "  ${GREEN}crack enum-scan <target>${NC}                   # Fast scan + CVE lookup"
echo -e "  ${GREEN}crack scan-analyze <nmap_file>${NC}             # Parse nmap output"

echo -e "\n${CYAN}${BOLD}═══════════ DEBUG LOGGING ═══════════${NC}"
echo -e "  ${GREEN}crack track <target> --debug${NC}                                    # Basic debug"
echo -e "  ${GREEN}crack track <target> --debug --debug-categories=UI:VERBOSE${NC}      # Category filter"
echo -e "  ${GREEN}crack track <target> --debug --debug-output=both${NC}                # Console + file"
echo -e "  Log location: ${CYAN}.debug_logs/tui_debug_*${NC}"

echo -e "\n${YELLOW}💡 TIP:${NC} Run ${CYAN}crack --help${NC} to see all available tools"
echo -e "${YELLOW}💡 TIP:${NC} Run ${CYAN}crack track --help${NC} for complete Track documentation"

echo -e "\n${GREEN}${BOLD}════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  Ready for OSCP Penetration Testing!${NC}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════${NC}\n"