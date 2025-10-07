#!/bin/bash
# Reinstall script for CRACK toolkit
# Handles clean uninstall and reinstall with proper dependencies

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  CRACK Toolkit Reinstall Script${NC}"
echo -e "${GREEN}========================================${NC}\n"

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo -e "${YELLOW}[1/4] Uninstalling existing installation...${NC}"
pip uninstall -y crack-toolkit 2>/dev/null || true

echo -e "${YELLOW}[2/4] Cleaning build artifacts...${NC}"
rm -rf "$SCRIPT_DIR/build" 2>/dev/null || true
rm -rf "$SCRIPT_DIR/dist" 2>/dev/null || true
rm -rf "$SCRIPT_DIR/*.egg-info" 2>/dev/null || true
rm -rf "$SCRIPT_DIR/crack_toolkit.egg-info" 2>/dev/null || true
find "$SCRIPT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "$SCRIPT_DIR" -type f -name "*.pyc" -delete 2>/dev/null || true

echo -e "${YELLOW}[3/4] Installing in editable mode...${NC}"
cd "$SCRIPT_DIR"
pip install -e . --break-system-packages

echo -e "${YELLOW}[4/4] Verifying installation...${NC}"
if command -v crack &> /dev/null; then
    echo -e "${GREEN}✓ crack command found${NC}"

    # Test import
    if python3 -c "from crack.network import scan_analyzer" 2>/dev/null; then
        echo -e "${GREEN}✓ Module imports working${NC}"
    else
        echo -e "${RED}✗ Module import failed${NC}"
        exit 1
    fi

    # Show version
    echo -e "\n${GREEN}Installation successful!${NC}"
    echo -e "Version: $(crack --version 2>/dev/null || echo 'v1.0.0')"
    echo -e "\nAvailable commands:"
    echo "  crack scan-analyze <nmap_file>  # Analyze nmap scan"
    echo "  crack enum-scan <target>        # Full enumeration"
    echo "  crack html-enum <url>           # HTML enumeration"
    echo "  crack sqli-scan <url>           # SQLi scanning"
    echo "  crack param-discover <url>      # Parameter discovery"

    echo -e "\n${GREEN}Try it out:${NC}"
    echo "  crack scan-analyze /tmp/scanme_comprehensive.nmap"
else
    echo -e "${RED}✗ Installation failed - crack command not found${NC}"
    exit 1
fi

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}  Reinstallation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"