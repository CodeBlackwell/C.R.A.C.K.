#!/bin/bash
# B.R.E.A.C.H. Launcher Script
#
# Usage:
#   ./start.sh           # Normal mode
#   ./start.sh debug     # Debug mode
#   ./start.sh verbose   # Maximum verbosity
#   ./start.sh build     # Build only

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║${NC}  ${RED}B${NC}.${YELLOW}R${NC}.${GREEN}E${NC}.${CYAN}A${NC}.${RED}C${NC}.${YELLOW}H${NC}.                                      ${CYAN}║${NC}"
echo -e "${CYAN}║${NC}  Box Reconnaissance, Exploitation & Attack Command Hub ${CYAN}║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
echo ""

# Check for node_modules
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}[!] Installing dependencies...${NC}"
    npm install

    # Rebuild native modules for Electron
    echo -e "${YELLOW}[!] Rebuilding native modules for Electron...${NC}"
    npm run rebuild
fi

# Check for neo4j
if ! command -v cypher-shell &> /dev/null; then
    echo -e "${YELLOW}[!] Warning: Neo4j cypher-shell not found. Database features may not work.${NC}"
fi

# Parse arguments
MODE="${1:-dev}"

case "$MODE" in
    debug)
        echo -e "${GREEN}[+] Starting B.R.E.A.C.H. in debug mode...${NC}"
        export DEBUG=true
        npm run dev:debug
        ;;
    verbose)
        echo -e "${GREEN}[+] Starting B.R.E.A.C.H. in verbose mode...${NC}"
        export DEBUG=true
        export DEBUG_CATEGORIES="*"
        npm run dev:verbose
        ;;
    build)
        echo -e "${GREEN}[+] Building B.R.E.A.C.H....${NC}"
        npm run build
        echo -e "${GREEN}[+] Build complete! Run with: npm run preview${NC}"
        ;;
    *)
        echo -e "${GREEN}[+] Starting B.R.E.A.C.H....${NC}"
        npm run dev
        ;;
esac
