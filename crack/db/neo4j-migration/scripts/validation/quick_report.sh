#!/bin/bash
#
# Quick Report - Run all diagnostic utilities and generate comprehensive report
#
# Usage: ./quick_report.sh [--verbose] [--save]
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERBOSE=""
SAVE_OUTPUT=0

# Parse arguments
for arg in "$@"; do
    case $arg in
        --verbose|-v)
            VERBOSE="--verbose"
            ;;
        --save|-s)
            SAVE_OUTPUT=1
            ;;
        --help|-h)
            echo "Usage: $0 [--verbose] [--save]"
            echo ""
            echo "Options:"
            echo "  --verbose, -v    Show detailed violations and examples"
            echo "  --save, -s       Save output to timestamped file"
            echo "  --help, -h       Show this help message"
            exit 0
            ;;
    esac
done

# Colors
GREEN='\033[32m'
YELLOW='\033[33m'
RED='\033[31m'
BLUE='\033[36m'
BOLD='\033[1m'
RESET='\033[0m'

# Output file
if [ $SAVE_OUTPUT -eq 1 ]; then
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTPUT_FILE="/tmp/crack_db_report_${TIMESTAMP}.txt"
    echo -e "${BLUE}Saving output to: ${OUTPUT_FILE}${RESET}"
    exec > >(tee "$OUTPUT_FILE")
fi

echo ""
echo -e "${BOLD}${BLUE}╔════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${BLUE}║${RESET}  ${BOLD}CRACK DATABASE DIAGNOSTIC REPORT${RESET}                                  ${BOLD}${BLUE}║${RESET}"
echo -e "${BOLD}${BLUE}╚════════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${DIM}Generated: $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
echo ""

# Check if Neo4j is running
echo -e "${BOLD}Checking Neo4j status...${RESET}"
if pgrep -x "java" > /dev/null && sudo neo4j status > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Neo4j is running${RESET}"
    NEO4J_RUNNING=1
else
    echo -e "${RED}✗ Neo4j is not running${RESET}"
    echo -e "${YELLOW}  To start: sudo neo4j start${RESET}"
    NEO4J_RUNNING=0
fi
echo ""

# 1. JSON Statistics
echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}1. JSON FILE ANALYSIS${RESET}"
echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
python3 "$SCRIPT_DIR/json_stats.py" $VERBOSE
JSON_EXIT=$?

# 2. Neo4j Statistics (if running)
if [ $NEO4J_RUNNING -eq 1 ]; then
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}2. NEO4J DATABASE ANALYSIS${RESET}"
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    python3 "$SCRIPT_DIR/neo4j_stats.py" $VERBOSE
    NEO4J_EXIT=$?

    # 3. Backend Comparison
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}3. BACKEND COMPARISON${RESET}"
    echo -e "${BOLD}${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    python3 "$SCRIPT_DIR/compare_backends.py"
    COMPARE_EXIT=$?
else
    echo -e "${YELLOW}⚠ Skipping Neo4j analysis (Neo4j not running)${RESET}"
    echo -e "${YELLOW}⚠ Skipping backend comparison (Neo4j not running)${RESET}"
    NEO4J_EXIT=1
    COMPARE_EXIT=1
fi

# Summary
echo ""
echo -e "${BOLD}${BLUE}╔════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}${BLUE}║${RESET}  ${BOLD}DIAGNOSTIC SUMMARY${RESET}                                                 ${BOLD}${BLUE}║${RESET}"
echo -e "${BOLD}${BLUE}╚════════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

# JSON status
if [ $JSON_EXIT -eq 0 ]; then
    echo -e "${GREEN}✓ JSON files analyzed successfully${RESET}"
else
    echo -e "${RED}✗ JSON file analysis had errors${RESET}"
fi

# Neo4j status
if [ $NEO4J_RUNNING -eq 0 ]; then
    echo -e "${YELLOW}⚠ Neo4j database not running${RESET}"
    echo -e "  ${DIM}Start with: sudo neo4j start${RESET}"
elif [ $NEO4J_EXIT -eq 0 ]; then
    echo -e "${GREEN}✓ Neo4j database analyzed successfully${RESET}"
else
    echo -e "${RED}✗ Neo4j database analysis had errors${RESET}"
fi

# Comparison status
if [ $NEO4J_RUNNING -eq 1 ]; then
    if [ $COMPARE_EXIT -eq 0 ]; then
        echo -e "${GREEN}✓ Backend comparison completed${RESET}"
    else
        echo -e "${RED}✗ Backend comparison had errors${RESET}"
    fi
fi

# Recommendations
echo ""
echo -e "${BOLD}Recommendations:${RESET}"

# Check if verbose was used
if [ -z "$VERBOSE" ]; then
    echo -e "  ${BLUE}ℹ${RESET} Run with ${BOLD}--verbose${RESET} for detailed violation examples"
fi

# Check if output was saved
if [ $SAVE_OUTPUT -eq 1 ]; then
    echo -e "  ${GREEN}✓${RESET} Report saved to: ${BOLD}${OUTPUT_FILE}${RESET}"
else
    echo -e "  ${BLUE}ℹ${RESET} Run with ${BOLD}--save${RESET} to save output to file"
fi

# Migration recommendations
if [ $NEO4J_RUNNING -eq 1 ]; then
    echo -e "  ${BLUE}ℹ${RESET} Review backend comparison for migration status"
    echo -e "  ${BLUE}ℹ${RESET} If differences found, run migration script to sync"
fi

echo ""
echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════════${RESET}"
echo ""

exit 0
