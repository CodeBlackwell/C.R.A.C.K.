#!/bin/bash
# Master script to run QA stories for plugin priority testing
#
# Usage: ./run_qa_story.sh <story_number>
# Example: ./run_qa_story.sh 1

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check argument
if [ -z "$1" ]; then
    echo -e "${RED}Error: Story number required${NC}"
    echo ""
    echo "Usage: ./run_qa_story.sh <story_number>"
    echo ""
    echo "Available stories:"
    echo "  1 - Generic HTTP (PHP-Bypass should NOT activate)"
    echo "  2 - HTTP with PHP in version (both plugins activate)"
    echo "  3 - Progressive discovery (finding-based activation)"
    echo "  4 - Profile load from disk (event handler test)"
    echo "  5 - Webshell finding (highest priority)"
    echo "  6 - Nmap import (full integration)"
    echo "  7 - Multi-stage discovery (cascading plugins)"
    echo ""
    exit 1
fi

STORY_NUM=$1

# Map story number to directory
case $STORY_NUM in
    1) STORY_DIR="1_generic_http" ;;
    2) STORY_DIR="2_http_with_php" ;;
    3) STORY_DIR="3_progressive_discovery" ;;
    4) STORY_DIR="4_profile_load" ;;
    5) STORY_DIR="5_webshell" ;;
    6) STORY_DIR="6_nmap_import" ;;
    7) STORY_DIR="7_multistage" ;;
    *)
        echo -e "${RED}Error: Invalid story number: $STORY_NUM${NC}"
        echo "Must be 1-7"
        exit 1
        ;;
esac

STORY_PATH="qa_profiles/$STORY_DIR"

# Check if story exists
if [ ! -d "$STORY_PATH" ]; then
    echo -e "${RED}Error: Story directory not found: $STORY_PATH${NC}"
    exit 1
fi

# Get target name from profile filename pattern
TARGET="qa-story-$STORY_NUM-$(echo $STORY_DIR | sed 's/_/-/g' | sed 's/^[0-9]-//')"

# Check if profile exists in CRACK_targets/
PROFILE_PATH="CRACK_targets/${TARGET}.json"
if [ ! -f "$PROFILE_PATH" ]; then
    echo -e "${RED}Error: Profile not found: $PROFILE_PATH${NC}"
    echo ""
    echo "Generate profiles first:"
    echo "  python qa_profiles/generate_profiles.py"
    exit 1
fi

# Display banner
echo ""
echo "========================================================================"
echo -e "${CYAN}QA Story $STORY_NUM: $(basename $STORY_DIR | sed 's/_/ /g' | sed 's/\b\(.\)/\u\1/g')${NC}"
echo "========================================================================"
echo ""
echo -e "${BLUE}Target:${NC} $TARGET"
echo -e "${BLUE}Profile:${NC} $PROFILE_PATH"
echo -e "${BLUE}Story Instructions:${NC} $STORY_PATH/STORY.md"
echo ""

# Display story instructions if available
if [ -f "$STORY_PATH/STORY.md" ]; then
    echo "------------------------------------------------------------------------"
    echo "Test Instructions:"
    echo "------------------------------------------------------------------------"
    head -30 "$STORY_PATH/STORY.md" | tail -25
    echo ""
    echo -e "${YELLOW}[Full instructions in: $STORY_PATH/STORY.md]${NC}"
    echo "------------------------------------------------------------------------"
    echo ""
fi

# Confirm before launching
echo -e "${YELLOW}Ready to launch TUI with debug logging${NC}"
echo ""
read -p "Press Enter to continue, or Ctrl+C to cancel..."
echo ""

# Clear old debug logs for this session
echo "Clearing old debug logs..."
rm -f .debug_logs/tui_debug_*.log 2>/dev/null || true

# Launch TUI with debug logging
echo "========================================================================"
echo "Launching TUI..."
echo "========================================================================"
echo ""
echo -e "${CYAN}Command:${NC} crack track --tui $TARGET --debug --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE"
echo ""

# Run TUI
crack track --tui "$TARGET" \
    --debug \
    --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE

# After TUI exits
echo ""
echo "========================================================================"
echo "TUI Session Ended"
echo "========================================================================"
echo ""

# Check if verification script exists
if [ -f "$STORY_PATH/verify.sh" ]; then
    echo -e "${BLUE}Running automated verification...${NC}"
    echo ""

    # Run verification
    if bash "$STORY_PATH/verify.sh"; then
        echo ""
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}✓ Story $STORY_NUM: PASSED${NC}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════${NC}"
        echo ""
        exit 0
    else
        echo ""
        echo -e "${RED}═══════════════════════════════════════════════════════════════════════${NC}"
        echo -e "${RED}✗ Story $STORY_NUM: FAILED${NC}"
        echo -e "${RED}═══════════════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "Review debug logs:"
        ls -lt .debug_logs/tui_debug_*.log | head -1 | awk '{print "  " $NF}'
        echo ""
        exit 1
    fi
else
    echo -e "${YELLOW}⚠ No verification script found${NC}"
    echo "  Expected: $STORY_PATH/verify.sh"
    echo ""
    echo "Manual verification required:"
    echo "  1. Check task tree for expected tasks"
    echo "  2. Review debug logs in .debug_logs/"
    echo ""
    exit 0
fi
