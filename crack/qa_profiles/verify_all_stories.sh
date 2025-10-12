#!/bin/bash
# Master script to run all QA stories sequentially
#
# Usage: ./verify_all_stories.sh
#
# Runs stories 1-7 in sequence, collecting results

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Results tracking
TOTAL_STORIES=7
PASSED_STORIES=0
FAILED_STORIES=0
SKIPPED_STORIES=0

# Story results array
declare -a STORY_RESULTS

# Banner
echo ""
echo "========================================================================"
echo -e "${CYAN}QA Story Verification Suite - Complete Test Run${NC}"
echo "========================================================================"
echo ""
echo "This will run all 7 QA stories sequentially with automated verification."
echo "Each story tests different aspects of the plugin priority system."
echo ""
echo "Stories:"
echo "  1. Generic HTTP (PHP-Bypass should NOT activate)"
echo "  2. HTTP with PHP in version (both plugins activate)"
echo "  3. Progressive discovery (finding-based activation)"
echo "  4. Profile load from disk (event handler test)"
echo "  5. Webshell finding (highest priority)"
echo "  6. Nmap import (full integration)"
echo "  7. Multi-stage discovery (cascading plugins)"
echo ""
echo -e "${YELLOW}Note: This will launch TUI 7 times. Press 'q' to exit each session.${NC}"
echo ""
read -p "Press Enter to start, or Ctrl+C to cancel..."
echo ""

# Run each story
for STORY_NUM in {1..7}; do
    echo ""
    echo "========================================================================"
    echo -e "${BLUE}Running Story $STORY_NUM / $TOTAL_STORIES${NC}"
    echo "========================================================================"
    echo ""

    # Check if run_qa_story.sh exists
    if [ ! -f "qa_profiles/run_qa_story.sh" ]; then
        echo -e "${RED}✗ Error: qa_profiles/run_qa_story.sh not found${NC}"
        exit 1
    fi

    # Run the story
    if ./qa_profiles/run_qa_story.sh "$STORY_NUM"; then
        echo -e "${GREEN}✓ Story $STORY_NUM: PASSED${NC}"
        STORY_RESULTS[$STORY_NUM]="PASSED"
        ((PASSED_STORIES++))
    else
        EXIT_CODE=$?

        # Check if verification script exists
        STORY_DIR=""
        case $STORY_NUM in
            1) STORY_DIR="1_generic_http" ;;
            2) STORY_DIR="2_http_with_php" ;;
            3) STORY_DIR="3_progressive_discovery" ;;
            4) STORY_DIR="4_profile_load" ;;
            5) STORY_DIR="5_webshell" ;;
            6) STORY_DIR="6_nmap_import" ;;
            7) STORY_DIR="7_multistage" ;;
        esac

        if [ ! -f "qa_profiles/$STORY_DIR/verify.sh" ]; then
            echo -e "${YELLOW}⚠ Story $STORY_NUM: SKIPPED (no verification script)${NC}"
            STORY_RESULTS[$STORY_NUM]="SKIPPED"
            ((SKIPPED_STORIES++))
        else
            echo -e "${RED}✗ Story $STORY_NUM: FAILED${NC}"
            STORY_RESULTS[$STORY_NUM]="FAILED"
            ((FAILED_STORIES++))
        fi
    fi

    # Pause between stories
    if [ $STORY_NUM -lt $TOTAL_STORIES ]; then
        echo ""
        echo -e "${YELLOW}Press Enter to continue to next story...${NC}"
        read
    fi
done

# Final Summary
echo ""
echo ""
echo "========================================================================"
echo -e "${CYAN}QA Story Verification Suite - Final Results${NC}"
echo "========================================================================"
echo ""

# Individual story results
echo "Story Results:"
echo ""
for i in {1..7}; do
    RESULT="${STORY_RESULTS[$i]}"
    case $RESULT in
        "PASSED")
            echo -e "  Story $i: ${GREEN}✓ PASSED${NC}"
            ;;
        "FAILED")
            echo -e "  Story $i: ${RED}✗ FAILED${NC}"
            ;;
        "SKIPPED")
            echo -e "  Story $i: ${YELLOW}⚠ SKIPPED${NC}"
            ;;
        *)
            echo -e "  Story $i: ${YELLOW}? UNKNOWN${NC}"
            ;;
    esac
done

echo ""
echo "Summary:"
echo -e "  ${GREEN}Passed:${NC}  $PASSED_STORIES / $TOTAL_STORIES"
echo -e "  ${RED}Failed:${NC}  $FAILED_STORIES / $TOTAL_STORIES"
echo -e "  ${YELLOW}Skipped:${NC} $SKIPPED_STORIES / $TOTAL_STORIES"
echo ""

# Overall result
if [ $FAILED_STORIES -eq 0 ] && [ $PASSED_STORIES -eq $TOTAL_STORIES ]; then
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}✓ ALL STORIES PASSED${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Plugin priority system fully validated:"
    echo "  ✓ Generic HTTP handling"
    echo "  ✓ Multi-plugin activation"
    echo "  ✓ Progressive discovery"
    echo "  ✓ Event handler registration"
    echo "  ✓ Priority-based task generation"
    echo "  ✓ Full integration workflows"
    echo ""
    echo "Ready for production use!"
    echo ""
    exit 0
elif [ $SKIPPED_STORIES -gt 0 ]; then
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}⚠ SOME STORIES SKIPPED${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Skipped stories need verification scripts created:"

    for i in {1..7}; do
        if [ "${STORY_RESULTS[$i]}" == "SKIPPED" ]; then
            STORY_DIR=""
            case $i in
                1) STORY_DIR="1_generic_http" ;;
                2) STORY_DIR="2_http_with_php" ;;
                3) STORY_DIR="3_progressive_discovery" ;;
                4) STORY_DIR="4_profile_load" ;;
                5) STORY_DIR="5_webshell" ;;
                6) STORY_DIR="6_nmap_import" ;;
                7) STORY_DIR="7_multistage" ;;
            esac
            echo "  - qa_profiles/$STORY_DIR/verify.sh"
        fi
    done

    echo ""
    echo "Create verification scripts following the pattern in:"
    echo "  qa_profiles/1_generic_http/verify.sh"
    echo "  qa_profiles/2_http_with_php/verify.sh"
    echo ""
    exit 2
else
    echo -e "${RED}═══════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}✗ SOME STORIES FAILED${NC}"
    echo -e "${RED}═══════════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Failed stories:"

    for i in {1..7}; do
        if [ "${STORY_RESULTS[$i]}" == "FAILED" ]; then
            echo "  - Story $i"
        fi
    done

    echo ""
    echo "Review debug logs in .debug_logs/ for details."
    echo ""
    echo "Common failure patterns:"
    echo "  - Plugin priority logic incorrect"
    echo "  - Event handlers not registered"
    echo "  - Task generation missing"
    echo "  - Confidence scoring wrong"
    echo ""
    echo "See qa_profiles/README.md for troubleshooting guide."
    echo ""
    exit 1
fi
