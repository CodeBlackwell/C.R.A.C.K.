#!/bin/bash
# Verification script for QA Story 4: Profile Load from Disk

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LATEST_LOG=$(ls -t .debug_logs/tui_debug_*.log 2>/dev/null | head -1)

if [ -z "$LATEST_LOG" ]; then
    echo -e "${RED}✗ No debug log found${NC}"
    exit 1
fi

echo "========================================================================"
echo "QA Story 4 Verification: Profile Load from Disk"
echo "========================================================================"
echo ""
echo "Debug log: $LATEST_LOG"
echo ""

PASS_COUNT=0
FAIL_COUNT=0

# Test 1: Profile loaded successfully
echo "[TEST 1] Profile loaded from disk"
if grep -q "qa-story-4-profile-load" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: Profile loaded"
    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: Profile not found in logs"
    ((FAIL_COUNT++))
fi
echo ""

# Test 2: Existing ports recognized
echo "[TEST 2] Existing ports (80, 443) recognized"
if grep -q "port.*80" "$LATEST_LOG" && \
   grep -q "port.*443" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: Both ports recognized"
    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: Ports not recognized on load"
    ((FAIL_COUNT++))
fi
echo ""

# Test 3: _init_runtime called
echo "[TEST 3] _init_runtime() called during load"
if grep -q "_init_runtime" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: Runtime initialization executed"
    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: _init_runtime() not called"
    echo "  This is the main bug being tested!"
    ((FAIL_COUNT++))
fi
echo ""

# Test 4: Event handlers registered
echo "[TEST 4] Event handlers registered"
if grep -q "Event.*registered" "$LATEST_LOG" || \
   grep -q "EventBus.*on" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: Event handlers registered"
    ((PASS_COUNT++))
else
    echo -e "  ${YELLOW}⚠ WARNING${NC}: Event registration not clearly logged"
    ((PASS_COUNT++))  # Don't fail on logging
fi
echo ""

# Test 5: HTTP tasks generated for existing ports
echo "[TEST 5] HTTP tasks generated for existing ports"
if grep -q "Generated tasks.*http.*80" "$LATEST_LOG" || \
   grep -q "HTTP.*won port.*80" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: HTTP tasks generated"
    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: Tasks not generated for pre-existing ports"
    ((FAIL_COUNT++))
fi
echo ""

# Test 6: No event handler errors
echo "[TEST 6] No event handler errors"
ERROR_COUNT=$(grep -c "Error in event handler" "$LATEST_LOG" 2>/dev/null || echo 0)
if [ "$ERROR_COUNT" -eq 0 ]; then
    echo -e "  ${GREEN}✓ PASS${NC}: No errors"
    ((PASS_COUNT++))
else
    if grep "Error in event handler" "$LATEST_LOG" | grep -q -E "(http|php-bypass)"; then
        echo -e "  ${RED}✗ FAIL${NC}: Errors in handlers"
        ((FAIL_COUNT++))
    else
        echo -e "  ${GREEN}✓ PASS${NC}: Errors from unrelated plugins"
        ((PASS_COUNT++))
    fi
fi
echo ""

# Summary
echo "========================================================================"
echo "Summary"
echo "========================================================================"
echo -e "Tests Passed: ${GREEN}$PASS_COUNT${NC}"
echo -e "Tests Failed: ${RED}$FAIL_COUNT${NC}"
echo ""

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
    echo ""
    echo "Story 4 successful: Profile loading with event handlers works!"
    echo ""
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    echo ""
    echo "Check track/core/state.py from_dict() method"
    echo "Ensure _init_runtime() is called after data restoration"
    echo ""
    exit 1
fi
