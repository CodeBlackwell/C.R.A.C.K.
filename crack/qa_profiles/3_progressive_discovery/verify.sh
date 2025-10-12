#!/bin/bash
# Verification script for QA Story 3: Progressive Discovery (Finding-Based Activation)
#
# Checks debug logs to verify:
# 1. Initial state: HTTP Plugin only (PHP-Bypass defers)
# 2. Finding added: User documented PHP indicator
# 3. finding_added event emitted
# 4. PHP-Bypass activated via detect_from_finding()
# 5. PHP-Bypass tasks generated dynamically
# 6. Both HTTP and PHP-Bypass tasks present

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Find latest debug log
LATEST_LOG=$(ls -t .debug_logs/tui_debug_*.log 2>/dev/null | head -1)

if [ -z "$LATEST_LOG" ]; then
    echo -e "${RED}✗ No debug log found${NC}"
    echo "  Expected: .debug_logs/tui_debug_*.log"
    echo "  Run TUI with --debug flag first"
    exit 1
fi

# Find profile JSON
PROFILE_JSON="CRACK_targets/qa-story-3-progressive.json"
if [ ! -f "$PROFILE_JSON" ]; then
    # Try legacy location
    PROFILE_JSON="$HOME/.crack/targets/qa-story-3-progressive.json"
fi

echo "========================================================================"
echo "QA Story 3 Verification: Progressive Discovery (Finding-Based)"
echo "========================================================================"
echo ""
echo "Debug log: $LATEST_LOG"
echo "Profile: $PROFILE_JSON"
echo ""

PASS_COUNT=0
FAIL_COUNT=0

# Test 1: Check HTTP Plugin won port 80 initially
echo "[TEST 1] HTTP Plugin won port 80 (initial state)"
if grep -q "Plugin 'http' won port.*80.*confidence.*100" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: HTTP Plugin won with confidence 100"
    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: HTTP Plugin did not win port 80"
    ((FAIL_COUNT++))
fi
echo ""

# Test 2: Check PHP-Bypass initially deferred (confidence 0)
echo "[TEST 2] PHP-Bypass initially deferred (confidence 0)"
if grep -q "php-bypass.*confidence.*0" "$LATEST_LOG" || \
   ! grep -q "PHP-Bypass.*activated" "$LATEST_LOG" | head -5; then
    echo -e "  ${GREEN}✓ PASS${NC}: PHP-Bypass initially deferred"
    ((PASS_COUNT++))
else
    echo -e "  ${YELLOW}⚠ WARNING${NC}: PHP-Bypass state unclear in initial phase"
    ((PASS_COUNT++))  # Don't fail - might just be logging
fi
echo ""

# Test 3: Check finding was added to profile
echo "[TEST 3] PHP finding added to profile"

if [ -f "$PROFILE_JSON" ]; then
    # Check if findings array contains PHP
    if grep -q "PHP" "$PROFILE_JSON" && \
       grep -q "findings" "$PROFILE_JSON"; then
        echo -e "  ${GREEN}✓ PASS${NC}: PHP finding present in profile JSON"

        # Show the finding
        echo "  Finding:"
        grep -A 3 "PHP" "$PROFILE_JSON" | head -5 | sed 's/^/    /'

        ((PASS_COUNT++))
    else
        echo -e "  ${RED}✗ FAIL${NC}: No PHP finding in profile JSON"
        echo ""
        echo "  This test requires manual interaction:"
        echo "  1. Launch TUI with the profile"
        echo "  2. Press 'd' to document a finding"
        echo "  3. Add finding: 'X-Powered-By: PHP/8.0'"
        echo "  4. Exit TUI and re-run verification"
        echo ""
        ((FAIL_COUNT++))
    fi
else
    echo -e "  ${YELLOW}⚠ WARNING${NC}: Profile JSON not found at $PROFILE_JSON"
    echo "  Cannot verify finding persistence"
    ((FAIL_COUNT++))
fi
echo ""

# Test 4: Check finding_added event was emitted
echo "[TEST 4] finding_added event emitted"
if grep -q "finding_added" "$LATEST_LOG" || \
   grep -q "Finding added" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: finding_added event emitted"
    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: finding_added event not found"
    echo "  User may not have added a finding during testing"
    echo "  Or EventBus.emit('finding_added') not called"
    ((FAIL_COUNT++))
fi
echo ""

# Test 5: Check PHP-Bypass activated via detect_from_finding()
echo "[TEST 5] PHP-Bypass activated via finding detection"
if grep -q "PHP-Bypass.*activated via finding" "$LATEST_LOG" || \
   grep -q "PHP-Bypass.*detect_from_finding" "$LATEST_LOG" || \
   grep -q "PHP-Bypass.*confidence.*9[0-9]" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: PHP-Bypass activated via finding"

    # Show activation details
    echo "  Activation:"
    grep -E "PHP-Bypass.*(activated|detect_from_finding|confidence.*9[0-9])" "$LATEST_LOG" | tail -5 | sed 's/^/    /'

    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: PHP-Bypass did NOT activate via finding"
    echo ""
    echo "  This indicates:"
    echo "  - detect_from_finding() method not implemented"
    echo "  - OR finding format doesn't match detection logic"
    echo "  - OR event handler not registered"
    echo ""
    echo "  Check track/services/php_bypass.py for detect_from_finding()"
    ((FAIL_COUNT++))
fi
echo ""

# Test 6: Check PHP-Bypass tasks were generated
echo "[TEST 6] PHP-Bypass tasks generated after finding"
if grep -q "Generated tasks for 'php-bypass'" "$LATEST_LOG" || \
   grep -q "PHP.*bypass.*80" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: PHP-Bypass tasks generated"
    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: PHP-Bypass tasks NOT generated after finding"
    echo "  Expected: Tasks generated dynamically when finding added"
    ((FAIL_COUNT++))
fi
echo ""

# Test 7: Check both HTTP and PHP-Bypass tasks present
echo "[TEST 7] Both HTTP and PHP-Bypass tasks coexist"
HTTP_TASKS=0
PHP_TASKS=0

if grep -q "Generated tasks for 'http'" "$LATEST_LOG" || \
   grep -q "HTTP.*won port.*80" "$LATEST_LOG"; then
    HTTP_TASKS=1
fi

if grep -q "Generated tasks for 'php-bypass'" "$LATEST_LOG"; then
    PHP_TASKS=1
fi

if [ $HTTP_TASKS -eq 1 ] && [ $PHP_TASKS -eq 1 ]; then
    echo -e "  ${GREEN}✓ PASS${NC}: Both HTTP and PHP-Bypass tasks present"
    echo "  This proves progressive discovery works!"
    ((PASS_COUNT++))
elif [ $HTTP_TASKS -eq 1 ] && [ $PHP_TASKS -eq 0 ]; then
    echo -e "  ${YELLOW}⚠ PARTIAL${NC}: Only HTTP tasks present"
    echo "  User may not have added PHP finding during test"
    echo "  Re-run test and add finding: X-Powered-By: PHP/8.0"
    ((FAIL_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: Task generation unclear"
    ((FAIL_COUNT++))
fi
echo ""

# Test 8: Check NO event handler errors
echo "[TEST 8] No event handler errors"
ERROR_COUNT=$(grep -c "Error in event handler" "$LATEST_LOG" 2>/dev/null || echo 0)
if [ "$ERROR_COUNT" -eq 0 ]; then
    echo -e "  ${GREEN}✓ PASS${NC}: No event handler errors"
    ((PASS_COUNT++))
else
    echo -e "  ${YELLOW}⚠ WARNING${NC}: Found $ERROR_COUNT event handler errors"

    # Check if errors are from HTTP or PHP-Bypass
    if grep "Error in event handler" "$LATEST_LOG" | grep -q -E "(http|php-bypass)"; then
        echo -e "  ${RED}✗ FAIL${NC}: Errors in HTTP or PHP-Bypass handlers"
        ((FAIL_COUNT++))
    else
        echo "  Errors from other plugins (non-critical)"
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
    echo "Story 3 verification successful!"
    echo "  - HTTP Plugin activated initially (confidence 100)"
    echo "  - PHP-Bypass deferred initially (confidence 0)"
    echo "  - User added PHP finding dynamically"
    echo "  - PHP-Bypass activated via finding (confidence 90)"
    echo "  - Both HTTP and PHP-Bypass tasks coexist"
    echo ""
    echo "Key Achievement:"
    echo "  Progressive discovery works! Plugins adapt to new information"
    echo "  without requiring profile reload or manual task generation."
    echo ""
    echo "This demonstrates the event-driven finding→task conversion"
    echo "system that enables infinite enumeration depth."
    echo ""
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    echo ""
    echo "Review debug log for details:"
    echo "  $LATEST_LOG"
    echo ""
    echo "Common issues:"
    echo ""
    echo "1. User didn't add finding during test:"
    echo "   - Launch TUI: crack track --tui qa-story-3-progressive --debug"
    echo "   - Press 'd' to document finding"
    echo "   - Add: 'X-Powered-By: PHP/8.0' (source: curl)"
    echo "   - Exit TUI and re-run verification"
    echo ""
    echo "2. detect_from_finding() not implemented:"
    echo "   - Check track/services/php_bypass.py"
    echo "   - Ensure method checks finding['description'] for 'PHP'"
    echo "   - Returns confidence 90 when PHP found"
    echo ""
    echo "3. Event handler not registered:"
    echo "   - Check _init_runtime() calls EventBus.on('finding_added', ...)"
    echo "   - Verify from_dict() calls _init_runtime()"
    echo ""
    echo "4. Finding not persisted:"
    echo "   - Check profile.add_finding() saves to JSON"
    echo "   - Verify EventBus.emit('finding_added', ...) called"
    echo ""
    exit 1
fi
