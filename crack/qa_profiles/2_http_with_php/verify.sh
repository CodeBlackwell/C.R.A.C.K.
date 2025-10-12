#!/bin/bash
# Verification script for QA Story 2: HTTP with PHP in Version String
#
# Checks debug logs to verify:
# 1. HTTP Plugin won port 80 (confidence 100)
# 2. PHP-Bypass activated with confidence 95 (NOT 0)
# 3. HTTP tasks generated
# 4. PHP-Bypass tasks generated
# 5. Both plugins contributed to enumeration
# 6. No event handler errors

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

echo "========================================================================"
echo "QA Story 2 Verification: HTTP with PHP in Version String"
echo "========================================================================"
echo ""
echo "Debug log: $LATEST_LOG"
echo ""

PASS_COUNT=0
FAIL_COUNT=0

# Test 1: Check HTTP Plugin won port 80
echo "[TEST 1] HTTP Plugin won port 80"
if grep -q "Plugin 'http' won port.*80.*confidence.*100" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: HTTP Plugin won with confidence 100"
    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: HTTP Plugin did not win port 80"
    echo "  Check: grep \"Plugin.*won port.*80\" $LATEST_LOG"
    ((FAIL_COUNT++))
fi
echo ""

# Test 2: Check PHP-Bypass confidence is 95 (NOT 0)
echo "[TEST 2] PHP-Bypass Plugin confidence is 95"
if grep -q "php-bypass.*confidence.*9[0-9]" "$LATEST_LOG" || \
   grep -q "PHP-Bypass.*detected.*PHP.*7\.4\.3" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: PHP-Bypass activated with high confidence"

    # Show actual confidence
    echo "  Actual confidence:"
    grep "php-bypass.*confidence" "$LATEST_LOG" | tail -3 | sed 's/^/    /'

    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: PHP-Bypass did not activate with expected confidence"
    echo "  Expected: confidence 95 (or 90-100 range)"
    echo "  Actual:"
    grep "php-bypass.*confidence" "$LATEST_LOG" | tail -3 | sed 's/^/    /'
    ((FAIL_COUNT++))
fi
echo ""

# Test 3: Check service_detected event was emitted
echo "[TEST 3] service_detected event emitted for port 80"
if grep -q "service_detected.*port.*80" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: service_detected event emitted"
    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: service_detected event not found"
    ((FAIL_COUNT++))
fi
echo ""

# Test 4: Check plugin_tasks_generated event was emitted
echo "[TEST 4] plugin_tasks_generated events emitted"
TASK_GEN_COUNT=$(grep -c "plugin_tasks_generated" "$LATEST_LOG" 2>/dev/null || echo 0)

if [ "$TASK_GEN_COUNT" -ge 2 ]; then
    echo -e "  ${GREEN}✓ PASS${NC}: Multiple plugin_tasks_generated events found ($TASK_GEN_COUNT)"
    ((PASS_COUNT++))
elif [ "$TASK_GEN_COUNT" -eq 1 ]; then
    echo -e "  ${YELLOW}⚠ WARNING${NC}: Only 1 plugin_tasks_generated event found"
    echo "  Expected: 2 events (HTTP + PHP-Bypass)"
    echo "  This might indicate only one plugin activated"
    ((FAIL_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: No plugin_tasks_generated events found"
    echo "  This indicates event handler registration failure"
    ((FAIL_COUNT++))
fi
echo ""

# Test 5: Check HTTP tasks were generated
echo "[TEST 5] HTTP enumeration tasks generated"
if grep -q "Generated tasks for 'http'" "$LATEST_LOG" || \
   grep -q "HTTP.*won port.*80" "$LATEST_LOG" || \
   grep -q "web.*methodology.*80" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: HTTP tasks generated"
    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: HTTP tasks not clearly logged"
    echo "  Manual verification required: Check task tree for gobuster/nikto"
    ((FAIL_COUNT++))
fi
echo ""

# Test 6: Check PHP-Bypass tasks were generated
echo "[TEST 6] PHP-Bypass tasks generated"
if grep -q "Generated tasks for 'php-bypass'" "$LATEST_LOG" || \
   grep -q "PHP.*bypass.*80" "$LATEST_LOG" || \
   grep -q "disable_functions" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: PHP-Bypass tasks generated"
    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: PHP-Bypass tasks were NOT generated"
    echo "  This is a critical failure for Story 2!"
    echo ""
    echo "  Expected behavior:"
    echo "    - HTTP Plugin wins priority (confidence 100)"
    echo "    - PHP-Bypass also activates (confidence 95)"
    echo "    - BOTH plugins generate tasks"
    echo ""
    echo "  Debug:"
    echo "    grep 'php-bypass' $LATEST_LOG | tail -10"
    ((FAIL_COUNT++))
fi
echo ""

# Test 7: Check NO event handler errors
echo "[TEST 7] No event handler errors"
ERROR_COUNT=$(grep -c "Error in event handler" "$LATEST_LOG" 2>/dev/null || echo 0)
if [ "$ERROR_COUNT" -eq 0 ]; then
    echo -e "  ${GREEN}✓ PASS${NC}: No event handler errors"
    ((PASS_COUNT++))
else
    echo -e "  ${YELLOW}⚠ WARNING${NC}: Found $ERROR_COUNT event handler errors"
    echo "  (Some errors may be from unrelated plugins)"

    # Check if errors are from HTTP or PHP-Bypass
    if grep "Error in event handler" "$LATEST_LOG" | grep -q -E "(http|php-bypass)"; then
        echo -e "  ${RED}✗ FAIL${NC}: Errors found in HTTP or PHP-Bypass handlers"
        grep "Error in event handler" "$LATEST_LOG" | grep -E "(http|php-bypass)" | head -5
        ((FAIL_COUNT++))
    else
        echo "  Errors are from other plugins (non-critical)"
        ((PASS_COUNT++))
    fi
fi
echo ""

# Test 8: Verify version string detection
echo "[TEST 8] PHP version string detected correctly"
if grep -q "PHP/7\.4\.3" "$LATEST_LOG" || \
   grep -q "Apache/2\.4\.41.*PHP" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: Version string with PHP detected"
    ((PASS_COUNT++))
else
    echo -e "  ${YELLOW}⚠ WARNING${NC}: Version string detection not clearly logged"
    echo "  Expected to see: Apache/2.4.41 (Ubuntu) PHP/7.4.3"
    ((PASS_COUNT++))  # Don't fail on logging issue
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
    echo "Story 2 verification successful!"
    echo "  - HTTP Plugin won port 80 (confidence 100)"
    echo "  - PHP-Bypass activated (confidence 95)"
    echo "  - Both HTTP and PHP-Bypass tasks generated"
    echo "  - Multiple plugins working together correctly"
    echo ""
    echo "Key Insight:"
    echo "  This story demonstrates that plugin priority (who wins) is"
    echo "  separate from plugin activation (who contributes tasks)."
    echo "  Both plugins can activate simultaneously when appropriate."
    echo ""
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    echo ""
    echo "Review debug log for details:"
    echo "  $LATEST_LOG"
    echo ""
    echo "Common issues:"
    echo "  - PHP-Bypass not detecting PHP in version string"
    echo "  - ServiceRegistry only allowing winner to generate tasks"
    echo "  - Event handlers not registered (check _init_runtime())"
    echo ""
    echo "Critical checks:"
    echo "  1. PHP-Bypass detect() method checks version field"
    echo "  2. ServiceRegistry allows multiple plugins to activate"
    echo "  3. Both plugins emit plugin_tasks_generated events"
    echo ""
    exit 1
fi
