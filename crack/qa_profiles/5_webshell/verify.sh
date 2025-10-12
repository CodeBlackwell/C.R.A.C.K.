#!/bin/bash
# Verification script for QA Story 5: Webshell Finding (Highest Priority)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LATEST_LOG=$(ls -t .debug_logs/tui_debug_*.log 2>/dev/null | head -1)
PROFILE_JSON="CRACK_targets/qa-story-5-webshell.json"

if [ -z "$LATEST_LOG" ]; then
    echo -e "${RED}✗ No debug log found${NC}"
    exit 1
fi

echo "========================================================================"
echo "QA Story 5 Verification: Webshell Finding (Highest Priority)"
echo "========================================================================"
echo ""

PASS_COUNT=0
FAIL_COUNT=0

# Test 1: Webshell finding added
echo "[TEST 1] Webshell finding documented"
if grep -q "webshell" "$LATEST_LOG" || \
   ([ -f "$PROFILE_JSON" ] && grep -q "webshell" "$PROFILE_JSON"); then
    echo -e "  ${GREEN}✓ PASS${NC}: Webshell finding present"
    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: No webshell finding"
    echo "  User must add finding: 'webshell uploaded: shell.php'"
    ((FAIL_COUNT++))
fi
echo ""

# Test 2: PHP-Bypass activated with confidence 100
echo "[TEST 2] PHP-Bypass activated with confidence 100"
if grep -q "PHP-Bypass.*confidence.*100" "$LATEST_LOG" || \
   grep -q "PHP-Bypass.*webshell.*critical" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: Highest priority activation"
    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: PHP-Bypass did not activate with confidence 100"
    ((FAIL_COUNT++))
fi
echo ""

# Test 3: High-priority tasks generated
echo "[TEST 3] PHP-Bypass tasks generated"
if grep -q "Generated tasks.*php-bypass" "$LATEST_LOG"; then
    echo -e "  ${GREEN}✓ PASS${NC}: PHP-Bypass tasks generated"
    ((PASS_COUNT++))
else
    echo -e "  ${RED}✗ FAIL${NC}: No PHP-Bypass tasks"
    ((FAIL_COUNT++))
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
    echo "Webshell detection works with highest priority!"
    echo ""
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    echo ""
    exit 1
fi
