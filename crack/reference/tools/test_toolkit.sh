#!/bin/bash
# Test script for command enrichment toolkit
# Validates all tools function correctly

set -e  # Exit on error

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$TOOLS_DIR/../data/commands"

echo "=========================================="
echo "Command Enrichment Toolkit - Test Suite"
echo "=========================================="
echo ""

# Test 1: Validation Tool
echo "[1/4] Testing validation tool..."
python3 "$TOOLS_DIR/validate_commands.py" --data-dir "$DATA_DIR" --limit 5 > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "  ✓ Validation tool works"
else
    echo "  ✗ Validation tool failed"
    exit 1
fi

# Test 2: Metrics Dashboard
echo "[2/4] Testing metrics dashboard..."
python3 "$TOOLS_DIR/metrics_dashboard.py" --data-dir "$DATA_DIR" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "  ✓ Metrics dashboard works"
else
    echo "  ✗ Metrics dashboard failed"
    exit 1
fi

# Test 3: Enrichment CLI (show mode)
echo "[3/4] Testing enrichment CLI..."
python3 "$TOOLS_DIR/enrich_command.py" curl-wordpress-version-feed --show --data-dir "$DATA_DIR" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "  ✓ Enrichment CLI works"
else
    echo "  ✗ Enrichment CLI failed"
    exit 1
fi

# Test 4: Template Generator
echo "[4/4] Testing template generator..."
python3 "$TOOLS_DIR/template_generator.py" curl-wordpress-version-feed --data-dir "$DATA_DIR" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "  ✓ Template generator works"
else
    echo "  ✗ Template generator failed"
    exit 1
fi

echo ""
echo "=========================================="
echo "All tests passed! ✓"
echo "=========================================="
echo ""

# Display current metrics summary
echo "Current Metrics Summary:"
echo "------------------------"
python3 "$TOOLS_DIR/metrics_dashboard.py" --data-dir "$DATA_DIR" | grep -A 5 "OVERALL METRICS"
