#!/bin/bash
# Test runner script for CRACK library
# Provides various test execution options

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}CRACK Library Test Suite${NC}"
echo "================================"

# Check if pytest is installed
if ! command -v pytest &> /dev/null; then
    echo -e "${RED}Error: pytest is not installed${NC}"
    echo "Install with: pip install pytest pytest-cov"
    exit 1
fi

# Default to running all tests with coverage
MODE=${1:-all}

case $MODE in
    all)
        echo -e "${YELLOW}Running all tests with coverage...${NC}"
        pytest --cov=crack --cov-report=term-missing --cov-report=html -v
        echo -e "${GREEN}Coverage report saved to htmlcov/index.html${NC}"
        ;;

    unit)
        echo -e "${YELLOW}Running unit tests only...${NC}"
        pytest tests/unit/ -v -m unit
        ;;

    integration)
        echo -e "${YELLOW}Running integration tests only...${NC}"
        pytest tests/integration/ -v -m integration
        ;;

    functional)
        echo -e "${YELLOW}Running functional tests only...${NC}"
        pytest tests/functional/ -v -m functional
        ;;

    fast)
        echo -e "${YELLOW}Running fast tests only...${NC}"
        pytest -v -m fast
        ;;

    coverage)
        echo -e "${YELLOW}Running full coverage analysis...${NC}"
        pytest --cov=crack --cov-report=term-missing --cov-report=html --cov-report=xml
        coverage report
        echo -e "${GREEN}Reports generated:${NC}"
        echo "  - HTML: htmlcov/index.html"
        echo "  - XML: coverage.xml"
        echo "  - Terminal: See above"
        ;;

    module)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Module name required${NC}"
            echo "Usage: $0 module <module_name>"
            echo "Example: $0 module network"
            exit 1
        fi
        echo -e "${YELLOW}Running tests for module: $2${NC}"
        pytest tests/unit/test_${2}*.py -v
        ;;

    specific)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Test file required${NC}"
            echo "Usage: $0 specific <test_file>"
            echo "Example: $0 specific test_network_scanner"
            exit 1
        fi
        echo -e "${YELLOW}Running specific test file: $2${NC}"
        pytest tests/unit/${2}.py -v
        ;;

    verbose)
        echo -e "${YELLOW}Running all tests with verbose output...${NC}"
        pytest -vvs --tb=short
        ;;

    watch)
        echo -e "${YELLOW}Running tests in watch mode...${NC}"
        echo "Tests will re-run automatically when files change"
        if ! command -v pytest-watch &> /dev/null; then
            echo -e "${RED}Error: pytest-watch is not installed${NC}"
            echo "Install with: pip install pytest-watch"
            exit 1
        fi
        ptw -- -v
        ;;

    report)
        echo -e "${YELLOW}Opening coverage report in browser...${NC}"
        if [ -f "htmlcov/index.html" ]; then
            xdg-open htmlcov/index.html 2>/dev/null || open htmlcov/index.html 2>/dev/null
        else
            echo -e "${RED}No coverage report found. Run tests with coverage first.${NC}"
            exit 1
        fi
        ;;

    clean)
        echo -e "${YELLOW}Cleaning test artifacts...${NC}"
        rm -rf .pytest_cache/
        rm -rf htmlcov/
        rm -rf tests/__pycache__/
        rm -rf tests/*/__pycache__/
        rm -f .coverage
        rm -f coverage.xml
        find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
        echo -e "${GREEN}Cleanup complete${NC}"
        ;;

    *)
        echo -e "${RED}Unknown mode: $MODE${NC}"
        echo ""
        echo "Available modes:"
        echo "  all         - Run all tests with coverage (default)"
        echo "  unit        - Run unit tests only"
        echo "  integration - Run integration tests only"
        echo "  functional  - Run functional tests only"
        echo "  fast        - Run fast tests only"
        echo "  coverage    - Run full coverage analysis"
        echo "  module <name> - Run tests for specific module"
        echo "  specific <file> - Run specific test file"
        echo "  verbose     - Run with verbose output"
        echo "  watch       - Run in watch mode (requires pytest-watch)"
        echo "  report      - Open coverage report in browser"
        echo "  clean       - Clean test artifacts"
        echo ""
        echo "Examples:"
        echo "  $0              # Run all tests with coverage"
        echo "  $0 unit         # Run unit tests only"
        echo "  $0 module network  # Run network module tests"
        echo "  $0 fast         # Run fast tests only"
        exit 1
        ;;
esac

# Show test summary
if [ "$MODE" != "clean" ] && [ "$MODE" != "report" ]; then
    echo ""
    echo -e "${GREEN}Test execution complete!${NC}"

    # Check if coverage data exists
    if [ -f ".coverage" ]; then
        echo ""
        echo "Quick coverage summary:"
        coverage report --skip-covered --show-missing | tail -5
    fi
fi