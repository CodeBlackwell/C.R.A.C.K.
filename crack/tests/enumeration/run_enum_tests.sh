#!/bin/bash
#
# Enumeration module test runner
# User-story driven testing for the enumeration checklist tool
#

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/../.." && pwd )"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Enumeration Module Test Suite Runner        ║${NC}"
echo -e "${BLUE}║   User-Story Driven Testing                   ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
echo ""

# Parse command
COMMAND=${1:-all}

cd "$PROJECT_ROOT"

case $COMMAND in
    all)
        echo -e "${YELLOW}Running ALL enumeration tests...${NC}"
        pytest tests/enumeration/ -v --tb=short
        ;;

    user-stories)
        echo -e "${YELLOW}Running USER STORY tests (real-world workflows)...${NC}"
        pytest tests/enumeration/test_user_stories.py -v
        ;;

    guidance)
        echo -e "${YELLOW}Running GUIDANCE QUALITY tests...${NC}"
        pytest tests/enumeration/test_guidance_quality.py -v
        ;;

    edge-cases)
        echo -e "${YELLOW}Running EDGE CASE tests...${NC}"
        pytest tests/enumeration/test_edge_cases.py -v
        ;;

    docs)
        echo -e "${YELLOW}Running DOCUMENTATION tests...${NC}"
        pytest tests/enumeration/test_documentation.py -v
        ;;

    coverage)
        echo -e "${YELLOW}Running tests WITH COVERAGE...${NC}"
        pytest tests/enumeration/ \
            --cov=crack.enumeration \
            --cov-report=term-missing \
            --cov-report=html \
            -v
        echo ""
        echo -e "${GREEN}Coverage report generated: htmlcov/index.html${NC}"
        ;;

    fast)
        echo -e "${YELLOW}Running FAST tests only...${NC}"
        pytest tests/enumeration/ -v -m "not slow" --tb=line
        ;;

    single)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Please specify test name${NC}"
            echo "Usage: $0 single test_name"
            echo "Example: $0 single test_create_new_target_shows_discovery_tasks"
            exit 1
        fi
        echo -e "${YELLOW}Running single test: $2${NC}"
        pytest tests/enumeration/ -v -k "$2"
        ;;

    story)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Please specify story number (1-8)${NC}"
            echo "Usage: $0 story <number>"
            echo "Example: $0 story 1"
            exit 1
        fi
        echo -e "${YELLOW}Running User Story $2 tests...${NC}"
        pytest tests/enumeration/test_user_stories.py::TestUserStory${2}_* -v
        ;;

    debug)
        echo -e "${YELLOW}Running tests in DEBUG mode...${NC}"
        pytest tests/enumeration/ -v -s --tb=long
        ;;

    ci)
        echo -e "${YELLOW}Running CI test suite...${NC}"
        pytest tests/enumeration/ \
            --cov=crack.enumeration \
            --cov-report=term \
            --cov-report=xml \
            --cov-fail-under=70 \
            -v \
            --tb=short
        echo -e "${GREEN}✓ CI tests passed${NC}"
        ;;

    watch)
        echo -e "${YELLOW}Running tests in WATCH mode...${NC}"
        echo "Watching for file changes..."
        pytest-watch tests/enumeration/ -- -v --tb=short
        ;;

    clean)
        echo -e "${YELLOW}Cleaning test artifacts...${NC}"
        rm -rf htmlcov/
        rm -rf .pytest_cache/
        rm -f .coverage
        rm -f coverage.xml
        find tests/enumeration -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
        echo -e "${GREEN}✓ Cleaned${NC}"
        ;;

    help|--help|-h)
        echo "Usage: $0 [command]"
        echo ""
        echo "Commands:"
        echo "  all           - Run all enumeration tests (default)"
        echo "  user-stories  - Run user story tests (real-world workflows)"
        echo "  guidance      - Run guidance quality tests"
        echo "  edge-cases    - Run edge case tests"
        echo "  docs          - Run documentation tests"
        echo "  coverage      - Run tests with coverage report"
        echo "  fast          - Run fast tests only (skip slow edge cases)"
        echo "  single <name> - Run single test by name"
        echo "  story <1-8>   - Run specific user story tests"
        echo "  debug         - Run with verbose output and full tracebacks"
        echo "  ci            - Run CI test suite (with coverage requirements)"
        echo "  watch         - Run tests in watch mode (auto-rerun on changes)"
        echo "  clean         - Clean test artifacts"
        echo "  help          - Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0 user-stories"
        echo "  $0 story 1"
        echo "  $0 single test_create_new_target"
        echo "  $0 coverage"
        echo ""
        echo "Test Philosophy:"
        echo "  These tests validate REAL-WORLD value, not just code execution."
        echo "  Each test represents a pentester workflow or frustration point."
        echo "  Tests should prove the tool helps users, not the other way around."
        ;;

    *)
        echo -e "${RED}Unknown command: $COMMAND${NC}"
        echo "Run '$0 help' for usage information"
        exit 1
        ;;
esac

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           ✓ Tests Passed                      ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
else
    echo ""
    echo -e "${RED}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║           ✗ Tests Failed                      ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════╝${NC}"
    echo -e "${YELLOW}Tip: Run '$0 debug' for detailed output${NC}"
fi

exit $EXIT_CODE
