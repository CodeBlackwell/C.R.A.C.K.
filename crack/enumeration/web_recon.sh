#!/bin/bash
#
# Web Reconnaissance Toolkit - Complete enumeration pipeline
# Combines html_enum.py and param_discover.py for comprehensive web app assessment
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HTML_ENUM="$SCRIPT_DIR/html_enum.py"
PARAM_DISC="$SCRIPT_DIR/param_discover.py"

# Colors
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
BOLD='\033[1m'
END='\033[0m'

usage() {
    cat << EOF
${BOLD}Web Reconnaissance Toolkit${END}
Complete enumeration pipeline for web applications

${BOLD}USAGE:${END}
  $(basename $0) [OPTIONS] <target_url>

${BOLD}OPTIONS:${END}
  -q, --quick          Quick parameter scan (22 high-value params, ~2-5 min)
  -f, --full          Full parameter scan (98 params, ~15-20 min)
  -m, --method METHOD  HTTP method for param discovery (GET|POST, default: GET)
  -w, --wordlist FILE  Custom parameter wordlist
  -o, --output DIR     Save results to directory (default: ./scans/)
  -h, --help          Show this help

${BOLD}EXAMPLES:${END}
  # Quick reconnaissance (recommended for initial scan)
  $(basename $0) -q http://192.168.45.100

  # Full deep scan
  $(basename $0) -f http://192.168.45.100

  # Test for POST parameters with custom wordlist
  $(basename $0) -m POST -w wp_params.txt http://192.168.45.100/wp-admin/

  # Save results to specific directory
  $(basename $0) -q -o /home/kali/OSCP/targets/web01 http://192.168.45.100

${BOLD}PIPELINE STAGES:${END}
  1. HTML Enumeration (html_enum.py -r)
     - Discovers all pages via recursive crawling
     - Extracts forms, comments, endpoints
     - Identifies interesting findings

  2. Parameter Discovery (param_discover.py)
     - Tests each discovered page for hidden parameters
     - Uses smart payload selection
     - Provides exploitation guidance

${BOLD}TIME ESTIMATES:${END}
  Quick mode (-q):  2-5 minutes for typical site
  Full mode (-f):   15-20 minutes for typical site

${BOLD}OUTPUT:${END}
  - Console: Real-time progress and findings
  - Files: Saved to output directory if -o specified
    * html_enumeration.txt
    * param_discovery.txt
    * findings_summary.txt

${BOLD}FLAGS EXPLAINED:${END}
  -q: Tests 22 OSCP-focused parameters (id, debug, admin, file, cmd, etc.)
      Faster scan for initial reconnaissance

  -f: Tests 98 comprehensive parameters
      Thorough scan when you have time

  -m: Specifies HTTP method (GET or POST)
      Some endpoints only respond to specific methods

  -w: Custom wordlist for parameter fuzzing
      Use application-specific params (WordPress, Joomla, etc.)

  -o: Output directory for saving scan results
      Organizes findings for documentation

EOF
    exit 0
}

# Parse arguments
QUICK=false
FULL=false
METHOD="GET"
WORDLIST=""
OUTPUT_DIR=""
TARGET=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -q|--quick)
            QUICK=true
            shift
            ;;
        -f|--full)
            FULL=true
            shift
            ;;
        -m|--method)
            METHOD="$2"
            shift 2
            ;;
        -w|--wordlist)
            WORDLIST="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            TARGET="$1"
            shift
            ;;
    esac
done

# Validate target
if [[ -z "$TARGET" ]]; then
    echo -e "${RED}Error: Target URL required${END}"
    usage
fi

# Set default mode if neither specified
if ! $QUICK && ! $FULL; then
    echo -e "${YELLOW}No mode specified, defaulting to quick mode (-q)${END}"
    QUICK=true
fi

# Setup output directory
if [[ -n "$OUTPUT_DIR" ]]; then
    mkdir -p "$OUTPUT_DIR"
    echo -e "${BLUE}[*] Results will be saved to: $OUTPUT_DIR${END}"
fi

# Extract hostname for file naming
HOSTNAME=$(echo "$TARGET" | sed -E 's|https?://||' | sed 's|/.*||' | sed 's|:.*||')
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo -e "${BOLD}======================================${END}"
echo -e "${BOLD}  WEB RECONNAISSANCE TOOLKIT${END}"
echo -e "${BOLD}======================================${END}"
echo -e "Target: ${GREEN}$TARGET${END}"
echo -e "Mode: $(if $QUICK; then echo "${GREEN}Quick (22 params)${END}"; else echo "${YELLOW}Full (98 params)${END}"; fi)"
echo -e "Method: $METHOD"
if [[ -n "$WORDLIST" ]]; then
    echo -e "Wordlist: $WORDLIST"
fi
echo -e "${BOLD}======================================${END}\n"

# Stage 1: HTML Enumeration
echo -e "${BOLD}${BLUE}[STAGE 1/2] HTML Enumeration${END}"
echo -e "${BLUE}Discovering pages, forms, and endpoints...${END}\n"

HTML_OUTPUT=$(mktemp)
python3 "$HTML_ENUM" "$TARGET" -r 2>/dev/null | tee "$HTML_OUTPUT"

if [[ -n "$OUTPUT_DIR" ]]; then
    cp "$HTML_OUTPUT" "$OUTPUT_DIR/html_enumeration_${HOSTNAME}_${TIMESTAMP}.txt"
fi

# Stage 2: Parameter Discovery
echo -e "\n${BOLD}${BLUE}[STAGE 2/2] Parameter Discovery${END}"
echo -e "${BLUE}Testing discovered pages for hidden parameters...${END}\n"

PARAM_ARGS="-m $METHOD"
if $QUICK; then
    PARAM_ARGS="$PARAM_ARGS -q"
fi
if [[ -n "$WORDLIST" ]]; then
    PARAM_ARGS="$PARAM_ARGS -w $WORDLIST"
fi

if [[ -n "$OUTPUT_DIR" ]]; then
    PARAM_OUTPUT="$OUTPUT_DIR/param_discovery_${HOSTNAME}_${TIMESTAMP}.txt"
    cat "$HTML_OUTPUT" | python3 "$PARAM_DISC" $PARAM_ARGS 2>&1 | tee "$PARAM_OUTPUT"
else
    cat "$HTML_OUTPUT" | python3 "$PARAM_DISC" $PARAM_ARGS
fi

# Cleanup
rm -f "$HTML_OUTPUT"

# Summary
echo -e "\n${BOLD}${GREEN}[RECONNAISSANCE COMPLETE]${END}"
if [[ -n "$OUTPUT_DIR" ]]; then
    echo -e "${GREEN}Results saved to: $OUTPUT_DIR/${END}"
    echo -e "\nGenerated files:"
    ls -lh "$OUTPUT_DIR" | tail -n +2 | awk '{print "  - " $9 " (" $5 ")"}'
fi

echo -e "\n${BOLD}[NEXT STEPS]${END}"
echo -e "  ${YELLOW}•${END} Review discovered parameters for exploitation opportunities"
echo -e "  ${YELLOW}•${END} Test high-confidence params for SQLi, XSS, LFI, RCE"
echo -e "  ${YELLOW}•${END} Check forms for authentication bypass or injection"
echo -e "  ${YELLOW}•${END} Investigate debug/admin parameters for information disclosure"
