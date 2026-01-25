#!/bin/bash
# PRISM 3-Terminal Demo Script
# Usage: ./demo.sh
#
# This demo uses 3 terminals:
# - Main (this script): Menu and orchestration
# - RAW (tmux: raw-demo): Shows raw file content
# - PRISM (tmux: prism-demo): Shows PRISM-processed output

# ═══════════════════════════════════════════════════════════════
# Colors
# ═══════════════════════════════════════════════════════════════
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

# ═══════════════════════════════════════════════════════════════
# Directory Setup
# ═══════════════════════════════════════════════════════════════
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# video-production/01-prism -> go up 2 levels to crack/
CRACK_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
SAMPLES_DIR="tools/post/prism/samples"

# Demo context - all data linked to same attack/domain
DEMO_HOST="DC01.CORP.LOCAL"
DEMO_DOMAIN="CORP.LOCAL"

# Change to crack directory
cd "$CRACK_DIR" || exit 1

# ═══════════════════════════════════════════════════════════════
# Neo4j Detection
# ═══════════════════════════════════════════════════════════════
check_neo4j() {
    if command -v nc &>/dev/null; then
        nc -z localhost 7687 2>/dev/null && return 0
    elif command -v curl &>/dev/null; then
        curl -s --connect-timeout 1 http://localhost:7474 &>/dev/null && return 0
    fi
    return 1
}

if check_neo4j; then
    NEO4J_FLAG=""
    NEO4J_STATUS="${GREEN}connected${NC}"
else
    NEO4J_FLAG="--no-neo4j"
    NEO4J_STATUS="${DIM}not detected${NC}"
fi

# ═══════════════════════════════════════════════════════════════
# tmux Session Management
# ═══════════════════════════════════════════════════════════════

# Session names
RAW_SESSION="raw-demo"
PRISM_SESSION="prism-demo"

# Initialize tmux sessions
init_sessions() {
    # Kill any existing sessions first
    tmux kill-session -t "$PRISM_SESSION" 2>/dev/null
    tmux kill-session -t "$RAW_SESSION" 2>/dev/null

    # Create new detached sessions
    tmux new-session -d -s "$RAW_SESSION"
    tmux new-session -d -s "$PRISM_SESSION"

    # Change to crack directory in both
    tmux send-keys -t "$RAW_SESSION" "cd '$CRACK_DIR'" Enter
    tmux send-keys -t "$PRISM_SESSION" "cd '$CRACK_DIR'" Enter

    # Set custom prompts for clarity
    tmux send-keys -t "$RAW_SESSION" 'export PS1="\[\033[0;33m\]raw\[\033[0m\]$ "' Enter
    tmux send-keys -t "$PRISM_SESSION" 'export PS1="\[\033[0;36m\]prism\[\033[0m\]$ "' Enter

    # Initial clear
    sleep 0.3
    tmux send-keys -t "$RAW_SESSION" "clear" Enter
    tmux send-keys -t "$PRISM_SESSION" "clear" Enter

    # Display waiting message
    sleep 0.1
    tmux send-keys -t "$RAW_SESSION" 'echo -e "\n\033[1;33m  ═══ RAW OUTPUT ═══\033[0m\n\n  Waiting for demo selection..."' Enter
    tmux send-keys -t "$PRISM_SESSION" 'echo -e "\n\033[1;36m  ═══ PRISM ANALYSIS ═══\033[0m\n\n  Waiting for demo selection..."' Enter
}

# Cleanup function - kills sessions on exit
cleanup() {
    echo -e "\n${DIM}Cleaning up tmux sessions...${NC}"
    tmux kill-session -t "$PRISM_SESSION" 2>/dev/null
    tmux kill-session -t "$RAW_SESSION" 2>/dev/null
    echo -e "${GREEN}Sessions terminated.${NC}\n"
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

# Send command to raw session
send_raw() {
    tmux send-keys -t "$RAW_SESSION" "$1" Enter
}

# Send command to prism session
send_prism() {
    tmux send-keys -t "$PRISM_SESSION" "$1" Enter
}

# Clear both sessions with headers
clear_sessions() {
    local raw_title="${1:-RAW OUTPUT}"
    local prism_title="${2:-PRISM ANALYSIS}"

    # Send Ctrl+C to kill any running commands first
    tmux send-keys -t "$RAW_SESSION" C-c
    tmux send-keys -t "$PRISM_SESSION" C-c
    sleep 0.3

    send_raw "clear"
    send_prism "clear"
    sleep 0.1
    send_raw "echo -e '\n\033[1;33m  ═══ $raw_title ═══\033[0m\n'"
    send_prism "echo -e '\n\033[1;36m  ═══ $prism_title ═══\033[0m\n'"
    sleep 0.2
}

# ═══════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════

print_header() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${WHITE}$1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}\n"
}

wait_for_input() {
    echo ""
    echo -e "${DIM}Press Enter to continue, or 'q' to return to menu...${NC}"
    read -r response
    if [[ "$response" == "q" || "$response" == "Q" ]]; then
        return 1
    fi
    return 0
}

# ═══════════════════════════════════════════════════════════════
# Demo Functions
# ═══════════════════════════════════════════════════════════════

demo_mimikatz() {
    local sample="$SAMPLES_DIR/mimikatz_logonpasswords.txt"

    clear_sessions "RAW MIMIKATZ OUTPUT" "PRISM ANALYSIS"

    # Send commands to both sessions
    send_raw "cat $sample"
    send_prism "python3 -m crack.tools.post.prism.cli $sample --host $DEMO_HOST $NEO4J_FLAG"

    # Main terminal description
    clear
    print_header "PARSER: Mimikatz Logonpasswords"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   Wall of text - credentials buried in noise"
    echo -e "  ${GREEN}PRISM:${NC} Structured extraction with cleartext highlighted"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${MAGENTA}*${NC} Cleartext password detection (HIGH VALUE yellow banner)"
    echo -e "  ${MAGENTA}*${NC} Service account filtering (DWM-1, UMFD-0 auto-excluded)"
    echo -e "  ${MAGENTA}*${NC} Machine account detection (accounts ending in \$)"
    echo -e "  ${MAGENTA}*${NC} Session tracking (Interactive vs Service logons)"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}mimikatz.exe \"sekurlsa::logonpasswords\" exit > loot.txt${NC}"
    echo -e "  ${CYAN}crack prism loot.txt${NC}"

    wait_for_input
}

demo_secretsdump() {
    local sample="$SAMPLES_DIR/secretsdump_ntds.txt"

    clear_sessions "RAW SECRETSDUMP OUTPUT" "PRISM ANALYSIS"

    send_raw "cat $sample"
    send_prism "python3 -m crack.tools.post.prism.cli $sample --host $DEMO_HOST $NEO4J_FLAG"

    clear
    print_header "PARSER: Secretsdump / NTDS Hashes"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   Long list of user:rid:lm:nt format hashes"
    echo -e "  ${GREEN}PRISM:${NC} Organized by account type, Kerberos keys extracted"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${MAGENTA}*${NC} NTDS hash extraction (user:rid:lm:nt format)"
    echo -e "  ${MAGENTA}*${NC} Empty hash filtering (Guest with 31d6cfe0... excluded)"
    echo -e "  ${MAGENTA}*${NC} Kerberos key extraction (AES256, AES128, DES)"
    echo -e "  ${MAGENTA}*${NC} Machine account separation (DC01\$, WS01\$)"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}secretsdump.py CORP/admin:pass@DC01 -just-dc-ntlm > ntds.txt${NC}"
    echo -e "  ${CYAN}crack prism ntds.txt${NC}"

    wait_for_input
}

demo_kerberoast() {
    local sample="$SAMPLES_DIR/kerberoast_hashes.txt"

    clear_sessions "RAW KERBEROAST OUTPUT" "PRISM ANALYSIS"

    send_raw "cat $sample"
    send_prism "python3 -m crack.tools.post.prism.cli $sample --host $DEMO_HOST $NEO4J_FLAG"

    clear
    print_header "PARSER: Kerberoast TGS Hashes"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   Massive \$krb5tgs\$ hash strings, hard to parse"
    echo -e "  ${GREEN}PRISM:${NC} Username, SPN, and hashcat mode clearly shown"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${MAGENTA}*${NC} TGS hash extraction (\$krb5tgs\$23\$...)"
    echo -e "  ${MAGENTA}*${NC} SPN detection (MSSQLSvc, HTTP, CIFS)"
    echo -e "  ${MAGENTA}*${NC} Hashcat mode reference (mode 13100)"
    echo -e "  ${MAGENTA}*${NC} Username and domain parsing"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}GetUserSPNs.py CORP/user:pass -dc-ip DC01 -request > tgs.txt${NC}"
    echo -e "  ${CYAN}crack prism tgs.txt${NC}"

    wait_for_input
}

demo_asreproast() {
    local sample="$SAMPLES_DIR/asreproast_hashes.txt"

    clear_sessions "RAW AS-REP ROAST OUTPUT" "PRISM ANALYSIS"

    send_raw "cat $sample"
    send_prism "python3 -m crack.tools.post.prism.cli $sample --host $DEMO_HOST $NEO4J_FLAG"

    clear
    print_header "PARSER: AS-REP Roast Hashes"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   \$krb5asrep\$ hash blobs mixed with tool output"
    echo -e "  ${GREEN}PRISM:${NC} Users without preauth clearly identified"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${MAGENTA}*${NC} AS-REP hash extraction (\$krb5asrep\$23\$...)"
    echo -e "  ${MAGENTA}*${NC} Users with DONT_REQ_PREAUTH flag"
    echo -e "  ${MAGENTA}*${NC} Hashcat mode reference (mode 18200)"
    echo -e "  ${MAGENTA}*${NC} Cross-reference with NTDS hashes"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}GetNPUsers.py CORP/ -usersfile users.txt -dc-ip DC01 > asrep.txt${NC}"
    echo -e "  ${CYAN}crack prism asrep.txt${NC}"

    wait_for_input
}

demo_ldap() {
    local sample="$SAMPLES_DIR/ldap_enum.ldif"

    clear_sessions "RAW LDAP OUTPUT" "PRISM ANALYSIS"

    send_raw "cat $sample | head -80"
    send_prism "python3 -m crack.tools.post.prism.cli $sample --host $DEMO_HOST $NEO4J_FLAG"

    clear
    print_header "PARSER: LDAP Enumeration"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   Verbose LDIF format with many irrelevant attributes"
    echo -e "  ${GREEN}PRISM:${NC} High-value targets: legacy passwords, kerberoastable, adminCount"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${RED}*${NC} ${RED}Legacy password detection (CRITICAL - instant win!)${NC}"
    echo -e "  ${MAGENTA}*${NC} Kerberoastable user detection (servicePrincipalName)"
    echo -e "  ${MAGENTA}*${NC} AS-REP roastable detection (userAccountControl flag)"
    echo -e "  ${YELLOW}*${NC} ${YELLOW}Password hints in descriptions (svc_sql shows 'pw: Summer2024!')${NC}"
    echo -e "  ${MAGENTA}*${NC} Admin account enumeration (adminCount=1)"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}ldapsearch -x -H ldap://DC01 -b \"DC=corp,DC=local\" > ldap.ldif${NC}"
    echo -e "  ${CYAN}crack prism ldap.ldif${NC}"

    wait_for_input
}

demo_smbmap() {
    local sample="$SAMPLES_DIR/smbmap_output.txt"

    clear_sessions "RAW SMBMAP OUTPUT" "PRISM ANALYSIS"

    send_raw "cat $sample"
    send_prism "python3 -m crack.tools.post.prism.cli $sample --host $DEMO_HOST $NEO4J_FLAG"

    clear
    print_header "PARSER: SMBMap Share Enumeration"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   Flat file listing with permissions"
    echo -e "  ${GREEN}PRISM:${NC} High-value files highlighted with attack reasoning"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${RED}*${NC} ${RED}High-value file detection (GPP Groups.xml, SSH keys)${NC}"
    echo -e "  ${MAGENTA}*${NC} Writable share identification (attack vectors)"
    echo -e "  ${MAGENTA}*${NC} File categorization with attack reasoning"
    echo -e "  ${MAGENTA}*${NC} Detects: passwords.txt, web.config, id_rsa, NTDS.dit backups"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}smbmap -H 10.10.10.10 -u user -p pass -R > shares.txt${NC}"
    echo -e "  ${CYAN}crack prism shares.txt${NC}"

    wait_for_input
}

demo_crawl() {
    local loot_dir="$SAMPLES_DIR/loot_dump"

    clear_sessions "RAW DIRECTORY LISTING" "PRISM CRAWL"

    # Show directory structure and sample files in RAW
    send_raw "echo 'Directory structure:' && tree $loot_dir -L 3 2>/dev/null || find $loot_dir -type f | head -25"
    send_prism "python3 -m crack.tools.post.prism.cli crawl $loot_dir --host $DEMO_HOST $NEO4J_FLAG"

    clear
    print_header "FEATURE: Directory Crawl (Loot Dump Analysis)"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   ~60 files mixed together - event logs, temp files, configs"
    echo -e "  ${GREEN}PRISM:${NC} 18 parsers scan 37+ files, extract 99 credentials"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${MAGENTA}*${NC} 18 parsers: mimikatz, NTDS, kerberoast, GPP, CME, responder..."
    echo -e "  ${MAGENTA}*${NC} Auto-detects: .potfile, web.config, .env, shadow, ssh keys"
    echo -e "  ${MAGENTA}*${NC} Binary file filtering (skips .exe, .dll, .pdf, etc.)"
    echo -e "  ${MAGENTA}*${NC} Aggregate summary with unique accounts and domains"
    echo -e "  ${YELLOW}*${NC} ${YELLOW}Signal extraction from noisy system dumps${NC}"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}scp -r victim:/C\$/Users/ ./loot/${NC}"
    echo -e "  ${CYAN}crack prism crawl ./loot/${NC}"

    wait_for_input
}

demo_report() {
    clear_sessions "NEO4J DATA" "DOMAIN REPORT"

    # RAW shows what's in the database
    send_raw "echo 'Neo4j contains aggregated data from all parsed files:'"
    send_raw "echo '  - Users from LDAP enumeration'"
    send_raw "echo '  - Credentials from mimikatz, secretsdump, kerberoast'"
    send_raw "echo '  - Computers and services'"
    send_raw "echo ''"
    send_raw "echo 'Query methods: --list-domains, --domain CORP.LOCAL'"

    # PRISM shows report generation
    send_prism "python3 -m crack.tools.post.prism.cli report --list-domains 2>/dev/null || echo 'Neo4j not available'"

    clear
    print_header "FEATURE: Domain Report (Neo4j Query)"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   Manual Cypher queries, scattered data"
    echo -e "  ${GREEN}PRISM:${NC} Unified report across all credential sources"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${MAGENTA}*${NC} Aggregated view from Neo4j"
    echo -e "  ${MAGENTA}*${NC} Cross-tool correlation (same cred from multiple sources)"
    echo -e "  ${MAGENTA}*${NC} Timestamp tracking (first_seen, last_seen)"
    echo -e "  ${MAGENTA}*${NC} Occurrence counting (how many times each cred found)"
    echo -e "  ${MAGENTA}*${NC} Section filtering (--section users, credentials, etc.)"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}# After parsing multiple files${NC}"
    echo -e "  ${CYAN}crack prism report --domain CORP.LOCAL${NC}"

    wait_for_input
}

demo_export() {
    clear_sessions "EXPORT OPTIONS" "REPORT FILES"

    send_raw "echo 'Export creates timestamped files:'"
    send_raw "echo '  prism-CORP_LOCAL/'"
    send_raw "echo '    ├── CORP_LOCAL_report_<timestamp>.json'"
    send_raw "echo '    └── CORP_LOCAL_report_<timestamp>.md'"
    send_raw "echo ''"
    send_raw "echo 'Features:'"
    send_raw "echo '  - Untruncated (all credentials)'"
    send_raw "echo '  - Source summary table'"
    send_raw "echo '  - credentials_by_source grouping'"

    send_prism "echo 'Running: crack prism report --domain CORP.LOCAL'"
    send_prism "python3 -m crack.tools.post.prism.cli report --domain CORP.LOCAL 2>/dev/null && ls -la prism-CORP_LOCAL/ 2>/dev/null || echo 'Neo4j not available - showing example only'"

    clear
    print_header "FEATURE: Export Reports (.md + .json)"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   Manual copy-paste, truncated terminal output"
    echo -e "  ${GREEN}PRISM:${NC} Complete export with all data preserved"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${MAGENTA}*${NC} Timestamped filenames (no overwrites)"
    echo -e "  ${MAGENTA}*${NC} Untruncated output (all credentials, all users)"
    echo -e "  ${MAGENTA}*${NC} Source summary table (which tools found what)"
    echo -e "  ${MAGENTA}*${NC} Duplicate tracking section"
    echo -e "  ${MAGENTA}*${NC} JSON includes credentials_by_source grouping"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${CYAN}crack prism report --domain CORP.LOCAL${NC}"
    echo -e "  ${DIM}# Creates: prism-CORP_LOCAL/*.json and *.md${NC}"

    wait_for_input
}

demo_purge_dryrun() {
    clear_sessions "DATA CLEANUP" "PURGE DRY-RUN"

    send_raw "echo 'Purge removes PRISM data from Neo4j:'"
    send_raw "echo ''"
    send_raw "echo 'Options:'"
    send_raw "echo '  --domain CORP.LOCAL  # Specific domain'"
    send_raw "echo '  --all                # All PRISM data'"
    send_raw "echo '  --dry-run            # Preview only'"
    send_raw "echo '  --force              # Skip confirmation'"

    send_prism "echo 'Running: crack prism purge --domain CORP.LOCAL --dry-run'"
    send_prism "python3 -m crack.tools.post.prism.cli purge --domain CORP.LOCAL --dry-run 2>/dev/null || echo 'Neo4j not available'"

    clear
    print_header "FEATURE: Purge Domain Data (Dry Run)"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   Manual Cypher DELETE queries"
    echo -e "  ${GREEN}PRISM:${NC} Safe preview before deletion"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${MAGENTA}*${NC} ${YELLOW}--dry-run shows what WOULD be deleted${NC}"
    echo -e "  ${MAGENTA}*${NC} Per-node-type counts (users, credentials, computers)"
    echo -e "  ${MAGENTA}*${NC} No data is modified"
    echo -e "  ${MAGENTA}*${NC} Always run dry-run first!"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${CYAN}crack prism purge --domain CORP.LOCAL --dry-run${NC}"
    echo -e "  ${DIM}# Review counts, then run actual purge${NC}"

    wait_for_input
}

demo_purge_execute() {
    clear_sessions "DATA CLEANUP" "PURGE EXECUTE"

    send_raw "echo 'ACTUAL DELETION - This removes data permanently!'"
    send_raw "echo ''"
    send_raw "echo 'Safety features:'"
    send_raw "echo '  - Requires typing \"yes\" to confirm'"
    send_raw "echo '  - Use --force to skip (scripting only)'"
    send_raw "echo ''"
    send_raw "echo 'Run dry-run first to verify!'"

    send_prism "echo 'Running: crack prism purge --domain CORP.LOCAL --force'"
    send_prism "python3 -m crack.tools.post.prism.cli purge --domain CORP.LOCAL --force 2>/dev/null || echo 'Neo4j not available'"

    clear
    print_header "FEATURE: Purge Domain Data (Execute)"

    echo -e "${RED}${BOLD}⚠  WARNING: This deletes data permanently!${NC}"
    echo ""
    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   Manual Cypher DELETE queries"
    echo -e "  ${GREEN}PRISM:${NC} Controlled deletion with confirmation"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${RED}*${NC} ${RED}Actually deletes nodes from Neo4j${NC}"
    echo -e "  ${MAGENTA}*${NC} Shows deletion counts per node type"
    echo -e "  ${MAGENTA}*${NC} Confirmation required (type 'yes')"
    echo -e "  ${MAGENTA}*${NC} --force skips confirmation (for scripts)"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}crack prism purge --domain CORP.LOCAL --dry-run  # Preview first${NC}"
    echo -e "  ${CYAN}crack prism purge --domain CORP.LOCAL           # Then execute${NC}"

    wait_for_input
}

demo_domain_report() {
    clear_sessions "NEO4J QUERY" "DOMAIN REPORT"

    send_raw "echo 'Domain report queries Neo4j for aggregated data:'"
    send_raw "echo ''"
    send_raw "echo 'Data sources merged:'"
    send_raw "echo '  - LDAP enumeration (users, groups)'"
    send_raw "echo '  - Mimikatz (sessions, cleartext)'"
    send_raw "echo '  - Secretsdump (NTDS hashes)'"
    send_raw "echo '  - Kerberoast (TGS tickets)'"
    send_raw "echo '  - CME (valid credentials)'"

    send_prism "echo 'Running: crack prism report --domain $DEMO_DOMAIN'"
    send_prism "python3 -m crack.tools.post.prism.cli report --domain $DEMO_DOMAIN 2>/dev/null || echo 'Neo4j not available - run some parsers first'"

    clear
    print_header "FEATURE: Domain Report (--domain)"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   Scattered credentials across multiple files"
    echo -e "  ${GREEN}PRISM:${NC} Unified view of all domain credentials"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${MAGENTA}*${NC} Aggregates credentials from all parsed sources"
    echo -e "  ${MAGENTA}*${NC} Cross-tool correlation (same cred, multiple sources)"
    echo -e "  ${MAGENTA}*${NC} Sections: users, credentials, computers, kerberos"
    echo -e "  ${MAGENTA}*${NC} High-value targets highlighted"
    echo -e "  ${MAGENTA}*${NC} Filter by section: --section credentials"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}# Parse multiple files first, then query${NC}"
    echo -e "  ${CYAN}crack prism report --domain CORP.LOCAL${NC}"
    echo -e "  ${CYAN}crack prism report --domain CORP.LOCAL --section credentials${NC}"

    wait_for_input
}

# ═══════════════════════════════════════════════════════════════
# NEW PARSERS (v2.0)
# ═══════════════════════════════════════════════════════════════

demo_hashcat() {
    local sample="$SAMPLES_DIR/hashcat_cracked.potfile"

    clear_sessions "RAW POTFILE" "PRISM ANALYSIS"

    send_raw "cat $sample"
    send_prism "python3 -m crack.tools.post.prism.cli $sample --host $DEMO_HOST $NEO4J_FLAG"

    clear
    print_header "PARSER: Hashcat Potfile"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   hash:password pairs - no context on source"
    echo -e "  ${GREEN}PRISM:${NC} Cracked passwords linked back to original accounts"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${RED}*${NC} ${RED}Correlates cracked hashes with NTDS/SAM dumps${NC}"
    echo -e "  ${MAGENTA}*${NC} Detects hash type (NTLM, SHA1, etc.)"
    echo -e "  ${MAGENTA}*${NC} Highlights reused passwords across accounts"
    echo -e "  ${MAGENTA}*${NC} Links to original credential source"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}hashcat -m 1000 ntds_hashes.txt rockyou.txt --potfile-path cracked.pot${NC}"
    echo -e "  ${CYAN}crack prism cracked.pot${NC}"

    wait_for_input
}

demo_crackmapexec() {
    local sample="$SAMPLES_DIR/cme_output.txt"

    clear_sessions "RAW CME OUTPUT" "PRISM ANALYSIS"

    send_raw "cat $sample"
    send_prism "python3 -m crack.tools.post.prism.cli $sample --host $DEMO_HOST $NEO4J_FLAG"

    clear
    print_header "PARSER: CrackMapExec"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   Log output with [+] success markers buried in noise"
    echo -e "  ${GREEN}PRISM:${NC} Only valid credentials extracted, structured"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${GREEN}*${NC} ${GREEN}Extracts [+] VALID credentials only${NC}"
    echo -e "  ${MAGENTA}*${NC} Supports SMB, WinRM, MSSQL protocols"
    echo -e "  ${MAGENTA}*${NC} Detects admin access (Pwn3d!)"
    echo -e "  ${MAGENTA}*${NC} Aggregates spray results across multiple targets"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}crackmapexec smb 10.10.10.0/24 -u users.txt -p pass.txt > spray.txt${NC}"
    echo -e "  ${CYAN}crack prism spray.txt${NC}"

    wait_for_input
}

demo_responder() {
    local sample="$SAMPLES_DIR/responder_hashes.txt"

    clear_sessions "RAW NETNTLM HASHES" "PRISM ANALYSIS"

    send_raw "cat $sample"
    send_prism "python3 -m crack.tools.post.prism.cli $sample --host $DEMO_HOST $NEO4J_FLAG"

    clear
    print_header "PARSER: Responder NetNTLM"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   Long hash strings in user::domain:challenge format"
    echo -e "  ${GREEN}PRISM:${NC} Parsed with account, domain, hash type identified"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${MAGENTA}*${NC} NTLMv1 detection (hashcat mode 5500)"
    echo -e "  ${MAGENTA}*${NC} NTLMv2 detection (hashcat mode 5600)"
    echo -e "  ${MAGENTA}*${NC} Domain and username extraction"
    echo -e "  ${YELLOW}*${NC} ${YELLOW}Ready for relay or offline cracking${NC}"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}responder -I eth0 -wrf${NC}"
    echo -e "  ${CYAN}crack prism /usr/share/responder/logs/*.txt${NC}"

    wait_for_input
}

demo_lazagne() {
    local sample="$SAMPLES_DIR/lazagne_output.json"

    clear_sessions "RAW LAZAGNE JSON" "PRISM ANALYSIS"

    send_raw "cat $sample | python3 -m json.tool 2>/dev/null || cat $sample"
    send_prism "python3 -m crack.tools.post.prism.cli $sample --host $DEMO_HOST $NEO4J_FLAG"

    clear
    print_header "PARSER: LaZagne"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   Nested JSON with software categories"
    echo -e "  ${GREEN}PRISM:${NC} Flat credential list with source tracking"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${GREEN}*${NC} ${GREEN}Multi-source: browsers, WiFi, mail, VPN, etc.${NC}"
    echo -e "  ${MAGENTA}*${NC} JSON and text output parsing"
    echo -e "  ${MAGENTA}*${NC} URL extraction for web credentials"
    echo -e "  ${MAGENTA}*${NC} Source software identification"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}lazagne.exe all -oJ > lazagne.json${NC}"
    echo -e "  ${CYAN}crack prism lazagne.json${NC}"

    wait_for_input
}

demo_connstring() {
    local sample="$SAMPLES_DIR/web.config"

    clear_sessions "RAW WEB.CONFIG" "PRISM ANALYSIS"

    send_raw "cat $sample"
    send_prism "python3 -m crack.tools.post.prism.cli $sample --host $DEMO_HOST $NEO4J_FLAG"

    clear
    print_header "PARSER: Connection Strings"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   XML/config files with credentials in attributes"
    echo -e "  ${GREEN}PRISM:${NC} Database credentials extracted with server info"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${RED}*${NC} ${RED}Detects DB passwords in web.config, .env, appsettings.json${NC}"
    echo -e "  ${MAGENTA}*${NC} SQL Server, MySQL, PostgreSQL connection strings"
    echo -e "  ${MAGENTA}*${NC} Environment variable formats (DB_PASSWORD=)"
    echo -e "  ${MAGENTA}*${NC} Server/database name extraction"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}# After SMB share access${NC}"
    echo -e "  ${CYAN}crack prism /mnt/shares/wwwroot/web.config${NC}"

    wait_for_input
}

demo_script() {
    local sample="$SAMPLES_DIR/deploy_script.ps1"

    clear_sessions "RAW SCRIPT FILE" "PRISM ANALYSIS"

    send_raw "cat $sample"
    send_prism "python3 -m crack.tools.post.prism.cli $sample --host $DEMO_HOST $NEO4J_FLAG"

    clear
    print_header "PARSER: Script Credentials"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   Code with hardcoded passwords buried in logic"
    echo -e "  ${GREEN}PRISM:${NC} All credential patterns extracted with context"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${RED}*${NC} ${RED}Finds hardcoded passwords in PS1, SH, PY, BAT${NC}"
    echo -e "  ${MAGENTA}*${NC} Detects \$password=, api_key=, secret= patterns"
    echo -e "  ${MAGENTA}*${NC} PSCredential object parsing"
    echo -e "  ${MAGENTA}*${NC} Base64 encoded credential detection"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}# SYSVOL scripts often contain creds${NC}"
    echo -e "  ${CYAN}crack prism crawl //DC/SYSVOL/scripts/${NC}"

    wait_for_input
}

demo_shadow() {
    local sample="$SAMPLES_DIR/shadow_dump.txt"

    clear_sessions "RAW SHADOW FILE" "PRISM ANALYSIS"

    send_raw "cat $sample"
    send_prism "python3 -m crack.tools.post.prism.cli $sample --host $DEMO_HOST $NEO4J_FLAG"

    clear
    print_header "PARSER: Linux Shadow"

    echo -e "${YELLOW}Comparison:${NC}"
    echo -e "  ${DIM}RAW:${NC}   Shadow format with hash algorithms mixed"
    echo -e "  ${GREEN}PRISM:${NC} Hash type identified, hashcat mode shown"
    echo ""
    echo -e "${YELLOW}Key Features:${NC}"
    echo -e "  ${MAGENTA}*${NC} SHA512 (\$6\$), SHA256 (\$5\$), MD5 (\$1\$) detection"
    echo -e "  ${MAGENTA}*${NC} Yescrypt (\$y\$) for modern systems"
    echo -e "  ${MAGENTA}*${NC} Filters locked/disabled accounts"
    echo -e "  ${MAGENTA}*${NC} Hashcat mode reference"
    echo ""
    echo -e "${YELLOW}Real-world usage:${NC}"
    echo -e "  ${DIM}cat /etc/shadow > shadow.txt${NC}"
    echo -e "  ${CYAN}crack prism shadow.txt${NC}"

    wait_for_input
}

show_progress() {
    local current=$1
    local total=$2
    local name=$3
    local next=$4

    # Build progress bar
    local pct=$((current * 100 / total))
    local filled=$((pct / 5))
    local empty=$((20 - filled))
    local bar=$(printf "█%.0s" $(seq 1 $filled 2>/dev/null) 2>/dev/null || echo "")
    bar+=$(printf "░%.0s" $(seq 1 $empty 2>/dev/null) 2>/dev/null || echo "")

    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  PROGRESS: ${WHITE}$current${NC}/${GREEN}$total${NC}  ${DIM}[$bar]${NC} ${pct}%"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${GREEN}▶${NC} Current: ${WHITE}$name${NC}"
    if [[ -n "$next" ]]; then
        echo -e "  ${DIM}▷ Next:    $next${NC}"
    fi
    echo ""
    sleep 0.5
}

run_all() {
    local total=18
    local current=0

    # Original parsers
    ((current++)); show_progress $current $total "Mimikatz" "Secretsdump"
    demo_mimikatz

    ((current++)); show_progress $current $total "Secretsdump" "Kerberoast"
    demo_secretsdump

    ((current++)); show_progress $current $total "Kerberoast" "AS-REP Roast"
    demo_kerberoast

    ((current++)); show_progress $current $total "AS-REP Roast" "LDAP"
    demo_asreproast

    ((current++)); show_progress $current $total "LDAP" "SMBMap"
    demo_ldap

    ((current++)); show_progress $current $total "SMBMap" "Hashcat"
    demo_smbmap

    # New parsers (v2.0)
    ((current++)); show_progress $current $total "Hashcat" "CrackMapExec"
    demo_hashcat

    ((current++)); show_progress $current $total "CrackMapExec" "Responder"
    demo_crackmapexec

    ((current++)); show_progress $current $total "Responder" "LaZagne"
    demo_responder

    ((current++)); show_progress $current $total "LaZagne" "Connection Strings"
    demo_lazagne

    ((current++)); show_progress $current $total "Connection Strings" "Script Creds"
    demo_connstring

    ((current++)); show_progress $current $total "Script Creds" "Linux Shadow"
    demo_script

    ((current++)); show_progress $current $total "Linux Shadow" "Directory Crawl"
    demo_shadow

    # Features
    ((current++)); show_progress $current $total "Directory Crawl" "List Domains"
    demo_crawl

    ((current++)); show_progress $current $total "List Domains" "Export Reports"
    demo_report

    ((current++)); show_progress $current $total "Export Reports" "Domain Report"
    demo_export

    ((current++)); show_progress $current $total "Domain Report" "Purge (Dry Run)"
    demo_domain_report

    ((current++)); show_progress $current $total "Purge (Dry Run)" ""
    demo_purge_dryrun
    # Note: Skipping demo_purge_execute in run_all for safety

    clear
    print_header "DEMO COMPLETE"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  ✓ All $total PRISM demos completed!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${WHITE}Parsers:${NC} 13 credential parsers demonstrated"
    echo -e "  ${WHITE}Features:${NC} Crawl, Report, Export, Purge"
    echo ""
    echo -e "For more information:"
    echo -e "  ${CYAN}crack prism --help${NC}"
    echo -e "  ${CYAN}crack prism report --help${NC}"
    echo -e "  ${CYAN}crack prism purge --help${NC}"
    echo ""
    wait_for_input
}

# ═══════════════════════════════════════════════════════════════
# Menu Display
# ═══════════════════════════════════════════════════════════════

show_menu() {
    clear
    # Rainbow gradient PRISM banner
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
    echo ""

    # Attach instructions box
    echo -e "  ${CYAN}┌─────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${CYAN}│${NC}  ${BOLD}ATTACH DEMO TERMINALS:${NC}                             ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}                                                     ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  ${YELLOW}Terminal 2:${NC}  tmux attach -t raw-demo              ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  ${YELLOW}Terminal 3:${NC}  tmux attach -t prism-demo            ${CYAN}│${NC}"
    echo -e "  ${CYAN}└─────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "                                      ${DIM}Neo4j:${NC} $NEO4J_STATUS"
    echo ""

    echo -e "${BOLD}${WHITE}  ◈ WINDOWS PARSERS ${DIM}────────────────────────────────${NC}"
    echo -e "  \033[38;5;196m1)\033[0m Mimikatz           ${DIM}Memory credential extraction${NC}"
    echo -e "  \033[38;5;208m2)\033[0m Secretsdump        ${DIM}NTDS hash parsing${NC}"
    echo -e "  \033[38;5;226m3)\033[0m Kerberoast         ${DIM}TGS ticket analysis${NC}"
    echo -e "  \033[38;5;46m4)\033[0m AS-REP Roast       ${DIM}Pre-auth disabled users${NC}"
    echo -e "  \033[38;5;51m5)\033[0m LDAP               ${DIM}Directory enumeration${NC}"
    echo -e "  \033[38;5;129m6)\033[0m SMBMap             ${DIM}Share enumeration${NC}"
    echo ""
    echo -e "${BOLD}${WHITE}  ◈ NEW PARSERS (v2.0) ${DIM}─────────────────────────────${NC}"
    echo -e "  \033[38;5;214m11)\033[0m Hashcat Potfile   ${DIM}Cracked password correlation${NC}"
    echo -e "  \033[38;5;118m12)\033[0m CrackMapExec      ${DIM}Spray results extraction${NC}"
    echo -e "  \033[38;5;39m13)\033[0m Responder         ${DIM}NetNTLM hash capture${NC}"
    echo -e "  \033[38;5;213m14)\033[0m LaZagne           ${DIM}Multi-source JSON parsing${NC}"
    echo -e "  \033[38;5;159m15)\033[0m Connection Str    ${DIM}web.config / .env files${NC}"
    echo -e "  \033[38;5;228m16)\033[0m Script Creds      ${DIM}Hardcoded passwords${NC}"
    echo -e "  \033[38;5;147m17)\033[0m Linux Shadow      ${DIM}/etc/shadow hashes${NC}"
    echo ""
    echo -e "${BOLD}${WHITE}  ◈ FEATURES ${DIM}────────────────────────────────────────${NC}"
    echo -e "  ${CYAN}7)${NC} Directory Crawl     ${DIM}Loot dump (18 parsers!)${NC}"
    echo ""
    echo -e "${BOLD}${WHITE}  ◈ NEO4J ${DIM}───────────────────────────────────────────${NC}"
    echo -e "  ${YELLOW}8)${NC} List Domains        ${DIM}Show available domains${NC}"
    echo -e "  ${YELLOW}9)${NC} Export Reports      ${DIM}Generate .md + .json${NC}"
    echo -e "  ${YELLOW}10)${NC} Purge (Dry Run)    ${DIM}Preview what would be deleted${NC}"
    echo -e "  ${RED}18)${NC} Purge (Execute)    ${DIM}Actually delete domain data${NC}"
    echo -e "  ${GREEN}19)${NC} Domain Report      ${DIM}Query domain credentials${NC}"
    echo ""
    echo -e "  ${MAGENTA}0)${NC} Run All             ${DIM}Complete demo (18 parsers)${NC}"
    echo -e "  ${RED}q)${NC} Quit"
    echo ""
    echo -n "  Enter selection: "
}

# ═══════════════════════════════════════════════════════════════
# Main Entry Point
# ═══════════════════════════════════════════════════════════════

# Check for tmux
if ! command -v tmux &>/dev/null; then
    echo -e "${RED}Error: tmux is required for this demo${NC}"
    echo "Install with: sudo apt install tmux"
    exit 1
fi

# Initialize sessions
echo -e "${CYAN}Initializing demo sessions...${NC}"
init_sessions
echo -e "${GREEN}Sessions ready!${NC}"
sleep 0.5

# Interactive menu loop
while true; do
    show_menu
    # Flush any pending input before reading
    read -r -t 0.1 -n 10000 discard 2>/dev/null || true
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
        10) demo_purge_dryrun ;;
        # New parsers (v2.0)
        11) demo_hashcat ;;
        12) demo_crackmapexec ;;
        13) demo_responder ;;
        14) demo_lazagne ;;
        15) demo_connstring ;;
        16) demo_script ;;
        17) demo_shadow ;;
        18) demo_purge_execute ;;
        19) demo_domain_report ;;
        0) run_all ;;
        q|Q) echo -e "\n${GREEN}Goodbye!${NC}"; exit 0 ;;
        *) echo -e "\n${RED}Invalid option${NC}"; sleep 1 ;;
    esac
done
