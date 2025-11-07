#!/bin/bash
#
# HAVE I BEEN PWNED? - Quick Security Health Check
# Based on CRACK Reference Network Monitoring Commands
#
# Purpose: Rapid defensive assessment to detect signs of compromise
# Usage: sudo ./have-i-been-pwned.sh [--full]
#
# Quick scan: Basic checks (30-60 seconds)
# Full scan:  Comprehensive analysis (2-5 minutes)
#

# Color codes
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# Counters
THREATS=0
WARNINGS=0
CHECKS=0

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] Warning: Not running as root. Some checks may fail.${RESET}"
    echo -e "${DIM}    Tip: Run with 'sudo ./have-i-been-pwned.sh' for full results${RESET}\n"
fi

# Parse arguments
FULL_SCAN=false
if [[ "$1" == "--full" ]]; then
    FULL_SCAN=true
fi

# Header
clear
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${CYAN}   HAVE I BEEN PWNED? - Security Health Check${RESET}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${DIM}Scan mode: $([ "$FULL_SCAN" = true ] && echo "FULL" || echo "QUICK")${RESET}"
echo -e "${DIM}Timestamp: $(date '+%Y-%m-%d %H:%M:%S')${RESET}\n"

# Function to print section header
section_header() {
    echo -e "\n${BOLD}${CYAN}▼ $1${RESET}"
    echo -e "${DIM}──────────────────────────────────────────────────────────${RESET}"
}

# Function to print check result
check_result() {
    local status=$1
    local message=$2
    local detail=$3

    ((CHECKS++))

    case $status in
        "OK")
            echo -e "  ${GREEN}✓${RESET} $message"
            ;;
        "WARN")
            echo -e "  ${YELLOW}⚠${RESET} $message"
            [ -n "$detail" ] && echo -e "    ${DIM}→ $detail${RESET}"
            ((WARNINGS++))
            ;;
        "THREAT")
            echo -e "  ${RED}✗${RESET} ${BOLD}$message${RESET}"
            [ -n "$detail" ] && echo -e "    ${RED}→ $detail${RESET}"
            ((THREATS++))
            ;;
    esac
}

# =============================================================================
# 1. NETWORK CONNECTION MONITORING
# =============================================================================
section_header "1. Network Connections"

# Check for established connections to unknown external IPs
echo -e "${DIM}Checking for suspicious external connections...${RESET}"
if command -v ss &> /dev/null; then
    EXTERNAL_CONNS=$(ss -tupn state established 2>/dev/null | grep -v "127.0.0.1" | grep -v "::1" | tail -n +2 | wc -l)
    if [ "$EXTERNAL_CONNS" -gt 10 ]; then
        check_result "WARN" "Found $EXTERNAL_CONNS established external connections" "Review with: ss -tupn state established"
    else
        check_result "OK" "External connections: $EXTERNAL_CONNS (reasonable)"
    fi
else
    EXTERNAL_CONNS=$(netstat -tupn 2>/dev/null | grep ESTABLISHED | grep -v "127.0.0.1" | wc -l)
    if [ "$EXTERNAL_CONNS" -gt 10 ]; then
        check_result "WARN" "Found $EXTERNAL_CONNS established external connections" "Review with: netstat -tupn"
    else
        check_result "OK" "External connections: $EXTERNAL_CONNS (reasonable)"
    fi
fi

# Check listening ports
echo -e "${DIM}Checking for unexpected listening ports...${RESET}"
if command -v ss &> /dev/null; then
    LISTENING_PORTS=$(ss -tulpn 2>/dev/null | grep LISTEN | wc -l)
    EXTERNAL_LISTENERS=$(ss -tulpn 2>/dev/null | grep "0.0.0.0:" | grep -v ":22 " | grep -v ":80 " | grep -v ":443 " | wc -l)
else
    LISTENING_PORTS=$(netstat -tulpn 2>/dev/null | grep LISTEN | wc -l)
    EXTERNAL_LISTENERS=$(netstat -tulpn 2>/dev/null | grep "0.0.0.0:" | grep -v ":22 " | grep -v ":80 " | grep -v ":443 " | wc -l)
fi

if [ "$EXTERNAL_LISTENERS" -gt 5 ]; then
    check_result "WARN" "Found $EXTERNAL_LISTENERS unusual externally-accessible ports" "Common backdoor indicator"
elif [ "$EXTERNAL_LISTENERS" -gt 0 ]; then
    check_result "WARN" "Found $EXTERNAL_LISTENERS non-standard listening ports" "Verify legitimacy"
else
    check_result "OK" "No suspicious listening ports detected"
fi

# Check for reverse shells (common ports)
echo -e "${DIM}Scanning for reverse shell indicators...${RESET}"
REVERSE_SHELL_PORTS=$(ss -tupn 2>/dev/null | grep -E ":(4444|4445|1234|9001|8080)" | wc -l)
if [ "$REVERSE_SHELL_PORTS" -gt 0 ]; then
    check_result "THREAT" "DETECTED: Connection on common reverse shell port" "Investigate immediately with: ss -tupn | grep -E ':(4444|4445|1234|9001)'"
else
    check_result "OK" "No connections on common reverse shell ports"
fi

if [ "$FULL_SCAN" = true ]; then
    # Full scan: Check all high ports
    HIGH_PORT_CONNS=$(ss -tupn 2>/dev/null | awk '{print $5}' | grep -oE ":[0-9]{5}" | wc -l)
    if [ "$HIGH_PORT_CONNS" -gt 5 ]; then
        check_result "WARN" "Found $HIGH_PORT_CONNS connections on high ports (>10000)" "May indicate non-standard services"
    fi
fi

# =============================================================================
# 2. PROCESS MONITORING
# =============================================================================
section_header "2. Process Analysis"

# Check for processes running from suspicious locations
echo -e "${DIM}Checking for processes in unusual locations...${RESET}"
SUSPICIOUS_PROCS=$(ps aux 2>/dev/null | grep -E "/tmp/|/var/tmp/|/dev/shm/" | grep -v grep | wc -l)
if [ "$SUSPICIOUS_PROCS" -gt 0 ]; then
    check_result "THREAT" "DETECTED: $SUSPICIOUS_PROCS processes running from /tmp or /dev/shm" "Common malware location"
    ps aux 2>/dev/null | grep -E "/tmp/|/var/tmp/|/dev/shm/" | grep -v grep | head -3 | while read line; do
        echo -e "    ${RED}→ $line${RESET}"
    done
else
    check_result "OK" "No processes running from suspicious directories"
fi

# Check for hidden processes (names starting with space or dot)
echo -e "${DIM}Checking for hidden/obfuscated processes...${RESET}"
HIDDEN_PROCS=$(ps aux 2>/dev/null | awk '{if(NF>0 && ($11 ~ /^\./ || $11 ~ /^ /)) print $0}' | wc -l)
if [ "$HIDDEN_PROCS" -gt 0 ]; then
    check_result "WARN" "Found $HIDDEN_PROCS process(es) with suspicious names" "May indicate stealth malware"
else
    check_result "OK" "No obviously hidden processes detected"
fi

# Check for unauthorized shells
echo -e "${DIM}Checking for unauthorized shell processes...${RESET}"
SHELL_PROCS=$(ps aux 2>/dev/null | grep -E "bash|sh|zsh|ksh" | grep -v "$USER" | grep -v grep | grep -v "have-i-been-pwned" | wc -l)
if [ "$SHELL_PROCS" -gt 5 ]; then
    check_result "WARN" "Found $SHELL_PROCS shell processes by other users" "May indicate lateral movement"
else
    check_result "OK" "Shell processes appear normal"
fi

# Check for netcat/socat processes
echo -e "${DIM}Checking for netcat/socat (common reverse shell tools)...${RESET}"
NC_PROCS=$(ps aux 2>/dev/null | grep -E "nc |ncat |netcat |socat " | grep -v grep | wc -l)
if [ "$NC_PROCS" -gt 0 ]; then
    check_result "THREAT" "DETECTED: Active netcat/socat processes" "Likely reverse shell"
    ps aux 2>/dev/null | grep -E "nc |ncat |netcat |socat " | grep -v grep | while read line; do
        echo -e "    ${RED}→ $line${RESET}"
    done
else
    check_result "OK" "No netcat/socat processes detected"
fi

if [ "$FULL_SCAN" = true ]; then
    # Check for high CPU/memory processes
    echo -e "${DIM}Checking for resource-intensive processes (potential cryptominers)...${RESET}"
    HIGH_CPU=$(ps aux --sort=-%cpu 2>/dev/null | awk 'NR==2 {print $3}' | cut -d. -f1)
    if [ "$HIGH_CPU" -gt 80 ]; then
        TOP_PROC=$(ps aux --sort=-%cpu 2>/dev/null | awk 'NR==2 {print $11}')
        check_result "WARN" "Process '$TOP_PROC' using ${HIGH_CPU}% CPU" "May indicate cryptominer"
    fi
fi

# =============================================================================
# 3. AUTHENTICATION LOG ANALYSIS
# =============================================================================
section_header "3. Authentication Logs"

# Check for failed login attempts
echo -e "${DIM}Checking for failed login attempts...${RESET}"
if [ -f /var/log/auth.log ]; then
    FAILED_LOGINS=$(grep -i "failed password" /var/log/auth.log 2>/dev/null | wc -l)
    INVALID_USERS=$(grep -i "invalid user" /var/log/auth.log 2>/dev/null | wc -l)

    if [ "$FAILED_LOGINS" -gt 50 ]; then
        check_result "THREAT" "DETECTED: $FAILED_LOGINS failed login attempts" "Likely brute force attack"
        echo -e "    ${DIM}Top attacking IPs:${RESET}"
        grep "Failed password" /var/log/auth.log 2>/dev/null | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -rn | head -3 | while read line; do
            echo -e "      ${RED}→ $line${RESET}"
        done
    elif [ "$FAILED_LOGINS" -gt 10 ]; then
        check_result "WARN" "$FAILED_LOGINS failed login attempts detected" "Monitor for escalation"
    else
        check_result "OK" "Failed logins: $FAILED_LOGINS (normal)"
    fi

    if [ "$INVALID_USERS" -gt 20 ]; then
        check_result "WARN" "$INVALID_USERS invalid user attempts detected" "Username enumeration attack"
    fi
elif [ -f /var/log/secure ]; then
    FAILED_LOGINS=$(grep -i "failed password" /var/log/secure 2>/dev/null | wc -l)
    if [ "$FAILED_LOGINS" -gt 50 ]; then
        check_result "THREAT" "DETECTED: $FAILED_LOGINS failed login attempts" "Likely brute force attack"
    elif [ "$FAILED_LOGINS" -gt 10 ]; then
        check_result "WARN" "$FAILED_LOGINS failed login attempts detected"
    else
        check_result "OK" "Failed logins: $FAILED_LOGINS (normal)"
    fi
else
    check_result "WARN" "Cannot access authentication logs" "Run with sudo for full analysis"
fi

# Check for successful root logins
echo -e "${DIM}Checking for root logins...${RESET}"
if [ -f /var/log/auth.log ]; then
    ROOT_LOGINS=$(grep "session opened.*root" /var/log/auth.log 2>/dev/null | tail -5 | wc -l)
    if [ "$ROOT_LOGINS" -gt 0 ]; then
        check_result "WARN" "Found $ROOT_LOGINS recent root sessions" "Verify legitimacy"
    else
        check_result "OK" "No recent root logins detected"
    fi
fi

# Check sudo usage
echo -e "${DIM}Checking sudo command history...${RESET}"
if [ -f /var/log/auth.log ]; then
    SUDO_CMDS=$(grep "sudo.*COMMAND" /var/log/auth.log 2>/dev/null | tail -10 | wc -l)
    SUSPICIOUS_SUDO=$(grep "sudo.*COMMAND" /var/log/auth.log 2>/dev/null | grep -E "bash|sh|nc |python|perl" | tail -5 | wc -l)

    if [ "$SUSPICIOUS_SUDO" -gt 0 ]; then
        check_result "WARN" "Found $SUSPICIOUS_SUDO sudo commands executing shells/interpreters" "May indicate privilege escalation"
    elif [ "$SUDO_CMDS" -gt 0 ]; then
        check_result "OK" "Sudo activity detected: $SUDO_CMDS recent commands"
    fi
fi

# =============================================================================
# 4. ACTIVE USER MONITORING
# =============================================================================
section_header "4. Active Users"

# Check currently logged in users
echo -e "${DIM}Checking for active user sessions...${RESET}"
ACTIVE_USERS=$(w -h 2>/dev/null | wc -l)
if [ "$ACTIVE_USERS" -gt 3 ]; then
    check_result "WARN" "Found $ACTIVE_USERS active user sessions" "Verify all are legitimate"
    w 2>/dev/null | tail -n +3 | while read line; do
        echo -e "    ${YELLOW}→ $line${RESET}"
    done
else
    check_result "OK" "Active sessions: $ACTIVE_USERS"
fi

# Check for recent logins from unusual locations
if [ "$FULL_SCAN" = true ]; then
    echo -e "${DIM}Checking recent login history...${RESET}"
    RECENT_LOGINS=$(last -n 10 2>/dev/null | grep -v "reboot" | grep -v "wtmp" | wc -l)
    if [ "$RECENT_LOGINS" -gt 0 ]; then
        check_result "OK" "Recent login history available (showing last 5)"
        last -n 5 2>/dev/null | grep -v "reboot" | grep -v "wtmp" | head -5 | while read line; do
            echo -e "    ${DIM}→ $line${RESET}"
        done
    fi
fi

# =============================================================================
# 5. RESOURCE MONITORING
# =============================================================================
section_header "5. System Resources"

# Check memory usage
echo -e "${DIM}Checking memory usage...${RESET}"
if command -v free &> /dev/null; then
    MEM_USED=$(free | grep Mem | awk '{print int($3/$2 * 100)}')
    if [ "$MEM_USED" -gt 90 ]; then
        check_result "WARN" "Memory usage at ${MEM_USED}%" "May indicate memory exhaustion attack"
    else
        check_result "OK" "Memory usage: ${MEM_USED}%"
    fi
fi

# Check disk usage
echo -e "${DIM}Checking disk usage...${RESET}"
DISK_USED=$(df -h / 2>/dev/null | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$DISK_USED" -gt 90 ]; then
    check_result "WARN" "Root disk usage at ${DISK_USED}%" "May prevent logging or cause service failures"
elif [ "$DISK_USED" -gt 80 ]; then
    check_result "WARN" "Root disk usage at ${DISK_USED}%" "Monitor closely"
else
    check_result "OK" "Root disk usage: ${DISK_USED}%"
fi

# Check load average
echo -e "${DIM}Checking system load...${RESET}"
LOAD_AVG=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
CPU_CORES=$(nproc 2>/dev/null || echo "1")
LOAD_PER_CORE=$(echo "$LOAD_AVG $CPU_CORES" | awk '{printf "%.1f", $1/$2}')
LOAD_PERCENT=$(echo "$LOAD_PER_CORE" | awk '{printf "%d", $1*100}')

if [ "$LOAD_PERCENT" -gt 200 ]; then
    check_result "WARN" "System load at ${LOAD_PER_CORE}x per core" "System overloaded"
elif [ "$LOAD_PERCENT" -gt 100 ]; then
    check_result "WARN" "System load at ${LOAD_PER_CORE}x per core" "Elevated load"
else
    check_result "OK" "System load: ${LOAD_PER_CORE}x per core"
fi

# =============================================================================
# 6. PERSISTENCE CHECKS
# =============================================================================
if [ "$FULL_SCAN" = true ]; then
    section_header "6. Persistence Mechanisms"

    # Check for suspicious cron jobs
    echo -e "${DIM}Checking cron jobs for backdoors...${RESET}"
    SUSPICIOUS_CRON=$(grep -r "nc \|bash \|/tmp/" /etc/cron* 2>/dev/null | wc -l)
    if [ "$SUSPICIOUS_CRON" -gt 0 ]; then
        check_result "THREAT" "DETECTED: Suspicious cron job entries" "May indicate persistence mechanism"
        grep -r "nc \|bash \|/tmp/" /etc/cron* 2>/dev/null | head -3 | while read line; do
            echo -e "    ${RED}→ $line${RESET}"
        done
    else
        check_result "OK" "No obviously suspicious cron jobs"
    fi

    # Check for unusual SUID binaries
    echo -e "${DIM}Checking for unusual SUID binaries...${RESET}"
    SUID_COUNT=$(find / -perm -4000 -type f 2>/dev/null | wc -l)
    if [ "$SUID_COUNT" -gt 50 ]; then
        check_result "WARN" "Found $SUID_COUNT SUID binaries" "High number, review manually"
    else
        check_result "OK" "SUID binaries: $SUID_COUNT (reasonable)"
    fi
fi

# =============================================================================
# SUMMARY
# =============================================================================
echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${CYAN}   SCAN SUMMARY${RESET}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${RESET}"

echo -e "\n${BOLD}Results:${RESET}"
echo -e "  Total checks performed: ${CYAN}$CHECKS${RESET}"

if [ "$THREATS" -gt 0 ]; then
    echo -e "  ${RED}✗ Critical threats:     $THREATS${RESET}"
fi

if [ "$WARNINGS" -gt 0 ]; then
    echo -e "  ${YELLOW}⚠ Warnings:             $WARNINGS${RESET}"
fi

PASSED=$((CHECKS - THREATS - WARNINGS))
echo -e "  ${GREEN}✓ Checks passed:        $PASSED${RESET}"

# Overall assessment
echo -e "\n${BOLD}Overall Assessment:${RESET}"
if [ "$THREATS" -gt 0 ]; then
    echo -e "  ${RED}${BOLD}COMPROMISED${RESET} - Immediate investigation required"
    echo -e "  ${DIM}Next steps:${RESET}"
    echo -e "    ${RED}1. Isolate system from network${RESET}"
    echo -e "    ${RED}2. Preserve evidence (logs, process dumps)${RESET}"
    echo -e "    ${RED}3. Analyze threats identified above${RESET}"
    echo -e "    ${RED}4. Consider full forensic analysis${RESET}"
elif [ "$WARNINGS" -gt 3 ]; then
    echo -e "  ${YELLOW}${BOLD}SUSPICIOUS${RESET} - Multiple anomalies detected"
    echo -e "  ${DIM}Next steps:${RESET}"
    echo -e "    ${YELLOW}1. Review all warnings above${RESET}"
    echo -e "    ${YELLOW}2. Verify legitimacy of flagged items${RESET}"
    echo -e "    ${YELLOW}3. Enable detailed logging${RESET}"
    echo -e "    ${YELLOW}4. Consider running --full scan${RESET}"
elif [ "$WARNINGS" -gt 0 ]; then
    echo -e "  ${YELLOW}${BOLD}CAUTION${RESET} - Minor issues detected"
    echo -e "  ${DIM}Review warnings and verify they are expected.${RESET}"
else
    echo -e "  ${GREEN}${BOLD}CLEAN${RESET} - No obvious signs of compromise"
    echo -e "  ${DIM}Continue regular security monitoring.${RESET}"
fi

# Additional recommendations
echo -e "\n${BOLD}Recommendations:${RESET}"
if [ "$FULL_SCAN" = false ]; then
    echo -e "  ${DIM}• Run with --full flag for comprehensive analysis${RESET}"
fi
echo -e "  ${DIM}• Review system logs manually: journalctl -xe${RESET}"
echo -e "  ${DIM}• Check network connections: ss -tupn${RESET}"
echo -e "  ${DIM}• Review running processes: ps auxww${RESET}"
echo -e "  ${DIM}• Monitor authentication logs: tail -f /var/log/auth.log${RESET}"

echo -e "\n${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${RESET}"
echo -e "${DIM}Scan completed at $(date '+%Y-%m-%d %H:%M:%S')${RESET}\n"

# Exit code based on findings
if [ "$THREATS" -gt 0 ]; then
    exit 2  # Critical threats
elif [ "$WARNINGS" -gt 0 ]; then
    exit 1  # Warnings
else
    exit 0  # Clean
fi
