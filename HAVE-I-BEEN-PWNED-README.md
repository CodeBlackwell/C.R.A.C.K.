# Have I Been Pwned? - Defensive Security Scanner

## Overview

A rapid defensive security assessment script based on CRACK reference network monitoring commands. Designed for OSCP-style quick compromise detection on Linux systems.

## Purpose

**Quick Answer:** "Has this system been compromised?"

Checks for common indicators of compromise (IOCs):
- Reverse shells and backdoor connections
- Malicious processes in suspicious locations
- Brute force attacks and authentication anomalies
- Unauthorized user sessions
- Resource exhaustion attacks
- Persistence mechanisms (cron backdoors, SUID backdoors)

## Usage

### Quick Scan (30-60 seconds)
```bash
sudo ./have-i-been-pwned.sh
```

### Full Scan (2-5 minutes)
```bash
sudo ./have-i-been-pwned.sh --full
```

**Note:** Requires root/sudo for full analysis (log access, process details)

## What It Checks

### 1. Network Connections
- **Established connections** to external IPs
- **Listening ports** (especially 0.0.0.0 bindings)
- **Reverse shell ports** (4444, 4445, 1234, 9001, 8080)
- **High port connections** (>10000) - Full scan only

**CRACK Commands Used:**
- `ss -tupn state established` (modern)
- `netstat -tupn` (legacy fallback)
- `ss -tulpn` (listening ports)

### 2. Process Analysis
- **Suspicious locations:** Processes in /tmp, /var/tmp, /dev/shm
- **Hidden processes:** Names starting with `.` or space
- **Unauthorized shells:** Bash/sh processes by other users
- **Reverse shell tools:** netcat, ncat, socat
- **Resource hogs:** High CPU/memory (cryptominers) - Full scan only

**CRACK Commands Used:**
- `ps aux` (process snapshot)
- `ps auxww` (no truncation, catches command-line passwords)
- `ps aux --sort=-%cpu` (CPU consumers)
- `ps aux --sort=-%mem` (memory consumers)

### 3. Authentication Logs
- **Failed logins:** Brute force detection
- **Invalid users:** Username enumeration
- **Root logins:** Elevated access tracking
- **Sudo usage:** Privilege escalation attempts

**CRACK Commands Used:**
- `grep "Failed password" /var/log/auth.log`
- `grep "Invalid user" /var/log/auth.log`
- `grep "session opened.*root" /var/log/auth.log`
- `grep "sudo.*COMMAND" /var/log/auth.log`

### 4. Active Users
- **Current sessions:** w command analysis
- **Login history:** Recent access patterns (Full scan)

**CRACK Commands Used:**
- `w` (who is logged in and what they're doing)
- `last -n 10` (recent login history)

### 5. System Resources
- **Memory usage:** Exhaustion attack detection
- **Disk usage:** Log/service denial
- **Load average:** CPU overload detection

**CRACK Commands Used:**
- `free -h` (memory stats)
- `df -h` (disk usage)
- `uptime` (load average)

### 6. Persistence Mechanisms (Full Scan)
- **Cron jobs:** Backdoor scheduled tasks
- **SUID binaries:** Privilege escalation vectors

**CRACK Commands Used:**
- `grep -r "nc \|bash \|/tmp/" /etc/cron*`
- `find / -perm -4000 -type f` (SUID enumeration)

## Output Interpretation

### Status Indicators

| Symbol | Meaning | Action |
|--------|---------|--------|
| ✓ Green | Check passed | No action needed |
| ⚠ Yellow | Warning/anomaly | Review and verify legitimacy |
| ✗ Red | Critical threat | Immediate investigation required |

### Exit Codes
- `0` - Clean (no threats, no warnings)
- `1` - Warnings detected (minor issues)
- `2` - Critical threats detected (compromised)

### Overall Assessments

**CLEAN** - No obvious signs of compromise
- Continue regular monitoring
- Review logs periodically

**CAUTION** - Minor issues detected
- Review warnings
- Verify flagged items are expected
- Consider full scan

**SUSPICIOUS** - Multiple anomalies
- Review ALL warnings
- Enable detailed logging
- Run full scan if not already
- Consider forensic analysis

**COMPROMISED** - Critical threats
- **Isolate system immediately**
- Preserve evidence (logs, memory dumps)
- Analyze identified threats
- Full forensic investigation required

## Example Output

```
═══════════════════════════════════════════════════════════════
   HAVE I BEEN PWNED? - Security Health Check
═══════════════════════════════════════════════════════════════
Scan mode: QUICK
Timestamp: 2024-11-05 14:23:45

▼ 1. Network Connections
──────────────────────────────────────────────────────────
  ✓ External connections: 3 (reasonable)
  ✓ No suspicious listening ports detected
  ✗ DETECTED: Connection on common reverse shell port
    → Investigate immediately with: ss -tupn | grep -E ':(4444|4445|1234|9001)'

▼ 2. Process Analysis
──────────────────────────────────────────────────────────
  ✗ DETECTED: 1 processes running from /tmp or /dev/shm
    → root  12345  0.0  0.1  12345  1234 ?  S  14:20  0:00 /tmp/.hidden/backdoor
  ✓ No obviously hidden processes detected
  ✓ Shell processes appear normal
  ✗ DETECTED: Active netcat/socat processes
    → www-data  12346  0.0  0.0  12345  1234 ?  S  14:20  0:00 nc -e /bin/bash 10.10.14.5 4444

...

═══════════════════════════════════════════════════════════════
   SCAN SUMMARY
═══════════════════════════════════════════════════════════════

Results:
  Total checks performed: 15
  ✗ Critical threats:     3
  ⚠ Warnings:             2
  ✓ Checks passed:        10

Overall Assessment:
  COMPROMISED - Immediate investigation required
  Next steps:
    1. Isolate system from network
    2. Preserve evidence (logs, process dumps)
    3. Analyze threats identified above
    4. Consider full forensic analysis
```

## OSCP Defensive Scenario Usage

### Scenario 1: Post-Exploitation Detection
You've gained access to a target and need to check if other attackers are present:
```bash
sudo ./have-i-been-pwned.sh
```

### Scenario 2: Blue Team Exercise
Defending a system during OSCP defensive challenges:
```bash
# Quick check every 5 minutes
watch -n 300 'sudo ./have-i-been-pwned.sh'

# Or run full scan periodically
while true; do
    sudo ./have-i-been-pwned.sh --full > "scan-$(date +%Y%m%d-%H%M%S).log"
    sleep 600
done
```

### Scenario 3: Incident Response
System behaving suspiciously:
```bash
# Full diagnostic
sudo ./have-i-been-pwned.sh --full | tee incident-$(date +%Y%m%d-%H%M%S).log

# Check specific threat
ss -tupn | grep -E ':(4444|4445|1234|9001)'
ps aux | grep -E "/tmp/|/var/tmp/|/dev/shm/"
grep "Failed password" /var/log/auth.log | tail -20
```

## Integration with CRACK Toolkit

This script uses the same commands documented in CRACK's monitoring reference:

```bash
# View full command documentation
crack reference --category monitoring

# Get specific command details
crack reference lsof-network-all
crack reference netstat-listening-tcp
crack reference grep-auth-failed
crack reference ps-sort-cpu
```

## Manual Investigation Commands

If script detects threats, use these for deep analysis:

### Network Threats
```bash
# View all connections with process details
sudo lsof -i -P -n

# Check specific port
sudo lsof -i :4444

# Monitor new connections
sudo watch -n 1 'ss -tupn state established'
```

### Process Threats
```bash
# Full process details (no truncation)
ps auxww

# Check process by PID
ps -p <PID> -o cmd=
sudo lsof -p <PID>

# View process environment (may contain passwords)
sudo cat /proc/<PID>/environ | tr '\0' '\n'
```

### Authentication Threats
```bash
# Failed login attempts
grep "Failed password" /var/log/auth.log

# Extract attacking IPs
grep "Failed password" /var/log/auth.log | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq -c | sort -rn

# Sudo command history
grep "sudo.*COMMAND" /var/log/auth.log | tail -20

# Failed login log
sudo lastb -a
```

### Persistence Checks
```bash
# Check all cron jobs
cat /etc/crontab
ls -la /etc/cron.*
crontab -l
sudo crontab -l

# Check startup scripts
ls -la /etc/init.d/
systemctl list-units --type=service

# Check SUID binaries
find / -perm -4000 -type f 2>/dev/null
```

## Threat Thresholds

The script uses these thresholds (tunable in source):

| Metric | Warning | Threat |
|--------|---------|--------|
| External connections | >10 | - |
| Failed logins | >10 | >50 |
| Active users | >3 | - |
| Memory usage | >90% | - |
| Disk usage | >80% | >90% |
| System load | >1.0/core | >2.0/core |

## Limitations

**Not Checked:**
- Kernel-level rootkits (use rkhunter/chkrootkit)
- Firmware/BIOS persistence
- Encrypted communications (TLS inspection needed)
- Memory-only malware (volatility analysis needed)
- Fileless attacks (advanced EDR needed)

**False Positives:**
- Legitimate high-port services
- Developer processes in /tmp
- Administrative maintenance sessions
- Load testing scenarios

**Requires Root:**
- Full process details (command lines)
- Network socket → process mapping
- Authentication log access
- SUID/cron enumeration

## Customization

Edit thresholds in script:
```bash
# Line 88: External connection threshold
if [ "$EXTERNAL_CONNS" -gt 10 ]; then

# Line 105: Non-standard port threshold
if [ "$EXTERNAL_LISTENERS" -gt 5 ]; then

# Line 150: Failed login threat level
if [ "$FAILED_LOGINS" -gt 50 ]; then
```

## Educational Value (OSCP Relevance)

**Teaches:**
1. **Defense methodology** - What to check when incident suspected
2. **Manual alternatives** - Every check has a manual command
3. **Tool independence** - Uses basic Linux tools (ps, ss, grep)
4. **Real-world IR** - Mirrors actual incident response workflow
5. **Log analysis** - Authentication patterns and anomalies

**OSCP Defense Scenarios:**
- Active machine defense during exam
- Post-exploitation hardening
- Blue team exercises
- Multi-vector detection

## Troubleshooting

**"Not running as root" warning:**
```bash
# Run with sudo
sudo ./have-i-been-pwned.sh
```

**"Cannot access authentication logs":**
```bash
# Check log location (Debian vs RHEL)
ls -la /var/log/auth.log    # Debian/Ubuntu
ls -la /var/log/secure      # RHEL/CentOS
```

**"ss: command not found":**
```bash
# Install iproute2 (ss) or script falls back to netstat
sudo apt install iproute2
```

**High false positive rate:**
- Adjust thresholds in script
- Run during known-good state to baseline
- Use --full scan for better context

## License

Based on CRACK reference commands (GPL-3.0).
Educational use for OSCP preparation.

## Credits

Command methodology from CRACK - Comprehensive Recon & Attack Creation Kit
Network monitoring commands: `crack/reference/data/commands/monitoring/`
