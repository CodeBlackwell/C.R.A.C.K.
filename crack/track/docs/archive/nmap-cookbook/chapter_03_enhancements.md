# Scan Profiles Chapter 3 Enhancements

**Date:** 2025-10-08
**Source:** `nmap_cookbook_chapters/NMAP_CH03_HOST_INFORMATION_MINING_REPORT.md`
**Status:** ✅ Complete

---

## Summary

Added OS detection, fingerprinting, and firewall detection scan profiles extracted from Nmap Cookbook Chapter 3 "Gathering Additional Host Information".

## New Profiles Added (5 Total)

### 1. os-detect-standard
**Profile ID:** `os-detect-standard`
**Command:** `nmap -O`
**Priority:** OSCP:HIGH
**Use Case:** Standard OS detection via TCP/IP fingerprinting

**Key Features:**
- Analyzes TCP window sizes, TTL values, TCP options
- Provides OS family (Linux, Windows, BSD)
- Extracts CPE identifiers for CVE matching
- Device type classification

**Manual Alternatives:**
- TTL inspection: `ping -c1 <TARGET>` (64=Linux, 128=Windows)
- Banner grabbing: `nc <TARGET> 22`
- HTTP headers: `curl -I http://<TARGET>`

**Requirements:** At least one open AND one closed port for accurate results

---

### 2. os-detect-aggressive
**Profile ID:** `os-detect-aggressive`
**Command:** `nmap -O --osscan-guess`
**Priority:** OSCP:MEDIUM
**Use Case:** Fallback when standard OS detection fails

**Key Features:**
- Aggressive guessing mode
- Provides OS family even without exact match
- Multiple OS possibilities with confidence percentages

**When to Use:** Standard `-O` returns "No exact OS matches"

---

### 3. fingerprint-banner-grab
**Profile ID:** `fingerprint-banner-grab`
**Command:** `nc -v`
**Priority:** OSCP:HIGH
**Use Case:** Manual service fingerprinting

**Key Features:**
- Fast banner grabbing (1-2 min per port)
- Works when automated tools fail
- Low detection risk
- OSCP exam friendly

**Service-Specific Commands:**
- HTTP: `curl -I http://<TARGET>`
- SSH: `nc <TARGET> 22`
- SMTP: `nc <TARGET> 25`, type `HELO test`
- FTP: `ftp <TARGET>`

**OSCP Note:** Manual banner grabbing is faster than version scans and works when nmap fails. Always try manual first for critical ports (22, 80, 21, 25).

---

### 4. firewall-detect-ack
**Profile ID:** `firewall-detect-ack`
**Command:** `nmap -sA`
**Priority:** OSCP:HIGH
**Use Case:** Detect stateful firewalls

**Key Features:**
- TCP ACK scan (sends ACK without prior SYN)
- Identifies stateful firewalls
- Helps shape exploitation strategy

**Success Indicators:**
- All ports "unfiltered" = no stateful firewall
- Mix of filtered/unfiltered = firewall with rules
- All ports "filtered" = stateful firewall blocking

**Manual Alternative:**
- `hping3 -A -p80 -c1 <TARGET>`

**Important:** ACK scan does NOT determine open/closed ports - only filtered/unfiltered.

---

### 5. udp-critical-oscp
**Profile ID:** `udp-critical-oscp`
**Command:** `nmap -sU -p 53,69,123,161,162,500`
**Priority:** OSCP:HIGH
**Use Case:** Target critical UDP services

**Key Features:**
- Focused on high-value UDP services
- Fast execution (3-5 minutes)
- SNMP often yields credentials

**Target Services:**
- DNS (53) - Zone transfers
- TFTP (69) - File download/upload
- NTP (123) - Time service
- SNMP (161/162) - Community string enumeration
- IPSec (500) - VPN detection

**Next Steps:**
```bash
# SNMP enumeration (HIGH VALUE)
snmpwalk -v2c -c public <TARGET>
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <TARGET>

# TFTP file retrieval
tftp <TARGET>
> get config.cfg

# DNS zone transfer
dig axfr @<TARGET> <domain>
```

**OSCP Critical:** NEVER skip UDP scanning. SNMP frequently contains credentials and system information.

---

## Integration with Existing System

### Parser Enhancements Already Complete

The `nmap_xml.py` parser already supports:
- ✅ OS detection parsing (`_parse_os_detection`)
- ✅ CPE identifier extraction (service and OS)
- ✅ Accuracy scores for OS matches
- ✅ Traceroute data parsing
- ✅ Scan statistics extraction
- ✅ NSE structured output parsing

### Metadata Updates

Added new category to scan profiles metadata:
```json
"os_fingerprinting_recommended": [
  "os-detect-standard",
  "os-detect-aggressive",
  "fingerprint-banner-grab",
  "firewall-detect-ack",
  "udp-critical-oscp"
]
```

Updated OSCP recommended list to include:
- `os-detect-standard`
- `firewall-detect-ack`
- `udp-critical-oscp`

---

## Usage Examples

### Standard OS Detection
```bash
# Create target profile
crack track new 192.168.45.100

# Run port scan first
nmap -p- --min-rate 1000 192.168.45.100 -oA full_scan

# Add OS detection
nmap -O 192.168.45.100 -oA os_scan

# Import results
crack track import 192.168.45.100 full_scan.xml
crack track import 192.168.45.100 os_scan.xml
```

### Firewall Detection Workflow
```bash
# Test for firewall presence
nmap -sA 192.168.45.100 -oA firewall_test

# Interpret results:
# - "unfiltered" = no stateful firewall, proceed with aggressive scans
# - "filtered" = firewall present, focus on allowed ports (80, 443)
```

### Critical UDP Services
```bash
# Target high-value UDP services
nmap -sU -p 53,69,123,161,162,500 192.168.45.100 -oA udp_critical

# If SNMP open:
snmpwalk -v2c -c public 192.168.45.100
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt 192.168.45.100
```

### Manual Banner Grabbing (OSCP Exam)
```bash
# SSH banner
nc 192.168.45.100 22
# Output: SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2

# HTTP headers
curl -I http://192.168.45.100
# Server: Apache/2.4.41 (Ubuntu)

# SMTP banner
nc 192.168.45.100 25
HELO test
# 220 mail.target.com ESMTP Postfix
```

---

## Complete OSCP Workflow

**Phase 1: Discovery (5-10 min)**
```bash
# Quick port scan
nmap --top-ports 1000 192.168.45.100 -oA quick

# UDP critical services
nmap -sU -p 53,69,123,161,162,500 192.168.45.100 -oA udp
```

**Phase 2: Enumeration (10 min)**
```bash
# Service version detection
nmap -sV -sC -p <PORTS> 192.168.45.100 -oA services

# OS detection
nmap -O 192.168.45.100 -oA os
```

**Phase 3: Context (5 min)**
```bash
# Firewall check
nmap -sA 192.168.45.100 -oA firewall

# Full port scan (background)
nmap -p- --min-rate 1000 192.168.45.100 -oA full &
```

**Phase 4: Research (15 min)**
```bash
# Exploit research for each service
searchsploit <SERVICE> <VERSION>

# OS-specific exploits
searchsploit <OS> <VERSION>
```

**Total Enumeration Time: 30-40 minutes per target**

---

## OSCP Exam Tips

### 1. Always Run OS Detection
- OS determines exploit payload selection
- Windows: `.exe`, PowerShell, msfvenom windows payloads
- Linux: ELF binaries, bash scripts, msfvenom linux payloads
- Saves significant time during exploitation

### 2. Manual Banner Grabbing First
- Faster than `-sV` scans
- Works when nmap version detection fails
- Lower detection risk
- Perfect for OSCP exam time constraints

### 3. Never Skip UDP
- SNMP (161/UDP) frequently contains:
  - Usernames and password hashes
  - System configuration details
  - Network topology information
- TFTP (69/UDP) may allow config file downloads
- DNS (53/UDP) zone transfers reveal hosts

### 4. Firewall Detection Shapes Strategy
- No firewall → Aggressive enumeration safe
- Firewall detected → Focus on allowed ports (80, 443)
- Helps avoid wasting time on filtered ports

### 5. TTL Quick Check
```bash
ping -c1 <TARGET>
# TTL ~64 = Linux/Unix
# TTL ~128 = Windows
# TTL ~255 = Cisco
```
Fastest OS indication (1 second)

---

## Technical Notes

### OS Detection Requirements
- **Minimum:** 1 open port + 1 closed port
- **Ideal:** Multiple open/closed ports
- **Failure modes:**
  - "Test conditions non-ideal" = need more ports
  - "No exact OS matches" = use `--osscan-guess`

### UDP Scanning Performance
- UDP is slow by design (OS ICMP rate-limiting)
- Top 100 ports: 5-10 minutes
- Full range: 20-30+ minutes
- **OSCP Strategy:** Target only critical ports (161, 69, 53)

### Firewall Types
- **Stateful:** Tracks connection state, blocks orphan ACK
- **Stateless:** Rule-based only, may allow ACK through
- ACK scan differentiates between these

### Banner Grabbing Services
| Service | Port | Command | Banner Example |
|---------|------|---------|----------------|
| SSH | 22 | `nc <target> 22` | SSH-2.0-OpenSSH_7.9p1 |
| FTP | 21 | `ftp <target>` | 220 ProFTPD 1.3.5 |
| SMTP | 25 | `nc <target> 25` | 220 mail ESMTP Postfix |
| HTTP | 80 | `curl -I http://<target>` | Server: Apache/2.4.41 |
| HTTPS | 443 | `openssl s_client -connect <target>:443` | Certificate details |

---

## Future Enhancements

### Potential Additions
1. **IP Protocol Scan** (`-sO`) - Low OSCP priority
2. **Idle Scan** (`-sI`) - Not applicable to OSCP labs
3. **DNS Brute-force** (`--script dns-brute`) - Domain targets only
4. **Geolocation/WHOIS** - OSINT only, not OSCP relevant

### Not Added (Reasons)
- **vulscan script:** External dependency, unreliable matching
- **Email harvesting:** Not typical in OSCP scenarios
- **Hostname discovery:** Manual `curl -H "Host: hostname"` sufficient
- **Advanced idle scanning:** Requires specific network conditions

---

## References

- **Source Document:** `NMAP_CH03_HOST_INFORMATION_MINING_REPORT.md`
- **Parser:** `/home/kali/OSCP/crack/track/parsers/nmap_xml.py`
- **Profiles:** `/home/kali/OSCP/crack/track/data/scan_profiles.json`
- **Nmap OS Detection:** https://nmap.org/book/man-os-detection.html
- **OSCP Methodology:** Port scan → Service scan → OS detection → Exploit research

---

## Validation

```bash
# Verify JSON structure
cd /home/kali/OSCP/crack
python3 -c "import json; data = json.load(open('track/data/scan_profiles.json')); print(f'Total profiles: {len(data[\"profiles\"])}'); print(f'OS profiles: {len(data[\"os_fingerprinting_profiles\"])}')"

# Expected output:
# Total profiles: 12
# OS profiles: 5
```

---

**Status:** ✅ Implementation Complete
**Next Steps:** Test profiles with real nmap scans, verify CRACK Track integration
