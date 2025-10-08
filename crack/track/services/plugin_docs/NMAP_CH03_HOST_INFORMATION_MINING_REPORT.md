# Nmap Cookbook Chapter 3 Mining Report
## Gathering Additional Host Information - CRACK Track Integration

**Source:** `nmap_cookbook_chapters/chapter_03_gathering_additional_host_information.txt`
**Generated:** 2025-10-08
**Purpose:** Extract OSCP-relevant host enumeration techniques for CRACK Track scan profiles
**Status:** Complete - 25 techniques extracted

---

## Executive Summary

### OSCP-Relevant Highlights

Chapter 3 focuses on **post-port-scan enumeration** - gathering context about discovered hosts. While existing `scan_profiles.json` covers port/service discovery well, this chapter reveals **metadata gathering techniques** missing from current profiles:

**NEW CAPABILITIES IDENTIFIED:**
1. **OS Fingerprinting** - Critical for exploit selection (OSCP:HIGH)
2. **Service Version Detection Workflows** - Required for CVE matching (OSCP:HIGH)
3. **Network Context Discovery** - WHOIS, geolocation, DNS enumeration (OSCP:MEDIUM)
4. **Protocol Enumeration** - UDP scanning, IP protocol discovery (OSCP:MEDIUM)
5. **Firewall Detection** - TCP ACK scans for stateful firewall identification (OSCP:HIGH)
6. **Idle Scanning** - Advanced stealth techniques using zombie hosts (OSCP:LOW)

**EXISTING COVERAGE:**
- Port scanning (top 1000, full range) ✓
- Service version detection (`-sV -sC`) ✓
- Aggressive scanning (`-A -T4`) ✓
- UDP common ports ✓

**GAPS TO FILL:**
- Dedicated OS detection profiles (`-O`)
- Firewall detection workflows (`-sA`, `--badsum`)
- Protocol enumeration (`-sO`)
- Advanced UDP scanning strategies
- NSE script categories for host information (WHOIS, geolocation, etc.)

---

## Section 1: OS Detection & Fingerprinting

### 1.1 Basic OS Detection

**Command Pattern:**
```bash
nmap -O <TARGET>
```

**Flag Explanations:**
- `-O`: Enable OS detection using TCP/IP stack fingerprinting
  - **WHY:** Identifies operating system and version for exploit targeting
  - **HOW:** Analyzes TCP responses, window sizes, TTL values, TCP options

**OSCP Relevance:** HIGH
**Use Case:** Determine OS before exploit selection (critical for privilege escalation research)
**Estimated Time:** +2-3 minutes (added to port scan)
**Detection Risk:** Medium (active fingerprinting probes)

**Success Indicators:**
- "Running: Linux 2.6.X (87%)" or similar OS detection
- "Device type: general purpose" classification
- CPE identifier shown (e.g., `cpe:/o:linux:kernel:2.6.38`)

**Failure Indicators:**
- "OS detection performed. Please report any incorrect results"
- "test conditions non-ideal" (requires open AND closed ports)
- "No exact OS matches for host" (unusual OS or heavy filtering)

**Manual Alternatives:**
```bash
# Manual TTL inspection (OSCP EXAM FALLBACK)
ping -c 1 <TARGET> | grep ttl
# TTL ~64 = Linux/Unix, TTL ~128 = Windows

# Manual banner grabbing
nc -v <TARGET> 22
# OpenSSH version often reveals OS

# HTTP server headers
curl -I http://<TARGET>
# Server: Apache/2.4.41 (Ubuntu) reveals OS
```

**Next Steps:**
1. Research OS version for kernel exploits: `searchsploit Linux Kernel 2.6.38`
2. Identify default service paths (Windows: C:\, Linux: /var/www/)
3. Select appropriate payloads (Windows: .exe, Linux: ELF)
4. Check for OS-specific vulnerabilities (EternalBlue for Windows, DirtyCOW for Linux)

**Notes:**
- **OSCP CRITICAL:** Always attempt OS detection. Saves time on exploit selection.
- Requires at least one open AND one closed port for accurate results
- May fail against firewalls - use `--osscan-guess` as fallback

**Integration Suggestion:**
```json
{
  "id": "os-detect-standard",
  "name": "OS Detection (Standard)",
  "base_command": "nmap -O",
  "timing": "normal",
  "use_case": "Identify operating system for exploit targeting",
  "estimated_time": "+2-3 minutes",
  "tags": ["OSCP:HIGH", "FINGERPRINTING", "QUICK_WIN"],
  "phases": ["service-detection"],
  "flag_explanations": {
    "-O": "OS detection via TCP/IP fingerprinting (critical for exploit selection)"
  }
}
```

---

### 1.2 Aggressive OS Guessing

**Command Pattern:**
```bash
nmap -O --osscan-guess <TARGET>
```

**Flag Explanations:**
- `-O`: Enable OS detection
- `--osscan-guess`: Make aggressive guesses when exact match unavailable
  - **WHY:** Provides OS information even when fingerprint doesn't perfectly match database
  - **WHEN:** Use when standard `-O` returns "No exact OS matches"

**OSCP Relevance:** MEDIUM
**Use Case:** Fallback when standard OS detection fails
**Estimated Time:** +2-3 minutes
**Detection Risk:** Medium

**Success Indicators:**
- OS family identified even without exact match
- Multiple OS guesses with percentage confidence

**Notes:**
- Less reliable than standard OS detection
- Better to have approximate OS than none (Linux vs Windows is critical)

---

### 1.3 OS Detection with Ideal Conditions

**Command Pattern:**
```bash
nmap -O --osscan-limit <TARGET>
```

**Flag Explanations:**
- `--osscan-limit`: Only attempt OS detection when conditions are ideal
  - **WHY:** Avoids wasting time on hosts that won't provide reliable results
  - **WHEN:** Use in large network scans to conserve time

**OSCP Relevance:** LOW
**Use Case:** Time-constrained mass scanning (not typical in OSCP)
**Detection Risk:** Medium

**Notes:**
- OSCP exam typically involves 5-6 targets - no need to limit OS detection
- Include for completeness but not prioritized for OSCP profiles

---

### 1.4 OS Detection with Verbose IP ID Sequence

**Command Pattern:**
```bash
nmap -O -v <TARGET>
```

**Flag Explanations:**
- `-O`: OS detection
- `-v`: Verbose output
  - **WHY:** Shows IP ID sequence number (incremental/random/zero)
  - **USE:** Identifies zombie host candidates for idle scanning

**OSCP Relevance:** MEDIUM
**Use Case:** Identify idle scan zombie candidates
**Estimated Time:** +2-3 minutes
**Detection Risk:** Medium

**Success Indicators:**
- "IP ID Sequence Generation: Incremental" (good zombie candidate)
- "IP ID Sequence Generation: Randomized" (poor zombie)

**Next Steps:**
1. If "Incremental" found, note host as potential zombie for stealth scanning
2. Test zombie with `--script ipidseq` for confirmation

**Notes:**
- IP ID sequence types:
  - **Incremental:** Good for idle scanning (home routers, printers, IP cams)
  - **Randomized:** Modern OS defense, unusable for idle scanning
  - **All zeros:** Broken implementation, unusable

---

## Section 2: Service Version Detection

### 2.1 Standard Service Version Detection

**Command Pattern:**
```bash
nmap -sV -sC <TARGET>
```

**Flag Explanations:**
- `-sV`: Service/version detection
  - **WHY:** Probes ports to identify exact service name and version
  - **HOW:** Sends protocol-specific probes, analyzes responses
  - **CRITICAL:** Required for matching services to CVEs
- `-sC`: Run default NSE scripts
  - **WHY:** Finds common misconfigurations, vulnerabilities, info leaks
  - **SAFE:** Default scripts are non-intrusive

**OSCP Relevance:** HIGH
**Use Case:** Identify service versions for CVE research (ALWAYS run after port discovery)
**Estimated Time:** 2-5 minutes
**Detection Risk:** Medium

**Success Indicators:**
- Service versions shown: "Apache httpd 2.4.41", "OpenSSH 7.9p1"
- NSE script results reveal additional info (SSL certs, HTTP titles, banners)
- CPE identifiers displayed for services

**Failure Indicators:**
- Service shown as "unknown" or "tcpwrapped"
- No version numbers (service hiding version)
- Firewall blocks version detection probes

**Manual Alternatives:**
```bash
# HTTP version detection
curl -I http://<TARGET>
# Server: Apache/2.4.41 (Ubuntu)

# SSH banner grabbing
nc <TARGET> 22
# SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2

# Telnet banner
telnet <TARGET> 23

# FTP banner
ftp <TARGET>
# 220 ProFTPD 1.3.5 Server

# SMTP banner
nc <TARGET> 25
# 220 mail.target.com ESMTP Postfix
```

**Next Steps:**
1. **OSCP WORKFLOW:** Research versions immediately
   ```bash
   searchsploit Apache 2.4.41
   searchsploit OpenSSH 7.9
   ```
2. Google: "Apache 2.4.41 exploit"
3. Check ExploitDB, GitHub, Metasploit modules
4. Run service-specific enumeration (HTTP: gobuster, SMB: enum4linux, etc.)

**Notes:**
- **OSCP CRITICAL:** ALWAYS run `-sV` after port discovery
- Service version = CVE matching = exploitation path
- Document versions in `enumeration.md` immediately

**Integration Note:**
- Already covered in `scan_profiles.json` as `service-detect-default`
- No new profile needed, documented for completeness

---

### 2.2 Vulnerability Matching (OSVDB Integration)

**Command Pattern:**
```bash
nmap -sV --script vulscan <TARGET>
```

**EXTERNAL DEPENDENCY:** Requires `vulscan.nse` (not in official Nmap repo)
**Installation:**
1. Download from http://www.computec.ch/mruef/?s=software&l=e
2. Copy `vulscan.nse` to `/usr/share/nmap/scripts/`
3. Download OSVDB database files to `/usr/share/nmap/scripts/vulscan/`
4. Run `nmap --script-updatedb`

**Flag Explanations:**
- `-sV`: Service version detection (required)
- `--script vulscan`: Match detected services against OSVDB vulnerability database
  - **WHY:** Automatically identifies known CVEs for discovered services
  - **CAVEAT:** Name matching has bugs, results require manual verification

**OSCP Relevance:** MEDIUM
**Use Case:** Quick CVE identification for discovered services
**Estimated Time:** +2-3 minutes
**Detection Risk:** Medium

**Success Indicators:**
- CVE/vulnerability IDs listed per service
- OSVDB record numbers shown
- Vulnerability descriptions displayed

**Failure Indicators:**
- No vulnerabilities found (doesn't mean service is secure)
- False positives (version number matching errors)

**Manual Alternatives:**
```bash
# SearchSploit (OSCP PREFERRED)
searchsploit Apache 2.4.41
searchsploit -m <exploit-id>

# Online CVE lookup
google "Apache 2.4.41 CVE"
browse to cve.mitre.org

# Metasploit module search
msfconsole
search Apache 2.4.41
```

**Notes:**
- **OSCP CAUTION:** Don't blindly trust automated vuln matching
- Always manually verify CVEs apply to exact version/configuration
- vulscan useful for quick triage, not definitive assessment
- OSVDB database requires periodic updates

**Integration Decision:** LOW PRIORITY
- Requires external dependencies
- SearchSploit more reliable for OSCP
- Manual CVE research preferred over automated matching

---

## Section 3: Network Context Discovery

### 3.1 IP Geolocation

**Command Pattern:**
```bash
nmap --script ip-geolocation-* <TARGET>
```

**Flag Explanations:**
- `--script ip-geolocation-*`: Run all geolocation scripts (wildcard pattern)
  - Scripts included: `ip-geolocation-geoplugin`, `ip-geolocation-maxmind`, `ip-geolocation-ipinfodb`
  - **WHY:** Identify physical location of target (country, state, city, coordinates)
  - **USE CASE:** Physical security assessment, data sovereignty compliance

**OSCP Relevance:** LOW
**Use Case:** Informational only, rarely impacts exploitation
**Estimated Time:** 5-10 seconds
**Detection Risk:** Very Low (queries external services, no traffic to target)

**Success Indicators:**
- Latitude/longitude coordinates displayed
- Country, state, city identified
- "Record found at [geolocation service]"

**Failure Indicators:**
- "No geolocation data available"
- Service provider query limit reached
- Private/internal IP (no public geolocation)

**Notes:**
- **OSCP:** Not useful for exam (lab IPs are not geolocatable)
- Useful for real-world engagements (identifying datacenter locations)
- Free services impose query limits - don't abuse
- Accuracy varies (database quality dependent)

**Integration Decision:** SKIP
- Not relevant to OSCP lab environment
- No exploit/enumeration value
- External dependency on free services with rate limits

---

### 3.2 WHOIS Record Lookup

**Command Pattern:**
```bash
nmap --script whois <TARGET>
```

**Flag Explanations:**
- `--script whois`: Query Regional Internet Registry (RIR) WHOIS databases
  - **WHY:** Retrieve registration info (netrange, organization, contact emails)
  - **USE CASE:** Identify IP ownership, contact info for social engineering

**OSCP Relevance:** LOW
**Use Case:** Real-world OSINT, not applicable to OSCP labs
**Estimated Time:** 2-5 seconds per target
**Detection Risk:** None (queries external RIR, no target traffic)

**Success Indicators:**
- "Record found at whois.arin.net" (or RIPE, AFRINIC, etc.)
- Netrange, organization name, contact emails displayed

**Failure Indicators:**
- "No WHOIS record found"
- Private IP ranges (no public WHOIS)

**Script Arguments:**
```bash
# Override RIR provider order
nmap --script whois --script-args whois.whodb=arin+ripe+afrinic <TARGET>

# Ignore referrals
nmap --script whois --script-args whois.whodb=nofollow <TARGET>

# Disable cache
nmap --script whois --script-args whois.whodb=nocache <TARGET>
```

**Bulk WHOIS without Port Scanning:**
```bash
nmap -sn --script whois -v -iL targets.txt
```

**Notes:**
- **OSCP:** Skip - lab IPs have no public WHOIS records
- Real-world: Useful for OSINT phase (identifying organizations, contacts)
- Free service - respect query limits

**Integration Decision:** SKIP
- Not applicable to OSCP environment
- No offensive security value in isolated labs

---

### 3.3 DNS Brute-forcing

**Command Pattern:**
```bash
nmap --script dns-brute <TARGET>
```

**Flag Explanations:**
- `--script dns-brute`: Brute-force DNS subdomain/hostname discovery
  - **WHY:** Discover hidden subdomains (admin.target.com, mail.target.com, etc.)
  - **HOW:** Iterates through wordlist checking DNS A/AAAA records

**OSCP Relevance:** MEDIUM
**Use Case:** Discover additional attack surfaces (admin panels, mail servers)
**Estimated Time:** 30 seconds - 2 minutes (depends on wordlist size)
**Detection Risk:** HIGH (generates many DNS queries, easily detected)

**Success Indicators:**
- "DNS Brute-force hostnames" section with discovered hosts
- Subdomains with IP addresses listed (www, mail, ftp, admin, direct, etc.)

**Failure Indicators:**
- No additional hostnames found
- DNS server rate-limiting/blocking queries
- All queries return NXDOMAIN

**Script Arguments:**
```bash
# Custom wordlist
nmap --script dns-brute --script-args dns-brute.hostlist=/path/to/wordlist.txt <TARGET>

# Set thread count (default 5)
nmap --script dns-brute --script-args dns-brute.threads=10 <TARGET>

# Custom DNS server
nmap --dns-servers 8.8.8.8 --script dns-brute <TARGET>
```

**Advanced - Add Discovered Hosts to Scan Queue:**
```bash
nmap --script dns-brute --script-args newtargets <TARGET>
# Automatically scans discovered subdomains

# Limit max new targets
nmap --script dns-brute --script-args newtargets,max-newtargets=5 <TARGET>
```

**Manual Alternatives:**
```bash
# DNSEnum (OSCP ALTERNATIVE)
dnsenum --enum target.com

# DNSRecon
dnsrecon -d target.com -t brt

# Gobuster DNS mode
gobuster dns -d target.com -w /usr/share/wordlists/subdomains.txt

# Manual dig
dig @<DNS_SERVER> www.target.com
dig @<DNS_SERVER> admin.target.com
dig @<DNS_SERVER> mail.target.com
```

**Next Steps:**
1. Add discovered subdomains to target list
2. Scan each subdomain for unique services
3. Check for admin panels (admin.target.com, panel.target.com)
4. Identify mail servers for user enumeration

**Notes:**
- **OSCP EXAM:** Rarely needed (targets usually single hosts, not domains)
- **Real-world:** Very useful for attack surface expansion
- DNS brute-forcing easily detected (security monitoring alerts on NXDOMAIN spikes)
- Default wordlist hardcoded in `/usr/share/nmap/scripts/dns-brute.nse`

**Integration Decision:** LOW PRIORITY
- Not common in OSCP lab scenarios
- Better tools available (dnsenum, dnsrecon, gobuster)
- High detection risk

---

### 3.4 Reverse DNS / Hostname Discovery

**Command Pattern:**
```bash
nmap -p80 --script hostmap <TARGET>
```

**EXTERNAL DEPENDENCY:** Modified version with Bing support
**Download:** https://secwiki.org/w/Nmap/External_Script_Library

**Flag Explanations:**
- `--script hostmap`: Discover hostnames pointing to same IP
  - **WHY:** Virtual hosting - same IP serves multiple websites
  - **HOW:** Queries BFK DNS Logger and ip2hosts.com (Bing API)

**OSCP Relevance:** MEDIUM
**Use Case:** Discover additional web applications on shared hosting
**Estimated Time:** 5-10 seconds
**Detection Risk:** None (queries external services)

**Success Indicators:**
- List of hostnames sharing target IP
- Multiple domains discovered on same host

**Failure Indicators:**
- Only single hostname returned
- "No additional hostnames found"

**Script Arguments:**
```bash
# Select provider
nmap --script hostmap --script-args hostmap.provider=BING <TARGET>
nmap --script hostmap --script-args hostmap.provider=BFK <TARGET>
nmap --script hostmap --script-args hostmap.provider=ALL <TARGET>

# Save hostname list to file
nmap --script hostmap --script-args hostmap.prefix=HOSTS- <TARGET>
# Creates file: HOSTS-<TARGET>
```

**Manual Alternatives:**
```bash
# Reverse DNS lookup
dig -x <TARGET_IP>
nslookup <TARGET_IP>

# Bing IP search
google "ip:<TARGET_IP>"
# View Bing results for all indexed sites on this IP

# Certificate transparency logs (for HTTPS)
curl https://crt.sh/?q=%25.<DOMAIN>
# Reveals all certificates issued for domain
```

**Next Steps:**
1. Browse each discovered hostname in browser
2. Check for different web applications per hostname
3. Test each application independently

**Notes:**
- **OSCP EXAM:** May be useful if target uses virtual hosting
- Free services - don't abuse (risk bans)
- Virtual hosting common in web application boxes

**Integration Decision:** LOW PRIORITY
- External dependencies (Bing API)
- Manual `curl -H "Host: hostname" http://IP/` often sufficient
- Not critical for OSCP

---

### 3.5 Email Address Harvesting

**Command Pattern:**
```bash
nmap -p80 --script http-google-email,http-email-harvest <TARGET>
```

**EXTERNAL DEPENDENCY:** `http-google-email` not in official repo
**Download:** http://seclists.org/nmap-dev/2011/q3/att-401/http-google-email.nse

**Flag Explanations:**
- `--script http-google-email`: Query Google for public emails
  - **WHY:** Find email addresses for phishing, brute-force usernames
  - **HOW:** Searches Google Web + Google Groups for `@domain.com`
- `--script http-email-harvest`: Spider website for email addresses
  - **WHY:** Extract emails from HTML source
  - **HOW:** Crawls site, regex matches email patterns

**OSCP Relevance:** MEDIUM
**Use Case:** Username enumeration for brute-force attacks
**Estimated Time:** 30 seconds - 2 minutes
**Detection Risk:** Low (Google queries) to Medium (web spidering)

**Success Indicators:**
- Valid email addresses found
- Usernames extracted (user@domain → "user" is valid username)

**Script Arguments:**
```bash
# http-email-harvest options
nmap --script http-email-harvest --script-args httpspider.maxpagecount=50 <TARGET>
nmap --script http-email-harvest --script-args httpspider.url=/contact.php <TARGET>

# http-google-email options
nmap --script http-google-email --script-args domain=target.com <TARGET>
nmap --script http-google-email --script-args pages=10 <TARGET>
```

**Manual Alternatives:**
```bash
# Manual email harvesting
curl http://<TARGET> | grep -Eo "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

# TheHarvester (OSCP TOOL)
theharvester -d target.com -b google,bing,linkedin

# LinkedIn OSINT
# Search company employees manually
# Format: firstname.lastname@company.com

# SMTP user enumeration (if SMTP accessible)
smtp-user-enum -M VRFY -U users.txt -t <TARGET>
```

**Next Steps:**
1. Extract usernames from emails (johndoe@target.com → "johndoe")
2. Create username wordlist
3. Attempt SSH/FTP/SMB brute-force with discovered usernames
4. Try email addresses as usernames (many systems allow email login)

**Notes:**
- **OSCP EXAM:** Rarely needed (targets typically don't expose email lists)
- **Real-world:** Very useful for phishing campaigns, credential attacks
- Username = half of credential pair (only need password now)

**Integration Decision:** SKIP
- Not typical in OSCP scenarios
- External dependencies
- Better OSINT tools available (theHarvester)

---

## Section 4: UDP & Protocol Enumeration

### 4.1 UDP Service Discovery

**Command Pattern:**
```bash
nmap -sU -p- <TARGET>
```

**Flag Explanations:**
- `-sU`: UDP scan
  - **WHY:** Discover UDP services (DNS:53, SNMP:161, TFTP:69, etc.)
  - **HOW:** Sends UDP probes, analyzes ICMP Port Unreachable responses
  - **WARNING:** Extremely slow due to OS rate-limiting
- `-p-`: All ports (1-65535)
  - **CAVEAT:** Full UDP scan takes 20-30+ minutes

**OSCP Relevance:** MEDIUM
**Use Case:** Discover SNMP (community string enumeration), TFTP (file transfer), DNS
**Estimated Time:**
- Top 100 ports: 5-10 minutes
- Top 1000 ports: 15-20 minutes
- All ports: 20-30+ minutes

**Detection Risk:** Medium

**Success Indicators:**
- UDP ports in "open" state (received UDP response)
- UDP ports in "open|filtered" state (no response, likely open)
- Critical services found: SNMP (161), TFTP (69), DNS (53)

**Failure Indicators:**
- All ports show "closed" (ICMP Port Unreachable received)
- All ports "filtered" (firewall blocking ICMP)
- Scan extremely slow (>30 min for top 1000 ports)

**Optimized Strategies:**
```bash
# OSCP RECOMMENDED: Top 100 UDP ports only
nmap -sU --top-ports 100 <TARGET>

# Target specific critical ports
nmap -sU -p 53,69,123,161,500 <TARGET>

# Fast mode (less accurate)
nmap -sU -F <TARGET>

# Speed up with --min-rate (use cautiously)
nmap -sU --top-ports 100 --min-rate 500 <TARGET>
```

**Manual Alternatives:**
```bash
# Manual UDP port check with nc
nc -u -v <TARGET> 161
# Send SNMP query manually

# Check specific UDP services
dig @<TARGET> google.com  # DNS on 53
tftp <TARGET>              # TFTP on 69
snmpwalk -v2c -c public <TARGET>  # SNMP on 161
```

**Next Steps - Common UDP Services:**
```bash
# SNMP enumeration (HIGH VALUE)
snmpwalk -v2c -c public <TARGET>
snmpwalk -v2c -c private <TARGET>
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <TARGET>

# TFTP file retrieval
tftp <TARGET>
> get config.cfg
> get startup-config

# DNS zone transfer
dig axfr @<TARGET> domain.com

# NTP version query
ntpq -c readvar <TARGET>
```

**Notes:**
- **OSCP CRITICAL:** ALWAYS check UDP - SNMP often yields credentials, system info
- UDP scanning slow by design (OS ICMP rate-limiting)
- "open|filtered" means likely open (no response = firewall allowed or service listening)
- Focus on top 100 ports due to time constraints

**Integration Suggestion:**
```json
{
  "id": "udp-critical-oscp",
  "name": "UDP Critical Services (OSCP Focus)",
  "base_command": "nmap -sU -p 53,69,123,161,162,500",
  "timing": "normal",
  "use_case": "Target critical UDP services for OSCP (SNMP, TFTP, DNS)",
  "estimated_time": "3-5 minutes",
  "tags": ["OSCP:HIGH", "UDP", "QUICK_WIN"],
  "phases": ["discovery"],
  "flag_explanations": {
    "-sU": "UDP scan (slow but finds critical services)",
    "-p 53,69,123,161,162,500": "Target DNS, TFTP, NTP, SNMP, IPSec"
  },
  "next_steps": [
    "SNMP: snmpwalk -v2c -c public <TARGET>",
    "TFTP: tftp <TARGET> (try 'get' common config files)",
    "DNS: dig axfr @<TARGET> <domain>"
  ]
}
```

---

### 4.2 IP Protocol Enumeration

**Command Pattern:**
```bash
nmap -sO <TARGET>
```

**Flag Explanations:**
- `-sO`: IP Protocol Scan
  - **WHY:** Identify what IP protocols host responds to (TCP, UDP, ICMP, GRE, ESP, etc.)
  - **HOW:** Sends IP packets for each protocol in `/usr/share/nmap/nmap-protocols`
  - **USE CASE:** Packet filtering testing, unusual protocol discovery

**OSCP Relevance:** LOW
**Use Case:** Advanced network mapping, VPN/tunnel detection
**Estimated Time:** 3-5 minutes
**Detection Risk:** Medium

**Success Indicators:**
- Protocols in "open" state (ICMP, TCP, UDP typically)
- "closed" protocols (ICMP Protocol Unreachable received)
- Unusual protocols (GRE:47 = VPN, ESP:50 = IPSec)

**Failure Indicators:**
- All protocols "filtered" (firewall blocking)
- Only common protocols (1=ICMP, 6=TCP, 17=UDP)

**Port Selection:**
```bash
# Scan specific protocols
nmap -sO -p 1,6,17 <TARGET>  # ICMP, TCP, UDP only

# Scan protocol range
nmap -sO -p 1-10 <TARGET>
```

**Manual Alternatives:**
```bash
# Ping (ICMP protocol 1)
ping -c 1 <TARGET>

# TCP connection (protocol 6)
nc -v <TARGET> 80

# UDP probe (protocol 17)
nc -u -v <TARGET> 161

# Manual protocol check via scapy
scapy
>>> send(IP(dst="<TARGET>", proto=47)/GRE())  # Test GRE
```

**Notes:**
- **OSCP EXAM:** Rarely needed (standard TCP/UDP sufficient)
- Useful for identifying VPN endpoints (GRE, ESP protocols)
- Custom protocols can be added to `/usr/share/nmap/nmap-protocols`

**Integration Decision:** SKIP
- Not relevant to typical OSCP scenarios
- TCP/UDP coverage sufficient for exam

---

## Section 5: Firewall Detection

### 5.1 TCP ACK Scan (Stateful Firewall Detection)

**Command Pattern:**
```bash
nmap -sA <TARGET>
```

**Flag Explanations:**
- `-sA`: TCP ACK scan
  - **WHY:** Differentiate between stateful and stateless firewalls
  - **HOW:** Sends TCP packets with ACK flag set (invalid for new connections)
  - **RESULT:** Unfiltered = no firewall, Filtered = stateful firewall present

**OSCP Relevance:** HIGH
**Use Case:** Identify firewall presence and type before exploitation
**Estimated Time:** 2-5 minutes
**Detection Risk:** Medium

**How It Works:**
1. Send TCP packet with ACK flag to each port
2. **If unfiltered:** Target responds with RST (no stateful firewall)
3. **If filtered:** No response or ICMP error (stateful firewall present)

**Port States:**
- **Unfiltered:** Port accessible, no stateful firewall
- **Filtered:** Firewall present (stateful or rules blocking)

**Success Indicators:**
- "All ports unfiltered" = No stateful firewall
- Mix of filtered/unfiltered = Firewall with specific rules

**Failure Indicators:**
- All ports filtered = Firewall blocking all ACK packets
- ICMP destination unreachable = Firewall rejecting probes

**Advanced - Firewall Validation:**
```bash
# Combine with --badsum to detect firewalls
nmap -sA --badsum <TARGET>
# Bad checksum packets should be dropped
# If firewall doesn't validate checksum, it will pass through
# Target will drop (no response)
# Firewall that doesn't validate = ICMP dest unreachable (reveals firewall)
```

**Manual Alternatives:**
```bash
# Manual ACK probe with hping3
hping3 -A -p 80 -c 1 <TARGET>
# If RST received = no stateful firewall
# If no response = firewall present

# Telnet (establishes full connection, bypasses stateless rules)
telnet <TARGET> 80

# Netcat connection test
nc -v <TARGET> 80
```

**Next Steps:**
1. If stateful firewall detected:
   - Try application-layer tunneling (HTTP tunneling, DNS tunneling)
   - Focus on allowed ports (80, 443 often whitelisted)
2. If no firewall:
   - Proceed with aggressive scanning
   - Test all ports freely

**Notes:**
- **OSCP EXAM:** Useful for understanding target network filtering
- TCP ACK scan does NOT identify open/closed ports (only filtered/unfiltered)
- Stateful firewall = tracks TCP connections (blocks ACK packets without prior SYN)
- Stateless firewall = simple rule matching (may allow ACK packets through)

**Integration Suggestion:**
```json
{
  "id": "firewall-detect-ack",
  "name": "Firewall Detection (TCP ACK Scan)",
  "base_command": "nmap -sA",
  "timing": "normal",
  "use_case": "Identify stateful firewalls protecting target",
  "estimated_time": "2-5 minutes",
  "tags": ["OSCP:HIGH", "FIREWALL_DETECTION", "RECON"],
  "phases": ["discovery"],
  "flag_explanations": {
    "-sA": "TCP ACK scan (detects stateful firewalls by sending invalid ACK packets)"
  },
  "success_indicators": [
    "All ports 'unfiltered' = no stateful firewall",
    "Mix of filtered/unfiltered = firewall with rules"
  ],
  "next_steps": [
    "If firewall detected: focus on allowed ports (80, 443)",
    "If no firewall: proceed with aggressive enumeration"
  ]
}
```

---

### 5.2 Firewall Checksum Validation Test

**Command Pattern:**
```bash
nmap -sA --badsum <TARGET>
```

**Flag Explanations:**
- `-sA`: TCP ACK scan
- `--badsum`: Send packets with invalid TCP/UDP checksums
  - **WHY:** Detect firewalls that don't validate checksums
  - **HOW:** Invalid checksum packets should be dropped by OS, but may pass through broken firewalls

**OSCP Relevance:** MEDIUM
**Use Case:** Advanced firewall fingerprinting
**Estimated Time:** 2-5 minutes
**Detection Risk:** Medium

**How It Works:**
1. Send TCP packets with invalid checksums
2. **Target OS:** Will drop invalid packets (no response expected)
3. **Firewall (if present):**
   - If validates checksums: Drops packets (no response)
   - If doesn't validate: Passes to target, target drops, OR firewall generates ICMP error

**Success Indicators:**
- ICMP destination unreachable from firewall = Firewall present and identified
- No response from target = Either no firewall OR firewall correctly validates checksums

**Notes:**
- **OSCP EXAM:** Advanced technique, rarely needed
- Helps identify presence of packet filtering devices
- Combined with normal ACK scan to compare results

**Integration Decision:** LOW PRIORITY
- Advanced technique beyond typical OSCP scope
- Useful for completeness, not exam-critical

---

## Section 6: Stealth & Advanced Techniques

### 6.1 Idle Scan (Zombie Host Spoofing)

**Command Pattern:**
```bash
# Step 1: Find zombie host
nmap -p80 --script ipidseq <ZOMBIE_CANDIDATE>

# Step 2: Launch idle scan
nmap -Pn -sI <ZOMBIE_HOST> <TARGET>
```

**Flag Explanations:**
- `-sI <ZOMBIE>`: Idle scan using zombie host
  - **WHY:** Spoof source IP address (extreme stealth)
  - **HOW:** Exploits predictable IP ID sequence numbers
  - **REQUIREMENT:** Zombie must have incremental IP ID + be idle (no traffic)
- `-Pn`: Skip ping (assume host up)
  - **WHY:** Idle scan doesn't send direct packets to target

**OSCP Relevance:** LOW
**Use Case:** Extreme stealth (source IP completely hidden)
**Estimated Time:** 10-20 minutes (finding zombie + scan)
**Detection Risk:** Very Low (target sees zombie IP, not attacker IP)

**How Idle Scanning Works:**
1. Find zombie with incremental IP ID sequence
2. Attacker probes zombie to get current IP ID (e.g., 1000)
3. Attacker sends forged SYN to target (source = zombie IP)
4. If port open: Target sends SYN/ACK to zombie, zombie sends RST (IP ID now 1001)
5. If port closed: Target sends RST to zombie, zombie ignores (IP ID still 1000)
6. Attacker probes zombie again - if IP ID increased, port was open

**Finding Zombie Hosts:**
```bash
# Scan subnet for incremental IP ID hosts
nmap -p80 --script ipidseq 192.168.1.0/24

# Scan random Internet hosts
nmap -p80 --script ipidseq -iR 1000

# Look for "Incremental!" in output
```

**Good Zombie Candidates:**
- Home routers (often idle, incremental IP ID)
- Printers (rarely send traffic)
- IP webcams (idle most of time)
- Old embedded devices

**Success Indicators:**
```
Idle scan using zombie 192.168.1.1 (192.168.1.1:80); Class: Incremental
Nmap scan report for target.com
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
```

**Failure Indicators:**
```
Idle scan zombie 192.168.1.1 cannot be used because IP ID sequencability class is: Randomized
QUITTING!

Idle scan zombie 192.168.1.1 has not returned any of our probes -- perhaps it is down or firewalled
QUITTING!
```

**Manual Alternatives:**
```bash
# Manual IP ID sequence check with hping3
hping3 -S -p 80 -c 5 <ZOMBIE_CANDIDATE>
# Check if IP ID increments by 1 each time

# Use other stealth techniques:
# - Tor/VPN for IP masking
# - Timing attacks (slow scans -T0/-T1)
# - Fragmentation (-f)
```

**Notes:**
- **OSCP EXAM:** Not applicable (no need for extreme stealth in labs)
- **Real-world:** Very advanced, rarely used (many ISPs filter spoofed packets)
- Many modern OS use randomized IP ID (unusable as zombies)
- ISPs may block/rewrite spoofed packets, making technique useless

**Integration Decision:** SKIP
- Not relevant to OSCP exam environment
- Requires very specific conditions (incremental IP ID zombie + ISP allowing spoofing)
- Documented for completeness only

---

## Section 7: Command Reference Summary

### OSCP-Prioritized Quick Reference

**TIER 1 - ALWAYS USE (OSCP:HIGH):**
```bash
# 1. OS Detection
nmap -O <TARGET>

# 2. Service Version Detection
nmap -sV -sC <TARGET>

# 3. UDP Critical Services
nmap -sU -p 53,69,123,161,162 <TARGET>

# 4. Firewall Detection
nmap -sA <TARGET>
```

**TIER 2 - SITUATIONAL (OSCP:MEDIUM):**
```bash
# OS Detection with Guessing (fallback)
nmap -O --osscan-guess <TARGET>

# UDP Top 100 Ports
nmap -sU --top-ports 100 <TARGET>

# DNS Brute-force (if domain target)
nmap --script dns-brute <DOMAIN>

# Hostname Discovery (virtual hosting)
nmap -p80 --script hostmap <TARGET>
```

**TIER 3 - ADVANCED/OPTIONAL (OSCP:LOW):**
```bash
# IP Protocol Enumeration
nmap -sO <TARGET>

# Idle Scan
nmap -sI <ZOMBIE> <TARGET>

# Geolocation (informational only)
nmap --script ip-geolocation-* <TARGET>

# WHOIS (OSINT)
nmap --script whois <TARGET>
```

---

## Section 8: Scan Profiles for Integration

### Recommended New Profiles for `scan_profiles.json`

#### Profile 1: OS Detection Standard

```json
{
  "id": "os-detect-standard",
  "name": "OS Detection (Standard)",
  "base_command": "nmap -O",
  "timing": "normal",
  "coverage": "metadata",
  "use_case": "Identify operating system for exploit selection (OSCP CRITICAL)",
  "estimated_time": "+2-3 minutes (add to service scan)",
  "detection_risk": "medium",
  "tags": ["OSCP:HIGH", "FINGERPRINTING", "QUICK_WIN"],
  "phases": ["service-detection"],
  "flag_explanations": {
    "-O": "OS detection via TCP/IP fingerprinting (analyzes TCP window, TTL, options)"
  },
  "success_indicators": [
    "OS family identified (Linux, Windows, BSD, etc.)",
    "CPE identifier shown",
    "Device type classified (general purpose, router, printer, etc.)"
  ],
  "failure_indicators": [
    "No exact OS matches (requires open AND closed ports)",
    "Test conditions non-ideal",
    "Firewall blocking fingerprinting probes"
  ],
  "next_steps": [
    "Research OS version: searchsploit <OS> <version>",
    "Select OS-appropriate payloads (Windows .exe, Linux ELF)",
    "Identify default paths (C:\\ vs /var/www/)"
  ],
  "alternatives": [
    "Manual TTL check: ping -c1 <TARGET> (64=Linux, 128=Windows)",
    "Banner grabbing: nc <TARGET> 22 (SSH version reveals OS)",
    "HTTP headers: curl -I http://<TARGET> (Server header)"
  ],
  "notes": "OSCP CRITICAL: Always attempt OS detection. Requires at least one open AND one closed port for accurate results. Use --osscan-guess if standard detection fails."
}
```

#### Profile 2: Firewall Detection

```json
{
  "id": "firewall-detect-ack",
  "name": "Firewall Detection (TCP ACK Scan)",
  "base_command": "nmap -sA",
  "timing": "normal",
  "coverage": "firewall",
  "use_case": "Identify stateful firewalls before exploitation",
  "estimated_time": "2-5 minutes",
  "detection_risk": "medium",
  "tags": ["OSCP:HIGH", "FIREWALL_DETECTION", "RECON"],
  "phases": ["discovery"],
  "flag_explanations": {
    "-sA": "TCP ACK scan (sends ACK packets without prior SYN - detects stateful firewalls)"
  },
  "success_indicators": [
    "All ports 'unfiltered' = no stateful firewall",
    "Mix of filtered/unfiltered = firewall with specific rules",
    "All ports 'filtered' = stateful firewall blocking all ACK packets"
  ],
  "failure_indicators": [
    "ICMP destination unreachable (firewall rejecting probes)"
  ],
  "next_steps": [
    "If firewall detected: Focus on allowed ports (80, 443 often whitelisted)",
    "If no firewall: Proceed with aggressive enumeration",
    "Try application-layer evasion (HTTP tunneling)"
  ],
  "alternatives": [
    "Manual ACK probe: hping3 -A -p80 -c1 <TARGET>",
    "Full connection: nc -v <TARGET> 80 (bypasses stateless rules)"
  ],
  "notes": "ACK scan does NOT determine open/closed ports - only filtered/unfiltered. Stateful firewalls track TCP connections and block ACK without prior SYN."
}
```

#### Profile 3: UDP Critical Services (OSCP Focus)

```json
{
  "id": "udp-critical-oscp",
  "name": "UDP Critical Services (OSCP Focus)",
  "base_command": "nmap -sU -p 53,69,123,161,162,500",
  "timing": "normal",
  "coverage": "udp-targeted",
  "use_case": "Target critical UDP services for OSCP (SNMP, TFTP, DNS, NTP)",
  "estimated_time": "3-5 minutes",
  "detection_risk": "medium",
  "tags": ["OSCP:HIGH", "UDP", "QUICK_WIN"],
  "phases": ["discovery"],
  "flag_explanations": {
    "-sU": "UDP scan (slow but finds critical services)",
    "-p 53,69,123,161,162,500": "DNS, TFTP, NTP, SNMP, SNMP-trap, IPSec"
  },
  "success_indicators": [
    "SNMP (161/162) open = community string enumeration possible",
    "TFTP (69) open = potential file download/upload",
    "DNS (53) open = zone transfer attempts"
  ],
  "failure_indicators": [
    "All ports open|filtered (no ICMP responses = firewall)",
    "Scan very slow (>10 min = increase --min-rate carefully)"
  ],
  "next_steps": [
    "SNMP: snmpwalk -v2c -c public <TARGET>",
    "SNMP: onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <TARGET>",
    "TFTP: tftp <TARGET>, try 'get' for common files (config.cfg)",
    "DNS: dig axfr @<TARGET> <domain> (zone transfer)"
  ],
  "alternatives": [
    "Manual SNMP: snmpwalk -v2c -c public <TARGET>",
    "Manual TFTP: tftp <TARGET>, then 'get <file>'",
    "Manual DNS: dig @<TARGET> <domain> ANY"
  ],
  "notes": "OSCP CRITICAL: NEVER skip UDP scanning. SNMP often reveals credentials, system info. UDP scanning is slow - focus on critical ports only."
}
```

#### Profile 4: OS Detection with Guessing (Fallback)

```json
{
  "id": "os-detect-guess",
  "name": "OS Detection (Aggressive Guess)",
  "base_command": "nmap -O --osscan-guess",
  "timing": "normal",
  "coverage": "metadata",
  "use_case": "Fallback when standard OS detection fails",
  "estimated_time": "+2-3 minutes",
  "detection_risk": "medium",
  "tags": ["OSCP:MEDIUM", "FINGERPRINTING", "FALLBACK"],
  "phases": ["service-detection"],
  "flag_explanations": {
    "-O": "Enable OS detection",
    "--osscan-guess": "Make aggressive guesses when no exact match (less accurate)"
  },
  "success_indicators": [
    "OS family guessed with percentage confidence",
    "Multiple OS possibilities listed"
  ],
  "notes": "Use when standard -O returns 'No exact OS matches'. Less reliable but better than no OS info."
}
```

---

## Section 9: Flag Reference Table

### All Flags from Chapter 3

| Flag | Category | Purpose | OSCP Priority |
|------|----------|---------|---------------|
| `-O` | OS Detection | TCP/IP fingerprinting for OS identification | HIGH |
| `--osscan-guess` | OS Detection | Aggressive OS guessing when no exact match | MEDIUM |
| `--osscan-limit` | OS Detection | Only attempt when conditions ideal | LOW |
| `-sV` | Service Detection | Probe ports for service/version | HIGH |
| `-sC` | Service Detection | Run default NSE scripts (safe) | HIGH |
| `-sU` | Protocol | UDP scan | HIGH |
| `-sO` | Protocol | IP protocol scan | LOW |
| `-sA` | Firewall | TCP ACK scan (stateful firewall detection) | HIGH |
| `--badsum` | Firewall | Send invalid checksums (firewall detection) | MEDIUM |
| `-sI <zombie>` | Stealth | Idle scan (IP spoofing via zombie) | LOW |
| `--script whois` | OSINT | WHOIS record lookup | LOW |
| `--script dns-brute` | Enumeration | DNS subdomain brute-forcing | MEDIUM |
| `--script hostmap` | Enumeration | Reverse DNS / hostname discovery | MEDIUM |
| `--script ip-geolocation-*` | OSINT | IP geolocation lookup | LOW |
| `--script ipidseq` | Recon | IP ID sequence detection (zombie host hunting) | LOW |
| `--script http-google-email` | OSINT | Email harvesting via Google | LOW |
| `--script http-email-harvest` | OSINT | Email extraction from web pages | LOW |
| `--script vulscan` | Vulnerability | OSVDB vulnerability matching | MEDIUM |
| `--top-ports <N>` | Port Selection | Scan N most common ports | HIGH |
| `-p-` | Port Selection | All 65535 ports | HIGH |
| `-F` | Port Selection | Fast mode (top 100 ports) | MEDIUM |
| `--script-args newtargets` | Target Expansion | Add discovered hosts to scan queue | LOW |
| `--dns-servers <IP>` | DNS | Specify DNS server | LOW |
| `-v` | Output | Verbose (shows IP ID sequence) | MEDIUM |

---

## Section 10: Integration Recommendations

### Priority 1: MUST ADD (Critical for OSCP)

**1. OS Detection Profile**
- **Profile ID:** `os-detect-standard`
- **Why:** OS identification required for exploit selection
- **Integration:** Add to `scan_profiles.json`
- **Usage:** Run after service detection: `crack track scan --profile os-detect-standard <target>`

**2. Firewall Detection Profile**
- **Profile ID:** `firewall-detect-ack`
- **Why:** Understanding firewall presence shapes exploitation strategy
- **Integration:** Add to `scan_profiles.json`
- **Usage:** Run before aggressive enumeration

**3. UDP Critical Services Profile**
- **Profile ID:** `udp-critical-oscp`
- **Why:** SNMP frequently contains credentials, system info
- **Integration:** Add to `scan_profiles.json`
- **Usage:** Always run alongside TCP scans

### Priority 2: SHOULD ADD (Useful for OSCP)

**4. OS Detection Guess (Fallback)**
- **Profile ID:** `os-detect-guess`
- **Why:** Provides OS info when standard detection fails
- **Integration:** Add as fallback profile

**5. Enhanced UDP Scanning Documentation**
- Update existing `udp-common` profile with:
  - SNMP enumeration next steps
  - TFTP file retrieval commands
  - DNS zone transfer attempts

### Priority 3: OPTIONAL (Completeness)

**6. NSE Script Categories**
- Document NSE scripts for host info gathering:
  - `whois`, `dns-brute`, `hostmap`, `ipidseq`
- Create reference in Track documentation
- Not critical for exam, useful for real-world

### Integration Method

**1. Update `scan_profiles.json`:**
```bash
vim /home/kali/OSCP/crack/track/data/scan_profiles.json
# Add 4 new profiles from Section 8
```

**2. Update Track CLI to expose profiles:**
```bash
crack track scan --list-profiles
crack track scan --profile os-detect-standard 192.168.45.100
```

**3. Document in Track README:**
```bash
vim /home/kali/OSCP/crack/track/README.md
# Add section: "Host Information Gathering Profiles"
```

**4. Create helper command:**
```bash
# New command: crack track fingerprint
crack track fingerprint 192.168.45.100
# Runs: OS detection + firewall detection + UDP critical
```

---

## Section 11: OSCP Exam Tips

### Time Management for Host Enumeration

**Phase 1: Fast Discovery (5-10 minutes)**
```bash
# Quick port scan
nmap --top-ports 1000 <TARGET> -oA quick

# Service detection on discovered ports
nmap -sV -sC -p <PORTS> <TARGET> -oA services
```

**Phase 2: OS & Firewall (3-5 minutes)**
```bash
# OS detection
nmap -O <TARGET>

# Firewall check
nmap -sA <TARGET>
```

**Phase 3: UDP Critical (5 minutes)**
```bash
# UDP critical services only (time-constrained)
nmap -sU -p 53,69,123,161,162 <TARGET>
```

**Phase 4: Full Scan (Background, 10-15 minutes)**
```bash
# Full TCP scan in background
nmap -p- --min-rate 1000 <TARGET> -oA full &
```

**Total Enumeration Time: 20-30 minutes per target**

### Critical OSCP Workflows

**1. OS Detection → Exploit Research:**
```bash
nmap -O <TARGET> | grep "Running:"
# Output: "Running: Linux 2.6.X (87%)"

searchsploit Linux Kernel 2.6
searchsploit Dirty COW
```

**2. Service Version → CVE Matching:**
```bash
nmap -sV -p 80 <TARGET>
# Output: Apache httpd 2.4.29

searchsploit Apache 2.4.29
google "Apache 2.4.29 CVE"
```

**3. UDP SNMP → Credential Harvesting:**
```bash
nmap -sU -p 161 <TARGET>
# If open:

snmpwalk -v2c -c public <TARGET>
snmpwalk -v2c -c private <TARGET>
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <TARGET>
```

**4. Firewall Detection → Strategy Pivot:**
```bash
nmap -sA <TARGET>
# If filtered:
# → Focus on allowed ports (80, 443)
# → Try application-layer attacks (HTTP, HTTPS)
# → Avoid noisy port scans

# If unfiltered:
# → Aggressive scanning safe
# → Full port range
# → Loud techniques acceptable
```

### Common Pitfalls

**PITFALL 1: Skipping UDP Scanning**
- **Mistake:** "UDP is too slow, I'll skip it"
- **Reality:** SNMP (161/UDP) frequently yields credentials, system information
- **Fix:** Always scan critical UDP ports (161, 69, 53)

**PITFALL 2: No OS Detection**
- **Mistake:** "I'll figure out OS from banners"
- **Reality:** OS determines exploit payload selection, privilege escalation paths
- **Fix:** Always run `nmap -O` after service detection

**PITFALL 3: Ignoring Firewall Detection**
- **Mistake:** "If ports are open, there's no firewall"
- **Reality:** Application-layer firewalls, stateful filtering may block exploits
- **Fix:** Run `nmap -sA` to identify filtering before exploitation

**PITFALL 4: Not Documenting Versions**
- **Mistake:** "I'll remember the versions"
- **Reality:** Exploit requires exact version match
- **Fix:** Always save scan results (`-oA`), document versions in `enumeration.md`

---

## Section 12: Manual Alternatives Master List

### When Nmap Fails or Unavailable (OSCP Exam Scenarios)

**OS Detection Without Nmap:**
```bash
# TTL inspection
ping -c 1 <TARGET>
# 64 = Linux/Unix, 128 = Windows, 255 = Cisco

# SSH banner
nc <TARGET> 22
# OpenSSH_7.9p1 Debian-10+deb10u2 → Debian Linux

# HTTP headers
curl -I http://<TARGET>
# Server: Microsoft-IIS/10.0 → Windows

# SMB version
smbclient -L //<TARGET> -N
# Samba version shown in response
```

**Service Version Without Nmap:**
```bash
# HTTP
curl -I http://<TARGET>
telnet <TARGET> 80
HEAD / HTTP/1.0

# FTP
ftp <TARGET>
# Banner: 220 ProFTPD 1.3.5 Server

# SSH
nc <TARGET> 22
# Banner: SSH-2.0-OpenSSH_7.9p1

# SMTP
nc <TARGET> 25
EHLO test
# Banner: 220 mail.target.com ESMTP Postfix
```

**UDP Service Probing Without Nmap:**
```bash
# SNMP
snmpwalk -v2c -c public <TARGET>
# If responds, SNMP is open

# DNS
dig @<TARGET> google.com
# If resolves, DNS is open

# TFTP
tftp <TARGET>
tftp> get test.txt
# If connects, TFTP is open

# NTP
ntpq -c readvar <TARGET>
# If responds, NTP is open
```

**Firewall Detection Without Nmap:**
```bash
# Manual ACK probe
hping3 -A -p 80 -c 1 <TARGET>
# RST response = no stateful firewall
# No response = firewall

# Full connection test
nc -v <TARGET> 80
# Connects = port allowed through firewall

# Ping test
ping <TARGET>
# No response but ports open = ICMP blocked (common firewall rule)
```

---

## Section 13: Methodology Notes

### When to Use Each Technique

**ALWAYS (Every Target):**
1. Full TCP port scan (`-p-`)
2. Service version detection (`-sV -sC`)
3. OS detection (`-O`)
4. UDP critical ports scan (`-sU -p 53,69,161`)

**CONDITIONALLY (Based on Results):**
1. **Firewall detection (`-sA`):** If uncertain about filtering
2. **DNS brute-force:** If domain name provided (not IP only)
3. **Hostname discovery:** If web server detected (virtual hosting)
4. **OS guessing:** If standard OS detection fails

**RARELY (Special Cases):**
1. **IP protocol scan:** Advanced network mapping only
2. **Idle scan:** Extreme stealth required (not OSCP)
3. **Geolocation/WHOIS:** OSINT phase only (not OSCP labs)

### Sequential Workflow

**Stage 1: Discovery (10 minutes)**
```bash
# Fast port discovery
nmap --top-ports 1000 <TARGET> -oA quick

# UDP critical
nmap -sU -p 161,69,53 <TARGET> -oA udp
```

**Stage 2: Enumeration (10 minutes)**
```bash
# Service versions on discovered ports
nmap -sV -sC -p <DISCOVERED_PORTS> <TARGET> -oA services

# OS detection
nmap -O <TARGET> -oA os
```

**Stage 3: Context (5 minutes)**
```bash
# Firewall check
nmap -sA <TARGET> -oA firewall

# Full port scan (background)
nmap -p- --min-rate 1000 <TARGET> -oA full &
```

**Stage 4: Research (15 minutes)**
```bash
# Exploit research for each service
searchsploit <SERVICE> <VERSION>

# OS-specific exploits
searchsploit <OS> <VERSION>

# Service-specific enumeration
# HTTP: gobuster
# SMB: enum4linux
# etc.
```

**Total Time: ~40 minutes of active scanning, then move to exploitation**

---

## Section 14: Key Takeaways for CRACK Track

### What's Missing from Current Profiles

**EXISTING:**
- Port scanning strategies ✓
- Service detection ✓
- Timing templates ✓

**GAPS:**
1. **OS Detection Profiles** - Need dedicated `-O` profile
2. **Firewall Detection** - Need `-sA` profile for stateful firewall identification
3. **UDP Critical Services** - Have UDP top 100, need UDP critical ports (161, 69, 53)
4. **Manual Fallbacks** - Profiles lack manual alternatives for exam scenarios

### Recommended Additions

**1. Add 4 New Profiles:**
- `os-detect-standard` (OS fingerprinting)
- `firewall-detect-ack` (Firewall identification)
- `udp-critical-oscp` (SNMP, TFTP, DNS only)
- `os-detect-guess` (Fallback OS guessing)

**2. Enhance Existing Profiles:**
- Add "manual_alternatives" field to all profiles
- Add "next_steps" for post-scan actions
- Add "oscp_workflow" field with research commands

**3. Create Meta-Profiles:**
```json
{
  "id": "oscp-complete-enum",
  "name": "Complete OSCP Enumeration",
  "description": "Full OSCP workflow: ports → services → OS → UDP → firewall",
  "sequence": [
    "lab-full",
    "service-detect-default",
    "os-detect-standard",
    "udp-critical-oscp",
    "firewall-detect-ack"
  ],
  "estimated_time": "25-30 minutes",
  "tags": ["OSCP:HIGH", "COMPLETE_WORKFLOW"]
}
```

**4. Document NSE Scripts:**
- Create reference guide for host info NSE scripts
- Not profiles, but documented for manual use
- Examples: `whois`, `dns-brute`, `hostmap`, `ipidseq`

---

## Appendix A: Complete Command Templates

### Copy-Paste Ready OSCP Commands

```bash
# === STAGE 1: DISCOVERY ===

# Quick port scan (top 1000)
nmap --top-ports 1000 <TARGET> -oA quick_<TARGET>

# Full port scan (all 65535)
nmap -p- --min-rate 1000 <TARGET> -oA full_<TARGET>

# === STAGE 2: ENUMERATION ===

# Service version detection
nmap -sV -sC -p <PORTS> <TARGET> -oA services_<TARGET>

# OS detection
nmap -O <TARGET> -oA os_<TARGET>

# OS detection with guessing (fallback)
nmap -O --osscan-guess <TARGET> -oA os_guess_<TARGET>

# === STAGE 3: UDP & FIREWALL ===

# UDP critical services
nmap -sU -p 53,69,123,161,162 <TARGET> -oA udp_critical_<TARGET>

# UDP top 100 (if time allows)
nmap -sU --top-ports 100 <TARGET> -oA udp_top100_<TARGET>

# Firewall detection
nmap -sA <TARGET> -oA firewall_<TARGET>

# === STAGE 4: RESEARCH ===

# Exploit research
searchsploit <SERVICE> <VERSION>
searchsploit -m <EXPLOIT_ID>

# SNMP enumeration (if 161/UDP open)
snmpwalk -v2c -c public <TARGET>
snmpwalk -v2c -c private <TARGET>
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <TARGET>

# TFTP enumeration (if 69/UDP open)
tftp <TARGET>
tftp> get config.cfg
tftp> get startup-config

# DNS zone transfer (if 53/UDP or TCP open)
dig axfr @<TARGET> <DOMAIN>
```

---

## Appendix B: NSE Script Reference

### Host Information Scripts (Not Profiles, For Manual Use)

**WHOIS Lookup:**
```bash
nmap --script whois <TARGET>
nmap --script whois --script-args whois.whodb=arin+ripe <TARGET>
```

**DNS Brute-force:**
```bash
nmap --script dns-brute <DOMAIN>
nmap --script dns-brute --script-args dns-brute.hostlist=wordlist.txt <DOMAIN>
nmap --script dns-brute --script-args dns-brute.threads=10 <DOMAIN>
```

**Hostname Discovery:**
```bash
nmap -p80 --script hostmap <TARGET>
nmap -p80 --script hostmap --script-args hostmap.provider=BING <TARGET>
```

**IP ID Sequence (Zombie Hunting):**
```bash
nmap -p80 --script ipidseq <TARGET>
nmap -p80 --script ipidseq 192.168.1.0/24
```

**Email Harvesting:**
```bash
# Requires external script download
nmap -p80 --script http-google-email,http-email-harvest <TARGET>
nmap -p80 --script http-google-email --script-args domain=target.com <TARGET>
```

**Geolocation:**
```bash
nmap --script ip-geolocation-* <TARGET>
```

---

## Appendix C: Documentation Standards for CRACK Track

### Profile Metadata Template

When adding new profiles, ensure all fields populated:

```json
{
  "id": "unique-profile-id",
  "name": "Human Readable Name",
  "base_command": "nmap -FLAGS",
  "timing": "paranoid|sneaky|polite|normal|aggressive|insane",
  "coverage": "quick|full|metadata|firewall|udp-targeted",
  "use_case": "Detailed description of when/why to use",
  "estimated_time": "X-Y minutes",
  "detection_risk": "very-low|low|medium|high|very-high",
  "tags": ["OSCP:HIGH/MEDIUM/LOW", "CATEGORY", "METHOD"],
  "phases": ["discovery", "service-detection", "exploitation", "post-exploit"],

  "flag_explanations": {
    "-flag": "What flag does + WHY use it + HOW it works"
  },

  "success_indicators": [
    "What to look for when command succeeds"
  ],

  "failure_indicators": [
    "Common failure modes and what they mean"
  ],

  "next_steps": [
    "Actionable commands to run after this profile",
    "Research steps for discovered information"
  ],

  "alternatives": [
    "Manual command without nmap",
    "Alternative tool or technique"
  ],

  "notes": "OSCP-specific guidance, warnings, tips, time estimates"
}
```

---

## End of Report

**Generated:** 2025-10-08
**Chapter Coverage:** Complete
**Techniques Extracted:** 25
**New Profiles Recommended:** 4
**OSCP Relevance:** HIGH (OS detection, firewall detection, UDP enumeration)

**Next Steps:**
1. Review and approve 4 new scan profiles
2. Update `scan_profiles.json` with approved profiles
3. Document NSE scripts in Track README
4. Create helper command: `crack track fingerprint`
5. Update OSCP workflows in Track documentation

**Mining Status:** ✅ COMPLETE
