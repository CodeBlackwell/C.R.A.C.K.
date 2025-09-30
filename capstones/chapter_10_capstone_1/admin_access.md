# WordPress Admin Access - SUCCESSFUL

**Date:** 2025-09-30
**Target:** alvida-eatery.org (192.168.229.47)

---

## CREDENTIALS

```
Username: admin
Password: hulabaloo
Email: admin@offsec-lab.com
```

**How Obtained:**
1. SQL Injection (CVE-2021-24762) → Extracted password hash
2. Hashcat cracking → Cracked hash from rockyou.txt
3. Authenticated login → Full admin access

---

## LOGIN DETAILS

**Login URL:** http://alvida-eatery.org/wp-login.php
**Admin Panel:** http://alvida-eatery.org/wp-admin/
**Status:** ✅ **AUTHENTICATED & VERIFIED**

**Session Cookies:**
- `wordpress_5b9329249fde69b10ce28fe10821014c` (wp-admin)
- `wordpress_logged_in_5b9329249fde69b10ce28fe10821014c` (site-wide)
- Session expires: ~48 hours

**Cookies saved to:** `/tmp/wp_cookies.txt`

---

## ADMIN PANEL ACCESS CONFIRMED

```bash
# Test with saved cookies
curl -s -b /tmp/wp_cookies.txt "http://alvida-eatery.org/wp-admin/"
```

**Page Title:** "Dashboard ‹ Alvida Eatery — WordPress"
**Access Level:** Full Administrator

---

## NEXT STEPS - POST-EXPLOITATION

### Option 1: Upload Malicious Plugin (RECOMMENDED)
**Why:** Clean, reversible, easy cleanup
**Steps:**
1. Create malicious plugin with PHP backdoor
2. Upload via Plugins → Add New → Upload Plugin
3. Activate plugin → Code execution achieved
4. Access backdoor for command execution

**Command:**
```bash
# Access plugin upload page
curl -b /tmp/wp_cookies.txt "http://alvida-eatery.org/wp-admin/plugin-install.php?tab=upload"
```

### Option 2: Theme Editor (File Write)
**Why:** Direct file manipulation, no upload needed
**Steps:**
1. Navigate to Appearance → Theme Editor
2. Edit 404.php or functions.php
3. Add PHP webshell code
4. Access modified file for RCE

**Command:**
```bash
# Access theme editor
curl -b /tmp/wp_cookies.txt "http://alvida-eatery.org/wp-admin/theme-editor.php"
```

### Option 3: Media Upload (Webshell)
**Why:** Simple, direct file upload
**Steps:**
1. Upload PHP file as "image"
2. Bypass MIME type checks
3. Access uploaded file directly

**Command:**
```bash
# Access media upload
curl -b /tmp/wp_cookies.txt "http://alvida-eatery.org/wp-admin/media-new.php"
```

### Option 4: Create Backup Admin Account
**Why:** Persistence, maintain access
**Steps:**
1. Users → Add New
2. Create new admin user
3. Use for backup access

**Command:**
```bash
# Access user creation page
curl -b /tmp/wp_cookies.txt "http://alvida-eatery.org/wp-admin/user-new.php"
```

---

## EXPLOITATION TIMELINE

```
1. Initial Enumeration → WordPress 6.0, Perfect Survey 1.5.1
2. SQLi Discovery → CVE-2021-24762 identified
3. GitHub Research → Metasploit module found
4. SQLi Exploitation → Admin hash extracted
5. Hash Cracking → Password: "hulabaloo"
6. Authentication → Admin panel access
7. Post-Exploitation → [NEXT PHASE]
```

---

## RECOMMENDED ATTACK PATH

**Phase 1: Establish RCE**
1. Create PHP webshell plugin
2. Upload and activate
3. Test command execution

**Phase 2: Establish Persistence**
1. Create backup admin account
2. Upload multiple webshells
3. Add SSH keys if possible

**Phase 3: System Enumeration**
1. Check user privileges
2. Find flags/sensitive data
3. Search for privesc vectors

**Phase 4: Privilege Escalation**
1. Enumerate sudo rights
2. Check for kernel exploits
3. Search for SUID binaries
4. Escalate to root

---

**Status:** ✅ Admin access achieved. Ready for RCE phase.
**Next Action:** Create and upload malicious plugin for code execution.
