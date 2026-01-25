# Command ID Mapping Analysis - Usage Writeup Validation

**Date**: 2025-11-19
**Purpose**: Minimize duplication by mapping missing command IDs to existing commands
**Total Missing**: 42 command IDs
**Can Map to Existing**: 7 confirmed
**Need to Create**: 35 commands

---

## ✅ CONFIRMED MAPPINGS - Update Usage.json

These existing commands can be used directly (verified in database):

| Missing ID | Existing ID | Action |
|------------|-------------|--------|
| `nmap-service-version` | `nmap-service-scan` | Replace in Usage.json |
| `netcat-listener` | `nc-listener` | Replace (or `rlwrap-nc-listener` for better shell) |
| `chmod-set-permissions` | `chmod-numeric-permissions` | Replace |
| `touch-create-file` | `touch-file` | Replace |
| `ln-create-symlink` | `ln-symbolic` | Replace |
| `sqli-manual-test-quote` | `sqli-manual-test` | Replace |
| `sudo-list-permissions` | `check-sudo-privs` | Replace |

**Impact**: Reduces missing commands from 42 → 35

---

## ❌ NEED TO CREATE (35 Commands)

### Priority 1: High Priority (17 commands)

#### SQLMap Suite (5 commands) - `web/sql-injection.json`
1. **`sqlmap-from-request`** - Run SQLMap from Burp request file
   ```
   sqlmap -r <REQUEST_FILE> -p <PARAMETER> --batch
   ```

2. **`sqlmap-from-request-level3`** - SQLMap with increased test depth
   ```
   sqlmap -r <REQUEST_FILE> -p <PARAMETER> --batch --level 3
   ```

3. **`sqlmap-enumerate-databases`** - Enumerate all databases
   ```
   sqlmap -r <REQUEST_FILE> --dbs --batch
   ```

4. **`sqlmap-enumerate-tables`** - Enumerate tables in database
   ```
   sqlmap -r <REQUEST_FILE> -D <DATABASE> --tables --batch
   ```

5. **`sqlmap-dump-table`** - Dump specific table
   ```
   sqlmap -r <REQUEST_FILE> -D <DATABASE> -T <TABLE> --dump --batch
   ```

#### Shell & Post-Exploitation (5 commands)
6. **`pty-spawn-script`** - Spawn interactive PTY shell
   `exploitation/shells.json` or `post-exploit/linux-shell-stabilization.json`
   ```
   script /dev/null -c bash
   # OR: python3 -c 'import pty;pty.spawn("/bin/bash")'
   ```

7. **`revshells-payload-generate`** - Generate reverse shell payload
   `exploitation/reverse-shells.json`
   ```
   # Manual or reference to revshells.com
   ```

8. **`linux-enumerate-users`** - Enumerate system users
   `post-exploit/linux-enumeration.json`
   ```
   cat /etc/passwd | grep -v nologin | cut -d: -f1
   ```

9. **`linux-enumerate-home-directory`** - List home directories
   `post-exploit/linux-enumeration.json`
   ```
   ls -la /home/
   ```

10. **`linux-check-directory-permissions`** - Check directory permissions
    `post-exploit/linux-enumeration.json`
    ```
    ls -ld <DIRECTORY>
    ```

#### SSH Operations (4 commands)
11. **`ssh-connect-password`** - SSH with password authentication
    `pivoting/ssh-tunneling.json` or `exploitation/lateral-movement.json`
    ```
    ssh <USER>@<TARGET>
    ```

12. **`ssh-key-authentication`** - SSH with private key
    `pivoting/ssh-tunneling.json`
    ```
    ssh -i <KEY_FILE> <USER>@<TARGET>
    ```

13. **`ssh-key-format`** - Fix SSH key format/permissions
    `utilities/ssh-utilities.json`
    ```
    chmod 600 <KEY_FILE>
    ```

14. **`extract-ssh-key`** - Extract SSH private key from file
    `post-exploit/credential-harvesting.json`
    ```
    cat <FILE> | grep -A 20 "BEGIN.*PRIVATE KEY"
    ```

#### Password Cracking
15. **`john-crack-bcrypt`** - Crack bcrypt hashes with John
    `enumeration/password-attacks.json`
    ```
    john --format=bcrypt <HASH_FILE> --wordlist=<WORDLIST>
    ```

#### File Operations
16. **`file-identify-type`** - Identify file type
    `utilities/file-operations.json`
    ```
    file <FILE>
    ```

17. **`su-user-switch`** - Switch to another user
    `post-exploit/lateral-movement.json`
    ```
    su - <USERNAME>
    ```

---

### Priority 2: Web Exploitation (9 commands)

#### Burp Suite (2 commands) - `web/burp-suite.json`
18. **`burpsuite-intercept-request`** - Intercept HTTP request in Burp
19. **`burpsuite-modify-upload`** - Modify file upload in Burp Proxy

#### Web Enumeration & Exploitation (7 commands) - `web/web-enumeration.json`
20. **`web-manual-enumeration`** - Manual web directory/file enumeration
21. **`web-login-admin-panel`** - Login to admin panel
22. **`web-version-enumeration`** - Enumerate web application version
23. **`user-registration-test`** - Test user registration functionality
24. **`web-access-uploaded-file`** - Access uploaded file/webshell
25. **`webshell-execute-revshell`** - Execute reverse shell from webshell
26. **`create-php-webshell`** - Create PHP webshell file

---

### Priority 3: Machine-Specific / Low Priority (9 commands)

#### Usage Machine Specific
27. **`7zip-listfile-research`** - Research 7zip listfile symlink vulnerability
    `post-exploit/research.json` (or note inline in writeup)

28. **`sudo-execute-usage-management`** - Execute /opt/usage_management/loader
    `post-exploit/privilege-escalation.json` (machine-specific)

#### File Operations
29. **`file-rename-extension`** - Rename file extension
    `utilities/file-operations.json`
    ```
    mv <FILE>.jpg <FILE>.php.jpg
    ```

#### Flag Capture (milestones, not commands)
30. **`capture-user-flag`** - Read user.txt flag
    ```
    cat /home/<USER>/user.txt
    ```

31. **`capture-root-flag`** - Read root.txt flag
    ```
    cat /root/root.txt
    ```

#### Too Basic (reconsider storing)
32. **`cat-read-file`** - Read file contents
    ```
    cat <FILE>
    ```
    *Note: Too basic to warrant dedicated command. Document inline.*

33. **`cd-change-directory`** - Change directory
    ```
    cd <DIRECTORY>
    ```
    *Note: Too basic to warrant dedicated command. Document inline.*

34. **`hosts-file-add-entry`** - Add entry to /etc/hosts
    `utilities/system-utilities.json`
    ```
    echo "<IP> <HOSTNAME>" | sudo tee -a /etc/hosts
    ```

35. **`nmap-quick-scan`** - Quick nmap port scan
    `enumeration/nmap.json` (if doesn't exist)
    ```
    nmap -p- --min-rate=1000 -T4 <TARGET>
    ```

---

## 📝 RECOMMENDED ACTION PLAN

### Phase 1: Quick Wins (5 minutes)
**Update Usage.json** - Replace 7 command IDs with existing alternatives:
```bash
sed -i 's/"nmap-service-version"/"nmap-service-scan"/g' db/data/writeups/hackthebox/Usage/Usage.json
sed -i 's/"netcat-listener"/"nc-listener"/g' db/data/writeups/hackthebox/Usage/Usage.json
sed -i 's/"chmod-set-permissions"/"chmod-numeric-permissions"/g' db/data/writeups/hackthebox/Usage/Usage.json
sed -i 's/"touch-create-file"/"touch-file"/g' db/data/writeups/hackthebox/Usage/Usage.json
sed -i 's/"ln-create-symlink"/"ln-symbolic"/g' db/data/writeups/hackthebox/Usage/Usage.json
sed -i 's/"sqli-manual-test-quote"/"sqli-manual-test"/g' db/data/writeups/hackthebox/Usage/Usage.json
sed -i 's/"sudo-list-permissions"/"check-sudo-privs"/g' db/data/writeups/hackthebox/Usage/Usage.json
```

**Re-validate** - Should reduce errors from 42 to 35.

---

### Phase 2: Priority Creates (SQLMap + Shell + SSH)
Create 14 high-priority commands in this order:

1. **SQLMap suite** (5 commands) → `reference/data/commands/web/sql-injection.json`
2. **Shell utilities** (3 commands) → `exploitation/shells.json`
3. **SSH operations** (4 commands) → `pivoting/ssh-operations.json`
4. **Password cracking** (1 command) → Add to existing john commands
5. **File operations** (2 commands) → `utilities/file-operations.json`

**Re-validate** - Should reduce to ~21 errors.

---

### Phase 3: Web Exploitation (9 commands)
Create Burp Suite and web enumeration commands.

**Re-validate** - Should reduce to ~12 errors.

---

### Phase 4: Cleanup (12 remaining)
- Machine-specific commands (2)
- Very basic utilities (3) - Consider documenting inline instead
- Flag capture (2) - Consider removing from writeup commands_used
- Hosts file, nmap-quick (2)

---

## 🎯 FINAL STATE ESTIMATE

After all phases:
- **0-5 validation errors** (machine-specific or intentionally omitted)
- **~30 new commands** created with full educational metadata
- **Usage.json validated** and ready for Neo4j import
- **Reusable command library** for future writeups

---

## 📊 VALIDATION CHECKPOINTS

```bash
# After Phase 1 (mappings)
python3 db/scripts/validate_writeups.py db/data/writeups/hackthebox/Usage/Usage.json
# Expected: ~35 errors

# After Phase 2 (priority creates)
python3 db/scripts/validate_writeups.py db/data/writeups/hackthebox/Usage/Usage.json
# Expected: ~21 errors

# After Phase 3 (web exploitation)
python3 db/scripts/validate_writeups.py db/data/writeups/hackthebox/Usage/Usage.json
# Expected: ~12 errors

# After Phase 4 (cleanup)
python3 db/scripts/validate_writeups.py db/data/writeups/hackthebox/Usage/Usage.json
# Expected: 0-5 errors
```

---

## ✅ EXISTING COMMANDS CONFIRMED

The following commands **already exist** in the database (no action needed):

- `strings-binary-analysis` ✅
- `nmap-service-scan` ✅
- `nc-listener`, `nc-listener-tcp`, `rlwrap-nc-listener` ✅
- `chmod-numeric-permissions` ✅
- `touch-file` ✅
- `ln-symbolic` ✅
- `sqli-manual-test` ✅
- `check-sudo-privs` ✅

---

**Generated**: 2025-11-19
**Database**: 1160 existing unique command IDs
**Target**: Minimize duplication, maximize reuse
