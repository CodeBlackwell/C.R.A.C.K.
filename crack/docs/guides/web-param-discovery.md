# Parameter Discovery Tool - Usage Guide

## Purpose
Intelligent parameter discovery through response differential analysis. Finds hidden GET/POST parameters that web applications accept but don't advertise.

## Core Features
- **Baseline establishment**: Creates stable response fingerprint for comparison
- **Smart payload selection**: Context-aware payloads based on parameter names
- **Multi-factor detection**: Size, status, timing, content, error patterns
- **Confidence scoring**: Prioritizes findings based on response changes
- **Decision tree output**: Actionable next steps based on discoveries

## Installation
```bash
# No additional dependencies required - runs on default Kali
python3 param_discover.py --help
```

## Usage Examples

### Standalone Usage
```bash
# Basic GET parameter discovery
python3 param_discover.py http://192.168.45.100/page.php

# POST parameter discovery
python3 param_discover.py http://192.168.45.100/api/endpoint -m POST

# With custom wordlist
python3 param_discover.py http://192.168.45.100/admin.php -w custom_params.txt

# Verbose mode (shows all tests)
python3 param_discover.py http://192.168.45.100/index.php -v
```

### Pipeline Usage
```bash
# Chain with html_enum.py for endpoint discovery
python3 html_enum.py http://192.168.45.100 | python3 param_discover.py

# Test all PHP files found
find /var/www -name "*.php" | sed 's|^/var/www|http://192.168.45.100|' | python3 param_discover.py

# Test endpoints from previous recon
cat endpoints.txt | python3 param_discover.py -m POST
```

## How It Works

### 1. Baseline Establishment
```
[*] Establishing baseline response...
  Status: 200 | Size: 5432 bytes
  Response time: 0.15s | Lines: 127
```
Takes 3 samples, uses median values for stability.

### 2. Parameter Testing
```
Command: GET http://target.com/page.php?PARAM=PAYLOAD
Progress: 45/76 [debug              ]
```
Tests each parameter with context-aware payloads:
- Numeric params (id, page): 1, 999999, -1, 0
- Boolean params (debug, admin): 1, true, yes, on
- Path params (file, include): index.php, ../, /etc/passwd
- Command params (cmd, exec): whoami, id, echo test

### 3. Change Detection
Monitors multiple factors:
- **Status code changes**: 200→404, 200→500
- **Size differences**: >50 bytes difference
- **Response time**: >50% change
- **Error patterns**: MySQL errors, warnings, exceptions
- **Content hash**: Different MD5 hash

### 4. Confidence Scoring
```
✓ debug          [Confidence: 85%]
  → Best payload: debug=true
  → Changes: status 200→302, size Δ+1337, errors detected
```

## Sample Output

### Successful Discovery
```
[PARAMETER DISCOVERY]
==================================================
Target: http://192.168.45.100/process.php
Method: GET
Testing 76 parameters...
--------------------------------------------------

[*] Establishing baseline response...
  Status: 200 | Size: 5432 bytes
  Response time: 0.12s | Lines: 127

[*] Testing parameters...
Command: GET http://192.168.45.100/process.php?PARAM=PAYLOAD

✓ debug          [Confidence: 85%]
  → Best payload: debug=true
  → Changes: status 200→302, size Δ+450

✓ action         [Confidence: 75%]
  → Best payload: action=test
  → Changes: size Δ+1250, errors detected

✓ id             [Confidence: 60%]
  → Best payload: id=999999
  → Changes: size Δ-200, lines Δ-15

[DISCOVERED PARAMETERS]
--------------------------------------------------
High Confidence (≥70%):
  • debug          [85%] - status 200→302, size Δ+450
  • action         [75%] - size Δ+1250, errors detected

Medium Confidence (40-69%):
  • id             [60%] - size Δ-200, lines Δ-15

[NEXT STEPS - DECISION TREE]
--------------------------------------------------
🔐 Authentication/Debug Parameters Found:
  1. Test boolean values: 1, true, yes, on, enabled
  2. Try privilege escalation: admin=1, role=admin
  3. Enable debug modes: debug=1, test=true

  Example: http://192.168.45.100/process.php?debug=true

📊 Data Parameters Found - Test for:
  1. SQL Injection: ' OR '1'='1, 1 AND 1=2, 1 UNION SELECT NULL
  2. NoSQL Injection: {$ne:1}, {$gt:''}
  3. IDOR/Access Control: Increment IDs, try 0, -1, 999999

  Example: http://192.168.45.100/process.php?id=' OR '1'='1

[SUMMARY]
--------------------------------------------------
Total parameters discovered: 3
High confidence findings: 2
Testing method used: GET

Priority targets for exploitation:
  → debug (test with: debug=true)
  → action (test with: action=test)
```

## Understanding Confidence Scores

| Score | Meaning | Typical Causes |
|-------|---------|---------------|
| 90-100% | Very High | Status change + errors + major size difference |
| 70-89% | High | Multiple strong indicators of parameter processing |
| 50-69% | Medium | Clear response change, worth investigating |
| 30-49% | Low | Minor changes, might be noise |
| <30% | Very Low | Minimal change, likely not processed |

## Next Steps Decision Tree

### If Critical Parameters Found (cmd, file, path)
```
⚠ Critical Parameters Found - Test for:
  1. Command Injection: ; id ; whoami ;
  2. Path Traversal: ../../../../etc/passwd
  3. File Inclusion: php://filter/convert.base64-encode/resource=index
```

### If Authentication Parameters Found (admin, debug)
```
🔐 Authentication/Debug Parameters Found:
  1. Test boolean values: 1, true, yes, on
  2. Try privilege escalation: admin=1, role=admin
```

### If Data Parameters Found (id, search, filter)
```
📊 Data Parameters Found - Test for:
  1. SQL Injection: ' OR '1'='1
  2. IDOR: Try different ID values
```

## Integration with Other Tools

### Pre-Discovery (Find Endpoints)
```bash
# Use html_enum.py to find endpoints first
python3 html_enum.py http://target.com > endpoints.txt
cat endpoints.txt | python3 param_discover.py
```

### Post-Discovery (Exploit Parameters)
```bash
# After finding 'id' parameter, test for SQLi
python3 sqli_finder.py http://target.com/page.php?id=1

# After finding 'file' parameter, test for LFI
python3 lfi_scanner.py http://target.com/view.php?file=index.php
```

## Tips for Effective Usage

1. **Test Both Methods**: Some endpoints accept GET, others POST
   ```bash
   python3 param_discover.py http://target.com/api -m GET
   python3 param_discover.py http://target.com/api -m POST
   ```

2. **Use Custom Wordlists for Specific Apps**
   ```bash
   # For WordPress
   echo -e "wp_nonce\naction\ntab\npage_id" > wp_params.txt
   python3 param_discover.py http://target.com/wp-admin/admin-ajax.php -w wp_params.txt
   ```

3. **Chain with grep for specific findings**
   ```bash
   python3 param_discover.py http://target.com | grep "High Confidence" -A 5
   ```

4. **Monitor server behavior**
   ```bash
   # Use verbose mode if server is responding slowly
   python3 param_discover.py http://target.com -v
   ```

## Common Parameter Categories

| Category | Common Names | Typical Vulnerabilities |
|----------|--------------|------------------------|
| Identifiers | id, uid, pid, oid | IDOR, SQL Injection |
| Actions | action, do, act, mode | Logic flaws, Auth bypass |
| Files | file, path, page, template | LFI, Path Traversal |
| Debug | debug, test, dev, admin | Information disclosure |
| Data | search, filter, sort, query | SQL/NoSQL Injection |
| Auth | user, role, token, key | Privilege escalation |
| Output | format, type, export | XXE, Template injection |

## Troubleshooting

### No parameters discovered
- Try different HTTP method (GET vs POST)
- Target might use JSON/XML body instead of parameters
- Check if endpoint requires authentication

### Too many false positives
- Increase baseline sample size in code
- Check if site has random content (ads, timestamps)
- Use verbose mode to see what's changing

### Slow performance
- Reduce parameter list (use custom wordlist)
- Check network latency to target
- Consider parallelization for large wordlists

## OSCP Exam Relevance

This tool is particularly useful for:
1. **Web application enumeration phase**: Find hidden functionality
2. **Pre-exploitation reconnaissance**: Identify injection points
3. **Time-efficient testing**: Quickly identify interesting parameters
4. **Systematic approach**: Ensures no parameter is missed

Remember: In the OSCP exam, discovering a hidden debug parameter can be the difference between a shell and frustration!

## Additional Notes

- **Baseline stability**: Tool takes 3 samples to avoid false positives from dynamic content
- **Rate limiting**: Built-in 100ms delay between requests to be server-friendly
- **Smart payloads**: Payloads are chosen based on parameter names for better detection
- **Educational output**: Shows exactly what's being tested for learning purposes